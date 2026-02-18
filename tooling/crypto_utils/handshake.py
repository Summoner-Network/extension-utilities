# =============================================================================
# Crypto Utilities for Summoner Handshake and Secure Envelopes (prod-ready)
# =============================================================================
"""
Design goals
- Safe defaults, explicit versioning, UTC timestamps, canonical serialization.
- Easy for agent developers: small set of functions with sensible defaults.
- Storage agnostic: caller supplies nonce / replay / peer-key stores (sync or async).

What you get
1) Handshake messages (Ed25519-signed) that carry:
   - version, type, nonce, timestamp(UTC), kx_pub(X25519), sign_pub(Ed25519)
   - signature covers the canonical "handshake_core" JSON

2) Session keys derived from X25519 + HKDF with transcript binding:
   - per-handshake freshness via transcript hash in HKDF salt
   - directional keys (send_key, recv_key)
   - stable session_id for logging and replay windows

3) Secure envelopes for application payloads:
   - AES-GCM with explicit AAD support (bind outer headers)
   - optional Ed25519 signature over envelope JSON (identity-authentication)
   - optional seq/session replay checks

4) Identity storage:
   - encrypted JSON identity using scrypt + AES-GCM, atomic write, chmod 600 best-effort
   - dev-readable JSON identity (optionally encrypted PKCS#8 PEM)

Recommended usage pattern (agent developer)
- Maintain a per-peer SessionContext after handshake validation.
- When sending: seal_envelope(ctx, sign_priv, obj, aad_dict=header_fields, seq=seq)
- When receiving: open_envelope(ctx, peer_sign_pub, signed, aad_dict=header_fields, replay_store=...)

Important note about authentication
- The handshake proves possession of the signing key included in the handshake.
- It does NOT by itself prove that this key belongs to a specific peer identity.
  If you need identity binding without PKI, use TOFU pinning helpers below.

"""

from __future__ import annotations

import base64
import datetime as _dt
import inspect
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any, Optional, Protocol, Union, runtime_checkable, Literal, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# =============================================================================
# Constants and versions
# =============================================================================

HS_VERSION = "hs.v1"
ENV_VERSION = "env.v1"

_HKDF_INFO_BASE = b"summoner/handshake/v1"
_HKDF_INFO_COMMON = b"summoner/handshake/v1/common"
_HKDF_INFO_KEYS = b"summoner/handshake/v1/keys"  # yields session_id + directional keys

# Identity encryption format
_ID_FILE_VERSION = "id.v1"
_ID_AAD = b"Summoner.identity.v1"


# =============================================================================
# Interfaces (sync or async)
# =============================================================================

@runtime_checkable
class NonceStore(Protocol):
    # Used for handshake nonce replay defense
    def exists(self, nonce: str) -> bool: ...
    def is_expired(self, ts: _dt.datetime) -> bool: ...
    def add(self, nonce: str, ts: _dt.datetime) -> None: ...


@runtime_checkable
class ReplayStore(Protocol):
    # Used for envelope replay defense (session_id, seq)
    def seen(self, session_id: str, seq: int) -> bool: ...
    def add(self, session_id: str, seq: int, ts: _dt.datetime) -> None: ...


@runtime_checkable
class PeerKeyStore(Protocol):
    # Used for TOFU (pin peer keys per peer_id)
    def get(self, peer_id: str) -> Optional[dict]: ...
    def set(self, peer_id: str, record: dict) -> None: ...


async def _maybe_await(x: Any) -> Any:
    return await x if inspect.isawaitable(x) else x


# =============================================================================
# Encoding and canonical JSON
# =============================================================================

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def _canon_json_bytes(obj: Any) -> bytes:
    # Deterministic serialization for signing and AAD
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def _iso_utc(ts: _dt.datetime) -> str:
    # Always ISO with offset
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    return ts.astimezone(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(ts_str: str) -> _dt.datetime:
    # Accept "...Z" or "+00:00". Enforce timezone-aware.
    if not isinstance(ts_str, str):
        raise ValueError("timestamp must be a string")
    s = ts_str.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    ts = _dt.datetime.fromisoformat(s)
    if ts.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware (include Z or offset)")
    return ts


# =============================================================================
# Public key serialization
# =============================================================================

def serialize_public_key(
    key: Union[x25519.X25519PublicKey, ed25519.Ed25519PublicKey]
) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64_encode(raw)


def _load_x25519_pub(peer_pub_b64: str) -> x25519.X25519PublicKey:
    raw = b64_decode(peer_pub_b64)
    if len(raw) != 32:
        raise ValueError("invalid X25519 public key length")
    return x25519.X25519PublicKey.from_public_bytes(raw)


def _load_ed25519_pub(pub_b64: str) -> ed25519.Ed25519PublicKey:
    raw = b64_decode(pub_b64)
    if len(raw) != 32:
        raise ValueError("invalid Ed25519 public key length")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


# =============================================================================
# Signatures
# =============================================================================

def sign_bytes(priv_sign: ed25519.Ed25519PrivateKey, data: bytes) -> str:
    return b64_encode(priv_sign.sign(data))


def verify_bytes(pub_sign_b64: str, data: bytes, sig_b64: str) -> None:
    pub = _load_ed25519_pub(pub_sign_b64)
    sig = b64_decode(sig_b64)
    if len(sig) != 64:
        raise ValueError("invalid Ed25519 signature length")
    pub.verify(sig, data)


# =============================================================================
# Session context and key schedule
# =============================================================================

Role = Literal["initiator", "responder"]
Direction = Literal["send", "recv"]

@dataclass(frozen=True)
class SessionContext:
    """
    Keys derived from a validated handshake.

    - session_id: stable identifier derived from transcript and DH secret
    - send_key: key to encrypt outbound envelopes
    - recv_key: key to decrypt inbound envelopes
    - peer_sign_pub: peer Ed25519 pubkey (as b64)
    - peer_kx_pub: peer X25519 pubkey (as b64)
    - transcript_hash_b64: sha256(canonical handshake core) as b64
    - derived_at: UTC ISO timestamp
    """
    session_id: str
    send_key: bytes
    recv_key: bytes
    peer_sign_pub: str
    peer_kx_pub: str
    transcript_hash_b64: str
    derived_at: str

    def key_for(self, direction: Direction) -> bytes:
        return self.send_key if direction == "send" else self.recv_key

    def common_key(self) -> bytes:
        """
        A symmetric key that is the same for both parties and both directions.
        Provided only for compatibility with very simple use cases.
        Prefer send_key/recv_key for protocols that can be concurrent.
        """
        # Derive a common key from transcript hash and both direction keys (stable and symmetric).
        h = hashes.Hash(hashes.SHA256())
        h.update(b"summoner/common/v1")
        h.update(self.send_key)
        h.update(self.recv_key)
        return h.finalize()


def _sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def _derive_session_context(
    *,
    priv_kx: x25519.X25519PrivateKey,
    peer_kx_pub_b64: str,
    local_role: Role,
    transcript_hash: bytes,
    peer_sign_pub_b64: str,
    derived_at: _dt.datetime,
) -> SessionContext:
    peer_pub = _load_x25519_pub(peer_kx_pub_b64)
    shared = priv_kx.exchange(peer_pub)

    # HKDF: salt binds the transcript, so keys are fresh per-handshake even with long-term kx keys.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16 + 32 + 32,  # session_id_seed + i2r + r2i
        salt=transcript_hash,
        info=_HKDF_INFO_KEYS,
    )
    okm = hkdf.derive(shared)

    sid_seed = okm[0:16]
    k_i2r = okm[16:48]
    k_r2i = okm[48:80]

    session_id = b64_encode(_sha256(b"summoner/sid/v1" + sid_seed))[:22]  # short, url-safe-ish
    # Directional selection by role
    if local_role == "initiator":
        send_key, recv_key = k_i2r, k_r2i
    else:
        send_key, recv_key = k_r2i, k_i2r

    return SessionContext(
        session_id=session_id,
        send_key=send_key,
        recv_key=recv_key,
        peer_sign_pub=peer_sign_pub_b64,
        peer_kx_pub=peer_kx_pub_b64,
        transcript_hash_b64=b64_encode(transcript_hash),
        derived_at=_iso_utc(derived_at),
    )


# =============================================================================
# Handshake messages
# =============================================================================

def build_handshake_message(
    msg_type: Literal["init", "response"],
    nonce: str,
    priv_kx: x25519.X25519PrivateKey,
    priv_sign: ed25519.Ed25519PrivateKey,
    *,
    sender_id: Optional[str] = None,
    now: Optional[_dt.datetime] = None,
) -> dict:
    """
    Construct a signed handshake message.

    The signature covers a canonical JSON object called handshake_core.
    This includes version and type.

    Returns a dict with fields:
      - v, type, nonce, timestamp, kx_pub, sign_pub, (optional) sender, sig
    """
    if msg_type not in ("init", "response"):
        raise ValueError("msg_type must be 'init' or 'response'")
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("nonce must be a non-empty string")

    ts = _iso_utc(now or _utc_now())
    kx_pub_b64 = serialize_public_key(priv_kx.public_key())
    sign_pub_b64 = serialize_public_key(priv_sign.public_key())

    core = {
        "v": HS_VERSION,
        "type": msg_type,
        "nonce": nonce,
        "timestamp": ts,
        "kx_pub": kx_pub_b64,
        "sign_pub": sign_pub_b64,
    }
    if sender_id is not None:
        core["sender"] = str(sender_id)

    core_bytes = _canon_json_bytes(core)
    sig_b64 = sign_bytes(priv_sign, core_bytes)

    msg = dict(core)
    msg["sig"] = sig_b64
    return msg


async def validate_handshake(
    msg: dict,
    *,
    expected_type: Literal["init", "response"],
    expected_nonce: str,
    nonce_store: NonceStore,
    priv_kx: x25519.X25519PrivateKey,
    local_role: Role,
    now: Optional[_dt.datetime] = None,
    max_clock_skew_seconds: int = 120,
    expected_sender_id: Optional[str] = None,
) -> SessionContext:
    """
    Validate a signed handshake message and derive a SessionContext.

    Checks:
      - schema and version
      - type matches expected_type
      - nonce matches expected_nonce
      - timestamp parses (timezone-aware)
      - timestamp not too far in the future (clock skew bound)
      - replay and staleness via nonce_store (exists/is_expired)
      - Ed25519 signature verifies over canonical handshake_core
      - derives session keys with transcript binding

    On success:
      - records the nonce via nonce_store.add(nonce, ts)
      - returns SessionContext (send_key, recv_key, session_id, peer keys)
    """
    if not isinstance(msg, dict):
        raise ValueError("handshake must be a dict")
    if msg.get("v") != HS_VERSION:
        raise ValueError("unsupported handshake version")
    if msg.get("type") != expected_type:
        raise ValueError("unexpected handshake type")

    nonce = msg.get("nonce")
    if nonce != expected_nonce:
        raise ValueError("nonce mismatch")

    ts_str = msg.get("timestamp")
    ts = _parse_iso(ts_str)

    now_dt = now or _utc_now()
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=_dt.timezone.utc)
    # Reject timestamps that are too far in the future (basic skew defense)
    if (ts - now_dt).total_seconds() > float(max_clock_skew_seconds):
        raise ValueError("timestamp is too far in the future")

    # Replay/staleness check (store decides what "expired" means)
    if await _maybe_await(nonce_store.exists(nonce)) or nonce_store.is_expired(ts):
        raise ValueError("replayed or stale handshake")

    peer_kx_pub = msg.get("kx_pub")
    peer_sign_pub = msg.get("sign_pub")
    sig = msg.get("sig")
    if not (isinstance(peer_kx_pub, str) and isinstance(peer_sign_pub, str) and isinstance(sig, str)):
        raise ValueError("handshake missing key material or signature")

    sender = msg.get("sender")
    if expected_sender_id is not None:
        if sender != str(expected_sender_id):
            raise ValueError("sender_id mismatch")

    # Rebuild core exactly (do not sign/verify arbitrary extra fields)
    core = {
        "v": HS_VERSION,
        "type": expected_type,
        "nonce": nonce,
        "timestamp": ts_str,
        "kx_pub": peer_kx_pub,
        "sign_pub": peer_sign_pub,
    }
    if sender is not None:
        core["sender"] = str(sender)

    core_bytes = _canon_json_bytes(core)
    verify_bytes(peer_sign_pub, core_bytes, sig)

    transcript_hash = _sha256(core_bytes)
    ctx = _derive_session_context(
        priv_kx=priv_kx,
        peer_kx_pub_b64=peer_kx_pub,
        local_role=local_role,
        transcript_hash=transcript_hash,
        peer_sign_pub_b64=peer_sign_pub,
        derived_at=now_dt,
    )

    await _maybe_await(nonce_store.add(nonce, ts))
    return ctx


# Backward-compatible wrapper (returns a single symmetric key)
async def validate_handshake_message(
    msg: dict,
    expected_type: str,
    expected_nonce: str,
    nonce_store: Any,
    priv_kx: x25519.X25519PrivateKey,
) -> bytes:
    """
    Compatibility wrapper for older code.

    Returns ctx.common_key(), which is per-handshake fresh (transcript-bound),
    but does not separate send/recv.
    """
    # Choose a default role. This wrapper cannot infer role safely.
    # For old symmetric usage, role does not matter for common_key().
    ctx = await validate_handshake(
        msg,
        expected_type=expected_type,  # type: ignore[arg-type]
        expected_nonce=expected_nonce,
        nonce_store=nonce_store,
        priv_kx=priv_kx,
        local_role="initiator",
    )
    return ctx.common_key()


# =============================================================================
# AAD helpers (bind outer headers)
# =============================================================================

def aad_from_dict(aad_dict: Optional[dict]) -> Optional[bytes]:
    """
    Canonicalize a dict into bytes for AEAD associated data.
    Pass the same dict on seal and open.

    Example dict:
      {"from": "...", "to": "...", "intent": "request", "my_nonce": "...", "your_nonce": "...", "session_id": "...", "seq": 7}
    """
    if aad_dict is None:
        return None
    if not isinstance(aad_dict, dict):
        raise ValueError("aad_dict must be a dict")
    return _canon_json_bytes(aad_dict)


# =============================================================================
# Secure envelopes
# =============================================================================

def seal_envelope(
    sym: Union[bytes, SessionContext],
    sign_priv: ed25519.Ed25519PrivateKey,
    obj: dict,
    *,
    aad: Optional[bytes] = None,
    aad_dict: Optional[dict] = None,
    seq: Optional[int] = None,
    session_id: Optional[str] = None,
    include_signature: bool = True,
    now: Optional[_dt.datetime] = None,
) -> dict:
    """
    Encrypt an application payload into a signed envelope.

    Parameters
    - sym: bytes (single symmetric key) OR SessionContext (uses send_key by default)
    - aad / aad_dict: associated data. Use this to bind outer headers.
    - seq: optional integer sequence number for replay defense.
    - session_id: optional override. If sym is SessionContext, defaults to ctx.session_id.
    - include_signature: if True, sign the envelope JSON with Ed25519.

    Returns
      {"v": ENV_VERSION, "envelope": {...}, "sig": "<b64>"}   (sig omitted if include_signature=False)
    """
    if not isinstance(obj, dict):
        raise ValueError("obj must be a dict")

    if isinstance(sym, SessionContext):
        key = sym.send_key
        sid = session_id or sym.session_id
    else:
        key = sym
        sid = session_id

    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("sym key must be 32 bytes")

    aad_bytes = aad if aad is not None else aad_from_dict(aad_dict)
    ts = _iso_utc(now or _utc_now())

    plaintext = _canon_json_bytes(obj)
    nonce = os.urandom(12)
    aes = AESGCM(bytes(key))
    ciphertext = aes.encrypt(nonce, plaintext, associated_data=aad_bytes)

    envelope: dict[str, Any] = {
        "v": ENV_VERSION,
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(ciphertext),
        "ts": ts,
    }
    if sid is not None:
        envelope["sid"] = str(sid)
    if seq is not None:
        if not isinstance(seq, int) or seq < 0:
            raise ValueError("seq must be a non-negative int")
        envelope["seq"] = seq

    env_bytes = _canon_json_bytes(envelope)

    out: dict[str, Any] = {"v": ENV_VERSION, "envelope": envelope}
    if include_signature:
        out["sig"] = sign_bytes(sign_priv, env_bytes)
    return out


def open_envelope(
    sym: Union[bytes, SessionContext],
    peer_sign_pub_b64: str,
    signed: dict,
    *,
    aad: Optional[bytes] = None,
    aad_dict: Optional[dict] = None,
    replay_store: Optional[ReplayStore] = None,
    now: Optional[_dt.datetime] = None,
    require_signature: bool = True,
) -> dict:
    """
    Verify (optional) and decrypt an envelope produced by seal_envelope().

    Parameters
    - sym: bytes OR SessionContext (uses recv_key by default)
    - peer_sign_pub_b64: peer Ed25519 pubkey (b64). Required if signature is required.
    - aad / aad_dict: associated data. Must match seal side.
    - replay_store: if provided and envelope contains (sid, seq), enforces replay defense.
    - require_signature: if True, missing signature is rejected.

    Returns the decrypted payload dict.
    """
    if not isinstance(signed, dict):
        raise ValueError("signed envelope must be a dict")
    envelope = signed.get("envelope")
    if not isinstance(envelope, dict):
        raise ValueError("missing envelope object")

    if envelope.get("v") != ENV_VERSION:
        raise ValueError("unsupported envelope version")

    if isinstance(sym, SessionContext):
        key = sym.recv_key
    else:
        key = sym
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("sym key must be 32 bytes")

    sig = signed.get("sig")
    if sig is None:
        if require_signature:
            raise ValueError("missing envelope signature")
    else:
        if not isinstance(sig, str):
            raise ValueError("invalid envelope signature type")
        env_bytes = _canon_json_bytes(envelope)
        verify_bytes(peer_sign_pub_b64, env_bytes, sig)

    sid = envelope.get("sid")
    seq = envelope.get("seq")
    if replay_store is not None and sid is not None and seq is not None:
        if not isinstance(sid, str) or not isinstance(seq, int):
            raise ValueError("invalid sid/seq types in envelope")
        if replay_store.seen(sid, seq):
            raise ValueError("replayed envelope (sid,seq)")
        replay_store.add(sid, seq, now or _utc_now())

    nonce = b64_decode(envelope["nonce"])
    ciphertext = b64_decode(envelope["ciphertext"])

    aad_bytes = aad if aad is not None else aad_from_dict(aad_dict)

    aes = AESGCM(bytes(key))
    plaintext = aes.decrypt(nonce, ciphertext, associated_data=aad_bytes)
    obj = json.loads(plaintext.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("decrypted payload is not a dict")
    return obj


# =============================================================================
# TOFU helpers (optional identity binding without PKI)
# =============================================================================

def tofu_check_or_pin(
    key_store: PeerKeyStore,
    *,
    peer_id: str,
    peer_sign_pub_b64: str,
    peer_kx_pub_b64: str,
    allow_rotation: bool = False,
) -> Literal["pinned", "match", "rotated"]:
    """
    Trust-On-First-Use helper.
    - If no record exists for peer_id, pin and return "pinned".
    - If record exists and matches, return "match".
    - If record exists and differs:
        - if allow_rotation, overwrite and return "rotated"
        - else raise ValueError
    """
    if not peer_id:
        raise ValueError("peer_id must be non-empty")

    rec = key_store.get(peer_id)
    new_rec = {"sign_pub": peer_sign_pub_b64, "kx_pub": peer_kx_pub_b64}

    if rec is None:
        key_store.set(peer_id, new_rec)
        return "pinned"

    if rec.get("sign_pub") == peer_sign_pub_b64 and rec.get("kx_pub") == peer_kx_pub_b64:
        return "match"

    if allow_rotation:
        key_store.set(peer_id, new_rec)
        return "rotated"

    raise ValueError("peer key mismatch (possible MitM or rotation)")


# =============================================================================
# Identity storage
# =============================================================================

def _atomic_write_json(path: str, doc: dict, *, mode: int = 0o600) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        # best-effort perms
        try:
            os.chmod(tmp, mode)
        except Exception:
            pass
        os.replace(tmp, path)
        try:
            os.chmod(path, mode)
        except Exception:
            pass
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass


def save_identity_json(
    path: str,
    my_id: str,
    kx_priv: x25519.X25519PrivateKey,
    sign_priv: ed25519.Ed25519PrivateKey,
    password: Optional[bytes] = None,
) -> None:
    """
    Dev-friendly identity file.
    - Always includes public keys (raw+b64).
    - Private keys are either:
        - encrypted PKCS#8 PEM if password is provided
        - raw+b64 if password is None (dev only)
    """
    kx_pub_raw = kx_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sign_pub_raw = sign_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    doc: dict[str, Any] = {
        "my_id": str(my_id),
        "created_at": _iso_utc(_utc_now()),
        "kx_pub_b64": b64_encode(kx_pub_raw),
        "sign_pub_b64": b64_encode(sign_pub_raw),
    }

    if password:
        kx_priv_pem = kx_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )
        sign_priv_pem = sign_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )
        doc["kx_priv_pem"] = kx_priv_pem.decode("utf-8")
        doc["sign_priv_pem"] = sign_priv_pem.decode("utf-8")
    else:
        kx_priv_raw = kx_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        sign_priv_raw = sign_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        doc["kx_priv_b64"] = b64_encode(kx_priv_raw)
        doc["sign_priv_b64"] = b64_encode(sign_priv_raw)

    _atomic_write_json(path, doc, mode=0o600)


def load_identity_json(
    path: str,
    password: Optional[bytes] = None,
) -> Tuple[str, x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey, str, str]:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    my_id = doc["my_id"]

    if "kx_priv_pem" in doc and "sign_priv_pem" in doc:
        kx_priv = serialization.load_pem_private_key(
            doc["kx_priv_pem"].encode("utf-8"), password=password
        )
        sign_priv = serialization.load_pem_private_key(
            doc["sign_priv_pem"].encode("utf-8"), password=password
        )
        if not isinstance(kx_priv, x25519.X25519PrivateKey):
            raise ValueError("kx_priv is not X25519")
        if not isinstance(sign_priv, ed25519.Ed25519PrivateKey):
            raise ValueError("sign_priv is not Ed25519")
    else:
        kx_priv = x25519.X25519PrivateKey.from_private_bytes(b64_decode(doc["kx_priv_b64"]))
        sign_priv = ed25519.Ed25519PrivateKey.from_private_bytes(b64_decode(doc["sign_priv_b64"]))

    kx_pub_b64 = doc["kx_pub_b64"]
    sign_pub_b64 = doc["sign_pub_b64"]
    return my_id, kx_priv, sign_priv, kx_pub_b64, sign_pub_b64


def _kdf_scrypt(password: bytes, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(password)


def save_identity_json_encrypted(
    path: str,
    password: bytes,
    my_id: str,
    kx_priv: x25519.X25519PrivateKey,
    sign_priv: ed25519.Ed25519PrivateKey,
    *,
    scrypt_n: int = 2**14,
    scrypt_r: int = 8,
    scrypt_p: int = 1,
) -> None:
    """
    Production identity storage.
    - Encrypts a small JSON blob containing raw key bytes (b64) using AES-GCM.
    - Key derived from password with scrypt.
    - Atomic write and chmod 600 best-effort.
    """
    if not isinstance(password, (bytes, bytearray)) or len(password) < 8:
        # Keep this light. Strong password policy is app-level, but avoid obvious footguns.
        raise ValueError("password must be bytes and should be at least 8 bytes")

    kx_priv_raw = kx_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    kx_pub_raw = kx_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sign_priv_raw = sign_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sign_pub_raw = sign_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    plaintext_obj = {
        "my_id": str(my_id),
        "created_at": _iso_utc(_utc_now()),
        "kx_priv_b64": b64_encode(kx_priv_raw),
        "kx_pub_b64": b64_encode(kx_pub_raw),
        "sign_priv_b64": b64_encode(sign_priv_raw),
        "sign_pub_b64": b64_encode(sign_pub_raw),
    }
    plaintext = _canon_json_bytes(plaintext_obj)

    salt = os.urandom(16)
    key = _kdf_scrypt(bytes(password), salt, n=scrypt_n, r=scrypt_r, p=scrypt_p)
    nonce = os.urandom(12)

    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, associated_data=_ID_AAD)

    doc = {
        "v": _ID_FILE_VERSION,
        "kdf": "scrypt",
        "kdf_params": {"n": scrypt_n, "r": scrypt_r, "p": scrypt_p},
        "salt": b64_encode(salt),
        "nonce": b64_encode(nonce),
        "aad": b64_encode(_ID_AAD),
        "ciphertext": b64_encode(ct),
    }
    _atomic_write_json(path, doc, mode=0o600)


def load_identity_json_encrypted(
    path: str,
    password: bytes,
) -> Tuple[str, x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey, str, str]:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    if doc.get("v") != _ID_FILE_VERSION or doc.get("kdf") != "scrypt":
        raise ValueError("unsupported identity file format")

    aad_b64 = doc.get("aad")
    if aad_b64 != b64_encode(_ID_AAD):
        raise ValueError("identity file AAD mismatch")

    params = doc.get("kdf_params") or {}
    n = int(params.get("n", 2**14))
    r = int(params.get("r", 8))
    p = int(params.get("p", 1))

    salt = b64_decode(doc["salt"])
    nonce = b64_decode(doc["nonce"])
    ct = b64_decode(doc["ciphertext"])

    key = _kdf_scrypt(bytes(password), salt, n=n, r=r, p=p)
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ct, associated_data=_ID_AAD)

    obj = json.loads(plaintext.decode("utf-8"))
    my_id = obj["my_id"]
    kx_priv = x25519.X25519PrivateKey.from_private_bytes(b64_decode(obj["kx_priv_b64"]))
    sign_priv = ed25519.Ed25519PrivateKey.from_private_bytes(b64_decode(obj["sign_priv_b64"]))
    kx_pub_b64 = obj.get("kx_pub_b64") or serialize_public_key(kx_priv.public_key())
    sign_pub_b64 = obj.get("sign_pub_b64") or serialize_public_key(sign_priv.public_key())
    return my_id, kx_priv, sign_priv, kx_pub_b64, sign_pub_b64


# =============================================================================
# Simple in-memory stores (optional conveniences)
# =============================================================================

class InMemoryNonceStore:
    """
    Simple handshake nonce store with TTL.

    exists/add are sync so it can be used directly, but it matches the duck-typed NonceStore interface.
    """
    def __init__(self, ttl_seconds: int = 60):
        self.ttl_seconds = int(ttl_seconds)
        self._seen: dict[str, _dt.datetime] = {}

    def exists(self, nonce: str) -> bool:
        return nonce in self._seen

    def is_expired(self, ts: _dt.datetime) -> bool:
        # Treat old timestamps as expired
        now = _utc_now()
        return (now - ts).total_seconds() > float(self.ttl_seconds)

    def add(self, nonce: str, ts: _dt.datetime) -> None:
        self._seen[str(nonce)] = ts


class InMemoryReplayStore:
    """
    Simple replay store for (session_id, seq) with TTL.

    This is for encrypted envelopes when you use seq.
    """
    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = int(ttl_seconds)
        self._seen: dict[tuple[str, int], _dt.datetime] = {}

    def _gc(self) -> None:
        now = _utc_now()
        cutoff = now - _dt.timedelta(seconds=self.ttl_seconds)
        dead = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in dead:
            del self._seen[k]

    def seen(self, session_id: str, seq: int) -> bool:
        self._gc()
        return (session_id, int(seq)) in self._seen

    def add(self, session_id: str, seq: int, ts: _dt.datetime) -> None:
        self._gc()
        self._seen[(str(session_id), int(seq))] = ts


class DictPeerKeyStore:
    """
    Basic TOFU peer key store backed by a Python dict.
    Record schema: {"sign_pub": "...", "kx_pub": "..."}.
    """
    def __init__(self):
        self._d: dict[str, dict] = {}

    def get(self, peer_id: str) -> Optional[dict]:
        return self._d.get(peer_id)

    def set(self, peer_id: str, record: dict) -> None:
        self._d[peer_id] = dict(record)
