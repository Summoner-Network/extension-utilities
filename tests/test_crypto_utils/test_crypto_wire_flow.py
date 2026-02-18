import copy
import base64
from typing import Optional, Tuple

import pytest

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import sys, os
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.crypto_utils import (
    build_handshake_message,
    validate_handshake,
    seal_envelope,
    open_envelope,
    InMemoryNonceStore,
    InMemoryReplayStore,
    DictPeerKeyStore,
    tofu_check_or_pin,
)

pytestmark = pytest.mark.asyncio


# -----------------------------------------------------------------------------
# Helpers: relay, AAD, and a symmetric "wire key" derivation
# -----------------------------------------------------------------------------

def relay_forward(msg: dict) -> dict:
    """Simulate an untrusted relay that forwards messages as-is (deep copy)."""
    return copy.deepcopy(msg)


def aad_for_wire_header(
    header: dict,
    *,
    seq: Optional[int] = None,
) -> dict:
    """
    Stable AAD dict derived from plaintext header fields.
    Keep it restricted to fields that are identical at seal/open time.

    We bind:
      - from, to, intent
      - (optional) my_nonce/your_nonce/my_ref/your_ref if present
      - seq if you use seq-based replay defense
    """
    aad = {
        "from": header["from"],
        "to": header["to"],
        "intent": header["intent"],
    }
    for k in ("my_nonce", "your_nonce", "my_ref", "your_ref"):
        if k in header:
            aad[k] = header[k]
    if seq is not None:
        aad["seq"] = seq
    return aad


def derive_wire_key(priv_kx: x25519.X25519PrivateKey, peer_kx_pub_b64: str) -> bytes:
    """
    Derive a 32-byte symmetric key from X25519 shared secret using HKDF-SHA256.

    This is the minimal interoperable construction for sealing over an untrusted relay:
    - both sides compute the same X25519 shared secret
    - HKDF expands it into an AES-GCM key

    If your crypto_utils has a public helper for this, you can swap it in.
    """
    peer_raw = base64.b64decode(peer_kx_pub_b64.encode("utf-8"))
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_raw)
    shared = priv_kx.exchange(peer_pub)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"summoner.wire.v1",
    )
    return hkdf.derive(shared)


def stable_sid_from_kx_pubs(kx_pub_a_b64: str, kx_pub_b_b64: str) -> str:
    """
    Build a stable session id string from the pair of kx pubs, independent of who saw which hs.
    """
    a = kx_pub_a_b64.encode("utf-8")
    b = kx_pub_b_b64.encode("utf-8")
    lo, hi = (a, b) if a <= b else (b, a)
    h = hashes.Hash(hashes.SHA256())
    h.update(lo + b"|" + hi)
    digest = h.finalize()
    # short, URL/JSON-friendly
    return base64.b64encode(digest[:18]).decode("utf-8")


# -----------------------------------------------------------------------------
# Fixtures: two peers (initiator/responder)
# -----------------------------------------------------------------------------

@pytest.fixture
def alice():
    return {
        "id": "alice",
        "kx_priv": x25519.X25519PrivateKey.generate(),
        "sign_priv": ed25519.Ed25519PrivateKey.generate(),
        "hs_store": InMemoryNonceStore(ttl_seconds=60),
        "peer_store": DictPeerKeyStore(),
        "replay_store": InMemoryReplayStore(ttl_seconds=300),
    }


@pytest.fixture
def bob():
    return {
        "id": "bob",
        "kx_priv": x25519.X25519PrivateKey.generate(),
        "sign_priv": ed25519.Ed25519PrivateKey.generate(),
        "hs_store": InMemoryNonceStore(ttl_seconds=60),
        "peer_store": DictPeerKeyStore(),
        "replay_store": InMemoryReplayStore(ttl_seconds=300),
    }


# -----------------------------------------------------------------------------
# Establish handshake (both sides validate) and derive the shared wire key
# -----------------------------------------------------------------------------

async def establish_handshake_and_wire_key(alice: dict, bob: dict):
    """
    Two-sides-of-the-wire flow:

    A) Alice -> Bob: hs(init) bound to Alice my_nonce
       Bob validates hs(init) (signature + nonce replay policy)
       Bob learns Alice kx_pub + sign_pub

    B) Bob -> Alice: hs(response) bound to Bob my_nonce
       Alice validates hs(response)
       Alice learns Bob kx_pub + sign_pub

    C) Wire key derivation (THIS is the key point):
       - Bob derives wire_key using his priv_kx and Alice kx_pub (from init hs)
       - Alice derives wire_key using her priv_kx and Bob kx_pub (from response hs)
       These must match (X25519 symmetry).
    """
    # --- A: Alice -> Bob (init hs) ---
    alice_my_nonce = "a_nonce_1"
    init_hs = build_handshake_message(
        "init",
        nonce=alice_my_nonce,
        priv_kx=alice["kx_priv"],
        priv_sign=alice["sign_priv"],
        sender_id=alice["id"],
    )
    msg_a = {
        "from": alice["id"],
        "to": bob["id"],
        "intent": "request",
        "my_nonce": alice_my_nonce,
        "hs": init_hs,
    }
    wire_a = relay_forward(msg_a)

    bob_ctx_from_init = await validate_handshake(
        msg=wire_a["hs"],
        expected_type="init",
        expected_nonce=wire_a["my_nonce"],
        nonce_store=bob["hs_store"],
        priv_kx=bob["kx_priv"],
        local_role="responder",
        expected_sender_id=alice["id"],
    )

    tofu_check_or_pin(
        bob["peer_store"],
        peer_id=alice["id"],
        peer_sign_pub_b64=bob_ctx_from_init.peer_sign_pub,
        peer_kx_pub_b64=bob_ctx_from_init.peer_kx_pub,
        allow_rotation=False,
    )

    # --- B: Bob -> Alice (response hs) ---
    bob_my_nonce = "b_nonce_1"
    resp_hs = build_handshake_message(
        "response",
        nonce=bob_my_nonce,
        priv_kx=bob["kx_priv"],
        priv_sign=bob["sign_priv"],
        sender_id=bob["id"],
    )
    msg_b = {
        "from": bob["id"],
        "to": alice["id"],
        "intent": "confirm",
        "my_nonce": bob_my_nonce,
        "hs": resp_hs,
    }
    wire_b = relay_forward(msg_b)

    alice_ctx_from_resp = await validate_handshake(
        msg=wire_b["hs"],
        expected_type="response",
        expected_nonce=wire_b["my_nonce"],
        nonce_store=alice["hs_store"],
        priv_kx=alice["kx_priv"],
        local_role="initiator",
        expected_sender_id=bob["id"],
    )

    tofu_check_or_pin(
        alice["peer_store"],
        peer_id=bob["id"],
        peer_sign_pub_b64=alice_ctx_from_resp.peer_sign_pub,
        peer_kx_pub_b64=alice_ctx_from_resp.peer_kx_pub,
        allow_rotation=False,
    )

    # --- C: derive shared wire key on both sides ---
    wire_key_bob = derive_wire_key(bob["kx_priv"], init_hs["kx_pub"])     # peer = Alice
    wire_key_alice = derive_wire_key(alice["kx_priv"], resp_hs["kx_pub"]) # peer = Bob

    assert wire_key_alice == wire_key_bob, "X25519-derived wire key must match on both sides"
    sid = stable_sid_from_kx_pubs(init_hs["kx_pub"], resp_hs["kx_pub"])

    return {
        "init_hs": init_hs,
        "resp_hs": resp_hs,
        "alice_ctx": alice_ctx_from_resp,
        "bob_ctx": bob_ctx_from_init,
        "wire_key": wire_key_alice,
        "sid": sid,
    }


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

async def test_handshake_validation_and_wire_key_symmetry(alice, bob):
    out = await establish_handshake_and_wire_key(alice, bob)

    assert isinstance(out["wire_key"], (bytes, bytearray)) and len(out["wire_key"]) == 32
    assert isinstance(out["sid"], str) and len(out["sid"]) > 10

    # These contexts exist and contain peer key material
    assert isinstance(out["alice_ctx"].peer_sign_pub, str) and len(out["alice_ctx"].peer_sign_pub) > 10
    assert isinstance(out["bob_ctx"].peer_sign_pub, str) and len(out["bob_ctx"].peer_sign_pub) > 10


async def test_seal_and_open_with_aad_binding(alice, bob):
    out = await establish_handshake_and_wire_key(alice, bob)
    sym = out["wire_key"]
    sid = out["sid"]

    seq = 1
    header = {
        "from": alice["id"],
        "to": bob["id"],
        "intent": "request",
        "my_nonce": "a_nonce_2",
        "your_nonce": "b_nonce_1",
    }
    aad = aad_for_wire_header(header, seq=seq)

    obj = {"message": "Hello Bob", "amount": 7}
    sec = seal_envelope(
        sym,
        alice["sign_priv"],
        obj,
        aad_dict=aad,
        seq=seq,
        session_id=sid,
    )

    wire_msg = dict(header)
    wire_msg["sec"] = sec
    wire = relay_forward(wire_msg)

    opened = open_envelope(
        sym,
        peer_sign_pub_b64=out["init_hs"]["sign_pub"],  # Alice sign pub as known to Bob
        signed=wire["sec"],
        aad_dict=aad,
        replay_store=bob["replay_store"],
        require_signature=True,
    )
    assert opened == obj


async def test_aad_tamper_breaks_decrypt(alice, bob):
    out = await establish_handshake_and_wire_key(alice, bob)
    sym = out["wire_key"]
    sid = out["sid"]

    seq = 1
    header = {
        "from": alice["id"],
        "to": bob["id"],
        "intent": "request",
        "my_nonce": "a_nonce_3",
        "your_nonce": "b_nonce_1",
    }
    aad_good = aad_for_wire_header(header, seq=seq)
    obj = {"message": "bind me", "x": 1}

    sec = seal_envelope(sym, alice["sign_priv"], obj, aad_dict=aad_good, seq=seq, session_id=sid)
    wire = relay_forward({**header, "sec": sec})

    # Relay tampers with plaintext header
    wire_tampered = relay_forward(wire)
    wire_tampered["intent"] = "respond"

    aad_bad = aad_for_wire_header(wire_tampered, seq=seq)

    with pytest.raises(Exception):
        open_envelope(
            sym,
            peer_sign_pub_b64=out["init_hs"]["sign_pub"],
            signed=wire_tampered["sec"],
            aad_dict=aad_bad,
            replay_store=bob["replay_store"],
            require_signature=True,
        )


async def test_ciphertext_tamper_breaks_signature_or_gcm(alice, bob):
    out = await establish_handshake_and_wire_key(alice, bob)
    sym = out["wire_key"]
    sid = out["sid"]

    seq = 1
    header = {"from": alice["id"], "to": bob["id"], "intent": "request"}
    aad = aad_for_wire_header(header, seq=seq)
    obj = {"message": "tamper test"}

    sec = seal_envelope(sym, alice["sign_priv"], obj, aad_dict=aad, seq=seq, session_id=sid)
    wire = relay_forward({**header, "sec": sec})

    tampered = relay_forward(wire)
    ct = tampered["sec"]["envelope"]["ciphertext"]
    tampered["sec"]["envelope"]["ciphertext"] = ("A" if ct[0] != "A" else "B") + ct[1:]

    with pytest.raises(Exception):
        open_envelope(
            sym,
            peer_sign_pub_b64=out["init_hs"]["sign_pub"],
            signed=tampered["sec"],
            aad_dict=aad,
            replay_store=bob["replay_store"],
            require_signature=True,
        )


async def test_replay_store_rejects_same_sid_seq(alice, bob):
    out = await establish_handshake_and_wire_key(alice, bob)
    sym = out["wire_key"]
    sid = out["sid"]

    seq = 1
    header = {"from": alice["id"], "to": bob["id"], "intent": "request"}
    aad = aad_for_wire_header(header, seq=seq)
    obj = {"message": "replay me"}

    sec = seal_envelope(sym, alice["sign_priv"], obj, aad_dict=aad, seq=seq, session_id=sid)
    wire = relay_forward({**header, "sec": sec})

    opened1 = open_envelope(
        sym,
        peer_sign_pub_b64=out["init_hs"]["sign_pub"],
        signed=wire["sec"],
        aad_dict=aad,
        replay_store=bob["replay_store"],
        require_signature=True,
    )
    assert opened1 == obj

    with pytest.raises(ValueError):
        open_envelope(
            sym,
            peer_sign_pub_b64=out["init_hs"]["sign_pub"],
            signed=wire["sec"],
            aad_dict=aad,
            replay_store=bob["replay_store"],
            require_signature=True,
        )


async def test_wrong_peer_sign_pub_rejected(alice, bob):
    out = await establish_handshake_and_wire_key(alice, bob)
    sym = out["wire_key"]
    sid = out["sid"]

    seq = 1
    header = {"from": alice["id"], "to": bob["id"], "intent": "request"}
    aad = aad_for_wire_header(header, seq=seq)
    obj = {"message": "sig check"}

    sec = seal_envelope(sym, alice["sign_priv"], obj, aad_dict=aad, seq=seq, session_id=sid)

    wrong_sign_priv = ed25519.Ed25519PrivateKey.generate()
    wrong_sign_pub_b64 = base64.b64encode(
        wrong_sign_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("utf-8")

    with pytest.raises(Exception):
        open_envelope(
            sym,
            peer_sign_pub_b64=wrong_sign_pub_b64,
            signed=sec,
            aad_dict=aad,
            replay_store=bob["replay_store"],
            require_signature=True,
        )


async def test_missing_signature_rejected_when_required(alice, bob):
    out = await establish_handshake_and_wire_key(alice, bob)
    sym = out["wire_key"]
    sid = out["sid"]

    seq = 1
    header = {"from": alice["id"], "to": bob["id"], "intent": "request"}
    aad = aad_for_wire_header(header, seq=seq)
    obj = {"message": "unsigned"}

    sec = seal_envelope(sym, alice["sign_priv"], obj, aad_dict=aad, seq=seq, session_id=sid, include_signature=False)

    with pytest.raises(ValueError):
        open_envelope(
            sym,
            peer_sign_pub_b64=out["init_hs"]["sign_pub"],
            signed=sec,
            aad_dict=aad,
            replay_store=bob["replay_store"],
            require_signature=True,
        )

    opened = open_envelope(
        sym,
        peer_sign_pub_b64=out["init_hs"]["sign_pub"],
        signed=sec,
        aad_dict=aad,
        replay_store=bob["replay_store"],
        require_signature=False,
    )
    assert opened == obj


async def test_handshake_replay_rejected_by_nonce_store(alice, bob):
    alice_my_nonce = "a_nonce_replay"
    hs = build_handshake_message(
        "init",
        nonce=alice_my_nonce,
        priv_kx=alice["kx_priv"],
        priv_sign=alice["sign_priv"],
        sender_id=alice["id"],
    )

    # first validate OK
    ctx1 = await validate_handshake(
        msg=hs,
        expected_type="init",
        expected_nonce=alice_my_nonce,
        nonce_store=bob["hs_store"],
        priv_kx=bob["kx_priv"],
        local_role="responder",
        expected_sender_id=alice["id"],
    )
    assert ctx1 is not None

    # replay should be rejected
    with pytest.raises(ValueError):
        await validate_handshake(
            msg=hs,
            expected_type="init",
            expected_nonce=alice_my_nonce,
            nonce_store=bob["hs_store"],
            priv_kx=bob["kx_priv"],
            local_role="responder",
            expected_sender_id=alice["id"],
        )