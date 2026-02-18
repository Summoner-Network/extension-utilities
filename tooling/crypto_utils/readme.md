# `crypto_utils` README

This README explains how to use `crypto_utils` to add authenticated key agreement and message confidentiality to agents that exchange JSON messages over TCP via a relay server that you do not trust. It is written for agent developers who want to wire these functions into a handshake plus a "secure envelope" field on their existing message format.

The module gives you three layers:

* **Identity at rest**: load and save long-term keys to disk, with a production encrypted format.
* **Handshake**: exchange a signed handshake blob (`hs`) that derives per-handshake session keys.
* **Secure envelopes**: seal application payloads into `sec` using AES-GCM, with optional signatures, AAD binding, and replay checks.

The relay is assumed to forward bytes and possibly inspect or modify plaintext headers. The relay should not learn message contents once you start sealing payloads.

## 1) Concepts and threat model

### What the relay can do

Assume the relay can:

* observe, log, drop, delay, and reorder messages
* modify fields
* replay old messages
* impersonate peers unless you bind keys to identities

The module is designed so that:

* payload confidentiality and integrity are provided by AES-GCM once a session exists
* handshake signatures prevent undetected tampering of handshake fields
* replay protection is available for both handshake and encrypted payloads if you use the provided store hooks

### What the module does not do for you

The handshake proves that the sender controls the private key corresponding to the `sign_pub` it included in `hs`. It does **not** prove that this key belongs to "the real Alice" unless you:

* pre-share Alice's public key out-of-band, or
* use TOFU pinning (trust on first use), then alert or reject changes later.

`crypto_utils` includes a TOFU helper to make that easy.

## 2) Message shape across the wire

A typical Summoner-style message has a plaintext header plus optional crypto fields:

```json
{
  "to": "... or null",
  "from": "...",
  "intent": "request|respond|confirm|...",
  "my_nonce": "...",
  "your_nonce": "...",
  "my_ref": "...",
  "your_ref": "...",

  "hs": { ... optional handshake blob ... },
  "sec": { ... optional sealed envelope ... }
}
```

What travels in plaintext depends on your protocol. The recommended approach for a relay setting is:

* Keep **routing and protocol control** fields in plaintext (the relay may need them):

  * `to`, `from`, `intent` and whatever is necessary for routing
* Put **application content** inside `sec` as soon as you have a session:

  * `{"message": "...", "payload": {...}}` inside the sealed envelope
* Bind the plaintext header to the ciphertext using **AEAD associated data (AAD)**, so the relay cannot transplant ciphertext into a different header.

This is the most important "professional" point for relay scenarios: confidentiality alone is not enough. You want the encrypted payload to be cryptographically tied to the outer message header.

## 3) Quickstart overview

In practice you do this:

1. Each agent loads or generates long-term keys:

* X25519 for key agreement
* Ed25519 for signing

2. The initiator sends a first message containing:

* a fresh nonce in the outer header (`my_nonce`)
* an `hs` built with `build_handshake_message("init", my_nonce, ...)`

3. The responder validates `hs` and derives `SessionContext`:

* `ctx = await validate_handshake(... local_role="responder" ...)`

4. The responder replies and may include its own `hs` (`"response"`) so the initiator can derive matching keys.

5. Once both sides have a `SessionContext`, they seal application payloads:

* `sec = seal_envelope(ctx, sign_priv, obj, aad_dict=header_fields, seq=seq)`
* receiver opens:
* `obj = open_envelope(ctx, peer_sign_pub, sec, aad_dict=header_fields, replay_store=...)`

## 4) Identity storage and loading

### Production identity file (recommended)

Use `save_identity_json_encrypted` and `load_identity_json_encrypted`. This stores private keys encrypted at rest using scrypt-derived AES-GCM and writes atomically. It is the correct default for agents that persist identity across restarts.

```python
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from crypto_utils import save_identity_json_encrypted, load_identity_json_encrypted

IDENT_PATH = "id_agent_alice.json"
PASSWORD = b"choose a strong secret"

try:
    my_id, kx_priv, sign_priv, kx_pub_b64, sign_pub_b64 = load_identity_json_encrypted(
        IDENT_PATH, PASSWORD
    )
except FileNotFoundError:
    my_id = "alice"
    kx_priv = x25519.X25519PrivateKey.generate()
    sign_priv = ed25519.Ed25519PrivateKey.generate()
    save_identity_json_encrypted(IDENT_PATH, PASSWORD, my_id, kx_priv, sign_priv)
```

Notes:

* The password must be bytes and should be treated as a real secret (not a deterministic string derived from a public name).
* The returned public keys are base64 strings you can log or store.

### Dev identity file (optional)

`save_identity_json` and `load_identity_json` support a readable JSON format. If you call `save_identity_json` without a password it stores raw private keys in base64. That is dev-only.

If you do want readability and encryption, pass a password and it will store encrypted PKCS#8 PEM.

## 5) Handshake: building and validating `hs`

### 5.1 `build_handshake_message`

**Purpose:** Construct a signed handshake blob that advertises:

* `kx_pub` for X25519 key agreement
* `sign_pub` for Ed25519 verification
* a timestamp and a nonce
* a signature that covers the canonical handshake core

**Call:**

```python
hs = build_handshake_message(
    "init",                     # or "response"
    nonce=my_nonce,             # bind to the outer message nonce
    priv_kx=kx_priv,
    priv_sign=sign_priv,
    sender_id=my_id             # optional but recommended
)
```

**What to send:** The resulting dict can be placed directly in your wire message under `"hs"`.

**How to choose the nonce:** In your existing protocol you already generate per-message nonces (`my_nonce`). You should bind the handshake to the same nonce you are already using for replay checks. That keeps the handshake aligned with your state machine.

### 5.2 `validate_handshake`

**Purpose:** Verify the handshake signature, enforce replay and staleness policy, and derive a `SessionContext` with directional keys.

**Call:**

```python
ctx = await validate_handshake(
    msg=hs,
    expected_type="init",            # you decide based on where you are in the flow
    expected_nonce=outer_my_nonce,   # must match hs["nonce"]
    nonce_store=handshake_nonce_store,
    priv_kx=kx_priv,
    local_role="responder",          # or "initiator"
    expected_sender_id=peer_id       # optional, if hs includes sender_id
)
```

What it checks:

* version and type match what you expect for that step
* `hs["nonce"]` matches the nonce you expected for this message
* timestamp parses as timezone-aware UTC ISO and is not too far in the future
* replay and staleness using your `nonce_store`
* Ed25519 signature verifies over the canonical core fields
* then it derives session keys with HKDF bound to the handshake transcript

**What you store from `ctx`:**

* `ctx.send_key` and `ctx.recv_key` for sealing and opening envelopes
* `ctx.session_id` for replay windows and logging
* `ctx.peer_sign_pub` and `ctx.peer_kx_pub` for peer identity handling

### 5.3 `validate_handshake_message` (compatibility wrapper)

This returns a single symmetric key (`ctx.common_key()`), which is per-handshake fresh but does not separate directions. Use it only if you are keeping legacy code that expects a single key.

For new code, prefer `validate_handshake`.

## 6) Stores you must provide (and how to do it)

### 6.1 Handshake nonce store (`NonceStore`)

`validate_handshake` requires a `nonce_store` with:

* `exists(nonce)`
* `is_expired(ts)`
* `add(nonce, ts)`

This is where you implement your handshake replay window.

You already have a DB-backed nonce store in your agent code. That is appropriate. The module also provides `InMemoryNonceStore` for local testing:

```python
from crypto_utils import InMemoryNonceStore
handshake_nonce_store = InMemoryNonceStore(ttl_seconds=60)
```

### 6.2 Encrypted message replay store (`ReplayStore`)

If you use `seq` in envelopes, you can enforce replay defense independent of your outer state machine.

The store interface is:

* `seen(session_id, seq)`
* `add(session_id, seq, ts)`

The module includes `InMemoryReplayStore`:

```python
from crypto_utils import InMemoryReplayStore
replay_store = InMemoryReplayStore(ttl_seconds=300)
```

In production, you typically persist this in memory for active sessions, not in your main durable database, unless you require very strong replay guarantees across restarts.

### 6.3 Peer key store for TOFU (`PeerKeyStore`)

If you want TOFU pinning, you store each peer's public keys keyed by `peer_id`.

The module provides `DictPeerKeyStore` as a simple example:

```python
from crypto_utils import DictPeerKeyStore
peer_key_store = DictPeerKeyStore()
```

In production, persist this mapping so that key changes can be detected across restarts.

## 7) TOFU key pinning (recommended for relay settings)

If you do not have a PKI, you can still get practical identity binding with TOFU:

* First time you see a peer_id, you store their `(sign_pub, kx_pub)`
* Next time, if it changes unexpectedly, you treat it as suspicious and reject or require manual rotation

Use `tofu_check_or_pin` right after a validated handshake:

```python
from crypto_utils import tofu_check_or_pin

status = tofu_check_or_pin(
    peer_key_store,
    peer_id=peer_id,
    peer_sign_pub_b64=ctx.peer_sign_pub,
    peer_kx_pub_b64=ctx.peer_kx_pub,
    allow_rotation=False
)
# status is "pinned" or "match"
```

If you set `allow_rotation=True`, it overwrites and returns `"rotated"`. Only do that if you have a deliberate key rotation workflow.

In a relay environment, TOFU is often the minimum you want, because otherwise a MitM can swap keys during first contact.

## 8) Secure envelopes: `seal_envelope` and `open_envelope`

### 8.1 Why AAD matters for relay scenarios

AES-GCM supports Associated Data (AAD) that is authenticated but not encrypted. You should use AAD to bind your plaintext header fields to the ciphertext.

Without AAD binding, a relay could take a valid `sec` blob and attach it to a different header. If your application logic uses header fields for routing or semantics, that can create confusing or exploitable behavior.

With AAD binding, any change to the AAD fields will cause decryption to fail.

### 8.2 Choosing AAD fields

Pick the stable header fields that you want to bind, typically:

* `from`, `to`, `intent`
* handshake or protocol nonces and references (`my_nonce`, `your_nonce`, `my_ref`, `your_ref`)
* `session_id` and `seq` if you use them

Do not include fields that legitimately differ between sender and receiver or fields that can change in transit (like relay timestamps). AAD must be identical at seal and open.

`crypto_utils` supports passing `aad_dict`, which it canonicalizes deterministically.

### 8.3 `seal_envelope`

You call `seal_envelope` when you want to encrypt a payload dict.

Typical sender usage:

```python
from crypto_utils import seal_envelope

header = {
    "from": my_id,
    "to": peer_id,
    "intent": "request",
    "my_nonce": my_nonce,
    "your_nonce": your_nonce,
    "session_id": ctx.session_id,
    "seq": seq,
}

payload_obj = {"message": "How are you?", "extra": {"x": 1}}

sec = seal_envelope(
    ctx,                      # SessionContext, uses ctx.send_key
    sign_priv,
    payload_obj,
    aad_dict=header,
    seq=seq,                  # put seq inside the envelope too
    session_id=ctx.session_id # redundant if ctx passed, but explicit is fine
)
```

Then you send over the wire:

```python
wire_msg = {
    "from": my_id,
    "to": peer_id,
    "intent": "request",
    "my_nonce": my_nonce,
    "your_nonce": your_nonce,
    "sec": sec
}
```

Notes:

* If `ctx` is provided, the function uses `ctx.send_key`.
* By default it also signs the envelope JSON with Ed25519. This gives you identity-authentication at the message layer. If you do not want that overhead, set `include_signature=False` and then you should set `require_signature=False` on `open_envelope`.

### 8.4 `open_envelope`

Receiver usage:

```python
from crypto_utils import open_envelope

header = {
    "from": peer_id,
    "to": my_id,
    "intent": "request",
    "my_nonce": peer_my_nonce,
    "your_nonce": my_nonce,
    "session_id": ctx.session_id,
    "seq": seq,
}

obj = open_envelope(
    ctx,                        # SessionContext, uses ctx.recv_key
    peer_sign_pub_b64=ctx.peer_sign_pub,
    signed=wire_msg["sec"],
    aad_dict=header,
    replay_store=replay_store,  # optional but recommended if you use seq
    require_signature=True
)

message = obj["message"]
```

If the relay modifies header fields that are part of AAD, `open_envelope` fails. That is the intended behavior for a secure protocol.

## 9) End-to-end flow examples on both sides of the wire

The exact handshake sequencing depends on your state machine. Below is a clean pattern that matches what you are already doing: initiator attaches `"init"` handshake on the first request, responder attaches `"response"` handshake on confirm.

### 9.1 Initiator flow (Alice)

**State:** no session with Bob yet.

1. Alice sends a first request with `hs`:

```python
my_nonce = generate_nonce()
hs = build_handshake_message("init", my_nonce, kx_priv, sign_priv, sender_id=my_id)

wire_msg = {
    "from": my_id,
    "to": peer_id,
    "intent": "request",
    "my_nonce": my_nonce,
    "your_nonce": peer_nonce_from_previous_step,
    "hs": hs,
    "message": "optional plaintext for demo only"
}
send(wire_msg)
```

2. Alice receives Bob's confirm containing `"response"` handshake:

```python
hs_resp = incoming["hs"]
peer_nonce = incoming["my_nonce"]

ctx = await validate_handshake(
    msg=hs_resp,
    expected_type="response",
    expected_nonce=peer_nonce,
    nonce_store=handshake_nonce_store,
    priv_kx=kx_priv,
    local_role="initiator",
    expected_sender_id=peer_id
)

tofu_check_or_pin(peer_key_store, peer_id=peer_id,
                  peer_sign_pub_b64=ctx.peer_sign_pub,
                  peer_kx_pub_b64=ctx.peer_kx_pub)

sessions[peer_id] = ctx
seq_send[peer_id] = 0
seq_recv[peer_id] = 0
```

3. Alice now seals payloads using `seal_envelope(ctx, ...)` and binds AAD.

### 9.2 Responder flow (Bob)

1. Bob receives Alice's first request containing `"init"` handshake:

```python
hs_init = incoming.get("hs")
peer_nonce = incoming["my_nonce"]

ctx = await validate_handshake(
    msg=hs_init,
    expected_type="init",
    expected_nonce=peer_nonce,
    nonce_store=handshake_nonce_store,
    priv_kx=kx_priv,
    local_role="responder",
    expected_sender_id=peer_id
)

tofu_check_or_pin(peer_key_store, peer_id=peer_id,
                  peer_sign_pub_b64=ctx.peer_sign_pub,
                  peer_kx_pub_b64=ctx.peer_kx_pub)

sessions[peer_id] = ctx
seq_send[peer_id] = 0
seq_recv[peer_id] = 0
```

2. Bob replies with confirm and includes `"response"` handshake bound to his confirm nonce:

```python
my_nonce = generate_nonce()
hs_resp = build_handshake_message("response", my_nonce, kx_priv, sign_priv, sender_id=my_id)

wire_msg = {
    "from": my_id,
    "to": peer_id,
    "intent": "confirm",
    "my_nonce": my_nonce,
    "hs": hs_resp
}
send(wire_msg)
```

3. Bob can now open Alice's sealed messages using `open_envelope(ctx, ...)` with AAD binding and replay checks.

## 10) Sequence numbers and replay defense for sealed payloads

If you strictly do request/response with strict state, you can rely on your outer nonces and DB dedupe. If you want to move toward more general concurrent messaging, add a `seq` per direction.

A practical approach is:

* For each peer and session, maintain:

  * `seq_send` incremented every time you call `seal_envelope`
  * `seq_recv` accepted if not seen, tracked via a replay store
* Put `seq` in both:

  * the AAD dict
  * and in the envelope itself (the function supports this)

This lets you:

* detect duplicates even if outer headers are replayed
* handle reordering more cleanly if you accept a small window

If you need a window, implement it in `ReplayStore.seen/add` rather than in `crypto_utils`.

## 11) Downgrade policy and operational guidance

Your agent code decides whether insecure messages are allowed. In a relay environment, once you have a valid `SessionContext` for a peer, a common policy is:

* If you previously established a session with a peer, require `sec` for application payloads.
* If `sec` is missing or fails to open, treat it as an error, not as plaintext fallback.

This prevents a relay from stripping `sec` and forcing plaintext.

Similarly, you can require that once a peer is known, their handshake key material must match pinned keys (TOFU or pre-shared).

## 12) Function-by-function reference

### Encoding and canonicalization

* `b64_encode(bytes) -> str`, `b64_decode(str) -> bytes`
  Used internally. Useful if you store raw keys or binary values in JSON.

* `aad_from_dict(dict) -> bytes`
  Deterministically serializes a dict into bytes. Use it indirectly by passing `aad_dict` to `seal_envelope` and `open_envelope`.

### Handshake

* `build_handshake_message(type, nonce, priv_kx, priv_sign, sender_id=None) -> dict`
  Build the `hs` object to send.

* `validate_handshake(msg, expected_type, expected_nonce, nonce_store, priv_kx, local_role, ...) -> SessionContext`
  Verify and derive keys. This is the main entry point.

* `validate_handshake_message(...) -> bytes`
  Backward-compatible wrapper returning a single symmetric key. Prefer `validate_handshake`.

### SessionContext

* `SessionContext.session_id`
  Stable identifier for replay windows and logging.

* `SessionContext.send_key`, `SessionContext.recv_key`
  Directional keys. `seal_envelope` uses `send_key` and `open_envelope` uses `recv_key` when you pass a `SessionContext`.

* `SessionContext.peer_sign_pub`, `SessionContext.peer_kx_pub`
  Peer public keys extracted from handshake.

### Secure envelopes

* `seal_envelope(sym_or_ctx, sign_priv, obj, aad_dict=..., seq=..., session_id=..., include_signature=True) -> dict`
  Produces the `sec` object to place on the wire.

* `open_envelope(sym_or_ctx, peer_sign_pub_b64, sec, aad_dict=..., replay_store=..., require_signature=True) -> dict`
  Verifies (optional) and decrypts.

### TOFU

* `tofu_check_or_pin(peer_key_store, peer_id, peer_sign_pub_b64, peer_kx_pub_b64, allow_rotation=False)`
  Pins peer keys on first use and rejects unexpected changes by default.

### Identity storage

* `save_identity_json_encrypted(...)` and `load_identity_json_encrypted(...)`
  Use these for production.

* `save_identity_json(...)` and `load_identity_json(...)`
  Use these for dev, tests, or manual inspection. Do not store raw private keys unencrypted outside development.

### Provided in-memory helpers

* `InMemoryNonceStore(ttl_seconds)`
  For handshake replay defense during tests.

* `InMemoryReplayStore(ttl_seconds)`
  For envelope replay defense using `sid` and `seq`.

* `DictPeerKeyStore()`
  Example TOFU store.

## 13) Recommended integration checklist for your agent code

If you want a clean integration for TCP-through-relay:

1. Load identity from `load_identity_json_encrypted`.
2. On handshake receipt, call `validate_handshake` and store `SessionContext` per peer.
3. Immediately run `tofu_check_or_pin` for that peer.
4. For every sealed message, build an `aad_dict` from header fields you want bound.
5. Use `seq` per peer session if you anticipate concurrency or want stronger replay guarantees.
6. After session established, require `sec` for application payloads and do not silently fall back to plaintext.

