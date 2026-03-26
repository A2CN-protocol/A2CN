# A2CN Reference Implementation — Python

**The canonical Python implementation of the A2CN protocol.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-77%20passing%2C%201%20skipped-brightgreen.svg)](tests/)
[![Spec](https://img.shields.io/badge/Spec-v0.1.3-green.svg)](../../spec/v0.1.3.md)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com)

This is the reference implementation of the [A2CN protocol](../../spec/v0.1.3.md) — the open protocol for agent-to-agent B2B commercial negotiation. It is the authoritative example of what spec-compliant A2CN behavior looks like in code.

---

## Quickstart

```bash
# Clone the repo
git clone https://github.com/A2CN-protocol/A2CN.git
cd A2CN/reference-implementation/python

# Install
python -m pip install -e .

# Run the bilateral negotiation demo
python examples/saas_renewal.py
```

Expected output:

```
✓ Discovery document fetched from seller
✓ Session initiated — session_id: 222118e7-7f18-4a20-9fa6-dd35a945e67d

✓ Round 1: TechCorp offers $95,000 — Acme counters $115,000
✓ Round 2: TechCorp offers $103,000 — Acme counters $105,000 net-45
✓ Round 4: TechCorp accepts $105,000

✓ Transaction record generated — record_hash: _H3cQxZuwkMculi1CXxPNVWQEBMYbasK...
✓ Buyer record_hash == Seller record_hash
✓ A2CN bilateral session complete
```

That is two processes — TechCorp's procurement agent and Acme's sales agent — completing a four-round SaaS renewal negotiation with a cryptographically verified transaction record. Neither side controls the authoritative record. Both independently derived the same hash.

---

## What the demo shows

The demo (`examples/saas_renewal.py`) is a verbose walkthrough of the Appendix B scenario from the spec. Run it with `--verbose` to see every message envelope on the wire:

```json
{
  "message_type": "offer",
  "message_id": "c4b0d581-489d-4af6-a354-fdd7c74496c9",
  "session_id": "222118e7-7f18-4a20-9fa6-dd35a945e67d",
  "round_number": 1,
  "sequence_number": 1,
  "sender_did": "did:web:techcorp.example",
  "sender_verification_method": "did:web:techcorp.example#key-1",
  "timestamp": "2026-03-25T21:40:11Z",
  "expires_at": "2026-03-25T21:55:11Z",
  "terms": {
    "total_value": 9500000,
    "currency": "USD",
    "line_items": [{ "description": "Acme Analytics Platform — 12 months", "total": 9500000 }],
    "payment_terms": { "net_days": 30 }
  },
  "protocol_act_hash": "CAJSH5sTyYzmlaF9ULieuH1aHSr8ABp14MUS8WF7_Jg",
  "protocol_act_signature": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Every offer is JCS-canonicalized, SHA-256 hashed, and ES256-signed before transmission. The server recomputes the hash from the message fields and rejects any mismatch before the message enters the state machine.

---

## Architecture

Two sides. Two processes. One protocol.

```
┌─────────────────────────────┐        ┌─────────────────────────────┐
│  A2CNClient (client.py)     │        │  FastAPI Server (server.py)  │
│                             │        │                              │
│  • fetch_discovery()        │──GET──▶│  /.well-known/a2cn-agent     │
│  • initiate_session()       │──POST─▶│  /sessions                   │
│  • send_offer()             │──POST─▶│  /sessions/{id}/messages     │
│  • send_acceptance()        │──POST─▶│  /sessions/{id}/messages     │
│  • build_client_side_record │        │                              │
│                             │◀──────│  SessionStore (session.py)   │
└─────────────────────────────┘        └─────────────────────────────┘
         ↑                                          ↑
    crypto.py                                  record.py
    JCS + SHA-256 + ES256                      Deterministic
    did.py                                     transaction record
    did:web resolution
```

The client and server are deliberately symmetric. Both derive the transaction record from the same protocol messages using the same deterministic procedure. The `record_hash` match at the end is the proof that the implementation is correct.

---

## Module reference

### `a2cn/crypto.py` — Cryptographic primitives

Everything cryptographic lives here. Start here when reading the code.

```python
from a2cn.crypto import generate_keypair, hash_protocol_act, sign_jws, verify_jws

# Generate a P-256 keypair for an agent
private_key, public_key = generate_keypair()

# Hash a protocol act (JCS → SHA-256 → base64url)
protocol_act = {
    "protocol_version": "0.1",
    "session_id": "...",
    "round_number": 1,
    "sequence_number": 1,
    "message_type": "offer",
    "sender_did": "did:web:example.com",
    "timestamp": "2026-03-25T10:00:00Z",
    "expires_at": "2026-03-25T10:15:00Z",
    "terms": { ... }
}
hash_str = hash_protocol_act(protocol_act)

# Sign and verify
signature = sign_jws(hash_str, private_key)
assert verify_jws(hash_str, signature, public_key)
```

**Key design decisions:**
- RFC 8785 JCS canonicalization via the `jcs` package — not "sort keys alphabetically"
- P-256 (SECP256R1) with ES256 — matches the spec's default cryptographic suite
- base64url encoding without padding throughout

### `a2cn/did.py` — DID resolution

Resolves `did:web` DIDs to DID documents and extracts public keys.

```python
from a2cn.did import resolve_did_web, get_public_key

# did:web:example.com → https://example.com/.well-known/did.json
did_document = resolve_did_web("did:web:example.com")

# Extract the public key for a specific verification method
public_key = get_public_key(did_document, "did:web:example.com#key-1")
```

**Note:** DID documents are resolved once per session and cached for the session duration. Mid-session re-resolution is prohibited by the spec (Section 5.5) to prevent split-brain verification.

### `a2cn/messages.py` — Wire format

Python dataclasses for every A2CN message type. Field names match the spec wire format exactly — no renaming for Python conventions.

```python
from a2cn.messages import SessionInit, SessionAck, Offer, Acceptance

# All dataclasses have a .to_dict() method for wire serialization
offer = Offer(
    message_type="offer",
    session_id="...",
    round_number=1,
    sequence_number=1,
    sender_did="did:web:techcorp.example",
    ...
)
wire_payload = offer.to_dict()
```

### `a2cn/session.py` — State machine

The session state machine is the core of the protocol. It enforces all the behavioral rules from Section 8 of the spec.

**States:**
```
PENDING → ACTIVE → NEGOTIATING → COMPLETED
                              → REJECTED_FINAL
                              → WITHDRAWN
                              → TIMED_OUT
                 → ERROR
```

**What the state machine enforces:**
- Turn-taking: only the current turn holder may send an offer or counteroffer
- Sequence ordering: `sequence_number` must equal `last_processed + 1` — no gaps, no reordering
- Offer expiry: accepted offers must not have an `expires_at` in the past
- Hash integrity: incoming `protocol_act_hash` is recomputed and verified from message fields
- Session timeout: sessions exceeding `session_timeout_seconds` transition to `TIMED_OUT`
- Terminal state enforcement: messages to completed/withdrawn/timed-out sessions return `SESSION_WRONG_STATE`
- Idempotency: duplicate `message_id` returns the cached response without re-processing

### `a2cn/record.py` — Transaction record generation

Generates the deterministic dual-signed transaction record after session completion.

```python
from a2cn.record import generate_transaction_record

record = generate_transaction_record(session)

# Key determinism rules (from spec Section 9):
# record_id    = UUID v5(A2CN_NAMESPACE, session_id)
# generated_at = Acceptance message timestamp (NOT datetime.now())
# offer_chain_hash = SHA-256(JCS([hash_1, hash_2, ..., hash_n]))
# record_hash  = SHA-256(JCS(entire_record))
```

The A2CN namespace UUID is `f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c` (Appendix A of the spec).

Both parties must independently call `generate_transaction_record()` and arrive at the same `record_hash`. This is the primary correctness invariant of the protocol.

### `a2cn/server.py` — FastAPI responder

Implements all required endpoints from Section 11.1.1 of the spec.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/sessions` | Session initiation — returns `SessionAck` (201) |
| `GET` | `/sessions/{id}` | Session state object |
| `POST` | `/sessions/{id}/messages` | Send offer, counteroffer, acceptance, rejection, or withdrawal |
| `GET` | `/sessions/{id}/messages` | Message history with pagination |
| `GET` | `/sessions/{id}/record` | Transaction record (COMPLETED sessions only) |
| `GET` | `/sessions/{id}/audit` | Audit log (any terminal state) |

All endpoints return `Content-Type: application/a2cn+json`.

Run the server:
```bash
uvicorn a2cn.server:app --reload --port 8000
```

Interactive API docs at `http://localhost:8000/docs`.

### `a2cn/client.py` — Initiator

The initiator side of a bilateral session.

```python
from a2cn.client import A2CNClient

client = A2CNClient(
    did="did:web:techcorp.example",
    private_key=private_key,
    agent_id="procurement-agent-001"
)

# Fetch discovery and initiate session
ack = await client.initiate_session(
    counterparty_endpoint="http://localhost:8000",
    deal_type="saas_renewal",
    currency="USD",
    subject="Acme Analytics renewal FY2027",
    estimated_value=12_000_000,  # cents
    max_rounds=4
)

# Send a signed offer
response = await client.send_offer(
    session_id=ack["session_id"],
    total_value=9_500_000,
    net_days=30
)

# Process incoming counteroffers — REQUIRED for deterministic record generation
client.process_incoming(response)
```

**Important:** Call `process_incoming()` for every message received from the counterparty. The client tracks incoming offer hashes to build the complete offer chain for the transaction record. Skipping this call causes `record_hash` mismatch.

---

## Running the tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

```
tests/test_crypto.py::test_sign_verify_roundtrip          PASSED
tests/test_crypto.py::test_jcs_deterministic              PASSED
tests/test_crypto.py::test_offer_chain_hash               PASSED
tests/test_session.py::test_turn_taking_enforced          PASSED
tests/test_session.py::test_sequence_ordering_strict      PASSED
tests/test_session.py::test_terminal_state_reentry        PASSED
tests/test_session.py::test_idempotency_message           PASSED
tests/test_session.py::test_offer_expiry_check            PASSED
tests/test_session.py::test_session_timeout               PASSED
tests/conformance/test_conformance.py::CONF-001           PASSED
tests/conformance/test_conformance.py::CONF-002           PASSED
tests/conformance/test_conformance.py::CONF-003           SKIPPED (JWT auth )
...
77 passed, 1 skipped
```

### Conformance tests

The conformance test suite (`tests/conformance/`) is designed to run against any A2CN implementation, not just this one. If you are building an independent implementation, point the conformance tests at your endpoint:

```bash
A2CN_ENDPOINT=http://your-server:8000 pytest tests/conformance/ -v
```

A passing conformance suite means your implementation can interoperate with any other conformant A2CN implementation.

---

## What is coming soon

The one skipped test (`CONF-003`) is the conformance test for server-side JWT authentication and protocol act signature verification. Week 2 wires these up:

- Every request to the server is verified against the sender's DID document before processing
- `protocol_act_signature` verification on incoming offers (not just hash recomputation)
- Full `did:web` resolution in the request handling path

The cryptographic primitives (`crypto.py`) and DID resolution (`did.py`) are already implemented. Week 2 connects them into the server request handlers.

---

## File structure

```
python/
├── a2cn/
│   ├── __init__.py
│   ├── crypto.py        # P-256 keygen, JCS, SHA-256/base64url, JWS signing/verification
│   ├── did.py           # did:web resolution, JWK2020 → public key extraction
│   ├── messages.py      # Wire-format dataclasses, exact spec field names
│   ├── session.py       # State machine, turn enforcement, sequence ordering, idempotency
│   ├── record.py        # Deterministic transaction record + audit log generation
│   ├── server.py        # Async FastAPI responder, all Section 11.1.1 endpoints
│   └── client.py        # Initiator: session init, signed offers, acceptance
├── tests/
│   ├── conftest.py      # Shared fixtures, mock DID documents
│   ├── test_crypto.py
│   ├── test_did.py
│   ├── test_messages.py
│   ├── test_session.py
│   ├── test_server.py
│   └── conformance/
│       └── test_conformance.py   # Protocol conformance suite
├── examples/
│   └── saas_renewal.py  # Appendix B walkthrough as running code (verbose mode available)
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Dependencies

```
fastapi==0.115.0       # Async HTTP server
uvicorn==0.32.0        # ASGI server
httpx==0.27.0          # Async HTTP client
PyJWT==2.9.0           # JWT/JWS signing (ES256)
cryptography==43.0.0   # P-256 key generation and operations
jcs==0.2.1             # RFC 8785 JSON Canonicalization Scheme
pytest==8.3.0          # Test runner
pytest-asyncio==0.24.0 # Async test support
```

Install: `pip install -r requirements.txt`

---

## Security posture

This is a pre-production reference implementation. Current security status after independent review:

| Category | Status |
|----------|--------|
| Cryptographic primitives | ✅ Correct — JCS, P-256, ES256, UUID v5 namespace |
| Protocol act signing scope | ✅ Correct — all 9 required fields per Section 7.3.1 |
| Acceptance signature payload | ✅ Correct — includes `round_number` and `sequence_number` |
| Transaction record determinism | ✅ Correct — both sides independently produce identical `record_hash` |
| Session state machine | ✅ Correct — all states, transitions, and enforcement rules |
| Turn-taking enforcement | ✅ Correct — `NOT_YOUR_TURN` on violation |
| Sequence ordering | ✅ Correct — `SEQUENCE_ERROR` on gap or reorder |
| Idempotency | ✅ Correct — duplicate `message_id` returns cached response |
| Input validation | ✅ Correct — type validation on all message fields |
| Offer expiry check | ✅ Correct — `OFFER_EXPIRED` on stale acceptance |
| Session timeout | ✅ Correct — `TIMED_OUT` transition on elapsed time |
| JWT request authentication | 🔄 In progress |
| Rate limiting | 📋 Planned |
| Free-text field sanitization | 📋 Planned |

---

## Contributing

See [`CONTRIBUTING.md`](../../CONTRIBUTING.md) at the repo root.

If you are building an independent A2CN implementation in another language, open an issue. We want to know — and we will help you pass the conformance tests.

Open issues tagged [`help wanted`](https://github.com/A2CN-protocol/A2CN/issues?q=label%3A%22help+wanted%22) and [`good first issue`](https://github.com/A2CN-protocol/A2CN/issues?q=label%3A%22good+first+issue%22).

---

## License

Apache 2.0. See [LICENSE](../../LICENSE).
