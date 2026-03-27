# A2CN Reference Implementation — Python

**The canonical Python implementation of the A2CN protocol.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-124%20passing%2C%201%20skipped-brightgreen.svg)](tests/)
[![Spec](https://img.shields.io/badge/Spec-v0.2.0-green.svg)](../../spec/a2cn-spec-v0.2.0.md)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com)

This is the reference implementation of the [A2CN protocol](../../spec/a2cn-spec-v0.2.0.md) — the open protocol for agent-to-agent B2B commercial negotiation. It is the authoritative example of what spec-compliant A2CN behavior looks like in code.

---

## Quickstart

```bash
git clone https://github.com/A2CN-protocol/A2CN.git
cd A2CN/reference-implementation/python
pip install -e .

# Run the bilateral SaaS renewal demo
python examples/saas_renewal.py

# Run the Session Invitation / Fairmarkit integration demo
# Terminal 1 (supplier, port 8002):
uvicorn server:app --port 8002
# Terminal 2:
python examples/invitation_flow.py
```

Expected output from `saas_renewal.py`:

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

Two processes. Different organizations. Neither controls the authoritative record. Both independently derived the same hash.

---

## What the demos show

### `examples/saas_renewal.py` — Bilateral negotiation demo

The canonical Appendix B walkthrough from the spec as running code. Flags:

```bash
python examples/saas_renewal.py                          # SaaS renewal, 4 rounds
python examples/saas_renewal.py --deal-type goods_procurement  # goods_procurement terms
python examples/saas_renewal.py --impasse-threshold 2    # impasse after 2 non-moving rounds
python examples/saas_renewal.py --verbose                # print every message envelope
```

### `examples/invitation_flow.py` — Session Invitation demo (Fairmarkit pattern)

Demonstrates Component 8: Session Invitation. The supplier has **no pre-deployed A2CN endpoint** at the start of the flow.

```
1. Buyer creates signed SessionInvitation for a goods_procurement event
2. Invitation delivered directly to supplier's /invitations endpoint
   (In Fairmarkit: delivered via BID_CREATED webhook)
3. Supplier validates signature, accepts
4. Buyer sends SessionInit to acceptor's newly-activated endpoint
5. 3-round negotiation completes
6. Both parties generate Transaction Record
7. record_hash verified to match
```

---

## Architecture

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│  A2CNClient (client.py)     │        │  FastAPI Server (server.py)  │
│                             │        │                              │
│  fetch_discovery()          │──GET──▶│  /.well-known/a2cn-agent     │
│  initiate_session()         │──POST─▶│  /sessions                   │
│  send_offer()               │──POST─▶│  /sessions/{id}/messages     │
│  send_acceptance()          │──POST─▶│  /sessions/{id}/messages     │
│  build_client_side_record() │        │                              │
│                             │        │  /invitations                │
│  InvitationStore            │───────▶│  /invitations/create         │
│  (invitation.py)            │        │  /invitations/{id}/accept    │
│                             │        │  /invitations/{id}/decline   │
└─────────────────────────────┘        └──────────────────────────────┘
         ↓                                          ↓
    crypto.py                                  record.py
    JCS + SHA-256 + ES256                      Deterministic
    invitation signing                         transaction record
    did.py
    did:web resolution
```

---

## Module reference

### `crypto.py` — Cryptographic primitives

```python
from crypto import generate_keypair, hash_protocol_act, sign_jws, verify_jws
from crypto import sign_invitation, verify_invitation_signature

private_key, public_key = generate_keypair()
hash_str = hash_protocol_act(protocol_act_dict)
signature = sign_jws(hash_str, private_key)
assert verify_jws(hash_str, signature, public_key)

# Invitation signing (Component 8)
sig = sign_invitation(invitation_dict, private_key)
assert verify_invitation_signature(invitation_dict, public_key)
```

RFC 8785 JCS canonicalization. P-256 / ES256. Invitation signing excludes the `invitation_signature` field from canonical form.

### `messages.py` — Wire format

Dataclasses for every message type. Field names match spec wire format exactly.

**v0.2 additions:** `SessionInvitation`, `InvitationAcceptance`, `InvitationDecline`, `InvitationStatus`, `WebhookPayload`, `validate_deal_type_terms()`, `impasse_threshold` on `SessionParams`.

```python
from messages import validate_deal_type_terms

errors = validate_deal_type_terms("goods_procurement", terms_dict)
# [] = valid; non-empty = validation errors
```

### `session.py` — State machine

States: `PENDING → ACTIVE → NEGOTIATING → COMPLETED / REJECTED_FINAL / WITHDRAWN / IMPASSE / TIMED_OUT / ERROR`

**Impasse detection (v0.2):** `consecutive_non_moving_rounds >= impasse_threshold` → `IMPASSE`. A round is non-moving if `|delta_total_value| < 0.5% of prev_total_value`.

Enforces: turn-taking, sequence ordering, offer expiry, hash integrity, terminal state enforcement, idempotency.

### `invitation.py` — Session Invitation (Component 8)

```python
from invitation import InvitationStore

store = InvitationStore()

invitation = store.create_invitation(
    inviter_did="did:web:buyer.example",
    proposed_deal_type="goods_procurement",
    proposed_terms_summary={"description": "...", "estimated_value": 1800000, "currency": "USD"},
    ...
)

acceptance = store.accept_invitation(
    invitation_id=invitation.invitation_id,
    acceptor_did="did:web:seller.example",
    acceptor_a2cn_endpoint="https://seller.example/api/a2cn",
    ...
)
```

### `server.py` — FastAPI responder

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/a2cn-agent` | Discovery document |
| `POST /sessions` | Session initiation |
| `POST /sessions/{id}/messages` | Offer / counteroffer / acceptance / rejection / withdrawal |
| `GET /sessions/{id}/record` | Transaction record (COMPLETED only) |
| `GET /sessions/{id}/audit` | Audit log (any terminal state) |
| `POST /invitations` | Receive inbound invitation |
| `POST /invitations/create` | Create outbound invitation |
| `POST /invitations/{id}/accept` | Accept invitation |
| `POST /invitations/{id}/decline` | Decline invitation |

Webhooks fire asynchronously on all terminal transitions with 1s/4s/16s retry backoff.

### `adapters/fairmarkit_adapter.py`

```python
from adapters.fairmarkit_adapter import FairmakitEventParser

# BID_CREATED webhook → A2CN terms
terms = FairmakitEventParser.bid_created_to_goods_procurement_terms(payload)

# Agreed terms → Fairmarkit response API payload
response = FairmakitEventParser.terms_to_fairmarkit_response(
    agreed_terms, session_id="...", request_id="..."
)
```

### `adapters/revenue_cloud_adapter.py`

```python
from adapters.revenue_cloud_adapter import RevenueCloudAdapter

# Revenue Cloud Pricing API → A2CN terms
terms = RevenueCloudAdapter.pricing_response_to_a2cn_terms(pricing_response, deal_type="saas_renewal")

# Agreed terms → Revenue Cloud order payload
order = RevenueCloudAdapter.a2cn_terms_to_order_payload(agreed_terms, account_id="...", pricebook_id="...")
```

---

## Running the tests

```bash
pytest tests/ -v   # 124 passed, 1 skipped
```

| Test file | What it covers |
|-----------|---------------|
| `test_crypto.py` | JCS, ES256, invitation signing |
| `test_session.py` | State machine, turn-taking, impasse |
| `test_server.py` | All HTTP endpoints, error codes |
| `test_invitations.py` | Invitation lifecycle, signature, expiry |
| `test_deal_type_terms.py` | `goods_procurement` and `saas_renewal` validation |
| `test_adapters.py` | Fairmarkit and Revenue Cloud translation |
| `conformance/test_conformance.py` | Protocol conformance suite |

Run conformance tests against any A2CN endpoint:
```bash
A2CN_ENDPOINT=http://your-server:8000 pytest tests/conformance/ -v
```

---

## File structure

```
python/
├── crypto.py            # P-256, JCS, SHA-256, ES256, invitation signing
├── did.py               # did:web resolution
├── messages.py          # Wire-format dataclasses, validation, error codes
├── session.py           # State machine, impasse detection
├── record.py            # Deterministic transaction record + audit log
├── invitation.py        # Component 8: SessionInvitation lifecycle
├── server.py            # FastAPI, all endpoints, async webhook delivery
├── client.py            # Initiator
├── adapters/
│   ├── fairmarkit_adapter.py
│   └── revenue_cloud_adapter.py
├── tests/
│   ├── test_crypto.py
│   ├── test_session.py
│   ├── test_server.py
│   ├── test_invitations.py
│   ├── test_deal_type_terms.py
│   ├── test_adapters.py
│   └── conformance/test_conformance.py
├── examples/
│   ├── saas_renewal.py
│   └── invitation_flow.py
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Security posture

| Category | Status |
|----------|--------|
| Cryptographic primitives | ✓ JCS, P-256, ES256, UUID v5 |
| Invitation signing | ✓ ES256+JCS, excludes signature field from canonical form |
| Transaction record determinism | ✓ Both sides independently produce identical `record_hash` |
| Turn-taking + sequence ordering | ✓ Enforced |
| Idempotency | ✓ Duplicate `message_id` returns cached response |
| Webhook delivery | ✓ Async, non-fatal on failure |
| JWT request authentication | 🔄 In progress — CONF-003 skipped |
| Rate limiting | 📋 Planned |

---

## License

Apache 2.0. See [LICENSE](../../LICENSE).
