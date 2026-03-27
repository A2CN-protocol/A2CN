# A2CN — Agent-to-Agent Commercial Negotiation Protocol

**The missing protocol layer for machine-to-machine B2B commerce.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Spec Version](https://img.shields.io/badge/Spec-v0.2.0-green.svg)](spec/a2cn-spec-v0.2.0.md)
[![Tests](https://img.shields.io/badge/Tests-124%20passing-brightgreen.svg)](reference-implementation/python/tests)
[![Status](https://img.shields.io/badge/Status-Partner%20Ready-orange.svg)]()

---

## The gap in the agent protocol stack

```
Layer 4 → AP2 / ACP     Payment execution        ✓ Exists
        ↑
Layer 3 → A2CN          Commercial negotiation   ← YOU ARE HERE
        ↑               THE EMPTY LAYER
        ↑
Layer 2 → A2A           Agent communication       ✓ Exists
        ↑
Layer 1 → MCP           Agent-to-tool             ✓ Exists
```

**Agents can talk. Agents can pay. Agents cannot safely negotiate commercial terms across organizational boundaries.**

MCP connects agents to their tools. A2A establishes communication between agents. AP2 executes payment. But when a buyer's procurement agent needs to negotiate a contract with a seller's sales agent — two autonomous systems, competing interests, different platforms — there is no protocol for what happens next.

Today it falls back to email. A human clicks a link. Another human responds.

That model breaks the moment both sides deploy agents.

---

## What a bilateral A2CN session looks like

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

Two Python processes. Different organizations. Neither controls the authoritative record. The cryptography proves the agreement — not the platform.

**[Run this yourself →](#quickstart)**

---

## What's new in v0.2.0

### Session Invitation — solving the cold-start problem

The original discovery model required both parties to have independently deployed A2CN endpoints before they could negotiate. v0.2 adds **Component 8: Session Invitation** — a push-based handshake that lets a buyer invite a supplier who has no A2CN endpoint yet.

```
Buyer agent creates a signed SessionInvitation
    → delivers via BID_CREATED webhook / email / Meeting Place
        → Supplier receives, validates signature, accepts
            → Buyer sends standard SessionInit to acceptor's endpoint
                → Normal A2CN session proceeds
```

The invitation is ES256-signed using the inviter's DID key. The supplier can verify authenticity before activating any endpoint. This is the integration pattern for Fairmarkit and other procurement platforms that use supplier webhooks.

### Platform integration adapters

**Fairmarkit:** `FairmakitEventParser` translates `BID_CREATED` webhook payloads into A2CN `goods_procurement` terms and translates agreed terms back into Fairmarkit's response API format for `POST /self-service/api/v3/responses/...`. Path B integration — zero Fairmarkit platform changes required.

**Salesforce Revenue Cloud:** `RevenueCloudAdapter` translates Revenue Cloud Pricing API responses (`/connect/pricing/...`) into A2CN offer terms, and translates agreed terms from the transaction record into Revenue Cloud order payloads (`/connect/qoc/sales-transactions`).

### Deal-type-specific terms schemas

Two registered deal types now have normative JSON schemas:
- `goods_procurement` — adds `delivery_days`, `unit_of_measure`, manufacturer and internal part numbers
- `saas_renewal` — adds `seat_count`, `subscription_tier`, `support_tier`, `auto_renew_terms`, `uptime_sla_percent`

### Impasse detection

`impasse_threshold` field in `session_params`. When N consecutive rounds show less than 0.5% movement in `total_value`, the session transitions to `IMPASSE`. Default N = 3, configurable 1–10.

### Webhooks required at Level 2

Webhook callbacks on all terminal state transitions (`COMPLETED`, `REJECTED_FINAL`, `WITHDRAWN`, `IMPASSE`, `TIMED_OUT`) promoted from RECOMMENDED to REQUIRED for Level 2 conformance. Async delivery with exponential backoff retry.

---

## What A2CN covers

| Component | What it defines |
|-----------|----------------|
| **Discovery** | `/.well-known/a2cn-agent` — how agents find each other and advertise capabilities |
| **Mandate verification** | Cryptographic proof an agent has authority to commit (W3C DIDs, two-tier system) |
| **Session Invitation** *(v0.2)* | Push-based pre-session handshake for parties without deployed endpoints |
| **Offer exchange** | Canonical schema for offers, counteroffers, acceptances, rejections, withdrawals |
| **Deal-type terms** *(v0.2)* | Normative schemas for `goods_procurement` and `saas_renewal` |
| **Session state machine** | Phases, turn-taking, round limits, timeouts, impasse detection |
| **Transaction record** | Immutable, content-addressed, dual-signed by both parties |
| **Audit log** | Structured EU AI Act compliance output for every terminal session state |

### What A2CN is not

- A negotiation strategy or pricing engine — those stay inside each party's system
- A platform or SaaS product
- A competitor to MCP, A2A, UCP, or AP2 — complementary to all of them
- Controlled by any single commercial entity

---

## Quickstart

```bash
git clone https://github.com/A2CN-protocol/A2CN.git
cd A2CN/reference-implementation/python
pip install -e .

# SaaS renewal demo (4-round bilateral negotiation)
python examples/saas_renewal.py

# Goods procurement with goods_procurement terms schema
python examples/saas_renewal.py --deal-type goods_procurement

# Session Invitation flow (Fairmarkit integration pattern)
# Terminal 1:
uvicorn server:app --port 8002
# Terminal 2:
python examples/invitation_flow.py
```

**Requirements:** Python 3.11+

### Run the test suite

```bash
pip install -r requirements.txt
pytest tests/ -v
# 124 passed, 1 skipped
```

---

## The Fairmarkit integration in under 60 seconds

Fairmarkit fires a `BID_CREATED` webhook when a buyer invites a supplier to a sourcing event. Here is what happens when the supplier has an A2CN agent:

```python
from adapters.fairmarkit_adapter import FairmakitEventParser

# 1. Fairmarkit fires BID_CREATED to your webhook endpoint
bid_created_payload = {
    "request_id": "req-001",
    "items": [
        {"description": "Hydraulic fluid 200L", "quantity": 50,
         "uom": "EA", "unit_price": 360.0}
    ],
    "deadline": "2026-04-10T17:00:00Z"
}

# 2. Parse into A2CN goods_procurement terms
terms = FairmakitEventParser.bid_created_to_goods_procurement_terms(bid_created_payload)
# → {total_value: 1800000, currency: "USD", line_items: [...], delivery_days: 14}

# 3. Negotiate via A2CN session...

# 4. Translate agreed terms back to Fairmarkit response format
response = FairmakitEventParser.terms_to_fairmarkit_response(
    agreed_terms, session_id="a2cn-sess-001", request_id="req-001"
)
# → POST /self-service/api/v3/responses/request/req-001/
```

No Fairmarkit platform changes required. Full end-to-end demo: `examples/invitation_flow.py`.

---

## Protocol stack integration

```
Fairmarkit / Pactum / Zip        Salesforce Revenue Cloud / Dynamics 365
(buyer-side platforms)           (seller-side platforms)
         ↓                                   ↓
         └──────── A2CN session ─────────────┘
                        ↓
              Transaction Record
              (dual-signed, content-addressed)
                        ↓
              ───────────┴───────────
            AP2                 Luminance
         (payment)           (contract formalization)
```

A2CN fits between the platforms that generate offers and the infrastructure that executes payment and formalizes contracts. Neither side needs to change their internal pricing logic or CRM workflow — A2CN is the exchange layer in between.

---

## The spec

Full protocol specification: [`spec/a2cn-spec-v0.2.0.md`](spec/a2cn-spec-v0.2.0.md) — 3,300+ lines covering eight protocol components with normative JSON schemas, platform integration patterns for Fairmarkit, Salesforce Revenue Cloud, Dynamics 365, Luminance, and A2A, and a complete four-round SaaS renewal walkthrough with concrete message envelopes.

**Spec status:** v0.2.0. Passed four independent critique cycles. Verified against reference implementation (124 tests).

---

## Repository structure

```
A2CN/
├── spec/
│   ├── a2cn-spec-v0.2.0.md         # Protocol specification (current)
│   └── schemas/                     # Normative JSON schemas
│       └── terms/
│           ├── goods_procurement.schema.json
│           └── saas_renewal.schema.json
└── reference-implementation/
    └── python/
        ├── crypto.py                # JCS, SHA-256, ES256 signing
        ├── did.py                   # did:web resolution
        ├── messages.py              # Wire-format dataclasses
        ├── session.py               # State machine + turn enforcement
        ├── record.py                # Deterministic transaction records
        ├── invitation.py            # Component 8: Session Invitation
        ├── server.py                # FastAPI responder (all endpoints)
        ├── client.py                # Initiator with JCS+JWS offer signing
        ├── adapters/
        │   ├── fairmarkit_adapter.py    # Fairmarkit → A2CN translation
        │   └── revenue_cloud_adapter.py # Revenue Cloud → A2CN translation
        ├── tests/
        │   ├── test_invitations.py
        │   ├── test_deal_type_terms.py
        │   ├── test_adapters.py
        │   └── conformance/
        └── examples/
            ├── saas_renewal.py          # Bilateral SaaS renewal demo
            └── invitation_flow.py       # Session Invitation / Fairmarkit demo
└── sdk/                                 # SDK (planned)
```

---

## Current status

| Milestone | Status |
|-----------|--------|
| Protocol spec v0.2.0 | ✓ Complete — 3,300+ lines, 8 components |
| Reference implementation (Python) | ✓ Complete — 124 tests passing |
| Session Invitation (Component 8) | ✓ Complete — signed invitations, lifecycle, hosted endpoint pattern |
| Platform adapters | ✓ Complete — Fairmarkit, Salesforce Revenue Cloud |
| End-to-end bilateral demo | ✓ Working — matching record hashes |
| Invitation flow demo | ✓ Working — Fairmarkit BID_CREATED pattern |
| Security review | ✓ Passed — 0 critical, 0 high findings |
| Deal type registry | ✓ Published — `a2cn.dev/registry/deal-types` |
| A2A extension proposal | 🔄 In progress |
| Meeting Place (neutral transaction hosting) | 📋 Planned — v0.3 |
| TypeScript reference implementation | 📋 Planned |
| SDK (pip + npm) | 📋 Planned |

---

## Who we are looking for

**Platform engineers** at procurement or sales automation companies who have hit the cross-platform agent interoperability problem. If your agent falls back to email when the supplier also has an agent — this is for you.

**Developers building on LangChain, CrewAI, Salesforce Agentforce, or Microsoft Copilot Studio** with agents that need to interact with counterparty agents across organizational boundaries.

**Protocol and distributed systems engineers** interested in open standards work. The cryptographic design, session state machine, and deterministic record generation all have interesting problems. Open issues tagged [`help wanted`](https://github.com/A2CN-protocol/A2CN/issues?q=label%3A%22help+wanted%22) and [`good first issue`](https://github.com/A2CN-protocol/A2CN/issues?q=label%3A%22good+first+issue%22).

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

> *Agents will transact. The question is where they meet and who built the ground beneath them.*
