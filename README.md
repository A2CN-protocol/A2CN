# A2CN — Agent-to-Agent Commercial Negotiation Protocol

**The missing protocol layer for machine-to-machine B2B commerce.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Spec Version](https://img.shields.io/badge/Spec-v0.1.3-green.svg)](spec/v0.1.3.md)
[![Tests](https://img.shields.io/badge/Tests-77%20passing-brightgreen.svg)](reference-implementation/python/tests)
[![Status](https://img.shields.io/badge/Status-Reference%20Implementation%20Complete-orange.svg)]()

---

## The gap in the agent protocol stack

```
Layer 4 │ AP2 / x402    Payment execution        ✓ Exists
        │
Layer 3 │ A2CN          Commercial negotiation   ← YOU ARE HERE
        │               THE EMPTY LAYER
        │
Layer 2 │ A2A           Agent communication       ✓ Exists
        │
Layer 1 │ MCP           Agent-to-tool             ✓ Exists
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

## What makes this different

### Every offer is cryptographically signed

```json
{
  "message_type": "offer",
  "round_number": 1,
  "sequence_number": 1,
  "sender_did": "did:web:techcorp.example",
  "terms": {
    "total_value": 9500000,
    "currency": "USD",
    "payment_terms": { "net_days": 30 }
  },
  "protocol_act_hash": "CAJSH5sTyYzmlaF9ULieuH1aHSr8ABp14MUS8WF7_Jg",
  "protocol_act_signature": "eyJhbGciOiJFUzI1NiIs..."
}
```

JCS canonicalization (RFC 8785) + ES256 signing. Cross-session and cross-round replay attacks are structurally prevented. Both parties verify every message against the sender's DID document.

### Both sides independently generate the same transaction record

```python
# Buyer generates their record
buyer_record = client.build_record()

# Seller generates their record  
seller_record = server.generate_record()

# Neither side communicated after acceptance
assert buyer_record["record_hash"] == seller_record["record_hash"]  # ✓ passes
```

UUID v5 determinism. JCS-canonicalized offer chain hash. `generated_at` derived from the Acceptance message timestamp — not a local clock. Both parties derive the identical record independently.

### Agents can't go rogue

The session state machine enforces strict turn-taking. An agent that sends an out-of-turn message gets `NOT_YOUR_TURN`. An agent that tries to accept an expired offer gets `OFFER_EXPIRED`. Sessions that exceed their round limit terminate cleanly. The protocol governs the conversation — negotiation strategy stays inside each party's system.

---

## What A2CN covers

| Component | What it defines |
|-----------|----------------|
| **Discovery** | `/.well-known/a2cn-agent` — how agents find each other and advertise capabilities |
| **Mandate verification** | Cryptographic proof an agent has authority to commit (W3C DIDs, two-tier system) |
| **Offer exchange** | Canonical schema for offers, counteroffers, acceptances, rejections, withdrawals |
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
python -m pip install -e .
python examples/saas_renewal.py
```

Watch two agents complete a four-round SaaS renewal negotiation and verify the matching transaction record — in under 30 seconds.

**Requirements:** Python 3.11+

### Run the test suite

```bash
pip install -r requirements.txt
pytest tests/ -v
# 77 passed, 1 skipped (JWT auth — Week 2)
```

---

## The spec

The full protocol specification is at [`spec/v0.1.3.md`](spec/v0.1.3.md) — 2,800+ lines covering all six components with normative JSON schemas, a complete four-round SaaS renewal walkthrough with concrete message envelopes, and a formal session state machine.

**Spec status:** v0.1.3. Passed four independent critique cycles. Two reviewers independently confirmed that two engineering teams can implement against this spec and interoperate without out-of-band coordination.

### Protocol stack position

```
A2A establishes the session
       ↓
A2CN governs the commercial exchange
       ↓
AP2 executes payment after agreement
```

---

## Repository structure

```
A2CN/
├── spec/
│   └── v0.1.3.md              # The protocol specification
├── reference-implementation/
│   └── python/
│       ├── a2cn/
│       │   ├── crypto.py      # JCS, SHA-256, ES256 signing
│       │   ├── did.py         # did:web resolution
│       │   ├── messages.py    # Wire-format dataclasses
│       │   ├── session.py     # State machine + turn enforcement
│       │   ├── record.py      # Deterministic transaction records
│       │   ├── server.py      # FastAPI responder (all §11.1.1 endpoints)
│       │   └── client.py      # Initiator with JCS+JWS offer signing
│       ├── tests/
│       │   └── conformance/   # Conformance test suite
│       └── examples/
│           └── saas_renewal.py  # Appendix B walkthrough as running code
└── sdk/                       # SDK (in progress)
```

---

## Current status

| Milestone | Status |
|-----------|--------|
| Protocol spec v0.1.3 | ✅ Complete |
| Reference implementation (Python) | ✅ Complete — 77 tests passing |
| End-to-end bilateral demo | ✅ Working — matching record hashes |
| Security review | ✅ Passed — 0 critical, 0 high findings |
| JWT authentication (Week 2) | 🔄 In progress |
| TypeScript reference implementation | 📋 Planned |
| SDK (pip + npm) | 📋 Planned |
| Meeting Place (neutral transaction hosting) | 📋 Planned — v0.2 |

---

## Who we are looking for

**Platform engineers** building procurement or sales agents who have hit the cross-platform interoperability problem. If your agent falls back to email when the other side also has an agent — this is for you.

**Protocol and distributed systems engineers** interested in open standards work. The spec design, cryptographic primitives, and state machine all have interesting problems. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) — open issues are tagged [`help wanted`](https://github.com/A2CN-protocol/A2CN/issues?q=is%3Aissue+label%3A%22help+wanted%22) and [`good first issue`](https://github.com/A2CN-protocol/A2CN/issues?q=is%3Aissue+label%3A%22good+first+issue%22).

**Developers building on LangChain, CrewAI, or Google ADK** with agents that need to interact with counterparty agents across organizational boundaries.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

> *Agents will transact. The question is where they meet and who built the ground beneath them.*
