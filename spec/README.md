# A2CN Protocol Specification

**The formal definition of the A2CN protocol.**

[![Spec Version](https://img.shields.io/badge/Version-0.1.3-green.svg)](v0.1.3.md)
[![Status](https://img.shields.io/badge/Status-Draft%20%E2%80%94%20Feedback%20Welcome-yellow.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)
[![Schemas](https://img.shields.io/badge/JSON%20Schemas-Normative-brightgreen.svg)](schemas/)

---

## What this directory contains

| File | Description |
|------|-------------|
| [`v0.1.3.md`](v0.1.3.md) | **Current spec** — 2,800+ lines, all six protocol components |
| [`schemas/`](schemas/) | Normative JSON schemas for all message types |

The specification is the authoritative definition of the A2CN protocol. The [reference implementation](../reference-implementation/python) is the authoritative example of correct behavior. When they disagree, the spec wins.

---

## The six protocol components at a glance

A2CN defines exactly what is needed for two agents from different organizations to negotiate a commercial deal machine-to-machine — and nothing more.

### 1 — Discovery

An agent determines whether its counterparty is A2CN-capable by fetching:

```
GET https://counterparty.example/.well-known/a2cn-agent
```

```json
{
  "a2cn_version": "0.1",
  "conformance_level": 2,
  "organization": { "name": "Acme Corp", "did": "did:web:acme-corp.com" },
  "endpoint": "https://acme-corp.com/api/a2cn",
  "deal_types": ["saas_renewal", "goods_procurement"],
  "mandate_methods": ["declared", "did_vc"],
  "verification_method": "did:web:acme-corp.com#key-2026-01",
  "value_thresholds": { "high_value_minimum": 5000000, "high_value_currency": "USD" }
}
```

The discovery document is not the trust anchor. All signing keys are retrieved by resolving the organization's DID document — a separate HTTPS fetch to `did:web:acme-corp.com`. This decouples capability advertisement from cryptographic identity.

---

### 2 — Mandate verification

Before negotiating, each agent proves it has authority to commit its organization to the deal. A2CN uses a two-tier system:

```
Does deal value exceed counterparty's value_thresholds.high_value_minimum?
         │
    No ──┴── Tier 1: Declared Mandate
    │        Agent self-asserts scope. Recorded for audit.
    │        Used for routine procurement below threshold.
    │
    Yes ─── Tier 2: DID VC Mandate
             W3C Verifiable Credential issued by principal org's DID.
             Cryptographic proof of delegated authority.
             Used for strategic spend above threshold.
```

Mandate tier requirements are determined by the **counterparty's** declared threshold — not the agent's own. This asymmetry is intentional and explicitly handled.

---

### 3 — Session initiation

The initiator sends a `SessionInit`. The responder validates the mandate and replies with `SessionAck`.

```
POST /sessions
Content-Type: application/a2cn+json

{
  "message_type": "session_init",
  "message_id": "ea0cdeb5-...",
  "session_params": {
    "deal_type": "saas_renewal",
    "currency": "USD",
    "max_rounds": 4,
    "session_timeout_seconds": 3600,
    "round_timeout_seconds": 900
  },
  "initiator": { "did": "did:web:techcorp.example", ... },
  "initiator_mandate": { "mandate_type": "declared", ... }
}
```

The `session_id` returned in the `SessionAck` anchors all subsequent messages. Parameters agreed at initiation — `deal_type`, `currency`, `session_timeout_seconds`, `round_timeout_seconds` — are immutable for the session lifetime.

---

### 4 — Offer exchange

Offers are **typed, structured, and cryptographically signed**. This is the core of what A2CN adds over natural language agent communication.

```json
{
  "message_type": "offer",
  "round_number": 1,
  "sequence_number": 1,
  "sender_did": "did:web:techcorp.example",
  "expires_at": "2026-03-25T21:55:11Z",
  "terms": {
    "total_value": 9500000,
    "currency": "USD",
    "line_items": [{ "description": "Acme Analytics Platform — 12 months", "total": 9500000 }],
    "payment_terms": { "net_days": 30 },
    "contract_duration": { "start_date": "2026-07-01", "end_date": "2027-06-30" }
  },
  "protocol_act_hash": "CAJSH5sTyYzmlaF9ULieuH1aHSr8ABp14MUS8WF7_Jg",
  "protocol_act_signature": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

The `protocol_act_hash` is `SHA-256(JCS(protocol_act_object))` where the protocol act covers all nine fields: `protocol_version`, `session_id`, `round_number`, `sequence_number`, `message_type`, `sender_did`, `timestamp`, `expires_at`, `terms`. This prevents cross-session and cross-round replay attacks.

Valid responses to an open offer: **Counteroffer**, **Acceptance**, **Rejection**, **Withdrawal**. Only one response per offer. Counteroffers implicitly reject the prior offer — there is no separate reject-then-counter compound action.

---

### 5 — Session state machine

```
                    ┌─────────┐
        SessionInit │ PENDING │ (server-side only, transitions immediately)
                    └────┬────┘
                         │ SessionAck
                    ┌────▼────┐
                    │ ACTIVE  │ awaiting first offer from initiator
                    └────┬────┘
                         │ First Offer received
                   ┌─────▼──────┐
                   │ NEGOTIATING│ ◄──── Counteroffers cycle here
                   └─────┬──────┘
          ┌──────────────┼──────────────┐
          │              │              │
     ┌────▼────┐  ┌──────▼──────┐ ┌───▼──────┐
     │COMPLETED│  │REJECTED_    │ │WITHDRAWN │
     └─────────┘  │FINAL        │ └──────────┘
                  └─────────────┘
          TIMED_OUT and ERROR also terminal
```

**Strict turn-taking:** Only the current turn holder may send an offer or counteroffer. Out-of-turn messages return `NOT_YOUR_TURN` (409). **Strict sequence ordering:** `sequence_number` must equal `last_processed + 1`. Gaps or reorders return `SEQUENCE_ERROR` (422). Senders MUST retry the current message until they receive HTTP 2xx before sending the next.

---

### 6 — Transaction record

After acceptance, both parties independently generate an identical transaction record. Neither side communicates after the acceptance — the protocol guarantees both records are byte-for-byte equivalent.

```json
{
  "record_type": "a2cn_transaction_record",
  "record_id": "48536f32-ee04-5e61-838a-d6ad0106a042",
  "session_id": "222118e7-7f18-4a20-9fa6-dd35a945e67d",
  "generated_at": "2026-03-25T21:40:11Z",
  "agreed_terms": { "total_value": 10500000, "currency": "USD", ... },
  "final_offer": {
    "protocol_act_hash": "Id6EaTMt0t61Ce9A1ivsYofLXfz8EYbQaY2GgbuvZcc",
    "protocol_act_signature": "eyJhbGciOiJFUzI1NiIs..."
  },
  "final_acceptance": {
    "accepted_protocol_act_hash": "Id6EaTMt0t61Ce9A1ivsYofLXfz8EYbQaY2GgbuvZcc",
    "acceptance_signature": "eyJhbGciOiJFUzI1NiIs..."
  },
  "offer_chain_hash": "t93TFS_KZNWMxNCq9tFS1jp_ufbwQSUee7qpO4M_XTY",
  "record_hash": "jpZQ4AVaFS0d5m9Nl2Falfe92KruMOg_T7CGXh8dp-w"
}
```

**Determinism rules:**
- `record_id` — UUID v5 using A2CN namespace `f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c` with `session_id` as input
- `generated_at` — the `timestamp` field of the Acceptance message, not a local clock
- `offer_chain_hash` — `SHA-256(JCS([hash_1, hash_2, ..., hash_n]))` — the JCS-serialized array of all protocol act hashes in order
- `record_hash` — `SHA-256(JCS(entire_record_object))`

The audit log is generated for all terminal states — not just `COMPLETED`. A rejected or timed-out session also produces a structured compliance trace.

---

## Reading the spec

The full specification is in [`v0.1.3.md`](v0.1.3.md). It is long. Here is the right reading order depending on your goal:

**Building an implementation from scratch:**
Start with Section 3 (Protocol Overview) → Section 8 (Session State Machine) → Section 7 (Offer Exchange) → Section 6 (Session Initiation) → Section 11 (Transport Binding) → Section 12 (Error Handling). Then Appendix B (complete four-round walkthrough with every message envelope shown as concrete JSON).

**Reviewing the cryptographic design:**
Section 4.2 (DID trust model) → Section 5 (Mandate verification) → Section 7.3 (Protocol act signing) → Section 7.4 (Acceptance signature) → Section 9.3 (Transaction record determinism) → Section 13 (Security considerations) → Appendix A (namespace UUID).

**Checking spec compliance of an existing implementation:**
Section 16 (Conformance) defines the three levels and the specific behavioral requirements for each. Then run the conformance test suite at `reference-implementation/python/tests/conformance/`.

**Understanding how A2CN fits with other protocols:**
Section 15 (Relationship to other protocols) covers MCP, A2A, AP2, and UCP with concrete integration patterns.

---

## Conformance levels

All implementations must declare their conformance level in their discovery document.

| Level | What it covers |
|-------|----------------|
| **Level 1 — Core** | Discovery, session initiation, offer exchange with full protocol act signing, session state machine, turn-taking, idempotency. Declared mandates only. |
| **Level 2 — Full** | All Level 1 requirements, plus DID VC mandate verification, transaction record generation, and audit log generation. |
| **Level 3 — Extended** | All Level 2 requirements, plus webhook callbacks, impasse detection, and all RECOMMENDED behaviors. |

**Protocol act signing (RFC 8785 JCS + ES256) is required at ALL conformance levels.** It is not a Level 2 feature.

---

## Error codes

| Code | HTTP | Description |
|------|------|-------------|
| `PROTOCOL_VERSION_MISMATCH` | 400 | Version not supported |
| `MANDATE_INVALID` | 403 | Mandate expired, missing, or VC proof failed |
| `MANDATE_INSUFFICIENT` | 403 | Mandate scope doesn't cover proposed terms |
| `INVALID_SIGNATURE` | 400 | Protocol act signature verification failed |
| `NOT_YOUR_TURN` | 409 | Message sent out of turn |
| `SESSION_WRONG_STATE` | 409 | Message invalid for current session state |
| `SEQUENCE_ERROR` | 422 | Gap or duplicate in sequence_number |
| `OFFER_EXPIRED` | 422 | Acceptance of expired offer attempted |
| `ROUND_LIMIT_EXCEEDED` | 422 | Message would exceed max_rounds |
| `DID_RESOLUTION_FAILURE` | 503 | DID temporarily unresolvable (retry with backoff) |
| `DID_NOT_FOUND` | 403 | DID does not exist (permanent — do not retry) |

Full error code reference with HTTP status codes and permanence classification: [Section 12.2](v0.1.3.md#122-error-code-reference).

---

## Open questions

The spec carries six open questions with stable IDs. Feedback on any of these is particularly valuable:

| ID | Question | Status |
|----|----------|--------|
| OQ-001 | Deal type registry vs. convention | Open — registry in v0.2 |
| OQ-002 | Max value threshold protocol cap | Open — $10K USD equivalent proposed |
| OQ-003 | DID resolver fallback when temporarily unavailable | Open — 24h cache proposed |
| OQ-004 | Deal-type-specific terms schemas | Open — extensions in v0.2 |
| OQ-005 | Configurable impasse threshold | Open — configurable in v0.2 |
| OQ-006 | Neutral transaction record storage | Open — bilateral for v0.1; Meeting Place in v0.2 |

Submit feedback as a [GitHub issue](https://github.com/A2CN-protocol/A2CN/issues) tagged `open-question`.

---

## Spec history

| Version | Date | Summary |
|---------|------|---------|
| **v0.1.3** | 2026-03-24 | Verification method precedence rule; DID session-duration binding; sender retry obligation; timeout parameter immutability; conformance level signing clarification; acceptance signature expanded; changelog structural fixes |
| v0.1.2 | 2026-03-24 | Fixed invalid namespace UUID; clarified rejection+offer round counting; JSON schemas promoted to normative; acceptance signature added; `ACTIVE` state defined; `NEGOTIATING` state introduced |
| v0.1.1 | 2026-03-24 | RFC 8785 JCS adopted; full protocol act signing scope; DID-as-trust-root; JWT anti-replay; turn-taking rules; `NEGOTIATING` state; `NOT_YOUR_TURN` error; deterministic transaction record |
| v0.1-draft | 2026-03-24 | Initial draft for community review |

Full changelog with per-section change detail: [Section 18 of the spec](v0.1.3.md#18-changelog).

---

## Providing feedback

The spec is in active development. The most valuable feedback at this stage:

**From implementers:** Did you encounter ambiguities while building against the spec? Places where two valid readings of the spec would produce different wire behavior? Open an issue with the section number and the ambiguity.

**From protocol engineers:** Are there security considerations or edge cases in Section 13 that are not addressed? Are the cryptographic design choices (P-256, ES256, JCS) appropriate for your deployment context?

**From procurement platform developers:** Does the terms schema in Section 7.2 cover the deal types you need? What additional `deal_types` beyond `saas_renewal` and `goods_procurement` should the spec address in v0.2?

Open issues are welcome. Pull requests against the spec text are welcome. The goal of v0.1 is to reach a state where two independent engineering teams can implement against this spec and interoperate without out-of-band coordination.

[**→ Open a GitHub issue**](https://github.com/A2CN-protocol/A2CN/issues/new)

---

## License

Apache 2.0. See [LICENSE](../LICENSE).
