# A2CN Protocol Specification

**The formal definition of the A2CN protocol.**

[![Spec Version](https://img.shields.io/badge/Version-0.2.0-green.svg)](a2cn-spec-v0.2.0.md)
[![Status](https://img.shields.io/badge/Status-Draft%20%E2%80%94%20Feedback%20Welcome-yellow.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)
[![Schemas](https://img.shields.io/badge/JSON%20Schemas-Normative-brightgreen.svg)](schemas/)

---

## What this directory contains

| File | Description |
|------|-------------|
| [`a2cn-spec-v0.2.0.md`](a2cn-spec-v0.2.0.md) | **Current spec** — 3,300+ lines, eight protocol components |
| [`schemas/`](schemas/) | Normative JSON schemas for all message types |
| [`schemas/terms/`](schemas/terms/) | Deal-type-specific terms extensions |

The specification is the authoritative definition. The [reference implementation](../reference-implementation/python) is the authoritative example of correct behavior. When they disagree, the spec wins.

---

## The eight protocol components

### 1 — Discovery
`GET /.well-known/a2cn-agent` returns a discovery document advertising deal types, mandate methods, conformance level, and the DID for key resolution.

### 2 — Mandate verification
Two-tier system: Tier 1 (Declared) for routine spend; Tier 2 (W3C DID VC) for high-value deals above the counterparty's declared threshold.

### 3 — Session initiation
`SessionInit` → `SessionAck`. Deal type, currency, and timeout parameters are immutable for session lifetime.

### 4 — Offer exchange
Signed offers with `protocol_act_hash = SHA-256(JCS(protocol_act))` covering all nine envelope fields. Prevents cross-session and cross-round replay. v0.2 adds normative terms schemas for `goods_procurement` and `saas_renewal`.

### 5 — Session state machine
Strict turn-taking, strict sequence ordering, impasse detection. States: `PENDING → ACTIVE → NEGOTIATING → COMPLETED / REJECTED_FINAL / WITHDRAWN / IMPASSE / TIMED_OUT / ERROR`.

### 6 — Transaction record
Both parties independently generate an identical record after acceptance. Determinism: `record_id` = UUID v5, `generated_at` = Acceptance timestamp, `record_hash` = SHA-256(JCS(record)).

### 7 — Audit log
Structured compliance trace for all terminal states. EU AI Act structured export available via Meeting Place (v0.3).

### 8 — Session Invitation *(v0.2)*
Push-based pre-session handshake. Buyer creates a signed `SessionInvitation`, delivers via webhook/HTTP/Meeting Place. Supplier validates ES256 signature, accepts, provides their endpoint. Buyer proceeds with standard `SessionInit`. Includes hosted endpoint provisioning pattern for suppliers without their own server.

---

## Conformance levels

| Level | What it covers |
|-------|---------------|
| **Level 1 — Core** | Discovery, session, offer exchange with signing, state machine, idempotency. Declared mandates only. |
| **Level 2 — Full** | Level 1 + DID VC mandates, transaction record, audit log, **webhooks (required)**. |
| **Level 3 — Extended** | Level 2 + Session Invitation, impasse detection, MESO terms, all RECOMMENDED behaviors. |

Protocol act signing is required at **all levels**.

---

## Platform integration (Section 16)

| Platform | Key integration point |
|----------|-----------------------|
| **Fairmarkit** | `BID_CREATED` webhook → Session Invitation; response API for agreed terms |
| **Salesforce Revenue Cloud** | `/connect/pricing/...` → offer terms; agreed terms → `/connect/qoc/sales-transactions` |
| **Microsoft Dynamics 365** | `api_invoke_action: NegotiationResponseCalculator` via ERP MCP Server |
| **Luminance** | A2CN transaction record → contract formalization input |
| **A2A** | A2CN as A2A profile/method extension (OQ-011, proposal filed) |
| **AP2** | A2CN transaction record → AP2 Intent Mandate |

---

## Open questions

| ID | Question | Status |
|----|----------|--------|
| OQ-001 | Deal type registry | **RESOLVED v0.2** |
| OQ-004 | Deal-type terms schemas | **RESOLVED v0.2** |
| OQ-005 | Impasse threshold | **RESOLVED v0.2** |
| OQ-009 | Platform DID proxy model | Open |
| OQ-010 | MESO offers | Open |
| OQ-011 | A2CN as A2A extension | Open — proposal filed |
| OQ-012 | Multi-party invitation | Open |

[→ GitHub issues tagged `open-question`](https://github.com/A2CN-protocol/A2CN/issues)

---

## Spec history

| Version | Summary |
|---------|---------|
| **v0.2.0** | Component 8 Session Invitation; deal-type terms schemas; impasse detection; webhooks required at Level 2; platform integration patterns |
| v0.1.3 | Verification method precedence; DID session-duration binding; sender retry; timeout immutability |
| v0.1.2 | Fixed namespace UUID; JSON schemas normative |
| v0.1.1 | RFC 8785 JCS; full protocol act signing; DID trust root; turn-taking |
| v0.1-draft | Initial draft |

---

## License

Apache 2.0. See [LICENSE](../LICENSE).
