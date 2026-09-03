# A2CN Protocol Specification

**The formal definition of the A2CN protocol.**

[![Release](https://img.shields.io/badge/Release-0.3.0-green.svg)](../CHANGELOG.md)
[![Spec](https://img.shields.io/badge/Spec-v0.2.0-blue.svg)](a2cn-spec-v0.2.0.md)
[![Wire protocol](https://img.shields.io/badge/Wire%20protocol-0.2-blue.svg)](a2cn-spec-v0.2.0.md#status-of-this-document)
[![Status](https://img.shields.io/badge/Status-Draft%20%E2%80%94%20Feedback%20Welcome-yellow.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)
[![Schemas](https://img.shields.io/badge/JSON%20Schemas-Normative-brightgreen.svg)](schemas/)

---

## Three version axes

A2CN versions three different things independently. Reading one as another is the
most common source of confusion, so they are named separately here.

| Axis | Current | What it is | When it moves |
|------|---------|------------|---------------|
| **Release** | `0.3.0` | The published package and repository release (`pyproject.toml`, `package.json`, git tag). | Any shipped change, additive or not. See [CHANGELOG](../CHANGELOG.md). |
| **Spec / wire protocol** | `0.2` | The on-the-wire contract: the `protocol_version` and `a2cn_version` fields, and the `$id` of every message schema. | Only on a **wire-incompatible** change. See [Status of This Document](a2cn-spec-v0.2.0.md#status-of-this-document). |
| **`record_version`** | TransactionRecord `0.1`<br>AuditLog `0.1`<br>SessionEvidenceRecord `0.1` | The version of each terminal artifact, carried inside its own hashed bytes. Each artifact has its **own** line. | Only when that artifact's shape or canonical meaning changes (Section 9A.1). |

A schema's `$id` version is the version of the **thing the schema describes** — the
wire version for wire messages, the `record_version` for record artifacts. This is
why `session-evidence-record/0.1` sits alongside `session-invitation/0.2`: both are
correct, because they version different things.

Release `0.3.0` is additive and fully wire-compatible with `0.2`: a `0.2` peer and a
`0.3.0` peer interoperate, and every signature, hash, and test vector produced under
`0.2` remains valid.

---

## What this directory contains

| File | Description |
|------|-------------|
| [`a2cn-spec-v0.2.0.md`](a2cn-spec-v0.2.0.md) | **Current spec** — 3,300+ lines, eight protocol components |
| [`schemas/`](schemas/) | Normative JSON schemas for all message types |
| [`schemas/terms/`](schemas/terms/) | Deal-type-specific terms extensions |
| [`test-vectors/`](test-vectors/) | Deterministic cross-language cryptographic vectors |

The specification is the authoritative definition. The [reference implementation](../reference-implementation/python) is the authoritative example of correct behavior. When they disagree, the spec wins.

---

## The eight protocol components and terminal artifacts

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

### 6A — Session evidence record
Each producer can seal the complete signed and unsigned evidence available for any terminal session. Evidence is classified as `bilateral`, `mixed`, or `unilateral`; sealing an unsigned observation protects bundle integrity but does not attribute that act to the named counterparty.

### 7 — Audit log
Structured compliance trace for all terminal states. EU AI Act structured export can compose with a neutral third-party record custodian.

### 8 — Session Invitation *(v0.2)*
Push-based pre-session handshake. Buyer creates a signed `SessionInvitation`, delivers via webhook/HTTP/neutral invitation relay. Supplier validates ES256 signature, accepts, provides their endpoint. Buyer proceeds with standard `SessionInit`. Includes hosted endpoint provisioning pattern for suppliers without their own server.

---

## Conformance levels

| Level | What it covers |
|-------|---------------|
| **Level 1 — Core** | Discovery, session, offer exchange with signing, state machine, idempotency. Declared mandates only. |
| **Level 2 — Full** | Level 1 + DID VC mandates, transaction record, Session Evidence Record, audit log, **webhooks (required)**. |
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
| **A2A** | A2CN extension URI `https://a2cn.io/extensions/commercial-negotiation/v1`; A2CN / Concordia / BidAngel substrate split |
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
| OQ-011 | A2CN as A2A extension | Open — profile scoped |
| OQ-012 | Multi-party invitation | Open |

[→ GitHub issues tagged `open-question`](https://github.com/A2CN-protocol/A2CN/issues)

---

## Spec history

Spec document versions, which track the wire protocol — not the release version. For release history (including `0.3.0`), see the [CHANGELOG](../CHANGELOG.md).

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
