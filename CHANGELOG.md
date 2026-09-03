# Changelog

Release history for the A2CN protocol repository — the specification, the Python
reference implementation, and the TypeScript reference implementation, which are
versioned and released together.

This file tracks the **release** version. A2CN versions three things independently;
see [Three version axes](spec/README.md#three-version-axes) for the full table.

| Axis | Current |
|------|---------|
| Release | `0.3.0` |
| Spec / wire protocol (`protocol_version`, `a2cn_version`) | `0.2` |
| `record_version` — TransactionRecord / AuditLog / SessionEvidenceRecord | `0.1` / `0.1` / `0.1` |

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0: the minor version moves for substantive additions.

---

## [Unreleased]

**Three additive Session Evidence Record extensions (wire-compatible with 0.2;
no signature changes).**

`record_version` stays `"0.1"` and the schema `$id` stays at `/0.1`. Changes 1
and 3 are relaxations, so a verifier predating them rejects the new records.
Amending in place is defensible only because the artifact has no external
consumers yet; see Section 9A.2. **This choice requires confirmation before
release.** The alternative is to bump `record_version` and `$id` to `0.2`
together, with verifiers accepting `{0.1, 0.2}`.

### Added

- **Section 9A.8 — identity-light responders.** `parties.responder` may be an
  `observed_party`: a producer-asserted, unverified descriptor for a counterparty
  with no A2CN identity. A verifier never resolves or authenticates it. Such a
  record must be `unilateral` and no act other than the initiator's may claim a
  verified signature. `acts[].sender_did` may be `null`, and only for an unsigned
  observation, so that no DID is ever fabricated.
- **Section 9A.9 — recomputable `money_basis`.** An optional per-act or terminal
  basis carrying the amounts as observed, so a reader can recompute the total.
  The recompute is unit normalization only: `basis` is a checked label and a
  verifier never converts between net and gross. A claimed total with absent raw
  amounts fails closed.
- **Section 9A.10 — `HALTED_BY_CONTROLS` terminal outcome.** An agent's own
  controls or governance stopped the run, distinct from `ERROR`, `IMPASSE`, and
  `WITHDRAWN`. An evidence-record outcome only; no session state is added.
  Unrecognized outcomes are still rejected.
- **Section 9A.11 — namespaced `extensions`.** The only place additional
  properties are permitted. Sealed by `record_hash`, never interpreted.
- `spec/test-vectors/session-evidence-record-extensions.json` — cross-language
  parity vectors covering all three extensions.

## [0.3.0] — 2026-09-02

**Terminal Session Evidence Record (additive; wire-compatible with 0.2; no
`record_version` or signature changes).**

### Added

- **Section 9A — `SessionEvidenceRecord`.** A producer-sealed evidence package for
  *any* terminal session outcome, not only accepted ones. This closes the gap where
  a session that ended in `REJECTED_FINAL`, `WITHDRAWN`, `IMPASSE`, or `TIMED_OUT`
  left no verifiable artifact behind. Evidence is classified as `bilateral`,
  `mixed`, or `unilateral`; sealing an unsigned observed act protects bundle
  integrity but does **not** attribute that act to the named counterparty.
- `GET /sessions/{session_id}/evidence` — terminal-only, party-authorized, in both
  reference implementations.
- Normative `spec/schemas/session-evidence-record.schema.json`
  (`$id` `.../session-evidence-record/0.1`).
- A cross-language hash vector, `spec/test-vectors/session-evidence-record-parity.json`.
- `evidence.py` and `evidence.ts` implementing generation and strict verification,
  including mandatory rejection of an unrecognized `record_version`.

### Changed

- Nothing on the wire, and nothing inside any hashed or signed byte range.

### Compatibility

`0.3.0` is **fully wire-compatible with `0.2`**. A `0.2` peer and a `0.3.0` peer
interoperate without changes. Specifically:

- `protocol_version` and `a2cn_version` remain `"0.2"`. The wire version moves only
  on a wire-incompatible change (spec, *Status of This Document*), and this release
  changed no wire message. `protocol_version` is the first field of the signed
  protocol act, so holding it fixed is what keeps every existing signature,
  `protocol_act_hash`, `offer_chain_hash`, `record_hash`, and parity vector valid.
- No `record_version` moved. `TransactionRecord` and `AuditLog` are byte-identical
  to `0.2.0` — their generation code was untouched. `SessionEvidenceRecord` is new,
  so `"0.1"` is its initial version.
- No schema `$id` moved. A schema's `$id` versions the thing it describes, so
  message schemas stay at `/0.2` and `session-evidence-record` is correctly at
  `/0.1` (Section 9A.1).
- The spec document remains `spec/a2cn-spec-v0.2.0.md`. It specifies wire `0.2`,
  which has not moved, and keeping the filename keeps published links and external
  bookmarks working.

### Upgrading

Update the dependency; there is nothing else to do. Producing or consuming
`SessionEvidenceRecord` is opt-in — existing negotiation, record, and audit-log
code paths are unaffected.

---

## [0.2.0] — 2026-03-26

### Added

- **Component 8 — Session Invitation.** Push-based pre-session handshake: a signed
  `SessionInvitation` delivered by webhook, HTTP, or a neutral relay, with hosted
  endpoint provisioning for suppliers without their own server.
- Normative deal-type terms schemas for `goods_procurement` and `saas_renewal`.
- Impasse detection (`IMPASSE` terminal state) after consecutive non-moving rounds.
- Post-commitment lifecycle: `delivery_notice`, `delivery_acknowledged`,
  `dispute_notice`, `dispute_resolved` — normative at Level 3.
- Platform integration patterns (Section 16) and the A2CN MCP server.

### Changed

- Webhooks became REQUIRED at Level 2 conformance.
- Wire protocol version moved `0.1` → `0.2` (wire-incompatible).

---

## [0.1.3] — 2026-03-24

Verification method precedence; DID session-duration binding; sender retry;
timeout immutability.

## [0.1.2] — 2026-03-24

Fixed namespace UUID; JSON schemas became normative.

## [0.1.1] — 2026-03-24

RFC 8785 JCS canonicalization; full protocol act signing; DID trust root;
strict turn-taking.

## [0.1-draft] — 2026-03-24

Initial draft.

[0.3.0]: https://github.com/A2CN-protocol/A2CN/releases/tag/v0.3.0
[0.2.0]: https://github.com/A2CN-protocol/A2CN/releases/tag/v0.2.0
