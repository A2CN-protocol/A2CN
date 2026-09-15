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
| `record_version` — TransactionRecord / AuditLog / SessionEvidenceRecord | `0.2` for a record that carries a basis, `0.1` for one that does not (no basis fixed, or an implementation that predates basis) / `0.1` / `0.2` |

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0: the minor version moves for substantive additions.

---

## [Unreleased]

**Session Evidence Record extensions, at `record_version` `"0.2"`
(wire-compatible with 0.2; no signature changes).**

The SessionEvidenceRecord moves to `record_version` `"0.2"`. Its schema is
published as `session-evidence-record-0.2.schema.json`, with `$id` `/0.2`,
beside the `"0.1"` schema exactly as release 0.3.0 published it; the Sections
9A.8 to 9A.11 additions are in the `"0.2"` schema only. Version `"0.2"` is the
one that introduced Sections 9A.8 to 9A.11 and the Section 9A.9 rule
that a `net` or `gross` `money_basis` agrees with the described act's
`terms.basis`. Sections 9A.8 to 9A.11 are relaxations,
so a verifier that predates them rejects records that use them, and the basis
rule adds a rejection. Producers emit `"0.2"`. Verifiers accept `"0.1"` and
`"0.2"`, apply the same rules to both, and reject any other value;
verification does not depend on the version. They therefore also accept a
`"0.1"` record that uses Sections 9A.8 to 9A.11; no released implementation
produces one, and it does not validate against the `"0.1"` schema.

**Session money basis, `session_params.basis`, restated in `terms.basis` and
recorded in the TransactionRecord at `record_version` `"0.2"` (wire-compatible
with 0.2).** Wire `protocol_version` stays `"0.2"`. The TransactionRecord's
`record_version` follows its content. The record of a session that fixed a
basis carries a top-level `basis`, which its `record_hash` covers, and is
`"0.2"`. The record of a session that fixed none has no `basis` and stays
`"0.1"`, byte-identical to the record an implementation that predates `basis`
generates, so parties on either version derive the same record for it. A party
whose implementation predates `basis` can still take part in a session that
fixed one, when its caller sets `basis` and `terms.basis` and the
implementation passes them through; its TransactionRecord is then a `"0.1"`
record without the top-level `basis`, while a current party's is a `"0.2"`
record with it, so the difference between the two records is explicit in
`record_version`. Verifiers accept `"0.1"` and `"0.2"`, reject any other value,
and hold each version to its shape: a `"0.2"` record carries `basis` and a
`"0.1"` record does not. AuditLog stays at `"0.1"`: its content does not change.
An evidence record for a completed session seals whatever TransactionRecord
hash that session has. The SessionEvidenceRecord stays at `"0.2"` for every
session, because it is sealed by its producer and need not be identical across
parties (Section 9A.2).

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
  parity vectors covering the extensions, and `money_basis_act_basis_cases`,
  where a `money_basis` label agrees with or contradicts the described act's
  `terms.basis`.
- **Section 6.3.1 — `session_params.basis`** (`net` | `gross`). The money basis
  of every amount in a session, fixed at initiation like
  `session_params.currency`. A SessionAck that carries it must carry it
  unchanged; one that omits it, from a responder that predates `basis`, leaves
  the basis unstated rather than failing, so a pre-change responder still
  interoperates (Section 6.4.1). RECOMMENDED for priced sessions now; a later
  version is expected to require it. An absent basis is unstated, and a
  consumer must not assume a default. It is a label: no party converts between
  net and gross. `session-invitation.schema.json` accepts it in
  `proposed_session_params`.
- **Section 7.2 — single-figure offers.** When the session fixed a basis, an
  offer states `terms.total_value` on that basis only, as a single figure.
- **Section 7.2 — `terms.basis`.** Every offer restates the session basis inside
  its signed terms, so the protocol-act signature covers it with no change to
  what is signed (Section 7.3.1). When the session fixed a basis, `terms.basis`
  is required and must equal it; when the session fixed none, it must be absent.
  A missing, different, or added `terms.basis` is rejected with
  `SESSION_PARAM_CHANGED`, and a value outside `net` | `gross` (including
  `null`) with `INVALID_BASIS`. Both reference implementations check it on every
  offer and counteroffer they receive, after signature verification and before
  any state changes. Their clients also check `terms.currency` and `terms.basis`
  on each offer or counteroffer they receive, before recording it; on each offer
  they send, before the round and sequence advance, so a refused offer can be
  corrected and resent in the same round; and on the offer they are accepting,
  before signing. The reference MCP servers record a counterparty offer only
  after the client has taken it, so a refused counteroffer is never reported or
  accepted. `TermsObject` takes an optional `basis`; the reference clients send
  terms as given and do not insert it.
- **Section 9.3 — TransactionRecord `basis`.** Beside `currency`, present exactly
  when the session fixed a basis, and equal to `agreed_terms.basis`. A record
  that carries it is `record_version` `"0.2"`; the record of a session that fixed
  no basis carries none and stays `"0.1"`.
- **Section 9.5 — verification step 1.** A TransactionRecord verifier accepts
  `record_version` `"0.1"` or `"0.2"` and rejects any other value, including an
  absent, `null`, or non-string one. Before, it did not check `record_version`.
  The later steps are renumbered.
- **Section 9.5 — verification step 7.** A record carries a top-level `basis`
  exactly when it is `"0.2"`. A `"0.2"` record verifies only if its `basis` is
  `net` or `gross` and `agreed_terms.basis` is present and equal to it; a
  `"0.2"` record without `basis` is rejected, whatever `agreed_terms` holds. A
  `"0.1"` record verifies only if it has no top-level `basis` key, not even a
  `null` one; its `agreed_terms.basis` is not checked, since an implementation
  that predates the field records it there alone.
- **Section 9A.9 — a `money_basis` agrees with the act's basis.** A
  `money_basis` describing an on-basis total SHOULD carry the session basis.
  When the described act's `terms` carries `basis` and `money_basis.basis` is
  `net` or `gross`, the two must be equal: the generator refuses such a record
  and the verifier rejects it, exactly as for `currency`, for per-act and
  terminal `money_basis` alike. `per_unit`, `line_total`, and `unspecified` are
  not compared, and an act without `terms.basis` gets no comparison. Labels are
  compared, never converted.
- **Section 12.3 — `INVALID_BASIS`, `SESSION_PARAM_CHANGED`, and
  `INVALID_REQUEST`.** Dedicated error codes for a `basis` outside `net` |
  `gross`, and for a message that changes a parameter fixed at session
  initiation; the error's `message` names the parameter. `INVALID_REQUEST`,
  which the reference implementations already returned, is now defined: a
  message, or a required part of it, is malformed before any protocol check
  runs.
- `spec/test-vectors/session-params-basis.json` — cross-language vectors for the
  basis enum, for SessionAcks that keep or change `currency` or `basis` or carry
  a malformed one, and for offers whose `terms.currency` or `terms.basis`
  matches, omits, adds, or changes the session value.
- `spec/test-vectors/transaction-record-basis.json` — a cross-language
  TransactionRecord vector for a session that fixed a basis, with a tampered
  negative and the evidence record that seals it; and a session that fixed none,
  whose record is exactly the `"0.1"` record an implementation that predates
  `basis` produced for it. Each record relabelled to the other version fails
  verification.
- `spec/test-vectors/record-versions.json` — the `record_version` values a
  TransactionRecord or SessionEvidenceRecord verifier accepts (`"0.1"`, `"0.2"`)
  and values it must reject, including `"0.3"`, `""`, `"0.2 "`, the number
  `0.2`, `null`, and an absent key; the TransactionRecord version producers emit
  for a session with and without a basis; and each recognized version on the
  other record shape, which fails.
- `spec/conformance-fixtures/offer_basis_diverges_from_session.json` and
  `offer_currency_diverges_from_session.json` — an offer whose `terms.basis` or
  `terms.currency` differs from the session value is rejected with
  `SESSION_PARAM_CHANGED`.
- `spec/schemas/transaction-record.schema.json` and
  `transaction-record-0.2.schema.json` — JSON Schemas (draft 2020-12) for the
  TransactionRecord at `record_version` `"0.1"`, which permits no top-level
  `basis`, and `"0.2"`, which requires `basis` in `net` | `gross`, equal to
  `agreed_terms.basis`. Both are closed except `agreed_terms`, the accepted
  offer's terms. Section 9.3's structure now lists the `final_acceptance`
  fields the record carries (`round_number`, `sequence_number`,
  `accepted_offer_id`) and gives `subject_reference` as a string or `null`.
- `spec/schemas/session-evidence-record-0.2.schema.json` — the
  SessionEvidenceRecord schema at `record_version` `"0.2"`, the only schema that
  describes Sections 9A.8 to 9A.11. It is published beside the `"0.1"` schema,
  `session-evidence-record.schema.json`, which stays exactly as release 0.3.0
  published it. A record artifact's unversioned schema file describes its
  `"0.1"` version, each later version is published beside it as
  `<name>-<version>.schema.json`, and a published schema file is never rewritten
  (Section 17).
- `spec/test-vectors/session-evidence-record-parity.json` —
  `release_0_3_0_record`, the SessionEvidenceRecord that release 0.3.0 produced
  for the vector's session, which validates against the `"0.1"` schema and
  verifies under the current verifiers; and `release_0_3_0_schema_sha256`, which
  pins the `"0.1"` schema file to the bytes release 0.3.0 published.

### Changed

- `TRANSACTION_RECORD_VERSION` (Python `a2cn.record`, TypeScript `record.ts`),
  exported in 0.3.0, is replaced by `TRANSACTION_RECORD_VERSION_WITHOUT_BASIS`
  (`"0.1"`) and `TRANSACTION_RECORD_VERSION_WITH_BASIS` (`"0.2"`), because a
  TransactionRecord's version now follows whether it carries `basis`.

### Fixed

- The Python and TypeScript reference implementations now reject a SessionAck
  that changes `currency` or `basis` with `SESSION_PARAM_CHANGED`, naming the
  parameter, both when the responder creates the session and when the initiator
  client receives the ack. Section 6.4.1 already forbade changing `currency` in
  the SessionAck, but nothing enforced it. They validate the SessionAck's
  `session_params_accepted` before comparing it, as Section 6.4.1 now states, so
  a malformed accepted value is reported as malformed and never as a change: a
  `basis` outside `net` | `gross`, proposed or accepted, is rejected with
  `INVALID_BASIS`. Malformed input is `INVALID_REQUEST`: a missing, empty, or
  non-string `session_params.currency` or `session_params_accepted.currency`,
  and a `session_params` or `session_params_accepted` that is not an object. The
  initiator client also rejects a SessionAck whose body is not an object or that
  omits `session_params_accepted`.
- Both reference implementations now enforce §7.2's requirement that each
  offer's `terms.currency` match the session currency. An offer or counteroffer
  whose `terms.currency` is absent, a different string, or not a string is
  rejected with `SESSION_PARAM_CHANGED`, naming `currency`, whether or not a
  mandate caps the commitment. Before, only a mandate's
  `max_commitment_currency` was compared, and only when the mandate set
  `max_commitment_value`. The check runs with the basis check on every offer,
  after signature verification and before the mandate check and any state
  change; a malformed `terms.basis` is reported first, then `currency`, then
  `basis`.

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
