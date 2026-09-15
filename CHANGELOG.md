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
| `record_version` — TransactionRecord / AuditLog / SessionEvidenceRecord | `0.2` / `0.1` / `0.2` |

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0: the minor version moves for substantive additions.

---

## [Unreleased]

**Session Evidence Record extensions, at `record_version` `"0.2"`
(wire-compatible with 0.2; no signature changes).**

The SessionEvidenceRecord moves to `record_version` `"0.2"`, and its schema
`$id` to `/0.2`. Version `"0.2"` is the one that introduced Sections 9A.8 to
9A.11 and the Section 9A.9 rule that a `net` or `gross` `money_basis` agrees
with the described act's `terms.basis`. Sections 9A.8 to 9A.11 are relaxations,
so a verifier that predates them rejects records that use them, and the basis
rule adds a rejection. Producers emit `"0.2"`. Verifiers accept `"0.1"` and
`"0.2"`, apply the same rules to both, and reject any other value;
verification does not depend on the version.

**Session money basis, `session_params.basis`, restated in `terms.basis` and
recorded in the TransactionRecord at `record_version` `"0.2"` (wire-compatible
with 0.2).** Wire `protocol_version` stays `"0.2"`. The TransactionRecord moves
to `record_version` `"0.2"`, and every newly generated record carries it. The
record of a session that fixed a basis also carries a top-level `basis`, which
its `record_hash` covers; the record of a session that fixed none differs from
its `"0.1"` record only in `record_version` and `record_hash`. A party whose
implementation predates `basis` can still take part in a session that fixed
one, when its caller sets `basis` and `terms.basis` and the implementation
passes them through, but its own TransactionRecord has no top-level `basis`. A
mixed-version session could produce two TransactionRecords that differ yet both
verify under 0.1; 0.2 makes the difference explicit. Verifiers accept `"0.1"`
and `"0.2"` and reject any other value. The other verification steps are the
same for both, except that a `"0.2"` record without `basis` must not carry
`agreed_terms.basis` either. AuditLog stays at `"0.1"`: its content does not
change. An
evidence record for a completed session seals whatever TransactionRecord hash
that session has.

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
  when the session fixed a basis, and equal to `agreed_terms.basis`.
- **Section 9.5 — verification step 1.** A TransactionRecord verifier accepts
  `record_version` `"0.1"` or `"0.2"` and rejects any other value, including an
  absent, `null`, or non-string one. Before, it did not check `record_version`.
  The later steps are renumbered.
- **Section 9.5 — verification step 7.** A record that carries `basis` verifies
  only if it is `net` or `gross` and `agreed_terms.basis` is present and equal to
  it, whichever version it carries. A `"0.2"` record without `basis` verifies
  only if `agreed_terms` has no `basis` key either. A `"0.1"` record without
  `basis` gets no new check, since an implementation that predates the field
  records `agreed_terms.basis` alone.
- **Section 9A.9 — a `money_basis` agrees with the act's basis.** A
  `money_basis` describing an on-basis total SHOULD carry the session basis.
  When the described act's `terms` carries `basis` and `money_basis.basis` is
  `net` or `gross`, the two must be equal: the generator refuses such a record
  and the verifier rejects it, exactly as for `currency`, for per-act and
  terminal `money_basis` alike. `per_unit`, `line_total`, and `unspecified` are
  not compared, and an act without `terms.basis` gets no comparison. Labels are
  compared, never converted.
- **Section 12.3 — `INVALID_BASIS` and `SESSION_PARAM_CHANGED`.** Dedicated error
  codes for a `basis` outside `net` | `gross`, and for a message that changes a
  parameter fixed at session initiation; the error's `message` names the
  parameter.
- `spec/test-vectors/session-params-basis.json` — cross-language vectors for the
  basis enum, for SessionAcks that keep or change `currency` or `basis`, and for
  offers whose `terms.currency` or `terms.basis` matches, omits, adds, or
  changes the session value.
- `spec/test-vectors/transaction-record-basis.json` — a cross-language
  TransactionRecord vector for a session that fixed a basis, with a tampered
  negative and the evidence record that seals it; and a session that fixed none,
  with the `"0.1"` record an implementation that predates `basis` produced for
  it.
- `spec/test-vectors/record-versions.json` — the `record_version` values a
  TransactionRecord or SessionEvidenceRecord verifier accepts (`"0.1"`, `"0.2"`)
  and values it must reject, including `"0.3"`, `""`, `"0.2 "`, the number
  `0.2`, `null`, and an absent key.
- `spec/conformance-fixtures/offer_basis_diverges_from_session.json` and
  `offer_currency_diverges_from_session.json` — an offer whose `terms.basis` or
  `terms.currency` differs from the session value is rejected with
  `SESSION_PARAM_CHANGED`.

### Fixed

- The Python and TypeScript reference implementations now reject a SessionAck
  that changes `currency` or `basis` with `SESSION_PARAM_CHANGED`, naming the
  parameter, both when the responder creates the session and when the initiator
  client receives the ack. Section 6.4.1 already forbade changing `currency` in
  the SessionAck, but nothing enforced it. A `basis` outside `net` | `gross` is
  rejected with `INVALID_BASIS`. Malformed input is `INVALID_REQUEST`: a missing,
  empty, or non-string `session_params.currency`, and a `session_params` or
  `session_params_accepted` that is not an object. The initiator client also
  rejects a SessionAck whose body is not an object or that omits
  `session_params_accepted`.
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
