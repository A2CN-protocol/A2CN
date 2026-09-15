# A2CN Test Vectors

Deterministic cross-language inputs and expected cryptographic outputs live in
this directory. Keys marked test-only are public fixtures and MUST NOT be used
outside tests.

`session-evidence-record-parity.json` exercises a signed A2CN Offer, an unsigned
external Counteroffer observation, a local timeout, and a producer seal. The
Python and TypeScript suites independently assert the same evidence ID, per-act
hashes, chain hash, evidence level, and record hash.

The vector also supplies `invalid_cases.non_rfc3339_timestamp`. Both suites place
that value in a fully resealed record whose acts otherwise carry unique numeric
sequence numbers, assert the same invalid-record hash, and assert rejection. This
ensures timestamp validation cannot be skipped merely because sequence ordering
determines every act position.

`session-params-basis.json` covers `session_params.basis` (Section 6.3.1): the
two valid bases; values that must be rejected, including `unspecified` and
`per_unit`, which are valid evidence-record `money_basis` labels but not session
bases; and SessionAck cases that keep or change `currency` or `basis` (Section
6.4.1). Adding or altering `basis` counts as a change; a SessionAck that omits
it (`gross-omitted-unstated`: a responder that predates `basis`) leaves the
basis unstated. Each rejected SessionAck case gives its error code
(`SESSION_PARAM_CHANGED`) and the parameter the error message must name;
`invalid_bases` are rejected with `INVALID_BASIS`. `invalid_currencies`
(including the empty string), `malformed_accepted`, `malformed_session_params`,
and `malformed_ack_bodies` cover a malformed `currency` and message parts that
are not JSON objects: inputs on which a looser check would let the two
implementations disagree. Both suites assert the same verdict for every case.

Its `offer_cases` open a session from the given `proposed` and `accepted` money
parameters and send one signed round-1 offer carrying the given `terms` (Section
7.2). `terms.currency` must equal the session currency: absent, a different
string, or a non-string is `SESSION_PARAM_CHANGED` naming `currency`. When the
session fixed a basis, `terms.basis` must be present and equal to it; when the
session fixed none, `terms.basis` must be absent. Either violation is
`SESSION_PARAM_CHANGED`, and a `terms.basis` from `invalid_bases` is
`INVALID_BASIS` whatever the session basis. When an offer breaks more than one
rule, a malformed `terms.basis` is reported first, then `currency`, then
`basis`. The `unechoed-basis-*` cases follow a SessionAck that omitted the
proposed basis: the basis is unstated, so an offer carries none. A `terms` value
that is not a JSON object carries neither `terms.currency` nor `terms.basis`.
Both suites assert every case through the session state machine and through the
reference client, both as a counteroffer it receives and as an offer it sends,
and assert the cases whose `accepted` equals `proposed` over
`POST /sessions/{id}/messages` too. A client that refuses an offer before
sending it has not advanced its round or sequence, so the corrected offer goes
out in the same round.

`transaction-record-basis.json` is a completed session that fixed `basis`
`"gross"`, with its signed messages recorded. Both suites replay the messages
through the session state machine, and build the record on the client side from
the same messages; both must produce `expected.full_record`, a `record_version`
`"0.2"` record whose top-level `basis` equals `agreed_terms.basis` (Sections 9.3
and 9.5), with the same `record_hash`, and the record must verify.
`expected.tampered_record_hash` is the hash after the top-level `basis` is set to
`expected.tampered_basis` and `record_hash` is recomputed; both suites assert
that hash and that the tampered record fails verification.
`expected.basis_dropped_record_hash` is the hash after the top-level `basis` is
removed and `record_hash` recomputed: a `record_version` `"0.2"` record whose
`agreed_terms` still carries `basis`, which must fail verification (Section 9.5,
step 7). `expected.basis_dropped_0_1_record_hash` is the same record at
`record_version` `"0.1"`, which verifies. The evidence record
sealed over the completed session with `producer_private_jwk` must have
`expected.evidence_record_hash` and verify. ES256 signatures are randomized, so
they are recorded rather than recomputed.

Its `without_basis` entry is a completed session that fixed no basis, recorded
with the `record_version` `"0.1"` TransactionRecord that an implementation
predating `basis` produced for it. Both suites replay its messages and assert
that the record they produce has no `basis` and is that `"0.1"` record with
`record_version` set to `"0.2"` and `record_hash` recomputed
(`without_basis.expected.record_hash`), and that the `"0.1"` record still
verifies.

`session-evidence-record-extensions.json` covers the Section 9A extensions. Its
`money_basis_act_basis_cases` apply the Section 9A.9 rule that a `money_basis`
labelled `net` or `gross` must equal the `terms.basis` of the act it describes
whenever that act's `terms` carries `basis`. Each case starts from the vector
named by `base_vector`, sets the observed quote's `terms.basis` to
`act_terms_basis` (an absent key means the act states no basis), and puts the
label `money_basis_basis` on the quote's own `money_basis` or on
`terminal.money_basis`, as `placement` says. A valid case generates a record
with `record_hash` that verifies. For an invalid case the generator refuses the
record; the same record generated with the label `unspecified`, relabelled, and
resealed with `producer_private_jwk` has `resealed_record_hash` and fails
verification. The cases include a `null` and an upper-case act basis, inputs on
which a looser comparison could let the two implementations disagree.

`record-versions.json` lists the `record_version` values a verifier accepts
(`"0.1"` and `"0.2"`) and a set it must reject: other versions, strings that
differ by a space or a prefix, the numbers `0.2` and `0.1`, an array, `null`, and
an absent key. Both suites set each value on a valid TransactionRecord (the
record `transaction-record-basis.json` replays to) and on a valid
SessionEvidenceRecord (the record `session-evidence-record-parity.json`
produces), recompute `record_hash` and, for the evidence record, the producer
seal, and assert that every accepted value verifies and every rejected value
fails verification (Sections 9.5 and 9A.6). `producers_emit` is the version each
producer writes; the AuditLog carries its version in `log_version`.
