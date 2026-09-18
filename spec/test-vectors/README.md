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

It also records `release_0_3_0_record`, the SessionEvidenceRecord that release
0.3.0 produced for its session with its producer key, at `record_version`
`"0.1"`. Both suites assert that it verifies under the current verifier and that
this implementation's record for the session, relabelled `"0.1"` and resealed,
has the same `record_hash`; the Python suite also validates it against
`session-evidence-record.schema.json`. `release_0_3_0_schema_sha256` is the
sha256 of that schema file as release 0.3.0 published it, which both suites pin,
because a published schema file is never rewritten (Section 17).

`session-params-basis.json` covers `session_params.basis` (Section 6.3.1): the
two valid bases; values that must be rejected, including `unspecified` and
`per_unit`, which are valid evidence-record `money_basis` labels but not session
bases; and SessionAck cases that keep or change `currency` or `basis`, or carry
a malformed one (Section 6.4.1). Adding or altering `basis` counts as a change;
a SessionAck that omits it (`gross-omitted-unstated`: a responder that predates
`basis`) leaves the basis unstated. Each rejected SessionAck case gives its
error code and the parameter the error message must name. A receiver validates
`session_params_accepted` before comparing it with `session_params` (Section
6.4.1): first its `currency`, where an absent or malformed value is
`INVALID_REQUEST` (Section 12.3), then its `basis`, where a value other than
`net` or `gross` is `INVALID_BASIS`. Neither is ever `SESSION_PARAM_CHANGED`,
which is left for a well-formed value that differs. The `accepted-*` cases pin
that order, including a malformed accepted `currency` reported before a
malformed accepted `basis`. `invalid_bases` are rejected with
`INVALID_BASIS`, proposed or accepted. `invalid_currencies` (including the empty
string), `malformed_accepted`, `malformed_session_params`, and
`malformed_ack_bodies` cover a malformed `currency` and message parts that are
not JSON objects: inputs on which a looser check would let the two
implementations disagree. Both suites also send every `invalid_bases` value as
the accepted `basis`, whatever the proposed basis, and every
`invalid_currencies` value and an absent key as the accepted `currency`, through
the session state machine and the initiator client. Both suites assert the same
verdict for every case.

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
`"0.2"` record, since it carries a top-level `basis`, whose `basis` equals
`agreed_terms.basis` (Sections 9.3 and 9.5), with the same `record_hash`, and
the record must verify. `expected.tampered_record_hash` is the hash after the
top-level `basis` is set to `expected.tampered_basis` and `record_hash` is
recomputed; both suites assert that hash and that the tampered record fails
verification. `expected.basis_dropped_record_hash` is the hash after the
top-level `basis` is removed and `record_hash` recomputed: a `record_version`
`"0.2"` record without `basis`, which must fail verification whatever
`agreed_terms` holds (Section 9.5, step 7).
`expected.basis_dropped_0_1_record_hash` is the same record at `record_version`
`"0.1"`: what an implementation that predates `basis` records for this session,
`agreed_terms.basis` alone, which verifies. `expected.relabelled_0_1_record_hash`
is `expected.full_record` at `record_version` `"0.1"` with its top-level `basis`
kept; a `"0.1"` record must not carry `basis`, so it must fail verification. The
evidence record sealed over the completed session with `producer_private_jwk`
must have `expected.evidence_record_hash` and verify. ES256 signatures are
randomized, so they are recorded rather than recomputed.

Its `without_basis` entry is a completed session that fixed no basis, recorded
with the `record_version` `"0.1"` TransactionRecord that an implementation
predating `basis` produced for it. Both suites replay its messages, and build
the record on the client side from them, and assert that the record they
produce is exactly that `"0.1"` record, with the same bytes and `record_hash`,
and that it verifies. `without_basis.relabelled_0_2_record_hash` is that record
at `record_version` `"0.2"`, resealed; a `"0.2"` record must carry `basis`, so it
must fail verification. `without_basis.unechoed_proposed_bases` covers a
SessionInit that proposed a basis that the SessionAck, from a responder that
predates `basis`, omitted, so the session's basis is unstated (Section 6.4.1).
Both suites replay the messages with `session_init.session_params.basis` set to
each value and the SessionAck unchanged, on the server side and on the client
side, and assert that the record is still exactly the `"0.1"` record, carries no
`basis`, and verifies; the Python suite also validates it against
`transaction-record.schema.json`. A record's `basis`, and so its version,
follows the SessionAck (Section 9.3). No signed act contains the SessionInit, so
the recorded signatures still verify.

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

Each of its `vectors` (an identity-light responder, a recomputable `money_basis`,
and a `HALTED_BY_CONTROLS` outcome with `extensions`) generates a `"0.2"` record
that validates against `session-evidence-record-0.2.schema.json`. Relabelled
`"0.1"` and resealed, each still verifies, because verification does not depend
on the version, but does not validate against the `"0.1"` schema, which predates
Sections 9A.8 to 9A.11 (Section 9A.2). The Python suite validates both; the
TypeScript suite checks that the `"0.1"` schema describes none of the features
each record uses and the `"0.2"` schema describes all of them.

`record-versions.json` lists the `record_version` values a verifier accepts
(`"0.1"` and `"0.2"`) and a set it must reject: other versions, strings that
differ by a space or a prefix, the numbers `0.2` and `0.1`, an array, `null`, and
an absent key. `producers_emit` is the version each producer writes. For the
TransactionRecord it follows the record's shape: `"0.1"` for a session that
fixed no basis and `"0.2"` for one that did. The AuditLog carries its version in
`log_version`. Both suites set each value on a valid TransactionRecord of each
shape (the two records `transaction-record-basis.json` replays to) and on a
valid SessionEvidenceRecord (the record `session-evidence-record-parity.json`
produces), recompute `record_hash` and, for the evidence record, the producer
seal, and assert the verdict. Each accepted TransactionRecord version verifies
on the shape that emits it, and each `transaction_record_cross_shape` case, a
recognized version on the other shape, fails (Section 9.5, step 7). Every
rejected value fails verification on both TransactionRecord shapes and on the
evidence record, and every accepted value verifies on the evidence record
(Sections 9.5 and 9A.6).
