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
`"gross"`, with its signed messages recorded. Each record it holds sits under
the version that produced it, so the file carries both what the reference
implementations produce now and what earlier ones produced for the same session.

Both suites replay the messages through the session state machine, and build the
record on the client side from the same messages; both must produce
`expected.record_version_0_3.full_record` and its `record_hash`, and that record
must verify. It is a `"0.3"` record because its `final_offer` carries the Section
7.3.1 act fields, so a verifier rebuilds the signed act from the record — its
`terms` are `agreed_terms`, its `session_id` the record's — and requires the
rebuilt hash to equal `final_offer.protocol_act_hash`, which the offer's
signature already covers (Sections 9.3 and 9.5). Nothing new is signed. It also
carries a top-level `basis` equal to `agreed_terms.basis`, since the session
fixed one. Its negatives, each resealed with `record_hash` recomputed, must all
fail verification: `agreed_terms_tampered_record_hash` sets
`agreed_terms.total_value` to `expected.agreed_terms_tampered_total_value`,
where both signatures still verify and only the rebuilt act hash rejects it;
`basis_flipped_record_hash` sets the top-level `basis` to
`expected.tampered_basis`; `act_fields_dropped_record_hash` removes every act
field while the record stays `"0.3"`; and `relabelled_0_2_record_hash` relabels
it `"0.2"` with its act fields kept, where its basis shape already fits `"0.2"`,
so only the act fields can be what rejects it. The evidence record sealed over
the session with `producer_private_jwk` must have
`expected.record_version_0_3.evidence_record_hash` and verify; an evidence record
seals whatever TransactionRecord hash its session has.

`expected.record_version_0_2` is the record an implementation that predates the
act fields produced for the same session, with the bytes and `record_hash` it
had. It carries the top-level `basis` and no act fields, and still verifies
untouched, as do its negatives: `tampered_record_hash` sets the top-level `basis`
to `expected.tampered_basis`; `basis_dropped_record_hash` removes the top-level
`basis`, and a `"0.2"` record without `basis` fails whatever `agreed_terms` holds
(Section 9.5, step 8); `basis_dropped_0_1_record_hash` is that record at
`record_version` `"0.1"`, which is what an implementation that predates `basis`
records for this session, `agreed_terms.basis` alone, and which verifies; and
`relabelled_0_1_record_hash` is the `"0.2"` record at `"0.1"` with its top-level
`basis` kept, which a `"0.1"` record must not carry. ES256 signatures are
randomized, so they are recorded rather than recomputed.

Its `without_basis` entry is a completed session that fixed no basis.
`record_version_0_1` is the record an implementation that predates `basis`
produced for it, and `record_version_0_3` is the record both reference
implementations produce now: the same fields, plus the act fields in
`final_offer`, and still no top-level `basis`, because the session fixed none.
Both suites replay its messages, and build the record on the client side from
them, and assert that the record they produce is exactly
`record_version_0_3.full_record`, with the same bytes and `record_hash`, and that
it verifies; the Python suite also validates it against
`transaction-record-0.3.schema.json`. `record_version_0_1.full_record` still
verifies untouched, with the `record_hash` it has always had.
`without_basis.relabelled_0_2_record_hash` is that `"0.1"` record at
`record_version` `"0.2"`, resealed; a `"0.2"` record must carry `basis`, so it
must fail verification. `record_version_0_3.relabelled_0_1_record_hash` is the
`"0.3"` record at `"0.1"` with its act fields kept; its basis shape already fits
`"0.1"`, so only the act fields can be what rejects it.
`without_basis.unechoed_proposed_bases` covers a SessionInit that proposed a
basis that the SessionAck, from a responder that predates `basis`, omitted, so
the session's basis is unstated (Section 6.4.1). Both suites replay the messages
with `session_init.session_params.basis` set to each value and the SessionAck
unchanged, on the server side and on the client side, and assert that the record
is still exactly `record_version_0_3.full_record` and carries no `basis`, because
a record's `basis` follows the SessionAck (Section 9.3). No signed act contains
the SessionInit, so the recorded signatures still verify.

Its `empty_expires_at` entry is a completed session whose round-1 offer omits
`expires_at`. Neither `expires_at` nor `timestamp` is validated on the wire, and
a receiver rebuilding the Section 7.3.1 act to check its hash defaults a missing
one to `""`, so the offer is signed, accepted and recorded with `""` inside the
signed act. Both suites replay its messages and must produce
`record_version_0_3.full_record` with its `record_hash`, and that record must
**verify**: Section 9.5 step 3 rebuilds the act from the record and compares
hashes, and a verifier that demanded a non-empty `expires_at` would reject a
record whose signature genuinely covers those bytes. `act_expires_at` is the
value the act carried. The block ships `private_jwks` for both parties, so a
reader can re-sign it; they are test-only fixtures and MUST NOT be used outside
tests. The record also validates against `transaction-record-0.3.schema.json`,
which constrains what a conformant producer emits and therefore permits the
empty value, while leaving a verifier free to accept the wider range Section 9.5
step 3 defines.

Its `record_version_0_3_binding` entry holds the cases both suites apply to
`expected.record_version_0_3.full_record`, so the two implementations read
byte-identical JSON and must reach identical verdicts. `act_integer_spellings`
restate `final_offer.round_number` or `sequence_number`, whose genuine value is
`2`. RFC 8785 serializes `2.0` and `2` as the same number, so an integral float
is the same signed act in a different spelling: `record_hash_unchanged` is true
and the record verifies. A fractional, string, boolean or `null` value, or an
absent key (a case with no `value`), is a different act or none at all, and is
rejected. `currency_cases` set the top-level `currency`, or drop
`agreed_terms.currency`, on the record of the given `record_version`: a `"0.3"`
record's `currency` must equal the signature-bound `agreed_terms.currency`
(Section 9.5, step 8), while a `"0.1"` or `"0.2"` record is refused outright,
with `expected_reason`, because only the bound version is accepted. Each case's
`record_hash` is recomputed before verifying, so only the rule under test
decides.

Its `downgrade_attack` entry is the forgery a verifier must refuse, and the
reason the accepted set is a single version. Each case starts from
`expected.record_version_0_3.full_record`, strips the six act fields from
`final_offer`, relabels the record to a version that predates them, optionally
alters `agreed_terms`, and recomputes `record_hash`. Both signatures still
verify and the record keeps the genuine `record_id`, so a verifier that accepted
an unbound version would report a forgery as genuine. Every case must be
REJECTED, with `expected_reason` rather than the generic unrecognized-version
reason. One case is worth reading twice: `stripped-and-relabelled-0.2-terms-untouched`
has the same `record_hash` as `expected.record_version_0_2.full_record`, so the
downgrade of an untouched record *is* the historical artifact, byte for byte.
Accepting one meant accepting the other.

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

`record-versions.json` lists, for each record artifact, the `record_version`
values its verifier accepts and the values it must reject. The two artifacts are
kept apart, because each versions its own shape, and one artifact's rules never
decide the other's. A TransactionRecord verifier accepts `"0.3"` alone: the
version whose `final_offer` carries the Section 7.3.1 act fields, so the record
can be rebound to the offering party's signature from the record alone.
`transaction_record.unbound` holds the versions this implementation knows but
cannot rebind — `"0.1"`, `"0.2"`, and a `"0.3"` whose act fields are missing —
each rejected with `unbound_reason` rather than the generic `unrecognized_reason`
that `transaction_record.rejected` gets, since those values are no version at
all. A SessionEvidenceRecord is untouched by that rule: it accepts `"0.1"`,
`"0.2"` and `"0.3"`, where `"0.3"` is the record that carries
`external_commitment_reference` (Section 9A.2), and rejects `"0.4"`.
`producers_emit` is the version each producer writes: one value for every
TransactionRecord, since every record the reference implementations produce
carries the act fields, and a per-shape value for the SessionEvidenceRecord. The
AuditLog carries its version in `log_version`.

Each artifact's `shapes` (TransactionRecord) or accepted `shape` names
(SessionEvidenceRecord) say which record each case is applied to. The three
TransactionRecord shapes come from `transaction-record-basis.json`: `"0.3"` is
the record its basis session replays to, `"0.2"` is
`expected.record_version_0_2.full_record`, and `"0.1"` is
`without_basis.record_version_0_1.full_record`. The SessionEvidenceRecord shapes
are the record `session-evidence-record-parity.json` produces (without the
reference) and the one `session-evidence-record-external-channel.json` produces
(with it). Both suites set each value on a record of each shape of each
artifact, recompute `record_hash` and, for an evidence record, the producer
seal, and assert the verdict. Each accepted version verifies on a shape that
carries it, and each `cross_shape` case puts a recognized version on another
shape of the same artifact and fails. Every value in an artifact's `rejected`
list fails on every shape of that artifact, instead of being parsed best-effort
(Sections 9.5 and 9A.6).

`session-evidence-record-external-channel.json` covers Section 9A.12: a
`COMPLETED` SessionEvidenceRecord whose completion witness is
`external_commitment_reference`, at `record_version` `"0.3"`. Its session
negotiates with a seller that holds no A2CN identity. The native log holds the
producer's signed A2CN Offer; `observed_acts` holds the seller's order
confirmation as an unsigned observation with a `null` `sender_did`; the
responder is an `observed_party` with an `observed_credential` digest; and there
is no SessionAck and no TransactionRecord. Both suites generate the record from
`options` and must produce `expected.record` exactly, producer seal included:
the key is Ed25519, whose signatures are deterministic. Each `valid_references`
case generates the record with another reference (only `external_commitment_id`, a
numeric-looking string id, an empty `reference_note`, a non-ASCII
`reference_note`) and must reach its `record_hash` and verify. Each
`invalid_references` case is a malformed reference: a missing, empty, integer,
`null`, or array `external_commitment_id`; an empty, `null`, numeric, or array
`locator`; a numeric or `null` `reference_note`; an extra member; or a reference
that is `null`, a string, an array, or empty. The generator refuses each one,
treating a `null` reference as not supplied, and `expected.record` with its
reference replaced and resealed has `resealed_record_hash` and fails
verification. Each `valid_variants` case generates the record with another
act list: `producer-acts-only` has the producer's signed offer and nothing
observed, and is `unilateral`, because the level of a record whose responder is
an `observed_party` is asserted rather than derived (Section 9A.5). Each
`invalid_records` case edits `expected.record` as its `set` and `remove` say,
and names the rule it breaks: both completion witnesses, neither, a reference on
another outcome, a DID-bearing responder, `mixed` or `bilateral` evidence, the
record labelled `"0.2"` or `"0.1"`, `"0.3"` without the reference, an
`observed_party` responder carrying a `transaction_record_hash` (at `"0.2"` and
at `"0.1"`), no act the producer signed, no acts at all, and a record sealed by
a DID that is not its initiator. That last case is sealed with `second_producer`,
whose `private_jwk` is test-only, as its `sealed_by` says, so its seal verifies
and only the producer binding refuses it; a case whose `schema_expresses` is
false states a rule a JSON Schema cannot express, so the `"0.3"` schema accepts
that record and only the verifier refuses it. Resealed, each has
`resealed_record_hash` and fails verification. The Python suite validates every
valid record against `session-evidence-record-0.3.schema.json`, checks that
every invalid one fails it unless `schema_expresses` says otherwise, and checks
that the `"0.1"` and `"0.2"` schemas refuse the reference.
`session_evidence_record_0_2_schema_sha256` pins
`session-evidence-record-0.2.schema.json`, beside which the `"0.3"` schema is
published and which is not rewritten (Section 17).
