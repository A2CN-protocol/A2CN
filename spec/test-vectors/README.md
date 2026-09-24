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
`"0.1"`. Its acts state no wire version, so they are rebuilt under the pinned
`"0.2"` (Section 7.3.1). Both suites assert that it verifies under the current
verifier and that this implementation's record for the session, with the wire
version it now states on each of its acts removed, relabelled
`"0.1"` and resealed, has the same `record_hash`; the Python suite also validates it against
`session-evidence-record.schema.json`. `release_0_3_0_schema_sha256` is the
sha256 of that schema file as release 0.3.0 published it, which both suites pin,
because a published schema file is never rewritten (Section 17).

`session-evidence-record-wire-version.json` covers the wire version a recorded
act is rebuilt under (Section 7.3.1). Its `current` session was negotiated at
`"0.3"`: both suites replay it through their own generator and must produce
`expected` byte for byte, the sealed record included, with every act of the
session's own log stating `protocol_version` `"0.3"`. `legacy_record` is a stored
record, not regenerated: the generator released before acts stated their version
sealed it for a session negotiated at `"0.2"`, so none of its acts states one,
and it must still verify, because such an act is rebuilt under the pinned
`"0.2"` rather than the version an implementation now emits. Each `edit_cases`
entry sets or removes one act's `protocol_version` on the base record it names,
recomputes that act's hash and the chain, reseals, and must reach
`resealed_record_hash` and the stated verdict: an act stating a version its
signature was not made under fails, and so does a `"0.3"` act stating none.
`observed` is the same session timed out after the buyer's offer, with the
seller's signed counteroffer supplied as an observed act that states no version:
the generator records it with the session's negotiated version and it verifies
as a signed observed act. Supplied already stating `"0.2"`, it keeps that version
and the record fails verification, because a stated version is never
overwritten.

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
`expected.record_version_0_4.full_record` and its `record_hash`, and that record
must verify. It is a `"0.4"` record because `final_offer` carries the Section
7.3.1 act fields **and** `final_acceptance` carries the acceptance's, so a
verifier rebuilds each signed act from the record — the offer's `terms` are
`agreed_terms` and its `session_id` the record's; the acceptance's fields are its
own — and requires each rebuilt hash to equal the hash that act's signature
covers (Sections 9.3 and 9.5). Neither rebuild reads the other act. It also
carries a top-level `basis` equal to `agreed_terms.basis`, since the session
fixed one. Its negatives, each resealed with `record_hash` recomputed, must all
fail verification: `agreed_terms_tampered_record_hash` sets
`agreed_terms.total_value` to `expected.agreed_terms_tampered_total_value`,
where both signatures still verify and only the rebuilt act hash rejects it;
`basis_flipped_record_hash` sets the top-level `basis` to
`expected.tampered_basis`; `act_fields_dropped_record_hash` removes every act
field of both acts while the record stays `"0.4"`; and
`relabelled_0_3_record_hash` relabels it `"0.3"` with its act fields kept, where
its offer already rebinds, so only the acceptance's fields can be what rejects
it. The evidence record sealed over the session with `producer_private_jwk` must
have `expected.record_version_0_4.evidence_record_hash` and verify; an evidence
record seals whatever TransactionRecord hash its session has.

`expected.record_version_0_3` is the record an implementation that bound only the
offer produced for this session. It carries the offer's act fields and none of
the acceptance's, so its acceptance cannot be rebuilt from the record at all, and
a verifier refuses it as unbound rather than inventing or borrowing the missing
fields (Section 9.5, step 5).

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
produced for it, and `record_version_0_4` is the record both reference
implementations produce now: the same fields, plus both acts' fields, and still
no top-level `basis`, because the session fixed none.
Both suites replay its messages, and build the record on the client side from
them, and assert that the record they produce is exactly
`record_version_0_4.full_record`, with the same bytes and `record_hash`, and that
it verifies; the Python suite also validates it against
`transaction-record-0.4.schema.json`. `record_version_0_1.full_record` still
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
is still exactly `record_version_0_4.full_record` and carries no `basis`, because
a record's `basis` follows the SessionAck (Section 9.3). No signed act contains
the SessionInit, so the recorded signatures still verify.

Its `empty_expires_at` entry is a completed session whose round-1 offer omits
`expires_at`. Neither `expires_at` nor `timestamp` is validated on the wire, and
a receiver rebuilding the Section 7.3.1 act to check its hash defaults a missing
one to `""`, so the offer is signed, accepted and recorded with `""` inside the
signed act. That defaulting is the offer path's own rule: an acceptance carries a
REQUIRED `timestamp`, and one that omits it cannot be rebuilt. Both suites replay
its messages and must produce
`record_version_0_4.full_record` with its `record_hash`, and that record must
**verify**: Section 9.5 step 3 rebuilds the act from the record and compares
hashes, and a verifier that demanded a non-empty `expires_at` would reject a
record whose signature genuinely covers those bytes. `act_expires_at` is the
value the act carried. The block ships `private_jwks` for both parties, so a
reader can re-sign it; they are test-only fixtures and MUST NOT be used outside
tests. The record also validates against `transaction-record-0.4.schema.json`,
which constrains what a conformant producer emits and therefore permits the
empty value, while leaving a verifier free to accept the wider range Section 9.5
step 3 defines.

Its `record_version_0_4_binding` entry holds the cases both suites apply to
`expected.record_version_0_4.full_record`, so the two implementations read
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
`expected.record_version_0_4.full_record`, strips the act fields from
`final_offer` and `final_acceptance`, relabels the record to a version that
predates them, optionally alters `agreed_terms`, and recomputes `record_hash`.
Both signatures still verify and the record keeps the genuine `record_id`, so a
verifier that accepted an unbound version would report a forgery as genuine.
Every case must be REJECTED, with `expected_reason` rather than the generic
unrecognized-version reason. `0.4-with-acceptance-act-fields-stripped` is the
case this version adds: a record whose **offer** still rebinds and whose
acceptance does not, because half a bound record is not a bound record.

One case is worth reading twice.
`stripped-and-relabelled-0.2-terms-untouched` and
`expected.record_version_0_2.full_record` differ in exactly two paths —
`final_acceptance.acceptance_signature` and the `record_hash` that covers it —
and in nothing else: no path exists on one side only, and `agreed_terms`,
`final_offer` in full including its `protocol_act_signature`, `record_id` and
`record_version` are identical. So the downgrade of an untouched record is the
historical artifact bar one signature, and an unbound-accepting verifier would
have nothing that matters to tell them apart by. Accepting one meant accepting
the other. Both suites assert that differing-path set, with the
`…-with-altered-terms` case as the control: it must show a third path,
`agreed_terms.total_value`, so the comparison is known to be sensitive rather
than blind.

Two properties of this file are worth stating so a later reader does not mistake
them for damage. **These artifacts are verifiable but not byte-reproducible.**
ES256 signatures carry a random nonce, so re-running a generator over the same
session yields different signature values and therefore a different
`record_hash` every time; the recorded values are the ones to verify against,
never ones to reproduce. And the **historical `"0.1"`, `"0.2"` and `"0.3"`
records are now unverifiable, not merely unbound.** The session was re-keyed — a
private key for the initiator was never stored, so re-signing its acts under the
changed acceptance scope required minting one — and `did_documents` no longer
publishes the key those older records were signed with. They never surface it,
because a verifier refuses them at the version check long before a signature is
examined, which is exactly what they exist to demonstrate. Re-signing them with
today's key would make them verify, which is the opposite of their purpose.

`signed-decline-acts.json` covers the signed decline acts (Sections 7.5 and
7.6), which had no in-band signature slot before this version. Each case states
the act, whether it rebuilds, and — when it does — the `signed_object` its
signature covers, that object's `canonical_bytes`, and its `signed_act_hash`.
Stating the signed object outright means a scope change in either implementation
shows up as a field diff and a byte count, not only as an opaque hash mismatch.
`header_fields`, `payload_fields` and `signature_fields` restate the envelope, and
both suites assert them against their own constants, so the vector and the code
cannot drift apart about the shape itself. `withdrawal_round_number` is the case
that pins the additive wire change: a Withdrawal that omits `round_number` cannot
be rebuilt, so it can be neither signed nor verified, and its own schema refuses
it. `rejection_missing_reason_code` and `unknown_act_type` are the other
refusals. `unsigned_field_is_not_covered` pins that `reason_description` sits
outside every signed scope — altering it or removing it leaves the signed act
byte-identical — because it is OPTIONAL, and signing it would make the signed
field set depend on whether the sender filled it in. `relabel_cases` relabel one
decline as the other: a rejection relabelled a withdrawal rebuilds to a different
hash, while a withdrawal relabelled a rejection cannot rebuild at all, since a
rejection's payload names `rejected_offer_id`, which a withdrawal does not carry.

`decline-act-admission.json` covers what a receiver admits on the two decline
paths. Both suites build the session it describes, send each case's act through
the state machine, and must reach its verdict, error code and error message.
`signature_presence` pins that a party's decline must be signed: an absent
signature field is refused as a missing signature, and `null`, an empty string, a
whitespace string, or any other non-string value is refused and never read as
unsigned. `withdrawal_round_number` pins that a Withdrawal carries a positive
integer `round_number`, judged by value; a Withdrawal sent before any offer
carries `1`. Signed, each case reaches its own verdict; unsigned, it is always
refused, for its invalid `round_number` first when it has one and otherwise as
`unsigned_refusal` says. Its `schema_valid` and `accepted` columns are always
equal, and the Python suite validates every case against
`withdrawal.schema.json`, so the schema and the runtime cannot disagree.

`foreign-signature-slots.json` covers signature fields carried on the wrong act
type (Section 7.3.1). Each act type has its own signature field, and a receiver
refuses an act carrying one that belongs to another type, whatever its value,
`null` included, because a verifier reads any such field as a signature claim
(Section 9A.6). The cases cover all five act types, signed and unsigned declines,
and stray fields set to a string or to `null`. For every case both suites then
close the session, generate the initiator's evidence record and require it to
verify, so each signed control shows the honest act records cleanly and each
refusal shows the stray act never reaches the record. An unsigned decline is
refused whether or not it carries a stray field, because a party's own decline
must be signed.

`reserved-wire-keys.json` covers the evidence record's own members on a wire act
(Section 7.3.1). A SessionEvidenceRecord act entry adds `act`, `act_hash`,
`attribution`, `signature`, `signature_type` and `source_protocol` around the act
it records; each of the five act types carrying any of them is refused with
`INVALID_REQUEST`, and each signed control without one is accepted. Both suites
then require the session's evidence record to verify, and the Python suite
validates every case against its act type's schema, which refuses the same keys by
name, so `schema_valid` and `accepted` agree.

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
decide the other's. A TransactionRecord verifier accepts `"0.4"` alone: the
version whose `final_offer` carries the Section 7.3.1 act fields **and** whose
`final_acceptance` carries the acceptance's, so both acts rebind from the record
alone, each from its own stored fields.
`transaction_record.unbound` holds the versions this implementation knows but
cannot rebind — `"0.1"`, `"0.2"`, `"0.3"`, and a `"0.4"` whose act fields are
missing — each rejected with `unbound_reason` rather than the generic
`unrecognized_reason` that `transaction_record.rejected` gets, since those values
are no version at all. `"0.3"` is refused for the same reason `"0.2"` is, one act
later: it bound its offer and stored none of the acceptance's act fields. A SessionEvidenceRecord is untouched by that rule: it accepts `"0.1"`,
`"0.2"`, `"0.3"`, `"0.4"` and `"0.5"`, and rejects `"0.6"`. That set is
**additive** — `"0.5"` was added and none removed — so a record sealed under an
earlier version stays valid. This is deliberately the opposite of the TransactionRecord's clean
break above: every evidence record is producer-sealed, so there is no unbound
tier for a relabelled record to be downgraded to.
`producers_emit` is the version each producer writes: one value for every
TransactionRecord, since every record the reference implementations produce
carries the act fields, and — since `"0.4"` — one value for the
SessionEvidenceRecord too. The two-key map is kept rather than flattened so that
both shapes are *asserted* to emit the same version instead of that being
assumed. The AuditLog carries its version in `log_version`.

Each artifact's `shapes` (TransactionRecord) or per-case `shape` names
(SessionEvidenceRecord) say which record each case is applied to. Every
SessionEvidenceRecord case carries its own `shape` — in `accepted`,
`additional_accepted_shapes` and `cross_shape` alike — because from `"0.4"` a
version no longer picks out a single shape: `"0.4"` and `"0.5"` each appear with
`without_external_commitment` in `accepted` and with `with_external_commitment`
in `additional_accepted_shapes`. The mapping is one-to-many from that version on,
so the `shape` named on the case, never the version, decides which record is
used. The four
TransactionRecord shapes come from `transaction-record-basis.json`: `"0.4"` is
the record its basis session replays to, `"0.3"` is
`expected.record_version_0_3.full_record`, `"0.2"` is
`expected.record_version_0_2.full_record`, and `"0.1"` is
`without_basis.record_version_0_1.full_record`. The SessionEvidenceRecord shapes
are the record `session-evidence-record-parity.json` produces (without the
reference) and the one `session-evidence-record-external-channel.json` produces
(with it). Both suites set each value on a record of each shape of each
artifact, recompute `record_hash` and, for an evidence record, the producer
seal, and assert the verdict. Each accepted version verifies on a shape that
carries it. Each `cross_shape` case puts a recognized version on another shape of
the same artifact and fails — for the SessionEvidenceRecord that biconditional
governs only *below* `"0.4"`, where a version and a shape still imply each other.
At `"0.4"` the external commitment reference is OPTIONAL, so both shapes are
legal at that one version and the combination is no longer a violation;
`session_evidence_record.additional_accepted_shapes` records the accepted
version/shape pairs that `accepted` cannot express, because `accepted` is
simultaneously the ordered version list a verifier's recognizer must equal and so
carries only one row per version. Every value in an artifact's `rejected` list
fails on every shape of that artifact, instead of being parsed best-effort
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
another outcome, `mixed` or `bilateral` evidence **against an `observed_party`
responder** (refused by Section 9A.8's coupling, not by Section 9A.12), a
DID-bearing responder at `bilateral`, the record labelled `"0.2"` or `"0.1"`,
`"0.3"` without the reference, an `observed_party` responder carrying a
`transaction_record_hash` (at `"0.2"` and at `"0.1"`), no act the producer
signed, no acts at all, and a record sealed by a DID that is not its initiator.
That last case is sealed with `second_producer`, whose `private_jwk` is
test-only, as its `sealed_by` says, so its seal verifies and only the producer
binding refuses it; a case whose `schema_expresses` is false states a rule a JSON
Schema cannot express, so every schema describing the record accepts it and only
the verifier refuses it. Resealed, each has `resealed_record_hash` and fails
verification. The Python suite validates every valid record against
`session-evidence-record-0.5.schema.json`, checks that every invalid one fails it
unless `schema_expresses` says otherwise, and checks that the `"0.1"` and `"0.2"`
schemas refuse the reference.

`valid_records` mirrors `invalid_records` — same `set`/`remove` shape, same
derivation, opposite verdict — so a case moving between the two buckets is a move
rather than a rewrite. Its one case is a DID-bearing responder carrying the
reference, which `"0.4"` refused and `"0.5"` admits; it lands at `unilateral`,
not `mixed`, because it sets only `parties.responder` while the inherited
observed act carries a null `sender_did`. **A DID-bearing responder does not
imply `mixed`.** The bucket is separate from `valid_variants`, which varies only
`observed_acts`: one structure carrying two contracts cannot tell a reader which
dimension a given entry varies.

**Whether a case reaches Section 9A.12's own exclusions is decided by its
responder shape, not by its name.** Section 9A.8 couples an `observed_party`
responder to `unilateral`, and a verifier enforces that first, so every case
pairing the reference with an `observed_party` is refused before Section 9A.12's
conditions are consulted. Only a full-party responder reaches them.
`session_evidence_record_0_2_schema_sha256` pins
`session-evidence-record-0.2.schema.json`, beside which the `"0.3"` schema is
published and which is not rewritten (Section 17).
