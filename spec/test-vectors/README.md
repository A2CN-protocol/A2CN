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
