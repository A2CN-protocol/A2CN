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
