"""The "0.4" SessionEvidenceRecord schema, held to the rule it transcribes.

"0.2" described the bilateral shape and "0.3" the external-channel shape, each
a single case: "0.3" makes COMPLETED mandatory (``else: false``) and forces
``transaction_record_hash`` null, so the two contradict each other and neither
covers an ordinary session that ended unsigned. "0.4" describes every outcome,
so it states the completion-witness rule structurally — Section 9A.6 step 9,
which holds "at every record_version" and which the verifier has always
enforced independently of any schema file.

The rule, in the four parts this file exercises:
  1. COMPLETED carries exactly one of a non-null transaction_record_hash and an
     external_commitment_reference;
  2. any other outcome carries a null transaction_record_hash and no reference;
  3. a reference implies an observed_party responder and evidence_level
     "unilateral";
  4. a non-null transaction_record_hash implies a DID-bearing responder — the
     converse direction, which neither "0.2" nor "0.3" ever stated.

Both directions are asserted. A schema that accepts everything passes any test
that only feeds it valid records, so every accepting case here is paired with a
refusing one that differs in exactly the field under test.

THE BASE ``record`` FIXTURE IS DELIBERATELY UNSIGNED, and that is load-bearing
rather than incidental. Because its only act is an unsigned observation, every
accepting case in this file is also an implicit assertion that allOf[1]'s
``acts.contains`` is conditional on the external-channel branch rather than
global — make it global and the bilateral TR-hash case goes red. Consolidating
the two fixtures into one signed fixture would delete that coverage while every
test in the file stayed green.

There is no TypeScript mirror: that suite carries no JSON Schema validator,
which is a tracked item and deliberately not this change's to close. The
asymmetry is real and is stated rather than papered over.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tests.test_evidence import (
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
    _generate,
    _make_session,
    _mark_timed_out,
)
from tests.test_signed_decline_acts import _rejection, _sign

REPO_ROOT = Path(__file__).parents[3]
SCHEMA_PATH = REPO_ROOT / "spec" / "schemas" / "session-evidence-record-0.4.schema.json"

# A syntactically valid base64url SHA-256 digest, standing in for a real
# TransactionRecord hash. The schema checks its shape, never its provenance.
STAND_IN_HASH = "A" * 43

OBSERVED_PARTY = {
    "identity_source": "ordering portal",
    "did_declared": False,
    "a2cn_endpoint_declared": False,
    "mandate_declared": False,
}

EXTERNAL_REFERENCE = {"external_commitment_id": "po-10014"}


@pytest.fixture(scope="module")
def validator():
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(json.loads(SCHEMA_PATH.read_text()))


@pytest.fixture
def record():
    """A real generated record whose only act is UNSIGNED, relabelled "0.4".

    Generated rather than hand-built: a stub that does not satisfy the $defs
    would fail for reasons unrelated to the rule under test, and a schema test
    fed malformed input reports the wrong cause. The producer seal is not
    checked by a JSON Schema, so relabelling is sound here and only here.

    Do NOT consolidate this with ``record_with_a_signed_act``. The split exists
    so an external-channel case does not fail on allOf[1]'s ``acts.contains``
    for a reason unrelated to the witness rule — but it also means every
    accepting case built on this fixture proves that clause does not fire
    outside the external branch. Signing this fixture would keep the file green
    and silently drop that proof.
    """
    _manager, session, _did_documents = _make_session()
    session._message_log = [_rejection(session.session_id)]
    _mark_timed_out(session)
    generated = _generate(session)
    generated["record_version"] = "0.4"
    return generated


def _completed(record: dict) -> dict:
    record = copy.deepcopy(record)
    record["terminal"]["outcome"] = "COMPLETED"
    return record


def _errors(validator, record: dict) -> list[str]:
    return [error.message for error in validator.iter_errors(record)]


# ---------------------------------------------------------------------------
# The witness rule, both directions
# ---------------------------------------------------------------------------


def test_a_non_completed_record_carrying_no_witness_is_accepted(validator, record):
    """The ordinary case neither "0.2" nor "0.3" could describe together.

    "0.3" refuses it outright (else: false) and would have refused every
    TIMED_OUT, WITHDRAWN and REJECTED_FINAL record had "0.4" been copied from
    it. This is the control the refusing cases below are measured against.
    """
    assert _errors(validator, record) == []


def test_a_completed_record_with_only_a_transaction_record_hash_is_accepted(validator, record):
    completed = _completed(record)
    completed["transaction_record_hash"] = STAND_IN_HASH

    assert _errors(validator, completed) == []


@pytest.fixture
def record_with_a_signed_act():
    """A record carrying one act whose attribution is "verified_signature".

    An external-channel record carries at least one act its producer signed
    (Section 9A.12), which the schema requires through allOf[1]'s
    acts.contains. A fixture whose only act is unsigned fails that clause for a
    reason unrelated to the witness rule — which is exactly what happened on
    this file's first run, and why the case below takes its own fixture rather
    than the unsigned one.

    That the signer must be the record's initiator is a cross-reference between
    two members which a JSON Schema cannot state; a verifier enforces it, so any
    verified act satisfies the schema here.
    """
    _manager, session, _did_documents = _make_session()
    session._message_log = [
        _sign(_rejection(session.session_id), RESPONDER_PRIVATE_KEY, RESPONDER_VM)
    ]
    _mark_timed_out(session)
    generated = _generate(session)
    generated["record_version"] = "0.4"
    return generated


def test_a_completed_record_with_only_an_external_reference_is_accepted(
    validator, record_with_a_signed_act
):
    completed = _completed(record_with_a_signed_act)
    completed["transaction_record_hash"] = None
    completed["external_commitment_reference"] = EXTERNAL_REFERENCE
    completed["parties"]["responder"] = OBSERVED_PARTY
    completed["evidence_level"] = "unilateral"

    assert _errors(validator, completed) == []


def test_an_external_reference_requires_a_producer_signed_act(validator, record):
    """The clause the case above tripped over, now asserted deliberately.

    Identical to it in every respect but the acts: this record's only act is an
    unsigned observation, so Section 9A.12's requirement is unmet and the schema
    must refuse it. Without this pairing the accepting case would pass partly
    because its fixture happens to carry a signed act, which is how a clause
    gets "verified" by accident.
    """
    completed = _completed(record)
    completed["transaction_record_hash"] = None
    completed["external_commitment_reference"] = EXTERNAL_REFERENCE
    completed["parties"]["responder"] = OBSERVED_PARTY
    completed["evidence_level"] = "unilateral"

    assert _errors(validator, completed) != []


def test_the_signed_act_requirement_is_conditional_rather_than_global(validator, record):
    """The trap in carrying "0.3" over unchanged, pinned by name.

    "0.3" requires a producer-signed act of every record it describes, because
    every record it describes is an external-channel completion. "0.4" describes
    every outcome, so carrying acts.contains over unconditionally would refuse an
    ordinary bilateral session that ended with nobody signing — the commonest
    record shape there is.

    The test above proves the clause FIRES when the reference is present; this
    one proves it does NOT fire when the reference is absent. Together they pin
    it as conditional, which neither case alone can distinguish from global or
    from missing.

    A bilateral COMPLETED case earlier in this file happens to guard the same
    property, because its fixture is the unsigned record — but its name claims
    the witness rule, so a later tidy-up swapping its fixture for a signed one
    would keep it passing and silently drop the guard. This test states the
    property outright and asserts its own precondition, so it cannot.
    """
    completed = _completed(record)
    completed["transaction_record_hash"] = STAND_IN_HASH

    # Preconditions, asserted rather than assumed: acceptance below means the
    # clause did not fire only if the record really carries acts and none of
    # them is signed.
    assert completed["acts"], "a record with no acts would satisfy acts.contains vacuously"
    assert all(act["attribution"] != "verified_signature" for act in completed["acts"])

    assert _errors(validator, completed) == []


def test_a_completed_record_carrying_both_witnesses_is_refused(validator, record):
    completed = _completed(record)
    completed["transaction_record_hash"] = STAND_IN_HASH
    completed["external_commitment_reference"] = EXTERNAL_REFERENCE

    assert _errors(validator, completed) != []


def test_a_completed_record_carrying_neither_witness_is_refused(validator, record):
    completed = _completed(record)
    completed["transaction_record_hash"] = None

    assert _errors(validator, completed) != []


@pytest.mark.parametrize(
    "witness_field,witness_value",
    [
        ("transaction_record_hash", STAND_IN_HASH),
        ("external_commitment_reference", EXTERNAL_REFERENCE),
    ],
)
def test_a_non_completed_record_carrying_a_witness_is_refused(
    validator, record, witness_field, witness_value
):
    """No outcome but COMPLETED carries a completion witness."""
    record[witness_field] = witness_value

    assert _errors(validator, record) != []


def test_a_transaction_record_hash_requires_a_did_bearing_responder(validator, record):
    """The converse direction, which neither "0.2" nor "0.3" stated.

    A TransactionRecord is bilateral by construction (Section 9.3), so a
    responder with no A2CN identity cannot have one. The verifier has enforced
    this at every record_version; "0.4" is the first schema to say it, so it
    refuses only a combination that was never valid.
    """
    completed = _completed(record)
    completed["transaction_record_hash"] = STAND_IN_HASH
    completed["parties"]["responder"] = OBSERVED_PARTY

    assert _errors(validator, completed) != []


# ---------------------------------------------------------------------------
# The act vocabulary, which is why "0.4" exists
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "signature_type",
    [
        "protocol_act_signature",
        "acceptance_signature",
        "rejection_signature",
        "withdrawal_signature",
    ],
)
def test_every_emittable_signature_type_is_admitted(validator, record, signature_type):
    """All five slots, the two new ones being the reason this version exists.

    Both enum sites have to admit them: the general one, and the narrower
    oneOf branch for a verified act. Widening only the first would leave a
    signed decline refused with one error instead of two.
    """
    act = record["acts"][0]
    act.update(
        attribution="verified_signature",
        signature_type=signature_type,
        signature="eyJ.stand-in.jws",
        sender_did="did:web:acme-corp.com",
        sender_verification_method="did:web:acme-corp.com#key-2026-01",
    )

    assert _errors(validator, record) == [], signature_type


def test_an_unknown_signature_type_is_still_refused(validator, record):
    """The negative that makes the parametrized case above worth anything."""
    act = record["acts"][0]
    act.update(
        attribution="verified_signature",
        signature_type="mandate_signature",
        signature="eyJ.stand-in.jws",
        sender_did="did:web:acme-corp.com",
        sender_verification_method="did:web:acme-corp.com#key-2026-01",
    )

    assert _errors(validator, record) != []


@pytest.mark.parametrize("version", ["0.1", "0.2", "0.3", "0.5", "0.4.0", ""])
def test_the_schema_describes_only_its_own_version(validator, record, version):
    """Each published file describes one version (Section 17)."""
    record["record_version"] = version

    assert _errors(validator, record) != []
