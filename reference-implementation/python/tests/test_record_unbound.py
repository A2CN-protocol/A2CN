"""A verifier accepts only records it can rebind (Section 9.5).

record_version is covered by no signature. A verifier that accepted a version
whose records cannot be rebound would let a presenter strip the Section 7.3.1
act fields, relabel the record to that version, alter agreed_terms and reseal:
both signatures still verify and the record keeps its record_id, so the forgery
would be reported as genuine. There is therefore no unbound accepted tier. Only
the bound version is accepted; a version this implementation knows but cannot
rebind is rejected with UNBOUND_RECORD_VERSION, distinct from the generic
rejection any other value gets.

This is a deliberate break: records produced before the act fields existed no
longer verify and must be regenerated.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn import record as record_module
from a2cn.crypto import hash_object
from a2cn.record import (
    ACCEPTED_TRANSACTION_RECORD_VERSIONS,
    FINAL_OFFER_ACT_FIELDS,
    KNOWN_TRANSACTION_RECORD_VERSIONS,
    REASON_UNBOUND_RECORD_VERSION,
    REASON_UNRECOGNIZED_RECORD_VERSION,
    TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
    verify_transaction_record,
    verify_transaction_record_reason,
)

REPO_ROOT = Path(__file__).parents[3]
VECTORS = REPO_ROOT / "spec" / "test-vectors"
VECTOR = json.loads((VECTORS / "transaction-record-basis.json").read_text())
RECORD_VERSIONS = json.loads((VECTORS / "record-versions.json").read_text())
# Each artifact versions its own shape, so the TransactionRecord's set is its own.
TR_VERSIONS = RECORD_VERSIONS["transaction_record"]
WITHOUT_BASIS = VECTOR["without_basis"]
DOWNGRADE = VECTOR["downgrade_attack"]
BOUND = VECTOR["expected"]["record_version_0_3"]["full_record"]
# The cases both suites apply to that record, one for each reason a verifier can
# give, so the two implementations must name the same cause for the same bytes.
REASON_API = VECTOR["reason_api"]
TAMPERED_SUFFIX = REASON_API["tampered_signature_suffix"]
# Every reason code the module exports, found by reflection: a code added
# without a case fails this file rather than sitting unreachable.
ALL_REASON_CODES = {
    getattr(record_module, name)
    for name in dir(record_module)
    if name.startswith("REASON_")
}

# The recorded session each record shape came from, for its DID documents and
# its offer chain.
SHAPE_VECTOR = {"0.1": WITHOUT_BASIS, "0.2": VECTOR, "0.3": VECTOR}


def _offer_hashes(vector: dict) -> list[str]:
    return [
        message["protocol_act_hash"]
        for message in vector["messages"]
        if message["message_type"] in ("offer", "counteroffer")
    ]


def _shape(version: str) -> dict:
    """A valid record of the given shape, as its producer emitted it."""
    if version == "0.3":
        return copy.deepcopy(BOUND)
    if version == "0.2":
        return copy.deepcopy(VECTOR["expected"]["record_version_0_2"]["full_record"])
    return copy.deepcopy(WITHOUT_BASIS["record_version_0_1"]["full_record"])


def _resealed(record: dict) -> dict:
    record = copy.deepcopy(record)
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)
    return record


def _verdict(record: dict, shape: str = "0.3") -> tuple[bool, str | None]:
    """The boolean and the reason, which must always agree."""
    vector = SHAPE_VECTOR[shape]
    args = (record, vector["did_documents"], _offer_hashes(vector))
    return verify_transaction_record(*args), verify_transaction_record_reason(*args)


# ---------------------------------------------------------------------------
# The downgrade a verifier must refuse
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", DOWNGRADE["cases"], ids=lambda case: case["name"])
def test_a_downgraded_record_is_rejected(case):
    """Both signatures still verify and the record_id is the genuine one."""
    record = case["full_record"]

    assert record["record_hash"] == case["record_hash"]
    assert record["record_id"] == BOUND["record_id"]
    assert (
        record["final_offer"]["protocol_act_signature"]
        == BOUND["final_offer"]["protocol_act_signature"]
    )

    verified, reason = _verdict(record)
    assert verified is False
    assert reason == case["expected_reason"] == REASON_UNBOUND_RECORD_VERSION


def test_the_untouched_downgrade_is_the_historical_record_itself():
    """Stripping the act fields and relabelling reproduces the "0.2" record exactly.

    That is what made the unbound tier a downgrade oracle: the forged shape and
    the genuine older artifact are the same bytes, so accepting one accepted the
    other.
    """
    untouched = next(
        case for case in DOWNGRADE["cases"]
        if case["name"] == "stripped-and-relabelled-0.2-terms-untouched"
    )

    assert untouched["record_hash"] == VECTOR["expected"]["record_version_0_2"]["record_hash"]


# ---------------------------------------------------------------------------
# The collapsed accepted set
# ---------------------------------------------------------------------------

def test_only_the_bound_version_is_accepted():
    assert ACCEPTED_TRANSACTION_RECORD_VERSIONS == (
        TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
    )
    assert list(ACCEPTED_TRANSACTION_RECORD_VERSIONS) == TR_VERSIONS["accepted"]
    # The older shapes are still known, because their schema files are published.
    assert set(KNOWN_TRANSACTION_RECORD_VERSIONS) == {"0.1", "0.2", "0.3"}
    assert set(ACCEPTED_TRANSACTION_RECORD_VERSIONS) < set(KNOWN_TRANSACTION_RECORD_VERSIONS)


def test_the_bound_record_still_verifies():
    verified, reason = _verdict(_shape("0.3"))

    assert verified is True
    assert reason is None


@pytest.mark.parametrize(
    "case", TR_VERSIONS["unbound"], ids=lambda case: case["name"]
)
def test_a_known_but_unbindable_version_is_rejected_as_unbound(case):
    """A version this implementation knows but cannot rebind (Section 9.5)."""
    record = _shape(case["shape"])
    record["record_version"] = case["record_version"]

    verified, reason = _verdict(_resealed(record), case["shape"])
    assert verified is False
    assert reason == REASON_UNBOUND_RECORD_VERSION
    # The reason both implementations report is the one the shared vector names.
    assert reason == TR_VERSIONS["unbound_reason"]


@pytest.mark.parametrize(
    "case", TR_VERSIONS["rejected"], ids=lambda case: case["name"]
)
def test_a_value_that_is_not_a_known_version_is_rejected_as_unrecognized(case):
    """The generic rejection stays, and is distinct from the unbound one."""
    record = _shape("0.3")
    if "record_version" in case:
        record["record_version"] = copy.deepcopy(case["record_version"])
    else:
        del record["record_version"]

    verified, reason = _verdict(_resealed(record))
    assert verified is False
    assert reason == REASON_UNRECOGNIZED_RECORD_VERSION
    assert reason != REASON_UNBOUND_RECORD_VERSION
    assert reason == TR_VERSIONS["unrecognized_reason"]


# ---------------------------------------------------------------------------
# The boolean API is unchanged
# ---------------------------------------------------------------------------

def test_the_boolean_verifier_keeps_its_signature_and_return_type():
    """Callers that only want a verdict are untouched by the reason API."""
    vector = VECTOR
    record = _shape("0.3")

    assert verify_transaction_record(record, vector["did_documents"]) is False
    verdict = verify_transaction_record(
        record, vector["did_documents"], _offer_hashes(vector)
    )
    assert isinstance(verdict, bool)
    assert verdict is True


def test_the_reason_is_none_exactly_when_the_boolean_is_true():
    """The two entry points never disagree, and a reason is never a bool.

    The boolean is `reason(...) is None`, and `False is None` is False, so a
    reason that is a bool keeps the verdict right while the diagnostic lies.
    Pinning only the agreement cannot see that; pinning the type can.
    """
    records = [
        _shape("0.3"),
        _resealed({**_shape("0.3"), "record_version": "0.2"}),
        DOWNGRADE["cases"][0]["full_record"],
    ] + [_mutated(case) for case in REASON_API["cases"]]

    for record in records:
        verified, reason = _verdict(record)
        assert verified is (reason is None)
        # A reason is a string or absent, never False, 0 or another falsy value.
        assert reason is None or isinstance(reason, str)
        assert not isinstance(reason, bool)


# ---------------------------------------------------------------------------
# The reason names the real cause (Section 9.5)
# ---------------------------------------------------------------------------

def _mutated(case: dict) -> dict:
    """Apply one shared case to the bound record, resealing when it says to."""
    record = _shape("0.3")
    mutation = case["mutation"]
    value = case.get("value")

    if mutation == "tamper_offer_signature":
        signature = record["final_offer"]["protocol_act_signature"]
        record["final_offer"]["protocol_act_signature"] = (
            signature[: -len(TAMPERED_SUFFIX)] + TAMPERED_SUFFIX
        )
    elif mutation == "tamper_acceptance_signature":
        signature = record["final_acceptance"]["acceptance_signature"]
        record["final_acceptance"]["acceptance_signature"] = (
            signature[: -len(TAMPERED_SUFFIX)] + TAMPERED_SUFFIX
        )
    elif mutation == "drop_final_offer":
        del record["final_offer"]
    elif mutation == "drop_final_acceptance":
        del record["final_acceptance"]
    elif mutation == "set_record_version":
        record["record_version"] = value
    elif mutation == "strip_act_fields":
        for field in FINAL_OFFER_ACT_FIELDS:
            record["final_offer"].pop(field, None)
    elif mutation == "set_currency":
        record["currency"] = value
    elif mutation == "set_agreed_terms_total_value":
        record["agreed_terms"]["total_value"] = value
    elif mutation == "flip_basis":
        record["basis"] = "gross" if record["basis"] == "net" else "net"
    elif mutation == "set_accepted_hash":
        record["final_acceptance"]["accepted_protocol_act_hash"] = value
    elif mutation == "set_offer_chain_hash":
        record["offer_chain_hash"] = value
    else:
        raise AssertionError(f"unknown mutation {mutation}")

    return _resealed(record) if case["reseal"] else record


@pytest.mark.parametrize("case", REASON_API["cases"], ids=lambda case: case["name"])
def test_the_reason_names_the_real_cause(case):
    """A tampered signature is a signature failure, not a malformed record.

    verify_jws raises on bad signature bytes. Letting that escape to the outer
    handler reports the single most likely failure -- someone edited a
    signature -- as the catch-all.
    """
    verified, reason = _verdict(_mutated(case))

    assert verified is False
    assert reason == case["expected_reason"]
    assert isinstance(reason, str)


def test_every_reason_code_is_reachable():
    """No exported reason code is dead.

    REASON_MALFORMED_RECORD was defined and never returned, because the handler
    that should have returned it returned False instead. A code no case can
    reach is either a missing test or a lie in the taxonomy.
    """
    observed = {_verdict(_mutated(case))[1] for case in REASON_API["cases"]}

    assert observed == ALL_REASON_CODES
