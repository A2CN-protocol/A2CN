"""One protocol, one rule: an act's counters are judged by value on every path.

RFC 8785 serializes 2.0 and 2 as the same number, so they are one signed act in
two JSON spellings and must reach one verdict. The record path and the shared
primitive always judged them that way. The evidence path did not: it asked
Python's ``isinstance(value, int)``, a type question rather than a protocol one,
so the same record bytes assessed valid in TypeScript and invalid here.

``act_integer_spellings`` in transaction-record-basis.json pins the seven
verdicts. Until now only test_record_act_binding consumed it, so only the record
path was held to them and nothing tested the evidence path at all. These tests
drive the same cases through the evidence path, so neither path can move without
the other failing here.

WHAT THIS ASSERTS, AND WHY NOT ``attribution``. An earlier version of this file
asserted ``attribution`` and could not distinguish the cases: attribution is
stamped at generation on the mere PRESENCE of a signature, so it reads
``verified_signature`` for a forged or unrebuildable act too. The verdict that
actually moves is the record's, so that is what is asserted.

Direction matters for what the negatives are worth: this is a LOOSENING on the
evidence side — 2.0 is now accepted where it was refused — so the risk is
over-loosening, and all five refusing cases are asserted, not just the two
accepting ones. The TypeScript mirror of this file is a parity guard rather than
a proof of the same fix: that side already accepted the integral float, so only
Python's verdicts move.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import a2cn.evidence as evidence_module
import a2cn.record as record_module
from a2cn.crypto import sign_jws
from a2cn.evidence import assess_session_evidence_record
from a2cn.messages import SIGNED_ACT_SIGNATURE_FIELDS, _is_act_integer, signed_act_hash
from tests.test_evidence import (
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
    _generate,
    _make_session,
    _mark_timed_out,
)
from tests.test_signed_decline_acts import _rejection

REPO_ROOT = Path(__file__).parents[3]
VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "transaction-record-basis.json").read_text()
)
ACT_INTEGER_SPELLINGS = VECTOR["record_version_0_4_binding"]["act_integer_spellings"]

# A spelling that breaks a covered field cannot be rebuilt, so it has no honest
# hash to sign. An attacker in that position signs something; so does this.
UNREBUILDABLE_STAND_IN = "0" * 43


def _spelled(spelling: dict, session_id: str) -> dict:
    act = _rejection(session_id)
    if "value" in spelling:
        act[spelling["field"]] = spelling["value"]
    else:
        del act[spelling["field"]]
    return act


def _signed(act: dict) -> dict:
    act = copy.deepcopy(act)
    act["sender_verification_method"] = RESPONDER_VM
    payload_hash = signed_act_hash(act) or UNREBUILDABLE_STAND_IN
    act[SIGNED_ACT_SIGNATURE_FIELDS["rejection"]] = sign_jws(
        payload_hash, RESPONDER_PRIVATE_KEY, kid=RESPONDER_VM
    )
    return act


def _assess_spelling(spelling: dict) -> dict:
    """Build the act against the real session, then assess the sealed record.

    The act has to be built after the session exists: Section 9A binds a signed
    act's session_id to the record's, so an act carrying any other value is
    refused for that reason rather than for its integer spelling, and every
    case would read as invalid for the wrong cause.
    """
    _manager, session, did_documents = _make_session()
    session._message_log = [_signed(_spelled(spelling, session.session_id))]
    _mark_timed_out(session)
    return assess_session_evidence_record(_generate(session), did_documents)


def test_an_unmutated_signed_rejection_verifies():
    """The control, without which none of the cases below mean anything.

    If the harness could not verify an untouched act, every spelling would read
    as refused and the table would pass while proving nothing at all.
    """
    _manager, session, did_documents = _make_session()
    session._message_log = [_signed(_rejection(session.session_id))]
    _mark_timed_out(session)

    assessment = assess_session_evidence_record(_generate(session), did_documents)

    assert assessment["valid"] is True
    assert assessment["verified_acts"] == 1
    assert assessment["invalid_acts"] == 0


@pytest.mark.parametrize(
    "spelling", ACT_INTEGER_SPELLINGS, ids=lambda spelling: spelling["name"]
)
def test_the_evidence_path_judges_an_act_integer_spelling_by_value(spelling):
    """The same seven cases the record path is held to, on the evidence path.

    An integral float is the same act in a different spelling and must verify.
    Anything that is not an integral JSON number — fractional, a string, a
    boolean, null, or absent — is a different act or no act, and must not.
    """
    assessment = _assess_spelling(spelling)

    assert assessment["valid"] is spelling["verifies"], spelling["name"]


def test_the_vector_still_carries_both_outcomes():
    """A guard on the vector, so this file cannot silently come to test nothing.

    Reduced to only-accepting or only-refusing cases, the parametrized test
    above would still pass while proving far less.
    """
    verdicts = [spelling["verifies"] for spelling in ACT_INTEGER_SPELLINGS]

    assert verdicts.count(True) == 2, verdicts
    assert verdicts.count(False) == 5, verdicts


# ---------------------------------------------------------------------------
# The primitive itself
# ---------------------------------------------------------------------------
#
# The vector cases above exercise the rule through the evidence path. They would
# still pass if each path kept its own copy of the predicate and the copies
# happened to agree -- which is exactly the state this consolidation ended, and
# exactly the drift it exists to prevent. So the primitive is pinned here by
# name, and the paths are asserted to be the same function object.

ACT_INTEGER_PRIMITIVE_CASES = [
    pytest.param(2, True, id="int"),
    pytest.param(2.0, True, id="integral-float"),
    pytest.param(1e0, True, id="exponent-spelling"),
    pytest.param(0, True, id="zero"),
    pytest.param(-3, True, id="negative-int"),
    pytest.param(2.5, False, id="fractional"),
    pytest.param("2", False, id="string"),
    pytest.param(True, False, id="bool-true"),
    pytest.param(False, False, id="bool-false"),
    pytest.param(None, False, id="null"),
]


@pytest.mark.parametrize(("value", "accepted"), ACT_INTEGER_PRIMITIVE_CASES)
def test_the_act_integer_primitive_judges_by_value(value, accepted):
    """One definition, called by the record, evidence and act paths alike.

    A bool is an int in Python and is excluded explicitly; TypeScript's typeof
    excludes it on its own, which is what keeps the two verdicts identical.

    The `>= 1` floor is deliberately NOT here. It belongs to the call sites that
    need it, so this primitive accepts 0 and negatives; folding a floor in would
    silently make an OPTIONAL null sequence_number mandatory at the sites that
    guard on `value is not None` separately.
    """
    assert _is_act_integer(value) is accepted


def test_every_path_shares_one_definition_of_the_primitive():
    """Not two byte-identical copies agreeing by coincidence: one check, not two.

    Without this, deleting the import and restoring a local copy in either
    module would leave the whole suite green until the copies drifted.
    """
    assert record_module._is_act_integer is _is_act_integer
    assert evidence_module._is_act_integer is _is_act_integer
