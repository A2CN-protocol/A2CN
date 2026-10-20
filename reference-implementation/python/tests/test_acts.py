"""verify_signed_act_reason: one signed act, checked on its own (Sections 7.3 to 7.6)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.acts import (
    ACT_REASON_DID_UNRESOLVED,
    ACT_REASON_HASH_MISMATCH,
    ACT_REASON_METHOD_NOT_CONTROLLED,
    ACT_REASON_NOT_RECOMPUTABLE,
    ACT_REASON_SIGNATURE_INVALID,
    ACT_REASON_SIGNATURE_MISSING,
    ACT_REASON_UNSUPPORTED_TYPE,
    ACT_REASON_VERSION_UNSTATED,
    verify_signed_act,
    verify_signed_act_reason,
)

VECTOR = json.loads(
    (Path(__file__).parents[3] / "spec" / "test-vectors" / "transaction-record-basis.json").read_text()
)
DIDS = VECTOR["did_documents"]
# The vector's session was signed under wire version "0.2", and its messages,
# as live acts, state no protocol_version.
WIRE = "0.2"
OFFER = next(m for m in VECTOR["messages"] if m["message_type"] == "offer")
ACCEPTANCE = next(m for m in VECTOR["messages"] if m["message_type"] == "acceptance")


@pytest.mark.parametrize("act", [OFFER, ACCEPTANCE], ids=["offer", "acceptance"])
def test_a_genuine_act_verifies_under_its_sessions_wire_version(act):
    assert verify_signed_act_reason(act, DIDS, wire_version=WIRE) is None
    assert verify_signed_act(act, DIDS, wire_version=WIRE)


def test_an_act_stating_no_version_needs_one():
    assert verify_signed_act_reason(OFFER, DIDS) == ACT_REASON_VERSION_UNSTATED


def test_an_act_rebuilt_under_another_version_does_not_verify():
    assert verify_signed_act_reason(OFFER, DIDS, wire_version="0.3") == ACT_REASON_HASH_MISMATCH
    assert verify_signed_act_reason(ACCEPTANCE, DIDS, wire_version="0.3") == ACT_REASON_SIGNATURE_INVALID


def test_a_stated_version_wins_over_the_callers():
    act = {**OFFER, "protocol_version": WIRE}
    assert verify_signed_act_reason(act, DIDS, wire_version="0.3") is None


def _changed(act, **fields):
    changed = copy.deepcopy(act)
    changed.update(fields)
    return changed


def test_altered_terms_no_longer_match_the_stated_hash():
    act = _changed(OFFER, terms={**OFFER["terms"], "total_value": OFFER["terms"]["total_value"] + 1})
    assert verify_signed_act_reason(act, DIDS, wire_version=WIRE) == ACT_REASON_HASH_MISMATCH


def test_an_altered_acceptance_no_longer_matches_its_signature():
    act = _changed(ACCEPTANCE, timestamp="2026-03-24T10:59:00Z")
    assert verify_signed_act_reason(act, DIDS, wire_version=WIRE) == ACT_REASON_SIGNATURE_INVALID


def test_a_tampered_signature_is_refused():
    signature = OFFER["protocol_act_signature"]
    act = _changed(OFFER, protocol_act_signature=signature[:-6] + "AAAAAA")
    assert verify_signed_act_reason(act, DIDS, wire_version=WIRE) == ACT_REASON_SIGNATURE_INVALID


def test_a_missing_signature_is_refused():
    act = copy.deepcopy(ACCEPTANCE)
    del act["acceptance_signature"]
    assert verify_signed_act_reason(act, DIDS, wire_version=WIRE) == ACT_REASON_SIGNATURE_MISSING


def test_a_method_outside_the_senders_did_is_refused():
    act = _changed(ACCEPTANCE, sender_verification_method="did:web:elsewhere.example#key-1")
    assert verify_signed_act_reason(act, DIDS, wire_version=WIRE) == ACT_REASON_METHOD_NOT_CONTROLLED


def test_an_unresolvable_did_is_reported_as_such():
    assert verify_signed_act_reason(ACCEPTANCE, {}, wire_version=WIRE) == ACT_REASON_DID_UNRESOLVED


def test_an_act_that_cannot_be_rebuilt_is_refused():
    act = copy.deepcopy(ACCEPTANCE)
    del act["accepted_offer_id"]
    assert verify_signed_act_reason(act, DIDS, wire_version=WIRE) == ACT_REASON_NOT_RECOMPUTABLE


@pytest.mark.parametrize("act", [{"message_type": "session_init"}, [], "offer"])
def test_only_signed_act_types_are_verified(act):
    assert verify_signed_act_reason(act, DIDS, wire_version=WIRE) == ACT_REASON_UNSUPPORTED_TYPE
