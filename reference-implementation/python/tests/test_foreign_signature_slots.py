"""An act carries no signature field but its own (Section 7.3.1).

The state machine used to look only at the signature field of the act's own
type, so an act carrying another type's field — an offer with a
rejection_signature, a withdrawal with an acceptance_signature — was admitted
with that field never looked at. The evidence record reads every signature field
as a signature claim, so the session's record then failed verification, or,
beside a valid own signature, could not be generated at all. Every act type had
the hole. foreign-signature-slots.json pins the refusal and shows, for every
case, that the session still produces an evidence record that verifies.

The TypeScript suite runs the same cases.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from a2cn.crypto import public_key_to_jwk, sign_jws
from a2cn.evidence import generate_session_evidence_record, verify_session_evidence_record
from a2cn.messages import PROTOCOL_ACT_VERSION, SIGNED_ACT_SIGNATURE_FIELDS, signed_act_hash
from a2cn.session import A2CNError
from tests.conftest import make_did_document
from tests.test_session import (
    INITIATOR_DID,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_PUBLIC_KEY,
    RESPONDER_DID,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_PUBLIC_KEY,
    _make_acceptance,
    _make_offer,
    _new_session,
)

REPO_ROOT = Path(__file__).parents[3]
VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "foreign-signature-slots.json").read_text()
)
CASES = VECTOR["cases"]
RESPONDER_VM = VECTOR["session"]["responder_verification_method"]
DID_DOCUMENTS = {
    INITIATOR_DID: make_did_document(INITIATOR_DID, "key-1", public_key_to_jwk(INITIATOR_PUBLIC_KEY)),
    RESPONDER_DID: make_did_document(
        RESPONDER_DID, "key-2026-01", public_key_to_jwk(RESPONDER_PUBLIC_KEY)
    ),
}


def _decline(session_id: str, act_type: str, signed: bool) -> dict:
    act = {
        "message_type": act_type,
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 2,
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "acme-agent",
        "timestamp": "2026-03-24T10:05:00Z",
    }
    if act_type == "rejection":
        act["rejected_offer_id"] = "offer-1"
        act["reason_code"] = "PRICE_TOO_HIGH"
    else:
        act["reason_code"] = "STRATEGY_DECISION"
    if signed:
        act["sender_verification_method"] = RESPONDER_VM
        act[SIGNED_ACT_SIGNATURE_FIELDS[act_type]] = sign_jws(
            signed_act_hash(
                act, version_when_absent=PROTOCOL_ACT_VERSION
            ), RESPONDER_PRIVATE_KEY, kid=RESPONDER_VM
        )
    return act


def _act_for(manager, session, case: dict) -> dict:
    """Build the case's act as act_setup says, then add its stray field."""
    act_type = case["act_type"]
    if act_type == "offer":
        act = _make_offer(session.session_id, 1, 1, INITIATOR_DID)
    else:
        offer = _make_offer(session.session_id, 1, 1, INITIATOR_DID)
        manager.process_message(session, offer)
        if act_type == "counteroffer":
            act = _make_offer(session.session_id, 2, 2, RESPONDER_DID, msg_type="counteroffer")
        elif act_type == "acceptance":
            act = _make_acceptance(session, offer)
        else:
            act = _decline(session.session_id, act_type, case["signed"])
    if "stray_field" in case:
        act[case["stray_field"]] = case["stray_value"]
    return act


def _close_and_record(manager, session) -> dict:
    if not session.is_terminal():
        manager.process_message(
            session,
            {
                "message_type": "withdrawal",
                "message_id": str(uuid.uuid4()),
                "session_id": session.session_id,
                "round_number": max(session.round_number, 1),
                "sequence_number": session.sequence_number + 1,
                "sender_did": INITIATOR_DID,
                "timestamp": "2026-03-24T10:09:00Z",
                "reason_code": "STRATEGY_DECISION",
            },
        )
    return generate_session_evidence_record(
        session,
        producer_private_key=INITIATOR_PRIVATE_KEY,
        producer_did=INITIATOR_DID,
        producer_agent_id="buyer-agent",
        producer_verification_method=f"{INITIATOR_DID}#key-1",
    )


def test_the_vector_matches_this_implementation_and_its_fixtures():
    assert VECTOR["signature_fields"] == SIGNED_ACT_SIGNATURE_FIELDS
    assert VECTOR["session"]["initiator_did"] == INITIATOR_DID
    assert VECTOR["session"]["responder_did"] == RESPONDER_DID
    for case in CASES:
        if "stray_field" in case:
            assert case["stray_field"] != SIGNED_ACT_SIGNATURE_FIELDS[case["act_type"]]
    # Every act type has a control and at least one refused case.
    for act_type in SIGNED_ACT_SIGNATURE_FIELDS:
        verdicts = {case["accepted"] for case in CASES if case["act_type"] == act_type}
        assert verdicts == {True, False}, act_type


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_foreign_signature_slot(case):
    manager, session = _new_session(VECTOR["session"]["session_id"])
    act = _act_for(manager, session, case)

    if case["accepted"]:
        manager.process_message(session, act)
        assert session.state == case["state_after"]
        assert act in session._message_log
    else:
        state_before = session.state
        with pytest.raises(A2CNError) as excinfo:
            manager.process_message(session, act)
        assert (excinfo.value.code, excinfo.value.message) == (
            case["error_code"],
            case["error_message"],
        )
        assert session.state == state_before
        assert act not in session._message_log

    record = _close_and_record(manager, session)
    assert verify_session_evidence_record(record, DID_DOCUMENTS) is case["record_verifies"]
