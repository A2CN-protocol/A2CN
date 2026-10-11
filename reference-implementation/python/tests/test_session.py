"""Tests for a2cn.session — state machine, turn-taking, idempotency."""

import uuid
import pytest

from a2cn.session import Session, SessionManager, SessionState, A2CNError
from a2cn.crypto import (
    generate_ed25519_keypair,
    generate_keypair,
    hash_object,
    public_key_to_jwk,
    sign_approval_receipt,
    sign_jws,
)
from a2cn.messages import PROTOCOL_ACT_VERSION, signed_act_hash
from a2cn.record import generate_audit_log
from tests.conftest import make_did_document, sign_decline


INITIATOR_DID = "did:web:techcorp.example"
RESPONDER_DID = "did:web:acme-corp.com"

SESSION_INIT = {
    "message_type": "session_init",
    "message_id": "init-msg-id",
    "protocol_version": "0.3",
    "session_params": {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "subject": "Test",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    },
    "initiator": {
        "organization_name": "TechCorp",
        "did": INITIATOR_DID,
        "verification_method": f"{INITIATOR_DID}#key-1",
        "agent_id": "tc-agent",
        "endpoint": "https://techcorp.example/api/a2cn",
    },
    "initiator_mandate": {"mandate_type": "declared"},
}

SESSION_ACK = {
    "message_type": "session_ack",
    "message_id": "ack-msg-id",
    "session_id": "sess-001",
    "in_reply_to": "init-msg-id",
    "protocol_version": "0.3",
    "session_params_accepted": {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    },
    "responder": {
        "organization_name": "Acme",
        "did": RESPONDER_DID,
        "verification_method": f"{RESPONDER_DID}#key-2026-01",
        "agent_id": "acme-agent",
        "endpoint": "http://localhost:8000",
    },
    "responder_mandate": {"mandate_type": "declared"},
    "session_created_at": "2026-03-24T10:00:00Z",
    "current_turn": "initiator",
}

INITIATOR_PRIVATE_KEY, INITIATOR_PUBLIC_KEY = generate_keypair()
RESPONDER_PRIVATE_KEY, RESPONDER_PUBLIC_KEY = generate_keypair()


def _make_offer(
    session_id,
    seq,
    rnd,
    sender_did,
    msg_type="offer",
    in_reply_to=None,
    terms=None,
):
    timestamp = "2026-03-24T10:01:00Z"
    expires_at = "2030-01-01T00:00:00Z"
    terms = terms or {"total_value": 9_500_000, "currency": "USD"}
    protocol_act = {
        "protocol_version": "0.3",
        "session_id": session_id,
        "round_number": rnd,
        "sequence_number": seq,
        "message_type": msg_type,
        "sender_did": sender_did,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
    }
    pah = hash_object(protocol_act)
    private_key = INITIATOR_PRIVATE_KEY if sender_did == INITIATOR_DID else RESPONDER_PRIVATE_KEY
    verification_method = (
        f"{INITIATOR_DID}#key-1"
        if sender_did == INITIATOR_DID
        else f"{RESPONDER_DID}#key-2026-01"
    )
    msg = {
        "message_type": msg_type,
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "round_number": rnd,
        "sequence_number": seq,
        "sender_did": sender_did,
        "sender_agent_id": "agent",
        "sender_verification_method": verification_method,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
        "protocol_act_hash": pah,
        "protocol_act_signature": sign_jws(pah, private_key, kid=verification_method),
    }
    if in_reply_to:
        msg["in_reply_to"] = in_reply_to
    return msg


def _resign_offer(offer: dict) -> None:
    protocol_act = {
        "protocol_version": "0.3",
        "session_id": offer["session_id"],
        "round_number": offer["round_number"],
        "sequence_number": offer["sequence_number"],
        "message_type": offer["message_type"],
        "sender_did": offer["sender_did"],
        "timestamp": offer["timestamp"],
        "expires_at": offer["expires_at"],
        "terms": offer["terms"],
    }
    offer["protocol_act_hash"] = hash_object(protocol_act)
    private_key = INITIATOR_PRIVATE_KEY if offer["sender_did"] == INITIATOR_DID else RESPONDER_PRIVATE_KEY
    offer["protocol_act_signature"] = sign_jws(
        offer["protocol_act_hash"],
        private_key,
        kid=offer["sender_verification_method"],
    )


def _make_acceptance(sess: Session, offer: dict, *, msg_id="acc-1") -> dict:
    sender_did = RESPONDER_DID
    verification_method = f"{RESPONDER_DID}#key-2026-01"
    acceptance = {
        "message_type": "acceptance",
        "message_id": msg_id,
        "session_id": sess.session_id,
        "in_reply_to": offer["message_id"],
        "round_number": offer["round_number"],
        "sequence_number": sess.sequence_number + 1,
        "accepted_offer_id": offer["message_id"],
        "accepted_protocol_act_hash": offer["protocol_act_hash"],
        "sender_did": sender_did,
        "sender_agent_id": "acme-agent",
        "sender_verification_method": verification_method,
        "timestamp": "2026-03-24T10:05:00Z",
    }
    # Signed over the act's own envelope (Section 7.3.1), built from the very
    # message the state machine receives.
    acceptance["acceptance_signature"] = sign_jws(
        signed_act_hash(acceptance, version_when_absent=PROTOCOL_ACT_VERSION),
        RESPONDER_PRIVATE_KEY,
        kid=verification_method,
    )
    return acceptance


def _new_session(session_id="sess-001") -> tuple[SessionManager, Session]:
    mgr = SessionManager()
    mgr.register_did_document(
        INITIATOR_DID,
        make_did_document(INITIATOR_DID, "key-1", public_key_to_jwk(INITIATOR_PUBLIC_KEY)),
    )
    mgr.register_did_document(
        RESPONDER_DID,
        make_did_document(RESPONDER_DID, "key-2026-01", public_key_to_jwk(RESPONDER_PUBLIC_KEY)),
    )
    sess = mgr.create_session(session_id, SESSION_INIT, SESSION_ACK, "2026-03-24T10:00:00Z")
    # Tests use a historical created_at; give them a large timeout so they never expire
    sess.session_timeout_seconds = 86400 * 365 * 100
    return mgr, sess


# ---------------------------------------------------------------------------
# Session creation
# ---------------------------------------------------------------------------

def test_create_session_state():
    mgr, sess = _new_session()
    assert sess.state == SessionState.ACTIVE
    assert sess.current_turn == "initiator"
    assert sess.round_number == 0
    assert sess.sequence_number == 0


# ---------------------------------------------------------------------------
# Turn-taking (Section 3.2)
# ---------------------------------------------------------------------------

def test_offer_from_wrong_turn_raises_not_your_turn():
    mgr, sess = _new_session()
    # Responder tries to send an offer before initiator
    offer = _make_offer(sess.session_id, 1, 1, RESPONDER_DID)
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, offer)
    assert exc_info.value.code == "NOT_YOUR_TURN"


def test_offer_from_correct_turn_accepted():
    mgr, sess = _new_session()
    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, offer)
    assert sess.state == SessionState.NEGOTIATING
    assert sess.current_turn == "responder"
    assert sess.round_number == 1


def test_turn_flips_after_counteroffer():
    mgr, sess = _new_session()
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, o1)
    assert sess.current_turn == "responder"

    co1 = _make_offer(sess.session_id, 2, 2, RESPONDER_DID, msg_type="counteroffer",
                      in_reply_to=o1["message_id"])
    mgr.process_message(sess, co1)
    assert sess.current_turn == "initiator"
    assert sess.round_number == 2


def test_impasse_counts_only_full_rounds_with_no_change():
    mgr, sess = _new_session()
    sess.max_rounds = 6
    sess.impasse_threshold = 2

    totals = [
        (INITIATOR_DID, 10_000_000),
        (RESPONDER_DID, 9_900_000),
        (INITIATOR_DID, 10_000_000),
        (RESPONDER_DID, 9_900_000),
        (INITIATOR_DID, 10_000_000),
        (RESPONDER_DID, 9_900_000),
    ]

    previous = None
    for index, (sender_did, total_value) in enumerate(totals, start=1):
        message = _make_offer(
            sess.session_id,
            index,
            index,
            sender_did,
            msg_type="offer" if index == 1 else "counteroffer",
            in_reply_to=previous,
            terms={"total_value": total_value, "currency": "USD"},
        )
        mgr.process_message(sess, message)
        previous = message["message_id"]

        if index == 3:
            assert sess.consecutive_non_moving_rounds == 0
            assert sess.state == SessionState.NEGOTIATING
        if index == 4:
            assert sess.consecutive_non_moving_rounds == 1
            assert sess.state == SessionState.NEGOTIATING

    assert sess.state == SessionState.IMPASSE
    assert sess.current_turn == "none"
    assert sess.consecutive_non_moving_rounds == 2


def test_impasse_treats_any_total_value_change_as_movement():
    mgr, sess = _new_session()
    sess.max_rounds = 6
    sess.impasse_threshold = 1

    totals = [
        (INITIATOR_DID, 10_000_000),
        (RESPONDER_DID, 9_999_980),
        (INITIATOR_DID, 10_000_020),
        (RESPONDER_DID, 9_999_980),
    ]

    previous = None
    for index, (sender_did, total_value) in enumerate(totals, start=1):
        message = _make_offer(
            sess.session_id,
            index,
            index,
            sender_did,
            msg_type="offer" if index == 1 else "counteroffer",
            in_reply_to=previous,
            terms={"total_value": total_value, "currency": "USD"},
        )
        mgr.process_message(sess, message)
        previous = message["message_id"]

    assert sess.state == SessionState.NEGOTIATING
    assert sess.consecutive_non_moving_rounds == 0


# ---------------------------------------------------------------------------
# Sequence number enforcement (Section 7.1)
# ---------------------------------------------------------------------------

def test_wrong_sequence_number_raises():
    mgr, sess = _new_session()
    offer = _make_offer(sess.session_id, 5, 1, INITIATOR_DID)  # wrong seq
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, offer)
    assert exc_info.value.code == "SEQUENCE_ERROR"


def test_sequence_monotonically_increments():
    mgr, sess = _new_session()
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, o1)
    assert sess.sequence_number == 1

    co1 = _make_offer(sess.session_id, 2, 2, RESPONDER_DID, msg_type="counteroffer",
                      in_reply_to=o1["message_id"])
    mgr.process_message(sess, co1)
    assert sess.sequence_number == 2


# ---------------------------------------------------------------------------
# Idempotency (Section 6.1)
# ---------------------------------------------------------------------------

def test_duplicate_message_returns_same_response():
    mgr, sess = _new_session()
    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    r1 = mgr.process_message(sess, offer)
    r2 = mgr.process_message(sess, offer)
    assert r1 == r2
    assert sess.sequence_number == 1  # not incremented twice


# ---------------------------------------------------------------------------
# Terminal state enforcement
# ---------------------------------------------------------------------------

def test_message_on_terminal_session_raises():
    mgr, sess = _new_session()
    # Force terminal state
    withdrawal = {
        "message_type": "withdrawal",
        "message_id": "w-1",
        "session_id": sess.session_id,
        "round_number": 1,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "tc-agent",
        "timestamp": "2026-03-24T10:02:00Z",
        "reason_code": "STRATEGY_DECISION",
    }
    withdrawal = sign_decline(withdrawal, INITIATOR_PRIVATE_KEY, f"{INITIATOR_DID}#key-1")
    mgr.process_message(sess, withdrawal)
    assert sess.state == SessionState.WITHDRAWN

    # Now try to send another message
    offer = _make_offer(sess.session_id, 2, 1, INITIATOR_DID)
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, offer)
    assert exc_info.value.code == "SESSION_WRONG_STATE"


# ---------------------------------------------------------------------------
# Acceptance
# ---------------------------------------------------------------------------

def test_acceptance_transitions_to_completed():
    mgr, sess = _new_session()
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, o1)

    acceptance = _make_acceptance(sess, o1)
    mgr.process_message(sess, acceptance)
    assert sess.state == SessionState.COMPLETED
    assert sess.current_turn == "none"


# ---------------------------------------------------------------------------
# WRONG_MESSAGE_TYPE
# ---------------------------------------------------------------------------

def test_offer_in_round2_wrong_type_raises():
    mgr, sess = _new_session()
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, o1)

    # Responder sends "offer" in round 2 (should be "counteroffer")
    bad = _make_offer(sess.session_id, 2, 2, RESPONDER_DID, msg_type="offer",
                      in_reply_to=o1["message_id"])
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, bad)
    assert exc_info.value.code == "WRONG_MESSAGE_TYPE"


# ---------------------------------------------------------------------------
# REJECTED_FINAL at max_rounds
# ---------------------------------------------------------------------------

def test_rejection_at_max_rounds_transitions_to_rejected_final():
    mgr, sess = _new_session()
    sess.max_rounds = 1  # single-round session

    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, o1)

    rejection = {
        "message_type": "rejection",
        "message_id": "rej-1",
        "session_id": sess.session_id,
        "in_reply_to": o1["message_id"],
        "round_number": 1,
        "sequence_number": 2,
        "rejected_offer_id": o1["message_id"],
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "acme-agent",
        "timestamp": "2026-03-24T10:05:00Z",
        "reason_code": "PRICE_TOO_LOW",
    }
    rejection = sign_decline(rejection, RESPONDER_PRIVATE_KEY, f"{RESPONDER_DID}#key-2026-01")
    mgr.process_message(sess, rejection)
    assert sess.state == SessionState.REJECTED_FINAL


# ---------------------------------------------------------------------------
# Security fixes (findings 2.8, 2.9, 4.1, 4.2, 4.3, 5.5)
# ---------------------------------------------------------------------------

def test_invalid_message_type_rejected():
    """Finding 4.1: unknown message_type raises WRONG_MESSAGE_TYPE."""
    mgr, sess = _new_session()
    bad = {
        "message_type": "surprise",
        "message_id": str(uuid.uuid4()),
        "session_id": sess.session_id,
        "sequence_number": 1,
        "round_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "agent",
        "timestamp": "2026-03-24T10:01:00Z",
    }
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, bad)
    assert exc_info.value.code == "WRONG_MESSAGE_TYPE"
    assert exc_info.value.http_status == 422


def test_invalid_sender_did_rejected():
    """Finding 4.1: non-DID sender_did raises INVALID_REQUEST."""
    mgr, sess = _new_session()
    bad = {
        "message_type": "offer",
        "message_id": str(uuid.uuid4()),
        "session_id": sess.session_id,
        "sequence_number": 1,
        "round_number": 1,
        "sender_did": "not-a-did",
        "sender_agent_id": "agent",
        "timestamp": "2026-03-24T10:01:00Z",
    }
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, bad)
    assert exc_info.value.code == "INVALID_REQUEST"
    assert exc_info.value.http_status == 400


def test_unknown_sender_did_raises_unauthorized_sender():
    """Finding 5.5: DID not party to session raises UNAUTHORIZED_SENDER."""
    mgr, sess = _new_session()
    o = _make_offer(sess.session_id, 1, 1, "did:web:stranger.example")
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, o)
    assert exc_info.value.code == "UNAUTHORIZED_SENDER"
    assert exc_info.value.http_status == 403


def test_protocol_act_hash_mismatch_rejected():
    """Finding 4.3: tampered protocol_act_hash raises INVALID_SIGNATURE."""
    mgr, sess = _new_session()
    o = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    o["protocol_act_hash"] = "sha256-tampered-hash"
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, o)
    assert exc_info.value.code == "INVALID_SIGNATURE"
    assert exc_info.value.http_status == 400


def test_protocol_act_signature_mismatch_rejected():
    mgr, sess = _new_session()
    o = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    o["protocol_act_signature"] = sign_jws(
        o["protocol_act_hash"],
        RESPONDER_PRIVATE_KEY,
        kid=f"{RESPONDER_DID}#key-2026-01",
    )
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, o)
    assert exc_info.value.code == "INVALID_SIGNATURE"
    assert exc_info.value.http_status == 400


def test_acceptance_signature_mismatch_rejected():
    mgr, sess = _new_session()
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, o1)

    acceptance = _make_acceptance(sess, o1)
    acceptance["acceptance_signature"] = sign_jws(
        hash_object({
            "session_id": acceptance["session_id"],
            "round_number": acceptance["round_number"],
            "sequence_number": acceptance["sequence_number"],
            "accepted_offer_id": acceptance["accepted_offer_id"],
            "accepted_protocol_act_hash": acceptance["accepted_protocol_act_hash"],
        }),
        INITIATOR_PRIVATE_KEY,
        kid=f"{INITIATOR_DID}#key-1",
    )
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, acceptance)
    assert exc_info.value.code == "INVALID_SIGNATURE"
    assert exc_info.value.http_status == 400


def test_offer_at_max_commitment_value_accepted():
    mgr, sess = _new_session()
    sess.initiator_mandate = {
        "mandate_type": "declared",
        "principal_did": INITIATOR_DID,
        "max_commitment_value": 9_500_000,
        "max_commitment_currency": "USD",
    }

    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    result = mgr.process_message(sess, offer)

    assert result["state"] == SessionState.NEGOTIATING
    assert sess.latest_offer_hash == offer["protocol_act_hash"]


def test_offer_over_max_commitment_value_rejected():
    mgr, sess = _new_session()
    sess.initiator_mandate = {
        "mandate_type": "declared",
        "principal_did": INITIATOR_DID,
        "max_commitment_value": 9_499_999,
        "max_commitment_currency": "USD",
    }

    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, offer)

    assert exc_info.value.code == "MANDATE_INVALID"
    assert exc_info.value.http_status == 403
    assert sess.sequence_number == 0
    assert sess.state == SessionState.ACTIVE


def test_offer_currency_mismatch_rejected():
    mgr, sess = _new_session()
    sess.initiator_mandate = {
        "mandate_type": "declared",
        "principal_did": INITIATOR_DID,
        "max_commitment_value": 20_000_000,
        "max_commitment_currency": "EUR",
    }

    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, offer)

    assert exc_info.value.code == "MANDATE_INVALID"
    assert exc_info.value.http_status == 403
    assert sess.sequence_number == 0


def test_acceptance_at_max_commitment_value_completes():
    mgr, sess = _new_session()
    sess.responder_mandate = {
        "mandate_type": "declared",
        "principal_did": RESPONDER_DID,
        "max_commitment_value": 9_500_000,
        "max_commitment_currency": "USD",
    }
    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, offer)

    acceptance = _make_acceptance(sess, offer)
    mgr.process_message(sess, acceptance)

    assert sess.state == SessionState.COMPLETED


def test_acceptance_over_max_commitment_value_rejected():
    mgr, sess = _new_session()
    sess.responder_mandate = {
        "mandate_type": "declared",
        "principal_did": RESPONDER_DID,
        "max_commitment_value": 9_499_999,
        "max_commitment_currency": "USD",
    }
    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, offer)

    acceptance = _make_acceptance(sess, offer)
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, acceptance)

    assert exc_info.value.code == "MANDATE_INVALID"
    assert exc_info.value.http_status == 403
    assert sess.state == SessionState.NEGOTIATING
    assert sess.sequence_number == 1
    assert sess._final_acceptance is None


def test_acceptance_currency_mismatch_rejected():
    mgr, sess = _new_session()
    sess.responder_mandate = {
        "mandate_type": "declared",
        "principal_did": RESPONDER_DID,
        "max_commitment_value": 20_000_000,
        "max_commitment_currency": "EUR",
    }
    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, offer)

    acceptance = _make_acceptance(sess, offer)
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, acceptance)

    assert exc_info.value.code == "MANDATE_INVALID"
    assert exc_info.value.http_status == 403
    assert sess.state == SessionState.NEGOTIATING


def test_acceptance_in_active_state_raises():
    """Finding 2.8: acceptance in ACTIVE state (before any offer) raises SESSION_WRONG_STATE."""
    mgr, sess = _new_session()
    assert sess.state == SessionState.ACTIVE
    acceptance = {
        "message_type": "acceptance",
        "message_id": str(uuid.uuid4()),
        "session_id": sess.session_id,
        "round_number": 1,
        "sequence_number": 1,
        "accepted_offer_id": "offer-x",
        "accepted_protocol_act_hash": "some-hash",
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "acme-agent",
        "sender_verification_method": f"{RESPONDER_DID}#key-2026-01",
        "timestamp": "2026-03-24T10:05:00Z",
        "acceptance_signature": "eyJ...",
    }
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, acceptance)
    assert exc_info.value.code == "SESSION_WRONG_STATE"


def test_offer_expiry_check():
    """Finding 4.2: accepting an expired offer raises OFFER_EXPIRED."""
    mgr, sess = _new_session()
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    # Backdate expiry to force expiration
    o1["expires_at"] = "2020-01-01T00:00:00Z"
    # Recompute hash/signature with the new expires_at (otherwise signature mismatch fires first)
    _resign_offer(o1)
    mgr.process_message(sess, o1)

    # Update session hash tracker
    sess.latest_offer_hash = o1["protocol_act_hash"]

    acceptance = _make_acceptance(sess, o1, msg_id=str(uuid.uuid4()))
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, acceptance)
    assert exc_info.value.code == "OFFER_EXPIRED"
    assert exc_info.value.http_status == 422


def test_session_timeout_check():
    """Finding 2.9: messages on a timed-out session raise SESSION_WRONG_STATE."""
    mgr, sess = _new_session()
    # Set session_created_at to well in the past and a short timeout
    sess.session_created_at = "2020-01-01T00:00:00Z"
    sess.session_timeout_seconds = 1

    o = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, o)
    assert exc_info.value.code == "SESSION_WRONG_STATE"
    assert sess.state == SessionState.TIMED_OUT


def test_process_message_returns_state_dict():
    """Finding 5.2: process_message returns session.to_state_dict()."""
    mgr, sess = _new_session()
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    result = mgr.process_message(sess, o1)
    assert "session_id" in result
    assert "state" in result
    assert result["state"] == SessionState.NEGOTIATING
    assert result["round_number"] == 1


# ---------------------------------------------------------------------------
# Human approval pause
# ---------------------------------------------------------------------------


# ApprovalReceipts are signed by an operator-side approver, not by the agent under
# oversight (Section 14.1). The approver has its own key, and the mandate that
# sets the threshold names it in approval_operator_dids.
APPROVER_DID = "did:web:approver.example"
APPROVER_PRIVATE_KEY, APPROVER_PUBLIC_KEY = generate_ed25519_keypair()
ES256_APPROVER_DID = "did:web:es256-approver.example"
ES256_APPROVER_PRIVATE_KEY, ES256_APPROVER_PUBLIC_KEY = generate_keypair()
OTHER_DID = "did:web:other.example"
OTHER_PRIVATE_KEY, OTHER_PUBLIC_KEY = generate_ed25519_keypair()


def _approval_mandate(principal_did=INITIATOR_DID, approvers=(APPROVER_DID, ES256_APPROVER_DID), **extra):
    return {
        "mandate_type": "declared",
        "principal_did": principal_did,
        "requires_human_approval_above": 9_000_000,
        "approval_operator_dids": list(approvers),
        **extra,
    }


def _register_approvers(mgr: SessionManager) -> None:
    mgr.register_did_document(
        APPROVER_DID, make_did_document(APPROVER_DID, "key-1", public_key_to_jwk(APPROVER_PUBLIC_KEY))
    )
    mgr.register_did_document(
        ES256_APPROVER_DID,
        make_did_document(ES256_APPROVER_DID, "key-1", public_key_to_jwk(ES256_APPROVER_PUBLIC_KEY)),
    )
    mgr.register_did_document(
        OTHER_DID, make_did_document(OTHER_DID, "key-1", public_key_to_jwk(OTHER_PUBLIC_KEY))
    )


def _paused_session(**mandate_extra) -> tuple[SessionManager, Session]:
    """A session whose initiator offer is paused for human approval."""
    mgr, sess = _new_session()
    _register_approvers(mgr)
    sess.initiator_mandate = _approval_mandate(**mandate_extra)
    mgr.process_message(sess, _make_offer(sess.session_id, 1, 1, INITIATOR_DID))
    assert sess.state == SessionState.AWAITING_HUMAN_APPROVAL
    return mgr, sess


def _approval_receipt(sess: Session, *, offer_hash=None, approver_did=APPROVER_DID,
                      expires_at="2030-01-01T00:00:00Z", sign_with=APPROVER_PRIVATE_KEY,
                      mandate_ref="hash", receipt_id="urn:concordia:receipt:test",
                      paused_party="auto"):
    receipt = {
        "artifact_type": "ApprovalReceipt",
        "id": receipt_id,
        "scope": {
            "decision": "approve",
            "offer_hash": offer_hash or sess.approval_pending_offer_hash,
            "amount": "95000.00 USD",
            "threshold_crossed": "90000.00 USD",
        },
        "references": [
            {
                "type": "negotiation_session",
                "id": f"a2cn:session:{sess.session_id}",
                "relationship": "approves",
            }
        ],
        "approver_did": approver_did,
    }
    if mandate_ref == "hash":
        receipt["references"].append({
            "type": "mandate",
            "id": hash_object(sess.approval_pending_mandate),
            "relationship": "fulfills",
        })
    elif mandate_ref is not None:
        receipt["references"].append({"type": "mandate", "id": mandate_ref, "relationship": "fulfills"})
    if paused_party == "auto":
        info = {"initiator": sess.initiator_info, "responder": sess.responder_info}.get(
            sess.approval_pending_sender_role or ""
        )
        paused_party = info.get("did") if info else None
    if paused_party is not None:
        receipt["references"].append({"type": "paused_party", "id": paused_party, "relationship": "approves"})
    if expires_at is not None:
        receipt["expires_at"] = expires_at
    if sign_with is not None:
        receipt["signature"] = sign_approval_receipt(receipt, sign_with)
    return receipt


def _refused(mgr: SessionManager, sess: Session, receipt: dict) -> str:
    """Apply a receipt that must be refused; the pause must survive it."""
    with pytest.raises(A2CNError) as exc_info:
        mgr.apply_approval_receipt(sess, receipt)
    assert sess.state == SessionState.AWAITING_HUMAN_APPROVAL
    assert sess.approval_receipts == []
    return exc_info.value.code


def test_threshold_crossing_offer_enters_awaiting_human_approval():
    mgr, sess = _new_session()
    sess.initiator_mandate = _approval_mandate()

    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    result = mgr.process_message(sess, offer)

    assert result["state"] == SessionState.AWAITING_HUMAN_APPROVAL
    assert sess.current_turn == "initiator"
    assert sess.approval_pending_offer_id == offer["message_id"]
    assert sess.approval_pending_offer_hash == offer["protocol_act_hash"]


def test_approval_receipt_releases_pause_and_restores_counterparty_turn():
    mgr, sess = _paused_session()

    result = mgr.apply_approval_receipt(sess, _approval_receipt(sess))

    assert result["state"] == SessionState.NEGOTIATING
    assert result["current_turn"] == "responder"
    assert result["approval_receipt_id"] == "urn:concordia:receipt:test"
    assert result["approval_pending_offer_hash"] is None
    assert sess.approval_receipts[-1]["id"] == "urn:concordia:receipt:test"


def test_es256_signed_approval_receipt_releases_pause():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, approver_did=ES256_APPROVER_DID, sign_with=ES256_APPROVER_PRIVATE_KEY)
    assert receipt["signature"]["alg"] == "ES256"

    assert mgr.apply_approval_receipt(sess, receipt)["state"] == SessionState.NEGOTIATING


def test_approval_receipt_naming_the_approver_by_did_url_releases_pause():
    mgr, sess = _paused_session(approvers=(f"{APPROVER_DID}#key-1",))
    receipt = _approval_receipt(sess, approver_did=f"{APPROVER_DID}#key-1")

    assert mgr.apply_approval_receipt(sess, receipt)["state"] == SessionState.NEGOTIATING


def test_approval_receipt_may_reference_the_mandate_hash_with_the_a2cn_prefix():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, mandate_ref=f"a2cn:mandate:{hash_object(sess.approval_pending_mandate)}")
    assert mgr.apply_approval_receipt(sess, receipt)["state"] == SessionState.NEGOTIATING


def test_approval_receipt_may_reference_the_mandate_by_its_id():
    mgr, sess = _paused_session(mandate_id="m-2026-04-19-0007")

    receipt = _approval_receipt(sess, mandate_ref="a2cn:mandate:m-2026-04-19-0007")

    assert mgr.apply_approval_receipt(sess, receipt)["state"] == SessionState.NEGOTIATING


def test_audit_metadata_defaults_to_autonomous_without_approval_receipts():
    mgr, sess = _new_session()
    withdrawal = {
        "message_type": "withdrawal",
        "message_id": "withdrawal-autonomous",
        "session_id": sess.session_id,
        "round_number": 1,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "tc-agent",
        "timestamp": "2026-03-24T10:02:00Z",
        "reason_code": "STRATEGY_DECISION",
    }
    withdrawal = sign_decline(withdrawal, INITIATOR_PRIVATE_KEY, f"{INITIATOR_DID}#key-1")
    mgr.process_message(sess, withdrawal)

    metadata = generate_audit_log(sess)["audit_metadata"]

    assert metadata["ai_system_involved"] is True
    assert metadata["human_oversight_present"] is False
    assert metadata["autonomous_decision"] is True


def test_audit_metadata_reflects_human_approval_receipt():
    mgr, sess = _paused_session()
    mgr.apply_approval_receipt(sess, _approval_receipt(sess))

    metadata = generate_audit_log(sess)["audit_metadata"]

    assert metadata["ai_system_involved"] is True
    assert metadata["human_oversight_present"] is True
    assert metadata["autonomous_decision"] is False


# --- Refusals. Each leaves the session paused with no receipt recorded. ---

def test_unsigned_approval_receipt_is_refused():
    mgr, sess = _paused_session()
    assert _refused(mgr, sess, _approval_receipt(sess, sign_with=None)) == "APPROVAL_RECEIPT_UNSIGNED"


def test_approval_receipt_with_malformed_signature_member_is_refused():
    mgr, sess = _paused_session()
    for bad in ("not-an-object", {"alg": "Ed25519"}, {"alg": "Ed25519", "value": ""}, {"value": "abc"}):
        receipt = _approval_receipt(sess)
        receipt["signature"] = bad
        assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_UNSIGNED"


def test_approval_receipt_with_corrupted_signature_is_refused():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess)
    value = receipt["signature"]["value"]
    receipt["signature"]["value"] = ("A" if value[0] != "A" else "B") + value[1:]
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNATURE_INVALID"


def test_approval_receipt_altered_after_signing_is_refused():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess)
    receipt["scope"]["amount"] = "1.00 USD"
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNATURE_INVALID"


def test_approval_receipt_signed_by_a_key_outside_the_approver_did_document_is_refused():
    mgr, sess = _paused_session()
    stray_private_key, _ = generate_ed25519_keypair()
    receipt = _approval_receipt(sess, sign_with=stray_private_key)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNATURE_INVALID"


def test_approval_receipt_signed_by_another_did_is_refused():
    # Signed with a key another DID controls, naming an authorised approver.
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=OTHER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNATURE_INVALID"


def test_approval_receipt_key_listed_by_the_approver_but_controlled_by_another_did_is_refused():
    # The approver's document lists another DID's method; that key does not count.
    mgr, sess = _paused_session()
    foreign = make_did_document(OTHER_DID, "key-1", public_key_to_jwk(OTHER_PUBLIC_KEY))
    approver_doc = make_did_document(APPROVER_DID, "unused", public_key_to_jwk(APPROVER_PUBLIC_KEY))
    approver_doc["verificationMethod"] = foreign["verificationMethod"]
    approver_doc["assertionMethod"] = [f"{OTHER_DID}#key-1"]
    approver_doc["authentication"] = [f"{OTHER_DID}#key-1"]
    mgr.register_did_document(APPROVER_DID, approver_doc)
    receipt = _approval_receipt(sess, sign_with=OTHER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNER_MISMATCH"


def test_approval_receipt_whose_method_names_another_controller_is_refused():
    mgr, sess = _paused_session()
    approver_doc = make_did_document(APPROVER_DID, "key-1", public_key_to_jwk(OTHER_PUBLIC_KEY))
    approver_doc["verificationMethod"][0]["controller"] = OTHER_DID
    mgr.register_did_document(APPROVER_DID, approver_doc)
    receipt = _approval_receipt(sess, sign_with=OTHER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNER_MISMATCH"


def test_approval_receipt_from_an_approver_with_no_resolvable_did_document_is_refused():
    mgr, sess = _paused_session(approvers=("did:example:unregistered",))
    receipt = _approval_receipt(sess, approver_did="did:example:unregistered")
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_KEY_UNRESOLVED"


def test_approval_receipt_whose_declared_algorithm_does_not_match_the_key_is_refused():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess)
    receipt["signature"]["alg"] = "ES256"
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNATURE_INVALID"


def test_validly_signed_approval_receipt_from_an_unauthorised_approver_is_refused():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, approver_did=OTHER_DID, sign_with=OTHER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "UNAUTHORIZED_APPROVER"


def test_approver_list_given_as_a_string_authorises_no_one():
    # Membership in a string would be a substring test: "did:web:approver.example"
    # is inside "did:web:approver.example.attacker". Only a list counts.
    mgr, sess = _paused_session(approvers=())
    sess.approval_pending_mandate["approval_operator_dids"] = f"{APPROVER_DID}.attacker"
    receipt = _approval_receipt(sess)
    assert _refused(mgr, sess, receipt) == "UNAUTHORIZED_APPROVER"


def test_approval_receipt_naming_a_non_string_approver_is_refused():
    mgr, sess = _paused_session()
    sess.approval_pending_mandate["approval_operator_dids"].append(["did:web:listed.example"])
    receipt = _approval_receipt(sess, approver_did=["did:web:listed.example"])
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_INVALID"


@pytest.mark.parametrize("label, mutate", [
    ("scope is a list", lambda r: r.__setitem__("scope", ["x"])),
    ("scope is null", lambda r: r.__setitem__("scope", None)),
    ("session reference id is a list", lambda r: r["references"][0].__setitem__("id", ["a"])),
    ("mandate reference id is an object", lambda r: r["references"][1].__setitem__("id", {"a": 1})),
    ("decision only at the top level", lambda r: (r["scope"].__setitem__("decision", None), r.__setitem__("decision", "approve"))),
    ("offer hash only at the top level", lambda r: (r["scope"].pop("offer_hash"), r.__setitem__("offer_hash", "x"))),
])
def test_malformed_signed_receipt_is_refused_cleanly(label, mutate):
    # Validly signed by the approver, but malformed: a clean refusal, never a crash.
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None)
    mutate(receipt)
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) in ("APPROVAL_RECEIPT_INVALID", "OFFER_HASH_MISMATCH")


@pytest.mark.parametrize("label, edit_document, code", [
    ("document is not an object", lambda d: ["not", "an", "object"], "APPROVAL_RECEIPT_KEY_UNRESOLVED"),
    ("relationship lists are not lists", lambda d: {**d, "assertionMethod": 5, "authentication": 5}, "APPROVAL_RECEIPT_KEY_UNRESOLVED"),
    ("method controller is null", lambda d: {**d, "verificationMethod": [{**d["verificationMethod"][0], "controller": None}]}, "APPROVAL_RECEIPT_SIGNER_MISMATCH"),
])
def test_malformed_approver_did_document_is_refused_cleanly(label, edit_document, code):
    mgr, sess = _paused_session()
    document = make_did_document(APPROVER_DID, "key-1", public_key_to_jwk(APPROVER_PUBLIC_KEY))
    mgr.register_did_document(APPROVER_DID, edit_document(document))
    assert _refused(mgr, sess, _approval_receipt(sess)) == code


# --- An approver is never the paused party; separation is by DID, not by key. ---

def test_paused_agent_cannot_approve_its_own_act_even_with_a_valid_signature():
    mgr, sess = _paused_session(approvers=(INITIATOR_DID,))
    receipt = _approval_receipt(sess, approver_did=INITIATOR_DID, sign_with=INITIATOR_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SELF_APPROVAL"


def test_paused_agent_named_by_did_url_cannot_approve_its_own_act():
    mgr, sess = _paused_session(approvers=(f"{INITIATOR_DID}#key-1",))
    receipt = _approval_receipt(sess, approver_did=f"{INITIATOR_DID}#key-1", sign_with=INITIATOR_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SELF_APPROVAL"


def test_principal_that_is_the_agent_itself_cannot_release_the_pause():
    # principal_did is the agent's own DID and the only authorised approver: the
    # pause cannot be released, by the agent or by anyone else.
    mgr, sess = _paused_session(approvers=())
    assert sess.approval_pending_mandate["principal_did"] == INITIATOR_DID
    by_agent = _approval_receipt(sess, approver_did=INITIATOR_DID, sign_with=INITIATOR_PRIVATE_KEY)
    assert _refused(mgr, sess, by_agent) == "APPROVAL_RECEIPT_SELF_APPROVAL"
    by_operator = _approval_receipt(sess)
    assert _refused(mgr, sess, by_operator) == "UNAUTHORIZED_APPROVER"


def test_principal_with_its_own_did_releases_the_pause():
    mgr, sess = _paused_session(approvers=())
    sess.approval_pending_mandate["principal_did"] = APPROVER_DID
    receipt = _approval_receipt(sess)
    assert mgr.apply_approval_receipt(sess, receipt)["state"] == SessionState.NEGOTIATING


def test_accepting_party_cannot_approve_its_own_paused_acceptance():
    mgr, sess, _offer, _acceptance = _paused_acceptance()
    sess.approval_pending_mandate["approval_operator_dids"].append(RESPONDER_DID)
    receipt = _approval_receipt(sess, approver_did=RESPONDER_DID, sign_with=RESPONDER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SELF_APPROVAL"
    assert sess._final_acceptance is None


def test_pause_stays_when_the_paused_party_cannot_be_determined():
    mgr, sess = _paused_session()
    sess.approval_pending_sender_role = None
    assert _refused(mgr, sess, _approval_receipt(sess)) == "APPROVAL_RECEIPT_SELF_APPROVAL"


def test_approval_receipt_without_a_mandate_reference_is_refused():
    mgr, sess = _paused_session()
    assert _refused(mgr, sess, _approval_receipt(sess, mandate_ref=None)) == "APPROVAL_RECEIPT_INVALID"


def test_approval_receipt_naming_a_different_mandate_is_refused():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, mandate_ref="a2cn:mandate:some-other-mandate")
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_INVALID"


def test_expired_approval_receipt_rejected():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, expires_at="2020-01-01T00:00:00Z")
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_EXPIRED"


def test_approval_receipt_without_expiry_is_refused():
    mgr, sess = _paused_session()
    assert _refused(mgr, sess, _approval_receipt(sess, expires_at=None)) == "APPROVAL_RECEIPT_INVALID"


def test_approval_receipt_with_an_expiry_lacking_a_timezone_is_refused():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, expires_at="2030-01-01T00:00:00")
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_INVALID"


def test_approval_receipt_wrong_offer_hash_rejected():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, offer_hash="sha256:wrong")
    assert _refused(mgr, sess, receipt) == "OFFER_HASH_MISMATCH"


def test_approval_receipt_wrong_session_reference_rejected():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None)
    receipt["references"][0]["id"] = "a2cn:session:different-session"
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_INVALID"


def test_approval_receipt_requires_approval_state():
    mgr, sess = _new_session()
    _register_approvers(mgr)
    sess.approval_pending_mandate = _approval_mandate()

    with pytest.raises(A2CNError) as exc_info:
        mgr.apply_approval_receipt(sess, _approval_receipt(sess))

    assert exc_info.value.code == "NOT_IN_AWAITING_HUMAN_APPROVAL"


def _paused_acceptance() -> tuple[SessionManager, Session, dict, dict]:
    mgr, sess = _new_session()
    _register_approvers(mgr)
    sess.responder_mandate = _approval_mandate(principal_did=RESPONDER_DID)
    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, offer)
    acceptance = _make_acceptance(sess, offer, msg_id="acc-requires-approval")
    result = mgr.process_message(sess, acceptance)
    assert result["state"] == SessionState.AWAITING_HUMAN_APPROVAL
    return mgr, sess, offer, acceptance


def test_threshold_crossing_acceptance_enters_awaiting_human_approval_then_completes():
    mgr, sess, offer, acceptance = _paused_acceptance()
    assert sess.current_turn == "responder"
    assert sess.approval_pending_offer_id == offer["message_id"]
    assert sess.approval_pending_offer_hash == offer["protocol_act_hash"]
    assert sess._final_acceptance is None

    approved = mgr.apply_approval_receipt(sess, _approval_receipt(sess))

    assert approved["state"] == SessionState.COMPLETED
    assert approved["current_turn"] == "none"
    assert approved["approval_receipt_id"] == "urn:concordia:receipt:test"
    assert sess._final_acceptance == acceptance


def test_unsigned_approval_receipt_does_not_complete_a_paused_acceptance():
    mgr, sess, _offer, _acceptance = _paused_acceptance()

    assert _refused(mgr, sess, _approval_receipt(sess, sign_with=None)) == "APPROVAL_RECEIPT_UNSIGNED"
    assert sess._final_acceptance is None
    assert sess.state != SessionState.COMPLETED


# --- A receipt releases at most one pause in a session. ---

def _paused_offer_then_acceptance_sharing_a_mandate_reference():
    """Both parties' mandates are referenced as "group-default" and authorise one approver."""
    mgr, sess = _new_session()
    _register_approvers(mgr)
    sess.initiator_mandate = _approval_mandate(mandate_id="group-default")
    sess.responder_mandate = _approval_mandate(principal_did=RESPONDER_DID, mandate_id="group-default")
    offer = _make_offer(sess.session_id, 1, 1, INITIATOR_DID)
    mgr.process_message(sess, offer)
    return mgr, sess, offer


def test_a_receipt_cannot_release_a_second_pause_in_the_session():
    mgr, sess, offer = _paused_offer_then_acceptance_sharing_a_mandate_reference()
    first = _approval_receipt(sess, mandate_ref="a2cn:mandate:group-default")
    assert mgr.apply_approval_receipt(sess, first)["state"] == SessionState.NEGOTIATING

    acceptance = _make_acceptance(sess, offer, msg_id="acc-requires-approval")
    assert mgr.process_message(sess, acceptance)["state"] == SessionState.AWAITING_HUMAN_APPROVAL
    assert _refused_after_use(mgr, sess, first) == "APPROVAL_RECEIPT_REPLAYED"
    assert sess._final_acceptance is None


def test_a_receipt_with_a_reused_id_is_refused_even_with_new_content():
    mgr, sess, offer = _paused_offer_then_acceptance_sharing_a_mandate_reference()
    mgr.apply_approval_receipt(sess, _approval_receipt(sess, mandate_ref="a2cn:mandate:group-default"))
    mgr.process_message(sess, _make_acceptance(sess, offer, msg_id="acc-requires-approval"))
    same_id = _approval_receipt(sess, mandate_ref="a2cn:mandate:group-default", expires_at="2031-01-01T00:00:00Z")
    assert _refused_after_use(mgr, sess, same_id) == "APPROVAL_RECEIPT_REPLAYED"


def test_a_fresh_receipt_releases_the_second_pause():
    mgr, sess, offer = _paused_offer_then_acceptance_sharing_a_mandate_reference()
    mgr.apply_approval_receipt(sess, _approval_receipt(sess, mandate_ref="a2cn:mandate:group-default"))
    mgr.process_message(sess, _make_acceptance(sess, offer, msg_id="acc-requires-approval"))
    fresh = _approval_receipt(sess, mandate_ref="a2cn:mandate:group-default", receipt_id="urn:concordia:receipt:second")
    assert mgr.apply_approval_receipt(sess, fresh)["state"] == SessionState.COMPLETED


def _refused_after_use(mgr: SessionManager, sess: Session, receipt: dict) -> str:
    """Like _refused, for a session that already holds one released receipt."""
    held = list(sess.approval_receipts)
    with pytest.raises(A2CNError) as exc_info:
        mgr.apply_approval_receipt(sess, receipt)
    assert sess.state == SessionState.AWAITING_HUMAN_APPROVAL
    assert sess.approval_receipts == held
    return exc_info.value.code


# --- expires_at: the one Section 14.1 form, identical in both implementations. ---

@pytest.mark.parametrize("expires_at", [
    "2030-01-01t00:00:00Z",          # lowercase t
    "2030-01-01T00:00:00z",          # lowercase z
    "2030-01-01T24:00:00Z",          # hour 24
    "2030-01-01T00:00:60Z",          # leap second
    "2030-04-31T00:00:00Z",          # no April 31
    "2030-02-30T00:00:00Z",          # no February 30
    "2031-02-29T00:00:00Z",          # 2031 is not a leap year
    "2030-01-01T00:00:00+01:60",     # offset minute 60
    "0000-01-01T00:00:00Z",          # year 0
    "2030-01-01T00:00:00.1234567Z",  # seven fractional digits
])
def test_expiry_outside_the_section_14_1_form_is_refused(expires_at):
    mgr, sess = _paused_session()
    assert _refused(mgr, sess, _approval_receipt(sess, expires_at=expires_at)) == "APPROVAL_RECEIPT_INVALID"


@pytest.mark.parametrize("expires_at", [
    "2032-02-29T00:00:00Z",           # leap day
    "2030-01-01T00:00:00.123456-05:30",
    "2099-12-31T23:59:59+14:00",
])
def test_expiry_in_the_section_14_1_form_is_accepted(expires_at):
    mgr, sess = _paused_session()
    assert mgr.apply_approval_receipt(sess, _approval_receipt(sess, expires_at=expires_at))["state"] == (
        SessionState.NEGOTIATING
    )


@pytest.mark.parametrize("receipt_hash", ["absent", None])
def test_a_pause_with_no_recorded_offer_hash_cannot_be_released(receipt_hash):
    mgr, sess = _paused_session()
    sess.approval_pending_offer_hash = None
    receipt = _approval_receipt(sess, sign_with=None)
    if receipt_hash == "absent":
        receipt["scope"].pop("offer_hash")
    else:
        receipt["scope"]["offer_hash"] = receipt_hash
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "OFFER_HASH_MISMATCH"


# --- Which approver a receipt names, and which list authorises it. ---

@pytest.mark.parametrize("present", ["", None, 0, False, [], {}])
def test_a_present_but_invalid_approver_did_does_not_fall_back(present):
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None)
    receipt["approver_did"] = present
    receipt["operator_did"] = APPROVER_DID
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_INVALID"


def test_operator_did_names_the_approver_when_approver_did_is_absent():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None)
    del receipt["approver_did"]
    receipt["operator_did"] = APPROVER_DID
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert mgr.apply_approval_receipt(sess, receipt)["state"] == SessionState.NEGOTIATING


def test_an_empty_operator_list_falls_through_to_the_trusted_list():
    mgr, sess = _paused_session(approvers=())
    sess.approval_pending_mandate["trusted_approver_dids"] = [APPROVER_DID]
    assert mgr.apply_approval_receipt(sess, _approval_receipt(sess))["state"] == SessionState.NEGOTIATING


# --- Key resolution within the approver's DID document. ---

def _approver_document(*methods, assertion=None, authentication=None):
    """A DID document for APPROVER_DID with the given (fragment, public key) methods."""
    vms = [
        {"id": f"{APPROVER_DID}#{frag}", "type": "JsonWebKey2020", "controller": APPROVER_DID,
         "publicKeyJwk": public_key_to_jwk(key)}
        for frag, key in methods
    ]
    ids = [vm["id"] for vm in vms]
    return {
        "id": APPROVER_DID,
        "verificationMethod": vms,
        "assertionMethod": ids if assertion is None else assertion,
        "authentication": ids if authentication is None else authentication,
    }


def test_a_did_url_approver_must_sign_with_the_method_it_names():
    mgr, sess = _paused_session(approvers=(f"{APPROVER_DID}#key-1",))
    _, sibling_public = generate_ed25519_keypair()
    mgr.register_did_document(APPROVER_DID, _approver_document(("key-1", sibling_public), ("key-2", APPROVER_PUBLIC_KEY)))
    receipt = _approval_receipt(sess, approver_did=f"{APPROVER_DID}#key-1")
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNATURE_INVALID"


def test_an_embedded_method_under_another_did_does_not_count_even_without_a_controller():
    mgr, sess = _paused_session()
    foreign = {"id": f"{OTHER_DID}#key-1", "type": "JsonWebKey2020", "publicKeyJwk": public_key_to_jwk(OTHER_PUBLIC_KEY)}
    mgr.register_did_document(APPROVER_DID, {"id": APPROVER_DID, "verificationMethod": [], "assertionMethod": [foreign], "authentication": []})
    receipt = _approval_receipt(sess, sign_with=OTHER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNER_MISMATCH"


def test_a_key_listed_only_under_authentication_can_sign():
    mgr, sess = _paused_session()
    mgr.register_did_document(APPROVER_DID, _approver_document(("key-1", APPROVER_PUBLIC_KEY), assertion=[]))
    assert mgr.apply_approval_receipt(sess, _approval_receipt(sess))["state"] == SessionState.NEGOTIATING


def test_any_controlled_key_in_a_multi_key_document_can_sign():
    mgr, sess = _paused_session()
    _, unrelated_public = generate_ed25519_keypair()
    mgr.register_did_document(APPROVER_DID, _approver_document(("key-1", unrelated_public), ("key-2", APPROVER_PUBLIC_KEY)))
    assert mgr.apply_approval_receipt(sess, _approval_receipt(sess))["state"] == SessionState.NEGOTIATING


def test_a_paused_party_with_an_empty_did_cannot_be_released():
    mgr, sess = _paused_session()
    sess.initiator_info = {**sess.initiator_info, "did": ""}  # a copy: the dict is shared
    assert _refused(mgr, sess, _approval_receipt(sess)) == "APPROVAL_RECEIPT_SELF_APPROVAL"


def test_an_es256_signature_labelled_ed25519_is_refused():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, approver_did=ES256_APPROVER_DID, sign_with=ES256_APPROVER_PRIVATE_KEY)
    receipt["signature"]["alg"] = "Ed25519"
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_SIGNATURE_INVALID"


def test_es256_receipt_signatures_always_have_a_low_s():
    import base64
    from cryptography.hazmat.primitives.asymmetric import utils as ec_utils
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    for i in range(64):
        value = sign_approval_receipt({"id": f"receipt-{i}"}, ES256_APPROVER_PRIVATE_KEY)["value"]
        _, s = ec_utils.decode_dss_signature(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
        assert s <= order // 2


def test_a_receipt_with_an_unpaired_surrogate_cannot_be_signed_or_verified():
    receipt = {"id": "x", "note": "\ud800"}
    with pytest.raises(Exception):
        sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    receipt["signature"] = {"alg": "Ed25519", "value": "A" * 86}
    from a2cn.crypto import verify_approval_receipt_signature
    assert verify_approval_receipt_signature(receipt, APPROVER_PUBLIC_KEY) is False


# --- A receipt names the party whose act it approves: one party's act, once. ---

def test_a_fresh_receipt_for_the_initiators_offer_does_not_release_the_responders_acceptance():
    # Shared approver, identically referenced mandates: the two pauses carry the
    # same offer hash, and only the named paused party tells them apart.
    mgr, sess, offer = _paused_offer_then_acceptance_sharing_a_mandate_reference()
    mgr.apply_approval_receipt(sess, _approval_receipt(sess, mandate_ref="a2cn:mandate:group-default"))
    mgr.process_message(sess, _make_acceptance(sess, offer, msg_id="acc-requires-approval"))
    for_the_offer = _approval_receipt(
        sess, mandate_ref="a2cn:mandate:group-default", receipt_id="urn:concordia:receipt:retry",
        paused_party=INITIATOR_DID,
    )
    assert _refused_after_use(mgr, sess, for_the_offer) == "APPROVAL_RECEIPT_INVALID"
    assert sess._final_acceptance is None


def test_a_receipt_that_names_no_paused_party_is_refused():
    mgr, sess = _paused_session()
    assert _refused(mgr, sess, _approval_receipt(sess, paused_party=None)) == "APPROVAL_RECEIPT_INVALID"


def test_a_receipt_that_names_another_party_as_paused_is_refused():
    mgr, sess = _paused_session()
    assert _refused(mgr, sess, _approval_receipt(sess, paused_party=RESPONDER_DID)) == "APPROVAL_RECEIPT_INVALID"


def test_a_receipt_that_also_names_another_party_as_paused_is_refused():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None)
    receipt["references"].append({"type": "paused_party", "id": RESPONDER_DID, "relationship": "approves"})
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_INVALID"


# --- Single use, by id or by signed content. ---

def _pause_again(sess: Session, pause: dict) -> None:
    """Re-enter the same pause, as Section 14.2 allows when a receipt expires before release."""
    sess.state = SessionState.AWAITING_HUMAN_APPROVAL
    sess.approval_pending_offer_hash = pause["hash"]
    sess.approval_pending_mandate = pause["mandate"]
    sess.approval_pending_sender_role = pause["role"]


def _pause_of(sess: Session) -> dict:
    return {
        "hash": sess.approval_pending_offer_hash,
        "mandate": sess.approval_pending_mandate,
        "role": sess.approval_pending_sender_role,
    }


def _reuse_after_release(build):
    """Release a pause with a receipt that has no id, pause again, and try `build(receipt)`."""
    mgr, sess = _paused_session()
    pause = _pause_of(sess)
    first = _approval_receipt(sess, sign_with=None)
    first.pop("id")
    first["signature"] = sign_approval_receipt(first, APPROVER_PRIVATE_KEY)
    mgr.apply_approval_receipt(sess, first)
    _pause_again(sess, pause)
    return mgr, sess, build(first)


def test_a_receipt_without_an_id_is_still_single_use():
    import copy
    mgr, sess, again = _reuse_after_release(copy.deepcopy)
    assert _refused_after_use(mgr, sess, again) == "APPROVAL_RECEIPT_REPLAYED"


def test_a_replayed_receipt_with_a_re_padded_signature_is_still_single_use():
    import copy
    def re_padded(receipt):
        again = copy.deepcopy(receipt)
        again["signature"]["value"] = again["signature"]["value"].rstrip("=")
        return again
    mgr, sess, again = _reuse_after_release(re_padded)
    assert _refused_after_use(mgr, sess, again) == "APPROVAL_RECEIPT_REPLAYED"


def test_a_receipt_reusing_an_id_through_approval_receipt_id_is_single_use():
    mgr, sess = _paused_session()
    pause = _pause_of(sess)
    first = _approval_receipt(sess, receipt_id="urn:concordia:receipt:shared")
    mgr.apply_approval_receipt(sess, first)
    _pause_again(sess, pause)
    again = _approval_receipt(sess, sign_with=None, expires_at="2031-01-01T00:00:00Z")
    again.pop("id")
    again["approval_receipt_id"] = "urn:concordia:receipt:shared"
    again["signature"] = sign_approval_receipt(again, APPROVER_PRIVATE_KEY)
    assert _refused_after_use(mgr, sess, again) == "APPROVAL_RECEIPT_REPLAYED"



def test_a_pause_with_an_empty_recorded_offer_hash_cannot_be_released():
    mgr, sess = _paused_session()
    sess.approval_pending_offer_hash = ""
    receipt = _approval_receipt(sess, sign_with=None)
    receipt["scope"]["offer_hash"] = ""
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "OFFER_HASH_MISMATCH"


def test_a_non_object_receipt_is_refused_by_the_library():
    mgr, sess = _paused_session()
    for receipt in ([], "receipt", 5, None):
        with pytest.raises(A2CNError) as exc_info:
            mgr.check_approval_receipt(sess, receipt)
        assert exc_info.value.code == "APPROVAL_RECEIPT_INVALID"


# --- expires_at: calendar, offset arithmetic and fractions. ---

@pytest.mark.parametrize("expires_at", ["2100-02-29T00:00:00Z", "2030-01-01T00:00:00+24:00", "2030-01-01T00:00:00-99:00"])
def test_more_expiry_forms_outside_section_14_1_are_refused(expires_at):
    mgr, sess = _paused_session()
    assert _refused(mgr, sess, _approval_receipt(sess, expires_at=expires_at)) == "APPROVAL_RECEIPT_INVALID"


def _in_offset(moment, offset_minutes):
    from datetime import timedelta as _td, timezone as _tz
    return moment.astimezone(_tz(_td(minutes=offset_minutes))).isoformat(timespec="seconds")


@pytest.mark.parametrize("offset_minutes", [330, -540, 1439, -1439])
def test_expiry_offsets_are_applied_with_the_right_sign(offset_minutes):
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    now = _dt.now(_tz.utc)
    mgr, sess = _paused_session()
    ahead = _approval_receipt(sess, expires_at=_in_offset(now + _td(hours=2), offset_minutes))
    assert mgr.apply_approval_receipt(sess, ahead)["state"] == SessionState.NEGOTIATING
    mgr, sess = _paused_session()
    behind = _approval_receipt(sess, expires_at=_in_offset(now - _td(hours=2), offset_minutes))
    assert _refused(mgr, sess, behind) == "APPROVAL_RECEIPT_EXPIRED"


def _clock(monkeypatch, iso):
    import a2cn.session as session_module
    from datetime import datetime as _dt
    fixed = _dt.fromisoformat(iso)

    class FixedClock(_dt):
        @classmethod
        def now(cls, tz=None):
            return fixed

    monkeypatch.setattr(session_module, "datetime", FixedClock)


def test_a_fractional_expiry_is_compared_to_the_millisecond(monkeypatch):
    _clock(monkeypatch, "2030-01-01T00:00:00.400+00:00")
    mgr, sess = _paused_session()
    assert mgr.apply_approval_receipt(sess, _approval_receipt(sess, expires_at="2030-01-01T00:00:00.500Z"))["state"] == (
        SessionState.NEGOTIATING
    )
    _clock(monkeypatch, "2030-01-01T00:00:00.600+00:00")
    mgr, sess = _paused_session()
    assert _refused(mgr, sess, _approval_receipt(sess, expires_at="2030-01-01T00:00:00.500Z")) == "APPROVAL_RECEIPT_EXPIRED"


def test_expiry_within_the_same_millisecond_is_not_yet_expired(monkeypatch):
    # Both implementations compare whole milliseconds.
    _clock(monkeypatch, "2030-01-01T00:00:00.000700+00:00")
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, expires_at="2030-01-01T00:00:00.000400Z")
    assert mgr.apply_approval_receipt(sess, receipt)["state"] == SessionState.NEGOTIATING


# --- Nesting depth. ---

def _nested(depth):
    value = {}
    inner = value
    for _ in range(depth - 1):
        inner["n"] = {}
        inner = inner["n"]
    return value


def test_a_receipt_at_the_depth_limit_signs_and_one_deeper_does_not():
    from a2cn.crypto import verify_approval_receipt_signature
    at_limit = {"id": "deep", "payload": _nested(63)}   # the receipt object is level 1
    at_limit["signature"] = sign_approval_receipt(at_limit, APPROVER_PRIVATE_KEY)
    assert verify_approval_receipt_signature(at_limit, APPROVER_PUBLIC_KEY) is True
    too_deep = {"id": "deeper", "payload": _nested(64)}
    with pytest.raises(ValueError):
        sign_approval_receipt(too_deep, APPROVER_PRIVATE_KEY)
    too_deep["signature"] = at_limit["signature"]
    assert verify_approval_receipt_signature(too_deep, APPROVER_PUBLIC_KEY) is False


@pytest.mark.parametrize("odd_id", [5, {"a": 1}, ["x"], True])
def test_a_non_string_receipt_id_is_not_recorded(odd_id):
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None)
    receipt["id"] = odd_id
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert mgr.apply_approval_receipt(sess, receipt)["approval_receipt_id"] is None


# --- paused_party is matched exactly, as one string, on a typed entry with an id. ---

@pytest.mark.parametrize("named", [
    f"{INITIATOR_DID}#key-1",          # a DID URL of the paused party
    INITIATOR_DID.upper(),              # another case
    f" {INITIATOR_DID} ",               # surrounding whitespace
])
def test_paused_party_must_be_named_exactly(named):
    mgr, sess = _paused_session()
    assert _refused(mgr, sess, _approval_receipt(sess, paused_party=named)) == "APPROVAL_RECEIPT_INVALID"


@pytest.mark.parametrize("entry_type", ["xpaused_party", "paused_party_extra", "Paused_Party"])
def test_only_an_entry_of_type_paused_party_counts(entry_type):
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None, paused_party=None)
    receipt["references"].append({"type": entry_type, "id": INITIATOR_DID, "relationship": "approves"})
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_INVALID"


def test_a_paused_party_entry_without_an_id_is_refused_even_beside_a_correct_one():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None)
    receipt["references"].append({"type": "paused_party", "relationship": "approves"})
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert _refused(mgr, sess, receipt) == "APPROVAL_RECEIPT_INVALID"


# --- Depth counts arrays and the signature member; id selection order. ---

def _nested_arrays(depth):
    value = []
    inner = value
    for _ in range(depth - 1):
        inner.append([])
        inner = inner[0]
    return value


def test_depth_counts_arrays_too():
    from a2cn.crypto import verify_approval_receipt_signature
    at_limit = {"id": "arrays", "payload": _nested_arrays(63)}
    at_limit["signature"] = sign_approval_receipt(at_limit, APPROVER_PRIVATE_KEY)
    assert verify_approval_receipt_signature(at_limit, APPROVER_PUBLIC_KEY) is True
    with pytest.raises(ValueError):
        sign_approval_receipt({"id": "arrays", "payload": _nested_arrays(64)}, APPROVER_PRIVATE_KEY)


def test_depth_counts_the_signature_member():
    from a2cn.crypto import verify_approval_receipt_signature
    receipt = {"id": "deep-signature"}
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    receipt["signature"]["x"] = _nested(200)
    assert verify_approval_receipt_signature(receipt, APPROVER_PUBLIC_KEY) is False


def test_an_empty_id_falls_back_to_approval_receipt_id():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None, receipt_id="")
    receipt["approval_receipt_id"] = "urn:concordia:receipt:fallback"
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert mgr.apply_approval_receipt(sess, receipt)["approval_receipt_id"] == "urn:concordia:receipt:fallback"


def test_id_is_read_before_approval_receipt_id():
    mgr, sess = _paused_session()
    receipt = _approval_receipt(sess, sign_with=None, receipt_id="urn:concordia:receipt:primary")
    receipt["approval_receipt_id"] = "urn:concordia:receipt:secondary"
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)
    assert mgr.apply_approval_receipt(sess, receipt)["approval_receipt_id"] == "urn:concordia:receipt:primary"
