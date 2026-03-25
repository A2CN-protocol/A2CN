"""Tests for a2cn.session — state machine, turn-taking, idempotency."""

import uuid
import pytest

from a2cn.session import Session, SessionManager, SessionState, A2CNError
from a2cn.crypto import generate_keypair, hash_object, sign_jws


INITIATOR_DID = "did:web:techcorp.example"
RESPONDER_DID = "did:web:acme-corp.com"

SESSION_INIT = {
    "message_type": "session_init",
    "message_id": "init-msg-id",
    "protocol_version": "0.1",
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
    "protocol_version": "0.1",
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


def _make_offer(session_id, seq, rnd, sender_did, msg_type="offer", in_reply_to=None):
    timestamp = "2026-03-24T10:01:00Z"
    expires_at = "2030-01-01T00:00:00Z"
    terms = {"total_value": 9_500_000, "currency": "USD"}
    protocol_act = {
        "protocol_version": "0.1",
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
    msg = {
        "message_type": msg_type,
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "round_number": rnd,
        "sequence_number": seq,
        "sender_did": sender_did,
        "sender_agent_id": "agent",
        "sender_verification_method": f"{sender_did}#key-1",
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
        "protocol_act_hash": pah,
        "protocol_act_signature": "eyJ...",
    }
    if in_reply_to:
        msg["in_reply_to"] = in_reply_to
    return msg


def _new_session(session_id="sess-001") -> tuple[SessionManager, Session]:
    mgr = SessionManager()
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
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "tc-agent",
        "timestamp": "2026-03-24T10:02:00Z",
        "reason_code": "STRATEGY_DECISION",
    }
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

    acceptance = {
        "message_type": "acceptance",
        "message_id": "acc-1",
        "session_id": sess.session_id,
        "in_reply_to": o1["message_id"],
        "round_number": 1,
        "sequence_number": 2,
        "accepted_offer_id": o1["message_id"],
        "accepted_protocol_act_hash": o1["protocol_act_hash"],
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "acme-agent",
        "sender_verification_method": f"{RESPONDER_DID}#key-2026-01",
        "timestamp": "2026-03-24T10:05:00Z",
        "acceptance_signature": "eyJ...",
    }
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
    # Recompute hash with the new expires_at (otherwise hash mismatch fires first)
    from a2cn.crypto import hash_object as _ho
    protocol_act = {
        "protocol_version": "0.1",
        "session_id": o1["session_id"],
        "round_number": o1["round_number"],
        "sequence_number": o1["sequence_number"],
        "message_type": o1["message_type"],
        "sender_did": o1["sender_did"],
        "timestamp": o1["timestamp"],
        "expires_at": o1["expires_at"],
        "terms": o1["terms"],
    }
    o1["protocol_act_hash"] = _ho(protocol_act)
    mgr.process_message(sess, o1)

    # Update session hash tracker
    sess.latest_offer_hash = o1["protocol_act_hash"]

    acceptance = {
        "message_type": "acceptance",
        "message_id": str(uuid.uuid4()),
        "session_id": sess.session_id,
        "in_reply_to": o1["message_id"],
        "round_number": 1,
        "sequence_number": 2,
        "accepted_offer_id": o1["message_id"],
        "accepted_protocol_act_hash": o1["protocol_act_hash"],
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "acme-agent",
        "sender_verification_method": f"{RESPONDER_DID}#key-2026-01",
        "timestamp": "2026-03-24T10:05:00Z",
        "acceptance_signature": "eyJ...",
    }
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
