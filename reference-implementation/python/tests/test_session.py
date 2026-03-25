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


def _make_offer(session_id, seq, rnd, sender_did, msg_type="offer", in_reply_to=None, pah="sha256-hash"):
    msg = {
        "message_type": msg_type,
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "round_number": rnd,
        "sequence_number": seq,
        "sender_did": sender_did,
        "sender_agent_id": "agent",
        "sender_verification_method": f"{sender_did}#key-1",
        "timestamp": "2026-03-24T10:01:00Z",
        "expires_at": "2026-03-24T10:16:00Z",
        "terms": {"total_value": 9_500_000, "currency": "USD"},
        "protocol_act_hash": pah,
        "protocol_act_signature": "eyJ...",
    }
    if in_reply_to:
        msg["in_reply_to"] = in_reply_to
    return msg


def _new_session(session_id="sess-001") -> tuple[SessionManager, Session]:
    mgr = SessionManager()
    sess = mgr.create_session(session_id, SESSION_INIT, SESSION_ACK, "2026-03-24T10:00:00Z")
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
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID, pah="hash-1")
    mgr.process_message(sess, o1)
    assert sess.current_turn == "responder"

    co1 = _make_offer(sess.session_id, 2, 2, RESPONDER_DID, msg_type="counteroffer",
                      in_reply_to=o1["message_id"], pah="hash-2")
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
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID, pah="h1")
    mgr.process_message(sess, o1)
    assert sess.sequence_number == 1

    co1 = _make_offer(sess.session_id, 2, 2, RESPONDER_DID, msg_type="counteroffer",
                      in_reply_to=o1["message_id"], pah="h2")
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
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID, pah="hash-offer-1")
    mgr.process_message(sess, o1)

    acceptance = {
        "message_type": "acceptance",
        "message_id": "acc-1",
        "session_id": sess.session_id,
        "in_reply_to": o1["message_id"],
        "round_number": 1,
        "sequence_number": 2,
        "accepted_offer_id": o1["message_id"],
        "accepted_protocol_act_hash": "hash-offer-1",
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
    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID, pah="h1")
    mgr.process_message(sess, o1)

    # Responder sends "offer" in round 2 (should be "counteroffer")
    bad = _make_offer(sess.session_id, 2, 2, RESPONDER_DID, msg_type="offer",
                      in_reply_to=o1["message_id"], pah="h2")
    with pytest.raises(A2CNError) as exc_info:
        mgr.process_message(sess, bad)
    assert exc_info.value.code == "WRONG_MESSAGE_TYPE"


# ---------------------------------------------------------------------------
# REJECTED_FINAL at max_rounds
# ---------------------------------------------------------------------------

def test_rejection_at_max_rounds_transitions_to_rejected_final():
    mgr, sess = _new_session()
    sess.max_rounds = 1  # single-round session

    o1 = _make_offer(sess.session_id, 1, 1, INITIATOR_DID, pah="h1")
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
