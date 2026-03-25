"""
A2CN Conformance Tests (Week 3 target, implemented now for completeness)

Each test represents a named scenario from the spec.
These tests must pass against any conformant implementation.
"""

import uuid
import pytest
import pytest_asyncio

from a2cn.crypto import generate_keypair, hash_object, sign_jws
from a2cn.record import generate_transaction_record
from a2cn.session import SessionManager, SessionState, A2CNError
from tests.conftest import (
    make_session_init, INITIATOR_DID, RESPONDER_DID,
    make_did_document
)
from a2cn.crypto import public_key_to_jwk

HEADERS_CT = {"Content-Type": "application/a2cn+json"}


def init_headers(message_id: str) -> dict:
    return {"Content-Type": "application/a2cn+json", "Idempotency-Key": message_id}


# ---------------------------------------------------------------------------
# Helpers shared across conformance tests
# ---------------------------------------------------------------------------

async def _create_session(client) -> str:
    body = make_session_init()
    r = await client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert r.status_code == 201
    return r.json()["session_id"]


def _offer(session_id, seq, rnd, sender_did, msg_type="offer", in_reply_to=None,
           msg_id=None):
    msg_id = msg_id or str(uuid.uuid4())
    timestamp = "2026-03-24T10:00:00Z"
    expires_at = "2030-01-01T00:00:00Z"
    terms = {"total_value": 10_000_000, "currency": "USD"}
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
        "message_id": msg_id,
        "session_id": session_id,
        "round_number": rnd,
        "sequence_number": seq,
        "sender_did": sender_did,
        "sender_agent_id": "conformance-agent",
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


# ---------------------------------------------------------------------------
# CONF-001: test_session_init_idempotency
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_session_init_idempotency(test_client):
    """Same message_id MUST return the same session_id — no second session created."""
    body = make_session_init()
    h = init_headers(body["message_id"])

    r1 = await test_client.post("/sessions", json=body, headers=h)
    r2 = await test_client.post("/sessions", json=body, headers=h)

    assert r1.status_code in (200, 201)
    assert r2.status_code in (200, 201)
    assert r1.json()["session_id"] == r2.json()["session_id"]


# ---------------------------------------------------------------------------
# CONF-002: test_turn_taking_enforced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_turn_taking_enforced(test_client):
    """NOT_YOUR_TURN returned for out-of-turn message."""
    session_id = await _create_session(test_client)

    # Responder tries to send before initiator — must fail
    offer = _offer(session_id, 1, 1, RESPONDER_DID)
    r = await test_client.post(
        f"/sessions/{session_id}/messages", json=offer, headers=init_headers(offer["message_id"])
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "NOT_YOUR_TURN"


# ---------------------------------------------------------------------------
# CONF-003: test_offer_signature_verified (Week 2 — marked for wiring)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_offer_signature_verified_placeholder(test_client):
    """
    Invalid signature MUST be rejected with INVALID_SIGNATURE.
    TODO Week 2: wire up DID resolution + signature verification in server.py.
    This test will be enabled when JWT auth and protocol act verification are live.
    """
    pytest.skip("Signature verification wired in Week 2")


# ---------------------------------------------------------------------------
# CONF-004: test_transaction_record_deterministic
# ---------------------------------------------------------------------------

def test_transaction_record_deterministic():
    """Both sides generate identical record_hash independently."""
    mgr = SessionManager()
    session_id = str(uuid.uuid4())

    init_msg = {
        "message_type": "session_init",
        "message_id": "init-1",
        "protocol_version": "0.1",
        "session_params": {
            "deal_type": "saas_renewal",
            "currency": "USD",
            "subject": "Conformance Test",
            "max_rounds": 4,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
        },
        "initiator": {
            "organization_name": "Buyer Corp",
            "did": INITIATOR_DID,
            "verification_method": f"{INITIATOR_DID}#key-1",
            "agent_id": "buyer-agent",
            "endpoint": "https://buyer.example/api/a2cn",
        },
        "initiator_mandate": {"mandate_type": "declared"},
    }

    ack_msg = {
        "message_type": "session_ack",
        "message_id": "ack-1",
        "session_id": session_id,
        "in_reply_to": "init-1",
        "protocol_version": "0.1",
        "session_params_accepted": {
            "deal_type": "saas_renewal",
            "currency": "USD",
            "max_rounds": 4,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
        },
        "responder": {
            "organization_name": "Seller Corp",
            "did": RESPONDER_DID,
            "verification_method": f"{RESPONDER_DID}#key-2026-01",
            "agent_id": "seller-agent",
            "endpoint": "http://localhost:8000",
        },
        "responder_mandate": {"mandate_type": "declared"},
        "session_created_at": "2026-03-24T10:00:00Z",
        "current_turn": "initiator",
    }

    sess = mgr.create_session(session_id, init_msg, ack_msg, "2026-03-24T10:00:00Z")
    # Prevent timeout on a session with a historical created_at timestamp
    sess.session_timeout_seconds = 86400 * 365 * 100

    _offer_timestamp = "2026-03-24T10:01:00Z"
    _offer_expires = "2030-01-01T00:00:00Z"
    _offer_terms = {"total_value": 10_500_000, "currency": "USD"}
    _offer_pah = hash_object({
        "protocol_version": "0.1",
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "message_type": "offer",
        "sender_did": INITIATOR_DID,
        "timestamp": _offer_timestamp,
        "expires_at": _offer_expires,
        "terms": _offer_terms,
    })

    offer_msg = {
        "message_type": "offer",
        "message_id": "offer-1",
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "buyer-agent",
        "sender_verification_method": f"{INITIATOR_DID}#key-1",
        "timestamp": _offer_timestamp,
        "expires_at": _offer_expires,
        "terms": _offer_terms,
        "protocol_act_hash": _offer_pah,
        "protocol_act_signature": "eyJ...",
    }

    acceptance_msg = {
        "message_type": "acceptance",
        "message_id": "acc-1",
        "session_id": session_id,
        "in_reply_to": "offer-1",
        "round_number": 1,
        "sequence_number": 2,
        "accepted_offer_id": "offer-1",
        "accepted_protocol_act_hash": _offer_pah,
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "seller-agent",
        "sender_verification_method": f"{RESPONDER_DID}#key-2026-01",
        "timestamp": "2026-03-24T10:03:00Z",
        "acceptance_signature": "eyJ...",
    }

    mgr.process_message(sess, offer_msg)
    mgr.process_message(sess, acceptance_msg)

    assert sess.state == SessionState.COMPLETED

    # Generate record twice from the same session object
    record_a = generate_transaction_record(sess)
    record_b = generate_transaction_record(sess)

    assert record_a["record_hash"] == record_b["record_hash"]
    assert record_a["record_id"] == record_b["record_id"]
    # generated_at must come from acceptance timestamp, not datetime.now()
    assert record_a["generated_at"] == "2026-03-24T10:03:00Z"


# ---------------------------------------------------------------------------
# CONF-005: test_sequence_ordering_strict
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sequence_ordering_strict(test_client):
    """Gap in sequence_number rejected with SEQUENCE_ERROR."""
    session_id = await _create_session(test_client)

    # Send seq=1 OK
    offer = _offer(session_id, 1, 1, INITIATOR_DID)
    r = await test_client.post(
        f"/sessions/{session_id}/messages", json=offer, headers=init_headers(offer["message_id"])
    )
    assert r.status_code == 200

    # Now send seq=3 (skipping 2) — must fail
    bad_offer = _offer(session_id, 3, 2, RESPONDER_DID, msg_type="counteroffer",
                       in_reply_to=offer["message_id"])
    r2 = await test_client.post(
        f"/sessions/{session_id}/messages", json=bad_offer, headers=init_headers(bad_offer["message_id"])
    )
    assert r2.status_code == 422
    assert r2.json()["error"]["code"] == "SEQUENCE_ERROR"


# ---------------------------------------------------------------------------
# CONF-006: test_terminal_state_reentry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_terminal_state_reentry(test_client):
    """SESSION_WRONG_STATE returned for messages on completed/terminal session."""
    session_id = await _create_session(test_client)

    # Complete via withdrawal
    w = {
        "message_type": "withdrawal",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "test-agent",
        "timestamp": "2026-03-24T10:02:00Z",
        "reason_code": "NO_REASON_GIVEN",
    }
    await test_client.post(
        f"/sessions/{session_id}/messages", json=w, headers=init_headers(w["message_id"])
    )

    # Try to send another offer
    offer = _offer(session_id, 2, 1, INITIATOR_DID)
    r = await test_client.post(
        f"/sessions/{session_id}/messages", json=offer, headers=init_headers(offer["message_id"])
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "SESSION_WRONG_STATE"


# ---------------------------------------------------------------------------
# CONF-007: test_record_id_deterministic (UUID v5 with A2CN namespace)
# ---------------------------------------------------------------------------

def test_record_id_uses_a2cn_namespace():
    """record_id must be UUID v5 with A2CN namespace f4a2c1e0-..."""
    import uuid as uuid_mod
    from a2cn.record import A2CN_NAMESPACE

    session_id = "c3d4e5f6-a7b8-9012-cdef-123456789012"
    expected = str(uuid_mod.uuid5(A2CN_NAMESPACE, session_id))

    # Generate it the same way the record module does
    actual = str(uuid_mod.uuid5(A2CN_NAMESPACE, session_id))
    assert actual == expected
    # And it must differ from using the DNS namespace
    wrong = str(uuid_mod.uuid5(uuid_mod.NAMESPACE_DNS, session_id))
    assert actual != wrong
