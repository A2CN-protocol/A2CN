"""Tests for a2cn.server — FastAPI endpoints."""

import uuid
import pytest
import pytest_asyncio

from tests.conftest import make_session_init, INITIATOR_DID, RESPONDER_DID

A2CN_CT = "application/a2cn+json"
HEADERS = {"Content-Type": A2CN_CT, "Idempotency-Key": "placeholder"}


def init_headers(message_id: str) -> dict:
    return {"Content-Type": A2CN_CT, "Idempotency-Key": message_id}


# ---------------------------------------------------------------------------
# POST /sessions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_session_init_returns_201(test_client):
    body = make_session_init()
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert r.status_code == 201
    data = r.json()
    assert data["message_type"] == "session_ack"
    assert "session_id" in data
    assert data["current_turn"] == "initiator"


@pytest.mark.asyncio
async def test_session_init_content_type(test_client):
    body = make_session_init()
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert "application/a2cn+json" in r.headers["content-type"]


@pytest.mark.asyncio
async def test_session_init_idempotency(test_client):
    body = make_session_init()
    h = init_headers(body["message_id"])
    r1 = await test_client.post("/sessions", json=body, headers=h)
    r2 = await test_client.post("/sessions", json=body, headers=h)
    assert r1.json()["session_id"] == r2.json()["session_id"]


@pytest.mark.asyncio
async def test_session_init_wrong_deal_type(test_client):
    body = make_session_init()
    body["session_params"]["deal_type"] = "freight_rate"  # not supported
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "DEAL_TYPE_NOT_SUPPORTED"


@pytest.mark.asyncio
async def test_session_init_expired_mandate(test_client):
    body = make_session_init()
    body["initiator_mandate"]["valid_until"] = "2020-01-01T00:00:00Z"  # in the past
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "MANDATE_INVALID"


@pytest.mark.asyncio
async def test_session_init_wrong_protocol_version(test_client):
    body = make_session_init()
    body["protocol_version"] = "0.2"
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "PROTOCOL_VERSION_MISMATCH"


# ---------------------------------------------------------------------------
# GET /sessions/{session_id}
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_session_state(test_client):
    body = make_session_init()
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    session_id = r.json()["session_id"]

    r2 = await test_client.get(f"/sessions/{session_id}")
    assert r2.status_code == 200
    data = r2.json()
    assert data["session_id"] == session_id
    assert data["state"] == "ACTIVE"


@pytest.mark.asyncio
async def test_get_session_not_found(test_client):
    r = await test_client.get("/sessions/nonexistent-id")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "SESSION_NOT_FOUND"


# ---------------------------------------------------------------------------
# POST /sessions/{session_id}/messages
# ---------------------------------------------------------------------------

async def _create_session(client) -> str:
    body = make_session_init()
    r = await client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    return r.json()["session_id"]


def _make_offer_msg(session_id, seq, rnd, sender_did, msg_type="offer",
                    in_reply_to=None, msg_id=None, pah="sha256-testhash"):
    msg_id = msg_id or str(uuid.uuid4())
    msg = {
        "message_type": msg_type,
        "message_id": msg_id,
        "session_id": session_id,
        "round_number": rnd,
        "sequence_number": seq,
        "sender_did": sender_did,
        "sender_agent_id": "test-agent",
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


@pytest.mark.asyncio
async def test_send_offer_succeeds(test_client):
    session_id = await _create_session(test_client)
    offer = _make_offer_msg(session_id, 1, 1, INITIATOR_DID)
    r = await test_client.post(
        f"/sessions/{session_id}/messages",
        json=offer,
        headers=init_headers(offer["message_id"]),
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_not_your_turn(test_client):
    session_id = await _create_session(test_client)
    # Responder tries to send before initiator
    offer = _make_offer_msg(session_id, 1, 1, RESPONDER_DID)
    r = await test_client.post(
        f"/sessions/{session_id}/messages",
        json=offer,
        headers=init_headers(offer["message_id"]),
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "NOT_YOUR_TURN"


@pytest.mark.asyncio
async def test_sequence_error(test_client):
    session_id = await _create_session(test_client)
    offer = _make_offer_msg(session_id, 5, 1, INITIATOR_DID)  # wrong seq
    r = await test_client.post(
        f"/sessions/{session_id}/messages",
        json=offer,
        headers=init_headers(offer["message_id"]),
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SEQUENCE_ERROR"


@pytest.mark.asyncio
async def test_message_idempotency(test_client):
    session_id = await _create_session(test_client)
    offer = _make_offer_msg(session_id, 1, 1, INITIATOR_DID)
    h = init_headers(offer["message_id"])
    r1 = await test_client.post(f"/sessions/{session_id}/messages", json=offer, headers=h)
    r2 = await test_client.post(f"/sessions/{session_id}/messages", json=offer, headers=h)
    assert r1.json() == r2.json()


# ---------------------------------------------------------------------------
# GET /sessions/{session_id}/record — COMPLETED only
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_record_not_available_for_active_session(test_client):
    session_id = await _create_session(test_client)
    r = await test_client.get(f"/sessions/{session_id}/record")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "SESSION_WRONG_STATE"


# ---------------------------------------------------------------------------
# GET /sessions/{session_id}/audit — terminal only
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_not_available_for_active_session(test_client):
    session_id = await _create_session(test_client)
    r = await test_client.get(f"/sessions/{session_id}/audit")
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_audit_available_after_withdrawal(test_client):
    session_id = await _create_session(test_client)
    withdrawal = {
        "message_type": "withdrawal",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "test-agent",
        "timestamp": "2026-03-24T10:02:00Z",
        "reason_code": "STRATEGY_DECISION",
    }
    wid = withdrawal["message_id"]
    await test_client.post(
        f"/sessions/{session_id}/messages",
        json=withdrawal,
        headers=init_headers(wid),
    )
    r = await test_client.get(f"/sessions/{session_id}/audit")
    assert r.status_code == 200
    data = r.json()
    assert data["session_outcome"] == "WITHDRAWN"
