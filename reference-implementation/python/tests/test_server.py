"""Tests for a2cn.server — FastAPI endpoints."""

import uuid
import httpx
import pytest
import pytest_asyncio
import respx

from a2cn.crypto import (
    create_jwt,
    generate_ed25519_keypair,
    generate_keypair,
    hash_bytes,
    hash_object,
    public_key_to_jwk,
    sign_invitation,
    sign_jws,
    verify_jws,
)
from tests.conftest import (
    INITIATOR_DID,
    RESPONDER_DID,
    SERVER_DID,
    make_did_document,
    make_session_init,
)

A2CN_CT = "application/a2cn+json"
HEADERS = {"Content-Type": A2CN_CT, "Idempotency-Key": "placeholder"}


def init_headers(message_id: str) -> dict:
    return {"Content-Type": A2CN_CT, "Idempotency-Key": message_id}


# ---------------------------------------------------------------------------
# GET /.well-known/a2cn-agent — discovery
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_discovery_document(test_client):
    r = await test_client.get("/.well-known/a2cn-agent")
    assert r.status_code == 200
    doc = r.json()
    assert doc["a2cn_version"] == "0.2"
    assert "saas_renewal" in doc["deal_types"]
    assert doc["conformance_level"] == 2
    assert doc["agent_did"] == RESPONDER_DID


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
async def test_session_init_accepts_ed25519_jwt(raw_test_client):
    import a2cn.server as server_module

    priv, pub = generate_ed25519_keypair()
    server_module.register_did_document(
        INITIATOR_DID,
        make_did_document(INITIATOR_DID, "ed25519-1", public_key_to_jwk(pub)),
    )

    body = make_session_init()
    body["initiator"]["verification_method"] = f"{INITIATOR_DID}#ed25519-1"
    token = create_jwt(
        INITIATOR_DID,
        SERVER_DID,
        priv,
        kid=f"{INITIATOR_DID}#ed25519-1",
        exp_seconds=3600,
    )
    headers = init_headers(body["message_id"])
    headers["Authorization"] = f"Bearer {token}"

    r = await raw_test_client.post("/sessions", json=body, headers=headers)

    assert r.status_code == 201
    assert r.json()["current_turn"] == "initiator"


@pytest.mark.asyncio
async def test_session_init_rejects_initiator_did_mismatch(test_client):
    body = make_session_init()
    body["initiator"]["did"] = "did:web:impostor.example"

    r = await test_client.post(
        "/sessions",
        json=body,
        headers=init_headers(body["message_id"]),
    )

    assert r.status_code == 401
    assert r.json()["error"]["code"] == "SENDER_DID_MISMATCH"
    assert "initiator.did" in r.json()["error"]["message"]


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


# ---------------------------------------------------------------------------
# POST /invitations — signature-authenticated cold-start delivery
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_receive_invitation_does_not_require_bearer_token(raw_test_client):
    import a2cn.server as server_module

    inviter_priv, inviter_pub = generate_keypair()
    inviter_did = "did:web:buyer.example"
    vm_id = f"{inviter_did}#key-1"
    server_module.register_did_document(
        inviter_did,
        make_did_document(inviter_did, "key-1", public_key_to_jwk(inviter_pub)),
    )
    invitation = {
        "message_type": "session_invitation",
        "invitation_id": str(uuid.uuid4()),
        "a2cn_version": "0.2",
        "inviter_did": inviter_did,
        "inviter_endpoint": "https://buyer.example/a2cn",
        "inviter_discovery_url": "https://buyer.example/.well-known/a2cn-agent",
        "proposed_deal_type": "saas_renewal",
        "proposed_session_params": {
            "currency": "USD",
            "max_rounds": 4,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
        },
        "proposed_terms_summary": {"total_value": 9_500_000, "currency": "USD"},
        "inviter_mandate_summary": {"mandate_type": "declared"},
        "invitation_expires_at": "2030-01-01T00:00:00Z",
        "accept_endpoint": "https://buyer.example/a2cn/invitations/test/accept",
        "decline_endpoint": "https://buyer.example/a2cn/invitations/test/decline",
        "inviter_verification_method": vm_id,
        "invitation_signature": "",
    }
    invitation["invitation_signature"] = sign_invitation(invitation, inviter_priv)

    r = await raw_test_client.post("/invitations", json=invitation)

    assert r.status_code == 201
    assert r.json() == {
        "invitation_id": invitation["invitation_id"],
        "status": "pending",
    }


@pytest.mark.asyncio
async def test_invitation_create_still_requires_bearer_token(raw_test_client):
    r = await raw_test_client.post("/invitations/create", json={})

    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_JWT"


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
    body["protocol_version"] = "0.1"
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
# Webhook delivery
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_deliver_webhook_uses_did_key_jws_signature():
    import jwt as pyjwt
    from a2cn.server import deliver_webhook

    priv, pub = generate_keypair()
    route = respx.post("https://receiver.example/a2cn/callbacks").mock(
        return_value=httpx.Response(204)
    )
    payload = {
        "event_type": "session.completed",
        "session_id": "session-123",
        "occurred_at": "2026-05-20T05:00:00Z",
        "session_state": "COMPLETED",
        "terminal": True,
        "a2cn_version": "0.2",
    }

    await deliver_webhook(
        "https://receiver.example/a2cn/callbacks",
        "session.completed",
        "session-123",
        payload,
        {"max_retries": 1},
        sender_did=INITIATOR_DID,
        sender_verification_method=f"{INITIATOR_DID}#key-1",
        private_key=priv,
    )

    assert route.called
    request = route.calls[0].request
    body_hash = hash_bytes(request.content)

    assert request.headers["X-A2CN-Sender-DID"] == INITIATOR_DID
    assert (
        request.headers["X-A2CN-Sender-Verification-Method"]
        == f"{INITIATOR_DID}#key-1"
    )
    assert request.headers["X-A2CN-Body-SHA256"] == body_hash
    signature_header = pyjwt.get_unverified_header(request.headers["X-A2CN-Signature"])
    assert signature_header["alg"] == "ES256"
    assert signature_header["kid"] == f"{INITIATOR_DID}#key-1"
    assert verify_jws(request.headers["X-A2CN-Signature"], pub) == body_hash


# ---------------------------------------------------------------------------
# POST /sessions/{session_id}/messages
# ---------------------------------------------------------------------------

async def _create_session(client) -> str:
    body = make_session_init()
    r = await client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    return r.json()["session_id"]


def _make_offer_msg(session_id, seq, rnd, sender_did, private_key, msg_type="offer",
                    in_reply_to=None, msg_id=None):
    msg_id = msg_id or str(uuid.uuid4())
    timestamp = "2026-03-24T10:01:00Z"
    expires_at = "2030-01-01T00:00:00Z"
    terms = {"total_value": 9_500_000, "currency": "USD"}
    protocol_act = {
        "protocol_version": "0.2",
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
    verification_method = (
        f"{INITIATOR_DID}#key-1"
        if sender_did == INITIATOR_DID
        else f"{RESPONDER_DID}#key-2026-01"
    )
    msg = {
        "message_type": msg_type,
        "message_id": msg_id,
        "session_id": session_id,
        "round_number": rnd,
        "sequence_number": seq,
        "sender_did": sender_did,
        "sender_agent_id": "test-agent",
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


@pytest.mark.asyncio
async def test_send_offer_succeeds(test_client, initiator_keypair):
    session_id = await _create_session(test_client)
    offer = _make_offer_msg(session_id, 1, 1, INITIATOR_DID, initiator_keypair[0])
    r = await test_client.post(
        f"/sessions/{session_id}/messages",
        json=offer,
        headers=init_headers(offer["message_id"]),
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_not_your_turn(test_client, responder_test_client, responder_keypair):
    session_id = await _create_session(test_client)
    # Responder tries to send before initiator
    offer = _make_offer_msg(session_id, 1, 1, RESPONDER_DID, responder_keypair[0])
    r = await responder_test_client.post(
        f"/sessions/{session_id}/messages",
        json=offer,
        headers=init_headers(offer["message_id"]),
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "NOT_YOUR_TURN"


@pytest.mark.asyncio
async def test_sequence_error(test_client, initiator_keypair):
    session_id = await _create_session(test_client)
    offer = _make_offer_msg(session_id, 5, 1, INITIATOR_DID, initiator_keypair[0])  # wrong seq
    r = await test_client.post(
        f"/sessions/{session_id}/messages",
        json=offer,
        headers=init_headers(offer["message_id"]),
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SEQUENCE_ERROR"


@pytest.mark.asyncio
async def test_message_idempotency(test_client, initiator_keypair):
    session_id = await _create_session(test_client)
    offer = _make_offer_msg(session_id, 1, 1, INITIATOR_DID, initiator_keypair[0])
    h = init_headers(offer["message_id"])
    r1 = await test_client.post(f"/sessions/{session_id}/messages", json=offer, headers=h)
    r2 = await test_client.post(f"/sessions/{session_id}/messages", json=offer, headers=h)
    assert r1.json() == r2.json()


@pytest.mark.asyncio
async def test_get_messages_cursor_tolerates_sequence_less_page_item(test_client, initiator_keypair):
    session_id = await _create_session(test_client)
    offer = _make_offer_msg(session_id, 1, 1, INITIATOR_DID, initiator_keypair[0])
    await test_client.post(
        f"/sessions/{session_id}/messages",
        json=offer,
        headers=init_headers(offer["message_id"]),
    )

    r = await test_client.get(
        f"/sessions/{session_id}/messages",
        params={"after_sequence": -1, "limit": 1},
    )

    assert r.status_code == 200
    assert r.json()["next_cursor"] is None


@pytest.mark.asyncio
async def test_approval_receipt_endpoint_releases_human_approval_pause(test_client, initiator_keypair):
    body = make_session_init()
    body["initiator_mandate"]["requires_human_approval_above"] = 9_000_000
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    session_id = r.json()["session_id"]

    offer = _make_offer_msg(session_id, 1, 1, INITIATOR_DID, initiator_keypair[0])
    offer_r = await test_client.post(
        f"/sessions/{session_id}/messages",
        json=offer,
        headers=init_headers(offer["message_id"]),
    )
    assert offer_r.status_code == 200
    assert offer_r.json()["state"] == "AWAITING_HUMAN_APPROVAL"

    receipt = {
        "artifact_type": "ApprovalReceipt",
        "id": "urn:concordia:receipt:test",
        "scope": {
            "decision": "approve",
            "offer_hash": offer["protocol_act_hash"],
            "amount": "95000.00 USD",
            "threshold_crossed": "90000.00 USD",
        },
        "references": [
            {
                "type": "negotiation_session",
                "id": f"a2cn:session:{session_id}",
                "relationship": "approves",
            }
        ],
        "approver_did": INITIATOR_DID,
        "expires_at": "2030-01-01T00:00:00Z",
    }
    receipt_r = await test_client.post(
        f"/sessions/{session_id}/approval-receipt",
        json=receipt,
        headers=init_headers("approval-receipt-test"),
    )

    assert receipt_r.status_code == 200
    assert receipt_r.json()["state"] == "NEGOTIATING"
    assert receipt_r.json()["current_turn"] == "responder"
    assert receipt_r.json()["approval_receipt_id"] == "urn:concordia:receipt:test"


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
# GET /sessions/{session_id}/evidence — terminal only
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_evidence_not_available_for_active_session(test_client):
    session_id = await _create_session(test_client)
    r = await test_client.get(f"/sessions/{session_id}/evidence")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "SESSION_WRONG_STATE"


@pytest.mark.asyncio
async def test_evidence_available_after_withdrawal(test_client):
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
    await test_client.post(
        f"/sessions/{session_id}/messages",
        json=withdrawal,
        headers=init_headers(withdrawal["message_id"]),
    )

    r = await test_client.get(f"/sessions/{session_id}/evidence")

    assert r.status_code == 200
    data = r.json()
    assert data["record_type"] == "a2cn_session_evidence_record"
    assert data["terminal"]["outcome"] == "WITHDRAWN"
    assert data["evidence_level"] == "unilateral"
    assert data["producer"]["did"] == RESPONDER_DID
    assert data["producer_signature"]


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
