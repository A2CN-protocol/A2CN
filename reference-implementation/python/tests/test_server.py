"""Tests for a2cn.server — FastAPI endpoints."""

import json
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
    sign_approval_receipt,
    sign_invitation,
    sign_jws,
    verify_jws,
)
from tests.conftest import (
    sign_decline,
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
    assert doc["a2cn_version"] == "0.3"
    assert "saas_renewal" in doc["deal_types"]
    # Level 1 (declared mandates only): this implementation does not verify
    # did_vc mandates, so it neither lists them nor claims Level 2.
    assert doc["conformance_level"] == 1
    assert doc["mandate_methods"] == ["declared"]
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
        "a2cn_version": "0.3",
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
async def test_session_init_did_vc_mandate_is_refused_unverified(test_client):
    # A did_vc mandate is refused, never accepted unchecked: this implementation
    # does not verify Tier 2 credentials. The credential is otherwise well formed
    # and unexpired, so the refusal comes from the mandate type alone.
    body = make_session_init()
    body["initiator_mandate"] = {
        "mandate_type": "did_vc",
        "credential": {
            "type": ["VerifiableCredential", "A2CNMandate"],
            "issuer": "did:web:principal.example",
            "expirationDate": "2099-01-01T00:00:00Z",
            "credentialSubject": {
                "id": body["initiator_mandate"].get("agent_did", "did:web:agent.example"),
                "authorized_deal_types": ["saas_renewal"],
            },
            "proof": {"type": "JsonWebSignature2020", "jws": "not-a-real-signature"},
        },
    }
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert r.status_code == 403
    error = r.json()["error"]
    assert error["code"] == "MANDATE_INVALID"
    assert "not verified by this implementation" in error["message"]
    assert "session_id" not in r.json()


@pytest.mark.asyncio
async def test_responder_did_vc_mandate_is_refused_at_configuration(test_client, responder_config):
    # The server copies its own configured mandate into every SessionAck, so a
    # did_vc responder mandate would present a capability a level 1 server does
    # not have. Configuring one fails, and leaves the existing configuration in
    # place.
    import a2cn.server as server

    before = server._responder_config
    with pytest.raises(ValueError, match="declared mandate"):
        server.configure_responder({**responder_config, "mandate": {
            "mandate_type": "did_vc",
            "credential": {
                "type": ["VerifiableCredential", "A2CNMandate"],
                "issuer": "did:web:principal.example",
                "expirationDate": "2099-01-01T00:00:00Z",
                "credentialSubject": {"authorized_deal_types": ["saas_renewal"]},
                "proof": {"type": "JsonWebSignature2020", "jws": "not-a-real-signature"},
            },
        }})
    assert server._responder_config is before

    body = make_session_init()
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert r.status_code == 201
    assert r.json()["responder_mandate"]["mandate_type"] == "declared"


@pytest.mark.asyncio
async def test_session_init_wrong_protocol_version(test_client):
    body = make_session_init()
    body["protocol_version"] = "0.1"
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "PROTOCOL_VERSION_MISMATCH"


@pytest.mark.asyncio
async def test_session_init_at_a_superseded_version_is_refused(test_client):
    # "0.2" is recognised for verifying records, never for establishing a session
    # (Section 11.2.1).
    body = make_session_init()
    body["protocol_version"] = "0.2"
    r = await test_client.post("/sessions", json=body, headers=init_headers(body["message_id"]))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "PROTOCOL_VERSION_MISMATCH"
    assert r.json()["error"]["message"] == "Only protocol_version '0.3' is supported"
    assert "session_id" not in r.json()


@pytest.mark.asyncio
async def test_invitation_at_a_superseded_version_is_refused(raw_test_client):
    r = await raw_test_client.post(
        "/invitations",
        json={"message_type": "session_invitation", "a2cn_version": "0.2"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVITATION_VERSION_MISMATCH"


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
        "a2cn_version": "0.3",
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


APPROVER_DID = "did:web:approver.example"
APPROVER_PRIVATE_KEY, APPROVER_PUBLIC_KEY = generate_ed25519_keypair()


async def _paused_over_http(test_client, initiator_keypair, approvers=(APPROVER_DID,)):
    """A session whose initiator offer is paused for an operator's approval."""
    import a2cn.server as server_module

    server_module.register_did_document(
        APPROVER_DID, make_did_document(APPROVER_DID, "key-1", public_key_to_jwk(APPROVER_PUBLIC_KEY))
    )
    body = make_session_init()
    body["initiator_mandate"]["requires_human_approval_above"] = 9_000_000
    body["initiator_mandate"]["approval_operator_dids"] = list(approvers)
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
    return session_id, offer, body["initiator_mandate"]


def _receipt(session_id: str, offer: dict, mandate: dict, approver_did: str,
             receipt_id: str = "urn:concordia:receipt:test") -> dict:
    return {
        "artifact_type": "ApprovalReceipt",
        "id": receipt_id,
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
            },
            {
                "type": "mandate",
                "id": hash_object(mandate),
                "relationship": "fulfills",
            },
            {"type": "paused_party", "id": INITIATOR_DID, "relationship": "approves"},
        ],
        "approver_did": approver_did,
        "expires_at": "2030-01-01T00:00:00Z",
    }


@pytest.mark.asyncio
async def test_approval_receipt_endpoint_releases_human_approval_pause(test_client, initiator_keypair):
    session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair)
    receipt = _receipt(session_id, offer, mandate, APPROVER_DID)
    receipt["signature"] = sign_approval_receipt(receipt, APPROVER_PRIVATE_KEY)

    receipt_r = await test_client.post(
        f"/sessions/{session_id}/approval-receipt",
        json=receipt,
        headers=init_headers("approval-receipt-test"),
    )

    assert receipt_r.status_code == 200
    assert receipt_r.json()["state"] == "NEGOTIATING"
    assert receipt_r.json()["current_turn"] == "responder"
    assert receipt_r.json()["approval_receipt_id"] == "urn:concordia:receipt:test"


@pytest.mark.asyncio
async def test_a_session_party_cannot_release_its_own_pause_with_an_unsigned_receipt(
    test_client, initiator_keypair
):
    # The paused agent posts an unsigned receipt naming an authorised approver.
    # It is refused and the session stays paused.
    session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair)
    receipt = _receipt(session_id, offer, mandate, APPROVER_DID)

    receipt_r = await test_client.post(
        f"/sessions/{session_id}/approval-receipt",
        json=receipt,
        headers=init_headers("approval-receipt-unsigned"),
    )

    assert receipt_r.status_code == 400
    assert receipt_r.json()["error"]["code"] == "APPROVAL_RECEIPT_UNSIGNED"
    state = (await test_client.get(f"/sessions/{session_id}")).json()
    assert state["state"] == "AWAITING_HUMAN_APPROVAL"


@pytest.mark.asyncio
async def test_a_receipt_signed_with_the_paused_agents_own_key_is_refused(test_client, initiator_keypair):
    session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair)
    receipt = _receipt(session_id, offer, mandate, APPROVER_DID)
    receipt["signature"] = sign_approval_receipt(receipt, initiator_keypair[0])

    receipt_r = await test_client.post(
        f"/sessions/{session_id}/approval-receipt",
        json=receipt,
        headers=init_headers("approval-receipt-self-signed"),
    )

    assert receipt_r.status_code == 400
    assert receipt_r.json()["error"]["code"] == "APPROVAL_RECEIPT_SIGNATURE_INVALID"
    state = (await test_client.get(f"/sessions/{session_id}")).json()
    assert state["state"] == "AWAITING_HUMAN_APPROVAL"


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
async def test_evidence_available_after_withdrawal(test_client, initiator_keypair):
    session_id = await _create_session(test_client)
    withdrawal = {
        "message_type": "withdrawal",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "test-agent",
        "timestamp": "2026-03-24T10:02:00Z",
        "reason_code": "STRATEGY_DECISION",
    }
    withdrawal = sign_decline(withdrawal, initiator_keypair[0], f"{INITIATOR_DID}#key-1")
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


@pytest.mark.asyncio
async def test_evidence_rejects_authenticated_nonparty(test_client, initiator_keypair):
    import a2cn.server as server_module

    session_id = await _create_session(test_client)
    withdrawal = {
        "message_type": "withdrawal",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "timestamp": "2026-03-24T10:02:00Z",
        "reason_code": "STRATEGY_DECISION",
    }
    withdrawal = sign_decline(withdrawal, initiator_keypair[0], f"{INITIATOR_DID}#key-1")
    await test_client.post(
        f"/sessions/{session_id}/messages",
        json=withdrawal,
        headers=init_headers(withdrawal["message_id"]),
    )

    outsider_did = "did:web:observer.example"
    outsider_private_key, outsider_public_key = generate_keypair()
    server_module.register_did_document(
        outsider_did,
        make_did_document(
            outsider_did,
            "key-1",
            public_key_to_jwk(outsider_public_key),
        ),
    )
    token = create_jwt(
        outsider_did,
        SERVER_DID,
        outsider_private_key,
        kid=f"{outsider_did}#key-1",
        exp_seconds=3600,
    )
    transport = httpx.ASGITransport(app=server_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as outsider:
        response = await outsider.get(
            f"/sessions/{session_id}/evidence",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "NOT_SESSION_PARTY"


@pytest.mark.asyncio
async def test_an_incomplete_unsigned_withdrawal_is_refused_on_the_wire(test_client):
    """A live withdrawal must be signed, and one this incomplete cannot even be rebuilt.

    It was once accepted and recorded as an unsigned observation with null
    message_id and timestamp. A party's own decline is now signed (Section 7.6),
    so the session stays open; the evidence record's handling of an incomplete
    unsigned act is covered where such an act is recorded, as an observation.
    """
    session_id = await _create_session(test_client)
    withdrawal = {
        "message_type": "withdrawal",
        "round_number": 1,
        "sender_did": INITIATOR_DID,
    }
    response = await test_client.post(
        f"/sessions/{session_id}/messages",
        json=withdrawal,
        headers=init_headers("incomplete-withdrawal"),
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_SIGNATURE"
    evidence_response = await test_client.get(f"/sessions/{session_id}/evidence")
    assert evidence_response.status_code == 409


# ---------------------------------------------------------------------------
# GET /sessions/{session_id}/audit — terminal only
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_not_available_for_active_session(test_client):
    session_id = await _create_session(test_client)
    r = await test_client.get(f"/sessions/{session_id}/audit")
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_audit_available_after_withdrawal(test_client, initiator_keypair):
    session_id = await _create_session(test_client)
    withdrawal = {
        "message_type": "withdrawal",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "test-agent",
        "timestamp": "2026-03-24T10:02:00Z",
        "reason_code": "STRATEGY_DECISION",
    }
    withdrawal = sign_decline(withdrawal, initiator_keypair[0], f"{INITIATOR_DID}#key-1")
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


# --- The approver's DID document is resolved per receipt, after the cheap checks. ---

DYNAMIC_APPROVER_DID = "did:web:dyn-approver.example"
DYNAMIC_APPROVER_URL = "https://dyn-approver.example/.well-known/did.json"


def _post_receipt(test_client, session_id, receipt, key):
    receipt = dict(receipt)
    receipt["signature"] = sign_approval_receipt(receipt, key)
    return test_client.post(
        f"/sessions/{session_id}/approval-receipt", json=receipt, headers=init_headers(f"receipt-{uuid.uuid4()}")
    )


@pytest.mark.asyncio
async def test_an_unregistered_did_web_approver_is_resolved_for_the_receipt(test_client, initiator_keypair):
    key, public = generate_ed25519_keypair()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(DYNAMIC_APPROVER_URL).mock(
            return_value=httpx.Response(200, json=make_did_document(DYNAMIC_APPROVER_DID, "key-1", public_key_to_jwk(public)))
        )
        session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair, (DYNAMIC_APPROVER_DID,))
        r = await _post_receipt(test_client, session_id, _receipt(session_id, offer, mandate, DYNAMIC_APPROVER_DID), key)
    assert r.status_code == 200 and r.json()["state"] == "NEGOTIATING"
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_a_rotated_approver_key_takes_effect_on_the_next_receipt(test_client, initiator_keypair):
    old_key, old_public = generate_ed25519_keypair()
    new_key, new_public = generate_ed25519_keypair()
    document = {"current": make_did_document(DYNAMIC_APPROVER_DID, "key-1", public_key_to_jwk(old_public))}
    with respx.mock(assert_all_called=False) as mock:
        mock.get(DYNAMIC_APPROVER_URL).mock(side_effect=lambda request: httpx.Response(200, json=document["current"]))
        first, offer, mandate = await _paused_over_http(test_client, initiator_keypair, (DYNAMIC_APPROVER_DID,))
        assert (await _post_receipt(test_client, first, _receipt(first, offer, mandate, DYNAMIC_APPROVER_DID), old_key)).status_code == 200

        # The approver rotates: its document now lists only the new key.
        document["current"] = make_did_document(DYNAMIC_APPROVER_DID, "key-2", public_key_to_jwk(new_public))
        second, offer, mandate = await _paused_over_http(test_client, initiator_keypair, (DYNAMIC_APPROVER_DID,))
        old = await _post_receipt(test_client, second, _receipt(second, offer, mandate, DYNAMIC_APPROVER_DID, "urn:r:old"), old_key)
        new = await _post_receipt(test_client, second, _receipt(second, offer, mandate, DYNAMIC_APPROVER_DID, "urn:r:new"), new_key)
    assert old.status_code == 400 and old.json()["error"]["code"] == "APPROVAL_RECEIPT_SIGNATURE_INVALID"
    assert new.status_code == 200 and new.json()["state"] == "NEGOTIATING"


@pytest.mark.asyncio
async def test_a_did_url_approver_is_resolved_from_its_base_did(test_client, initiator_keypair):
    key, public = generate_ed25519_keypair()
    approver = f"{DYNAMIC_APPROVER_DID}#key-1"
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(DYNAMIC_APPROVER_URL).mock(
            return_value=httpx.Response(200, json=make_did_document(DYNAMIC_APPROVER_DID, "key-1", public_key_to_jwk(public)))
        )
        session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair, (approver,))
        r = await _post_receipt(test_client, session_id, _receipt(session_id, offer, mandate, approver), key)
    assert r.status_code == 200
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_an_approver_outside_did_web_is_never_fetched(test_client, initiator_keypair):
    key, _ = generate_ed25519_keypair()
    approver = "did:example:approver"
    with respx.mock(assert_all_called=False) as mock:
        catch_all = mock.route().mock(return_value=httpx.Response(500))
        session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair, (approver,))
        r = await _post_receipt(test_client, session_id, _receipt(session_id, offer, mandate, approver), key)
    assert r.status_code == 400 and r.json()["error"]["code"] == "APPROVAL_RECEIPT_KEY_UNRESOLVED"
    assert catch_all.call_count == 0


@pytest.mark.asyncio
async def test_a_receipt_failing_a_check_that_needs_no_key_causes_no_fetch(test_client, initiator_keypair):
    key, public = generate_ed25519_keypair()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(DYNAMIC_APPROVER_URL).mock(
            return_value=httpx.Response(200, json=make_did_document(DYNAMIC_APPROVER_DID, "key-1", public_key_to_jwk(public)))
        )
        session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair)  # approver not authorised
        r = await _post_receipt(test_client, session_id, _receipt(session_id, offer, mandate, DYNAMIC_APPROVER_DID), key)
    assert r.status_code == 403 and r.json()["error"]["code"] == "UNAUTHORIZED_APPROVER"
    assert route.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [None, [], "receipt", 5, True])
async def test_a_non_object_receipt_body_is_refused_cleanly(test_client, initiator_keypair, body):
    session_id, _offer, _mandate = await _paused_over_http(test_client, initiator_keypair)
    r = await test_client.post(
        f"/sessions/{session_id}/approval-receipt",
        content=json.dumps(body),
        headers={**init_headers("receipt-non-object"), "Content-Type": "application/a2cn+json"},
    )
    assert r.status_code == 400 and r.json()["error"]["code"] == "APPROVAL_RECEIPT_INVALID"


@pytest.mark.asyncio
async def test_a_did_web_redirect_is_not_followed(test_client, initiator_keypair):
    # Both implementations follow no redirects when resolving an approver.
    key, public = generate_ed25519_keypair()
    with respx.mock(assert_all_called=False) as mock:
        mock.get(DYNAMIC_APPROVER_URL).mock(
            return_value=httpx.Response(302, headers={"Location": "https://dyn-approver.example/moved/did.json"})
        )
        moved = mock.get("https://dyn-approver.example/moved/did.json").mock(
            return_value=httpx.Response(200, json=make_did_document(DYNAMIC_APPROVER_DID, "key-1", public_key_to_jwk(public)))
        )
        session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair, (DYNAMIC_APPROVER_DID,))
        r = await _post_receipt(test_client, session_id, _receipt(session_id, offer, mandate, DYNAMIC_APPROVER_DID), key)
    assert r.status_code == 400 and r.json()["error"]["code"] == "APPROVAL_RECEIPT_KEY_UNRESOLVED"
    assert moved.call_count == 0


# --- did:web resolution limits: total deadline, size, encoding. ---

def test_did_web_resolution_gives_up_after_five_seconds_in_total():
    import a2cn.did as did_module
    assert did_module.DID_RESOLUTION_TIMEOUT_SECONDS == 5.0


@pytest.mark.asyncio
async def test_a_slow_did_web_host_is_cut_off_at_the_deadline(test_client, initiator_keypair, monkeypatch):
    import asyncio
    import a2cn.did as did_module
    monkeypatch.setattr(did_module, "DID_RESOLUTION_TIMEOUT_SECONDS", 0.2)
    key, public = generate_ed25519_keypair()
    document = make_did_document(DYNAMIC_APPROVER_DID, "key-1", public_key_to_jwk(public))

    async def slow(request):
        await asyncio.sleep(1.0)
        return httpx.Response(200, json=document)

    with respx.mock(assert_all_called=False) as mock:
        mock.get(DYNAMIC_APPROVER_URL).mock(side_effect=slow)
        session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair, (DYNAMIC_APPROVER_DID,))
        r = await _post_receipt(test_client, session_id, _receipt(session_id, offer, mandate, DYNAMIC_APPROVER_DID), key)
    assert r.status_code == 400 and r.json()["error"]["code"] == "APPROVAL_RECEIPT_KEY_UNRESOLVED"


def _document_bytes_variants(public):
    document = make_did_document(DYNAMIC_APPROVER_DID, "key-1", public_key_to_jwk(public))
    text = json.dumps(document)
    return {
        "utf8_bom": (b"\xef\xbb\xbf" + text.encode("utf-8"), 200),
        "utf16": (text.encode("utf-16"), 400),
        "nan_literal": (text[:-1].encode("utf-8") + b', "x": NaN}', 400),
        "too_large": (text[:-1].encode("utf-8") + b', "pad": "' + b"a" * 70000 + b'"}', 400),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["utf8_bom", "utf16", "nan_literal", "too_large"])
async def test_did_documents_are_strict_utf8_json_within_the_size_limit(test_client, initiator_keypair, variant):
    key, public = generate_ed25519_keypair()
    body, expected = _document_bytes_variants(public)[variant]
    with respx.mock(assert_all_called=False) as mock:
        mock.get(DYNAMIC_APPROVER_URL).mock(return_value=httpx.Response(200, content=body))
        session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair, (DYNAMIC_APPROVER_DID,))
        r = await _post_receipt(test_client, session_id, _receipt(session_id, offer, mandate, DYNAMIC_APPROVER_DID), key)
    assert r.status_code == expected
    if expected == 400:
        assert r.json()["error"]["code"] == "APPROVAL_RECEIPT_KEY_UNRESOLVED"
