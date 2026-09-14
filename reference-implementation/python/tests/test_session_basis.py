"""Tests for session_params.basis: carried, enum-checked, and fixed at initiation.

Verdicts come from spec/test-vectors/session-params-basis.json, which the
TypeScript suite asserts too. basis is a label: nothing here converts net and
gross, and an absent basis stays absent (no default).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import httpx
import pytest

from a2cn.client import A2CNClient
from a2cn.crypto import generate_keypair, hash_object, sign_jws
from a2cn.messages import SessionParams
from a2cn.session import SESSION_BASES, A2CNError, SessionManager
from tests.conftest import INITIATOR_DID, RESPONDER_DID, make_session_init

REPO_ROOT = Path(__file__).parents[3]
VECTORS = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "session-params-basis.json").read_text()
)
INVITATION_SCHEMA = json.loads(
    (REPO_ROOT / "spec" / "schemas" / "session-invitation.schema.json").read_text()
)
NOW = "2026-03-24T10:00:00Z"


def _headers(message_id: str) -> dict:
    return {"Content-Type": "application/a2cn+json", "Idempotency-Key": message_id}


def _init_and_ack(proposed: dict, accepted: dict) -> tuple[dict, dict]:
    """A SessionInit/SessionAck pair that differ only in the given money parameters."""
    timing = {
        "deal_type": "saas_renewal",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    }
    session_init = make_session_init()
    session_init["session_params"] = {**timing, "subject": "Test negotiation", **proposed}
    session_ack = {
        "message_type": "session_ack",
        "message_id": str(uuid.uuid4()),
        "session_id": "sess-basis",
        "in_reply_to": session_init["message_id"],
        "protocol_version": "0.2",
        "session_params_accepted": {**timing, **accepted},
        "responder": {"did": RESPONDER_DID},
        "responder_mandate": {"mandate_type": "declared"},
        "session_created_at": NOW,
        "current_turn": "initiator",
    }
    return session_init, session_ack


def _signed_offer(session_id, rnd, sender_did, private_key, in_reply_to=None) -> dict:
    """A signed round-``rnd`` offer or counteroffer; its terms carry no basis field."""
    timestamp = "2026-03-24T10:01:00Z"
    expires_at = "2030-01-01T00:00:00Z"
    message_type = "offer" if rnd == 1 else "counteroffer"
    terms = {"total_value": 9_500_000, "currency": "USD"}
    protocol_act_hash = hash_object({
        "protocol_version": "0.2",
        "session_id": session_id,
        "round_number": rnd,
        "sequence_number": rnd,
        "message_type": message_type,
        "sender_did": sender_did,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
    })
    verification_method = (
        f"{INITIATOR_DID}#key-1" if sender_did == INITIATOR_DID else f"{RESPONDER_DID}#key-2026-01"
    )
    msg = {
        "message_type": message_type,
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "round_number": rnd,
        "sequence_number": rnd,
        "sender_did": sender_did,
        "sender_agent_id": "test-agent",
        "sender_verification_method": verification_method,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
        "protocol_act_hash": protocol_act_hash,
        "protocol_act_signature": sign_jws(protocol_act_hash, private_key, kid=verification_method),
    }
    if in_reply_to:
        msg["in_reply_to"] = in_reply_to
    return msg


# ---------------------------------------------------------------------------
# The enum: vectors, implementation, and schema agree
# ---------------------------------------------------------------------------

def test_vector_bases_match_implementation_and_schema():
    params_schema = INVITATION_SCHEMA["properties"]["proposed_session_params"]
    assert VECTORS["valid_bases"] == list(SESSION_BASES) == params_schema["properties"]["basis"]["enum"]
    assert "basis" not in params_schema["required"]


# ---------------------------------------------------------------------------
# SessionManager.create_session
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", VECTORS["ack_cases"], ids=lambda case: case["name"])
def test_session_ack_money_params_fixed_at_initiation(case):
    session_init, session_ack = _init_and_ack(case["proposed"], case["accepted"])
    manager = SessionManager()
    if case["valid"]:
        session = manager.create_session("sess-basis", session_init, session_ack, NOW)
        assert session.session_params == session_ack["session_params_accepted"]
    else:
        with pytest.raises(A2CNError) as exc_info:
            manager.create_session("sess-basis", session_init, session_ack, NOW)
        assert exc_info.value.code == case["error"]
        assert case["changed"] in exc_info.value.message
        assert manager.get_session("sess-basis") is None


@pytest.mark.parametrize("basis", VECTORS["invalid_bases"], ids=repr)
def test_unrecognized_basis_rejected_even_when_echoed(basis):
    money = {"currency": "USD", "basis": basis}
    session_init, session_ack = _init_and_ack(money, money)
    with pytest.raises(A2CNError) as exc_info:
        SessionManager().create_session("sess-basis", session_init, session_ack, NOW)
    assert exc_info.value.code == "INVALID_BASIS"


@pytest.mark.parametrize("currency", VECTORS["invalid_currencies"], ids=repr)
def test_malformed_currency_rejected_even_when_echoed(currency):
    money = {"currency": currency}
    session_init, session_ack = _init_and_ack(money, money)
    with pytest.raises(A2CNError) as exc_info:
        SessionManager().create_session("sess-basis", session_init, session_ack, NOW)
    assert exc_info.value.code == "INVALID_REQUEST"


def test_missing_currency_rejected():
    session_init, session_ack = _init_and_ack({}, {})
    with pytest.raises(A2CNError) as exc_info:
        SessionManager().create_session("sess-basis", session_init, session_ack, NOW)
    assert exc_info.value.code == "INVALID_REQUEST"
    assert "currency" in exc_info.value.message


@pytest.mark.parametrize("accepted", VECTORS["malformed_accepted"], ids=repr)
def test_create_session_rejects_malformed_session_params_accepted(accepted):
    session_init, session_ack = _init_and_ack({"currency": "USD"}, {"currency": "USD"})
    session_ack["session_params_accepted"] = accepted
    with pytest.raises(A2CNError) as exc_info:
        SessionManager().create_session("sess-basis", session_init, session_ack, NOW)
    assert exc_info.value.code == "INVALID_REQUEST"


@pytest.mark.parametrize("params", VECTORS["malformed_session_params"], ids=repr)
def test_create_session_rejects_malformed_session_params(params):
    session_init, session_ack = _init_and_ack({"currency": "USD"}, {"currency": "USD"})
    session_init["session_params"] = params
    with pytest.raises(A2CNError) as exc_info:
        SessionManager().create_session("sess-basis", session_init, session_ack, NOW)
    assert exc_info.value.code == "INVALID_REQUEST"


# ---------------------------------------------------------------------------
# POST /sessions (responder)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_basis_echoed_and_pinned_across_rounds(
    test_client, responder_test_client, initiator_keypair, responder_keypair
):
    body = make_session_init()
    body["session_params"]["basis"] = "gross"
    r = await test_client.post("/sessions", json=body, headers=_headers(body["message_id"]))
    assert r.status_code == 201
    assert r.json()["session_params_accepted"]["basis"] == "gross"
    session_id = r.json()["session_id"]

    offer = _signed_offer(session_id, 1, INITIATOR_DID, initiator_keypair[0])
    counter = _signed_offer(
        session_id, 2, RESPONDER_DID, responder_keypair[0], in_reply_to=offer["message_id"]
    )
    for client, message in ((test_client, offer), (responder_test_client, counter)):
        r = await client.post(
            f"/sessions/{session_id}/messages", json=message, headers=_headers(message["message_id"])
        )
        assert r.status_code == 200
        state = (await test_client.get(f"/sessions/{session_id}")).json()
        assert state["round_number"] == message["round_number"]
        assert state["session_params"]["basis"] == "gross"


@pytest.mark.asyncio
async def test_absent_basis_is_no_signal(test_client):
    body = make_session_init()
    assert "basis" not in body["session_params"]
    r = await test_client.post("/sessions", json=body, headers=_headers(body["message_id"]))
    assert r.status_code == 201
    assert "basis" not in r.json()["session_params_accepted"]
    state = (await test_client.get(f"/sessions/{r.json()['session_id']}")).json()
    assert "basis" not in state["session_params"]


@pytest.mark.asyncio
async def test_unrecognized_basis_rejected_at_session_init(test_client):
    body = make_session_init()
    body["session_params"]["basis"] = "vat"
    r = await test_client.post("/sessions", json=body, headers=_headers(body["message_id"]))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_BASIS"


@pytest.mark.asyncio
async def test_missing_currency_rejected_at_session_init(test_client):
    body = make_session_init()
    del body["session_params"]["currency"]
    r = await test_client.post("/sessions", json=body, headers=_headers(body["message_id"]))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


# ---------------------------------------------------------------------------
# A2CNClient.initiate_session (the initiator receives the SessionAck)
# ---------------------------------------------------------------------------

_OMITTED = object()


def _client(respond) -> A2CNClient:
    """An initiator whose responder answers every request with ``respond(request)``."""
    private_key, _ = generate_keypair()
    return A2CNClient(
        agent_info={
            "did": INITIATOR_DID,
            "verification_method": f"{INITIATOR_DID}#key-1",
            "agent_id": "test-agent",
        },
        private_key=private_key,
        mandate={"mandate_type": "declared"},
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    )


def _client_answering_with(accepted) -> A2CNClient:
    """An initiator whose responder answers any SessionInit with ``accepted`` params.

    ``_OMITTED`` leaves session_params_accepted out of the SessionAck.
    """

    def respond(request: httpx.Request) -> httpx.Response:
        ack = {
            "message_type": "session_ack",
            "message_id": str(uuid.uuid4()),
            "session_id": "sess-basis",
            "in_reply_to": json.loads(request.content)["message_id"],
            "protocol_version": "0.2",
            "responder": {"did": RESPONDER_DID},
            "responder_mandate": {"mandate_type": "declared"},
            "session_created_at": NOW,
            "current_turn": "initiator",
        }
        if accepted is not _OMITTED:
            ack["session_params_accepted"] = accepted
        return httpx.Response(201, json=ack)

    return _client(respond)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", VECTORS["ack_cases"], ids=lambda case: case["name"])
async def test_client_checks_session_ack_money_params(case):
    session_init, session_ack = _init_and_ack(case["proposed"], case["accepted"])
    client = _client_answering_with(session_ack["session_params_accepted"])
    proposed = session_init["session_params"]
    if case["valid"]:
        ack = await client.initiate_session("https://acme.example", RESPONDER_DID, proposed)
        assert ack["session_params_accepted"] == session_ack["session_params_accepted"]
        assert "sess-basis" in client._sessions
    else:
        with pytest.raises(A2CNError) as exc_info:
            await client.initiate_session("https://acme.example", RESPONDER_DID, proposed)
        assert exc_info.value.code == case["error"]
        assert case["changed"] in exc_info.value.message
        assert client._sessions == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "accepted",
    [*VECTORS["malformed_accepted"], _OMITTED],
    ids=lambda accepted: "omitted" if accepted is _OMITTED else repr(accepted),
)
async def test_client_rejects_malformed_session_params_accepted(accepted):
    client = _client_answering_with(accepted)
    params = make_session_init()["session_params"] | {"basis": "gross"}
    with pytest.raises(A2CNError) as exc_info:
        await client.initiate_session("https://acme.example", RESPONDER_DID, params)
    assert exc_info.value.code == "INVALID_REQUEST"
    assert client._sessions == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("body", VECTORS["malformed_ack_bodies"], ids=repr)
async def test_client_rejects_malformed_ack_body(body):
    client = _client(lambda request: httpx.Response(201, content=json.dumps(body).encode()))
    params = make_session_init()["session_params"] | {"basis": "gross"}
    with pytest.raises(A2CNError) as exc_info:
        await client.initiate_session("https://acme.example", RESPONDER_DID, params)
    assert exc_info.value.code == "INVALID_REQUEST"
    assert client._sessions == {}


# ---------------------------------------------------------------------------
# SessionParams and the SessionInvitation schema
# ---------------------------------------------------------------------------

def test_session_params_carry_basis_only_when_set():
    fields = {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "subject": "Test",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    }
    assert SessionParams(**fields, basis="gross").to_dict()["basis"] == "gross"
    assert "basis" not in SessionParams(**fields).to_dict()


def _invitation(proposed_session_params: dict) -> dict:
    return {
        "message_type": "session_invitation",
        "invitation_id": "11111111-2222-3333-4444-555555555555",
        "a2cn_version": "0.2",
        "inviter_did": INITIATOR_DID,
        "inviter_endpoint": "https://techcorp.example/api/a2cn",
        "inviter_discovery_url": "https://techcorp.example/.well-known/a2cn-agent",
        "proposed_deal_type": "saas_renewal",
        "proposed_session_params": proposed_session_params,
        "proposed_terms_summary": {},
        "inviter_mandate_summary": {},
        "invitation_expires_at": "2030-01-01T00:00:00Z",
        "accept_endpoint": "https://techcorp.example/accept",
        "decline_endpoint": "https://techcorp.example/decline",
        "inviter_verification_method": f"{INITIATOR_DID}#key-1",
        "invitation_signature": "signature",
    }


def test_invitation_schema_accepts_only_enumerated_bases():
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(INVITATION_SCHEMA)
    params = {
        "currency": "USD",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    }
    assert list(validator.iter_errors(_invitation(params))) == []
    for basis in VECTORS["valid_bases"]:
        assert list(validator.iter_errors(_invitation(params | {"basis": basis}))) == []
    for basis in VECTORS["invalid_bases"]:
        errors = validator.iter_errors(_invitation(params | {"basis": basis}))
        assert any(
            list(error.absolute_path) == ["proposed_session_params", "basis"] for error in errors
        ), basis
