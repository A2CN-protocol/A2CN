"""The wire version a session is negotiated at (Section 12.1.7).

A SessionInit proposes a version and the SessionAck that answers it must state
the same one; the session runs at it. Before this, the session manager took the
ack's version when it had one and the init's otherwise, and accepted any string,
so an ack of "9.9" produced a session that signed and verified under "9.9". The
initiator's client did not look at the ack's version at all, and signed its
offers under whatever the responder stated. Both now refuse any pair that does
not agree on a version this implementation recognises, and fill nothing in.

session-version-negotiation.json pins the cases. The TypeScript suite runs them
too.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from a2cn.client import A2CNClient
from a2cn.crypto import generate_keypair
from a2cn.messages import PROTOCOL_ACT_VERSION, SUPPORTED_WIRE_VERSIONS
from a2cn.session import A2CNError, SessionManager

VECTOR = json.loads(
    (
        Path(__file__).parents[3] / "spec" / "test-vectors" / "session-version-negotiation.json"
    ).read_text()
)
CASES = VECTOR["cases"]
CLIENT_CASES = [c for c in CASES if c.get("init_protocol_version") == PROTOCOL_ACT_VERSION]

INITIATOR_DID = "did:web:techcorp.example"
RESPONDER_DID = "did:web:acme-corp.com"
PARAMS = {
    "deal_type": "saas_renewal",
    "currency": "USD",
    "subject": "Test",
    "max_rounds": 4,
    "session_timeout_seconds": 3600,
    "round_timeout_seconds": 900,
}


def _with_version(message: dict, case: dict, key: str) -> dict:
    message = dict(message)
    if key in case:
        message["protocol_version"] = case[key]
    return message


def _init(case: dict) -> dict:
    return _with_version(
        {
            "message_type": "session_init",
            "message_id": "neg-init-1",
            "session_params": PARAMS,
            "initiator": {"did": INITIATOR_DID},
            "initiator_mandate": {"mandate_type": "declared"},
        },
        case,
        "init_protocol_version",
    )


def _ack(case: dict, in_reply_to: str = "neg-init-1") -> dict:
    return _with_version(
        {
            "message_type": "session_ack",
            "message_id": "neg-ack-1",
            "session_id": "sess-neg",
            "in_reply_to": in_reply_to,
            "session_params_accepted": PARAMS,
            "responder": {"did": RESPONDER_DID},
            "responder_mandate": {"mandate_type": "declared"},
            "session_created_at": "2026-03-24T10:00:00Z",
            "current_turn": "initiator",
        },
        case,
        "ack_protocol_version",
    )


def test_the_vector_names_the_versions_this_implementation_recognises():
    assert list(SUPPORTED_WIRE_VERSIONS) == VECTOR["supported_wire_versions"]
    assert {c["accepted"] for c in CASES} == {True, False}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_the_session_manager_negotiates_one_version(case):
    manager = SessionManager()
    init, ack = _init(case), _ack(case)

    if case["accepted"]:
        session = manager.create_session("sess-neg", init, ack, "2026-03-24T10:00:00Z")
        assert session.protocol_version == case["runs_at"]
        assert session.to_state_dict()["protocol_version"] == case["runs_at"]
        return

    with pytest.raises(A2CNError) as excinfo:
        manager.create_session("sess-neg", init, ack, "2026-03-24T10:00:00Z")
    assert (excinfo.value.code, excinfo.value.message) == (
        case["error_code"],
        case["error_message"],
    )
    assert manager.get_session("sess-neg") is None


def _client_answering(case: dict, posted: list) -> A2CNClient:
    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        posted.append(body)
        if request.url.path.endswith("/messages"):
            return httpx.Response(200, json={"state": "NEGOTIATING"})
        return httpx.Response(201, json=_ack(case, in_reply_to=body["message_id"]))

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


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CLIENT_CASES, ids=lambda case: case["name"])
async def test_the_client_refuses_an_ack_that_changes_its_version(case):
    posted: list = []
    client = _client_answering(case, posted)

    if case["accepted"]:
        ack = await client.initiate_session("https://acme.example", RESPONDER_DID, PARAMS)
        assert ack["protocol_version"] == case["runs_at"]
        assert "sess-neg" in client._sessions
        return

    with pytest.raises(A2CNError) as excinfo:
        await client.initiate_session("https://acme.example", RESPONDER_DID, PARAMS)
    assert (excinfo.value.code, excinfo.value.message) == (
        case["error_code"],
        case["error_message"],
    )
    # Refused before anything is stored or signed: only the SessionInit went out.
    assert client._sessions == {}
    assert [m["message_type"] for m in posted] == ["session_init"]
    assert posted[0]["protocol_version"] == PROTOCOL_ACT_VERSION


def test_the_client_cases_cover_both_verdicts():
    assert {c["accepted"] for c in CLIENT_CASES} == {True, False}
