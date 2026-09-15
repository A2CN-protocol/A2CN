"""Tests for session_params.basis: carried, enum-checked, fixed at initiation, and
restated in every offer's terms.basis.

Verdicts come from spec/test-vectors/session-params-basis.json, which the
TypeScript suite asserts too. basis is a label: nothing here converts net and
gross, and an absent basis stays absent (no default).
"""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path

import httpx
import pytest

from a2cn.client import A2CNClient
from a2cn.crypto import generate_keypair, hash_object, public_key_to_jwk, sign_jws
from a2cn.messages import SessionParams, TermsObject
from a2cn.session import SESSION_BASES, A2CNError, SessionManager, SessionState
from tests.conftest import INITIATOR_DID, RESPONDER_DID, make_did_document, make_session_init

REPO_ROOT = Path(__file__).parents[3]
VECTORS = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "session-params-basis.json").read_text()
)
INVITATION_SCHEMA = json.loads(
    (REPO_ROOT / "spec" / "schemas" / "session-invitation.schema.json").read_text()
)
MONEY_PARAM_FIXTURES = {
    name: json.loads((REPO_ROOT / "spec" / "conformance-fixtures" / f"{name}.json").read_text())
    for name in ("offer_basis_diverges_from_session", "offer_currency_diverges_from_session")
}
NOW = "2026-03-24T10:00:00Z"

INITIATOR_KEY, INITIATOR_PUBLIC_KEY = generate_keypair()
RESPONDER_KEY, RESPONDER_PUBLIC_KEY = generate_keypair()
DID_DOCUMENTS = {
    INITIATOR_DID: make_did_document(
        INITIATOR_DID, "key-1", public_key_to_jwk(INITIATOR_PUBLIC_KEY)
    ),
    RESPONDER_DID: make_did_document(
        RESPONDER_DID, "key-2026-01", public_key_to_jwk(RESPONDER_PUBLIC_KEY)
    ),
}


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


def _terms(basis) -> dict:
    return {"total_value": 9_500_000, "currency": "USD", "basis": basis}


def _signed_offer(session_id, rnd, sender_did, private_key, *, terms, in_reply_to=None) -> dict:
    """A signed round-``rnd`` offer or counteroffer carrying ``terms`` verbatim."""
    timestamp = "2026-03-24T10:01:00Z"
    expires_at = "2030-01-01T00:00:00Z"
    message_type = "offer" if rnd == 1 else "counteroffer"
    terms = copy.deepcopy(terms)
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
# SessionAck money parameters are validated before they are compared (Section 6.4.1)
# ---------------------------------------------------------------------------

_ABSENT = object()


def _malformed_accepted_money_cases() -> list:
    """Every invalid basis and malformed currency as a SessionAck's session_params_accepted.

    Each case has the shape of an ack_cases entry. A receiver validates
    session_params_accepted before comparing it with session_params, so each is
    refused with its own error code, naming the accepted parameter, whatever the
    SessionInit proposed; never with SESSION_PARAM_CHANGED.
    """
    cases = []
    for proposed_basis in [*VECTORS["valid_bases"], _ABSENT]:
        proposed = {"currency": "USD"}
        if proposed_basis is not _ABSENT:
            proposed["basis"] = proposed_basis
        label = "no-basis" if proposed_basis is _ABSENT else proposed_basis
        for basis in VECTORS["invalid_bases"]:
            cases.append(pytest.param(
                {
                    "proposed": proposed,
                    "accepted": {"currency": "USD", "basis": basis},
                    "error": "INVALID_BASIS",
                    "changed": "session_params_accepted.basis",
                },
                id=f"basis-{basis!r}-proposed-{label}",
            ))
    for currency in [*VECTORS["invalid_currencies"], _ABSENT]:
        cases.append(pytest.param(
            {
                "proposed": {"currency": "USD"},
                "accepted": {} if currency is _ABSENT else {"currency": currency},
                "error": "INVALID_REQUEST",
                "changed": "session_params_accepted.currency",
            },
            id="currency-absent" if currency is _ABSENT else f"currency-{currency!r}",
        ))
    return cases


MALFORMED_ACCEPTED_MONEY = _malformed_accepted_money_cases()


@pytest.mark.parametrize("case", MALFORMED_ACCEPTED_MONEY)
def test_session_ack_money_params_validated_before_comparison(case):
    session_init, session_ack = _init_and_ack(case["proposed"], case["accepted"])
    manager = SessionManager()
    with pytest.raises(A2CNError) as exc_info:
        manager.create_session("sess-basis", session_init, session_ack, NOW)
    assert exc_info.value.code == case["error"]
    assert case["changed"] in exc_info.value.message
    assert manager.get_session("sess-basis") is None


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

    # Each offer restates the session basis in its signed terms (Section 7.2).
    offer = _signed_offer(
        session_id, 1, INITIATOR_DID, initiator_keypair[0], terms=_terms("gross")
    )
    counter = _signed_offer(
        session_id,
        2,
        RESPONDER_DID,
        responder_keypair[0],
        terms=_terms("gross"),
        in_reply_to=offer["message_id"],
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
# Offers restate the session basis in terms.basis (Section 7.2)
# ---------------------------------------------------------------------------

def _open_session(proposed: dict, accepted: dict):
    """A live session whose SessionInit and SessionAck carry the given money parameters.

    The initiator's mandate caps commitments in the session currency, so a
    conformant offer also passes the mandate check.
    """
    session_init, session_ack = _init_and_ack(proposed, accepted)
    session_init["initiator_mandate"]["max_commitment_currency"] = proposed["currency"]
    manager = SessionManager()
    for did, did_document in DID_DOCUMENTS.items():
        manager.register_did_document(did, did_document)
    session = manager.create_session("sess-basis", session_init, session_ack, NOW)
    session.session_timeout_seconds = 86400 * 365 * 100  # NOW is in the past
    return manager, session


def _assert_offer_left_no_trace(session, offer: dict) -> None:
    """A rejected offer is refused before any session state changes."""
    assert session.state == SessionState.ACTIVE
    assert (session.round_number, session.sequence_number) == (0, 0)
    assert session.current_turn == "initiator"
    assert session.latest_offer_id is None
    assert session._message_log == []
    assert session._offer_chain == []
    assert offer["message_id"] not in session._processed_messages


@pytest.mark.parametrize("case", VECTORS["offer_cases"], ids=lambda case: case["name"])
def test_offer_terms_basis_held_to_the_session_basis(case):
    manager, session = _open_session(case["proposed"], case["accepted"])
    offer = _signed_offer("sess-basis", 1, INITIATOR_DID, INITIATOR_KEY, terms=case["terms"])
    if case["valid"]:
        state = manager.process_message(session, offer)
        assert (state["state"], state["round_number"]) == (SessionState.NEGOTIATING, 1)
    else:
        with pytest.raises(A2CNError) as exc_info:
            manager.process_message(session, offer)
        assert exc_info.value.code == case["error"]
        assert exc_info.value.http_status == 400
        assert case["changed"] in exc_info.value.message
        _assert_offer_left_no_trace(session, offer)


@pytest.mark.parametrize(
    "session_basis", [*VECTORS["valid_bases"], None], ids=lambda basis: basis or "no-basis"
)
@pytest.mark.parametrize("basis", VECTORS["invalid_bases"], ids=repr)
def test_unrecognized_terms_basis_rejected(basis, session_basis):
    money = {"currency": "USD"}
    if session_basis is not None:
        money["basis"] = session_basis
    manager, session = _open_session(money, money)
    offer = _signed_offer("sess-basis", 1, INITIATOR_DID, INITIATOR_KEY, terms=_terms(basis))
    with pytest.raises(A2CNError) as exc_info:
        manager.process_message(session, offer)
    assert exc_info.value.code == "INVALID_BASIS"
    assert "basis" in exc_info.value.message
    _assert_offer_left_no_trace(session, offer)


def test_counteroffer_cannot_change_the_basis():
    money = {"currency": "USD", "basis": "gross"}
    manager, session = _open_session(money, money)
    offer = _signed_offer("sess-basis", 1, INITIATOR_DID, INITIATOR_KEY, terms=_terms("gross"))
    manager.process_message(session, offer)

    net = _signed_offer(
        "sess-basis", 2, RESPONDER_DID, RESPONDER_KEY,
        terms=_terms("net"), in_reply_to=offer["message_id"],
    )
    with pytest.raises(A2CNError) as exc_info:
        manager.process_message(session, net)
    assert exc_info.value.code == "SESSION_PARAM_CHANGED"
    assert "basis" in exc_info.value.message
    assert (session.round_number, session.sequence_number, session.current_turn) == (
        1, 1, "responder",
    )
    assert session._offer_chain == [offer["protocol_act_hash"]]

    gross = _signed_offer(
        "sess-basis", 2, RESPONDER_DID, RESPONDER_KEY,
        terms=_terms("gross"), in_reply_to=offer["message_id"],
    )
    assert manager.process_message(session, gross)["round_number"] == 2


def test_session_money_params_are_checked_before_the_mandate():
    """A currency the session did not fix is SESSION_PARAM_CHANGED, whatever the mandate says."""
    manager, session = _open_session({"currency": "EUR"}, {"currency": "EUR"})
    assert session.initiator_mandate["max_commitment_currency"] == "EUR"
    # Both a mandate-currency mismatch and over the mandate cap: the session check wins.
    offer = _signed_offer(
        "sess-basis", 1, INITIATOR_DID, INITIATOR_KEY,
        terms={"total_value": 99_000_000, "currency": "USD"},
    )
    with pytest.raises(A2CNError) as exc_info:
        manager.process_message(session, offer)
    assert exc_info.value.code == "SESSION_PARAM_CHANGED"
    assert "currency" in exc_info.value.message
    _assert_offer_left_no_trace(session, offer)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    # The reference responder echoes basis unchanged, so over HTTP accepted == proposed.
    [case for case in VECTORS["offer_cases"] if case["accepted"] == case["proposed"]],
    ids=lambda case: case["name"],
)
async def test_offer_terms_basis_held_over_http(case, test_client, initiator_keypair):
    body = make_session_init()
    body["session_params"] = {**body["session_params"], **case["proposed"]}
    body["initiator_mandate"]["max_commitment_currency"] = case["proposed"]["currency"]
    r = await test_client.post("/sessions", json=body, headers=_headers(body["message_id"]))
    assert r.status_code == 201
    session_id = r.json()["session_id"]

    offer = _signed_offer(session_id, 1, INITIATOR_DID, initiator_keypair[0], terms=case["terms"])
    r = await test_client.post(
        f"/sessions/{session_id}/messages", json=offer, headers=_headers(offer["message_id"])
    )
    state = (await test_client.get(f"/sessions/{session_id}")).json()
    if case["valid"]:
        assert r.status_code == 200
        assert (state["state"], state["round_number"]) == (SessionState.NEGOTIATING, 1)
    else:
        assert r.status_code == 400
        error = r.json()["error"]
        assert error["code"] == case["error"]
        assert case["changed"] in error["message"]
        assert (state["state"], state["round_number"], state["sequence_number"]) == (
            SessionState.ACTIVE, 0, 0,
        )


@pytest.mark.parametrize("name", sorted(MONEY_PARAM_FIXTURES))
def test_offer_money_param_conformance_fixture(name):
    given, expect = MONEY_PARAM_FIXTURES[name]["given"], MONEY_PARAM_FIXTURES[name]["expect"]
    manager, session = _open_session(given["session_params"], given["session_params"])
    assert session.state == given["session_state"]
    offer = _signed_offer(
        "sess-basis", 1, INITIATOR_DID, INITIATOR_KEY, terms=given["offer"]["terms"]
    )
    assert offer["message_type"] == given["offer"]["message_type"]
    assert expect["accepted"] is False
    with pytest.raises(A2CNError) as exc_info:
        manager.process_message(session, offer)
    assert exc_info.value.code == expect["error_code"]
    _assert_offer_left_no_trace(session, offer)


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


def _client_answering_with(accepted, posted: list | None = None) -> A2CNClient:
    """An initiator whose responder answers any SessionInit with ``accepted`` params.

    ``_OMITTED`` leaves session_params_accepted out of the SessionAck. Each
    message posted to the session is appended to ``posted`` and answered 200.
    """

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/messages"):
            posted.append(json.loads(request.content))
            return httpx.Response(200, json={"state": SessionState.NEGOTIATING})
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
@pytest.mark.parametrize("case", MALFORMED_ACCEPTED_MONEY)
async def test_client_validates_session_ack_money_params_before_comparison(case):
    session_init, session_ack = _init_and_ack(case["proposed"], case["accepted"])
    client = _client_answering_with(session_ack["session_params_accepted"])
    with pytest.raises(A2CNError) as exc_info:
        await client.initiate_session(
            "https://acme.example", RESPONDER_DID, session_init["session_params"]
        )
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
# A2CNClient: the offers it sends and the counteroffers it receives (Section 7.2)
# ---------------------------------------------------------------------------

async def _opened_client(case: dict, posted: list) -> A2CNClient:
    """An initiator holding session sess-basis, opened from the case's money parameters."""
    session_init, session_ack = _init_and_ack(case["proposed"], case["accepted"])
    client = _client_answering_with(session_ack["session_params_accepted"], posted)
    await client.initiate_session(
        "https://acme.example", RESPONDER_DID, session_init["session_params"]
    )
    return client


def _conformant_terms(accepted: dict) -> dict:
    """Terms restating the session currency and, when the session fixed one, its basis."""
    basis = {"basis": accepted["basis"]} if "basis" in accepted else {}
    return {"total_value": 9_500_000, "currency": accepted["currency"], **basis}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", VECTORS["offer_cases"], ids=lambda case: case["name"])
async def test_client_checks_received_offer_money_params(case):
    """The initiator receives counteroffers, so it applies the Section 7.2 receiver rules."""
    client = await _opened_client(case, posted=[])
    state = client._sessions["sess-basis"]
    before = copy.deepcopy(state)
    counteroffer = _signed_offer("sess-basis", 2, RESPONDER_DID, RESPONDER_KEY, terms=case["terms"])
    if case["valid"]:
        client.process_incoming("sess-basis", counteroffer)
        assert state["latest_offer"] == counteroffer
        assert state["offer_chain"] == [counteroffer["protocol_act_hash"]]
    else:
        with pytest.raises(A2CNError) as exc_info:
            client.process_incoming("sess-basis", counteroffer)
        assert exc_info.value.code == case["error"]
        assert case["changed"] in exc_info.value.message
        assert state == before


@pytest.mark.asyncio
@pytest.mark.parametrize("case", VECTORS["offer_cases"], ids=lambda case: case["name"])
async def test_client_checks_offer_money_params_before_sending(case):
    """A refused offer is never posted and leaves the round and sequence where they were."""
    posted: list = []
    client = await _opened_client(case, posted)
    state = client._sessions["sess-basis"]
    send = lambda terms: client.send_offer(  # noqa: E731
        "https://acme.example", RESPONDER_DID, "sess-basis", terms
    )
    if case["valid"]:
        await send(case["terms"])
    else:
        with pytest.raises(A2CNError) as exc_info:
            await send(case["terms"])
        assert exc_info.value.code == case["error"]
        assert case["changed"] in exc_info.value.message
        assert posted == []
        assert (state["round_number"], state["sequence_number"]) == (0, 0)
        await send(_conformant_terms(case["accepted"]))
    assert [(offer["round_number"], offer["sequence_number"]) for offer in posted] == [(1, 1)]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", VECTORS["offer_cases"], ids=lambda case: case["name"])
async def test_client_checks_offer_money_params_before_accepting(case):
    """The client signs only terms the session allows, whatever reached it unchecked."""
    posted: list = []
    client = await _opened_client(case, posted)
    state = client._sessions["sess-basis"]
    before = copy.deepcopy(state)
    offer = _signed_offer("sess-basis", 2, RESPONDER_DID, RESPONDER_KEY, terms=case["terms"])
    accept = lambda: client.send_acceptance(  # noqa: E731
        "https://acme.example", RESPONDER_DID, "sess-basis", offer
    )
    if case["valid"]:
        await accept()
        assert [message["accepted_offer_id"] for message in posted] == [offer["message_id"]]
        assert state["sequence_number"] == before["sequence_number"] + 1
    else:
        with pytest.raises(A2CNError) as exc_info:
            await accept()
        assert exc_info.value.code == case["error"]
        assert case["changed"] in exc_info.value.message
        assert posted == []
        assert state == before


@pytest.mark.asyncio
async def test_client_refuses_to_accept_a_mislabelled_offer_it_recorded():
    """A message_type other than offer or counteroffer skips the receive check, not this one."""
    posted: list = []
    usd = {"currency": "USD"}
    client = await _opened_client({"proposed": usd, "accepted": usd}, posted)
    state = client._sessions["sess-basis"]
    mislabelled = _signed_offer(
        "sess-basis", 2, RESPONDER_DID, RESPONDER_KEY,
        terms={"total_value": 9_500_000, "currency": "EUR"},
    )
    mislabelled["message_type"] = "Counteroffer"
    client.process_incoming("sess-basis", mislabelled)
    sequence_number = state["sequence_number"]

    with pytest.raises(A2CNError) as exc_info:
        await client.send_acceptance(
            "https://acme.example", RESPONDER_DID, "sess-basis", mislabelled
        )
    assert exc_info.value.code == "SESSION_PARAM_CHANGED"
    assert "currency" in exc_info.value.message
    assert posted == []
    assert state["sequence_number"] == sequence_number


# ---------------------------------------------------------------------------
# SessionParams, TermsObject, and the SessionInvitation schema
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


def test_terms_object_carries_basis_only_when_set():
    assert TermsObject(total_value=9_500_000, currency="USD", basis="gross").to_dict() == {
        "total_value": 9_500_000,
        "currency": "USD",
        "basis": "gross",
    }
    assert "basis" not in TermsObject(total_value=9_500_000, currency="USD").to_dict()


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
