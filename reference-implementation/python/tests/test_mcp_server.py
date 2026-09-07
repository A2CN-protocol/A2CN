"""Tests for mcp_server — six A2CN MCP tools.

Uses respx to mock all outgoing HTTP calls so no real server is needed.
The mcp_server module is imported once per session; _sessions is cleared
between each test via the autouse clear_sessions fixture.
"""

from __future__ import annotations

import sys
import os
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import respx

pytest.importorskip("mcp")

# mcp_server lives at reference-implementation/python/mcp_server.py (one level up)
_REPO_PY = Path(__file__).parent.parent
if str(_REPO_PY) not in sys.path:
    sys.path.insert(0, str(_REPO_PY))

import mcp_server
from a2cn.client import A2CNClient
from a2cn.crypto import generate_keypair

# ---------------------------------------------------------------------------
# Constants shared across tests
# ---------------------------------------------------------------------------

COUNTERPARTY_DID = "did:web:acme-corp.com"
BASE_URL = "https://acme-corp.com"
SESSION_ID = "test-session-00000000-0000-0000-0000"

DISCOVERY_DOC = {
    "a2cn_version": "0.2",
    "agent_did": COUNTERPARTY_DID,
    "conformance_level": 2,
    "deal_types": ["saas_renewal"],
    "mandate_methods": ["declared"],
    "endpoint": BASE_URL,
    "agent_id": "sales-agent-acme-007",
    "verification_method": f"{COUNTERPARTY_DID}#key-1",
}

SESSION_ACK = {
    "message_type": "session_ack",
    "message_id": str(uuid.uuid4()),
    "session_id": SESSION_ID,
    "in_reply_to": "init-001",
    "protocol_version": "0.2",
    "session_params_accepted": {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "max_rounds": 6,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    },
    "responder": {
        "organization_name": "Acme Corp",
        "did": COUNTERPARTY_DID,
        "verification_method": f"{COUNTERPARTY_DID}#key-1",
        "agent_id": "sales-agent-acme-007",
        "endpoint": BASE_URL,
    },
    "responder_mandate": {"mandate_type": "declared"},
    "session_created_at": "2026-04-01T10:00:00Z",
    "current_turn": "initiator",
}

SAMPLE_CP_OFFER = {
    "message_id": "seller-offer-001",
    "message_type": "counteroffer",
    "session_id": SESSION_ID,
    "sequence_number": 2,
    "round_number": 2,
    "sender_did": COUNTERPARTY_DID,
    "terms": {
        "total_value": 11_500_000,
        "currency": "USD",
        "payment_terms": {"net_days": 30},
    },
    "protocol_act_hash": "def456abc",
    "protocol_act_signature": "eyJ...",
    "timestamp": "2026-04-01T10:01:00Z",
    "expires_at": "2030-01-01T00:00:00Z",
}

TRANSACTION_RECORD = {
    "record_id": "rec-" + SESSION_ID,
    "session_id": SESSION_ID,
    "record_hash": "sha256-" + "a" * 40,
    "generated_at": "2026-04-01T10:03:00Z",
    "outcome": "COMPLETED",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_sessions():
    """Reset MCP in-memory session store before and after each test."""
    mcp_server._sessions.clear()
    yield
    mcp_server._sessions.clear()


def _seed_session(
    session_id: str = SESSION_ID,
    status: str = "NEGOTIATING",
    cp_offer: dict | None = None,
) -> dict:
    """
    Inject a fake session into mcp_server._sessions.

    Used by tests that need an active session without going through
    a2cn_initiate_session (which requires a real server or full HTTP mocking).
    """
    http_client = httpx.AsyncClient()

    client = A2CNClient(
        agent_info={
            "organization_name": "Test Buyer",
            "did": mcp_server._agent_did,
            "verification_method": f"{mcp_server._agent_did}#key-1",
            "agent_id": "test-buyer",
            "endpoint": "https://test-buyer.example",
        },
        private_key=mcp_server._private_key,
        mandate={"mandate_type": "declared"},
        http_client=http_client,
    )
    # Bootstrap the client's internal session state
    client._sessions[session_id] = {
        "session_init": {},
        "session_ack": SESSION_ACK,
        "sequence_number": 1,
        "round_number": 1,
        "latest_offer": {
            "message_id": "offer-001",
            "message_type": "offer",
            "terms": {
                "total_value": 9_500_000,
                "currency": "USD",
                "payment_terms": {"net_days": 30},
            },
            "protocol_act_hash": "abc123",
        },
        "offer_chain": ["abc123"],
        "message_log": [],
        "current_turn": "responder",
    }

    entry = {
        "client": client,
        "http_client": http_client,
        "endpoint": BASE_URL,
        "counterparty_did": COUNTERPARTY_DID,
        "deal_type": "saas_renewal",
        "session_ack": SESSION_ACK,
        "my_did": mcp_server._agent_did,
        "my_last_offer_cents": 9_500_000,
        "my_last_offer_net_days": 30,
        "counterparty_last_offer_cents": (
            cp_offer["terms"]["total_value"] if cp_offer else None
        ),
        "counterparty_last_offer_net_days": (
            cp_offer["terms"].get("payment_terms", {}).get("net_days")
            if cp_offer
            else None
        ),
        "counterparty_last_offer_message": cp_offer,
        "round_number": 1,
        "status": status,
        "transaction_record": None,
    }
    mcp_server._sessions[session_id] = entry
    return entry


# ---------------------------------------------------------------------------
# Tool 1: a2cn_discover
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_discover_a2cn_capable():
    """Valid A2CN endpoint returns capability document."""
    with respx.mock:
        respx.get(f"{BASE_URL}/.well-known/a2cn-agent").mock(
            return_value=httpx.Response(200, json=DISCOVERY_DOC)
        )
        result = await mcp_server.a2cn_discover(COUNTERPARTY_DID)

    assert result["a2cn_capable"] is True
    assert result["a2cn_version"] == "0.2"
    assert result["conformance_level"] == 2
    assert "saas_renewal" in result["deal_types"]
    assert result["agent_did"] == COUNTERPARTY_DID


@pytest.mark.asyncio
async def test_discover_not_a2cn_capable_404():
    """404 on discovery endpoint → not_a2cn_capable error."""
    with respx.mock:
        respx.get(f"{BASE_URL}/.well-known/a2cn-agent").mock(
            return_value=httpx.Response(404)
        )
        result = await mcp_server.a2cn_discover(COUNTERPARTY_DID)

    assert result.get("error") == "not_a2cn_capable"


@pytest.mark.asyncio
async def test_discover_unreachable_endpoint():
    """Network error → discovery_failed error."""
    with respx.mock:
        respx.get(f"{BASE_URL}/.well-known/a2cn-agent").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        result = await mcp_server.a2cn_discover(COUNTERPARTY_DID)

    assert "error" in result
    assert result["error"] in ("discovery_failed", "not_a2cn_capable")


@pytest.mark.asyncio
async def test_discover_invalid_did():
    """Non-DID-web identifier → invalid_did error, no HTTP call."""
    result = await mcp_server.a2cn_discover("mailto:agent@example.com")
    assert result["error"] == "invalid_did"


# ---------------------------------------------------------------------------
# Tool 2: a2cn_initiate_session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_initiate_session_success():
    """
    Full happy path: discovery → POST /sessions → POST /sessions/{id}/messages.
    Session is stored in mcp_server._sessions on success.
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE_URL}/.well-known/a2cn-agent").mock(
            return_value=httpx.Response(200, json=DISCOVERY_DOC)
        )
        mock.post(f"{BASE_URL}/sessions").mock(
            return_value=httpx.Response(201, json=SESSION_ACK,
                                        headers={"Content-Type": "application/a2cn+json"})
        )
        # Opening offer POST
        mock.post(url__regex=rf"{BASE_URL}/sessions/.+/messages").mock(
            return_value=httpx.Response(200, json={"status": "received"},
                                        headers={"Content-Type": "application/a2cn+json"})
        )

        result = await mcp_server.a2cn_initiate_session(
            counterparty_did=COUNTERPARTY_DID,
            deal_type="saas_renewal",
            my_did=mcp_server._agent_did,
            initial_offer_total_value_cents=9_500_000,
            currency="USD",
            max_rounds=6,
            payment_terms_net_days=30,
            subject="Test negotiation",
        )

    assert "error" not in result
    assert result["status"] == "ACTIVE"
    sid = result["session_id"]
    assert sid in mcp_server._sessions
    entry = mcp_server._sessions[sid]
    assert entry["status"] == "NEGOTIATING"
    assert entry["my_last_offer_cents"] == 9_500_000
    assert entry["deal_type"] == "saas_renewal"


@pytest.mark.asyncio
async def test_initiate_session_invalid_deal_type():
    """Unsupported deal_type → error without any HTTP call."""
    result = await mcp_server.a2cn_initiate_session(
        counterparty_did=COUNTERPARTY_DID,
        deal_type="freight_rate",
        my_did=mcp_server._agent_did,
        initial_offer_total_value_cents=9_500_000,
        currency="USD",
        max_rounds=6,
        payment_terms_net_days=30,
        subject="Invalid deal type test",
    )
    assert result["error"] == "invalid_deal_type"
    assert len(mcp_server._sessions) == 0


@pytest.mark.asyncio
async def test_initiate_session_invalid_max_rounds():
    """max_rounds outside 1-20 → error."""
    result = await mcp_server.a2cn_initiate_session(
        counterparty_did=COUNTERPARTY_DID,
        deal_type="saas_renewal",
        my_did=mcp_server._agent_did,
        initial_offer_total_value_cents=9_500_000,
        currency="USD",
        max_rounds=25,
        payment_terms_net_days=30,
        subject="Max rounds test",
    )
    assert result["error"] == "invalid_max_rounds"


@pytest.mark.asyncio
async def test_initiate_session_server_error():
    """Server returns 403 → session_init_failed, no session stored."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE_URL}/.well-known/a2cn-agent").mock(
            return_value=httpx.Response(200, json=DISCOVERY_DOC)
        )
        mock.post(f"{BASE_URL}/sessions").mock(
            return_value=httpx.Response(
                403,
                json={"error": {"code": "DEAL_TYPE_NOT_SUPPORTED"}},
                headers={"Content-Type": "application/a2cn+json"},
            )
        )

        result = await mcp_server.a2cn_initiate_session(
            counterparty_did=COUNTERPARTY_DID,
            deal_type="saas_renewal",
            my_did=mcp_server._agent_did,
            initial_offer_total_value_cents=9_500_000,
            currency="USD",
            max_rounds=6,
            payment_terms_net_days=30,
            subject="Server error test",
        )

    assert result["error"] == "session_init_failed"
    assert len(mcp_server._sessions) == 0


# ---------------------------------------------------------------------------
# Tool 3: a2cn_send_offer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_offer_success():
    """Active session + mocked server → offer sent, round_number incremented."""
    _seed_session()

    with respx.mock:
        respx.post(url__regex=rf"{BASE_URL}/sessions/.+/messages").mock(
            return_value=httpx.Response(200, json={"status": "received"},
                                        headers={"Content-Type": "application/a2cn+json"})
        )
        result = await mcp_server.a2cn_send_offer(
            session_id=SESSION_ID,
            total_value_cents=9_800_000,
            payment_terms_net_days=30,
        )

    assert "error" not in result
    assert result["status"] == "offer_sent"
    assert result["your_offer_cents"] == 9_800_000
    entry = mcp_server._sessions[SESSION_ID]
    assert entry["my_last_offer_cents"] == 9_800_000


@pytest.mark.asyncio
async def test_send_offer_session_not_found():
    """Unknown session_id → session_not_found error."""
    result = await mcp_server.a2cn_send_offer(
        session_id="nonexistent-id",
        total_value_cents=9_800_000,
        payment_terms_net_days=30,
    )
    assert result["error"] == "session_not_found"


@pytest.mark.asyncio
async def test_send_offer_terminal_session():
    """Terminal session → session_already_terminal error."""
    _seed_session(status="COMPLETED")

    result = await mcp_server.a2cn_send_offer(
        session_id=SESSION_ID,
        total_value_cents=9_800_000,
        payment_terms_net_days=30,
    )
    assert result["error"] == "session_already_terminal"
    assert result["status"] == "COMPLETED"


# ---------------------------------------------------------------------------
# Tool 4: a2cn_accept
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_accept_success():
    """Session with counterparty offer → acceptance sent, status COMPLETED."""
    _seed_session(cp_offer=SAMPLE_CP_OFFER)

    with respx.mock(assert_all_called=False) as mock:
        mock.post(url__regex=rf"{BASE_URL}/sessions/.+/messages").mock(
            return_value=httpx.Response(200, json={"status": "accepted"},
                                        headers={"Content-Type": "application/a2cn+json"})
        )
        mock.get(url__regex=rf"{BASE_URL}/sessions/.+/record").mock(
            return_value=httpx.Response(200, json=TRANSACTION_RECORD,
                                        headers={"Content-Type": "application/a2cn+json"})
        )
        result = await mcp_server.a2cn_accept(SESSION_ID)

    assert "error" not in result
    assert result["status"] == "COMPLETED"
    assert result["record_hash"] == TRANSACTION_RECORD["record_hash"]
    assert result["agreed_total_cents"] == SAMPLE_CP_OFFER["terms"]["total_value"]
    assert mcp_server._sessions[SESSION_ID]["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_accept_no_counterparty_offer():
    """No counterparty offer yet → no_counterparty_offer error."""
    _seed_session(cp_offer=None)

    result = await mcp_server.a2cn_accept(SESSION_ID)
    assert result["error"] == "no_counterparty_offer"


@pytest.mark.asyncio
async def test_accept_terminal_session():
    """Already completed session → session_already_terminal."""
    _seed_session(status="WITHDRAWN", cp_offer=SAMPLE_CP_OFFER)

    result = await mcp_server.a2cn_accept(SESSION_ID)
    assert result["error"] == "session_already_terminal"


@pytest.mark.asyncio
async def test_accept_session_not_found():
    result = await mcp_server.a2cn_accept("no-such-session")
    assert result["error"] == "session_not_found"


# ---------------------------------------------------------------------------
# Tool 5: a2cn_reject
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reject_success():
    """Active session → rejection sent, status REJECTED_FINAL."""
    _seed_session(cp_offer=SAMPLE_CP_OFFER)

    with respx.mock:
        respx.post(url__regex=rf"{BASE_URL}/sessions/.+/messages").mock(
            return_value=httpx.Response(200, json={"status": "received"},
                                        headers={"Content-Type": "application/a2cn+json"})
        )
        result = await mcp_server.a2cn_reject(SESSION_ID, reason_description="Price too high")

    assert "error" not in result
    assert result["status"] == "REJECTED_FINAL"
    assert mcp_server._sessions[SESSION_ID]["status"] == "REJECTED_FINAL"


@pytest.mark.asyncio
async def test_reject_terminal_guard():
    """Rejecting an already-terminal session → error."""
    _seed_session(status="REJECTED_FINAL")

    result = await mcp_server.a2cn_reject(SESSION_ID)
    assert result["error"] == "session_already_terminal"


# ---------------------------------------------------------------------------
# Tool 6: a2cn_get_session_status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_status_no_counterparty_offer():
    """Active session without any counterparty offer."""
    _seed_session(cp_offer=None)

    result = await mcp_server.a2cn_get_session_status(SESSION_ID)

    assert result["status"] == "NEGOTIATING"
    assert result["session_id"] == SESSION_ID
    assert result["has_counterparty_offer"] is False
    assert result["counterparty_last_offer"] is None
    assert result["my_last_offer"]["total_cents"] == 9_500_000


@pytest.mark.asyncio
async def test_get_status_with_counterparty_offer():
    """Session with a counterparty offer shows the offer details."""
    _seed_session(cp_offer=SAMPLE_CP_OFFER)

    result = await mcp_server.a2cn_get_session_status(SESSION_ID)

    assert result["has_counterparty_offer"] is True
    cp = result["counterparty_last_offer"]
    assert cp is not None
    assert cp["total_cents"] == SAMPLE_CP_OFFER["terms"]["total_value"]
    assert cp["net_days"] == SAMPLE_CP_OFFER["terms"]["payment_terms"]["net_days"]


@pytest.mark.asyncio
async def test_get_status_completed():
    """Completed session includes transaction_record."""
    _seed_session(status="COMPLETED")
    mcp_server._sessions[SESSION_ID]["transaction_record"] = TRANSACTION_RECORD

    result = await mcp_server.a2cn_get_session_status(SESSION_ID)

    assert result["status"] == "COMPLETED"
    assert result["transaction_record"] == TRANSACTION_RECORD


@pytest.mark.asyncio
async def test_get_status_not_found():
    result = await mcp_server.a2cn_get_session_status("ghost-session")
    assert result["error"] == "session_not_found"


# ---------------------------------------------------------------------------
# inject_counterparty_offer helper
# ---------------------------------------------------------------------------


def test_inject_counterparty_offer_updates_store():
    """inject_counterparty_offer updates session store and client state."""
    _seed_session()

    mcp_server.inject_counterparty_offer(SESSION_ID, SAMPLE_CP_OFFER)

    entry = mcp_server._sessions[SESSION_ID]
    assert entry["counterparty_last_offer_message"] == SAMPLE_CP_OFFER
    assert entry["counterparty_last_offer_cents"] == SAMPLE_CP_OFFER["terms"]["total_value"]

    # client internal state also updated
    client_state = entry["client"]._sessions[SESSION_ID]
    assert client_state["latest_offer"] == SAMPLE_CP_OFFER


def test_inject_counterparty_offer_unknown_session():
    with pytest.raises(KeyError):
        mcp_server.inject_counterparty_offer("no-such-session", SAMPLE_CP_OFFER)
