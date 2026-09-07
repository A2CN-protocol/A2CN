"""
A2CN MCP Server — Agent-to-Agent Commercial Negotiation Protocol

Exposes A2CN negotiation capabilities as MCP tools, enabling any
MCP-compatible agent framework to negotiate commercial terms autonomously.

Compatible with:
- Claude Desktop (stdio transport)
- LangChain / LangGraph (HTTP transport via /mcp endpoint)
- Cursor and other MCP clients (stdio transport)
- Any MCP-compliant agent framework

Architecture (per spec Section 13.9):
    LLM reasoning layer (the agent calling these tools)
        → decides: what to offer, whether to accept, when to reject
    MCP tool layer (this file) — the deterministic protocol adapter
        → handles: DID resolution, message construction, signing,
          schema validation, sequence tracking, session state

The LLM never sees or generates protocol internals (hashes, signatures,
sequence numbers). Those are computed here, deterministically.

Usage (stdio, for Claude Desktop / Cursor):
    python mcp_server.py

Usage (HTTP, for LangGraph / remote agents):
    python mcp_server.py --http --port 8080
    # Then connect via http://localhost:8080/mcp

Tools exposed:
    a2cn_discover              Check if counterparty supports A2CN
    a2cn_initiate_session      Start a negotiation session
    a2cn_send_offer            Send a counteroffer
    a2cn_accept                Accept current counterparty offer
    a2cn_reject                Reject and end session
    a2cn_get_session_status    Poll for counterparty response
"""

import argparse
import os
import uuid
from typing import Any

import httpx
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - only reachable when the mcp extra is absent.
    raise SystemExit(
        "The A2CN MCP server requires the optional MCP dependencies. "
        "Install them with: pip install -e '.[mcp]'"
    ) from None

from a2cn.client import A2CNClient
from a2cn.crypto import (
    generate_keypair,
    public_key_to_jwk,
    create_jwt,
    hash_object,
    sign_jws,
)
from a2cn.session import _now

# ---------------------------------------------------------------------------
# MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "a2cn",
    instructions=(
        "A2CN negotiation tools. Call a2cn_discover first to confirm the counterparty "
        "supports A2CN. Then a2cn_initiate_session to open a session and send your "
        "opening offer. Use a2cn_get_session_status to poll for the counterparty's "
        "response. Respond with a2cn_send_offer (counter), a2cn_accept, or a2cn_reject."
    ),
)

# ---------------------------------------------------------------------------
# Agent identity — ephemeral by default; configure via environment variables
#
#   A2CN_AGENT_DID      Your agent's DID (default: did:web:mcp-agent.local)
#   A2CN_AGENT_ID       Your agent's ID string (default: mcp-agent-001)
#   A2CN_AGENT_ORG      Your organization name (default: MCP Agent)
#
# The ephemeral keypair is regenerated every time the server starts.
# For production, load a stable key from A2CN_PRIVATE_KEY_FILE.
# ---------------------------------------------------------------------------

_private_key, _public_key = generate_keypair()
_public_key_jwk = public_key_to_jwk(_public_key)

_agent_did: str = os.environ.get("A2CN_AGENT_DID", "did:web:mcp-agent.local")
_agent_id: str = os.environ.get("A2CN_AGENT_ID", "mcp-agent-001")
_agent_org: str = os.environ.get("A2CN_AGENT_ORG", "MCP Agent")
_verification_method: str = f"{_agent_did}#key-1"

# Public DID document — counterparty A2CN servers can call register_did_document()
# with this so they can verify JWT signatures without live HTTP resolution.
agent_did_document: dict = {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
    ],
    "id": _agent_did,
    "verificationMethod": [
        {
            "id": _verification_method,
            "type": "JsonWebKey2020",
            "controller": _agent_did,
            "publicKeyJwk": _public_key_jwk,
        }
    ],
    "authentication": [_verification_method],
    "assertionMethod": [_verification_method],
}

# ---------------------------------------------------------------------------
# In-memory session store
#
# session_id → {
#   client:                        A2CNClient        (holds signing keys + HTTP client)
#   http_client:                   httpx.AsyncClient (kept alive for the session lifetime)
#   endpoint:                      str               (counterparty base URL)
#   counterparty_did:              str
#   deal_type:                     str
#   session_ack:                   dict              (raw SessionAck from counterparty)
#   my_did:                        str
#   my_last_offer_cents:           int | None
#   my_last_offer_net_days:        int | None
#   counterparty_last_offer_cents: int | None
#   counterparty_last_offer_net_days: int | None
#   counterparty_last_offer_message:  dict | None    (full wire message; needed for accept)
#   round_number:                  int
#   status:                        str               (ACTIVE | NEGOTIATING | COMPLETED | …)
#   transaction_record:            dict | None
# }
#
# NOTE: Production deployments should replace this dict with a persistent store
# (Redis, PostgreSQL, etc.) so sessions survive server restarts.
# ---------------------------------------------------------------------------

_sessions: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# HTTP auth: injects a fresh ES256 Bearer JWT on every outgoing A2CN request.
# Generating a new JWT per-request gives each call a unique jti, which is
# required to pass the anti-replay check on the counterparty's server.
# ---------------------------------------------------------------------------

class _MCPBearerAuth(httpx.Auth):
    """Fresh-JWT-per-request auth — safe against anti-replay protection."""

    def __init__(self, audience_did: str) -> None:
        self._audience = audience_did

    def auth_flow(self, request):
        token = create_jwt(
            _agent_did, self._audience, _private_key,
            kid=_verification_method, exp_seconds=300,
        )
        request.headers["Authorization"] = f"Bearer {token}"
        yield request


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _did_to_base_url(did: str) -> str:
    """Convert a did:web DID to its HTTPS base URL."""
    if not did.startswith("did:web:"):
        raise ValueError(f"Not a did:web DID: {did!r}")
    remainder = did[len("did:web:"):]
    parts = remainder.split(":")
    domain = parts[0]
    if len(parts) > 1:
        return f"https://{domain}/{'/'.join(parts[1:])}"
    return f"https://{domain}"


def _make_mandate(deal_type: str) -> dict:
    """Build a Tier-1 declared mandate for outgoing session initiation."""
    return {
        "mandate_type": "declared",
        "agent_id": _agent_id,
        "principal_organization": _agent_org,
        "principal_did": _agent_did,
        "authorized_deal_types": [deal_type],
        "max_commitment_value": int(os.environ.get("A2CN_MAX_COMMITMENT", "100000000")),
        "max_commitment_currency": "USD",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-12-31T00:00:00Z",
    }


def _make_agent_info(my_did: str) -> dict:
    return {
        "organization_name": _agent_org,
        "did": my_did,
        "verification_method": f"{my_did}#key-1",
        "agent_id": _agent_id,
        "endpoint": f"https://{my_did.replace('did:web:', '')}",
    }


def _session_not_found(session_id: str) -> dict:
    return {
        "error": "session_not_found",
        "message": (
            f"No active session with id {session_id!r}. "
            "Use a2cn_initiate_session to start a new session."
        ),
    }


def _session_terminal(session_id: str, status: str) -> dict:
    return {
        "error": "session_already_terminal",
        "message": f"Session {session_id!r} is already in terminal state {status!r}.",
        "status": status,
        "session_id": session_id,
    }


_TERMINAL_STATES = frozenset(
    {"COMPLETED", "REJECTED_FINAL", "WITHDRAWN", "IMPASSE", "TIMED_OUT", "ERROR"}
)

_VALID_DEAL_TYPES = frozenset(
    {"saas_renewal", "goods_procurement", "services_engagement", "logistics_rate"}
)

# ---------------------------------------------------------------------------
# Public helper — called by demos / webhooks to inject counterparty offers
#
# In production, call this from your webhook handler when the counterparty
# POSTs their counteroffer to your A2CN server endpoint.
# In the demo, it's called directly after simulating the counterparty's move.
# ---------------------------------------------------------------------------

def inject_counterparty_offer(session_id: str, offer_message: dict) -> None:
    """
    Record a counterparty offer in the session store.

    In production: call this from your A2CN server's message handler when
    the counterparty POSTs a counteroffer to your /sessions/{id}/messages.
    In the MCP demo: call this directly after simulating the seller's response.
    """
    entry = _sessions.get(session_id)
    if entry is None:
        raise KeyError(f"Session {session_id!r} not found in MCP session store")
    terms = offer_message.get("terms", {})
    payment = terms.get("payment_terms", {})
    entry["counterparty_last_offer_cents"] = terms.get("total_value")
    entry["counterparty_last_offer_net_days"] = payment.get("net_days")
    entry["counterparty_last_offer_message"] = offer_message
    # Keep the A2CNClient's internal state in sync (for record generation)
    entry["client"].process_incoming(session_id, offer_message)


# ---------------------------------------------------------------------------
# Tool 1: a2cn_discover
# ---------------------------------------------------------------------------

@mcp.tool()
async def a2cn_discover(counterparty_did: str) -> dict:
    """
    Fetch the A2CN discovery document from a counterparty to check
    whether they support A2CN and what deal types and conformance level
    they advertise.

    Returns the discovery document dict on success, or an error dict
    with 'error' key if the counterparty does not support A2CN.

    Use this before initiating any session to verify the counterparty
    is A2CN-capable.

    Args:
        counterparty_did: The DID of the counterparty agent
                          (e.g., 'did:web:supplier.example.com')
    """
    try:
        base_url = _did_to_base_url(counterparty_did)
    except ValueError as exc:
        return {"error": "invalid_did", "message": str(exc), "counterparty_did": counterparty_did}

    discovery_url = f"{base_url}/.well-known/a2cn-agent"
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            resp = await http.get(discovery_url)
        if resp.status_code == 404:
            return {
                "error": "not_a2cn_capable",
                "message": (
                    f"Counterparty {counterparty_did!r} has no discovery document "
                    f"at {discovery_url}. They may not support A2CN."
                ),
            }
        resp.raise_for_status()
        doc = resp.json()
        return {
            "a2cn_capable": True,
            "a2cn_version": doc.get("a2cn_version"),
            "conformance_level": doc.get("conformance_level"),
            "deal_types": doc.get("deal_types", []),
            "mandate_methods": doc.get("mandate_methods", ["declared"]),
            "endpoint": doc.get("endpoint") or base_url,
            "agent_did": doc.get("agent_did", counterparty_did),
        }
    except httpx.HTTPStatusError as exc:
        return {
            "error": "discovery_http_error",
            "message": f"HTTP {exc.response.status_code} fetching discovery from {discovery_url}",
        }
    except Exception as exc:
        return {
            "error": "discovery_failed",
            "message": f"Could not reach {discovery_url}: {exc}",
        }


# ---------------------------------------------------------------------------
# Tool 2: a2cn_initiate_session
# ---------------------------------------------------------------------------

@mcp.tool()
async def a2cn_initiate_session(
    counterparty_did: str,
    deal_type: str,
    my_did: str,
    initial_offer_total_value_cents: int,
    currency: str,
    max_rounds: int,
    payment_terms_net_days: int,
    subject: str,
    custom_terms: dict | None = None,
    impasse_threshold: int | None = None,
) -> dict:
    """
    Initiate an A2CN commercial negotiation session with a counterparty.

    Sends a SessionInit message to the counterparty and waits for
    SessionAck. Returns the session_id and initial session state on
    success.

    This tool handles all protocol machinery: DID resolution, mandate
    verification, message signing, and sequence tracking. You only
    provide the commercial intent.

    Args:
        counterparty_did: DID of the counterparty (e.g. 'did:web:acme.com')
        deal_type: One of 'saas_renewal', 'goods_procurement',
                   'services_engagement', 'logistics_rate'
        my_did: Your agent's DID
        initial_offer_total_value_cents: Your opening offer in cents
                                         (e.g., 9500000 for $95,000)
        currency: ISO 4217 code (e.g., 'USD')
        max_rounds: Maximum negotiation rounds (1-20)
        payment_terms_net_days: Payment terms in days (e.g., 30 for net-30)
        subject: Human-readable description of what is being negotiated
        custom_terms: Optional dict of deal-type-specific terms
        impasse_threshold: Optional rounds without movement before impasse
    """
    if deal_type not in _VALID_DEAL_TYPES:
        return {
            "error": "invalid_deal_type",
            "message": (
                f"deal_type {deal_type!r} is not recognised. "
                f"Valid types: {', '.join(sorted(_VALID_DEAL_TYPES))}"
            ),
        }
    if not (1 <= max_rounds <= 20):
        return {"error": "invalid_max_rounds", "message": "max_rounds must be between 1 and 20"}

    try:
        base_url = _did_to_base_url(counterparty_did)
    except ValueError as exc:
        return {"error": "invalid_did", "message": str(exc)}

    # Fetch discovery to get the server's own DID (used as JWT audience).
    # Falls back to env override or counterparty DID if discovery fails.
    server_did = os.environ.get("A2CN_COUNTERPARTY_SERVER_DID", "")
    if not server_did:
        try:
            async with httpx.AsyncClient(timeout=5.0) as disc_http:
                disc_resp = await disc_http.get(f"{base_url}/.well-known/a2cn-agent")
            if disc_resp.status_code == 200:
                server_did = disc_resp.json().get("agent_did", counterparty_did)
        except Exception:
            pass
        if not server_did:
            server_did = counterparty_did

    session_params: dict = {
        "deal_type": deal_type,
        "currency": currency,
        "subject": subject,
        "max_rounds": max_rounds,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    }
    if impasse_threshold is not None:
        session_params["impasse_threshold"] = impasse_threshold

    http_client = httpx.AsyncClient(
        auth=_MCPBearerAuth(audience_did=server_did),
        timeout=30.0,
    )
    client = A2CNClient(
        agent_info=_make_agent_info(my_did),
        private_key=_private_key,
        mandate=_make_mandate(deal_type),
        http_client=http_client,
    )

    try:
        ack = await client.initiate_session(
            endpoint=base_url,
            responder_did=counterparty_did,
            session_params=session_params,
        )
    except httpx.HTTPStatusError as exc:
        await http_client.aclose()
        detail: Any = {}
        try:
            detail = exc.response.json()
        except Exception:
            pass
        return {
            "error": "session_init_failed",
            "message": f"Counterparty returned HTTP {exc.response.status_code}",
            "detail": detail,
        }
    except Exception as exc:
        await http_client.aclose()
        return {"error": "session_init_error", "message": str(exc)}

    session_id = ack["session_id"]

    # Build and send the opening offer (round 1)
    terms: dict = {
        "total_value": initial_offer_total_value_cents,
        "currency": currency,
        "payment_terms": {"net_days": payment_terms_net_days},
    }
    if custom_terms:
        terms.update(custom_terms)

    try:
        await client.send_offer(
            endpoint=base_url,
            responder_did=counterparty_did,
            session_id=session_id,
            terms=terms,
        )
    except Exception as exc:
        # Session created but opening offer failed — store partial state
        _sessions[session_id] = {
            "client": client, "http_client": http_client,
            "endpoint": base_url, "counterparty_did": counterparty_did,
            "deal_type": deal_type, "session_ack": ack, "my_did": my_did,
            "my_last_offer_cents": None, "my_last_offer_net_days": None,
            "counterparty_last_offer_cents": None,
            "counterparty_last_offer_net_days": None,
            "counterparty_last_offer_message": None,
            "round_number": 0, "status": "ACTIVE", "transaction_record": None,
        }
        return {
            "error": "opening_offer_failed",
            "message": f"Session created (id={session_id!r}) but opening offer failed: {exc}",
            "session_id": session_id,
        }

    _sessions[session_id] = {
        "client": client,
        "http_client": http_client,
        "endpoint": base_url,
        "counterparty_did": counterparty_did,
        "deal_type": deal_type,
        "session_ack": ack,
        "my_did": my_did,
        "my_last_offer_cents": initial_offer_total_value_cents,
        "my_last_offer_net_days": payment_terms_net_days,
        "counterparty_last_offer_cents": None,
        "counterparty_last_offer_net_days": None,
        "counterparty_last_offer_message": None,
        "round_number": 1,
        "status": "NEGOTIATING",
        "transaction_record": None,
    }

    accepted = ack.get("session_params_accepted", {})
    return {
        "status": "ACTIVE",
        "session_id": session_id,
        "deal_type": deal_type,
        "currency": currency,
        "my_opening_offer_cents": initial_offer_total_value_cents,
        "my_opening_offer_net_days": payment_terms_net_days,
        "max_rounds": accepted.get("max_rounds", max_rounds),
        "awaiting_counterparty_response": True,
        "counterparty_did": counterparty_did,
    }


# ---------------------------------------------------------------------------
# Tool 3: a2cn_send_offer
# ---------------------------------------------------------------------------

@mcp.tool()
async def a2cn_send_offer(
    session_id: str,
    total_value_cents: int,
    payment_terms_net_days: int,
    custom_terms: dict | None = None,
    reason_description: str | None = None,
) -> dict:
    """
    Send a counteroffer in an active A2CN negotiation session.

    Use this when you decide to counter the counterparty's most recent
    offer rather than accepting or rejecting it.

    The tool validates your offer against the session's mandate and
    deal-type schema before sending. It handles signing and sequence
    number tracking automatically.

    Args:
        session_id: The session ID from a2cn_initiate_session
        total_value_cents: Your counteroffer total in cents
        payment_terms_net_days: Payment terms in days
        custom_terms: Optional deal-type-specific terms
        reason_description: Optional human-readable rationale (visible
                            to counterparty, keep concise)

    Returns:
        dict with 'status', 'round_number', 'counterparty_response'
        (if counterparty has already responded via webhook), or
        'awaiting_response' if polling is needed.
    """
    entry = _sessions.get(session_id)
    if entry is None:
        return _session_not_found(session_id)
    if entry["status"] in _TERMINAL_STATES:
        return _session_terminal(session_id, entry["status"])

    terms: dict = {
        "total_value": total_value_cents,
        "currency": entry["session_ack"]["session_params_accepted"].get("currency", "USD"),
        "payment_terms": {"net_days": payment_terms_net_days},
    }
    if custom_terms:
        terms.update(custom_terms)

    in_reply_to = None
    cp_offer = entry.get("counterparty_last_offer_message")
    if cp_offer:
        in_reply_to = cp_offer.get("message_id")

    try:
        await entry["client"].send_offer(
            endpoint=entry["endpoint"],
            responder_did=entry["counterparty_did"],
            session_id=session_id,
            terms=terms,
            in_reply_to=in_reply_to,
        )
    except httpx.HTTPStatusError as exc:
        detail: Any = {}
        try:
            detail = exc.response.json()
        except Exception:
            pass
        return {
            "error": "offer_rejected_by_server",
            "message": f"Counterparty server returned HTTP {exc.response.status_code}",
            "detail": detail,
            "session_id": session_id,
        }
    except Exception as exc:
        return {"error": "offer_send_failed", "message": str(exc), "session_id": session_id}

    entry["my_last_offer_cents"] = total_value_cents
    entry["my_last_offer_net_days"] = payment_terms_net_days
    entry["status"] = "NEGOTIATING"
    entry["round_number"] += 1

    return {
        "status": "offer_sent",
        "session_id": session_id,
        "round_number": entry["round_number"],
        "your_offer_cents": total_value_cents,
        "your_offer_net_days": payment_terms_net_days,
        "awaiting_counterparty_response": True,
    }


# ---------------------------------------------------------------------------
# Tool 4: a2cn_accept
# ---------------------------------------------------------------------------

@mcp.tool()
async def a2cn_accept(session_id: str) -> dict:
    """
    Accept the counterparty's most recent offer in an A2CN session,
    completing the negotiation.

    Only call this when you have decided the current counterparty offer
    is acceptable. This is a terminal action — it cannot be undone.

    On success, both parties independently generate the same
    transaction record. The returned record_hash can be used to
    verify agreement integrity.

    Args:
        session_id: The session ID from a2cn_initiate_session

    Returns:
        dict with 'status': 'COMPLETED', 'record_hash', 'agreed_terms',
        and the full 'transaction_record'.
    """
    entry = _sessions.get(session_id)
    if entry is None:
        return _session_not_found(session_id)
    if entry["status"] in _TERMINAL_STATES:
        return _session_terminal(session_id, entry["status"])

    offer = entry.get("counterparty_last_offer_message")
    if offer is None:
        return {
            "error": "no_counterparty_offer",
            "message": (
                "There is no counterparty offer to accept yet. "
                "Call a2cn_get_session_status to check for a response, "
                "or a2cn_send_offer to send your own counteroffer."
            ),
            "session_id": session_id,
        }

    client = entry["client"]
    try:
        await client.send_acceptance(
            endpoint=entry["endpoint"],
            responder_did=entry["counterparty_did"],
            session_id=session_id,
            offer=offer,
        )
    except httpx.HTTPStatusError as exc:
        detail: Any = {}
        try:
            detail = exc.response.json()
        except Exception:
            pass
        return {
            "error": "acceptance_rejected_by_server",
            "message": f"Counterparty server returned HTTP {exc.response.status_code}",
            "detail": detail,
            "session_id": session_id,
        }
    except Exception as exc:
        return {"error": "acceptance_failed", "message": str(exc), "session_id": session_id}

    # Fetch the authoritative transaction record from the counterparty's server
    try:
        record = await client.get_transaction_record(entry["endpoint"], session_id)
    except Exception:
        record = {}

    agreed_terms = offer.get("terms", {})
    entry["status"] = "COMPLETED"
    entry["transaction_record"] = record

    return {
        "status": "COMPLETED",
        "session_id": session_id,
        "record_hash": record.get("record_hash", ""),
        "agreed_total_cents": agreed_terms.get("total_value"),
        "agreed_net_days": agreed_terms.get("payment_terms", {}).get("net_days"),
        "agreed_terms": agreed_terms,
        "transaction_record": record,
    }


# ---------------------------------------------------------------------------
# Tool 5: a2cn_reject
# ---------------------------------------------------------------------------

@mcp.tool()
async def a2cn_reject(
    session_id: str,
    reason_description: str | None = None,
) -> dict:
    """
    Reject the counterparty's most recent offer and end the session
    without agreement.

    Use this when the counterparty's offer is outside acceptable bounds
    and further negotiation is not productive. This is a terminal action.

    Args:
        session_id: The session ID from a2cn_initiate_session
        reason_description: Optional reason visible to counterparty

    Returns:
        dict with 'status': 'REJECTED_FINAL'
    """
    entry = _sessions.get(session_id)
    if entry is None:
        return _session_not_found(session_id)
    if entry["status"] in _TERMINAL_STATES:
        return _session_terminal(session_id, entry["status"])

    client = entry["client"]
    client_state = client._sessions.get(session_id, {})
    seq = client_state.get("sequence_number", 0) + 1
    rnd = client_state.get("round_number", 1)

    cp_offer = entry.get("counterparty_last_offer_message")
    rejected_offer_id = cp_offer["message_id"] if cp_offer else ""
    in_reply_to = rejected_offer_id

    rejection = {
        "message_type": "rejection",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "in_reply_to": in_reply_to,
        "round_number": rnd,
        "sequence_number": seq,
        "rejected_offer_id": rejected_offer_id,
        "sender_did": entry["my_did"],
        "sender_agent_id": _agent_id,
        "timestamp": _now(),
        "reason_code": "PRICE_OUT_OF_RANGE",
    }
    if reason_description:
        rejection["reason_description"] = reason_description

    headers = {
        "Content-Type": "application/a2cn+json",
        "Idempotency-Key": rejection["message_id"],
    }

    try:
        resp = await entry["http_client"].post(
            f"{entry['endpoint']}/sessions/{session_id}/messages",
            json=rejection,
            headers=headers,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return {
            "error": "rejection_failed",
            "message": f"Counterparty server returned HTTP {exc.response.status_code}",
            "session_id": session_id,
        }
    except Exception as exc:
        return {"error": "rejection_failed", "message": str(exc), "session_id": session_id}

    entry["status"] = "REJECTED_FINAL"
    return {
        "status": "REJECTED_FINAL",
        "session_id": session_id,
        "reason": reason_description or "Offer rejected.",
    }


# ---------------------------------------------------------------------------
# Tool 6: a2cn_get_session_status
# ---------------------------------------------------------------------------

@mcp.tool()
async def a2cn_get_session_status(session_id: str) -> dict:
    """
    Get the current status of an A2CN negotiation session, including
    the latest offer from the counterparty if one has arrived.

    Use this to poll for counterparty responses when webhooks are not
    configured, or to check session state before making a decision.

    Args:
        session_id: The session ID from a2cn_initiate_session

    Returns:
        dict with 'status', 'round_number', 'my_last_offer',
        'counterparty_last_offer', 'rounds_remaining', and
        'transaction_record' (if session is COMPLETED).
    """
    entry = _sessions.get(session_id)
    if entry is None:
        return _session_not_found(session_id)

    ack = entry.get("session_ack", {})
    accepted = ack.get("session_params_accepted", {})
    max_rounds = accepted.get("max_rounds", 10)
    rounds_remaining = max(0, max_rounds - entry["round_number"])

    result: dict = {
        "status": entry["status"],
        "session_id": session_id,
        "round_number": entry["round_number"],
        "rounds_remaining": rounds_remaining,
        "deal_type": entry.get("deal_type"),
        "my_last_offer": {
            "total_cents": entry.get("my_last_offer_cents"),
            "net_days": entry.get("my_last_offer_net_days"),
        },
        "counterparty_last_offer": None,
        "has_counterparty_offer": False,
        "transaction_record": entry.get("transaction_record"),
    }

    cp_offer = entry.get("counterparty_last_offer_message")
    if cp_offer is not None:
        result["has_counterparty_offer"] = True
        result["counterparty_last_offer"] = {
            "total_cents": entry.get("counterparty_last_offer_cents"),
            "net_days": entry.get("counterparty_last_offer_net_days"),
            "terms": cp_offer.get("terms", {}),
        }

    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A2CN MCP Server — expose A2CN negotiation as MCP tools"
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Run as HTTP server (streamable-http transport) instead of stdio",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for HTTP mode (default: 8080)",
    )
    args = parser.parse_args()

    if args.http:
        import uvicorn

        starlette_app = mcp.streamable_http_app()
        uvicorn.run(starlette_app, host="0.0.0.0", port=args.port)
    else:
        mcp.run(transport="stdio")
