"""
A2CN Responder — FastAPI server (Section 11.1.1)

Endpoints:
  POST   /sessions                              — SessionInit
  GET    /sessions/{session_id}                — Session state
  POST   /sessions/{session_id}/messages       — Send any session message
  GET    /sessions/{session_id}/messages       — Message history (paginated)
  GET    /sessions/{session_id}/record         — Transaction record (COMPLETED only)
  GET    /sessions/{session_id}/audit          — Audit log (any terminal state)
  POST   /invitations                          — Receive inbound invitation (v0.2.0)
  POST   /invitations/create                   — Create outbound invitation (v0.2.0)
  POST   /invitations/{invitation_id}/accept   — Accept invitation (v0.2.0)
  POST   /invitations/{invitation_id}/decline  — Decline invitation (v0.2.0)
  GET    /invitations/{invitation_id}          — Get invitation status (v0.2.0)

JWT authentication is marked TODO for Week 2.
All endpoints return Content-Type: application/a2cn+json.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from a2cn.session import Session, SessionManager, SessionState, A2CNError, _now
from a2cn.record import generate_transaction_record, generate_audit_log
from a2cn.invitation import InvitationStore
from a2cn.messages import (
    WebhookPayload,
    InvitationStatus,
    INVITATION_NOT_FOUND,
    INVITATION_EXPIRED,
    INVITATION_ALREADY_ANSWERED,
    INVITATION_SIGNATURE_INVALID,
    INVITATION_VERSION_MISMATCH,
)
from a2cn.crypto import verify_invitation_signature, public_key_from_jwk

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application + state
# ---------------------------------------------------------------------------

A2CN_CONTENT_TYPE = "application/a2cn+json"

app = FastAPI(title="A2CN Responder", version="0.2")
manager = SessionManager()
invitation_store = InvitationStore()

# Responder identity — injected at startup by the example script
_responder_config: dict = {}


def configure_responder(config: dict) -> None:
    """Set responder identity info (DID, agent info, mandate, private key, etc.)."""
    global _responder_config
    _responder_config = config


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def a2cn_response(data: dict, status_code: int = 200) -> Response:
    import json
    return Response(
        content=json.dumps(data),
        status_code=status_code,
        media_type=A2CN_CONTENT_TYPE,
    )


def error_response(code: str, message: str, http_status: int, detail: str = "",
                   session_id: str | None = None, message_id: str | None = None) -> Response:
    import json
    body = {
        "error": {
            "code": code,
            "message": message,
            "detail": detail,
            "timestamp": _now(),
            "session_id": session_id,
            "message_id": message_id,
        }
    }
    return Response(
        content=json.dumps(body),
        status_code=http_status,
        media_type=A2CN_CONTENT_TYPE,
    )


# ---------------------------------------------------------------------------
# Middleware: enforce Content-Type on all responses
# ---------------------------------------------------------------------------

@app.exception_handler(A2CNError)
async def a2cn_error_handler(request: Request, exc: A2CNError) -> Response:
    return error_response(
        exc.code, exc.message, exc.http_status,
        detail=exc.detail,
        session_id=exc.session_id,
        message_id=exc.message_id,
    )


# ---------------------------------------------------------------------------
# POST /sessions — SessionInit
# ---------------------------------------------------------------------------

@app.post("/sessions")
async def create_session(request: Request) -> Response:
    # TODO Week 2: verify JWT Authorization header

    body = await _parse_body(request)
    message_id = body.get("message_id", "")

    # Idempotency check (Section 6.1)
    if manager.has_init_response(message_id):
        return a2cn_response(manager.get_init_response(message_id), 200)

    # Validate required fields
    _require(body, ["message_type", "message_id", "protocol_version", "session_params", "initiator", "initiator_mandate"])

    if body.get("message_type") != "session_init":
        return error_response("WRONG_MESSAGE_TYPE", "Expected message_type 'session_init'", 400, message_id=message_id)

    if body.get("protocol_version") != "0.1":
        return error_response("PROTOCOL_VERSION_MISMATCH", "Only protocol_version '0.1' is supported", 400, message_id=message_id)

    session_params = body.get("session_params", {})
    cfg = _responder_config

    # Validate deal type
    supported_deal_types = cfg.get("deal_types", ["saas_renewal"])
    if session_params.get("deal_type") not in supported_deal_types:
        return error_response("DEAL_TYPE_NOT_SUPPORTED", f"Deal type '{session_params.get('deal_type')}' not supported", 403, message_id=message_id)

    # Validate mandate
    mandate = body.get("initiator_mandate", {})
    mandate_error = _validate_mandate(mandate, session_params)
    if mandate_error:
        return error_response("MANDATE_INVALID", mandate_error, 403, message_id=message_id)

    # Build SessionAck
    session_id = str(uuid.uuid4())
    now = _now()

    responder_info = cfg.get("agent_info", {})
    responder_mandate = cfg.get("mandate", {})

    session_ack = {
        "message_type": "session_ack",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "in_reply_to": message_id,
        "protocol_version": "0.1",
        "session_params_accepted": {
            "deal_type": session_params["deal_type"],
            "currency": session_params["currency"],
            "max_rounds": min(
                session_params.get("max_rounds", 10),
                cfg.get("max_rounds_by_deal_type", {}).get(session_params["deal_type"], 10),
            ),
            "session_timeout_seconds": session_params["session_timeout_seconds"],
            "round_timeout_seconds": session_params["round_timeout_seconds"],
        },
        "responder": responder_info,
        "responder_mandate": responder_mandate,
        "session_created_at": now,
        "current_turn": "initiator",
    }

    # Create session
    session = manager.create_session(session_id, body, session_ack, now)

    manager.store_init_response(message_id, session_ack)
    return a2cn_response(session_ack, 201)


# ---------------------------------------------------------------------------
# GET /sessions/{session_id}
# ---------------------------------------------------------------------------

@app.get("/sessions/{session_id}")
async def get_session(session_id: str, request: Request) -> Response:
    # TODO Week 2: verify JWT
    session = _get_session_or_404(session_id)
    return a2cn_response(session.to_state_dict())


# ---------------------------------------------------------------------------
# POST /sessions/{session_id}/messages — send any session message
# ---------------------------------------------------------------------------

@app.post("/sessions/{session_id}/messages")
async def send_message(session_id: str, request: Request) -> Response:
    # TODO Week 2: verify JWT
    session = _get_session_or_404(session_id)
    body = await _parse_body(request)
    message_id = body.get("message_id", "")

    try:
        response = manager.process_message(session, body)
    except A2CNError as exc:
        return error_response(exc.code, exc.message, exc.http_status, exc.detail, exc.session_id, exc.message_id)

    # v0.2.0: Async webhook delivery for terminal transitions (Level 2 REQUIRED)
    if session.is_terminal():
        webhook_url = _responder_config.get("webhook_url")
        if webhook_url:
            asyncio.create_task(_fire_terminal_webhook(session, webhook_url))

    return a2cn_response(response)


# ---------------------------------------------------------------------------
# GET /sessions/{session_id}/messages — message history
# ---------------------------------------------------------------------------

@app.get("/sessions/{session_id}/messages")
async def get_messages(session_id: str, request: Request,
                       after_sequence: int = 0, limit: int = 50) -> Response:
    session = _get_session_or_404(session_id)
    params = dict(request.query_params)

    all_messages = session._message_log
    filtered = [m for m in all_messages if m.get("sequence_number", 0) > after_sequence]
    page = filtered[:limit]
    next_cursor = page[-1]["sequence_number"] if len(filtered) > limit else None

    return a2cn_response({
        "session_id": session_id,
        "messages": page,
        "next_cursor": next_cursor,
    })


# ---------------------------------------------------------------------------
# GET /sessions/{session_id}/record — transaction record
# ---------------------------------------------------------------------------

@app.get("/sessions/{session_id}/record")
async def get_record(session_id: str, request: Request) -> Response:
    session = _get_session_or_404(session_id)
    if session.state != SessionState.COMPLETED:
        return error_response(
            "SESSION_WRONG_STATE",
            "Transaction record is only available for COMPLETED sessions",
            409,
            session_id=session_id,
        )
    record = generate_transaction_record(session)
    return a2cn_response(record)


# ---------------------------------------------------------------------------
# GET /sessions/{session_id}/audit — audit log
# ---------------------------------------------------------------------------

@app.get("/sessions/{session_id}/audit")
async def get_audit(session_id: str, request: Request) -> Response:
    session = _get_session_or_404(session_id)
    if not session.is_terminal():
        return error_response(
            "SESSION_WRONG_STATE",
            "Audit log is only available for sessions in a terminal state",
            409,
            session_id=session_id,
        )
    log = generate_audit_log(session)
    return a2cn_response(log)


# ---------------------------------------------------------------------------
# v0.2.0: Invitation endpoints (Component 8)
# ---------------------------------------------------------------------------

# Route order matters: /invitations/create must be declared before
# /invitations/{invitation_id} so FastAPI doesn't treat "create" as an ID.

@app.post("/invitations/create", status_code=201)
async def create_invitation_endpoint(request: Request) -> Response:
    """
    Create and sign an outbound SessionInvitation.
    The caller delivers it via their chosen channel.
    If recipient_endpoint is provided, also POSTs it directly.
    """
    body = await _parse_body(request)
    cfg = _responder_config
    agent_info = cfg.get("agent_info", {})
    private_key = cfg.get("private_key")

    if not private_key:
        return error_response("INTERNAL_ERROR", "Server private key not configured", 500)

    invitation = invitation_store.create_invitation(
        inviter_did=agent_info.get("did", ""),
        inviter_endpoint=agent_info.get("endpoint", ""),
        inviter_discovery_url=f"{agent_info.get('endpoint', '')}/.well-known/a2cn-agent",
        inviter_verification_method=agent_info.get("verification_method", ""),
        private_key=private_key,
        proposed_deal_type=body.get("proposed_deal_type", ""),
        proposed_session_params=body.get("proposed_session_params", {}),
        proposed_terms_summary=body.get("proposed_terms_summary", {}),
        inviter_mandate_summary=body.get("inviter_mandate_summary", {}),
        expires_hours=int(body.get("expires_hours", 24)),
        base_url=agent_info.get("endpoint", "http://localhost:8000"),
    )

    invitation_dict = invitation.to_dict()

    # Optionally deliver directly to recipient
    recipient_endpoint = body.get("recipient_endpoint")
    if recipient_endpoint:
        try:
            async with httpx.AsyncClient(timeout=10.0) as http:
                await http.post(f"{recipient_endpoint}/invitations", json=invitation_dict)
        except Exception as exc:
            logger.warning("Failed to deliver invitation to %s: %s", recipient_endpoint, exc)

    return a2cn_response(invitation_dict, 201)


@app.post("/invitations")
async def receive_invitation(request: Request) -> Response:
    """
    Receive an inbound SessionInvitation from a counterparty.
    Verifies the signature, then stores with PENDING status.
    """
    body = await _parse_body(request)

    if body.get("a2cn_version") != "0.2":
        return error_response(
            INVITATION_VERSION_MISMATCH,
            f"Unsupported a2cn_version: {body.get('a2cn_version')!r}",
            400,
        )

    # Signature verification: resolve inviter DID to get public key
    # For now (Week 2 TODO: full DID resolution), accept without signature check
    # if no DID resolver is configured.
    try:
        from a2cn.did import resolve_did_web, get_verification_method, get_public_key
        inviter_did = body.get("inviter_did", "")
        vm_id = body.get("inviter_verification_method", "")
        if inviter_did and vm_id:
            async with httpx.AsyncClient() as http:
                did_doc = await resolve_did_web(inviter_did, http)
            vm = get_verification_method(did_doc, vm_id)
            pub_key = get_public_key(vm)
            if not verify_invitation_signature(body, pub_key):
                return error_response(INVITATION_SIGNATURE_INVALID, "Invitation signature is invalid", 400)
    except Exception as exc:
        logger.debug("DID resolution skipped during invitation receipt: %s", exc)

    invitation_store.store_inbound(body)
    return a2cn_response({"invitation_id": body.get("invitation_id"), "status": "pending"}, 201)


@app.post("/invitations/{invitation_id}/accept")
async def accept_invitation_endpoint(invitation_id: str, request: Request) -> Response:
    """Accept a stored invitation."""
    body = await _parse_body(request)
    cfg = _responder_config
    agent_info = cfg.get("agent_info", {})
    private_key = cfg.get("private_key")

    if not private_key:
        return error_response("INTERNAL_ERROR", "Server private key not configured", 500)

    try:
        acceptance = invitation_store.accept_invitation(
            invitation_id=invitation_id,
            acceptor_did=body.get("acceptor_did", agent_info.get("did", "")),
            acceptor_a2cn_endpoint=body.get("acceptor_a2cn_endpoint", agent_info.get("endpoint", "")),
            acceptor_discovery_url=body.get(
                "acceptor_discovery_url",
                f"{agent_info.get('endpoint', '')}/.well-known/a2cn-agent",
            ),
            acceptor_verification_method=body.get(
                "acceptor_verification_method",
                agent_info.get("verification_method", ""),
            ),
            private_key=private_key,
        )
    except ValueError as exc:
        code = str(exc)
        status = {
            INVITATION_NOT_FOUND: 404,
            INVITATION_EXPIRED: 410,
            INVITATION_ALREADY_ANSWERED: 409,
        }.get(code, 400)
        return error_response(code, code.replace("_", " ").lower(), status)

    return a2cn_response(acceptance.to_dict())


@app.post("/invitations/{invitation_id}/decline")
async def decline_invitation_endpoint(invitation_id: str, request: Request) -> Response:
    """Decline a stored invitation."""
    body = await _parse_body(request)

    try:
        decline = invitation_store.decline_invitation(
            invitation_id=invitation_id,
            reason_code=body.get("reason_code", "OTHER"),
            reason_message=body.get("reason_message", ""),
        )
    except ValueError as exc:
        code = str(exc)
        status = {
            INVITATION_NOT_FOUND: 404,
            INVITATION_EXPIRED: 410,
            INVITATION_ALREADY_ANSWERED: 409,
        }.get(code, 400)
        return error_response(code, code.replace("_", " ").lower(), status)

    return a2cn_response(decline.to_dict())


@app.get("/invitations/{invitation_id}")
async def get_invitation_endpoint(invitation_id: str) -> Response:
    """Get status of any invitation (inbound or outbound)."""
    entry = invitation_store.get_invitation(invitation_id)
    if entry is None:
        return error_response(INVITATION_NOT_FOUND, f"Invitation {invitation_id!r} not found", 404)
    return a2cn_response({
        "invitation_id": invitation_id,
        "status": entry["status"].value if hasattr(entry["status"], "value") else entry["status"],
        "invitation": entry["invitation"],
        "created_at": entry.get("created_at"),
        "answered_at": entry.get("answered_at"),
    })


# ---------------------------------------------------------------------------
# v0.2.0: Webhook delivery (Level 2 REQUIRED)
# ---------------------------------------------------------------------------

_TERMINAL_EVENT_MAP = {
    SessionState.COMPLETED: "session.completed",
    SessionState.REJECTED_FINAL: "session.rejected",
    SessionState.WITHDRAWN: "session.withdrawn",
    SessionState.IMPASSE: "session.impasse",
    SessionState.TIMED_OUT: "session.timed_out",
    SessionState.ERROR: "session.error",
}


async def _fire_terminal_webhook(session: Session, webhook_url: str) -> None:
    """Build and deliver a terminal-state webhook payload."""
    event_type = _TERMINAL_EVENT_MAP.get(session.state, "session.error")
    record_hash = ""
    if session.state == SessionState.COMPLETED:
        try:
            record = generate_transaction_record(session)
            record_hash = record.get("record_hash", "")
        except Exception:
            pass

    payload = WebhookPayload(
        event_type=event_type,
        session_id=session.session_id,
        occurred_at=_now(),
        session_state=session.state,
        terminal=True,
        record_hash=record_hash,
    )
    await deliver_webhook_with_retry(webhook_url, payload.to_dict())


async def deliver_webhook_with_retry(url: str, payload: dict, max_retries: int = 3) -> None:
    """
    Attempt webhook delivery up to max_retries times.
    Backoff: 1s, 4s, 16s between attempts.
    Non-fatal — logs failures but does not raise.
    """
    import json
    backoff_seconds = [1, 4, 16]
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=10.0) as http:
                resp = await http.post(
                    url,
                    content=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code < 300:
                    return
                logger.warning("Webhook delivery attempt %d returned %d", attempt + 1, resp.status_code)
        except Exception as exc:
            logger.warning("Webhook delivery attempt %d failed: %s", attempt + 1, exc)
        if attempt < max_retries - 1:
            await asyncio.sleep(backoff_seconds[attempt])
    logger.error("Webhook delivery to %s failed after %d attempts", url, max_retries)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _parse_body(request: Request) -> dict:
    try:
        return await request.json()
    except Exception:
        raise A2CNError("INTERNAL_ERROR", "Invalid JSON in request body", 400)


def _get_session_or_404(session_id: str) -> Session:
    session = manager.get_session(session_id)
    if session is None:
        raise A2CNError("SESSION_NOT_FOUND", f"Session {session_id!r} not found", 404, session_id=session_id)
    return session


def _require(body: dict, fields: list[str]) -> None:
    for f in fields:
        if f not in body:
            raise A2CNError("INTERNAL_ERROR", f"Missing required field: {f!r}", 400)


def _validate_mandate(mandate: dict, session_params: dict) -> str | None:
    """Basic Tier 1 mandate validation. Returns error string or None."""
    mandate_type = mandate.get("mandate_type")
    if mandate_type not in ("declared", "did_vc"):
        return f"Unknown mandate_type: {mandate_type!r}"

    if mandate_type == "declared":
        valid_until = mandate.get("valid_until", "")
        try:
            expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
            if expiry < datetime.now(timezone.utc):
                return f"Mandate expired at {valid_until}"
        except (ValueError, AttributeError):
            return "Invalid valid_until format"

        authorized_types = mandate.get("authorized_deal_types", [])
        if session_params.get("deal_type") not in authorized_types:
            return f"Deal type '{session_params.get('deal_type')}' not in authorized_deal_types"

    return None
