"""
A2CN Responder — FastAPI server (Section 11.1.1)

Endpoints:
  POST   /sessions                        — SessionInit
  GET    /sessions/{session_id}           — Session state
  POST   /sessions/{session_id}/messages  — Send any session message
  GET    /sessions/{session_id}/messages  — Message history (paginated)
  GET    /sessions/{session_id}/record    — Transaction record (COMPLETED only)
  GET    /sessions/{session_id}/audit     — Audit log (any terminal state)

JWT authentication is marked TODO for Week 2.
All endpoints return Content-Type: application/a2cn+json.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from a2cn.session import Session, SessionManager, SessionState, A2CNError, _now
from a2cn.record import generate_transaction_record, generate_audit_log

# ---------------------------------------------------------------------------
# Application + state
# ---------------------------------------------------------------------------

A2CN_CONTENT_TYPE = "application/a2cn+json"

app = FastAPI(title="A2CN Responder", version="0.1")
manager = SessionManager()

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
