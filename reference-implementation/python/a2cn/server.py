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

JWT authentication is enforced on all state-modifying endpoints (Section 11.1.4).
All endpoints return Content-Type: application/a2cn+json.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import httpx
import jwt as pyjwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response
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
from a2cn.crypto import verify_jwt, verify_invitation_signature, public_key_from_jwk
from a2cn.did import resolve_did_web, get_verification_method, get_public_key
from session_store import InMemorySessionStore, SessionStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application + state
# ---------------------------------------------------------------------------

A2CN_CONTENT_TYPE = "application/a2cn+json"

app = FastAPI(title="A2CN Responder", version="0.2")
manager = SessionManager()
invitation_store = InvitationStore()

# Post-commitment data store (delivery notices, dispute notices, lifecycle status).
# Keyed by session_id → {delivery_notice, delivery_notice_message_id,
#                         acknowledgment_message_id, dispute_notice,
#                         dispute_notice_message_id, post_commitment_status}.
# Replace with a durable InMemorySessionStore subclass for production.
_session_store: InMemorySessionStore = InMemorySessionStore()

# Responder identity — injected at startup by the example script
_responder_config: dict = {}


def configure_responder(config: dict, session_store: "SessionStore | None" = None) -> None:
    """Set responder identity info (DID, agent info, mandate, private key, etc.)."""
    global _responder_config, _session_store
    _responder_config = config
    if session_store is not None:
        _session_store = session_store


# ---------------------------------------------------------------------------
# Middleware: transport auth (Section 14.1) + Content-Type enforcement
# ---------------------------------------------------------------------------

@app.middleware("http")
async def transport_auth_middleware(request: Request, call_next) -> Response:
    """
    Enforce Bearer JWT on all state-mutating requests (POST, PUT, PATCH).
    Only validates token shape here; full DID-based signature verification
    is performed by verify_jwt_auth dependency on each protected endpoint.
    """
    if request.method in ("POST", "PUT", "PATCH"):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": {"code": "INVALID_JWT",
                                   "message": "Authorization: Bearer <token> header is required",
                                   "spec_ref": "Section 14.1"}},
            )
        token = auth[7:]
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            return JSONResponse(
                status_code=401,
                content={"error": {"code": "INVALID_JWT",
                                   "message": "Bearer token is not a valid JWT",
                                   "spec_ref": "Section 14.1"}},
            )
        # Verify each segment is valid base64url
        try:
            for part in parts:
                padding = (4 - len(part) % 4) % 4
                base64.urlsafe_b64decode(part + "=" * padding)
        except Exception:
            return JSONResponse(
                status_code=401,
                content={"error": {"code": "INVALID_JWT",
                                   "message": "Bearer token is not a valid JWT",
                                   "spec_ref": "Section 14.1"}},
            )
        request.state.bearer_token = token

    return await call_next(request)


@app.middleware("http")
async def content_type_middleware(request: Request, call_next) -> Response:
    """Set Content-Type on all A2CN responses. Discovery doc uses application/json."""
    response = await call_next(request)
    if request.url.path == "/.well-known/a2cn-agent":
        response.headers["content-type"] = "application/json"
    else:
        response.headers["content-type"] = A2CN_CONTENT_TYPE
    return response


# ---------------------------------------------------------------------------
# JWT auth — Section 11.1.4
# ---------------------------------------------------------------------------

# This server's own DID, used as JWT audience.  Override with A2CN_SERVER_DID env var
# or by setting server_module.SERVER_DID directly in tests.
SERVER_DID: str = os.environ.get("A2CN_SERVER_DID", "did:web:localhost")

# Anti-replay cache: (iss, jti) → expiry timestamp
_jti_store: dict[tuple[str, str], float] = {}

# Pre-registered DID documents: did → did_document dict.
# Checked before live HTTP DID resolution — used for tests and known trading partners.
_did_doc_override: dict[str, dict] = {}


def register_did_document(did: str, did_document: dict) -> None:
    """Pre-register a DID document so JWT verification skips HTTP resolution."""
    _did_doc_override[did] = did_document


def _clean_expired_jtis() -> None:
    """Remove expired entries from the JTI replay cache."""
    now = time.time()
    expired = [k for k, exp in list(_jti_store.items()) if exp < now]
    for k in expired:
        del _jti_store[k]


async def verify_jwt_auth(request: Request) -> dict:
    """
    FastAPI dependency: verifies ES256 Bearer JWT on every protected endpoint.

    Steps:
      1. Extract Bearer token from Authorization header.
      2. Decode unverified header/claims to get kid and iss.
      3. Resolve issuer DID document (_did_doc_override first, then HTTP).
      4. Find verification method matching kid; extract public key.
      5. Verify JWT signature, expiry, and audience (SERVER_DID).
      6. Enforce anti-replay via (iss, jti) tuple.

    Raises A2CNError("INVALID_JWT", ..., 401) on any failure.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise A2CNError("INVALID_JWT", "Missing or invalid Authorization header", 401)

    token = auth[7:]

    try:
        header = pyjwt.get_unverified_header(token)
        kid = header.get("kid", "")
        unverified = pyjwt.decode(token, options={"verify_signature": False})
        iss = unverified.get("iss", "")

        if not iss:
            raise A2CNError("INVALID_JWT", "JWT missing iss claim", 401)

        # Resolve DID document (override dict first, then HTTP)
        if iss in _did_doc_override:
            did_doc = _did_doc_override[iss]
        else:
            try:
                async with httpx.AsyncClient() as http:
                    did_doc = await resolve_did_web(iss, http)
            except Exception as exc:
                raise A2CNError("INVALID_JWT", f"Could not resolve issuer DID: {exc}", 401)

        # Find verification method and extract public key
        try:
            vm = get_verification_method(did_doc, kid)
            pub_key = get_public_key(vm)
        except (KeyError, ValueError) as exc:
            raise A2CNError("INVALID_JWT", f"Verification method not found: {exc}", 401)

        # Verify signature, expiry, and audience
        try:
            claims = verify_jwt(token, pub_key, expected_audience=SERVER_DID)
        except Exception as exc:
            raise A2CNError("INVALID_JWT", f"JWT validation failed: {exc}", 401)

        # Anti-replay: reject reuse of any (iss, jti) pair
        jti = claims.get("jti", "")
        if jti:
            _clean_expired_jtis()
            key = (iss, jti)
            if key in _jti_store:
                raise A2CNError("INVALID_JWT", "JWT already used (replay detected)", 401)
            exp = float(claims.get("exp", time.time() + 600))
            _jti_store[key] = exp

        return claims

    except A2CNError:
        raise
    except Exception as exc:
        raise A2CNError("INVALID_JWT", f"JWT processing error: {exc}", 401)


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
# GET /.well-known/a2cn-agent — Discovery document (Component 1, Section 4.3)
# ---------------------------------------------------------------------------

@app.get("/.well-known/a2cn-agent")
async def get_discovery() -> Response:
    """Return the A2CN discovery document. No authentication required."""
    cfg = _responder_config
    agent_info = cfg.get("agent_info", {})
    return a2cn_response({
        "a2cn_version": "0.2",
        "agent_did": agent_info.get("did", ""),
        "conformance_level": 2,
        "deal_types": cfg.get("deal_types", ["saas_renewal"]),
        "mandate_methods": ["declared"],
        "endpoint": agent_info.get("endpoint", ""),
        "agent_id": agent_info.get("agent_id", ""),
        "verification_method": agent_info.get("verification_method", ""),
    })


# ---------------------------------------------------------------------------
# POST /sessions — SessionInit
# ---------------------------------------------------------------------------

@app.post("/sessions")
async def create_session(request: Request, _jwt: dict = Depends(verify_jwt_auth)) -> Response:
    # Transport auth enforced by middleware. DID-based key verification: TODO v0.3
    body = await _parse_body(request)
    message_id = body.get("message_id", "")

    # Idempotency check (Section 6.1)
    if manager.has_init_response(message_id):
        return a2cn_response(manager.get_init_response(message_id), 200)

    # Validate required fields
    _require(body, ["message_type", "message_id", "protocol_version", "session_params", "initiator", "initiator_mandate"])

    if body.get("message_type") != "session_init":
        return error_response("WRONG_MESSAGE_TYPE", "Expected message_type 'session_init'", 400, message_id=message_id)

    if body.get("protocol_version") != "0.2":
        return error_response("PROTOCOL_VERSION_MISMATCH", "Only protocol_version '0.2' is supported", 400, message_id=message_id)

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
        "protocol_version": "0.2",
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
async def get_session(session_id: str, request: Request,
                      _jwt: dict = Depends(verify_jwt_auth)) -> Response:
    session = _get_session_or_404(session_id)
    return a2cn_response(session.to_state_dict())


# ---------------------------------------------------------------------------
# POST /sessions/{session_id}/messages — send any session message
# ---------------------------------------------------------------------------

@app.post("/sessions/{session_id}/messages")
async def send_message(session_id: str, request: Request,
                       _jwt: dict = Depends(verify_jwt_auth)) -> Response:
    # Transport auth enforced by middleware. DID-based key verification: TODO v0.3
    session = _get_session_or_404(session_id)
    body = await _parse_body(request)

    # Bind JWT issuer to session and sender identity (Section 14.1)
    body_session_id = body.get("session_id")
    if body_session_id is not None and body_session_id != session_id:
        return error_response("SESSION_ID_MISMATCH",
                               "session_id in request body does not match URL path",
                               400, session_id=session_id)
    body_sender_did = body.get("sender_did", "")
    if body_sender_did and body_sender_did != _jwt.get("iss", ""):
        return error_response("SENDER_DID_MISMATCH",
                               "JWT issuer does not match sender_did in request body",
                               401, detail="Section 14.1", session_id=session_id)

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
                       _jwt: dict = Depends(verify_jwt_auth),
                       after_sequence: int = 0, limit: int = 50) -> Response:
    session = _get_session_or_404(session_id)
    jwt_iss = _jwt.get("iss", "")
    if jwt_iss not in (session.initiator_info.get("did"), session.responder_info.get("did")):
        return error_response("NOT_SESSION_PARTY",
                               "JWT issuer is not a party to this session",
                               403, session_id=session_id)
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
async def get_record(session_id: str, request: Request,
                     _jwt: dict = Depends(verify_jwt_auth)) -> Response:
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
async def get_audit(session_id: str, request: Request,
                    _jwt: dict = Depends(verify_jwt_auth)) -> Response:
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
# v0.3 planned: Post-commitment lifecycle endpoints (OQ-017)
# ---------------------------------------------------------------------------

@app.post("/sessions/{session_id}/delivery-notice")
async def post_delivery_notice(session_id: str, request: Request,
                               _jwt: dict = Depends(verify_jwt_auth)) -> Response:
    # Transport auth enforced by middleware. DID-based key verification: TODO v0.3
    session = _get_session_or_404(session_id)
    body = await _parse_body(request)

    if body.get("session_id") is not None and body.get("session_id") != session_id:
        return error_response("SESSION_ID_MISMATCH",
                               "session_id in request body does not match URL path",
                               400, session_id=session_id)

    if session.state != SessionState.COMPLETED:
        return error_response(
            "SESSION_WRONG_STATE",
            "Delivery notice requires a COMPLETED session",
            409,
            session_id=session_id,
        )

    try:
        record = generate_transaction_record(session)
    except Exception as exc:
        return error_response("INTERNAL_ERROR", f"Could not generate transaction record: {exc}", 500, session_id=session_id)

    if body.get("transaction_record_hash") != record["record_hash"]:
        return error_response(
            "INVALID_RECORD_HASH",
            "transaction_record_hash does not match the agreed transaction record",
            409,
            session_id=session_id,
        )

    message_id = body.get("message_id", str(uuid.uuid4()))
    pc_data = _session_store.get(session_id) or {}
    pc_data["delivery_notice"] = body
    pc_data["delivery_notice_message_id"] = message_id
    _session_store.save(session_id, pc_data)

    return a2cn_response({
        "delivery_notice_message_id": message_id,
        "session_id": session_id,
        "status": "DELIVERY_NOTICE_RECORDED",
    })


@app.post("/sessions/{session_id}/delivery-acknowledged")
async def post_delivery_acknowledged(session_id: str, request: Request,
                                     _jwt: dict = Depends(verify_jwt_auth)) -> Response:
    # Transport auth enforced by middleware. DID-based key verification: TODO v0.3
    session = _get_session_or_404(session_id)
    body = await _parse_body(request)

    if body.get("session_id") is not None and body.get("session_id") != session_id:
        return error_response("SESSION_ID_MISMATCH",
                               "session_id in request body does not match URL path",
                               400, session_id=session_id)

    pc_data = _session_store.get(session_id) or {}

    if "delivery_notice" not in pc_data:
        return error_response(
            "NO_DELIVERY_NOTICE",
            "No delivery notice found for this session",
            409,
            session_id=session_id,
        )

    stored_notice_id = pc_data.get("delivery_notice_message_id")
    if body.get("delivery_notice_message_id") != stored_notice_id:
        return error_response(
            "INVALID_REFERENCE",
            "delivery_notice_message_id does not match the stored delivery notice",
            409,
            session_id=session_id,
        )

    try:
        record = generate_transaction_record(session)
    except Exception as exc:
        return error_response("INTERNAL_ERROR", f"Could not generate transaction record: {exc}", 500, session_id=session_id)

    if body.get("transaction_record_hash") != record["record_hash"]:
        return error_response(
            "INVALID_RECORD_HASH",
            "transaction_record_hash does not match the agreed transaction record",
            409,
            session_id=session_id,
        )

    accepted = body.get("accepted", False)
    post_commitment_status = "CLOSED" if accepted else "DISPUTED"
    message_id = body.get("message_id", str(uuid.uuid4()))

    pc_data["post_commitment_status"] = post_commitment_status
    if not accepted:
        pc_data["dispute_reason"] = body.get("notes", "")
    pc_data["acknowledgment_message_id"] = message_id
    _session_store.save(session_id, pc_data)

    return a2cn_response({
        "acknowledgment_message_id": message_id,
        "session_id": session_id,
        "post_commitment_status": post_commitment_status,
    })


@app.post("/sessions/{session_id}/dispute-notice")
async def post_dispute_notice(session_id: str, request: Request,
                              _jwt: dict = Depends(verify_jwt_auth)) -> Response:
    # Transport auth enforced by middleware. DID-based key verification: TODO v0.3
    session = _get_session_or_404(session_id)
    body = await _parse_body(request)

    if body.get("session_id") is not None and body.get("session_id") != session_id:
        return error_response("SESSION_ID_MISMATCH",
                               "session_id in request body does not match URL path",
                               400, session_id=session_id)

    pc_data = _session_store.get(session_id) or {}

    if session.state != SessionState.COMPLETED and "delivery_notice" not in pc_data:
        return error_response(
            "SESSION_WRONG_STATE",
            "Dispute notice requires a COMPLETED session or a recorded delivery notice",
            409,
            session_id=session_id,
        )

    try:
        record = generate_transaction_record(session)
    except Exception as exc:
        return error_response("INTERNAL_ERROR", f"Could not generate transaction record: {exc}", 500, session_id=session_id)

    if body.get("transaction_record_hash") != record["record_hash"]:
        return error_response(
            "INVALID_RECORD_HASH",
            "transaction_record_hash does not match the agreed transaction record",
            409,
            session_id=session_id,
        )

    message_id = body.get("message_id", str(uuid.uuid4()))
    pc_data["dispute_notice"] = body
    pc_data["post_commitment_status"] = "DISPUTED"
    pc_data["dispute_notice_message_id"] = message_id
    _session_store.save(session_id, pc_data)

    return a2cn_response({
        "dispute_notice_message_id": message_id,
        "session_id": session_id,
        "post_commitment_status": "DISPUTED",
        "note": "Dispute recorded. Route to neutral resolver via Meeting Place or designated dispute resolution service.",
    })


# ---------------------------------------------------------------------------
# v0.2.0: Invitation endpoints (Component 8)
# ---------------------------------------------------------------------------

# Route order matters: /invitations/create must be declared before
# /invitations/{invitation_id} so FastAPI doesn't treat "create" as an ID.

@app.post("/invitations/create", status_code=201)
async def create_invitation_endpoint(request: Request,
                                     _jwt: dict = Depends(verify_jwt_auth)) -> Response:
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

    # Signature verification: resolve inviter DID to get public key.
    # Skipped only if inviter_did or inviter_verification_method is absent.
    inviter_did = body.get("inviter_did", "")
    vm_id = body.get("inviter_verification_method", "")
    if inviter_did and vm_id:
        # Resolve DID document (_did_doc_override first, then HTTP)
        if inviter_did in _did_doc_override:
            did_doc = _did_doc_override[inviter_did]
        else:
            try:
                async with httpx.AsyncClient() as http:
                    did_doc = await resolve_did_web(inviter_did, http)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    return error_response(INVITATION_SIGNATURE_INVALID, "Inviter DID not found", 403)
                return error_response("DID_RESOLUTION_FAILED", "Temporary DID resolution failure", 503)
            except Exception:
                return error_response("DID_RESOLUTION_FAILED", "Temporary DID resolution failure", 503)

        try:
            vm = get_verification_method(did_doc, vm_id)
            pub_key = get_public_key(vm)
        except (KeyError, ValueError) as exc:
            return error_response(INVITATION_SIGNATURE_INVALID,
                                  f"Verification method not found: {exc}", 400)

        if not verify_invitation_signature(body, pub_key):
            return error_response(INVITATION_SIGNATURE_INVALID, "Invitation signature is invalid", 400)

    invitation_store.store_inbound(body)
    return a2cn_response({"invitation_id": body.get("invitation_id"), "status": "pending"}, 201)


@app.post("/invitations/{invitation_id}/accept")
async def accept_invitation_endpoint(invitation_id: str, request: Request,
                                     _jwt: dict = Depends(verify_jwt_auth)) -> Response:
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
async def decline_invitation_endpoint(invitation_id: str, request: Request,
                                      _jwt: dict = Depends(verify_jwt_auth)) -> Response:
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
    await deliver_webhook(webhook_url, event_type, session.session_id, payload.to_dict())


# Webhook signing: v0.2 uses HMAC-SHA256 with session_id as key material.
# v0.3 will upgrade to ES256 signed JWS envelope using sender DID verification method.
# Receivers MUST verify X-A2CN-Signature before processing webhook payloads.
async def deliver_webhook(url: str, event_type: str, session_id: str, payload: dict,
                          retry_config: dict = None) -> None:
    """
    Attempt webhook delivery with signed headers.
    Backoff: 1s, 4s, 16s between attempts.
    Non-fatal — logs failures but does not raise.
    """
    import json
    body_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig_bytes = hmac.new(session_id.encode(), body_bytes, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers = {
        "Content-Type": A2CN_CONTENT_TYPE,
        "X-A2CN-Timestamp": timestamp,
        "X-A2CN-Session-ID": session_id,
        "X-A2CN-Event-Type": event_type,
        "X-A2CN-Signature": sig_b64,
    }
    max_retries = (retry_config or {}).get("max_retries", 3)
    backoff_seconds = [1, 4, 16]
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=10.0) as http:
                resp = await http.post(url, content=body_bytes, headers=headers)
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
