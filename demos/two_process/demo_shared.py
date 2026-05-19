"""Shared constants and helpers for the two-process A2CN HTTP demo."""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
PYTHON_IMPL = ROOT / "reference-implementation" / "python"
if str(PYTHON_IMPL) not in sys.path:
    sys.path.insert(0, str(PYTHON_IMPL))

from a2cn.crypto import (  # noqa: E402
    create_jwt,
    hash_object,
    private_key_from_jwk,
    public_key_to_jwk,
    sign_jws,
)

BUYER_DID = "did:web:buyer.demo"
SUPPLIER_DID = "did:web:supplier.demo"

BUYER_PORT = 8001
SUPPLIER_PORT = 8002
BUYER_URL = f"http://127.0.0.1:{BUYER_PORT}"
SUPPLIER_URL = f"http://127.0.0.1:{SUPPLIER_PORT}"

BUYER_KEY_ID = f"{BUYER_DID}#key-1"
SUPPLIER_KEY_ID = f"{SUPPLIER_DID}#key-1"

BUYER_PRIVATE_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "yBqAozmK34lgmawkZJiql8cV8mBdLvmyVH8AHrThJHo",
    "y": "YlgfTYFme_XeFKLxzh0LLOKi-q7x6sqZAyGBVbglaX4",
    "d": "XZJC7OiOPA9RvV6yobPgm1kZdg9htDWgIxXP0wDT6b0",
}

SUPPLIER_PRIVATE_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "6vLBotDYauSe6zbkEWMLxM84MYXIXbsvqRU-yfvdOAM",
    "y": "iENZCpZVUyC63C9Y7fhtZ6z367TNAm1Iebia49zfGzY",
    "d": "Fp0yOmzWBBlaSTbhggddYAZEt97_mGyjSI6BUBywS9k",
}


class FreshJwtAuth(httpx.Auth):
    """Attach a fresh A2CN ES256 bearer JWT to every request."""

    def __init__(self, issuer_did: str, audience_did: str, private_key: Any, kid: str) -> None:
        self.issuer_did = issuer_did
        self.audience_did = audience_did
        self.private_key = private_key
        self.kid = kid

    def auth_flow(self, request):
        token = create_jwt(
            self.issuer_did,
            self.audience_did,
            self.private_key,
            kid=self.kid,
            exp_seconds=300,
        )
        request.headers["Authorization"] = f"Bearer {token}"
        yield request


def buyer_private_key():
    return private_key_from_jwk(BUYER_PRIVATE_JWK)


def supplier_private_key():
    return private_key_from_jwk(SUPPLIER_PRIVATE_JWK)


def did_document(did: str, key_id: str, private_key: Any) -> dict:
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_key_to_jwk(private_key.public_key()),
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


def buyer_agent_info() -> dict:
    return {
        "organization_name": "TechCorp Inc",
        "did": BUYER_DID,
        "verification_method": BUYER_KEY_ID,
        "agent_id": "procurement-agent-techcorp-demo",
        "endpoint": BUYER_URL,
    }


def supplier_agent_info() -> dict:
    return {
        "organization_name": "Acme Corp",
        "did": SUPPLIER_DID,
        "verification_method": SUPPLIER_KEY_ID,
        "agent_id": "sales-agent-acme-demo",
        "endpoint": SUPPLIER_URL,
    }


def buyer_mandate() -> dict:
    return {
        "mandate_type": "declared",
        "agent_id": "procurement-agent-techcorp-demo",
        "principal_organization": "TechCorp Inc",
        "principal_did": BUYER_DID,
        "authorized_deal_types": ["saas_renewal"],
        "max_commitment_value": 15_000_000,
        "max_commitment_currency": "USD",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T00:00:00Z",
    }


def supplier_mandate() -> dict:
    return {
        "mandate_type": "declared",
        "agent_id": "sales-agent-acme-demo",
        "principal_organization": "Acme Corp",
        "principal_did": SUPPLIER_DID,
        "authorized_deal_types": ["saas_renewal"],
        "max_commitment_value": 20_000_000,
        "max_commitment_currency": "USD",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T00:00:00Z",
    }


def session_params() -> dict:
    return {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "subject": "Acme Analytics Platform - annual renewal FY2027",
        "subject_reference": "CONTRACT-2024-ACME-001",
        "estimated_value": 12_000_000,
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    }


def renewal_terms(total_value: int, net_days: int) -> dict:
    return {
        "total_value": total_value,
        "currency": "USD",
        "line_items": [
            {
                "id": "li-1",
                "description": "Acme Analytics Platform - 12 months",
                "quantity": 1,
                "unit": "year",
                "unit_price": total_value,
                "total": total_value,
            }
        ],
        "payment_terms": {"net_days": net_days},
        "contract_duration": {
            "start_date": "2026-07-01",
            "end_date": "2027-06-30",
            "auto_renewal": False,
            "cancellation_notice_days": 60,
        },
    }


def now_iso(offset_seconds: int = 0) -> str:
    t = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def supplier_counteroffer(session: Any, terms: dict, in_reply_to: str) -> dict:
    sequence_number = session.sequence_number + 1
    round_number = session.round_number + 1
    message_id = str(uuid.uuid4())
    timestamp = now_iso()
    expires_at = now_iso(900)
    private_key = supplier_private_key()
    protocol_act = {
        "protocol_version": "0.2",
        "session_id": session.session_id,
        "round_number": round_number,
        "sequence_number": sequence_number,
        "message_type": "counteroffer",
        "sender_did": SUPPLIER_DID,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
    }
    protocol_act_hash = hash_object(protocol_act)
    return {
        "message_type": "counteroffer",
        "message_id": message_id,
        "session_id": session.session_id,
        "in_reply_to": in_reply_to,
        "round_number": round_number,
        "sequence_number": sequence_number,
        "sender_did": SUPPLIER_DID,
        "sender_agent_id": supplier_agent_info()["agent_id"],
        "sender_verification_method": SUPPLIER_KEY_ID,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
        "protocol_act_hash": protocol_act_hash,
        "protocol_act_signature": sign_jws(
            protocol_act_hash,
            private_key,
            kid=SUPPLIER_KEY_ID,
        ),
    }
