"""
DocuSign eSignature/CLM -> A2CN formalization adapter.

Translates an A2CN transaction record into a DocuSign eSignature envelope
definition, and translates DocuSign Connect webhook notifications into a small
post-commitment status update shape.

Public documentation used for this adapter:
  eSignature REST API:
    POST /restapi/v2.1/accounts/{accountId}/envelopes
    EnvelopeDefinition: status, emailSubject, documents, recipients
  DocuSign Connect:
    envelope event notifications, completed envelope events, HMAC signatures
  OAuth:
    JWT bearer grant with integration key, user ID, account ID, and RSA key

No core protocol changes are required. A2CN remains the neutral bilateral
transaction record; DocuSign executes signature and downstream CLM workflow.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from typing import Any

import httpx
import jwt as pyjwt


DOCUSIGN_JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
DOCUSIGN_DEMO_AUTH_BASE_URI = "https://account-d.docusign.com"
DOCUSIGN_PROD_AUTH_BASE_URI = "https://account.docusign.com"


def _money_to_decimal(cents: Any) -> float:
    if cents is None or cents == "":
        return 0.0
    return int(cents) / 100.0


def _party_label(role: str, party: dict) -> str:
    organization = party.get("organization_name") or role.title()
    did = party.get("did", "")
    return f"{organization} ({did})" if did else organization


def _get_contact(
    party: dict,
    signer_contacts: dict[str, dict] | None,
) -> dict:
    did = party.get("did", "")
    contact = (signer_contacts or {}).get(did, {})
    name = contact.get("name") or party.get("organization_name") or did
    email = contact.get("email") or party.get("email")
    if not email:
        raise ValueError(f"Missing signer email for party DID {did!r}.")
    return {"name": name, "email": email}


def _terms_summary_text(record: dict) -> str:
    terms = record.get("agreed_terms", {})
    parties = record.get("parties", {})
    lines = [
        "A2CN Transaction Terms Summary",
        "",
        f"Session ID: {record.get('session_id', '')}",
        f"Record Hash: {record.get('record_hash', '')}",
        f"Deal Type: {record.get('deal_type', '')}",
        f"Currency: {record.get('currency', terms.get('currency', ''))}",
        f"Total Value: {_money_to_decimal(terms.get('total_value', 0)):.2f}",
        "",
        "Parties:",
        f"- Initiator: {_party_label('initiator', parties.get('initiator', {}))}",
        f"- Responder: {_party_label('responder', parties.get('responder', {}))}",
        "",
        "Agreed Terms:",
    ]
    if terms.get("seat_count") is not None:
        lines.append(f"- Seat count: {terms['seat_count']}")
    if terms.get("subscription_tier"):
        lines.append(f"- Subscription tier: {terms['subscription_tier']}")
    if terms.get("term_months") is not None:
        lines.append(f"- Term months: {terms['term_months']}")
    if terms.get("delivery_days") is not None:
        lines.append(f"- Delivery days: {terms['delivery_days']}")
    if terms.get("payment_terms", {}).get("net_days") is not None:
        lines.append(f"- Payment terms: Net {terms['payment_terms']['net_days']}")
    if terms.get("contract_duration"):
        duration = terms["contract_duration"]
        lines.append(
            f"- Contract duration: {duration.get('start_date', '')} to "
            f"{duration.get('end_date', '')}"
        )
    line_items = terms.get("line_items", [])
    if line_items:
        lines.append("")
        lines.append("Line Items:")
        for item in line_items:
            lines.append(
                "- "
                f"{item.get('description', '')}: "
                f"qty {item.get('quantity', 1)}, "
                f"unit {_money_to_decimal(item.get('unit_price', 0)):.2f}, "
                f"total {_money_to_decimal(item.get('total', 0)):.2f}"
            )
    lines.extend([
        "",
        "This document is generated from the A2CN dual-signed transaction record.",
        "\\s1\\",
        "\\s2\\",
    ])
    return "\n".join(lines)


def a2cn_record_to_docusign_envelope(
    record: dict,
    signer_contacts: dict[str, dict],
    *,
    email_subject: str | None = None,
    status: str = "sent",
    connect_url: str | None = None,
) -> dict:
    """
    Build a DocuSign eSignature envelope definition for an A2CN record.

    ``signer_contacts`` maps party DID to ``{"name": ..., "email": ...}``.
    The record itself remains the canonical agreement; the envelope signs a
    generated terms-summary document that references the A2CN record hash.
    """
    parties = record.get("parties", {})
    initiator = parties.get("initiator", {})
    responder = parties.get("responder", {})
    initiator_contact = _get_contact(initiator, signer_contacts)
    responder_contact = _get_contact(responder, signer_contacts)
    summary_text = _terms_summary_text(record)
    document_b64 = base64.b64encode(summary_text.encode("utf-8")).decode("ascii")

    envelope: dict = {
        "emailSubject": email_subject or (
            f"A2CN agreement for session {record.get('session_id', '')}"
        ),
        "status": status,
        "documents": [
            {
                "documentBase64": document_b64,
                "name": "A2CN Transaction Terms Summary.txt",
                "fileExtension": "txt",
                "documentId": "1",
            }
        ],
        "recipients": {
            "signers": [
                {
                    "email": initiator_contact["email"],
                    "name": initiator_contact["name"],
                    "recipientId": "1",
                    "routingOrder": "1",
                    "tabs": {
                        "signHereTabs": [
                            {
                                "anchorString": "\\s1\\",
                                "anchorUnits": "pixels",
                                "anchorXOffset": "0",
                                "anchorYOffset": "0",
                            }
                        ]
                    },
                },
                {
                    "email": responder_contact["email"],
                    "name": responder_contact["name"],
                    "recipientId": "2",
                    "routingOrder": "1",
                    "tabs": {
                        "signHereTabs": [
                            {
                                "anchorString": "\\s2\\",
                                "anchorUnits": "pixels",
                                "anchorXOffset": "0",
                                "anchorYOffset": "0",
                            }
                        ]
                    },
                },
            ]
        },
        "customFields": {
            "textCustomFields": [
                {
                    "name": "a2cn_session_id",
                    "value": record.get("session_id", ""),
                    "show": "false",
                },
                {
                    "name": "a2cn_record_hash",
                    "value": record.get("record_hash", ""),
                    "show": "false",
                },
                {
                    "name": "a2cn_record_id",
                    "value": record.get("record_id", ""),
                    "show": "false",
                },
            ]
        },
    }
    if connect_url:
        envelope["eventNotification"] = {
            "url": connect_url,
            "loggingEnabled": "true",
            "requireAcknowledgment": "true",
            "includeDocuments": "false",
            "includeCertificateOfCompletion": "true",
            "envelopeEvents": [
                {"envelopeEventStatusCode": "completed"},
                {"envelopeEventStatusCode": "declined"},
                {"envelopeEventStatusCode": "voided"},
            ],
        }
    return envelope


class DocuSignConnectParser:
    """
    Parses DocuSign Connect webhook notifications into A2CN status updates.
    """

    @staticmethod
    def verify_hmac_signature(
        payload_bytes: bytes,
        signature_header: str,
        secret: str | bytes,
    ) -> bool:
        if not payload_bytes or not signature_header or not secret:
            return False
        key = secret.encode("utf-8") if isinstance(secret, str) else secret
        expected = base64.b64encode(
            hmac.new(key, payload_bytes, hashlib.sha256).digest()
        ).decode("ascii")
        candidates = [
            part.strip()
            for part in signature_header.replace(",", " ").split()
            if part.strip()
        ]
        return any(hmac.compare_digest(expected, candidate) for candidate in candidates)

    @staticmethod
    def parse_envelope_event(payload: dict) -> dict:
        """
        Parse a DocuSign Connect JSON payload into a post-commitment update.
        """
        data = payload.get("data") or {}
        envelope_summary = data.get("envelopeSummary") or payload.get("envelopeSummary") or {}
        envelope_id = (
            data.get("envelopeId")
            or envelope_summary.get("envelopeId")
            or payload.get("envelopeId")
            or ""
        )
        status = (
            data.get("envelopeStatus")
            or envelope_summary.get("status")
            or payload.get("status")
            or payload.get("event")
            or ""
        )
        status_normalized = str(status).lower()
        custom_fields = _custom_fields_from_payload(data, envelope_summary, payload)
        event_name = payload.get("event") or payload.get("eventName") or ""
        return {
            "provider": "docusign",
            "event": event_name,
            "envelope_id": envelope_id,
            "envelope_status": status_normalized,
            "post_commitment_status": _post_commitment_status(status_normalized),
            "a2cn_session_id": custom_fields.get("a2cn_session_id", ""),
            "a2cn_record_hash": custom_fields.get("a2cn_record_hash", ""),
            "completed": status_normalized == "completed",
            "raw_payload": payload,
        }


def _custom_fields_from_payload(*sections: dict) -> dict:
    fields: dict[str, str] = {}
    for section in sections:
        custom_fields = section.get("customFields", {})
        text_fields = (
            custom_fields.get("textCustomFields")
            or section.get("customFields", {}).get("textCustomFields")
            or []
        )
        if isinstance(text_fields, dict):
            text_fields = text_fields.get("textCustomField", [])
        for item in text_fields:
            name = item.get("name")
            value = item.get("value")
            if name:
                fields[str(name)] = "" if value is None else str(value)
    return fields


def _post_commitment_status(envelope_status: str) -> str:
    if envelope_status == "completed":
        return "signature_completed"
    if envelope_status == "declined":
        return "signature_declined"
    if envelope_status == "voided":
        return "signature_voided"
    return "signature_pending"


def docusign_envelope_create_request(
    account_id: str,
    envelope_definition: dict,
    base_uri: str | None = None,
) -> dict:
    """
    Build the documented eSignature create-envelope request shape.
    """
    resolved_base_uri = (base_uri or os.environ.get("DOCUSIGN_BASE_URI") or "").rstrip("/")
    if not resolved_base_uri:
        raise ValueError("DOCUSIGN_BASE_URI or base_uri is required.")
    return {
        "method": "POST",
        "url": f"{resolved_base_uri}/restapi/v2.1/accounts/{account_id}/envelopes",
        "json": envelope_definition,
    }


def docusign_auth_headers(access_token: str) -> dict:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def fetch_docusign_access_token(
    auth_base_uri: str | None = None,
    now: int | None = None,
) -> str:
    """
    Fetch a DocuSign OAuth JWT bearer token.
    """
    integration_key = os.environ.get("DOCUSIGN_INTEGRATION_KEY")
    user_id = os.environ.get("DOCUSIGN_USER_ID")
    private_key = os.environ.get("DOCUSIGN_PRIVATE_KEY")
    scope = os.environ.get("DOCUSIGN_SCOPE", "signature impersonation")
    resolved_auth_base_uri = (
        auth_base_uri
        or os.environ.get("DOCUSIGN_AUTH_BASE_URI")
        or DOCUSIGN_DEMO_AUTH_BASE_URI
    ).rstrip("/")
    if not integration_key or not user_id or not private_key:
        raise ValueError(
            "DOCUSIGN_INTEGRATION_KEY, DOCUSIGN_USER_ID, and "
            "DOCUSIGN_PRIVATE_KEY are required."
        )

    issued_at = int(now if now is not None else time.time())
    audience = resolved_auth_base_uri.removeprefix("https://")
    assertion = pyjwt.encode(
        {
            "iss": integration_key,
            "sub": user_id,
            "aud": audience,
            "iat": issued_at,
            "exp": issued_at + 3600,
            "scope": scope,
        },
        private_key,
        algorithm="RS256",
    )
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{resolved_auth_base_uri}/oauth/token",
            data={
                "grant_type": DOCUSIGN_JWT_GRANT_TYPE,
                "assertion": assertion,
            },
            headers={"Accept": "application/json"},
        )
    response.raise_for_status()
    return response.json()["access_token"]
