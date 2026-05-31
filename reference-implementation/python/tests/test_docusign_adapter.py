"""Tests for DocuSign eSignature / Connect adapter."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from adapters.docusign_adapter import (
    DOCUSIGN_JWT_GRANT_TYPE,
    DocuSignConnectParser,
    a2cn_record_to_docusign_envelope,
    docusign_auth_headers,
    docusign_envelope_create_request,
    fetch_docusign_access_token,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


SAMPLE_RECORD = {
    "record_type": "a2cn_transaction_record",
    "record_id": "record-001",
    "session_id": "sess-001",
    "record_hash": "abc123" * 10,
    "deal_type": "saas_renewal",
    "currency": "USD",
    "parties": {
        "initiator": {
            "organization_name": "Buyer Co",
            "did": "did:web:buyer.example",
        },
        "responder": {
            "organization_name": "Seller Co",
            "did": "did:web:seller.example",
        },
    },
    "agreed_terms": {
        "total_value": 10_000_000,
        "currency": "USD",
        "seat_count": 100,
        "subscription_tier": "Enterprise",
        "term_months": 12,
        "payment_terms": {"net_days": 45},
        "line_items": [
            {
                "description": "Enterprise Subscription",
                "quantity": 100,
                "unit_price": 95_000,
                "total": 9_500_000,
            },
            {
                "description": "Premium Support",
                "quantity": 1,
                "unit_price": 500_000,
                "total": 500_000,
            },
        ],
    },
}

SIGNER_CONTACTS = {
    "did:web:buyer.example": {
        "name": "Buyer Legal",
        "email": "legal@buyer.example",
    },
    "did:web:seller.example": {
        "name": "Seller Legal",
        "email": "legal@seller.example",
    },
}


def _make_async_client_mock(json_data: dict):
    mock_response = MagicMock()
    mock_response.json.return_value = json_data
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    return mock_cm, mock_client


def _private_key_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


class TestDocuSignEnvelopeMapping:
    def test_record_to_envelope_maps_documents_recipients_and_custom_fields(self):
        envelope = a2cn_record_to_docusign_envelope(
            SAMPLE_RECORD,
            SIGNER_CONTACTS,
            connect_url="https://middleware.example.com/docusign/connect",
        )

        assert envelope["status"] == "sent"
        assert envelope["emailSubject"] == "A2CN agreement for session sess-001"
        assert envelope["documents"][0]["documentId"] == "1"
        assert envelope["documents"][0]["fileExtension"] == "txt"
        signers = envelope["recipients"]["signers"]
        assert signers[0]["email"] == "legal@buyer.example"
        assert signers[0]["name"] == "Buyer Legal"
        assert signers[1]["email"] == "legal@seller.example"
        assert signers[1]["name"] == "Seller Legal"
        fields = envelope["customFields"]["textCustomFields"]
        assert {"name": "a2cn_session_id", "value": "sess-001", "show": "false"} in fields
        assert {"name": "a2cn_record_hash", "value": SAMPLE_RECORD["record_hash"], "show": "false"} in fields
        assert envelope["eventNotification"]["url"] == "https://middleware.example.com/docusign/connect"

    def test_generated_document_contains_record_hash_and_terms(self):
        envelope = a2cn_record_to_docusign_envelope(SAMPLE_RECORD, SIGNER_CONTACTS)
        document_text = base64.b64decode(
            envelope["documents"][0]["documentBase64"]
        ).decode("utf-8")

        assert "A2CN Transaction Terms Summary" in document_text
        assert "Session ID: sess-001" in document_text
        assert f"Record Hash: {SAMPLE_RECORD['record_hash']}" in document_text
        assert "Seat count: 100" in document_text
        assert "Term months: 12" in document_text
        assert "\\s1\\" in document_text
        assert "\\s2\\" in document_text

    def test_missing_signer_email_is_rejected(self):
        with pytest.raises(ValueError, match="Missing signer email"):
            a2cn_record_to_docusign_envelope(
                SAMPLE_RECORD,
                {"did:web:buyer.example": {"email": "legal@buyer.example"}},
            )

    def test_envelope_create_request_uses_v21_account_path(self):
        envelope = a2cn_record_to_docusign_envelope(SAMPLE_RECORD, SIGNER_CONTACTS)

        request = docusign_envelope_create_request(
            account_id="acct-001",
            envelope_definition=envelope,
            base_uri="https://demo.docusign.net/",
        )

        assert request["method"] == "POST"
        assert request["url"] == "https://demo.docusign.net/restapi/v2.1/accounts/acct-001/envelopes"
        assert request["json"] == envelope


class TestDocuSignConnectParser:
    def test_parse_completed_envelope_event(self):
        payload = {
            "event": "envelope-completed",
            "data": {
                "envelopeId": "env-001",
                "envelopeSummary": {
                    "status": "completed",
                    "customFields": {
                        "textCustomFields": [
                            {"name": "a2cn_session_id", "value": "sess-001"},
                            {"name": "a2cn_record_hash", "value": "hash-001"},
                        ]
                    },
                },
            },
        }

        update = DocuSignConnectParser.parse_envelope_event(payload)

        assert update["provider"] == "docusign"
        assert update["event"] == "envelope-completed"
        assert update["envelope_id"] == "env-001"
        assert update["envelope_status"] == "completed"
        assert update["post_commitment_status"] == "signature_completed"
        assert update["a2cn_session_id"] == "sess-001"
        assert update["a2cn_record_hash"] == "hash-001"
        assert update["completed"] is True

    def test_parse_declined_envelope_event(self):
        update = DocuSignConnectParser.parse_envelope_event({
            "event": "envelope-declined",
            "data": {
                "envelopeId": "env-002",
                "envelopeStatus": "declined",
            },
        })

        assert update["post_commitment_status"] == "signature_declined"
        assert update["completed"] is False

    def test_parse_completed_event_name_without_explicit_status(self):
        update = DocuSignConnectParser.parse_envelope_event({
            "event": "envelope-completed",
            "data": {
                "envelopeId": "env-003",
            },
        })

        assert update["envelope_status"] == "completed"
        assert update["post_commitment_status"] == "signature_completed"
        assert update["completed"] is True

    def test_verify_hmac_signature_accepts_valid_signature(self):
        payload_bytes = json.dumps({"event": "envelope-completed"}).encode("utf-8")
        signature = base64.b64encode(
            hmac.new(b"secret", payload_bytes, hashlib.sha256).digest()
        ).decode("ascii")

        assert DocuSignConnectParser.verify_hmac_signature(
            payload_bytes,
            signature,
            "secret",
        )

    def test_verify_hmac_signature_rejects_tampered_payload(self):
        payload_bytes = json.dumps({"event": "envelope-completed"}).encode("utf-8")
        signature = base64.b64encode(
            hmac.new(b"secret", payload_bytes, hashlib.sha256).digest()
        ).decode("ascii")

        assert not DocuSignConnectParser.verify_hmac_signature(
            b'{"event":"envelope-voided"}',
            signature,
            "secret",
        )


class TestDocuSignAuthHelpers:
    def test_docusign_auth_headers(self):
        headers = docusign_auth_headers("access-token")

        assert headers == {
            "Authorization": "Bearer access-token",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @pytest.mark.asyncio
    async def test_fetch_docusign_access_token_uses_jwt_bearer_grant(self):
        mock_cm, mock_client = _make_async_client_mock({"access_token": "token-123"})
        private_key = _private_key_pem()
        with patch("adapters.docusign_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "DOCUSIGN_INTEGRATION_KEY": "integration-key",
                "DOCUSIGN_USER_ID": "user-guid",
                "DOCUSIGN_PRIVATE_KEY": private_key,
                "DOCUSIGN_AUTH_BASE_URI": "https://account-d.docusign.com",
            }):
                token = await fetch_docusign_access_token(now=1_700_000_000)

        assert token == "token-123"
        _, kwargs = mock_client.post.call_args
        assert kwargs["data"]["grant_type"] == DOCUSIGN_JWT_GRANT_TYPE
        decoded = pyjwt.decode(
            kwargs["data"]["assertion"],
            options={"verify_signature": False},
        )
        assert decoded["iss"] == "integration-key"
        assert decoded["sub"] == "user-guid"
        assert decoded["aud"] == "account-d.docusign.com"
        assert decoded["scope"] == "signature impersonation"
        assert kwargs["headers"] == {"Accept": "application/json"}

    @pytest.mark.asyncio
    async def test_fetch_docusign_access_token_uses_custom_scope_and_auth_uri(self):
        mock_cm, mock_client = _make_async_client_mock({"access_token": "token-123"})
        private_key = _private_key_pem()
        with patch("adapters.docusign_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "DOCUSIGN_INTEGRATION_KEY": "integration-key",
                "DOCUSIGN_USER_ID": "user-guid",
                "DOCUSIGN_PRIVATE_KEY": private_key,
                "DOCUSIGN_SCOPE": "signature impersonation click.manage",
            }):
                token = await fetch_docusign_access_token(
                    auth_base_uri="https://account.docusign.com",
                    now=1_700_000_000,
                )

        assert token == "token-123"
        _, kwargs = mock_client.post.call_args
        decoded = pyjwt.decode(
            kwargs["data"]["assertion"],
            options={"verify_signature": False},
        )
        assert decoded["aud"] == "account.docusign.com"
        assert decoded["scope"] == "signature impersonation click.manage"
        assert mock_client.post.call_args.args[0] == "https://account.docusign.com/oauth/token"

    @pytest.mark.asyncio
    async def test_fetch_docusign_access_token_requires_env(self):
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {
                "DOCUSIGN_INTEGRATION_KEY",
                "DOCUSIGN_USER_ID",
                "DOCUSIGN_PRIVATE_KEY",
            }
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="DOCUSIGN_INTEGRATION_KEY"):
                await fetch_docusign_access_token()
