"""Tests for Ironclad CLM platform adapter."""

from __future__ import annotations

import base64
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from a2cn.messages import validate_deal_type_terms
from adapters.ironclad_adapter import (
    IroncladWebhookParser,
    a2cn_terms_to_ironclad_record,
    a2cn_terms_to_ironclad_workflow,
    update_ironclad_workflow_metadata,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


SAMPLE_RENEWAL_WORKFLOW = {
    "eventId": "evt-ironclad-001",
    "eventType": "workflow.updated",
    "workflow": {
        "id": "wf-001",
        "ironcladId": "IC-001",
        "title": "Enterprise Subscription Renewal - Acme Analytics",
        "step": "Review",
        "status": "active",
        "attributes": {
            "counterpartyName": "Acme Analytics",
            "contractValue": {"currency": "USD", "amount": 105000.0},
            "seatCount": 100,
            "termMonths": 12,
            "product": "Analytics Platform Enterprise",
            "paymentTermsNetDays": 45,
        },
    },
}

SAMPLE_GOODS_WORKFLOW = {
    "eventId": "evt-ironclad-002",
    "eventType": "workflow.updated",
    "workflow": {
        "id": "wf-002",
        "ironcladId": "IC-002",
        "title": "Master Supply Agreement - Pumps",
        "step": "Review",
        "attributes": {
            "counterpartyName": "Pump Supplier LLC",
            "contractValue": {"currency": "EUR", "amount": 18000.0},
            "product": "Industrial hydraulic pumps",
            "deliveryDays": 21,
        },
    },
}

SAMPLE_AGREED_TERMS = {
    "deal_type": "saas_renewal",
    "total_value": 10_500_000,
    "currency": "USD",
    "seat_count": 100,
    "subscription_tier": "enterprise",
    "term_months": 12,
    "payment_terms": {"net_days": 45},
    "custom_terms": {
        "ironclad": {
            "workflow_id": "wf-001",
            "ironclad_id": "IC-001",
            "counterparty_name": "Acme Analytics",
        }
    },
}


def _compact_json(body: dict) -> str:
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def _make_async_client_mock(json_data: dict, status_code: int = 200):
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = json_data
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.patch.return_value = mock_response

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    return mock_cm, mock_client


class TestIroncladWebhookParser:
    def test_renewal_workflow_maps_to_saas_renewal_terms(self):
        parsed = IroncladWebhookParser.workflow_event_to_session_inputs(
            SAMPLE_RENEWAL_WORKFLOW
        )

        assert parsed["workflow_id"] == "wf-001"
        assert parsed["session_params"]["deal_type"] == "saas_renewal"
        assert parsed["session_params"]["ironclad_id"] == "IC-001"
        assert parsed["initial_terms"]["total_value"] == 10_500_000
        assert parsed["initial_terms"]["seat_count"] == 100
        assert parsed["initial_terms"]["payment_terms"]["net_days"] == 45
        assert validate_deal_type_terms("saas_renewal", parsed["initial_terms"]) == []

    def test_non_renewal_workflow_maps_to_goods_procurement_terms(self):
        parsed = IroncladWebhookParser.workflow_event_to_session_inputs(
            SAMPLE_GOODS_WORKFLOW
        )

        assert parsed["session_params"]["deal_type"] == "goods_procurement"
        assert parsed["initial_terms"]["currency"] == "EUR"
        assert parsed["initial_terms"]["delivery_days"] == 21
        assert parsed["initial_terms"]["line_items"][0]["unit_price"] == 1_800_000
        assert validate_deal_type_terms("goods_procurement", parsed["initial_terms"]) == []

    def test_signed_webhook_verification_accepts_valid_signature(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        event_id = "evt-ironclad-003"
        nonce = "nonce-123"
        body = {"workflow": {"id": "wf-003"}, "eventType": "workflow.updated"}
        signed_data = (event_id + _compact_json(body) + nonce).encode("utf-8")
        signature = private_key.sign(
            signed_data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        verification_header = json.dumps({
            "nonce": nonce,
            "signAlgorithm": "RSA-SHA256",
            "signature": base64.b64encode(signature).decode("ascii"),
            "encoding": "base64",
        })

        assert IroncladWebhookParser.verify_webhook_signature(
            event_id,
            verification_header,
            body,
            public_pem,
        )

    def test_signed_webhook_verification_rejects_tampered_body(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        event_id = "evt-ironclad-004"
        nonce = "nonce-456"
        body = {"workflow": {"id": "wf-004"}}
        signed_data = (event_id + _compact_json(body) + nonce).encode("utf-8")
        signature = private_key.sign(
            signed_data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        verification_header = json.dumps({
            "nonce": nonce,
            "signAlgorithm": "RSA-SHA256",
            "signature": base64.b64encode(signature).decode("ascii"),
            "encoding": "base64",
        })

        assert not IroncladWebhookParser.verify_webhook_signature(
            event_id,
            verification_header,
            {"workflow": {"id": "wf-tampered"}},
            public_pem,
        )


class TestIroncladWriteBackPayloads:
    def test_terms_to_workflow_update_payload_shape(self):
        update = a2cn_terms_to_ironclad_workflow(
            SAMPLE_AGREED_TERMS,
            workflow_id="wf-001",
            a2cn_session_id="sess-001",
            record_hash="deadbeef" * 8,
        )

        payload = update["payload"]
        assert update["endpoint"] == "/workflows/wf-001/attributes"
        assert payload["updates"][0] == {
            "action": "set",
            "path": "contractValue",
            "value": {"currency": "USD", "amount": 105000.0},
        }
        assert {
            "action": "set",
            "path": "a2cnSessionId",
            "value": "sess-001",
        } in payload["updates"]

    def test_terms_to_workflow_update_supports_field_map(self):
        update = a2cn_terms_to_ironclad_workflow(
            SAMPLE_AGREED_TERMS,
            workflow_id="wf-001",
            a2cn_session_id="sess-002",
            record_hash="cafebabe" * 8,
            field_map={"contract_value": "fee", "a2cn_record_hash": "a2cnHash"},
        )

        paths = {item["path"] for item in update["payload"]["updates"]}
        assert "fee" in paths
        assert "a2cnHash" in paths

    def test_terms_to_record_payload_shape(self):
        record = a2cn_terms_to_ironclad_record(
            SAMPLE_AGREED_TERMS,
            record_type="vendorAgreement",
            name="A2CN Renewal - Acme Analytics",
            a2cn_session_id="sess-003",
            record_hash="feedface" * 8,
        )

        assert record["type"] == "vendorAgreement"
        assert record["name"] == "A2CN Renewal - Acme Analytics"
        assert record["properties"]["contractValue"]["type"] == "monetary_amount"
        assert record["properties"]["contractValue"]["value"]["amount"] == 105000.0
        assert record["properties"]["a2cnSessionId"]["value"] == "sess-003"


class TestIroncladHttpUpdate:
    @pytest.mark.asyncio
    async def test_update_workflow_metadata_uses_env_token_and_actor(self):
        mock_cm, mock_client = _make_async_client_mock({"id": "wf-001"})
        with patch("adapters.ironclad_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "IRONCLAD_API_TOKEN": "test-token",
                "IRONCLAD_BASE_URL": "https://demo.ironcladapp.com/public/api/v1",
                "IRONCLAD_AS_USER_EMAIL": "legal@example.com",
            }):
                result = await update_ironclad_workflow_metadata(
                    "wf-001",
                    {"updates": []},
                )

        assert result["id"] == "wf-001"
        _, kwargs = mock_client.patch.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer test-token"
        assert kwargs["headers"]["x-as-user-email"] == "legal@example.com"
        assert kwargs["json"] == {"updates": []}

    def test_update_workflow_metadata_requires_token(self):
        env = {k: v for k, v in os.environ.items() if k != "IRONCLAD_API_TOKEN"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="IRONCLAD_API_TOKEN"):
                import asyncio
                asyncio.get_event_loop().run_until_complete(
                    update_ironclad_workflow_metadata("wf-001", {"updates": []})
                )
