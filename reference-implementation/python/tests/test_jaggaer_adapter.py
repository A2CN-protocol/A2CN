"""Tests for JAGGAER ASO platform adapter."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from a2cn.messages import validate_deal_type_terms
from adapters.jaggaer_adapter import (
    JaggaerEventParser,
    a2cn_terms_to_jaggaer_response,
    fetch_jaggaer_access_token,
    jaggaer_auth_headers,
    jaggaer_poll_request,
)


SAMPLE_JAGGAER_PUSH_EVENT = {
    "event": {
        "eventId": "aso-10003",
        "customerHostId": "275",
        "name": "Industrial Supplies RFQ",
        "eventOwner": "Global Manufacturing Inc.",
        "biddingClose": "2026-08-01T17:00:00Z",
        "currency": "USD",
        "deliveryDays": 21,
        "paymentTermsNetDays": 45,
        "items": [
            {
                "itemId": "10",
                "lotId": "LOT-HF-001",
                "description": "Hydraulic fluid 200L drums",
                "quantity": 50,
                "unitOfMeasure": "EA",
                "targetPrice": 360.0,
            },
            {
                "itemId": "20",
                "lotId": "LOT-SC-002",
                "description": "Sealing compound 5kg tubs",
                "quantity": 20,
                "unitOfMeasure": "KG",
                "targetPrice": 85.0,
            },
        ],
    }
}

SAMPLE_JAGGAER_POLLED_EVENT = {
    "eventId": 10004,
    "customerHostId": 275,
    "title": "Public sector pump sourcing event",
    "buyerOrganization": "City Procurement Office",
    "closeDate": "2026-09-15T17:00:00Z",
    "currencyCode": "EUR",
    "lineItems": {
        "results": [
            {
                "id": "item-001",
                "lotNumber": "lot-001",
                "name": "Industrial hydraulic pump",
                "qty": 10,
                "uom": "EA",
                "unitPrice": {"amount": 1500.0, "currency": "EUR"},
            },
        ],
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


class TestJaggaerEventParser:
    def test_parse_push_event_payload(self):
        parsed = JaggaerEventParser.parse_sourcing_event(SAMPLE_JAGGAER_PUSH_EVENT)

        assert parsed["event_id"] == "aso-10003"
        assert parsed["customer_host_id"] == "275"
        assert parsed["event_name"] == "Industrial Supplies RFQ"
        assert parsed["buyer_org"] == "Global Manufacturing Inc."
        assert parsed["currency"] == "USD"
        assert parsed["mode"] == "push"
        assert len(parsed["line_items"]) == 2

    def test_event_to_goods_procurement_terms_converts_prices_to_cents(self):
        terms = JaggaerEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_JAGGAER_PUSH_EVENT
        )

        assert terms["currency"] == "USD"
        assert terms["delivery_days"] == 21
        assert terms["payment_terms"]["net_days"] == 45
        assert terms["line_items"][0]["unit_price"] == 36_000
        assert terms["line_items"][0]["total"] == 1_800_000
        assert terms["total_value"] == 1_970_000
        assert validate_deal_type_terms("goods_procurement", terms) == []

    def test_item_and_lot_ids_are_preserved_for_bid_reconstruction(self):
        terms = JaggaerEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_JAGGAER_PUSH_EVENT
        )

        assert terms["line_items"][0]["internal_part_number"] == "LOT-HF-001"
        assert terms["line_items"][0]["jaggaer_item_id"] == "10"
        assert terms["line_items"][0]["jaggaer_lot_id"] == "LOT-HF-001"
        assert terms["custom_terms"]["jaggaer"]["event_id"] == "aso-10003"
        assert terms["custom_terms"]["jaggaer"]["source"] == "jaggaer_aso"

    def test_polled_event_aliases_supported(self):
        parsed = JaggaerEventParser.sourcing_event_to_session_inputs(
            SAMPLE_JAGGAER_POLLED_EVENT,
            max_rounds=3,
            mode="poll",
        )

        assert parsed["session_params"]["deal_type"] == "goods_procurement"
        assert parsed["session_params"]["max_rounds"] == 3
        assert parsed["session_params"]["jaggaer_event_id"] == "10004"
        assert parsed["session_params"]["jaggaer_customer_host_id"] == 275
        assert parsed["initial_terms"]["currency"] == "EUR"
        assert parsed["initial_terms"]["total_value"] == 1_500_000
        assert parsed["initial_terms"]["custom_terms"]["jaggaer"]["mode"] == "poll"
        assert validate_deal_type_terms("goods_procurement", parsed["initial_terms"]) == []

    def test_total_price_overrides_computed_line_total_when_present(self):
        event = {
            "eventId": "evt-total",
            "currency": "USD",
            "items": [
                {
                    "itemId": "1",
                    "description": "Configured assembly",
                    "quantity": 3,
                    "unitPrice": 100.0,
                    "totalPrice": 275.0,
                },
            ],
        }

        terms = JaggaerEventParser.sourcing_event_to_goods_procurement_terms(event)

        assert terms["line_items"][0]["unit_price"] == 10_000
        assert terms["line_items"][0]["total"] == 27_500
        assert terms["total_value"] == 27_500


class TestJaggaerWriteBackPayloads:
    def test_terms_to_jaggaer_response_converts_cents_to_dollars(self):
        terms = JaggaerEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_JAGGAER_PUSH_EVENT
        )

        response = a2cn_terms_to_jaggaer_response(
            terms,
            event_id="aso-10003",
            supplier_id="supplier-001",
        )

        assert response["eventId"] == "aso-10003"
        assert response["supplierId"] == "supplier-001"
        assert response["totalAmount"] == 19_700.0
        assert response["items"][0]["itemId"] == "10"
        assert response["items"][0]["lotId"] == "LOT-HF-001"
        assert response["items"][0]["unitPrice"] == 360.0
        assert response["items"][0]["totalPrice"] == 18_000.0
        assert response["paymentTerms"] == "Net 45"

    def test_poll_request_builds_customer_host_api_events_path(self):
        request = jaggaer_poll_request(
            customer_host_id="275",
            user_id="user-123",
            base_url="https://ches.demo-api.example.com/",
        )

        assert request == {
            "method": "GET",
            "url": "https://ches.demo-api.example.com/chost/275/user/user-123/apiEvents",
            "headers": {
                "Accept": "application/vnd.sciquest.com.ches+json",
            },
        }


class TestJaggaerAuthHelpers:
    def test_jaggaer_auth_headers_include_api_key(self):
        headers = jaggaer_auth_headers("access-token", api_key="api-key")

        assert headers["Authorization"] == "Bearer access-token"
        assert headers["X-API-Key"] == "api-key"
        assert headers["Accept"] == "application/json"

    def test_jaggaer_auth_headers_reads_api_key_from_env(self):
        with patch.dict(os.environ, {"JAGGAER_API_KEY": "env-api-key"}):
            headers = jaggaer_auth_headers("access-token")

        assert headers["X-API-Key"] == "env-api-key"

    def test_jaggaer_auth_headers_require_api_key(self):
        env = {k: v for k, v in os.environ.items() if k != "JAGGAER_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="JAGGAER_API_KEY"):
                jaggaer_auth_headers("access-token")

    @pytest.mark.asyncio
    async def test_fetch_jaggaer_access_token_uses_client_credentials(self):
        mock_cm, mock_client = _make_async_client_mock({"access_token": "token-123"})
        with patch("adapters.jaggaer_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "JAGGAER_CLIENT_ID": "client-id",
                "JAGGAER_CLIENT_SECRET": "client-secret",
                "JAGGAER_API_KEY": "api-key",
                "JAGGAER_TOKEN_URL": "https://auth.demo-api.example.com/oauth2/token",
            }):
                token = await fetch_jaggaer_access_token()

        assert token == "token-123"
        _, kwargs = mock_client.post.call_args
        assert kwargs["data"] == {"grant_type": "client_credentials"}
        assert kwargs["auth"] == ("client-id", "client-secret")
        assert kwargs["headers"]["X-API-Key"] == "api-key"

    @pytest.mark.asyncio
    async def test_fetch_jaggaer_access_token_includes_scope_when_present(self):
        mock_cm, mock_client = _make_async_client_mock({"access_token": "token-123"})
        with patch("adapters.jaggaer_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "JAGGAER_CLIENT_ID": "client-id",
                "JAGGAER_CLIENT_SECRET": "client-secret",
                "JAGGAER_API_KEY": "api-key",
                "JAGGAER_SCOPE": "tenant-aso 275",
            }):
                token = await fetch_jaggaer_access_token(
                    token_url="https://auth.demo-api.example.com/oauth2/token"
                )

        assert token == "token-123"
        _, kwargs = mock_client.post.call_args
        assert kwargs["data"] == {
            "grant_type": "client_credentials",
            "scope": "tenant-aso 275",
        }
