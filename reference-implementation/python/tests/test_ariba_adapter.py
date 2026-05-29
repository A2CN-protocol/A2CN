"""Tests for SAP Ariba Sourcing platform adapter."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from a2cn.messages import validate_deal_type_terms
from adapters.ariba_adapter import (
    AribaEventParser,
    a2cn_terms_to_ariba_bid,
    ariba_acknowledgement_payload,
    ariba_auth_headers,
    fetch_ariba_access_token,
)


SAMPLE_ARIBA_EVENT = {
    "eventId": "evt-ariba-001",
    "externalSystemCorrelationId": "RFQ-2026-001",
    "title": "Q3 Industrial Supplies RFQ",
    "buyerOrg": "Global Manufacturing Inc.",
    "biddingEndDate": "2026-08-01T17:00:00Z",
    "currency": "USD",
    "deliveryDays": 21,
    "paymentTermsNetDays": 45,
    "items": [
        {
            "itemId": "10",
            "lotId": "LOT-HF-001",
            "title": "Hydraulic fluid 200L drums",
            "quantity": 50,
            "unitOfMeasure": "EA",
            "targetPrice": 360.0,
        },
        {
            "itemId": "20",
            "lotId": "LOT-SC-002",
            "title": "Sealing compound 5kg tubs",
            "quantity": 20,
            "unitOfMeasure": "KG",
            "targetPrice": 85.0,
        },
    ],
}

SAMPLE_DISCOVERY_RFX = {
    "rfxId": "rfx-001",
    "externalRfxId": "DISC-2026-001",
    "rfxTitle": "Public sector pump sourcing event",
    "buyerOrganization": "City Procurement Office",
    "closeDate": "2026-09-15T17:00:00Z",
    "currencyCode": "EUR",
    "lots": [
        {
            "id": "lot-001",
            "name": "Industrial hydraulic pump",
            "qty": 10,
            "uom": "EA",
            "unitPrice": 1500.0,
        },
    ],
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


class TestAribaEventParser:
    def test_parse_event_management_payload(self):
        parsed = AribaEventParser.parse_sourcing_event(SAMPLE_ARIBA_EVENT)

        assert parsed["event_id"] == "evt-ariba-001"
        assert parsed["external_rfx_id"] == "RFQ-2026-001"
        assert parsed["event_name"] == "Q3 Industrial Supplies RFQ"
        assert parsed["buyer_org"] == "Global Manufacturing Inc."
        assert parsed["currency"] == "USD"
        assert len(parsed["line_items"]) == 2

    def test_event_to_goods_procurement_terms_converts_prices_to_cents(self):
        terms = AribaEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_ARIBA_EVENT
        )

        assert terms["currency"] == "USD"
        assert terms["delivery_days"] == 21
        assert terms["payment_terms"]["net_days"] == 45
        assert terms["line_items"][0]["unit_price"] == 36_000
        assert terms["line_items"][0]["total"] == 1_800_000
        assert terms["total_value"] == 1_970_000
        assert validate_deal_type_terms("goods_procurement", terms) == []

    def test_item_lot_id_maps_to_internal_part_number(self):
        terms = AribaEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_ARIBA_EVENT
        )

        assert terms["line_items"][0]["internal_part_number"] == "LOT-HF-001"
        assert terms["line_items"][0]["ariba_item_id"] == "10"
        assert terms["line_items"][0]["ariba_lot_id"] == "LOT-HF-001"
        assert terms["custom_terms"]["ariba"]["event_id"] == "evt-ariba-001"

    def test_discovery_rfx_aliases_supported(self):
        parsed = AribaEventParser.sourcing_event_to_session_inputs(
            SAMPLE_DISCOVERY_RFX,
            max_rounds=3,
        )

        assert parsed["session_params"]["deal_type"] == "goods_procurement"
        assert parsed["session_params"]["max_rounds"] == 3
        assert parsed["session_params"]["ariba_event_id"] == "rfx-001"
        assert parsed["session_params"]["ariba_external_rfx_id"] == "DISC-2026-001"
        assert parsed["initial_terms"]["currency"] == "EUR"
        assert parsed["initial_terms"]["total_value"] == 1_500_000
        assert validate_deal_type_terms("goods_procurement", parsed["initial_terms"]) == []

    def test_total_price_overrides_computed_line_total_when_present(self):
        event = {
            "eventId": "evt-total",
            "currency": "USD",
            "items": [
                {
                    "itemId": "1",
                    "title": "Configured assembly",
                    "quantity": 3,
                    "unitPrice": 100.0,
                    "totalPrice": 275.0,
                },
            ],
        }

        terms = AribaEventParser.sourcing_event_to_goods_procurement_terms(event)

        assert terms["line_items"][0]["unit_price"] == 10_000
        assert terms["line_items"][0]["total"] == 27_500
        assert terms["total_value"] == 27_500


class TestAribaWriteBackPayloads:
    def test_terms_to_ariba_bid_converts_cents_to_dollars(self):
        terms = AribaEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_ARIBA_EVENT
        )

        bid = a2cn_terms_to_ariba_bid(
            terms,
            event_id="evt-ariba-001",
            supplier_id="supplier-001",
        )

        assert bid["eventId"] == "evt-ariba-001"
        assert bid["supplierId"] == "supplier-001"
        assert bid["totalAmount"] == 19_700.0
        assert bid["items"][0]["itemId"] == "10"
        assert bid["items"][0]["lotId"] == "LOT-HF-001"
        assert bid["items"][0]["unitPrice"] == 360.0
        assert bid["items"][0]["totalPrice"] == 18_000.0
        assert bid["paymentTerms"] == "Net 45"

    def test_acknowledgement_payload_shape(self):
        ack = ariba_acknowledgement_payload(
            event_id="rfx-001",
            external_reference="a2cn-session-sess-001",
        )

        assert ack == {
            "eventId": "rfx-001",
            "externalReference": "a2cn-session-sess-001",
            "status": "ACKNOWLEDGED",
            "message": "Accepted for A2CN negotiation.",
        }


class TestAribaAuthHelpers:
    def test_ariba_auth_headers_include_api_key(self):
        headers = ariba_auth_headers("access-token", api_key="app-key")

        assert headers["Authorization"] == "Bearer access-token"
        assert headers["apiKey"] == "app-key"
        assert headers["Accept"] == "application/json"

    def test_ariba_auth_headers_reads_api_key_from_env(self):
        with patch.dict(os.environ, {"ARIBA_API_KEY": "env-app-key"}):
            headers = ariba_auth_headers("access-token")

        assert headers["apiKey"] == "env-app-key"

    def test_ariba_auth_headers_require_api_key(self):
        env = {k: v for k, v in os.environ.items() if k != "ARIBA_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="ARIBA_API_KEY"):
                ariba_auth_headers("access-token")

    @pytest.mark.asyncio
    async def test_fetch_ariba_access_token_uses_client_credentials(self):
        mock_cm, mock_client = _make_async_client_mock({"access_token": "token-123"})
        with patch("adapters.ariba_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "ARIBA_CLIENT_ID": "client-id",
                "ARIBA_CLIENT_SECRET": "client-secret",
                "ARIBA_TOKEN_URL": "https://api.ariba.com/oauth/token",
            }):
                token = await fetch_ariba_access_token()

        assert token == "token-123"
        _, kwargs = mock_client.post.call_args
        assert kwargs["data"] == {"grant_type": "client_credentials"}
        assert kwargs["auth"] == ("client-id", "client-secret")

    @pytest.mark.asyncio
    async def test_fetch_ariba_access_token_accepts_explicit_token_url(self):
        mock_cm, mock_client = _make_async_client_mock({"access_token": "token-456"})
        with patch("adapters.ariba_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "ARIBA_CLIENT_ID": "client-id",
                "ARIBA_CLIENT_SECRET": "client-secret",
            }, clear=True):
                token = await fetch_ariba_access_token(
                    token_url="https://example.ariba.com/oauth/token"
                )

        assert token == "token-456"
        mock_client.post.assert_called_once()
        assert mock_client.post.call_args.args[0] == "https://example.ariba.com/oauth/token"

    @pytest.mark.asyncio
    async def test_fetch_ariba_access_token_requires_env(self):
        env = {
            k: v for k, v in os.environ.items()
            if k not in {"ARIBA_CLIENT_ID", "ARIBA_CLIENT_SECRET", "ARIBA_TOKEN_URL"}
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="ARIBA_CLIENT_ID"):
                await fetch_ariba_access_token()
