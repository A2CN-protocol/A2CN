"""Tests for Conga CPQ/CLM platform adapter."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from a2cn.messages import validate_deal_type_terms
from adapters.conga_adapter import (
    CongaAdapter,
    a2cn_terms_to_conga_quote,
    conga_agreement_update_payload,
    conga_auth_headers,
    conga_quote_to_a2cn_terms,
    fetch_conga_access_token,
)


SAMPLE_CONGA_SAAS_QUOTE = {
    "id": "conga-q-001",
    "agreementId": "clm-agreement-001",
    "accountId": "001xx000003DGbY",
    "opportunityId": "006xx000004TqVQ",
    "currency": "USD",
    "startDate": "2026-07-01",
    "endDate": "2027-06-30",
    "termMonths": 12,
    "paymentTermsNetDays": 45,
    "lineItems": [
        {
            "id": "qli-001",
            "productId": "prod-001",
            "productName": "Enterprise Subscription License",
            "quantity": 100,
            "unitPrice": 950.0,
            "totalPrice": 95_000.0,
        },
        {
            "id": "qli-002",
            "productId": "prod-002",
            "productName": "Premium Support",
            "quantity": 1,
            "unitPrice": 5_000.0,
            "totalPrice": 5_000.0,
        },
    ],
}

SAMPLE_CONGA_GOODS_QUOTE = {
    "Id": "a1Qxx0000009abc",
    "CurrencyIsoCode": "EUR",
    "deliveryDays": 21,
    "records": [
        {
            "Id": "a2Lxx0000001",
            "ProductId": "01txx0000001",
            "Name": "Hydraulic fluid 200L drums",
            "Quantity": 50,
            "NetUnitPrice": 360.0,
            "NetAmount": 18_000.0,
            "Uom": "EA",
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


class TestCongaQuoteToTerms:
    def test_saas_quote_maps_to_saas_renewal_terms(self):
        terms = conga_quote_to_a2cn_terms(SAMPLE_CONGA_SAAS_QUOTE)

        assert terms["currency"] == "USD"
        assert terms["total_value"] == 10_000_000
        assert terms["seat_count"] == 100
        assert terms["subscription_tier"] == "Enterprise Subscription License"
        assert terms["term_months"] == 12
        assert "contract_term_months" not in terms
        assert terms["payment_terms"]["net_days"] == 45
        assert terms["contract_duration"] == {
            "start_date": "2026-07-01",
            "end_date": "2027-06-30",
        }
        assert validate_deal_type_terms("saas_renewal", terms) == []

    def test_line_item_ids_and_product_ids_are_preserved(self):
        terms = conga_quote_to_a2cn_terms(SAMPLE_CONGA_SAAS_QUOTE)

        assert terms["line_items"][0]["conga_line_item_id"] == "qli-001"
        assert terms["line_items"][0]["conga_product_id"] == "prod-001"
        assert terms["line_items"][0]["internal_part_number"] == "qli-001"
        assert terms["custom_terms"]["conga"]["quote_id"] == "conga-q-001"
        assert terms["custom_terms"]["conga"]["agreement_id"] == "clm-agreement-001"

    def test_goods_quote_maps_to_goods_procurement_terms(self):
        terms = conga_quote_to_a2cn_terms(SAMPLE_CONGA_GOODS_QUOTE)

        assert terms["currency"] == "EUR"
        assert terms["delivery_days"] == 21
        assert terms["line_items"][0]["description"] == "Hydraulic fluid 200L drums"
        assert terms["line_items"][0]["unit_of_measure"] == "EA"
        assert terms["line_items"][0]["unit_price"] == 36_000
        assert terms["line_items"][0]["total"] == 1_800_000
        assert validate_deal_type_terms("goods_procurement", terms) == []

    def test_header_total_used_when_line_items_have_no_prices(self):
        quote = {
            "id": "conga-q-empty-price",
            "totalAmount": 7_500.0,
            "currency": "USD",
            "lineItems": [
                {"productName": "Widget", "quantity": 1, "unitPrice": 0.0, "totalPrice": 0.0},
            ],
        }

        terms = conga_quote_to_a2cn_terms(quote)

        assert terms["total_value"] == 750_000

    def test_custom_field_map_overrides_tenant_names(self):
        quote = {
            "quote_total": 5_000.0,
            "ccy": "GBP",
            "rows": [
                {"label": "Widget Pro", "qty": 10, "price": 500.0, "row_total": 5_000.0},
            ],
        }
        field_map = {
            "total_value_field": "quote_total",
            "currency_field": "ccy",
            "line_items_field": "rows",
            "product_name_field": "label",
            "quantity_field": "qty",
            "unit_price_field": "price",
            "total_price_field": "row_total",
        }

        terms = conga_quote_to_a2cn_terms(quote, field_map=field_map)

        assert terms["currency"] == "GBP"
        assert terms["line_items"][0]["description"] == "Widget Pro"
        assert terms["line_items"][0]["quantity"] == 10
        assert terms["line_items"][0]["unit_price"] == 50_000

    def test_advantage_platform_casing_aliases_supported(self):
        quote = {
            "Id": "cart-001",
            "CurrencyCode": "CAD",
            "LineItems": [
                {
                    "Id": "line-001",
                    "ProductName": "Managed Service Subscription",
                    "Quantity": 2,
                    "UnitPrice": 1_200.0,
                    "TotalPrice": 2_400.0,
                },
            ],
        }

        terms = conga_quote_to_a2cn_terms(quote)

        assert terms["currency"] == "CAD"
        assert terms["total_value"] == 240_000
        assert terms["seat_count"] == 2
        assert terms["line_items"][0]["unit_price"] == 120_000


class TestCongaSessionAndWriteBack:
    def test_quote_to_session_inputs_sets_saas_deal_type(self):
        parsed = CongaAdapter.quote_to_session_inputs(SAMPLE_CONGA_SAAS_QUOTE, max_rounds=3)

        assert parsed["quote_id"] == "conga-q-001"
        assert parsed["session_params"]["deal_type"] == "saas_renewal"
        assert parsed["session_params"]["max_rounds"] == 3
        assert parsed["session_params"]["conga_quote_id"] == "conga-q-001"
        assert parsed["session_params"]["conga_account_id"] == "001xx000003DGbY"
        assert parsed["session_params"]["conga_opportunity_id"] == "006xx000004TqVQ"

    def test_a2cn_terms_to_conga_quote_converts_cents_to_dollars(self):
        terms = conga_quote_to_a2cn_terms(SAMPLE_CONGA_SAAS_QUOTE)

        payload = a2cn_terms_to_conga_quote(
            terms,
            quote_id="conga-q-001",
            agreement_id="clm-agreement-001",
        )

        assert payload["quoteId"] == "conga-q-001"
        assert payload["agreementId"] == "clm-agreement-001"
        assert payload["totalAmount"] == 100_000.0
        assert payload["seatCount"] == 100
        assert payload["termMonths"] == 12
        assert payload["lineItems"][0]["id"] == "qli-001"
        assert payload["lineItems"][0]["productId"] == "prod-001"
        assert payload["lineItems"][0]["unitPrice"] == 950.0
        assert payload["lineItems"][0]["totalPrice"] == 95_000.0
        assert payload["paymentTerms"] == "Net 45"

    def test_goods_terms_to_conga_quote_includes_delivery_days(self):
        terms = conga_quote_to_a2cn_terms(SAMPLE_CONGA_GOODS_QUOTE)

        payload = a2cn_terms_to_conga_quote(terms, quote_id="a1Qxx0000009abc")

        assert payload["deliveryDays"] == 21
        assert payload["lineItems"][0]["id"] == "a2Lxx0000001"
        assert payload["lineItems"][0]["unitOfMeasure"] == "EA"

    def test_agreement_update_payload_links_a2cn_record(self):
        payload = conga_agreement_update_payload(
            agreement_id="clm-agreement-001",
            a2cn_session_id="sess-001",
            record_hash="record-hash",
        )

        assert payload == {
            "agreementId": "clm-agreement-001",
            "status": "Ready for Contracting",
            "externalReferences": {
                "a2cn_session_id": "sess-001",
                "a2cn_record_hash": "record-hash",
            },
        }


class TestCongaAuthHelpers:
    def test_conga_auth_headers(self):
        headers = conga_auth_headers("access-token")

        assert headers["Authorization"] == "Bearer access-token"
        assert headers["Accept"] == "application/json"
        assert headers["Content-Type"] == "application/json"

    @pytest.mark.asyncio
    async def test_fetch_conga_access_token_requires_env(self):
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"CONGA_CLIENT_ID", "CONGA_CLIENT_SECRET", "CONGA_TOKEN_URL"}
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="CONGA_CLIENT_ID"):
                await fetch_conga_access_token()

    @pytest.mark.asyncio
    async def test_fetch_conga_access_token_uses_client_credentials(self):
        mock_cm, mock_client = _make_async_client_mock({"access_token": "token-123"})
        with patch("adapters.conga_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "CONGA_CLIENT_ID": "client-id",
                "CONGA_CLIENT_SECRET": "client-secret",
                "CONGA_TOKEN_URL": "https://auth.example.com/oauth2/token",
            }):
                token = await fetch_conga_access_token()

        assert token == "token-123"
        _, kwargs = mock_client.post.call_args
        assert kwargs["data"] == {"grant_type": "client_credentials"}
        assert kwargs["auth"] == ("client-id", "client-secret")

    @pytest.mark.asyncio
    async def test_fetch_conga_access_token_includes_scope_when_present(self):
        mock_cm, mock_client = _make_async_client_mock({"access_token": "token-123"})
        with patch("adapters.conga_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "CONGA_CLIENT_ID": "client-id",
                "CONGA_CLIENT_SECRET": "client-secret",
                "CONGA_SCOPE": "api cpq",
            }):
                token = await fetch_conga_access_token(
                    token_url="https://auth.example.com/oauth2/token"
                )

        assert token == "token-123"
        _, kwargs = mock_client.post.call_args
        assert kwargs["data"] == {
            "grant_type": "client_credentials",
            "scope": "api cpq",
        }
