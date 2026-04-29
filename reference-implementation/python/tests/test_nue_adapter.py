"""Tests for Nue.io Revenue Lifecycle platform adapter."""

from __future__ import annotations

import os
from datetime import date
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from adapters.nue_adapter import NueEventParser


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_NUE_PRICING = {
    "productId": "prod-analytics-001",
    "priceBookId": "pb-enterprise-2026",
    # FIELD NOTE: listPrice field name verified against Nue sandbox
    "listPrice": 1000.0,
    "currency": "USD",
    "quantity": 50,
}

SAMPLE_NUE_SUBSCRIPTION = {
    "subscriptionId": "sub-001",
    "customerId": "cust-techcorp",
    "productId": "prod-analytics-001",
    # FIELD NOTE: productTier, quantity, totalValue, autoRenew, termMonths
    # should be verified against live Nue sandbox instance.
    "productTier": "enterprise",
    "quantity": 100,
    "totalValue": 100000.0,
    "currency": "USD",
    "termMonths": 12,
    "autoRenew": True,
}

SAMPLE_A2CN_AGREED_TERMS = {
    "deal_type": "saas_renewal",
    "total_value": 10_500_000,   # $105,000 in cents
    "currency": "USD",
    "seat_count": 100,
    "term_months": 12,
    "line_items": [
        {
            "description": "Analytics Platform Enterprise",
            "quantity": 100,
            "unit_price": 105_000,   # cents per seat per year
            "total": 10_500_000,
        }
    ],
}


# ---------------------------------------------------------------------------
# Async HTTP mock helper
# ---------------------------------------------------------------------------

def _make_async_client_mock(json_data, status_code: int = 200):
    """Returns a context-manager mock for httpx.AsyncClient."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = json_data
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    return mock_cm


# ---------------------------------------------------------------------------
# TestNuePricingToMandateBounds
# ---------------------------------------------------------------------------

class TestNuePricingToMandateBounds:
    def test_floor_is_less_than_ceiling(self):
        bounds = NueEventParser.pricing_to_mandate_bounds(SAMPLE_NUE_PRICING)
        assert bounds["floor_value_cents"] < bounds["ceiling_value_cents"]

    def test_ceiling_equals_list_price_in_cents(self):
        # 50 seats × $1000 = $50,000 = 5,000,000 cents
        bounds = NueEventParser.pricing_to_mandate_bounds(SAMPLE_NUE_PRICING)
        assert bounds["ceiling_value_cents"] == 5_000_000

    def test_default_floor_discount_ten_percent(self):
        bounds = NueEventParser.pricing_to_mandate_bounds(SAMPLE_NUE_PRICING)
        assert bounds["floor_value_cents"] == int(5_000_000 * 0.90)

    def test_custom_floor_discount_pct(self):
        bounds = NueEventParser.pricing_to_mandate_bounds(
            SAMPLE_NUE_PRICING, floor_discount_pct=0.20
        )
        assert bounds["floor_value_cents"] == int(5_000_000 * 0.80)

    def test_currency_passthrough(self):
        bounds = NueEventParser.pricing_to_mandate_bounds(SAMPLE_NUE_PRICING)
        assert bounds["currency"] == "USD"

    def test_single_unit_pricing(self):
        pricing = {"listPrice": 2000.0, "currency": "EUR"}
        bounds = NueEventParser.pricing_to_mandate_bounds(pricing, floor_discount_pct=0.15)
        assert bounds["ceiling_value_cents"] == 200_000
        assert bounds["floor_value_cents"] == int(200_000 * 0.85)

    def test_custom_field_map_list_price_field(self):
        pricing = {"unitListPrice": 500.0, "currency": "GBP", "qty": 10}
        bounds = NueEventParser.pricing_to_mandate_bounds(
            pricing,
            field_map={"list_price_field": "unitListPrice", "quantity_field": "qty"},
        )
        # 10 × $500 = $5000 = 500,000 cents
        assert bounds["ceiling_value_cents"] == 500_000
        assert bounds["currency"] == "GBP"

    def test_custom_field_map_currency_field(self):
        pricing = {"listPrice": 100.0, "ccy": "JPY"}
        bounds = NueEventParser.pricing_to_mandate_bounds(
            pricing,
            field_map={"currency_field": "ccy"},
        )
        assert bounds["currency"] == "JPY"


# ---------------------------------------------------------------------------
# TestNueSubscriptionToRenewalTerms
# ---------------------------------------------------------------------------

class TestNueSubscriptionToRenewalTerms:
    def test_deal_type_is_saas_renewal(self):
        terms = NueEventParser.subscription_to_renewal_terms(SAMPLE_NUE_SUBSCRIPTION)
        assert terms["deal_type"] == "saas_renewal"

    def test_renewal_markup_applied_correctly(self):
        # $100,000 * 100 cents * 1.05 = 10,500,000 cents
        terms = NueEventParser.subscription_to_renewal_terms(
            SAMPLE_NUE_SUBSCRIPTION, renewal_markup_pct=0.05
        )
        assert terms["total_value"] == int(100_000.0 * 100 * 1.05)

    def test_seat_count_from_subscription_quantity(self):
        terms = NueEventParser.subscription_to_renewal_terms(SAMPLE_NUE_SUBSCRIPTION)
        assert terms["seat_count"] == 100

    def test_subscription_tier_extracted(self):
        terms = NueEventParser.subscription_to_renewal_terms(SAMPLE_NUE_SUBSCRIPTION)
        assert terms["subscription_tier"] == "enterprise"

    def test_auto_renew_terms_included(self):
        terms = NueEventParser.subscription_to_renewal_terms(SAMPLE_NUE_SUBSCRIPTION)
        assert terms["auto_renew_terms"]["auto_renew"] is True

    def test_term_months_included(self):
        terms = NueEventParser.subscription_to_renewal_terms(SAMPLE_NUE_SUBSCRIPTION)
        assert terms["term_months"] == 12

    def test_zero_markup_preserves_current_value(self):
        terms = NueEventParser.subscription_to_renewal_terms(
            SAMPLE_NUE_SUBSCRIPTION, renewal_markup_pct=0.0
        )
        assert terms["total_value"] == int(100_000.0 * 100)

    def test_custom_field_map_total_value_field(self):
        sub = {
            "contractValue": 50000.0,
            "seats": 50,
            "tier": "standard",
            "renew": False,
            "months": 24,
            "currency": "EUR",
        }
        terms = NueEventParser.subscription_to_renewal_terms(
            sub,
            renewal_markup_pct=0.0,
            field_map={
                "total_value_field": "contractValue",
                "quantity_field":    "seats",
                "tier_field":        "tier",
                "auto_renew_field":  "renew",
                "term_months_field": "months",
            },
        )
        assert terms["seat_count"] == 50
        assert terms["subscription_tier"] == "standard"
        assert terms["term_months"] == 24
        assert terms["total_value"] == int(50_000.0 * 100)


# ---------------------------------------------------------------------------
# TestNueOrderCreation
# ---------------------------------------------------------------------------

class TestNueOrderCreation:
    @pytest.mark.asyncio
    async def test_external_reference_contains_session_id(self):
        mock_cm = _make_async_client_mock({"orderId": "nue-order-001", "status": "created"})
        with patch("adapters.nue_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "NUE_API_KEY": "test-api-key",
                "NUE_BASE_URL": "https://api.nue.io",
            }):
                result = await NueEventParser.a2cn_terms_to_nue_order(
                    agreed_terms=SAMPLE_A2CN_AGREED_TERMS,
                    customer_id="cust-techcorp",
                    price_book_id="pb-enterprise-2026",
                    product_id="prod-analytics-001",
                    a2cn_session_id="sess-xyz-789",
                    record_hash="abc123" * 10,
                )

        assert "sess-xyz-789" in result["order_payload_sent"]["externalReference"]

    @pytest.mark.asyncio
    async def test_notes_contain_record_hash(self):
        record_hash = "feedcafe" * 8
        mock_cm = _make_async_client_mock({"orderId": "nue-order-001", "status": "created"})
        with patch("adapters.nue_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "NUE_API_KEY": "test-api-key",
                "NUE_BASE_URL": "https://api.nue.io",
            }):
                result = await NueEventParser.a2cn_terms_to_nue_order(
                    agreed_terms=SAMPLE_A2CN_AGREED_TERMS,
                    customer_id="cust-001",
                    price_book_id="pb-001",
                    product_id="prod-001",
                    a2cn_session_id="sess-001",
                    record_hash=record_hash,
                )

        assert record_hash in result["order_payload_sent"]["notes"]

    @pytest.mark.asyncio
    async def test_start_date_defaults_to_today(self):
        today = date.today().strftime("%Y-%m-%d")
        mock_cm = _make_async_client_mock({"orderId": "nue-order-001", "status": "created"})
        with patch("adapters.nue_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "NUE_API_KEY": "test-api-key",
                "NUE_BASE_URL": "https://api.nue.io",
            }):
                result = await NueEventParser.a2cn_terms_to_nue_order(
                    agreed_terms=SAMPLE_A2CN_AGREED_TERMS,
                    customer_id="cust-001",
                    price_book_id="pb-001",
                    product_id="prod-001",
                    a2cn_session_id="sess-001",
                    record_hash="hash-001",
                    start_date=None,
                )

        assert result["order_payload_sent"]["startDate"] == today

    @pytest.mark.asyncio
    async def test_explicit_start_date_honoured(self):
        mock_cm = _make_async_client_mock({"orderId": "nue-order-001", "status": "created"})
        with patch("adapters.nue_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "NUE_API_KEY": "test-api-key",
                "NUE_BASE_URL": "https://api.nue.io",
            }):
                result = await NueEventParser.a2cn_terms_to_nue_order(
                    agreed_terms=SAMPLE_A2CN_AGREED_TERMS,
                    customer_id="cust-001",
                    price_book_id="pb-001",
                    product_id="prod-001",
                    a2cn_session_id="sess-001",
                    record_hash="hash-001",
                    start_date="2026-07-01",
                )

        assert result["order_payload_sent"]["startDate"] == "2026-07-01"

    @pytest.mark.asyncio
    async def test_line_item_prices_converted_to_dollars(self):
        mock_cm = _make_async_client_mock({"orderId": "nue-order-001", "status": "created"})
        with patch("adapters.nue_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "NUE_API_KEY": "test-api-key",
                "NUE_BASE_URL": "https://api.nue.io",
            }):
                result = await NueEventParser.a2cn_terms_to_nue_order(
                    agreed_terms=SAMPLE_A2CN_AGREED_TERMS,
                    customer_id="cust-001",
                    price_book_id="pb-001",
                    product_id="prod-001",
                    a2cn_session_id="sess-001",
                    record_hash="hash-001",
                )

        # 105_000 cents → $1050.00
        assert result["order_payload_sent"]["lines"][0]["unitPrice"] == pytest.approx(1050.0)

    @pytest.mark.asyncio
    async def test_fallback_unit_price_is_per_seat_not_total(self):
        # $105,000 total / 100 seats = $1050.00 per seat
        terms_no_line_items = {
            "deal_type": "saas_renewal",
            "total_value": 10_500_000,  # cents
            "seat_count": 100,
            "term_months": 12,
            "line_items": [],
        }
        mock_cm = _make_async_client_mock({"orderId": "nue-order-002", "status": "created"})
        with patch("adapters.nue_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "NUE_API_KEY": "test-api-key",
                "NUE_BASE_URL": "https://api.nue.io",
            }):
                result = await NueEventParser.a2cn_terms_to_nue_order(
                    agreed_terms=terms_no_line_items,
                    customer_id="cust-001",
                    price_book_id="pb-001",
                    product_id="prod-001",
                    a2cn_session_id="sess-002",
                    record_hash="hash-002",
                )

        line = result["order_payload_sent"]["lines"][0]
        assert line["quantity"] == 100
        # $105,000 / 100 seats = $1050.00 per seat
        assert line["unitPrice"] == pytest.approx(1050.0)

    @pytest.mark.asyncio
    async def test_fallback_single_seat_unit_price_equals_total(self):
        terms_single = {
            "total_value": 50_000,  # $500 in cents
            "seat_count": 1,
            "term_months": 12,
            "line_items": [],
        }
        mock_cm = _make_async_client_mock({"orderId": "nue-order-003", "status": "created"})
        with patch("adapters.nue_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "NUE_API_KEY": "test-api-key",
                "NUE_BASE_URL": "https://api.nue.io",
            }):
                result = await NueEventParser.a2cn_terms_to_nue_order(
                    agreed_terms=terms_single,
                    customer_id="cust-001",
                    price_book_id="pb-001",
                    product_id="prod-001",
                    a2cn_session_id="sess-003",
                    record_hash="hash-003",
                )

        line = result["order_payload_sent"]["lines"][0]
        assert line["quantity"] == 1
        assert line["unitPrice"] == pytest.approx(500.0)


# ---------------------------------------------------------------------------
# TestNueFetchCustomerSubscriptions
# ---------------------------------------------------------------------------

class TestNueFetchCustomerSubscriptions:
    def test_raises_on_missing_api_key(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("NUE_API_KEY", "NUE_BASE_URL")}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="NUE_API_KEY"):
                import asyncio
                asyncio.get_event_loop().run_until_complete(
                    NueEventParser.fetch_customer_subscriptions("cust-001")
                )

    @pytest.mark.asyncio
    async def test_returns_list_when_api_returns_list(self):
        subs = [{"subscriptionId": "sub-001"}, {"subscriptionId": "sub-002"}]
        mock_cm = _make_async_client_mock(subs)
        with patch("adapters.nue_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "NUE_API_KEY": "test-key",
                "NUE_BASE_URL": "https://api.nue.io",
            }):
                result = await NueEventParser.fetch_customer_subscriptions("cust-001")

        assert len(result) == 2
        assert result[0]["subscriptionId"] == "sub-001"

    @pytest.mark.asyncio
    async def test_returns_list_when_api_wraps_in_dict(self):
        mock_cm = _make_async_client_mock({"subscriptions": [{"subscriptionId": "sub-003"}]})
        with patch("adapters.nue_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "NUE_API_KEY": "test-key",
                "NUE_BASE_URL": "https://api.nue.io",
            }):
                result = await NueEventParser.fetch_customer_subscriptions("cust-001")

        assert result[0]["subscriptionId"] == "sub-003"
