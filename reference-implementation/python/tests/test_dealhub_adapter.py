"""Tests for DealHub CPQ platform adapter."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from adapters.dealhub_adapter import DealHubEventParser


# ---------------------------------------------------------------------------
# Sample payloads
# ---------------------------------------------------------------------------

SAMPLE_QUOTE_READY_SAAS = {
    "event_info": {"webhook_id": "wh-001", "event_id": "evt-001", "api_version": "1.0"},
    "dealhub_quote_id": "dh-q-001",
    "dealhub_opportunity_id": "dh-opp-001",
    "execution_date": "2026-04-28T10:00:00Z",
    "executed_by": "rep@company.com",
    "currency": "USD",
    # items enriched from quote API (PATH A)
    "items": [
        {"product_name": "Enterprise Subscription 500 seats", "quantity": 500, "unit_price": 200.0},
    ],
}

SAMPLE_QUOTE_READY_GOODS = {
    "event_info": {"webhook_id": "wh-002", "event_id": "evt-002", "api_version": "1.0"},
    "dealhub_quote_id": "dh-q-002",
    "dealhub_opportunity_id": "dh-opp-002",
    "execution_date": "2026-04-28T11:00:00Z",
    "executed_by": "rep@company.com",
    "currency": "USD",
    "items": [
        {"product_name": "Industrial Hydraulic Pump", "quantity": 10, "unit_price": 1500.0},
        {"product_name": "O-Ring Seal Kit", "quantity": 50, "unit_price": 25.0},
    ],
}

SAMPLE_QUOTE_RESPONSE = {
    "total_price": 100000.0,
    "currency": "USD",
    "line_items": [
        {"product_name": "Analytics Platform License", "quantity": 100, "unit_price": 950.0},
        {"product_name": "Support Package", "quantity": 1, "unit_price": 5000.0},
    ],
}

SAMPLE_QUOTE_RESPONSE_GOODS = {
    "total_price": 18000.0,
    "currency": "EUR",
    "line_items": [
        {"product_name": "Hydraulic fluid 200L drums", "quantity": 50, "unit_price": 360.0},
    ],
}


# ---------------------------------------------------------------------------
# Async HTTP mock helper
# ---------------------------------------------------------------------------

def _make_async_client_mock(json_data: dict, status_code: int = 200):
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
# TestDealHubWebhookToSessionParams
# ---------------------------------------------------------------------------

class TestDealHubWebhookToSessionParams:
    def test_subscription_products_yield_saas_renewal(self):
        params = DealHubEventParser.quote_ready_webhook_to_session_params(
            SAMPLE_QUOTE_READY_SAAS
        )
        assert params["deal_type"] == "saas_renewal"

    def test_physical_goods_yield_goods_procurement(self):
        params = DealHubEventParser.quote_ready_webhook_to_session_params(
            SAMPLE_QUOTE_READY_GOODS
        )
        assert params["deal_type"] == "goods_procurement"

    def test_session_params_include_quote_and_opportunity_ids(self):
        params = DealHubEventParser.quote_ready_webhook_to_session_params(
            SAMPLE_QUOTE_READY_SAAS
        )
        assert params["dealhub_quote_id"] == "dh-q-001"
        assert params["dealhub_opportunity_id"] == "dh-opp-001"

    def test_session_params_currency_passthrough(self):
        params = DealHubEventParser.quote_ready_webhook_to_session_params(
            SAMPLE_QUOTE_READY_GOODS
        )
        assert params["currency"] == "USD"

    def test_no_items_defaults_to_goods_procurement(self):
        payload = {
            "dealhub_quote_id": "dh-q-003",
            "dealhub_opportunity_id": "dh-opp-003",
        }
        params = DealHubEventParser.quote_ready_webhook_to_session_params(payload)
        assert params["deal_type"] == "goods_procurement"

    def test_max_rounds_default_is_five(self):
        params = DealHubEventParser.quote_ready_webhook_to_session_params(
            SAMPLE_QUOTE_READY_SAAS
        )
        assert params["max_rounds"] == 5

    def test_max_rounds_configurable(self):
        params = DealHubEventParser.quote_ready_webhook_to_session_params(
            SAMPLE_QUOTE_READY_SAAS, max_rounds=3
        )
        assert params["max_rounds"] == 3


# ---------------------------------------------------------------------------
# TestDealHubQuoteToOfferTerms
# ---------------------------------------------------------------------------

class TestDealHubQuoteToOfferTerms:
    def test_default_field_map_extracts_total_value_in_cents(self):
        # 100 * $950 + 1 * $5000 = $100,000 = 10,000,000 cents
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(SAMPLE_QUOTE_RESPONSE)
        assert terms["total_value"] == 10_000_000

    def test_default_field_map_extracts_currency(self):
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(SAMPLE_QUOTE_RESPONSE)
        assert terms["currency"] == "USD"

    def test_saas_renewal_terms_include_seat_count(self):
        # "Analytics Platform License" contains "license" → saas_renewal → seat_count included
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(SAMPLE_QUOTE_RESPONSE)
        assert "seat_count" in terms
        assert terms["seat_count"] == 100  # quantity from first line item

    def test_goods_procurement_terms_include_delivery_days(self):
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(SAMPLE_QUOTE_RESPONSE_GOODS)
        assert "delivery_days" in terms
        assert terms["delivery_days"] == 14

    def test_custom_field_map_overrides_product_name_field(self):
        quote = {
            "grand_total": 5000.0,
            "ccy": "GBP",
            "items": [
                {"name": "Widget Pro", "qty": 10, "price": 500.0},
            ],
        }
        custom_map = {
            "total_value_field":  "grand_total",
            "currency_field":     "ccy",
            "line_items_field":   "items",
            "product_name_field": "name",
            "quantity_field":     "qty",
            "unit_price_field":   "price",
        }
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(quote, field_map=custom_map)
        assert terms["currency"] == "GBP"
        assert terms["line_items"][0]["description"] == "Widget Pro"
        assert terms["line_items"][0]["quantity"] == 10
        # $500 → 50000 cents
        assert terms["line_items"][0]["unit_price"] == 50_000

    def test_line_items_prices_converted_to_cents(self):
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(SAMPLE_QUOTE_RESPONSE_GOODS)
        # $360.0 → 36000 cents
        assert terms["line_items"][0]["unit_price"] == 36_000

    def test_total_fallback_to_header_when_line_items_empty(self):
        quote = {"total_price": 7500.0, "currency": "USD", "line_items": []}
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(quote)
        assert terms["total_value"] == 750_000  # $7500 in cents

    def test_unit_of_measure_included_when_present(self):
        quote = {
            "total_price": 5000.0,
            "currency": "USD",
            "line_items": [
                {
                    "product_name": "Industrial Hydraulic Pump",
                    "quantity": 10,
                    "unit_price": 500.0,
                    "unit_of_measure": "EA",
                },
            ],
        }
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(quote)
        assert terms["line_items"][0]["unit_of_measure"] == "EA"

    def test_unit_of_measure_omitted_when_absent(self):
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(SAMPLE_QUOTE_RESPONSE_GOODS)
        assert "unit_of_measure" not in terms["line_items"][0]

    def test_custom_unit_of_measure_field_name(self):
        quote = {
            "total_price": 1000.0,
            "currency": "USD",
            "line_items": [
                {"product_name": "Widget", "quantity": 5, "unit_price": 200.0, "uom": "KG"},
            ],
        }
        terms = DealHubEventParser.quote_to_a2cn_offer_terms(
            quote, field_map={"unit_of_measure_field": "uom"}
        )
        assert terms["line_items"][0]["unit_of_measure"] == "KG"


# ---------------------------------------------------------------------------
# TestDealHubMandateBounds
# ---------------------------------------------------------------------------

class TestDealHubMandateBounds:
    @pytest.mark.asyncio
    async def test_floor_is_ceiling_minus_discount(self):
        mock_cm = _make_async_client_mock(
            {"total_price": 100000.0, "currency": "USD", "line_items": []}
        )
        with patch("adapters.dealhub_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "DEALHUB_AUTH_TOKEN": "test-token",
                "DEALHUB_BASE_URL": "https://test.dealhub.io",
            }):
                result = await DealHubEventParser.simulate_quote_for_mandate_bounds(
                    playbook_id="pb-001",
                    answers={"product_id": "prod-001", "quantity": 1},
                    floor_discount_pct=0.15,
                )

        ceiling = result["ceiling_value_cents"]
        floor = result["floor_value_cents"]
        assert floor == int(ceiling * 0.85)

    @pytest.mark.asyncio
    async def test_floor_discount_pct_applied_correctly(self):
        mock_cm = _make_async_client_mock(
            {"total_price": 10000.0, "currency": "USD", "line_items": []}
        )
        with patch("adapters.dealhub_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "DEALHUB_AUTH_TOKEN": "tok",
                "DEALHUB_BASE_URL": "https://test.dealhub.io",
            }):
                result = await DealHubEventParser.simulate_quote_for_mandate_bounds(
                    playbook_id="pb-001",
                    answers={},
                    floor_discount_pct=0.20,
                )

        # $10,000 → 1,000,000 cents ceiling; 80% of ceiling = 800,000 floor
        assert result["ceiling_value_cents"] == 1_000_000
        assert result["floor_value_cents"] == 800_000

    def test_simulate_raises_on_empty_playbook_id(self):
        with pytest.raises(ValueError, match="playbook_id is required"):
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                DealHubEventParser.simulate_quote_for_mandate_bounds(
                    playbook_id="",
                    answers={},
                )
            )

    def test_simulate_raises_on_missing_env_vars(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("DEALHUB_AUTH_TOKEN", "DEALHUB_BASE_URL")}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="DEALHUB_AUTH_TOKEN"):
                import asyncio
                asyncio.get_event_loop().run_until_complete(
                    DealHubEventParser.simulate_quote_for_mandate_bounds(
                        playbook_id="pb-001",
                        answers={},
                    )
                )


# ---------------------------------------------------------------------------
# TestDealHubActionsApi
# ---------------------------------------------------------------------------

class TestDealHubActionsApi:
    @pytest.mark.asyncio
    async def test_action_payload_includes_session_id(self):
        mock_cm = _make_async_client_mock({"status": "success"})
        with patch("adapters.dealhub_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "DEALHUB_AUTH_TOKEN": "test-token",
                "DEALHUB_BASE_URL": "https://test.dealhub.io",
            }):
                result = await DealHubEventParser.agreed_terms_to_dealhub_action(
                    quote_id="dh-q-001",
                    a2cn_session_id="sess-abc-123",
                    record_hash="deadbeef" * 8,
                )

        assert "sess-abc-123" in result["action_payload_sent"]["note"]

    @pytest.mark.asyncio
    async def test_action_payload_includes_record_hash(self):
        mock_cm = _make_async_client_mock({"status": "success"})
        with patch("adapters.dealhub_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "DEALHUB_AUTH_TOKEN": "test-token",
                "DEALHUB_BASE_URL": "https://test.dealhub.io",
            }):
                result = await DealHubEventParser.agreed_terms_to_dealhub_action(
                    quote_id="dh-q-001",
                    a2cn_session_id="sess-abc-123",
                    record_hash="cafebabe" * 8,
                )

        assert "cafebabe" * 8 in result["action_payload_sent"]["note"]

    @pytest.mark.asyncio
    async def test_action_uses_sign_externally_action(self):
        mock_cm = _make_async_client_mock({})
        with patch("adapters.dealhub_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "DEALHUB_AUTH_TOKEN": "tok",
                "DEALHUB_BASE_URL": "https://test.dealhub.io",
            }):
                result = await DealHubEventParser.agreed_terms_to_dealhub_action(
                    "dh-q-001", "sess-001", "hash-001"
                )

        assert result["action_payload_sent"]["action"] == "signExternally"


# ---------------------------------------------------------------------------
# TestDealHubFetchQuoteDetails
# ---------------------------------------------------------------------------

class TestDealHubFetchQuoteDetails:
    def test_raises_on_missing_env_vars(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("DEALHUB_AUTH_TOKEN", "DEALHUB_BASE_URL")}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="DEALHUB_AUTH_TOKEN"):
                import asyncio
                asyncio.get_event_loop().run_until_complete(
                    DealHubEventParser.fetch_quote_details("dh-q-001")
                )

    @pytest.mark.asyncio
    async def test_returns_json_on_success(self):
        mock_cm = _make_async_client_mock({"dealhub_quote_id": "dh-q-001"}, status_code=200)
        with patch("adapters.dealhub_adapter.httpx.AsyncClient", return_value=mock_cm):
            with patch.dict(os.environ, {
                "DEALHUB_AUTH_TOKEN": "tok",
                "DEALHUB_BASE_URL": "https://test.dealhub.io",
            }):
                result = await DealHubEventParser.fetch_quote_details("dh-q-001")

        assert result["dealhub_quote_id"] == "dh-q-001"
