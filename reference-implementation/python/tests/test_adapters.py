"""Tests for platform integration adapters (v0.2.0)."""

from __future__ import annotations

import pytest
from adapters.fairmarkit_adapter import FairmakitEventParser
from adapters.revenue_cloud_adapter import RevenueCloudAdapter


SAMPLE_BID_CREATED = {
    "request_id": "req-abc-123",
    "tenant_id": "acme-corp",
    "status": "submitted",
    "items": [
        {"description": "Hydraulic fluid 200L drums", "quantity": 50,
         "uom": "EA", "unit_price": 360.0},
        {"description": "Sealing compound", "quantity": 10,
         "uom": "KG", "unit_price": 45.0},
    ],
    "deadline": "2026-04-10T17:00:00Z",
}

SAMPLE_PRICING_RESPONSE = {
    "totalAmount": 95000.0,
    "currency": "USD",
    "lineItems": [
        {"productId": "01tXXX", "productName": "Analytics Platform",
         "quantity": 100, "unitPrice": 950.0, "totalPrice": 95000.0,
         "startDate": "2026-07-01", "endDate": "2027-06-30"}
    ],
}


class TestFairmakitAdapter:
    def test_parse_bid_created_summary(self):
        result = FairmakitEventParser.parse_bid_created_webhook(SAMPLE_BID_CREATED)
        assert result["item_count"] == 2
        assert result["fairmarkit_request_id"] == "req-abc-123"
        # 50 * $360 = $18,000 = 1,800,000 cents; 10 * $45 = $450 = 45,000 cents
        assert result["estimated_value"] == 50 * 36000 + 10 * 4500

    def test_parse_bid_created_summary_currency(self):
        result = FairmakitEventParser.parse_bid_created_webhook(SAMPLE_BID_CREATED)
        assert result["currency"] == "USD"

    def test_parse_bid_created_summary_deadline(self):
        result = FairmakitEventParser.parse_bid_created_webhook(SAMPLE_BID_CREATED)
        assert result["deadline"] == "2026-04-10T17:00:00Z"

    def test_parse_empty_items(self):
        result = FairmakitEventParser.parse_bid_created_webhook(
            {"request_id": "r1", "items": [], "deadline": "2026-04-10T17:00:00Z"}
        )
        assert result["item_count"] == 0
        assert result["estimated_value"] == 0

    def test_bid_created_to_goods_procurement_terms(self):
        terms = FairmakitEventParser.bid_created_to_goods_procurement_terms(SAMPLE_BID_CREATED)
        assert terms["currency"] == "USD"
        assert len(terms["line_items"]) == 2
        assert terms["line_items"][0]["unit_of_measure"] == "EA"
        assert terms["line_items"][1]["unit_of_measure"] == "KG"
        assert "delivery_days" in terms

    def test_bid_created_line_item_prices_in_cents(self):
        terms = FairmakitEventParser.bid_created_to_goods_procurement_terms(SAMPLE_BID_CREATED)
        # $360.0 → 36000 cents
        assert terms["line_items"][0]["unit_price"] == 36000

    def test_bid_created_total_value_in_cents(self):
        terms = FairmakitEventParser.bid_created_to_goods_procurement_terms(SAMPLE_BID_CREATED)
        # 50 * 36000 + 10 * 4500
        assert terms["total_value"] == 50 * 36000 + 10 * 4500

    def test_terms_to_fairmarkit_response(self):
        terms = FairmakitEventParser.bid_created_to_goods_procurement_terms(SAMPLE_BID_CREATED)
        response = FairmakitEventParser.terms_to_fairmarkit_response(
            terms, session_id="sess-001", request_id="req-abc-123"
        )
        assert response["request_id"] == "req-abc-123"
        assert response["a2cn_session_id"] == "sess-001"
        assert response["currency"] == "USD"
        assert len(response["items"]) == 2

    def test_fairmarkit_response_prices_in_dollars(self):
        terms = FairmakitEventParser.bid_created_to_goods_procurement_terms(SAMPLE_BID_CREATED)
        response = FairmakitEventParser.terms_to_fairmarkit_response(
            terms, session_id="sess-001", request_id="req-abc-123"
        )
        # 36000 cents → $360.0
        assert response["items"][0]["unit_price"] == 360.0

    def test_fairmarkit_response_uom_passthrough(self):
        terms = FairmakitEventParser.bid_created_to_goods_procurement_terms(SAMPLE_BID_CREATED)
        response = FairmakitEventParser.terms_to_fairmarkit_response(
            terms, session_id="sess-001", request_id="r1"
        )
        assert response["items"][0]["uom"] == "EA"
        assert response["items"][1]["uom"] == "KG"


class TestRevenueCloudAdapter:
    def test_pricing_response_to_saas_renewal_terms(self):
        terms = RevenueCloudAdapter.pricing_response_to_a2cn_terms(
            SAMPLE_PRICING_RESPONSE, deal_type="saas_renewal"
        )
        assert terms["total_value"] == 9500000  # $95,000 in cents
        assert terms["currency"] == "USD"
        assert terms["seat_count"] == 100
        assert terms["contract_duration"]["start_date"] == "2026-07-01"
        assert terms["contract_duration"]["end_date"] == "2027-06-30"

    def test_pricing_response_line_items(self):
        terms = RevenueCloudAdapter.pricing_response_to_a2cn_terms(SAMPLE_PRICING_RESPONSE)
        assert len(terms["line_items"]) == 1
        assert terms["line_items"][0]["description"] == "Analytics Platform"
        assert terms["line_items"][0]["unit_price"] == 95000  # $950 in cents

    def test_pricing_response_no_seat_count_for_other_deal_type(self):
        terms = RevenueCloudAdapter.pricing_response_to_a2cn_terms(
            SAMPLE_PRICING_RESPONSE, deal_type="goods_procurement"
        )
        assert "seat_count" not in terms

    def test_a2cn_terms_to_order_payload(self):
        terms = RevenueCloudAdapter.pricing_response_to_a2cn_terms(SAMPLE_PRICING_RESPONSE)
        order = RevenueCloudAdapter.a2cn_terms_to_order_payload(
            terms, account_id="001XXX", pricebook_id="01sXXX"
        )
        assert order["transactionType"] == "Order"
        assert order["accountId"] == "001XXX"
        assert len(order["lineItems"]) == 1
        assert order["lineItems"][0]["unitPrice"] == 950.0

    def test_a2cn_terms_to_quote_payload_type(self):
        terms = RevenueCloudAdapter.pricing_response_to_a2cn_terms(SAMPLE_PRICING_RESPONSE)
        quote = RevenueCloudAdapter.a2cn_terms_to_quote_payload(
            terms, "001XXX", "01sXXX", transaction_type="Quote"
        )
        assert quote["transactionType"] == "Quote"

    def test_a2cn_terms_to_quote_includes_dates(self):
        terms = RevenueCloudAdapter.pricing_response_to_a2cn_terms(SAMPLE_PRICING_RESPONSE)
        payload = RevenueCloudAdapter.a2cn_terms_to_quote_payload(terms, "001XXX", "01sXXX")
        assert payload["startDate"] == "2026-07-01"
        assert payload["endDate"] == "2027-06-30"

    def test_pricing_response_uses_total_amount_fallback(self):
        # When lineItems have 0 prices, fall back to totalAmount
        response = {
            "totalAmount": 5000.0,
            "currency": "USD",
            "lineItems": [
                {"productName": "X", "quantity": 1, "unitPrice": 0.0, "totalPrice": 0.0}
            ],
        }
        terms = RevenueCloudAdapter.pricing_response_to_a2cn_terms(response)
        assert terms["total_value"] == 500000  # $5000 in cents
