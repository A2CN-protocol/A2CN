"""Tests for platform integration adapters (v0.2.0)."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from adapters.fairmarkit_adapter import FairmakitEventParser
from adapters.keelvar_adapter import KeelvarEventParser
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


# ---------------------------------------------------------------------------
# Keelvar adapter tests
#
# Field mapping (Keelvar → A2CN goods_procurement):
#   event.line_items[].description     → line_items[].description
#   event.line_items[].quantity        → line_items[].quantity
#   event.line_items[].unit_of_measure → line_items[].unit_of_measure
#   event.line_items[].unit_price (USD)→ line_items[].unit_price (cents)
#   event.line_items[].lot_id          → line_items[].internal_part_number
#   event.currency                     → currency
#   Computed from line items           → total_value (cents)
#   default_delivery_days param        → delivery_days
#   Hardcoded default 30               → payment_terms.net_days
# ---------------------------------------------------------------------------

SAMPLE_SOURCING_EVENT = {
    "event_id": "evt-keelvar-001",
    "event_name": "Q3 2026 Industrial Supplies RFQ",
    "buyer_org": "AcmeBuyer Corp",
    "deadline": "2026-05-01T17:00:00Z",
    "currency": "EUR",
    "line_items": [
        {
            "description": "Hydraulic fluid 200L drums",
            "quantity": 50,
            "unit_of_measure": "EA",
            "unit_price": 360.0,
            "lot_id": "LOT-HF-001",
        },
        {
            "description": "Sealing compound 5kg tubs",
            "quantity": 20,
            "unit_of_measure": "KG",
            "unit_price": 85.0,
            "lot_id": "LOT-SC-002",
        },
        {
            "description": "Safety gloves (box of 100)",
            "quantity": 10,
            "unit_of_measure": "BX",
            "unit_price": 45.0,
            # no lot_id — optional field
        },
    ],
}

SAMPLE_SOURCING_EVENT_NO_PRICE = {
    "event_id": "evt-keelvar-002",
    "event_name": "Open Bid — Supplier Sets Price",
    "buyer_org": "GlobalBuyer Ltd",
    "deadline": None,
    "currency": "USD",
    "line_items": [
        {
            "description": "Custom machined bracket",
            "quantity": 100,
            "unit_of_measure": "EA",
            # unit_price intentionally absent — buyer hasn't set benchmark
            "lot_id": "LOT-MB-007",
        },
    ],
}


class TestKeelvarAdapter:
    def test_parse_sourcing_event_webhook_basic(self):
        result = KeelvarEventParser.parse_sourcing_event_webhook(SAMPLE_SOURCING_EVENT)
        assert result["event_id"] == "evt-keelvar-001"
        assert result["event_name"] == "Q3 2026 Industrial Supplies RFQ"
        assert result["buyer_org"] == "AcmeBuyer Corp"
        assert result["deadline"] == "2026-05-01T17:00:00Z"
        assert result["currency"] == "EUR"
        assert len(result["line_items"]) == 3
        assert result["line_items"][0]["description"] == "Hydraulic fluid 200L drums"
        assert result["line_items"][0]["quantity"] == 50
        assert result["line_items"][0]["lot_id"] == "LOT-HF-001"
        assert result["raw_payload"] is SAMPLE_SOURCING_EVENT

    def test_parse_sourcing_event_webhook_price_in_cents(self):
        result = KeelvarEventParser.parse_sourcing_event_webhook(SAMPLE_SOURCING_EVENT)
        # $360.0 → 36000 cents
        assert result["line_items"][0]["unit_price_cents"] == 36000
        assert result["line_items"][1]["unit_price_cents"] == 8500

    def test_parse_sourcing_event_webhook_missing_price(self):
        result = KeelvarEventParser.parse_sourcing_event_webhook(
            SAMPLE_SOURCING_EVENT_NO_PRICE
        )
        assert result["line_items"][0]["unit_price_cents"] is None

    def test_sourcing_event_to_goods_procurement_terms_total_value(self):
        # 50 * $360 = $18,000 = 1,800,000 cents
        # 20 * $85  =  $1,700 =   170,000 cents
        # 10 * $45  =    $450 =    45,000 cents
        # total = 2,015,000 cents
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT
        )
        assert terms["total_value"] == 50 * 36_000 + 20 * 8_500 + 10 * 4_500

    def test_sourcing_event_to_goods_procurement_terms_currency(self):
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT
        )
        assert terms["currency"] == "EUR"

    def test_sourcing_event_to_goods_procurement_terms_default_delivery(self):
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT
        )
        assert terms["delivery_days"] == 14
        assert terms["payment_terms"] == {"net_days": 30}

    def test_sourcing_event_to_goods_procurement_terms_custom_delivery(self):
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT, default_delivery_days=21
        )
        assert terms["delivery_days"] == 21

    def test_sourcing_event_to_goods_procurement_terms_zero_price(self):
        """When unit_price is absent total_value must be 0."""
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT_NO_PRICE
        )
        assert terms["total_value"] == 0
        assert terms["line_items"][0]["unit_price"] == 0

    def test_sourcing_event_lot_id_to_internal_part_number(self):
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT
        )
        assert terms["line_items"][0]["internal_part_number"] == "LOT-HF-001"
        assert terms["line_items"][1]["internal_part_number"] == "LOT-SC-002"
        # third item has no lot_id — field should be absent
        assert "internal_part_number" not in terms["line_items"][2]

    def test_terms_to_keelvar_bid_response_structure(self):
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT
        )
        response = KeelvarEventParser.terms_to_keelvar_bid_response(
            terms, event_id="evt-keelvar-001"
        )
        assert response["event_id"] == "evt-keelvar-001"
        assert response["currency"] == "EUR"
        assert response["status"] == "submitted"
        assert response["delivery_days"] == 14
        assert len(response["line_items"]) == 3

    def test_terms_to_keelvar_bid_response_price_conversion(self):
        """Prices must be in dollars (not cents) in the bid response."""
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT
        )
        response = KeelvarEventParser.terms_to_keelvar_bid_response(
            terms, event_id="evt-keelvar-001"
        )
        # 36000 cents → $360.0
        assert response["line_items"][0]["unit_price"] == 360.0
        # total_value in cents → dollars
        expected_total = (50 * 36_000 + 20 * 8_500 + 10 * 4_500) / 100.0
        assert response["total_price"] == pytest.approx(expected_total)

    def test_terms_to_keelvar_bid_response_supplier_id(self):
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT
        )
        response = KeelvarEventParser.terms_to_keelvar_bid_response(
            terms, event_id="evt-001", supplier_id="sup-xyz-999"
        )
        assert response["supplier_id"] == "sup-xyz-999"

    def test_terms_to_keelvar_bid_response_no_supplier_id(self):
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT
        )
        response = KeelvarEventParser.terms_to_keelvar_bid_response(
            terms, event_id="evt-001"
        )
        assert "supplier_id" not in response

    def test_verify_webhook_signature_valid(self):
        signing_key = "keelvar-secret-signing-key"
        body = json.dumps({"event_id": "evt-001"}).encode("utf-8")
        expected_sig = hmac.new(
            signing_key.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        assert KeelvarEventParser.verify_webhook_signature(
            body, expected_sig, signing_key
        ) is True

    def test_verify_webhook_signature_invalid(self):
        body = b'{"event_id": "evt-001"}'
        assert KeelvarEventParser.verify_webhook_signature(
            body, "wrong-signature", "correct-key"
        ) is False

    def test_verify_webhook_signature_wrong_key(self):
        body = b'{"event_id": "evt-001"}'
        real_sig = hmac.new(b"real-key", body, hashlib.sha256).hexdigest()
        assert KeelvarEventParser.verify_webhook_signature(
            body, real_sig, "wrong-key"
        ) is False

    def test_field_mapping_completeness(self):
        """Round-trip: parse → terms → bid response preserves all line item data."""
        terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
            SAMPLE_SOURCING_EVENT
        )
        response = KeelvarEventParser.terms_to_keelvar_bid_response(
            terms, event_id=SAMPLE_SOURCING_EVENT["event_id"]
        )

        # Every source line item maps to a response line item
        assert len(response["line_items"]) == len(SAMPLE_SOURCING_EVENT["line_items"])

        # Descriptions survive the round-trip unchanged
        src_descs = [li["description"] for li in SAMPLE_SOURCING_EVENT["line_items"]]
        out_descs = [li["description"] for li in response["line_items"]]
        assert src_descs == out_descs

        # lot_id → internal_part_number → lot_id in bid response
        assert response["line_items"][0]["lot_id"] == "LOT-HF-001"
        assert response["line_items"][1]["lot_id"] == "LOT-SC-002"

        # unit_of_measure passes through
        assert response["line_items"][0]["unit_of_measure"] == "EA"
        assert response["line_items"][1]["unit_of_measure"] == "KG"
