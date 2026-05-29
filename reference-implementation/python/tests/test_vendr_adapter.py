"""Tests for Vendr MCP/webhook platform adapter."""

from __future__ import annotations

import hashlib
import hmac

from a2cn.messages import validate_deal_type_terms
from adapters.vendr_adapter import (
    VendrWebhookParser,
    a2cn_terms_to_vendr_summary,
    vendr_pricing_to_a2cn_terms,
    webhook_body_for_signature,
)


SAMPLE_VENDR_PRICING = {
    "vendor": "Acme Analytics",
    "product": "Enterprise Analytics Suite",
    "list_price": 1200.0,
    "seat_count": 100,
    "currency": "USD",
    "term_months": 12,
    "observed_discount_band": {"min": 0.15, "max": 0.25},
    "benchmark_range": {"low": 85000.0, "median": 95000.0, "high": 110000.0},
    "source": "vendr_mcp",
}

SAMPLE_VENDR_WEBHOOK = {
    "event_id": "vendr-evt-001",
    "event_type": "renewal.workflow.updated",
    "workflow_id": "vendr-wf-001",
    "buyer_org": "TechCorp",
    "renewal_date": "2026-07-01",
    "vendor": "Acme Analytics",
    "product": "Enterprise Analytics Suite",
    "list_price": 1200.0,
    "seat_count": 100,
    "currency": "USD",
    "term_months": 12,
    "observed_discount_band": {"min": 0.15, "max": 0.25},
}


class TestVendrPricingToA2CNTerms:
    def test_pricing_maps_to_saas_renewal_terms(self):
        terms = vendr_pricing_to_a2cn_terms(SAMPLE_VENDR_PRICING)

        assert terms["deal_type"] == "saas_renewal"
        assert terms["currency"] == "USD"
        assert terms["seat_count"] == 100
        assert terms["subscription_tier"] == "Enterprise Analytics Suite"
        assert validate_deal_type_terms("saas_renewal", terms) == []

    def test_discount_midpoint_applied_and_converted_to_cents(self):
        terms = vendr_pricing_to_a2cn_terms(SAMPLE_VENDR_PRICING)

        # $1200 list * 20% midpoint discount = $960 per seat.
        assert terms["line_items"][0]["unit_price"] == 96_000
        assert terms["total_value"] == 9_600_000

    def test_benchmark_range_converted_to_cents(self):
        terms = vendr_pricing_to_a2cn_terms(SAMPLE_VENDR_PRICING)

        benchmark = terms["custom_terms"]["vendr"]["benchmark_range"]
        assert benchmark["low"] == 8_500_000
        assert benchmark["median"] == 9_500_000
        assert benchmark["high"] == 11_000_000
        assert terms["custom_terms"]["vendr"]["source"] == "vendr_mcp"

    def test_percentage_discount_values_are_supported(self):
        pricing = {
            "product": "Security Platform",
            "list_price": 1000.0,
            "seat_count": 10,
            "observed_discount_band": {"min": 10, "max": 20},
        }

        terms = vendr_pricing_to_a2cn_terms(pricing)

        assert terms["line_items"][0]["unit_price"] == 85_000
        assert terms["total_value"] == 850_000

    def test_flat_observed_discount_field_is_supported(self):
        terms = vendr_pricing_to_a2cn_terms({
            "product": "AI Contract Review",
            "list_price": 2000.0,
            "seat_count": 5,
            "observed_discount": 0.25,
        })

        assert terms["line_items"][0]["unit_price"] == 150_000
        assert terms["total_value"] == 750_000
        assert terms["custom_terms"]["vendr"]["observed_discount"] == 0.25

    def test_missing_seat_count_defaults_to_one_valid_seat(self):
        terms = vendr_pricing_to_a2cn_terms({"list_price": 500.0})

        assert terms["seat_count"] == 1
        assert validate_deal_type_terms("saas_renewal", terms) == []


class TestVendrWebhookParser:
    def test_webhook_parse_returns_session_params_and_terms(self):
        parsed = VendrWebhookParser.parse_renewal_webhook(SAMPLE_VENDR_WEBHOOK)

        assert parsed["event_id"] == "vendr-evt-001"
        assert parsed["workflow_id"] == "vendr-wf-001"
        assert parsed["session_params"]["deal_type"] == "saas_renewal"
        assert parsed["session_params"]["vendr_event_id"] == "vendr-evt-001"
        assert parsed["session_params"]["vendr_workflow_id"] == "vendr-wf-001"
        assert parsed["initial_terms"]["total_value"] == 9_600_000

    def test_webhook_nested_pricing_shape_supported(self):
        payload = {
            "event_id": "vendr-evt-002",
            "workflowId": "vendr-wf-002",
            "buyerOrg": "MegaBuyer",
            "renewalDate": "2026-09-01",
            "pricing": SAMPLE_VENDR_PRICING,
        }

        parsed = VendrWebhookParser.parse_renewal_webhook(payload, max_rounds=3)

        assert parsed["session_params"]["max_rounds"] == 3
        assert parsed["session_params"]["buyer_org"] == "MegaBuyer"
        assert parsed["session_params"]["renewal_date"] == "2026-09-01"
        assert parsed["initial_terms"]["seat_count"] == 100

    def test_webhook_signature_accepts_prefixed_sha256_digest(self):
        body = webhook_body_for_signature(SAMPLE_VENDR_WEBHOOK)
        secret = "vendr-secret"
        digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

        assert VendrWebhookParser.verify_webhook_signature(
            body,
            f"sha256={digest}",
            secret,
        )

    def test_webhook_signature_accepts_v1_prefixed_digest(self):
        body = webhook_body_for_signature(SAMPLE_VENDR_WEBHOOK)
        secret = "vendr-secret"
        digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

        assert VendrWebhookParser.verify_webhook_signature(
            body,
            f"v1={digest}",
            secret,
        )

    def test_webhook_signature_rejects_wrong_digest(self):
        body = webhook_body_for_signature(SAMPLE_VENDR_WEBHOOK)

        assert not VendrWebhookParser.verify_webhook_signature(
            body,
            "sha256=not-the-real-digest",
            "vendr-secret",
        )


class TestVendrRoundTripSummary:
    def test_terms_to_vendr_summary_converts_cents_to_dollars(self):
        terms = vendr_pricing_to_a2cn_terms(SAMPLE_VENDR_PRICING)
        summary = a2cn_terms_to_vendr_summary(
            terms,
            session_id="sess-vendr-001",
            record_hash="deadbeef" * 8,
            workflow_id="vendr-wf-001",
        )

        assert summary["source"] == "a2cn"
        assert summary["a2cn_session_id"] == "sess-vendr-001"
        assert summary["workflow_id"] == "vendr-wf-001"
        assert summary["total_value"] == 96_000.0
        assert summary["unit_price"] == 960.0
        assert summary["payment_terms"] == "Net 30"

    def test_summary_preserves_vendr_vendor_and_product(self):
        terms = vendr_pricing_to_a2cn_terms(SAMPLE_VENDR_PRICING)
        summary = a2cn_terms_to_vendr_summary(
            terms,
            session_id="sess-vendr-002",
            record_hash="cafebabe" * 8,
        )

        assert summary["vendor"] == "Acme Analytics"
        assert summary["product"] == "Enterprise Analytics Suite"
        assert summary["status"] == "negotiated"
