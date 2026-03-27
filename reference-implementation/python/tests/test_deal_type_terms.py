"""Tests for deal-type-specific terms validation (OQ-004, v0.2.0)."""

from __future__ import annotations

import pytest
from a2cn.messages import validate_deal_type_terms


class TestGoodsProcurementTerms:
    def test_valid_terms_returns_empty_errors(self):
        terms = {
            "total_value": 1800000,
            "currency": "USD",
            "line_items": [{"description": "Hydraulic fluid", "quantity": 50,
                            "unit_price": 36000, "total": 1800000,
                            "unit_of_measure": "EA"}],
            "delivery_days": 14,
            "payment_terms": {"net_days": 30},
        }
        assert validate_deal_type_terms("goods_procurement", terms) == []

    def test_missing_delivery_days_returns_error(self):
        terms = {"total_value": 100, "currency": "USD", "line_items": []}
        errors = validate_deal_type_terms("goods_procurement", terms)
        assert any("delivery_days" in e for e in errors)

    def test_invalid_delivery_days_type(self):
        terms = {"total_value": 100, "currency": "USD",
                 "line_items": [], "delivery_days": "two weeks"}
        errors = validate_deal_type_terms("goods_procurement", terms)
        assert len(errors) > 0

    def test_zero_delivery_days_returns_error(self):
        terms = {"total_value": 100, "currency": "USD",
                 "line_items": [], "delivery_days": 0}
        errors = validate_deal_type_terms("goods_procurement", terms)
        assert len(errors) > 0

    def test_negative_delivery_days_returns_error(self):
        terms = {"total_value": 100, "currency": "USD",
                 "line_items": [], "delivery_days": -5}
        errors = validate_deal_type_terms("goods_procurement", terms)
        assert len(errors) > 0

    def test_bool_delivery_days_rejected(self):
        # bool is a subtype of int in Python — must be rejected
        terms = {"total_value": 100, "currency": "USD",
                 "line_items": [], "delivery_days": True}
        errors = validate_deal_type_terms("goods_procurement", terms)
        assert len(errors) > 0


class TestSaaSRenewalTerms:
    def test_valid_terms_returns_empty_errors(self):
        terms = {
            "total_value": 9500000,
            "currency": "USD",
            "line_items": [{"description": "Analytics Platform",
                            "quantity": 100, "unit_price": 95000, "total": 9500000}],
            "payment_terms": {"net_days": 30},
            "seat_count": 100,
            "subscription_tier": "enterprise",
        }
        assert validate_deal_type_terms("saas_renewal", terms) == []

    def test_missing_seat_count_returns_error(self):
        terms = {"total_value": 100, "currency": "USD", "line_items": []}
        errors = validate_deal_type_terms("saas_renewal", terms)
        assert any("seat_count" in e for e in errors)

    def test_zero_seat_count_returns_error(self):
        terms = {"total_value": 100, "currency": "USD",
                 "line_items": [], "seat_count": 0}
        errors = validate_deal_type_terms("saas_renewal", terms)
        assert len(errors) > 0

    def test_negative_seat_count_returns_error(self):
        terms = {"total_value": 100, "currency": "USD",
                 "line_items": [], "seat_count": -1}
        errors = validate_deal_type_terms("saas_renewal", terms)
        assert len(errors) > 0

    def test_string_seat_count_returns_error(self):
        terms = {"total_value": 100, "currency": "USD",
                 "line_items": [], "seat_count": "hundred"}
        errors = validate_deal_type_terms("saas_renewal", terms)
        assert len(errors) > 0

    def test_bool_seat_count_rejected(self):
        terms = {"total_value": 100, "currency": "USD",
                 "line_items": [], "seat_count": True}
        errors = validate_deal_type_terms("saas_renewal", terms)
        assert len(errors) > 0

    def test_optional_fields_do_not_cause_errors(self):
        terms = {
            "total_value": 100, "currency": "USD", "line_items": [],
            "seat_count": 50,
            "subscription_tier": "professional",
            "support_tier": "premium",
            "uptime_sla_percent": 9999,
            "auto_renew_terms": {"enabled": True, "notice_days": 30},
        }
        assert validate_deal_type_terms("saas_renewal", terms) == []


class TestUnknownDealType:
    def test_unknown_deal_type_permissive(self):
        errors = validate_deal_type_terms("custom_deal_type_xyz", {"total_value": 100})
        assert errors == []

    def test_empty_terms_unknown_deal_type_permissive(self):
        assert validate_deal_type_terms("freight_rate", {}) == []
