"""
Vendr -> A2CN translation layer.

Translates Vendr renewal/workflow webhook payloads and pricing benchmark data
into A2CN SaaS renewal terms. The primary integration pattern is MCP-to-MCP:
an agent calls Vendr's MCP server for pricing intelligence, then calls A2CN's
MCP tools to run the bilateral negotiation and produce the signed record.

No I/O in this module -- pure data translation, fully testable offline.

Vendr integration surfaces:
  MCP server: pricing and benchmark intelligence for agent use
  Webhooks:   one-way procurement/workflow notifications from Vendr

Field mapping -- Vendr pricing -> A2CN saas_renewal:

  Vendr field                         A2CN saas_renewal field
  ----------------------------------------------------------------------
  vendor                              custom_terms.vendr.vendor
  product                             subscription_tier / line description
  list_price                          line_items[].unit_price (cents)
  seat_count                          seat_count / line quantity
  term_months                         term_months
  currency                            currency
  observed_discount_band.midpoint     total_value discount basis
  benchmark_range                     custom_terms.vendr.benchmark_range
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def _money_to_cents(value: Any) -> int:
    """Convert a decimal money value into integer cents."""
    if value is None:
        return 0
    return int(float(value) * 100)


def _int_value(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    return int(float(value))


def _discount_to_fraction(value: Any) -> float | None:
    if value is None or value == "":
        return None
    discount = float(value)
    if discount > 1:
        discount = discount / 100.0
    return discount


def _discount_band_midpoint(discount_band: dict | None) -> float | None:
    if not isinstance(discount_band, dict):
        return None
    if "midpoint" in discount_band:
        return _discount_to_fraction(discount_band["midpoint"])
    minimum = _discount_to_fraction(discount_band.get("min"))
    maximum = _discount_to_fraction(discount_band.get("max"))
    if minimum is None and maximum is None:
        return None
    if minimum is None:
        return maximum
    if maximum is None:
        return minimum
    return (minimum + maximum) / 2.0


def vendr_pricing_to_a2cn_terms(
    pricing: dict,
    default_net_days: int = 30,
) -> dict:
    """
    Map Vendr benchmark/pricing data into A2CN saas_renewal terms.

    Expected pricing fields:
      vendor: str
      product: str
      list_price: number        # per-seat annual price in dollars
      seat_count: int
      currency: str             # ISO 4217, default USD
      term_months: int          # default 12
      observed_discount_band: {min, max} or {midpoint}
      benchmark_range: {low, median, high}  # optional, dollars

    The observed discount band midpoint is applied to list_price to create the
    proposed A2CN total_value. Values are stored in integer cents.
    """
    vendor = str(pricing.get("vendor", ""))
    product = str(pricing.get("product", ""))
    seat_count = max(_int_value(pricing.get("seat_count"), 1), 1)
    term_months = max(_int_value(pricing.get("term_months"), 12), 1)
    list_price_cents = _money_to_cents(
        pricing.get("list_price", pricing.get("annual_unit_price", 0))
    )

    discount = _discount_band_midpoint(pricing.get("observed_discount_band"))
    if discount is None:
        discount = _discount_to_fraction(pricing.get("observed_discount"))
    effective_unit_price_cents = list_price_cents
    if discount is not None:
        effective_unit_price_cents = int(list_price_cents * (1.0 - discount))

    total_cents = effective_unit_price_cents * seat_count
    benchmark_range = pricing.get("benchmark_range") or {}
    benchmark_range_cents = {
        key: _money_to_cents(value)
        for key, value in benchmark_range.items()
        if key in {"low", "median", "high"}
    }

    return {
        "deal_type": "saas_renewal",
        "total_value": total_cents,
        "currency": pricing.get("currency", "USD"),
        "line_items": [
            {
                "description": product or vendor or "Vendr benchmarked subscription",
                "quantity": seat_count,
                "unit_price": effective_unit_price_cents,
                "total": total_cents,
            }
        ],
        "payment_terms": {"net_days": default_net_days},
        "seat_count": seat_count,
        "subscription_tier": pricing.get("subscription_tier", product or "standard"),
        "term_months": term_months,
        "custom_terms": {
            "vendr": {
                "vendor": vendor,
                "product": product,
                "list_price": list_price_cents,
                "observed_discount": discount,
                "benchmark_range": benchmark_range_cents,
                "source": pricing.get("source", "vendr_mcp"),
            }
        },
    }


class VendrWebhookParser:
    """
    Translates Vendr workflow/renewal webhooks into A2CN session inputs.

    Vendr webhooks are one-way notifications, so this parser returns local
    session parameters and opening terms; it does not try to write back to Vendr.
    """

    @staticmethod
    def parse_renewal_webhook(
        payload: dict,
        max_rounds: int = 5,
    ) -> dict:
        """
        Parse a Vendr renewal/workflow event into A2CN session params and terms.

        Expected payload fields are intentionally tolerant because Vendr webhook
        payloads may vary by workflow:
          event_id, event_type, workflow_id, buyer_org, vendor, product,
          renewal_date, currency, seat_count, term_months, pricing

        Returns:
          Dict with session_params, initial_terms, event_id, workflow_id, and
          raw_payload for audit correlation.
        """
        pricing = dict(payload.get("pricing") or {})
        for key in (
            "vendor",
            "product",
            "list_price",
            "annual_unit_price",
            "seat_count",
            "currency",
            "term_months",
            "observed_discount",
            "observed_discount_band",
            "benchmark_range",
            "subscription_tier",
        ):
            if key not in pricing and key in payload:
                pricing[key] = payload[key]

        terms = vendr_pricing_to_a2cn_terms(pricing)
        event_id = payload.get("event_id", payload.get("id", ""))
        workflow_id = payload.get("workflow_id", payload.get("workflowId", ""))

        session_params = {
            "deal_type": "saas_renewal",
            "currency": terms.get("currency", "USD"),
            "max_rounds": max_rounds,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
            "vendr_event_id": event_id,
            "vendr_workflow_id": workflow_id,
            "buyer_org": payload.get("buyer_org", payload.get("buyerOrg", "")),
            "vendor": pricing.get("vendor", ""),
            "product": pricing.get("product", ""),
            "renewal_date": payload.get("renewal_date", payload.get("renewalDate", "")),
        }

        return {
            "event_id": event_id,
            "event_type": payload.get("event_type", payload.get("eventType", "")),
            "workflow_id": workflow_id,
            "session_params": session_params,
            "initial_terms": terms,
            "raw_payload": payload,
        }

    @staticmethod
    def verify_webhook_signature(
        payload_bytes: bytes,
        signature_header: str,
        webhook_secret: str,
    ) -> bool:
        """
        Verify an HMAC-SHA256 Vendr webhook signature when a secret is provided.

        Accepts either a bare hex digest or common prefixed forms such as
        ``sha256=<digest>`` and ``v1=<digest>``.
        """
        if not webhook_secret or not signature_header:
            return False
        expected = hmac.new(
            webhook_secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()
        received = signature_header.strip()
        for prefix in ("sha256=", "v1="):
            if received.startswith(prefix):
                received = received[len(prefix):]
                break
        return hmac.compare_digest(expected, received)


def a2cn_terms_to_vendr_summary(
    agreed_terms: dict,
    session_id: str,
    record_hash: str,
    workflow_id: str | None = None,
) -> dict:
    """
    Translate agreed A2CN terms into a Vendr-shaped summary for audit linkage.

    Vendr webhooks do not provide a write-back API, so this is a local summary
    that can be attached to downstream systems or used by an agent when calling
    non-webhook Vendr surfaces.
    """
    vendr_meta = agreed_terms.get("custom_terms", {}).get("vendr", {})
    total_value = agreed_terms.get("total_value", 0)
    seat_count = max(_int_value(agreed_terms.get("seat_count"), 1), 1)
    summary = {
        "source": "a2cn",
        "a2cn_session_id": session_id,
        "a2cn_record_hash": record_hash,
        "workflow_id": workflow_id,
        "vendor": vendr_meta.get("vendor", ""),
        "product": vendr_meta.get("product", agreed_terms.get("subscription_tier", "")),
        "status": "negotiated",
        "total_value": total_value / 100.0,
        "currency": agreed_terms.get("currency", "USD"),
        "seat_count": seat_count,
        "unit_price": total_value / seat_count / 100.0,
        "term_months": agreed_terms.get("term_months", 12),
        "payment_terms": f"Net {agreed_terms.get('payment_terms', {}).get('net_days', 30)}",
    }
    return {k: v for k, v in summary.items() if v is not None}


def webhook_body_for_signature(payload: dict) -> bytes:
    """
    Deterministically encode a sample payload for tests and webhook fixtures.

    Production servers should verify the exact raw request body bytes they
    received, not a re-serialized dict.
    """
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
