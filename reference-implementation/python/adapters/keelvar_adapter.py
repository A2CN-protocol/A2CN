"""
Keelvar → A2CN translation layer.

Translates Keelvar SOURCING_EVENTS_FEED_UPDATED webhook payloads and sourcing
event data into A2CN protocol messages, and vice versa.

No I/O in this module — pure data translation, fully testable offline.

Keelvar API reference:
  Docs:     https://docs.keelvar.app
  Webhooks: POST https://my.keelvar.app/api/webhooks
  Events:   GET  https://my.keelvar.app/api/sourcing-events
  Bids:     GET  https://my.keelvar.app/api/bids

Field mapping — Keelvar → A2CN goods_procurement:

  Keelvar field                        A2CN goods_procurement field
  ───────────────────────────────────────────────────────────────────────
  event.line_items[].description       line_items[].description
  event.line_items[].quantity          line_items[].quantity
  event.line_items[].unit_of_measure   line_items[].unit_of_measure
  event.line_items[].unit_price (USD)  line_items[].unit_price (cents)
  event.line_items[].lot_id            line_items[].internal_part_number
  event.currency                       currency
  Computed from line items             total_value (cents)
  default_delivery_days param          delivery_days
  Hardcoded default 30                 payment_terms.net_days
"""

from __future__ import annotations

import hashlib
import hmac


class KeelvarEventParser:
    """
    Translates between Keelvar sourcing event data and A2CN protocol messages.

    Integration pattern (Path B — supplier-side, zero Keelvar platform changes):

        Keelvar fires SOURCING_EVENTS_FEED_UPDATED webhook
            -> KeelvarEventParser.parse_sourcing_event_webhook(payload)
                -> Returns event summary with event_id, line items, deadline
            -> KeelvarEventParser.sourcing_event_to_goods_procurement_terms(payload)
                -> Returns A2CN goods_procurement terms dict
            -> A2CN Session Invitation accepted / SessionInit sent
            -> A2CN negotiation completes
            -> KeelvarEventParser.terms_to_keelvar_bid_response(agreed_terms, event_id)
                -> Returns Keelvar bid response payload
            -> POST bid response to Keelvar API

    Keelvar docs: https://docs.keelvar.app
    Keelvar webhook API: https://my.keelvar.app/api/webhooks
    """

    @staticmethod
    def parse_sourcing_event_webhook(payload: dict) -> dict:
        """
        Parse a Keelvar SOURCING_EVENTS_FEED_UPDATED webhook payload into a
        clean summary dict.

        Expected payload shape (from Keelvar sourcing events feed):
          event_id:    str
          event_name:  str
          buyer_org:   str
          deadline:    str | None   (ISO 8601)
          currency:    str          (ISO 4217, default 'USD')
          line_items:  list of {description, quantity, unit_of_measure,
                                unit_price (optional, USD), lot_id (optional)}

        Returns:
          event_id:     str
          event_name:   str
          buyer_org:    str
          deadline:     str | None
          currency:     str
          line_items:   list of parsed line item dicts
          raw_payload:  dict   (original payload, kept for audit)
        """
        line_items_raw = payload.get("line_items", [])
        line_items = []
        for item in line_items_raw:
            unit_price_raw = item.get("unit_price")
            unit_price_cents: int | None = (
                int(float(unit_price_raw) * 100)
                if unit_price_raw is not None
                else None
            )
            line_items.append({
                "description": item.get("description", ""),
                "quantity": int(float(item.get("quantity", 1))),
                "unit_of_measure": item.get("unit_of_measure", "EA"),
                "unit_price_cents": unit_price_cents,
                "lot_id": item.get("lot_id", ""),
            })

        return {
            "event_id": payload.get("event_id", ""),
            "event_name": payload.get("event_name", ""),
            "buyer_org": payload.get("buyer_org", ""),
            "deadline": payload.get("deadline") or None,
            "currency": payload.get("currency", "USD"),
            "line_items": line_items,
            "raw_payload": payload,
        }

    @staticmethod
    def sourcing_event_to_goods_procurement_terms(
        webhook_payload: dict,
        default_delivery_days: int = 14,
    ) -> dict:
        """
        Translate a Keelvar SOURCING_EVENTS_FEED_UPDATED webhook payload into
        A2CN goods_procurement terms suitable for a first-round offer or
        SessionInit.proposed_terms_summary.

        Args:
            webhook_payload:       Raw Keelvar webhook payload dict.
            default_delivery_days: Delivery days to use when Keelvar has not
                                   specified a delivery requirement (default 14).

        Returns:
            A2CN goods_procurement terms dict with total_value in cents.
            If no unit_price is present in the payload, total_value is 0 —
            the supplier will set their own opening price in the A2CN session.
        """
        line_items_raw = webhook_payload.get("line_items", [])
        line_items: list[dict] = []
        total_cents = 0

        for item in line_items_raw:
            qty = int(float(item.get("quantity", 1)))
            unit_price_raw = item.get("unit_price")
            unit_price_cents = (
                int(float(unit_price_raw) * 100) if unit_price_raw is not None else 0
            )
            line_total = qty * unit_price_cents
            total_cents += line_total

            line_item: dict = {
                "description": item.get("description", ""),
                "quantity": qty,
                "unit_of_measure": item.get("unit_of_measure", "EA"),
                "unit_price": unit_price_cents,
                "total": line_total,
            }
            if item.get("lot_id"):
                line_item["internal_part_number"] = item["lot_id"]
            line_items.append(line_item)

        return {
            "total_value": total_cents,
            "currency": webhook_payload.get("currency", "USD"),
            "line_items": line_items,
            "delivery_days": default_delivery_days,
            "payment_terms": {"net_days": 30},
        }

    @staticmethod
    def terms_to_keelvar_bid_response(
        agreed_terms: dict,
        event_id: str,
        supplier_id: str | None = None,
    ) -> dict:
        """
        Translate A2CN agreed_terms from a completed transaction record into a
        Keelvar bid response payload ready for submission to the Keelvar API.

        Args:
            agreed_terms: The terms dict from a completed A2CN transaction record.
            event_id:     The Keelvar sourcing event ID this response is for.
            supplier_id:  Optional Keelvar supplier ID (included if provided).

        Returns:
            Bid response dict with prices in dollars (not cents), suitable for
            submission to the Keelvar sourcing event bid API.
        """
        line_items_raw = agreed_terms.get("line_items", [])
        response_line_items = []

        for item in line_items_raw:
            entry: dict = {
                "description": item.get("description", ""),
                "quantity": item.get("quantity", 1),
                "unit_of_measure": item.get("unit_of_measure", "EA"),
                "unit_price": item.get("unit_price", 0) / 100.0,
                "total_price": item.get("total", 0) / 100.0,
            }
            if item.get("internal_part_number"):
                entry["lot_id"] = item["internal_part_number"]
            response_line_items.append(entry)

        net_days = agreed_terms.get("payment_terms", {}).get("net_days", 30)

        result: dict = {
            "event_id": event_id,
            "total_price": agreed_terms.get("total_value", 0) / 100.0,
            "currency": agreed_terms.get("currency", "USD"),
            "line_items": response_line_items,
            "delivery_days": agreed_terms.get("delivery_days", 14),
            "payment_terms": f"Net {net_days}",
            "status": "submitted",
        }
        if supplier_id is not None:
            result["supplier_id"] = supplier_id
        return result

    @staticmethod
    def verify_webhook_signature(
        payload_bytes: bytes,
        signature_header: str,
        signing_key: str,
    ) -> bool:
        """
        Verify the HMAC_SHA256 signature on a Keelvar webhook delivery.

        Keelvar signs the raw request body with the webhook signing key and
        sends the hex digest in the X-Signature header.

        Always call this before processing any webhook payload to prevent
        replay and forgery attacks.

        Args:
            payload_bytes:    Raw request body bytes.
            signature_header: Value of the X-Signature header from Keelvar.
            signing_key:      The webhook signing key configured in Keelvar.

        Returns:
            True if the signature is valid, False otherwise.
        """
        expected = hmac.new(
            signing_key.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature_header)
