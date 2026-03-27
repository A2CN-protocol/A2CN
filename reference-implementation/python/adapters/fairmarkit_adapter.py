"""
Fairmarkit → A2CN translation layer.

Translates Fairmarkit webhook payloads and API responses into A2CN
message structures, and vice versa.

No I/O in this module — pure data translation, fully testable offline.

Fairmarkit API reference:
  Webhooks: developers.fairmarkit.com/docs/webhooks
  Responses: GET /self-service/api/v3/responses/request/{request_id}/
"""

from __future__ import annotations


class FairmakitEventParser:

    @staticmethod
    def parse_bid_created_webhook(payload: dict) -> dict:
        """
        Parse a Fairmarkit BID_CREATED webhook payload into an A2CN
        proposed_terms_summary for a SessionInvitation.

        Expected payload fields:
          request_id: str
          tenant_id: str
          status: str ("submitted")
          items: list of {description, quantity, uom, unit_price (optional)}
          deadline: str  # ISO 8601

        Returns dict suitable for SessionInvitation.proposed_terms_summary.
        """
        items = payload.get("items", [])
        description_parts = [item.get("description", "")[:50] for item in items[:3]]
        description = "; ".join(description_parts)
        if len(items) > 3:
            description += f" (+{len(items) - 3} more items)"

        estimated_value = 0
        for item in items:
            qty = float(item.get("quantity", 0))
            price = float(item.get("unit_price", 0))
            estimated_value += int(qty * price * 100)  # convert to cents

        return {
            "description": description,
            "estimated_value": estimated_value,
            "currency": "USD",
            "item_count": len(items),
            "deadline": payload.get("deadline", ""),
            "fairmarkit_request_id": payload.get("request_id", ""),
        }

    @staticmethod
    def bid_created_to_goods_procurement_terms(payload: dict) -> dict:
        """
        Parse a Fairmarkit BID_CREATED payload into A2CN goods_procurement
        terms suitable for a first-round offer.

        Maps Fairmarkit items to A2CN line_items.
        Fairmarkit UOM passes through directly to A2CN unit_of_measure.
        """
        items = payload.get("items", [])
        line_items = []
        total_cents = 0

        for item in items:
            qty = float(item.get("quantity", 1))
            unit_price_cents = int(float(item.get("unit_price", 0)) * 100)
            line_total = int(qty * unit_price_cents)
            total_cents += line_total

            line_item: dict = {
                "description": item.get("description", ""),
                "quantity": int(qty),
                "unit_price": unit_price_cents,
                "total": line_total,
                "unit_of_measure": item.get("uom", "EA"),
            }
            if item.get("mfg_part_number"):
                line_item["manufacturer_part_number"] = item["mfg_part_number"]
            if item.get("internal_part_number"):
                line_item["internal_part_number"] = item["internal_part_number"]
            line_items.append(line_item)

        return {
            "total_value": total_cents,
            "currency": "USD",
            "line_items": line_items,
            "delivery_days": 14,  # default; override with actual requirements
            "payment_terms": {"net_days": 30},
        }

    @staticmethod
    def terms_to_fairmarkit_response(
        agreed_terms: dict,
        session_id: str,
        request_id: str,
    ) -> dict:
        """
        Translate A2CN agreed_terms from a completed transaction record
        into a Fairmarkit response submission payload.

        Output can be submitted to:
        POST /self-service/api/v3/responses/request/{request_id}/

        Converts cents to dollars (Fairmarkit uses decimal prices).
        """
        line_items = agreed_terms.get("line_items", [])
        response_items = []

        for item in line_items:
            response_items.append({
                "description": item.get("description", ""),
                "quantity": item.get("quantity", 1),
                "unit_price": item.get("unit_price", 0) / 100.0,
                "total_price": item.get("total", 0) / 100.0,
                "uom": item.get("unit_of_measure", "EA"),
                "manufacturer_part_number": item.get("manufacturer_part_number", ""),
                "internal_part_number": item.get("internal_part_number", ""),
                "delivery_days": agreed_terms.get("delivery_days", 14),
            })

        net_days = agreed_terms.get("payment_terms", {}).get("net_days", 30)

        return {
            "request_id": request_id,
            "a2cn_session_id": session_id,
            "status": "submitted",
            "items": response_items,
            "total_price": agreed_terms.get("total_value", 0) / 100.0,
            "currency": agreed_terms.get("currency", "USD"),
            "payment_terms": f"Net {net_days}",
            "delivery_days": agreed_terms.get("delivery_days", 14),
            "notes": f"Negotiated via A2CN session {session_id}",
        }
