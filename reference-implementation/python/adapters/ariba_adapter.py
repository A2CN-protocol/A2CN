"""
SAP Ariba -> A2CN translation layer.

Translates SAP Ariba Sourcing / Discovery RFx event payloads into A2CN
goods_procurement terms, and translates agreed A2CN terms into Ariba-shaped bid
or acknowledgement payloads.

SAP public documentation used for this adapter:
  Event Management API:
    GET /events
    GET /events/{eventId}/items
  Discovery RFx Publication TO External Marketplace API:
    GetNextRfxEvent -> GetRfxAttachment -> UpdateRfxEvent -> Acknowledge

No core protocol changes are required. This module keeps the platform mapping
offline-testable, while small auth helpers document the OAuth/API-key shape
needed when wiring it into a live SAP Ariba environment.
"""

from __future__ import annotations

import os
from typing import Any

import httpx


def _money_to_cents(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, dict):
        value = value.get("amount", 0)
    return int(float(value) * 100)


def _int_value(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    return int(float(value))


def _first(mapping: dict, *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return default


def _items_from_payload(payload: dict) -> list[dict]:
    items = (
        payload.get("items")
        or payload.get("lineItems")
        or payload.get("line_items")
        or payload.get("lots")
        or []
    )
    if isinstance(items, dict):
        items = items.get("items") or items.get("lineItems") or items.get("results") or []
    return list(items)


def _normalize_item(item: dict, default_currency: str) -> dict:
    item_id = _first(
        item,
        "itemId",
        "item_id",
        "lineItemId",
        "internalId",
        "id",
        default="",
    )
    lot_id = _first(item, "lotId", "lot_id", "lot", "lotNumber", default="")
    quantity = _int_value(_first(item, "quantity", "qty", "amount", default=1), 1)
    unit_price_raw = _first(
        item,
        "unitPrice",
        "unit_price",
        "targetPrice",
        "target_price",
        "estimatedUnitPrice",
        "price",
        default=0,
    )
    unit_price_cents = _money_to_cents(unit_price_raw)
    total_raw = _first(item, "totalPrice", "total_price", "extendedPrice", default=None)
    total_cents = _money_to_cents(total_raw) if total_raw is not None else quantity * unit_price_cents
    line_item: dict = {
        "description": _first(item, "title", "description", "name", "itemName", default=""),
        "quantity": quantity,
        "unit_of_measure": _first(item, "unitOfMeasure", "unit_of_measure", "uom", default="EA"),
        "unit_price": unit_price_cents,
        "total": total_cents,
    }
    internal_ref = lot_id or item_id
    if internal_ref:
        line_item["internal_part_number"] = str(internal_ref)
    if item_id:
        line_item["ariba_item_id"] = str(item_id)
    if lot_id:
        line_item["ariba_lot_id"] = str(lot_id)
    if item.get("currency"):
        line_item["currency"] = item["currency"]
    else:
        line_item["currency"] = default_currency
    return line_item


class AribaEventParser:
    """
    Translates SAP Ariba sourcing/RFx events into A2CN session inputs.
    """

    @staticmethod
    def parse_sourcing_event(payload: dict) -> dict:
        """
        Parse an SAP Ariba event or Discovery RFx payload into a clean summary.

        The parser accepts tolerant aliases from Event Management responses
        (event id/header/items) and Discovery RFx publications (RFx id/lots).
        """
        event = payload.get("event") or payload.get("rfxEvent") or payload
        currency = _first(event, "currency", "currencyCode", default="USD")
        raw_items = _items_from_payload(event)
        line_items = [_normalize_item(item, currency) for item in raw_items]
        total_cents = sum(item["total"] for item in line_items)
        event_id = _first(
            event,
            "eventId",
            "event_id",
            "internalId",
            "rfxId",
            "id",
            default="",
        )

        return {
            "event_id": event_id,
            "external_rfx_id": _first(
                event,
                "externalSystemCorrelationId",
                "externalRfxId",
                "rfxReference",
                default="",
            ),
            "event_name": _first(event, "title", "name", "eventName", "rfxTitle", default=""),
            "buyer_org": _first(event, "buyerOrg", "buyerOrganization", "owner", default=""),
            "deadline": _first(event, "biddingEndDate", "deadline", "closeDate", default=None),
            "currency": currency,
            "line_items": line_items,
            "estimated_value": total_cents,
            "raw_payload": payload,
        }

    @staticmethod
    def sourcing_event_to_goods_procurement_terms(
        payload: dict,
        default_delivery_days: int = 14,
        default_net_days: int = 30,
    ) -> dict:
        """
        Translate an SAP Ariba sourcing/RFx event into A2CN goods_procurement terms.
        """
        event = payload.get("event") or payload.get("rfxEvent") or payload
        parsed = AribaEventParser.parse_sourcing_event(payload)
        delivery_days = _int_value(
            _first(event, "deliveryDays", "delivery_days", "leadTimeDays", default=default_delivery_days),
            default_delivery_days,
        )
        net_days = _int_value(
            _first(event, "paymentTermsNetDays", "netDays", "paymentTermDays", default=default_net_days),
            default_net_days,
        )
        return {
            "total_value": parsed["estimated_value"],
            "currency": parsed["currency"],
            "line_items": [
                {
                    key: value
                    for key, value in item.items()
                    if key not in {"currency", "ariba_item_id", "ariba_lot_id"}
                }
                for item in parsed["line_items"]
            ],
            "delivery_days": delivery_days,
            "payment_terms": {"net_days": net_days},
            "custom_terms": {
                "ariba": {
                    "event_id": parsed["event_id"],
                    "external_rfx_id": parsed["external_rfx_id"],
                    "source": _first(event, "source", default="sap_ariba"),
                }
            },
        }

    @staticmethod
    def sourcing_event_to_session_inputs(
        payload: dict,
        max_rounds: int = 5,
        default_delivery_days: int = 14,
    ) -> dict:
        """
        Return both A2CN session params and initial goods_procurement terms.
        """
        parsed = AribaEventParser.parse_sourcing_event(payload)
        terms = AribaEventParser.sourcing_event_to_goods_procurement_terms(
            payload,
            default_delivery_days=default_delivery_days,
        )
        return {
            "event_id": parsed["event_id"],
            "session_params": {
                "deal_type": "goods_procurement",
                "currency": parsed["currency"],
                "max_rounds": max_rounds,
                "session_timeout_seconds": 3600,
                "round_timeout_seconds": 900,
                "ariba_event_id": parsed["event_id"],
                "ariba_external_rfx_id": parsed["external_rfx_id"],
                "buyer_org": parsed["buyer_org"],
            },
            "initial_terms": terms,
            "raw_payload": payload,
        }


def a2cn_terms_to_ariba_bid(
    agreed_terms: dict,
    event_id: str,
    supplier_id: str | None = None,
    status: str = "submitted",
) -> dict:
    """
    Translate agreed A2CN goods_procurement terms into an Ariba bid payload.
    """
    response_items = []
    for item in agreed_terms.get("line_items", []):
        entry: dict = {
            "itemId": item.get("ariba_item_id", item.get("internal_part_number", "")),
            "lotId": item.get("ariba_lot_id", item.get("internal_part_number", "")),
            "description": item.get("description", ""),
            "quantity": item.get("quantity", 1),
            "unitOfMeasure": item.get("unit_of_measure", "EA"),
            "unitPrice": item.get("unit_price", 0) / 100.0,
            "totalPrice": item.get("total", 0) / 100.0,
            "currency": agreed_terms.get("currency", "USD"),
        }
        response_items.append({key: value for key, value in entry.items() if value != ""})

    net_days = agreed_terms.get("payment_terms", {}).get("net_days", 30)
    payload: dict = {
        "eventId": event_id,
        "status": status,
        "currency": agreed_terms.get("currency", "USD"),
        "totalAmount": agreed_terms.get("total_value", 0) / 100.0,
        "items": response_items,
        "deliveryDays": agreed_terms.get("delivery_days", 14),
        "paymentTerms": f"Net {net_days}",
    }
    if supplier_id is not None:
        payload["supplierId"] = supplier_id
    return payload


def ariba_acknowledgement_payload(
    event_id: str,
    external_reference: str,
    status: str = "ACKNOWLEDGED",
    message: str = "Accepted for A2CN negotiation.",
) -> dict:
    """
    Build the Discovery RFx Publication TO External Marketplace Acknowledge shape.
    """
    return {
        "eventId": event_id,
        "externalReference": external_reference,
        "status": status,
        "message": message,
    }


def ariba_auth_headers(access_token: str, api_key: str | None = None) -> dict:
    """
    Build SAP Ariba Open API auth headers.
    """
    key = api_key or os.environ.get("ARIBA_API_KEY")
    if not key:
        raise ValueError("ARIBA_API_KEY environment variable is required.")
    return {
        "Authorization": f"Bearer {access_token}",
        "apiKey": key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def fetch_ariba_access_token(token_url: str | None = None) -> str:
    """
    Fetch an OAuth client-credentials token for SAP Ariba Open APIs.
    """
    client_id = os.environ.get("ARIBA_CLIENT_ID")
    client_secret = os.environ.get("ARIBA_CLIENT_SECRET")
    resolved_token_url = token_url or os.environ.get("ARIBA_TOKEN_URL")
    if not client_id or not client_secret or not resolved_token_url:
        raise ValueError(
            "ARIBA_CLIENT_ID, ARIBA_CLIENT_SECRET, and ARIBA_TOKEN_URL are required."
        )
    async with httpx.AsyncClient() as client:
        response = await client.post(
            resolved_token_url,
            data={"grant_type": "client_credentials"},
            auth=(client_id, client_secret),
        )
    response.raise_for_status()
    data = response.json()
    return data["access_token"]
