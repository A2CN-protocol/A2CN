"""
JAGGAER ASO -> A2CN translation layer.

Translates JAGGAER Advanced Sourcing Optimizer (ASO) customer-host / sourcing
event payloads into A2CN goods_procurement terms, and translates agreed A2CN
terms into JAGGAER-shaped bid response payloads.

Public documentation used for this adapter:
  ASO API documentation:
    Customer Host Entity Service - query ASO events for a customer host
    Event Entity Service - interact with a specific ASO event
    Async upload endpoints - entity imports for rate and bid
  Integration via JAGGAER Public APIs:
    REST/JSON integrations, request/response or event-driven push

No core protocol changes are required. This module keeps platform mapping
offline-testable, while small auth/request helpers document the OAuth/API-key
shape needed when wiring it into a live JAGGAER environment.
"""

from __future__ import annotations

import os
from typing import Any

import httpx


def _money_to_cents(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, dict):
        value = value.get("amount", value.get("value", 0))
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


def _event_from_payload(payload: dict) -> dict:
    return (
        payload.get("event")
        or payload.get("asoEvent")
        or payload.get("sourcingEvent")
        or payload.get("apiEvent")
        or payload.get("data")
        or payload
    )


def _items_from_payload(payload: dict) -> list[dict]:
    items = (
        payload.get("items")
        or payload.get("lineItems")
        or payload.get("line_items")
        or payload.get("eventItems")
        or payload.get("lots")
        or []
    )
    if isinstance(items, dict):
        items = (
            items.get("items")
            or items.get("lineItems")
            or items.get("eventItems")
            or items.get("results")
            or []
        )
    return list(items)


def _normalize_item(item: dict, default_currency: str) -> dict:
    item_id = _first(
        item,
        "itemId",
        "item_id",
        "lineItemId",
        "line_item_id",
        "bidItemId",
        "id",
        default="",
    )
    lot_id = _first(item, "lotId", "lot_id", "lotNumber", "lot", default="")
    quantity = _int_value(_first(item, "quantity", "qty", "amount", default=1), 1)
    unit_price_raw = _first(
        item,
        "unitPrice",
        "unit_price",
        "targetPrice",
        "target_price",
        "reservePrice",
        "price",
        default=0,
    )
    unit_price_cents = _money_to_cents(unit_price_raw)
    total_raw = _first(item, "totalPrice", "total_price", "extendedPrice", default=None)
    total_cents = (
        _money_to_cents(total_raw)
        if total_raw is not None
        else quantity * unit_price_cents
    )

    line_item: dict = {
        "description": _first(item, "description", "name", "title", "itemName", default=""),
        "quantity": quantity,
        "unit_of_measure": _first(item, "unitOfMeasure", "unit_of_measure", "uom", default="EA"),
        "unit_price": unit_price_cents,
        "total": total_cents,
    }
    internal_ref = lot_id or item_id
    if internal_ref:
        line_item["internal_part_number"] = str(internal_ref)
    if item_id:
        line_item["jaggaer_item_id"] = str(item_id)
    if lot_id:
        line_item["jaggaer_lot_id"] = str(lot_id)
    line_item["currency"] = item.get("currency") or item.get("currencyCode") or default_currency
    return line_item


class JaggaerEventParser:
    """
    Translates JAGGAER ASO sourcing events into A2CN session inputs.
    """

    @staticmethod
    def parse_sourcing_event(payload: dict, mode: str = "push") -> dict:
        """
        Parse a JAGGAER push event or polled ASO event into a clean summary.

        The parser accepts tolerant aliases from push-webhook payloads and ASO
        CHES/EES event responses. Tenant-specific integrations should normalize
        their exact JAGGAER schema before calling this helper.
        """
        event = _event_from_payload(payload)
        currency = _first(event, "currency", "currencyCode", default="USD")
        line_items = [_normalize_item(item, currency) for item in _items_from_payload(event)]
        total_cents = sum(item["total"] for item in line_items)
        event_id = _first(
            event,
            "eventId",
            "event_id",
            "apiEventId",
            "sourcingEventId",
            "rfqId",
            "id",
            default="",
        )

        return {
            "event_id": str(event_id) if event_id != "" else "",
            "customer_host_id": _first(
                event,
                "customerHostId",
                "customer_host_id",
                "chostId",
                default="",
            ),
            "event_name": _first(event, "name", "eventName", "title", "rfxTitle", default=""),
            "buyer_org": _first(event, "buyerOrg", "buyerOrganization", "owner", "eventOwner", default=""),
            "deadline": _first(event, "biddingClose", "deadline", "closeDate", "dueDate", default=None),
            "currency": currency,
            "line_items": line_items,
            "estimated_value": total_cents,
            "mode": mode,
            "raw_payload": payload,
        }

    @staticmethod
    def sourcing_event_to_goods_procurement_terms(
        payload: dict,
        default_delivery_days: int = 14,
        default_net_days: int = 30,
        mode: str = "push",
    ) -> dict:
        """
        Translate a JAGGAER ASO event into A2CN goods_procurement terms.
        """
        event = _event_from_payload(payload)
        parsed = JaggaerEventParser.parse_sourcing_event(payload, mode=mode)
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
                    if key != "currency"
                }
                for item in parsed["line_items"]
            ],
            "delivery_days": delivery_days,
            "payment_terms": {"net_days": net_days},
            "custom_terms": {
                "jaggaer": {
                    "event_id": parsed["event_id"],
                    "customer_host_id": parsed["customer_host_id"],
                    "source": _first(event, "source", default="jaggaer_aso"),
                    "mode": mode,
                }
            },
        }

    @staticmethod
    def sourcing_event_to_session_inputs(
        payload: dict,
        max_rounds: int = 5,
        default_delivery_days: int = 14,
        mode: str = "push",
    ) -> dict:
        """
        Return both A2CN session params and initial goods_procurement terms.
        """
        parsed = JaggaerEventParser.parse_sourcing_event(payload, mode=mode)
        terms = JaggaerEventParser.sourcing_event_to_goods_procurement_terms(
            payload,
            default_delivery_days=default_delivery_days,
            mode=mode,
        )
        return {
            "event_id": parsed["event_id"],
            "session_params": {
                "deal_type": "goods_procurement",
                "currency": parsed["currency"],
                "max_rounds": max_rounds,
                "session_timeout_seconds": 3600,
                "round_timeout_seconds": 900,
                "jaggaer_event_id": parsed["event_id"],
                "jaggaer_customer_host_id": parsed["customer_host_id"],
                "buyer_org": parsed["buyer_org"],
            },
            "initial_terms": terms,
            "raw_payload": payload,
        }


def a2cn_terms_to_jaggaer_response(
    agreed_terms: dict,
    event_id: str,
    supplier_id: str | None = None,
    status: str = "submitted",
) -> dict:
    """
    Translate agreed A2CN goods_procurement terms into a JAGGAER bid response.
    """
    response_items = []
    for item in agreed_terms.get("line_items", []):
        entry: dict = {
            "itemId": item.get("jaggaer_item_id", item.get("internal_part_number", "")),
            "lotId": item.get("jaggaer_lot_id", item.get("internal_part_number", "")),
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


def jaggaer_poll_request(
    customer_host_id: str,
    user_id: str,
    base_url: str | None = None,
) -> dict:
    """
    Build the documented ASO CHES request shape for polling customer-host events.
    """
    resolved_base_url = (base_url or os.environ.get("JAGGAER_CHES_BASE_URL") or "").rstrip("/")
    if not resolved_base_url:
        raise ValueError("JAGGAER_CHES_BASE_URL or base_url is required.")
    return {
        "method": "GET",
        "url": f"{resolved_base_url}/chost/{customer_host_id}/user/{user_id}/apiEvents",
        "headers": {
            "Accept": "application/vnd.sciquest.com.ches+json",
        },
    }


def jaggaer_auth_headers(access_token: str, api_key: str | None = None) -> dict:
    """
    Build JAGGAER ASO API auth headers.
    """
    key = api_key or os.environ.get("JAGGAER_API_KEY")
    if not key:
        raise ValueError("JAGGAER_API_KEY environment variable is required.")
    return {
        "Authorization": f"Bearer {access_token}",
        "X-API-Key": key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def fetch_jaggaer_access_token(token_url: str | None = None) -> str:
    """
    Fetch an OAuth client-credentials bearer access token for JAGGAER ASO APIs.
    """
    client_id = os.environ.get("JAGGAER_CLIENT_ID")
    client_secret = os.environ.get("JAGGAER_CLIENT_SECRET")
    api_key = os.environ.get("JAGGAER_API_KEY")
    resolved_token_url = token_url or os.environ.get("JAGGAER_TOKEN_URL")
    scope = os.environ.get("JAGGAER_SCOPE")
    if not client_id or not client_secret or not api_key or not resolved_token_url:
        raise ValueError(
            "JAGGAER_CLIENT_ID, JAGGAER_CLIENT_SECRET, JAGGAER_API_KEY, "
            "and JAGGAER_TOKEN_URL are required."
        )

    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope
    async with httpx.AsyncClient() as client:
        response = await client.post(
            resolved_token_url,
            data=data,
            auth=(client_id, client_secret),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-API-Key": api_key,
            },
        )
    response.raise_for_status()
    return response.json()["access_token"]
