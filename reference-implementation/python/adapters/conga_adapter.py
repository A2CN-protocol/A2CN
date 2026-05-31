"""
Conga CPQ/CLM -> A2CN translation layer.

Translates Conga CPQ quote / cart payloads into A2CN terms, and translates
agreed A2CN terms back into Conga quote update payloads.

Public documentation used for this adapter:
  Conga Documentation Portal:
    CPQ REST API Version 5 - Quote, Cart Items, Order, Assets
    CLM for REST API Developers - agreement records and lifecycle actions
  Conga Developer Portal:
    Advantage Platform REST APIs use predictable REST URLs and JSON payloads

No core protocol changes are required. This module keeps platform mapping
offline-testable, while auth helpers document the Salesforce/Advantage OAuth
shape used by live Conga integrations.
"""

from __future__ import annotations

import os
from typing import Any

import httpx


_SUBSCRIPTION_KEYWORDS = frozenset({
    "license",
    "subscription",
    "seat",
    "renewal",
    "term",
})


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


def _line_items_from_quote(quote: dict, field_map: dict) -> list[dict]:
    items = _first(
        quote,
        field_map["line_items_field"],
        "lineItems",
        "LineItems",
        "quoteLineItems",
        "cartItems",
        "items",
        "records",
        default=[],
    )
    if isinstance(items, dict):
        items = (
            items.get("lineItems")
            or items.get("quoteLineItems")
            or items.get("cartItems")
            or items.get("records")
            or items.get("items")
            or []
        )
    return list(items)


def _is_subscription_item(item: dict, field_map: dict) -> bool:
    product_name = str(_first(
        item,
        field_map["product_name_field"],
        "productName",
        "ProductName",
        "Name",
        "Description",
        "Apttus_Config2__Description__c",
        default="",
    )).lower()
    charge_type = str(_first(
        item,
        "chargeType",
        "ChargeType",
        "pricingType",
        "Apttus_Config2__ChargeType__c",
        default="",
    )).lower()
    return any(keyword in product_name or keyword in charge_type for keyword in _SUBSCRIPTION_KEYWORDS)


class CongaAdapter:
    """
    Translates Conga CPQ / CLM records into A2CN session terms and write-back
    payloads.
    """

    DEFAULT_FIELD_MAP: dict[str, str] = {
        "quote_id_field": "id",
        "agreement_id_field": "agreementId",
        "account_id_field": "accountId",
        "opportunity_id_field": "opportunityId",
        "total_value_field": "totalAmount",
        "currency_field": "currency",
        "line_items_field": "lineItems",
        "line_item_id_field": "id",
        "product_id_field": "productId",
        "product_name_field": "productName",
        "quantity_field": "quantity",
        "unit_price_field": "unitPrice",
        "total_price_field": "totalPrice",
        "unit_of_measure_field": "unitOfMeasure",
        "start_date_field": "startDate",
        "end_date_field": "endDate",
        "term_months_field": "termMonths",
    }

    @staticmethod
    def quote_to_session_inputs(
        quote: dict,
        max_rounds: int = 5,
        field_map: dict | None = None,
        default_delivery_days: int = 14,
    ) -> dict:
        """
        Return both A2CN session params and initial terms for a Conga quote.
        """
        fm = {**CongaAdapter.DEFAULT_FIELD_MAP, **(field_map or {})}
        terms = conga_quote_to_a2cn_terms(
            quote,
            field_map=fm,
            default_delivery_days=default_delivery_days,
        )
        quote_id = _first(
            quote,
            fm["quote_id_field"],
            "quoteId",
            "QuoteId",
            "Id",
            "Apttus_Proposal__Proposal__c",
            default="",
        )
        return {
            "quote_id": str(quote_id) if quote_id != "" else "",
            "session_params": {
                "deal_type": "saas_renewal" if "seat_count" in terms else "goods_procurement",
                "currency": terms.get("currency", "USD"),
                "max_rounds": max_rounds,
                "session_timeout_seconds": 3600,
                "round_timeout_seconds": 900,
                "conga_quote_id": str(quote_id) if quote_id != "" else "",
                "conga_account_id": _first(
                    quote,
                    fm["account_id_field"],
                    "account",
                    "AccountId",
                    "Apttus_Proposal__Account__c",
                    default="",
                ),
                "conga_opportunity_id": _first(
                    quote,
                    fm["opportunity_id_field"],
                    "opportunity",
                    "OpportunityId",
                    "Apttus_Proposal__Opportunity__c",
                    default="",
                ),
            },
            "initial_terms": terms,
            "raw_payload": quote,
        }


def conga_quote_to_a2cn_terms(
    quote: dict,
    field_map: dict | None = None,
    default_delivery_days: int = 14,
    default_net_days: int = 30,
) -> dict:
    """
    Translate a Conga CPQ quote/cart response into A2CN terms.

    The default field map accepts simple REST JSON names while the alias list
    covers common Conga/Salesforce-style names for quote and line-item records.
    """
    fm = {**CongaAdapter.DEFAULT_FIELD_MAP, **(field_map or {})}
    items_raw = _line_items_from_quote(quote, fm)
    line_items: list[dict] = []
    total_cents = 0

    for item in items_raw:
        quantity = _int_value(_first(
            item,
            fm["quantity_field"],
            "Quantity",
            "Apttus_Config2__Quantity__c",
            default=1,
        ), 1)
        unit_price_cents = _money_to_cents(_first(
            item,
            fm["unit_price_field"],
            "UnitPrice",
            "netUnitPrice",
            "NetUnitPrice",
            "ListPrice",
            "Apttus_Config2__NetUnitPrice__c",
            "Apttus_Config2__NetPrice__c",
            default=0,
        ))
        total_raw = _first(
            item,
            fm["total_price_field"],
            "netAmount",
            "NetAmount",
            "TotalPrice",
            "lineTotal",
            "Apttus_Config2__NetAmount__c",
            default=None,
        )
        line_total = _money_to_cents(total_raw) if total_raw is not None else quantity * unit_price_cents
        total_cents += line_total
        line_item: dict = {
            "description": _first(
                item,
                fm["product_name_field"],
                "ProductName",
                "Name",
                "Description",
                "Apttus_Config2__Description__c",
                default="",
            ),
            "quantity": quantity,
            "unit_price": unit_price_cents,
            "total": line_total,
        }
        uom = _first(item, fm["unit_of_measure_field"], "Uom", "uom", default=None)
        if uom:
            line_item["unit_of_measure"] = str(uom)
        line_id = _first(
            item,
            fm["line_item_id_field"],
            "lineItemId",
            "LineItemId",
            "Id",
            "Apttus_Config2__LineItemId__c",
            default="",
        )
        product_id = _first(
            item,
            fm["product_id_field"],
            "ProductId",
            "product",
            "Apttus_Config2__ProductId__c",
            default="",
        )
        if line_id:
            line_item["conga_line_item_id"] = str(line_id)
            line_item["internal_part_number"] = str(line_id)
        if product_id:
            line_item["conga_product_id"] = str(product_id)
        line_items.append(line_item)

    header_total_cents = _money_to_cents(_first(
        quote,
        fm["total_value_field"],
        "grandTotal",
        "netAmount",
        "totalPrice",
        "TotalPrice",
        "NetAmount",
        "GrandTotal",
        "Apttus_Proposal__Net_Amount__c",
        default=0,
    ))
    total_cents = total_cents or header_total_cents
    currency = str(_first(
        quote,
        fm["currency_field"],
        "currencyCode",
        "CurrencyCode",
        "currencyIsoCode",
        "CurrencyIsoCode",
        "Apttus_Proposal__CurrencyIsoCode__c",
        default="USD",
    ))

    deal_type = "saas_renewal" if any(_is_subscription_item(item, fm) for item in items_raw) else "goods_procurement"
    terms: dict = {
        "total_value": total_cents,
        "currency": currency,
        "line_items": line_items,
        "payment_terms": {"net_days": _int_value(_first(
            quote,
            "paymentTermsNetDays",
            "netDays",
            "paymentTermDays",
            default=default_net_days,
        ), default_net_days)},
        "custom_terms": {
            "conga": {
                "quote_id": str(_first(quote, fm["quote_id_field"], "quoteId", "Id", default="")),
                "agreement_id": str(_first(quote, fm["agreement_id_field"], "AgreementId", "contractId", default="")),
                "source": str(_first(quote, "source", default="conga_cpq")),
            }
        },
    }

    start_date = _first(quote, fm["start_date_field"], "StartDate", "effectiveDate", default=None)
    end_date = _first(quote, fm["end_date_field"], "EndDate", "expirationDate", default=None)
    if start_date and end_date:
        terms["contract_duration"] = {
            "start_date": start_date,
            "end_date": end_date,
        }

    if deal_type == "saas_renewal":
        terms["seat_count"] = _int_value(_first(
            items_raw[0] if items_raw else {},
            fm["quantity_field"],
            "Quantity",
            "Apttus_Config2__Quantity__c",
            default=1,
        ), 1)
        first_item = items_raw[0] if items_raw else {}
        terms["subscription_tier"] = str(_first(
            first_item,
            fm["product_name_field"],
            "ProductName",
            "Name",
            default="",
        ))
        term_months = _first(
            quote,
            fm["term_months_field"],
            "sellingTerm",
            "SellingTerm",
            "Apttus_QPConfig__ProposalTerm__c",
            default=None,
        )
        if term_months is not None:
            terms["contract_term_months"] = _int_value(term_months)
    else:
        terms["delivery_days"] = _int_value(_first(
            quote,
            "deliveryDays",
            "delivery_days",
            "leadTimeDays",
            default=default_delivery_days,
        ), default_delivery_days)

    return terms


def a2cn_terms_to_conga_quote(
    agreed_terms: dict,
    quote_id: str,
    agreement_id: str | None = None,
    status: str = "Accepted",
) -> dict:
    """
    Translate agreed A2CN terms into a Conga quote update payload.
    """
    line_items = []
    for item in agreed_terms.get("line_items", []):
        entry: dict = {
            "id": item.get("conga_line_item_id", item.get("internal_part_number", "")),
            "productId": item.get("conga_product_id", ""),
            "description": item.get("description", ""),
            "quantity": item.get("quantity", 1),
            "unitPrice": item.get("unit_price", 0) / 100.0,
            "totalPrice": item.get("total", 0) / 100.0,
        }
        if item.get("unit_of_measure"):
            entry["unitOfMeasure"] = item["unit_of_measure"]
        line_items.append({key: value for key, value in entry.items() if value != ""})

    payload: dict = {
        "quoteId": quote_id,
        "status": status,
        "currency": agreed_terms.get("currency", "USD"),
        "totalAmount": agreed_terms.get("total_value", 0) / 100.0,
        "lineItems": line_items,
        "paymentTerms": f"Net {agreed_terms.get('payment_terms', {}).get('net_days', 30)}",
    }
    if agreement_id is not None:
        payload["agreementId"] = agreement_id
    if "seat_count" in agreed_terms:
        payload["seatCount"] = agreed_terms["seat_count"]
    if "delivery_days" in agreed_terms:
        payload["deliveryDays"] = agreed_terms["delivery_days"]
    duration = agreed_terms.get("contract_duration", {})
    if duration.get("start_date"):
        payload["startDate"] = duration["start_date"]
    if duration.get("end_date"):
        payload["endDate"] = duration["end_date"]
    if agreed_terms.get("contract_term_months"):
        payload["termMonths"] = agreed_terms["contract_term_months"]
    return payload


def conga_agreement_update_payload(
    agreement_id: str,
    a2cn_session_id: str,
    record_hash: str,
    status: str = "Ready for Contracting",
) -> dict:
    """
    Build a CLM agreement metadata update payload linked to an A2CN record.
    """
    return {
        "agreementId": agreement_id,
        "status": status,
        "externalReferences": {
            "a2cn_session_id": a2cn_session_id,
            "a2cn_record_hash": record_hash,
        },
    }


def conga_auth_headers(access_token: str) -> dict:
    """
    Build Conga REST API auth headers for Salesforce or Advantage API calls.
    """
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def fetch_conga_access_token(token_url: str | None = None) -> str:
    """
    Fetch an OAuth client-credentials bearer token for Conga REST APIs.
    """
    client_id = os.environ.get("CONGA_CLIENT_ID")
    client_secret = os.environ.get("CONGA_CLIENT_SECRET")
    resolved_token_url = token_url or os.environ.get("CONGA_TOKEN_URL")
    scope = os.environ.get("CONGA_SCOPE")
    if not client_id or not client_secret or not resolved_token_url:
        raise ValueError(
            "CONGA_CLIENT_ID, CONGA_CLIENT_SECRET, and CONGA_TOKEN_URL are required."
        )

    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope
    async with httpx.AsyncClient() as client:
        response = await client.post(
            resolved_token_url,
            data=data,
            auth=(client_id, client_secret),
            headers={"Accept": "application/json"},
        )
    response.raise_for_status()
    return response.json()["access_token"]
