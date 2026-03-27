"""
Salesforce Revenue Cloud → A2CN translation layer.

Translates Revenue Cloud Pricing API responses into A2CN terms,
and translates A2CN agreed terms back into Revenue Cloud order payloads.

No I/O in this module — pure data translation, fully testable offline.

Revenue Cloud API reference (v65.0+):
  Pricing: POST /services/data/v65.0/connect/pricing/...
  Quote/Order: POST /services/data/v65.0/connect/qoc/sales-transactions
"""

from __future__ import annotations


class RevenueCloudAdapter:

    @staticmethod
    def pricing_response_to_a2cn_terms(
        pricing_response: dict,
        deal_type: str = "saas_renewal",
        currency: str = "USD",
    ) -> dict:
        """
        Translate a Salesforce Revenue Cloud Pricing API response into
        A2CN terms suitable for an offer message.

        Revenue Cloud Pricing API response fields:
          lineItems: list of {productId, productName, quantity, unitPrice,
                               totalPrice, discountPercent, startDate, endDate}
          totalAmount (decimal dollars)
          currency

        For saas_renewal, extracts seat_count from quantity of first line item.
        All prices converted from dollars to cents (A2CN integer format).
        """
        line_items_raw = pricing_response.get("lineItems", [])
        line_items = []
        total_cents = 0

        for item in line_items_raw:
            unit_price_cents = int(float(item.get("unitPrice", 0)) * 100)
            total_price_cents = int(float(item.get("totalPrice", 0)) * 100)
            total_cents += total_price_cents

            line_items.append({
                "description": item.get("productName", ""),
                "quantity": int(item.get("quantity", 1)),
                "unit_price": unit_price_cents,
                "total": total_price_cents,
            })

        terms: dict = {
            "total_value": total_cents or int(
                float(pricing_response.get("totalAmount", 0)) * 100
            ),
            "currency": pricing_response.get("currency", currency),
            "line_items": line_items,
            "payment_terms": {"net_days": 30},
        }

        # Contract duration from first line item dates
        if line_items_raw:
            first = line_items_raw[0]
            if first.get("startDate") and first.get("endDate"):
                terms["contract_duration"] = {
                    "start_date": first["startDate"],
                    "end_date": first["endDate"],
                }

        # saas_renewal extensions
        if deal_type == "saas_renewal" and line_items_raw:
            terms["seat_count"] = int(line_items_raw[0].get("quantity", 1))

        return terms

    @staticmethod
    def a2cn_terms_to_quote_payload(
        terms: dict,
        account_id: str,
        pricebook_id: str,
        transaction_type: str = "Quote",
    ) -> dict:
        """
        Translate A2CN terms into a Salesforce Revenue Cloud sales transaction
        payload for quote or order creation.

        POST /services/data/v65.0/connect/qoc/sales-transactions
        {transactionType, accountId, pricebookId, lineItems}

        Use transaction_type="Order" when converting an agreed A2CN transaction
        record into a Revenue Cloud order.
        """
        line_items_raw = terms.get("line_items", [])
        rc_line_items = []

        for item in line_items_raw:
            rc_line_items.append({
                "quantity": item.get("quantity", 1),
                "unitPrice": item.get("unit_price", 0) / 100.0,
                # productId would need to be resolved from description
                # in a real integration — omitting here for prototype
            })

        payload: dict = {
            "transactionType": transaction_type,
            "accountId": account_id,
            "pricebookId": pricebook_id,
            "lineItems": rc_line_items,
            "currencyIsoCode": terms.get("currency", "USD"),
        }

        duration = terms.get("contract_duration", {})
        if duration.get("start_date"):
            payload["startDate"] = duration["start_date"]
        if duration.get("end_date"):
            payload["endDate"] = duration["end_date"]

        return payload

    @staticmethod
    def a2cn_terms_to_order_payload(
        agreed_terms: dict,
        account_id: str,
        pricebook_id: str,
    ) -> dict:
        """
        Convenience wrapper: translate A2CN agreed_terms from a completed
        transaction record into a Revenue Cloud order payload.

          transaction_record.agreed_terms → Revenue Cloud Order
        """
        return RevenueCloudAdapter.a2cn_terms_to_quote_payload(
            agreed_terms, account_id, pricebook_id, transaction_type="Order"
        )
