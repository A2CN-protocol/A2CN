"""
Nue.io Revenue Lifecycle → A2CN translation layer.

Translates Nue pricing and subscription data into A2CN session terms, and
translates A2CN agreed terms back into Nue order creation.

Primary flow:
  NueEventParser.fetch_pricing(price_book_id, product_id)
      → NueEventParser.pricing_to_mandate_bounds(pricing_response)
          → configure agent mandate bounds
      → A2CN negotiation session
      → NueEventParser.a2cn_terms_to_nue_order(agreed_terms, ...)

Renewal flow:
  NueEventParser.fetch_customer_subscriptions(customer_id)
      → NueEventParser.subscription_to_renewal_terms(subscription_response)
          → A2CN saas_renewal session
      → NueEventParser.a2cn_terms_to_nue_order(agreed_terms, ...)

Nue API reference (Revenue Lifecycle API):
  Pricing:       GET  {NUE_BASE_URL}/commerce/pricing
  Orders:        POST {NUE_BASE_URL}/orders
  Subscriptions: GET  {NUE_BASE_URL}/subscriptions

Environment variables required:
  NUE_API_KEY:  API key from Nue administrator
  NUE_BASE_URL: Base URL — production (https://api.nue.io) or
                sandbox (https://api.sandbox.nue.io)
"""

from __future__ import annotations

import os
from datetime import date

import httpx


class NueEventParser:
    """
    Translates Nue.io pricing and subscription data into A2CN session terms,
    and translates A2CN agreed terms back into Nue order creation.

    Nue is a seller-side CPQ and billing platform for SaaS companies.
    The primary A2CN use case is SaaS subscription negotiation — the seller's
    Nue instance provides pricing, the buyer's agent negotiates via A2CN, and
    agreed terms are written back as a Nue order.

    Environment variables required:
        NUE_API_KEY:  API key from Nue administrator
        NUE_BASE_URL: Base URL (production or sandbox)
    """

    @staticmethod
    def fetch_pricing(price_book_id: str, product_id: str) -> dict:
        """
        Calls the Nue Commerce API to get pricing for a specific product and
        price book.

        GET {NUE_BASE_URL}/commerce/pricing?priceBookId={id}&productId={id}
        Nue-Api-Key: {NUE_API_KEY}

        Args:
            price_book_id: Nue price book ID.
            product_id:    Nue product ID.

        Returns:
            Raw pricing response dict from Nue.

        Raises:
            ValueError: If NUE_API_KEY or NUE_BASE_URL is not set, or if the
                        API returns 401 / 404.
        """
        api_key = os.environ.get("NUE_API_KEY")
        base_url = os.environ.get("NUE_BASE_URL")
        if not api_key or not base_url:
            raise ValueError(
                "NUE_API_KEY and NUE_BASE_URL environment variables are required."
            )
        url = f"{base_url.rstrip('/')}/commerce/pricing"
        response = httpx.get(
            url,
            params={"priceBookId": price_book_id, "productId": product_id},
            headers={"Nue-Api-Key": api_key},
        )
        if response.status_code == 401:
            raise ValueError("Nue API returned 401 Unauthorized — check NUE_API_KEY.")
        if response.status_code == 404:
            raise ValueError(
                f"Nue pricing not found for priceBookId={price_book_id!r}, "
                f"productId={product_id!r}."
            )
        response.raise_for_status()
        return response.json()

    @staticmethod
    def pricing_to_mandate_bounds(
        pricing_response: dict,
        floor_discount_pct: float = 0.10,
        ceiling_markup_pct: float = 0.0,
    ) -> dict:
        """
        Translates a Nue pricing response into A2CN mandate bounds.

        The ceiling is the full list price (optionally marked up by
        ceiling_markup_pct). The floor is ceiling * (1 - floor_discount_pct).

        # floor_discount_pct represents the maximum discount the seller's agent
        # is authorized to offer without human approval. Configure per product
        # tier in production.

        FIELD NOTE: listPrice, quantity, and currency field names should be
        verified against a live Nue sandbox instance. Contact Nue support or
        check sandbox responses for exact pricing response field names.

        Args:
            pricing_response:   Raw pricing response from fetch_pricing().
            floor_discount_pct: Max authorised discount (default 0.10 = 10%).
            ceiling_markup_pct: Markup above list price for ceiling (default 0).

        Returns:
            Dict with ceiling_value_cents, floor_value_cents, and currency.
        """
        # FIELD NOTE: Verify listPrice field name against live Nue sandbox instance.
        # Contact Nue support or check sandbox response for exact name.
        list_price = float(
            pricing_response.get("listPrice",
                pricing_response.get("list_price",
                    pricing_response.get("unitPrice",
                        pricing_response.get("price", 0))))
        )
        # FIELD NOTE: Verify quantity field name against live Nue sandbox instance.
        quantity = int(pricing_response.get("quantity", 1))
        total_list_price = list_price * quantity

        ceiling_cents = int(total_list_price * 100 * (1.0 + ceiling_markup_pct))
        floor_cents = int(ceiling_cents * (1.0 - floor_discount_pct))
        currency = str(pricing_response.get("currency", "USD"))

        return {
            "ceiling_value_cents": ceiling_cents,
            "floor_value_cents": floor_cents,
            "currency": currency,
        }

    @staticmethod
    def subscription_to_renewal_terms(
        subscription_response: dict,
        renewal_markup_pct: float = 0.05,
    ) -> dict:
        """
        Translates an existing Nue subscription into A2CN saas_renewal offer
        terms for a renewal negotiation.

        The proposed renewal value is the current subscription total plus
        renewal_markup_pct (default 5%).

        FIELD NOTE: Field names (totalValue, productTier, autoRenew, termMonths,
        quantity) should be verified against a live Nue sandbox instance.
        Contact Nue support or check sandbox subscription responses.

        Args:
            subscription_response: Nue subscription dict (from fetch_customer_subscriptions).
            renewal_markup_pct:    Annual price increase to apply (default 0.05 = 5%).

        Returns:
            A2CN saas_renewal offer terms dict with total_value in cents.
        """
        # FIELD NOTE: Verify all field names below against live Nue sandbox instance.
        current_value = float(
            subscription_response.get("totalValue",
                subscription_response.get("total_value", 0))
        )
        renewal_value_cents = int(current_value * 100 * (1.0 + renewal_markup_pct))

        seat_count = int(
            subscription_response.get("quantity",
                subscription_response.get("seats", 1))
        )
        tier = str(
            subscription_response.get("productTier",
                subscription_response.get("product_tier", "standard"))
        )
        auto_renew = bool(
            subscription_response.get("autoRenew",
                subscription_response.get("auto_renew", False))
        )
        term_months = int(
            subscription_response.get("termMonths",
                subscription_response.get("term_months", 12))
        )
        currency = str(subscription_response.get("currency", "USD"))

        return {
            "deal_type": "saas_renewal",
            "total_value": renewal_value_cents,
            "currency": currency,
            "seat_count": seat_count,
            "subscription_tier": tier,
            "auto_renew_terms": {"auto_renew": auto_renew},
            "term_months": term_months,
        }

    @staticmethod
    def a2cn_terms_to_nue_order(
        agreed_terms: dict,
        customer_id: str,
        price_book_id: str,
        product_id: str,
        a2cn_session_id: str,
        record_hash: str,
        start_date: str | None = None,
    ) -> dict:
        """
        Translates A2CN agreed terms into a Nue order payload and calls the
        Nue Orders API.

        POST {NUE_BASE_URL}/orders
        Nue-Api-Key: {NUE_API_KEY}

        The externalReference field MUST include the A2CN session_id and the
        notes field MUST include the record_hash. These two fields create the
        audit link between the Nue order and the A2CN transaction record.

        Args:
            agreed_terms:      Terms dict from a completed A2CN transaction record.
            customer_id:       Nue customer ID.
            price_book_id:     Nue price book ID.
            product_id:        Nue product ID.
            a2cn_session_id:   A2CN session ID from the completed session.
            record_hash:       Record hash from the A2CN transaction record.
            start_date:        Order start date (YYYY-MM-DD). Defaults to today.

        Returns:
            Dict containing:
              api_response:       Raw Nue Orders API response.
              order_payload_sent: The payload submitted to the API (for audit log).

        Raises:
            ValueError: If NUE_API_KEY or NUE_BASE_URL is not set.
        """
        api_key = os.environ.get("NUE_API_KEY")
        base_url = os.environ.get("NUE_BASE_URL")
        if not api_key or not base_url:
            raise ValueError(
                "NUE_API_KEY and NUE_BASE_URL environment variables are required."
            )
        if start_date is None:
            start_date = date.today().strftime("%Y-%m-%d")

        line_items = agreed_terms.get("line_items", [])
        term_months = int(agreed_terms.get("term_months", 12))

        if line_items:
            lines = [
                {
                    "productId": product_id,
                    "quantity": item.get("quantity", 1),
                    "unitPrice": item.get("unit_price", 0) / 100.0,
                    "term": term_months,
                }
                for item in line_items
            ]
        else:
            # No line items — build a single line from the total
            lines = [
                {
                    "productId": product_id,
                    "quantity": agreed_terms.get("seat_count", 1),
                    "unitPrice": agreed_terms.get("total_value", 0) / 100.0,
                    "term": term_months,
                }
            ]

        order_payload = {
            "customerId": customer_id,
            "priceBookId": price_book_id,
            "startDate": start_date,
            "lines": lines,
            "externalReference": f"a2cn-session-{a2cn_session_id}",
            "notes": f"Agreed via A2CN. Record hash: {record_hash}",
        }

        url = f"{base_url.rstrip('/')}/orders"
        response = httpx.post(
            url,
            json=order_payload,
            headers={
                "Nue-Api-Key": api_key,
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        return {
            "api_response": response.json(),
            "order_payload_sent": order_payload,
        }

    @staticmethod
    def fetch_customer_subscriptions(customer_id: str) -> list[dict]:
        """
        Fetches all active subscriptions for a customer from Nue.

        GET {NUE_BASE_URL}/subscriptions?customerId={customer_id}
        Nue-Api-Key: {NUE_API_KEY}

        Used to establish renewal context before initiating an A2CN session.

        Args:
            customer_id: Nue customer ID.

        Returns:
            List of subscription dicts.

        Raises:
            ValueError: If NUE_API_KEY or NUE_BASE_URL is not set.
        """
        api_key = os.environ.get("NUE_API_KEY")
        base_url = os.environ.get("NUE_BASE_URL")
        if not api_key or not base_url:
            raise ValueError(
                "NUE_API_KEY and NUE_BASE_URL environment variables are required."
            )
        url = f"{base_url.rstrip('/')}/subscriptions"
        response = httpx.get(
            url,
            params={"customerId": customer_id},
            headers={"Nue-Api-Key": api_key},
        )
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            return data
        # FIELD NOTE: Verify top-level list key against live Nue sandbox instance.
        return data.get("subscriptions", data.get("items", []))
