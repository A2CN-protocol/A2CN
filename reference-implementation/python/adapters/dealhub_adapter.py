"""
DealHub CPQ → A2CN translation layer.

Translates DealHub quoteReady webhook events and API responses into A2CN
session terms, and translates A2CN agreed terms back into DealHub Actions
API calls.

PATH A (primary):   DealHub fires quoteReady webhook
                        → DealHubEventParser.quote_ready_webhook_to_session_params(payload)
                        → DealHubEventParser.fetch_quote_details(quote_id)
                        → DealHubEventParser.quote_to_a2cn_offer_terms(quote_response)
                        → A2CN negotiation session
                        → DealHubEventParser.agreed_terms_to_dealhub_action(...)

PATH B (secondary): DealHubEventParser.simulate_quote_for_mandate_bounds(playbook_id, answers)
                        → use ceiling / floor to configure agent mandate
                        → A2CN negotiation session

DealHub API reference:
  Quote API:    {DEALHUB_BASE_URL}/api/v1/quotes/{quote_id}
  Actions API:  {DEALHUB_BASE_URL}/api/v1/quotes/{quote_id}/actions
  Simulate API: {DEALHUB_BASE_URL}/api/v1/headless/simulate

Environment variables required:
  DEALHUB_AUTH_TOKEN:  Bearer token from DealHub Control Panel → API Settings
  DEALHUB_BASE_URL:    Your DealHub instance base URL
  DEALHUB_PLAYBOOK_ID: API Playbook ID for headless quote simulation
"""

from __future__ import annotations

import os

import httpx


_SUBSCRIPTION_KEYWORDS = frozenset({"license", "subscription", "seat"})


class DealHubEventParser:
    """
    Translates DealHub CPQ webhook events and API responses into A2CN session
    terms, and translates A2CN agreed terms back into DealHub Actions API calls.

    Integration pattern: PATH A (webhook-driven) is primary for live seller-side
    negotiation. PATH B (headless simulate) is used to set mandate bounds before
    session initiation.

    Environment variables required:
        DEALHUB_AUTH_TOKEN: Bearer token from DealHub API Settings
        DEALHUB_BASE_URL:   Your DealHub instance URL (e.g. https://yourdomain.dealhub.io)
        DEALHUB_PLAYBOOK_ID: API Playbook ID for headless quotes
    """

    # Default field map for translating DealHub quote responses to A2CN terms.
    # Override via the field_map parameter on quote_to_a2cn_offer_terms() if
    # your DealHub instance uses different field names.
    # FIELD NOTE: All field names should be verified against a live DealHub
    # instance. Contact DealHub support or inspect sandbox responses for exact names.
    DEFAULT_FIELD_MAP: dict[str, str] = {
        "total_value_field":    "total_price",    # FIELD NOTE: Verify against live DealHub instance.
        "currency_field":       "currency",        # FIELD NOTE: Verify against live DealHub instance.
        "line_items_field":     "line_items",      # FIELD NOTE: Verify against live DealHub instance.
        "product_name_field":   "product_name",    # FIELD NOTE: Verify against live DealHub instance.
        "quantity_field":       "quantity",        # FIELD NOTE: Verify against live DealHub instance.
        "unit_price_field":     "unit_price",      # FIELD NOTE: Verify against live DealHub instance.
        "unit_of_measure_field": "unit_of_measure", # FIELD NOTE: Verify against live DealHub instance.
    }

    @staticmethod
    def quote_ready_webhook_to_session_params(
        payload: dict,
        max_rounds: int = 5,
    ) -> dict:
        """
        Translates a quoteReady webhook payload into A2CN session parameters.

        Detects deal_type from product names in the optional ``items`` list:
        if any product name contains 'license', 'subscription', or 'seat'
        (case-insensitive) the deal is classified as 'saas_renewal', otherwise
        'goods_procurement'.  In PATH A the caller typically enriches the payload
        with line items returned by fetch_quote_details() before calling this
        method.

        Expected webhook payload fields:
          event_info:              dict  (webhook_id, event_id, api_version)
          dealhub_quote_id:        str
          dealhub_opportunity_id:  str
          execution_date:          str   (ISO 8601)
          executed_by:             str
          currency:                str   (ISO 4217, default "USD")
          items:                   list  (optional — enriched from quote API)

        Args:
            payload:    DealHub quoteReady webhook payload dict.
            max_rounds: Maximum negotiation rounds to propose (default 5).

        Returns:
            A2CN session_params dict suitable for SessionInit.
        """
        items = payload.get("items", [])
        deal_type = "goods_procurement"
        for item in items:
            product_name = str(item.get("product_name", "")).lower()
            if any(kw in product_name for kw in _SUBSCRIPTION_KEYWORDS):
                deal_type = "saas_renewal"
                break

        return {
            "deal_type": deal_type,
            "currency": payload.get("currency", "USD"),
            "max_rounds": max_rounds,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
            "dealhub_quote_id": payload.get("dealhub_quote_id", ""),
            "dealhub_opportunity_id": payload.get("dealhub_opportunity_id", ""),
        }

    @staticmethod
    async def fetch_quote_details(quote_id: str) -> dict:
        """
        Calls the DealHub Get Quote API and returns the full quote response.

        GET {DEALHUB_BASE_URL}/api/v1/quotes/{quote_id}
        Authorization: Bearer {DEALHUB_AUTH_TOKEN}

        Args:
            quote_id: DealHub quote ID (dealhub_quote_id from the webhook payload).

        Returns:
            Full quote response dict from DealHub.

        Raises:
            ValueError: If DEALHUB_AUTH_TOKEN or DEALHUB_BASE_URL is not set,
                        or if the API returns 403 / 404.
        """
        auth_token = os.environ.get("DEALHUB_AUTH_TOKEN")
        base_url = os.environ.get("DEALHUB_BASE_URL")
        if not auth_token or not base_url:
            raise ValueError(
                "DEALHUB_AUTH_TOKEN and DEALHUB_BASE_URL environment variables are required."
            )
        url = f"{base_url.rstrip('/')}/api/v1/quotes/{quote_id}"
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers={"Authorization": f"Bearer {auth_token}"})
        if response.status_code == 403:
            raise ValueError(
                "DealHub API returned 403 Forbidden — check DEALHUB_AUTH_TOKEN."
            )
        if response.status_code == 404:
            raise ValueError(f"DealHub quote {quote_id!r} not found (404).")
        response.raise_for_status()
        return response.json()

    @staticmethod
    def quote_to_a2cn_offer_terms(
        quote_response: dict,
        field_map: dict | None = None,
        delivery_days: int = 14,
    ) -> dict:
        """
        Translates a DealHub quote response into A2CN offer terms.

        Field names are resolved via field_map (or DEFAULT_FIELD_MAP if omitted).
        Pass a custom field_map dict to override individual keys without replacing
        the entire mapping.

        Deal type is inferred from product names: any product name containing
        'license', 'subscription', or 'seat' (case-insensitive) classifies the
        quote as 'saas_renewal'; otherwise 'goods_procurement'.

        Prices are converted from dollars to cents (A2CN integer format).

        Args:
            quote_response: Full DealHub quote response dict (from fetch_quote_details).
            field_map:      Optional field name overrides merged with DEFAULT_FIELD_MAP.
            delivery_days:  Delivery days for goods_procurement terms (default 14).

        Returns:
            A2CN offer terms dict with total_value in cents.
        """
        fm = {**DealHubEventParser.DEFAULT_FIELD_MAP, **(field_map or {})}

        items_raw = quote_response.get(fm["line_items_field"], [])
        line_items: list[dict] = []
        total_cents = 0

        for item in items_raw:
            product_name = str(item.get(fm["product_name_field"], ""))
            qty = int(float(item.get(fm["quantity_field"], 1)))
            unit_price_cents = int(float(item.get(fm["unit_price_field"], 0)) * 100)
            line_total = qty * unit_price_cents
            total_cents += line_total

            entry: dict = {
                "description": product_name,
                "quantity": qty,
                "unit_price": unit_price_cents,
                "total": line_total,
            }
            uom = item.get(fm["unit_of_measure_field"])
            if uom:
                entry["unit_of_measure"] = str(uom)
            line_items.append(entry)

        # Fall back to top-level total_price when line items carry no prices
        total_from_header = int(float(quote_response.get(fm["total_value_field"], 0)) * 100)
        total_cents = total_cents or total_from_header

        currency = str(quote_response.get(fm["currency_field"], "USD"))

        # Detect deal type from product names
        deal_type = "goods_procurement"
        for item in items_raw:
            name = str(item.get(fm["product_name_field"], "")).lower()
            if any(kw in name for kw in _SUBSCRIPTION_KEYWORDS):
                deal_type = "saas_renewal"
                break

        terms: dict = {
            "total_value": total_cents,
            "currency": currency,
            "line_items": line_items,
            "payment_terms": {"net_days": 30},
        }

        if deal_type == "saas_renewal" and items_raw:
            first = items_raw[0]
            terms["seat_count"] = int(float(first.get(fm["quantity_field"], 1)))
            terms["subscription_tier"] = str(first.get(fm["product_name_field"], ""))
        else:
            terms["delivery_days"] = delivery_days

        return terms

    @staticmethod
    async def simulate_quote_for_mandate_bounds(
        playbook_id: str,
        answers: dict,
        floor_discount_pct: float = 0.15,
    ) -> dict:
        """
        Calls the DealHub Headless Simulate Quote API to derive mandate bounds.

        POST {DEALHUB_BASE_URL}/api/v1/headless/simulate
        Authorization: Bearer {DEALHUB_AUTH_TOKEN}

        The ceiling is the full list price returned by the simulation.
        The floor is ceiling * (1 - floor_discount_pct).

        # floor_discount_pct should be configured per product category based on
        # actual sales policy — the 15% default is illustrative only.

        Args:
            playbook_id:       DealHub API Playbook ID (DEALHUB_PLAYBOOK_ID env var).
            answers:           Playbook answers dict (product_id, quantity,
                               customer_segment, etc.).
            floor_discount_pct: Maximum discount authorised without human approval
                               (default 0.15 = 15%).

        Returns:
            Dict with ceiling_value_cents, floor_value_cents, currency,
            and simulated_line_items.

        Raises:
            ValueError: If playbook_id is empty, or if required env vars are missing.
        """
        if not playbook_id:
            raise ValueError(
                "playbook_id is required for DealHub headless simulation."
            )
        auth_token = os.environ.get("DEALHUB_AUTH_TOKEN")
        base_url = os.environ.get("DEALHUB_BASE_URL")
        if not auth_token or not base_url:
            raise ValueError(
                "DEALHUB_AUTH_TOKEN and DEALHUB_BASE_URL environment variables are required."
            )
        url = f"{base_url.rstrip('/')}/api/v1/headless/simulate"
        payload = {"playbook_id": playbook_id, "answers": answers}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {auth_token}",
                    "Content-Type": "application/json",
                },
            )
        response.raise_for_status()
        data = response.json()

        # FIELD NOTE: total_price field name should be verified against a live
        # DealHub sandbox. Contact DealHub support for exact simulate response schema.
        ceiling_cents = int(float(data.get("total_price", 0)) * 100)
        floor_cents = int(ceiling_cents * (1.0 - floor_discount_pct))

        return {
            "ceiling_value_cents": ceiling_cents,
            "floor_value_cents": floor_cents,
            "currency": data.get("currency", "USD"),
            "simulated_line_items": data.get("line_items", []),
        }

    @staticmethod
    async def agreed_terms_to_dealhub_action(
        quote_id: str,
        a2cn_session_id: str,
        record_hash: str,
    ) -> dict:
        """
        Calls the DealHub Actions API to mark the quote as signed externally.

        POST {DEALHUB_BASE_URL}/api/v1/quotes/{quote_id}/actions
        Authorization: Bearer {DEALHUB_AUTH_TOKEN}

        The note field includes both the A2CN session_id and record_hash so the
        DealHub record is traceable back to the A2CN transaction.

        Args:
            quote_id:          DealHub quote ID to update.
            a2cn_session_id:   A2CN session ID from the completed session.
            record_hash:       Record hash from the A2CN transaction record.

        Returns:
            Dict containing:
              api_response:        Raw DealHub Actions API response.
              action_payload_sent: The payload submitted to the API (for audit log).

        Raises:
            ValueError: If DEALHUB_AUTH_TOKEN or DEALHUB_BASE_URL is not set.
        """
        auth_token = os.environ.get("DEALHUB_AUTH_TOKEN")
        base_url = os.environ.get("DEALHUB_BASE_URL")
        if not auth_token or not base_url:
            raise ValueError(
                "DEALHUB_AUTH_TOKEN and DEALHUB_BASE_URL environment variables are required."
            )
        action_payload = {
            "action": "signExternally",
            "note": (
                f"Agreed via A2CN session {a2cn_session_id}. "
                f"Record hash: {record_hash}"
            ),
        }
        url = f"{base_url.rstrip('/')}/api/v1/quotes/{quote_id}/actions"
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=action_payload,
                headers={
                    "Authorization": f"Bearer {auth_token}",
                    "Content-Type": "application/json",
                },
            )
        response.raise_for_status()
        return {
            "api_response": response.json(),
            "action_payload_sent": action_payload,
        }
