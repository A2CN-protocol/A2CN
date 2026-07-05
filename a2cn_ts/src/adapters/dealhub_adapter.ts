/**
 * DealHub CPQ → A2CN translation layer.
 *
 * Translates DealHub quoteReady webhook events and API responses into A2CN
 * session terms, and translates A2CN agreed terms back into DealHub Actions
 * API calls.
 *
 * PATH A (primary):   DealHub fires quoteReady webhook
 *                         → DealHubEventParser.quoteReadyWebhookToSessionParams(payload)
 *                         → DealHubEventParser.fetchQuoteDetails(quoteId)
 *                         → DealHubEventParser.quoteToA2cnOfferTerms(quoteResponse)
 *                         → A2CN negotiation session
 *                         → DealHubEventParser.agreedTermsToDealhubAction(...)
 *
 * PATH B (secondary): DealHubEventParser.simulateQuoteForMandateBounds(playbookId, answers)
 *                         → use ceiling / floor to configure agent mandate
 *                         → A2CN negotiation session
 *
 * DealHub API reference:
 *   Quote API:    {DEALHUB_BASE_URL}/api/v1/quotes/{quote_id}
 *   Actions API:  {DEALHUB_BASE_URL}/api/v1/quotes/{quote_id}/actions
 *   Simulate API: {DEALHUB_BASE_URL}/api/v1/headless/simulate
 *
 * Environment variables required:
 *   DEALHUB_AUTH_TOKEN:  Bearer token from DealHub Control Panel → API Settings
 *   DEALHUB_BASE_URL:    Your DealHub instance base URL
 *   DEALHUB_PLAYBOOK_ID: API Playbook ID for headless quote simulation
 */

import type { Dict } from "../a2cn/messages.js";

const SUBSCRIPTION_KEYWORDS = ["license", "subscription", "seat"];

/**
 * Translates DealHub CPQ webhook events and API responses into A2CN session
 * terms, and translates A2CN agreed terms back into DealHub Actions API calls.
 *
 * Integration pattern: PATH A (webhook-driven) is primary for live seller-side
 * negotiation. PATH B (headless simulate) is used to set mandate bounds before
 * session initiation.
 *
 * Environment variables required:
 *     DEALHUB_AUTH_TOKEN: Bearer token from DealHub API Settings
 *     DEALHUB_BASE_URL:   Your DealHub instance URL (e.g. https://yourdomain.dealhub.io)
 *     DEALHUB_PLAYBOOK_ID: API Playbook ID for headless quotes
 */
export class DealHubEventParser {
  // Default field map for translating DealHub quote responses to A2CN terms.
  // Override via the fieldMap parameter on quoteToA2cnOfferTerms() if
  // your DealHub instance uses different field names.
  // FIELD NOTE: All field names should be verified against a live DealHub
  // instance. Contact DealHub support or inspect sandbox responses for exact names.
  static DEFAULT_FIELD_MAP: Record<string, string> = {
    total_value_field: "total_price", // FIELD NOTE: Verify against live DealHub instance.
    currency_field: "currency", // FIELD NOTE: Verify against live DealHub instance.
    line_items_field: "line_items", // FIELD NOTE: Verify against live DealHub instance.
    product_name_field: "product_name", // FIELD NOTE: Verify against live DealHub instance.
    quantity_field: "quantity", // FIELD NOTE: Verify against live DealHub instance.
    unit_price_field: "unit_price", // FIELD NOTE: Verify against live DealHub instance.
    unit_of_measure_field: "unit_of_measure", // FIELD NOTE: Verify against live DealHub instance.
  };

  /**
   * Translates a quoteReady webhook payload into A2CN session parameters.
   *
   * Detects deal_type from product names in the optional `items` list:
   * if any product name contains 'license', 'subscription', or 'seat'
   * (case-insensitive) the deal is classified as 'saas_renewal', otherwise
   * 'goods_procurement'.  In PATH A the caller typically enriches the payload
   * with line items returned by fetchQuoteDetails() before calling this
   * method.
   */
  static quoteReadyWebhookToSessionParams(payload: Dict, maxRounds = 5): Dict {
    const items = (payload.items as Dict[]) ?? [];
    let dealType = "goods_procurement";
    for (const item of items) {
      const productName = String(item.product_name ?? "").toLowerCase();
      if (SUBSCRIPTION_KEYWORDS.some((kw) => productName.includes(kw))) {
        dealType = "saas_renewal";
        break;
      }
    }

    return {
      deal_type: dealType,
      currency: payload.currency ?? "USD",
      max_rounds: maxRounds,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
      dealhub_quote_id: payload.dealhub_quote_id ?? "",
      dealhub_opportunity_id: payload.dealhub_opportunity_id ?? "",
    };
  }

  /**
   * Calls the DealHub Get Quote API and returns the full quote response.
   *
   * GET {DEALHUB_BASE_URL}/api/v1/quotes/{quote_id}
   * Authorization: Bearer {DEALHUB_AUTH_TOKEN}
   *
   * Throws Error if DEALHUB_AUTH_TOKEN or DEALHUB_BASE_URL is not set,
   * or if the API returns 403 / 404.
   */
  static async fetchQuoteDetails(quoteId: string, fetchFn: typeof fetch = fetch): Promise<Dict> {
    const authToken = process.env.DEALHUB_AUTH_TOKEN;
    const baseUrl = process.env.DEALHUB_BASE_URL;
    if (!authToken || !baseUrl) {
      throw new Error(
        "DEALHUB_AUTH_TOKEN and DEALHUB_BASE_URL environment variables are required.",
      );
    }
    const url = `${baseUrl.replace(/\/+$/, "")}/api/v1/quotes/${quoteId}`;
    const response = await fetchFn(url, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    if (response.status === 403) {
      throw new Error("DealHub API returned 403 Forbidden — check DEALHUB_AUTH_TOKEN.");
    }
    if (response.status === 404) {
      throw new Error(`DealHub quote ${JSON.stringify(quoteId)} not found (404).`);
    }
    if (response.status >= 400) {
      throw new Error(`DealHub quote request failed: HTTP ${response.status}`);
    }
    return (await response.json()) as Dict;
  }

  /**
   * Translates a DealHub quote response into A2CN offer terms.
   *
   * Field names are resolved via fieldMap (or DEFAULT_FIELD_MAP if omitted).
   * Pass a custom fieldMap dict to override individual keys without replacing
   * the entire mapping.
   *
   * Deal type is inferred from product names: any product name containing
   * 'license', 'subscription', or 'seat' (case-insensitive) classifies the
   * quote as 'saas_renewal'; otherwise 'goods_procurement'.
   *
   * Prices are converted from dollars to cents (A2CN integer format).
   */
  static quoteToA2cnOfferTerms(
    quoteResponse: Dict,
    fieldMap: Record<string, string> | null = null,
    deliveryDays = 14,
  ): Dict {
    const fm = { ...DealHubEventParser.DEFAULT_FIELD_MAP, ...(fieldMap ?? {}) };

    const itemsRaw = (quoteResponse[fm.line_items_field] as Dict[]) ?? [];
    const lineItems: Dict[] = [];
    let totalCents = 0;

    for (const item of itemsRaw) {
      const productName = String(item[fm.product_name_field] ?? "");
      const qty = Math.trunc(Number(item[fm.quantity_field] ?? 1));
      const unitPriceCents = Math.trunc(Number(item[fm.unit_price_field] ?? 0) * 100);
      const lineTotal = qty * unitPriceCents;
      totalCents += lineTotal;

      const entry: Dict = {
        description: productName,
        quantity: qty,
        unit_price: unitPriceCents,
        total: lineTotal,
      };
      const uom = item[fm.unit_of_measure_field];
      if (uom) {
        entry.unit_of_measure = String(uom);
      }
      lineItems.push(entry);
    }

    // Fall back to top-level total_price when line items carry no prices
    const totalFromHeader = Math.trunc(Number(quoteResponse[fm.total_value_field] ?? 0) * 100);
    totalCents = totalCents || totalFromHeader;

    const currency = String(quoteResponse[fm.currency_field] ?? "USD");

    // Detect deal type from product names
    let dealType = "goods_procurement";
    for (const item of itemsRaw) {
      const name = String(item[fm.product_name_field] ?? "").toLowerCase();
      if (SUBSCRIPTION_KEYWORDS.some((kw) => name.includes(kw))) {
        dealType = "saas_renewal";
        break;
      }
    }

    const terms: Dict = {
      total_value: totalCents,
      currency,
      line_items: lineItems,
      payment_terms: { net_days: 30 },
    };

    if (dealType === "saas_renewal" && itemsRaw.length > 0) {
      const firstItem = itemsRaw[0];
      terms.seat_count = Math.trunc(Number(firstItem[fm.quantity_field] ?? 1));
      terms.subscription_tier = String(firstItem[fm.product_name_field] ?? "");
    } else {
      terms.delivery_days = deliveryDays;
    }

    return terms;
  }

  /**
   * Calls the DealHub Headless Simulate Quote API to derive mandate bounds.
   *
   * POST {DEALHUB_BASE_URL}/api/v1/headless/simulate
   * Authorization: Bearer {DEALHUB_AUTH_TOKEN}
   *
   * The ceiling is the full list price returned by the simulation.
   * The floor is ceiling * (1 - floorDiscountPct).
   *
   * floorDiscountPct should be configured per product category based on
   * actual sales policy — the 15% default is illustrative only.
   */
  static async simulateQuoteForMandateBounds(
    playbookId: string,
    answers: Dict,
    floorDiscountPct = 0.15,
    fetchFn: typeof fetch = fetch,
  ): Promise<Dict> {
    if (!playbookId) {
      throw new Error("playbook_id is required for DealHub headless simulation.");
    }
    const authToken = process.env.DEALHUB_AUTH_TOKEN;
    const baseUrl = process.env.DEALHUB_BASE_URL;
    if (!authToken || !baseUrl) {
      throw new Error(
        "DEALHUB_AUTH_TOKEN and DEALHUB_BASE_URL environment variables are required.",
      );
    }
    const url = `${baseUrl.replace(/\/+$/, "")}/api/v1/headless/simulate`;
    const payload = { playbook_id: playbookId, answers };
    const response = await fetchFn(url, {
      method: "POST",
      body: JSON.stringify(payload),
      headers: {
        Authorization: `Bearer ${authToken}`,
        "Content-Type": "application/json",
      },
    });
    if (response.status >= 400) {
      throw new Error(`DealHub simulate request failed: HTTP ${response.status}`);
    }
    const data = (await response.json()) as Dict;

    // FIELD NOTE: total_price field name should be verified against a live
    // DealHub sandbox. Contact DealHub support for exact simulate response schema.
    const ceilingCents = Math.trunc(Number(data.total_price ?? 0) * 100);
    const floorCents = Math.trunc(ceilingCents * (1.0 - floorDiscountPct));

    return {
      ceiling_value_cents: ceilingCents,
      floor_value_cents: floorCents,
      currency: data.currency ?? "USD",
      simulated_line_items: data.line_items ?? [],
    };
  }

  /**
   * Calls the DealHub Actions API to mark the quote as signed externally.
   *
   * POST {DEALHUB_BASE_URL}/api/v1/quotes/{quote_id}/actions
   * Authorization: Bearer {DEALHUB_AUTH_TOKEN}
   *
   * The note field includes both the A2CN session_id and record_hash so the
   * DealHub record is traceable back to the A2CN transaction.
   */
  static async agreedTermsToDealhubAction(
    quoteId: string,
    a2cnSessionId: string,
    recordHash: string,
    fetchFn: typeof fetch = fetch,
  ): Promise<Dict> {
    const authToken = process.env.DEALHUB_AUTH_TOKEN;
    const baseUrl = process.env.DEALHUB_BASE_URL;
    if (!authToken || !baseUrl) {
      throw new Error(
        "DEALHUB_AUTH_TOKEN and DEALHUB_BASE_URL environment variables are required.",
      );
    }
    const actionPayload = {
      action: "signExternally",
      note: `Agreed via A2CN session ${a2cnSessionId}. Record hash: ${recordHash}`,
    };
    const url = `${baseUrl.replace(/\/+$/, "")}/api/v1/quotes/${quoteId}/actions`;
    const response = await fetchFn(url, {
      method: "POST",
      body: JSON.stringify(actionPayload),
      headers: {
        Authorization: `Bearer ${authToken}`,
        "Content-Type": "application/json",
      },
    });
    if (response.status >= 400) {
      throw new Error(`DealHub action request failed: HTTP ${response.status}`);
    }
    return {
      api_response: (await response.json()) as Dict,
      action_payload_sent: actionPayload,
    };
  }
}
