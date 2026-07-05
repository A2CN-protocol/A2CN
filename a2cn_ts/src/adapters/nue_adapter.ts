/**
 * Nue.io Revenue Lifecycle → A2CN translation layer.
 *
 * Translates Nue pricing and subscription data into A2CN session terms, and
 * translates A2CN agreed terms back into Nue order creation.
 *
 * Primary flow:
 *   NueEventParser.fetchPricing(priceBookId, productId)
 *       → NueEventParser.pricingToMandateBounds(pricingResponse)
 *           → configure agent mandate bounds
 *       → A2CN negotiation session
 *       → NueEventParser.a2cnTermsToNueOrder(agreedTerms, ...)
 *
 * Renewal flow:
 *   NueEventParser.fetchCustomerSubscriptions(customerId)
 *       → NueEventParser.subscriptionToRenewalTerms(subscriptionResponse)
 *           → A2CN saas_renewal session
 *       → NueEventParser.a2cnTermsToNueOrder(agreedTerms, ...)
 *
 * Nue API reference (Revenue Lifecycle API):
 *   Pricing:       GET  {NUE_BASE_URL}/commerce/pricing
 *   Orders:        POST {NUE_BASE_URL}/orders
 *   Subscriptions: GET  {NUE_BASE_URL}/subscriptions
 *
 * Environment variables required:
 *   NUE_API_KEY:  API key from Nue administrator
 *   NUE_BASE_URL: Base URL — production (https://api.nue.io) or
 *                 sandbox (https://api.sandbox.nue.io)
 */

import type { Dict } from "../a2cn/messages.js";

/**
 * Translates Nue.io pricing and subscription data into A2CN session terms,
 * and translates A2CN agreed terms back into Nue order creation.
 *
 * Nue is a seller-side CPQ and billing platform for SaaS companies.
 * The primary A2CN use case is SaaS subscription negotiation — the seller's
 * Nue instance provides pricing, the buyer's agent negotiates via A2CN, and
 * agreed terms are written back as a Nue order.
 *
 * Environment variables required:
 *     NUE_API_KEY:  API key from Nue administrator
 *     NUE_BASE_URL: Base URL (production or sandbox)
 */
export class NueEventParser {
  // Default field map for Nue pricing API responses.
  // Override via the fieldMap parameter on pricingToMandateBounds() if
  // your Nue instance uses different field names.
  // FIELD NOTE: All names should be verified against a live Nue sandbox instance.
  static PRICING_FIELD_MAP: Record<string, string> = {
    list_price_field: "listPrice", // FIELD NOTE: Verify against live Nue sandbox.
    quantity_field: "quantity", // FIELD NOTE: Verify against live Nue sandbox.
    currency_field: "currency", // FIELD NOTE: Verify against live Nue sandbox.
  };

  // Default field map for Nue subscription API responses.
  // Override via the fieldMap parameter on subscriptionToRenewalTerms() if
  // your Nue instance uses different field names.
  // FIELD NOTE: All names should be verified against a live Nue sandbox instance.
  static SUBSCRIPTION_FIELD_MAP: Record<string, string> = {
    total_value_field: "totalValue", // FIELD NOTE: Verify against live Nue sandbox.
    quantity_field: "quantity", // FIELD NOTE: Verify against live Nue sandbox.
    tier_field: "productTier", // FIELD NOTE: Verify against live Nue sandbox.
    auto_renew_field: "autoRenew", // FIELD NOTE: Verify against live Nue sandbox.
    term_months_field: "termMonths", // FIELD NOTE: Verify against live Nue sandbox.
    currency_field: "currency", // FIELD NOTE: Verify against live Nue sandbox.
  };

  /**
   * Calls the Nue Commerce API to get pricing for a specific product and
   * price book.
   *
   * GET {NUE_BASE_URL}/commerce/pricing?priceBookId={id}&productId={id}
   * Nue-Api-Key: {NUE_API_KEY}
   *
   * Throws Error if NUE_API_KEY or NUE_BASE_URL is not set, or if the
   * API returns 401 / 404.
   */
  static async fetchPricing(
    priceBookId: string,
    productId: string,
    fetchFn: typeof fetch = fetch,
  ): Promise<Dict> {
    const apiKey = process.env.NUE_API_KEY;
    const baseUrl = process.env.NUE_BASE_URL;
    if (!apiKey || !baseUrl) {
      throw new Error("NUE_API_KEY and NUE_BASE_URL environment variables are required.");
    }
    const params = new URLSearchParams({ priceBookId, productId });
    const url = `${baseUrl.replace(/\/+$/, "")}/commerce/pricing?${params}`;
    const response = await fetchFn(url, { headers: { "Nue-Api-Key": apiKey } });
    if (response.status === 401) {
      throw new Error("Nue API returned 401 Unauthorized — check NUE_API_KEY.");
    }
    if (response.status === 404) {
      throw new Error(
        `Nue pricing not found for priceBookId=${JSON.stringify(priceBookId)}, ` +
          `productId=${JSON.stringify(productId)}.`,
      );
    }
    if (response.status >= 400) {
      throw new Error(`Nue pricing request failed: HTTP ${response.status}`);
    }
    return (await response.json()) as Dict;
  }

  /**
   * Translates a Nue pricing response into A2CN mandate bounds.
   *
   * The ceiling is the full list price (optionally marked up by
   * ceilingMarkupPct). The floor is ceiling * (1 - floorDiscountPct).
   *
   * floorDiscountPct represents the maximum discount the seller's agent
   * is authorized to offer without human approval. Configure per product
   * tier in production.
   *
   * FIELD NOTE: listPrice, quantity, and currency field names should be
   * verified against a live Nue sandbox instance.
   */
  static pricingToMandateBounds(
    pricingResponse: Dict,
    floorDiscountPct = 0.1,
    ceilingMarkupPct = 0.0,
    fieldMap: Record<string, string> | null = null,
  ): Dict {
    const fm = { ...NueEventParser.PRICING_FIELD_MAP, ...(fieldMap ?? {}) };

    const listPrice = Number(pricingResponse[fm.list_price_field] ?? 0);
    const quantity = Math.trunc(Number(pricingResponse[fm.quantity_field] ?? 1));
    const totalListPrice = listPrice * quantity;

    const ceilingCents = Math.trunc(totalListPrice * 100 * (1.0 + ceilingMarkupPct));
    const floorCents = Math.trunc(ceilingCents * (1.0 - floorDiscountPct));
    const currency = String(pricingResponse[fm.currency_field] ?? "USD");

    return {
      ceiling_value_cents: ceilingCents,
      floor_value_cents: floorCents,
      currency,
    };
  }

  /**
   * Translates an existing Nue subscription into A2CN saas_renewal offer
   * terms for a renewal negotiation.
   *
   * The proposed renewal value is the current subscription total plus
   * renewalMarkupPct (default 5%).
   *
   * FIELD NOTE: Field names (totalValue, productTier, autoRenew, termMonths,
   * quantity) should be verified against a live Nue sandbox instance.
   */
  static subscriptionToRenewalTerms(
    subscriptionResponse: Dict,
    renewalMarkupPct = 0.05,
    fieldMap: Record<string, string> | null = null,
  ): Dict {
    const fm = { ...NueEventParser.SUBSCRIPTION_FIELD_MAP, ...(fieldMap ?? {}) };

    const currentValue = Number(subscriptionResponse[fm.total_value_field] ?? 0);
    const renewalValueCents = Math.trunc(currentValue * 100 * (1.0 + renewalMarkupPct));

    const seatCount = Math.trunc(Number(subscriptionResponse[fm.quantity_field] ?? 1));
    const tier = String(subscriptionResponse[fm.tier_field] ?? "standard");
    const autoRenew = Boolean(subscriptionResponse[fm.auto_renew_field] ?? false);
    const termMonths = Math.trunc(Number(subscriptionResponse[fm.term_months_field] ?? 12));
    const currency = String(subscriptionResponse[fm.currency_field] ?? "USD");

    return {
      deal_type: "saas_renewal",
      total_value: renewalValueCents,
      currency,
      seat_count: seatCount,
      subscription_tier: tier,
      auto_renew_terms: { auto_renew: autoRenew },
      term_months: termMonths,
    };
  }

  /**
   * Translates A2CN agreed terms into a Nue order payload and calls the
   * Nue Orders API.
   *
   * POST {NUE_BASE_URL}/orders
   * Nue-Api-Key: {NUE_API_KEY}
   *
   * The externalReference field MUST include the A2CN session_id and the
   * notes field MUST include the record_hash. These two fields create the
   * audit link between the Nue order and the A2CN transaction record.
   */
  static async a2cnTermsToNueOrder(
    agreedTerms: Dict,
    customerId: string,
    priceBookId: string,
    productId: string,
    a2cnSessionId: string,
    recordHash: string,
    startDate: string | null = null,
    fetchFn: typeof fetch = fetch,
  ): Promise<Dict> {
    const apiKey = process.env.NUE_API_KEY;
    const baseUrl = process.env.NUE_BASE_URL;
    if (!apiKey || !baseUrl) {
      throw new Error("NUE_API_KEY and NUE_BASE_URL environment variables are required.");
    }
    if (startDate === null) {
      startDate = new Date().toISOString().slice(0, 10);
    }

    const lineItems = (agreedTerms.line_items as Dict[]) ?? [];
    const termMonths = Math.trunc(Number(agreedTerms.term_months ?? 12));

    let lines: Dict[];
    if (lineItems.length > 0) {
      lines = lineItems.map((item) => ({
        productId,
        quantity: item.quantity ?? 1,
        unitPrice: ((item.unit_price as number) ?? 0) / 100.0,
        term: termMonths,
      }));
    } else {
      // No line items — build a single line from the total.
      // unitPrice = per-seat price: divide total by seat count before converting cents→dollars.
      const seatCount = Math.max(Math.trunc(Number(agreedTerms.seat_count ?? 1)), 1);
      lines = [
        {
          productId,
          quantity: seatCount,
          unitPrice: ((agreedTerms.total_value as number) ?? 0) / seatCount / 100.0,
          term: termMonths,
        },
      ];
    }

    const orderPayload: Dict = {
      customerId,
      priceBookId,
      startDate,
      lines,
      externalReference: `a2cn-session-${a2cnSessionId}`,
      notes: `Agreed via A2CN. Record hash: ${recordHash}`,
    };

    const url = `${baseUrl.replace(/\/+$/, "")}/orders`;
    const response = await fetchFn(url, {
      method: "POST",
      body: JSON.stringify(orderPayload),
      headers: {
        "Nue-Api-Key": apiKey,
        "Content-Type": "application/json",
      },
    });
    if (response.status >= 400) {
      throw new Error(`Nue order request failed: HTTP ${response.status}`);
    }
    return {
      api_response: (await response.json()) as Dict,
      order_payload_sent: orderPayload,
    };
  }

  /**
   * Fetches all active subscriptions for a customer from Nue.
   *
   * GET {NUE_BASE_URL}/subscriptions?customerId={customer_id}
   * Nue-Api-Key: {NUE_API_KEY}
   *
   * Used to establish renewal context before initiating an A2CN session.
   */
  static async fetchCustomerSubscriptions(
    customerId: string,
    fetchFn: typeof fetch = fetch,
  ): Promise<Dict[]> {
    const apiKey = process.env.NUE_API_KEY;
    const baseUrl = process.env.NUE_BASE_URL;
    if (!apiKey || !baseUrl) {
      throw new Error("NUE_API_KEY and NUE_BASE_URL environment variables are required.");
    }
    const params = new URLSearchParams({ customerId });
    const url = `${baseUrl.replace(/\/+$/, "")}/subscriptions?${params}`;
    const response = await fetchFn(url, { headers: { "Nue-Api-Key": apiKey } });
    if (response.status >= 400) {
      throw new Error(`Nue subscriptions request failed: HTTP ${response.status}`);
    }
    const data = (await response.json()) as Dict | Dict[];
    if (Array.isArray(data)) {
      return data;
    }
    // FIELD NOTE: Verify top-level list key against live Nue sandbox instance.
    return ((data.subscriptions ?? data.items ?? []) as Dict[]);
  }
}
