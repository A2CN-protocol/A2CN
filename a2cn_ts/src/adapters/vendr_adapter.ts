/**
 * Vendr -> A2CN translation layer.
 *
 * Translates Vendr renewal/workflow webhook payloads and pricing benchmark data
 * into A2CN SaaS renewal terms. The primary integration pattern is MCP-to-MCP:
 * an agent calls Vendr's MCP server for pricing intelligence, then calls A2CN's
 * MCP tools to run the bilateral negotiation and produce the signed record.
 *
 * No I/O in this module -- pure data translation, fully testable offline.
 *
 * Vendr integration surfaces:
 *   MCP server: pricing and benchmark intelligence for agent use
 *   Webhooks:   one-way procurement/workflow notifications from Vendr
 *
 * Field mapping -- Vendr pricing -> A2CN saas_renewal:
 *
 *   Vendr field                         A2CN saas_renewal field
 *   ----------------------------------------------------------------------
 *   vendor                              custom_terms.vendr.vendor
 *   product                             subscription_tier / line description
 *   list_price                          line_items[].unit_price (cents)
 *   seat_count                          seat_count / line quantity
 *   term_months                         term_months
 *   currency                            currency
 *   observed_discount_band.midpoint     total_value discount basis
 *   benchmark_range                     custom_terms.vendr.benchmark_range
 */

import { createHmac, timingSafeEqual } from "node:crypto";

import type { Dict } from "../a2cn/messages.js";

/** Convert a decimal money value into integer cents. */
function moneyToCents(value: unknown): number {
  if (value === null || value === undefined) {
    return 0;
  }
  return Math.trunc(Number(value) * 100);
}

function intValue(value: unknown, defaultValue = 0): number {
  if (value === null || value === undefined || value === "") {
    return defaultValue;
  }
  return Math.trunc(Number(value));
}

function discountToFraction(value: unknown): number | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  let discount = Number(value);
  if (discount > 1) {
    discount = discount / 100.0;
  }
  return discount;
}

function discountBandMidpoint(discountBand: unknown): number | null {
  if (discountBand === null || typeof discountBand !== "object" || Array.isArray(discountBand)) {
    return null;
  }
  const band = discountBand as Dict;
  if ("midpoint" in band) {
    return discountToFraction(band.midpoint);
  }
  const minimum = discountToFraction(band.min);
  const maximum = discountToFraction(band.max);
  if (minimum === null && maximum === null) {
    return null;
  }
  if (minimum === null) {
    return maximum;
  }
  if (maximum === null) {
    return minimum;
  }
  return (minimum + maximum) / 2.0;
}

/**
 * Map Vendr benchmark/pricing data into A2CN saas_renewal terms.
 *
 * Expected pricing fields:
 *   vendor: str
 *   product: str
 *   list_price: number        # per-seat annual price in dollars
 *   seat_count: int
 *   currency: str             # ISO 4217, default USD
 *   term_months: int          # default 12
 *   observed_discount_band: {min, max} or {midpoint}
 *   benchmark_range: {low, median, high}  # optional, dollars
 *
 * The observed discount band midpoint is applied to list_price to create the
 * proposed A2CN total_value. Values are stored in integer cents.
 */
export function vendrPricingToA2cnTerms(pricing: Dict, defaultNetDays = 30): Dict {
  const vendor = String(pricing.vendor ?? "");
  const product = String(pricing.product ?? "");
  const seatCount = Math.max(intValue(pricing.seat_count, 1), 1);
  const termMonths = Math.max(intValue(pricing.term_months, 12), 1);
  const listPriceCents = moneyToCents(pricing.list_price ?? pricing.annual_unit_price ?? 0);

  let discount = discountBandMidpoint(pricing.observed_discount_band);
  if (discount === null) {
    discount = discountToFraction(pricing.observed_discount);
  }
  let effectiveUnitPriceCents = listPriceCents;
  if (discount !== null) {
    effectiveUnitPriceCents = Math.trunc(listPriceCents * (1.0 - discount));
  }

  const totalCents = effectiveUnitPriceCents * seatCount;
  const benchmarkRange = (pricing.benchmark_range as Dict) ?? {};
  const benchmarkRangeCents: Dict = {};
  for (const [key, value] of Object.entries(benchmarkRange)) {
    if (["low", "median", "high"].includes(key)) {
      benchmarkRangeCents[key] = moneyToCents(value);
    }
  }

  return {
    deal_type: "saas_renewal",
    total_value: totalCents,
    currency: pricing.currency ?? "USD",
    line_items: [
      {
        description: product || vendor || "Vendr benchmarked subscription",
        quantity: seatCount,
        unit_price: effectiveUnitPriceCents,
        total: totalCents,
      },
    ],
    payment_terms: { net_days: defaultNetDays },
    seat_count: seatCount,
    subscription_tier: pricing.subscription_tier ?? (product || "standard"),
    term_months: termMonths,
    custom_terms: {
      vendr: {
        vendor,
        product,
        list_price: listPriceCents,
        observed_discount: discount,
        benchmark_range: benchmarkRangeCents,
        source: pricing.source ?? "vendr_mcp",
      },
    },
  };
}

/**
 * Translates Vendr workflow/renewal webhooks into A2CN session inputs.
 *
 * Vendr webhooks are one-way notifications, so this parser returns local
 * session parameters and opening terms; it does not try to write back to Vendr.
 */
export class VendrWebhookParser {
  /**
   * Parse a Vendr renewal/workflow event into A2CN session params and terms.
   *
   * Expected payload fields are intentionally tolerant because Vendr webhook
   * payloads may vary by workflow:
   *   event_id, event_type, workflow_id, buyer_org, vendor, product,
   *   renewal_date, currency, seat_count, term_months, pricing
   *
   * Returns:
   *   Dict with session_params, initial_terms, event_id, workflow_id, and
   *   raw_payload for audit correlation.
   */
  static parseRenewalWebhook(payload: Dict, maxRounds = 5): Dict {
    const pricing: Dict = { ...((payload.pricing as Dict) ?? {}) };
    for (const key of [
      "vendor",
      "product",
      "list_price",
      "annual_unit_price",
      "seat_count",
      "currency",
      "term_months",
      "observed_discount",
      "observed_discount_band",
      "benchmark_range",
      "subscription_tier",
    ]) {
      if (!(key in pricing) && key in payload) {
        pricing[key] = payload[key];
      }
    }

    const terms = vendrPricingToA2cnTerms(pricing);
    const eventId = payload.event_id ?? payload.id ?? "";
    const workflowId = payload.workflow_id ?? payload.workflowId ?? "";

    const sessionParams: Dict = {
      deal_type: "saas_renewal",
      currency: terms.currency ?? "USD",
      max_rounds: maxRounds,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
      vendr_event_id: eventId,
      vendr_workflow_id: workflowId,
      buyer_org: payload.buyer_org ?? payload.buyerOrg ?? "",
      vendor: pricing.vendor ?? "",
      product: pricing.product ?? "",
      renewal_date: payload.renewal_date ?? payload.renewalDate ?? "",
    };

    return {
      event_id: eventId,
      event_type: payload.event_type ?? payload.eventType ?? "",
      workflow_id: workflowId,
      session_params: sessionParams,
      initial_terms: terms,
      raw_payload: payload,
    };
  }

  /**
   * Verify an HMAC-SHA256 Vendr webhook signature when a secret is provided.
   *
   * Accepts either a bare hex digest or common prefixed forms such as
   * `sha256=<digest>` and `v1=<digest>`.
   */
  static verifyWebhookSignature(
    payloadBytes: Buffer | Uint8Array,
    signatureHeader: string,
    webhookSecret: string,
  ): boolean {
    if (!webhookSecret || !signatureHeader) {
      return false;
    }
    const expected = createHmac("sha256", Buffer.from(webhookSecret, "utf-8"))
      .update(payloadBytes)
      .digest("hex");
    let received = signatureHeader.trim();
    for (const prefix of ["sha256=", "v1="]) {
      if (received.startsWith(prefix)) {
        received = received.slice(prefix.length);
        break;
      }
    }
    const expectedBuf = Buffer.from(expected, "utf-8");
    const receivedBuf = Buffer.from(received, "utf-8");
    return expectedBuf.length === receivedBuf.length && timingSafeEqual(expectedBuf, receivedBuf);
  }
}

/**
 * Translate agreed A2CN terms into a Vendr-shaped summary for audit linkage.
 *
 * Vendr webhooks do not provide a write-back API, so this is a local summary
 * that can be attached to downstream systems or used by an agent when calling
 * non-webhook Vendr surfaces.
 */
export function a2cnTermsToVendrSummary(
  agreedTerms: Dict,
  sessionId: string,
  recordHash: string,
  workflowId: string | null = null,
): Dict {
  const vendrMeta = (((agreedTerms.custom_terms as Dict) ?? {}).vendr as Dict) ?? {};
  const totalValue = (agreedTerms.total_value as number) ?? 0;
  const seatCount = Math.max(intValue(agreedTerms.seat_count, 1), 1);
  const summary: Dict = {
    source: "a2cn",
    a2cn_session_id: sessionId,
    a2cn_record_hash: recordHash,
    workflow_id: workflowId,
    vendor: vendrMeta.vendor ?? "",
    product: vendrMeta.product ?? agreedTerms.subscription_tier ?? "",
    status: "negotiated",
    total_value: totalValue / 100.0,
    currency: agreedTerms.currency ?? "USD",
    seat_count: seatCount,
    unit_price: totalValue / seatCount / 100.0,
    term_months: agreedTerms.term_months ?? 12,
    payment_terms: `Net ${((agreedTerms.payment_terms as Dict) ?? {}).net_days ?? 30}`,
  };
  return Object.fromEntries(Object.entries(summary).filter(([, v]) => v !== null && v !== undefined));
}

/**
 * Deterministically encode a sample payload for tests and webhook fixtures.
 *
 * Production servers should verify the exact raw request body bytes they
 * received, not a re-serialized dict.
 */
export function webhookBodyForSignature(payload: Dict): Buffer {
  return Buffer.from(JSON.stringify(sortKeysDeep(payload)), "utf-8");
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}
