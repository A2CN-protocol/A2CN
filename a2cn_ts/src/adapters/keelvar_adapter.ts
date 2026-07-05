/**
 * Keelvar → A2CN translation layer.
 *
 * Translates Keelvar SOURCING_EVENTS_FEED_UPDATED webhook payloads and sourcing
 * event data into A2CN protocol messages, and vice versa.
 *
 * No I/O in this module — pure data translation, fully testable offline.
 *
 * Keelvar API reference:
 *   Docs:     https://docs.keelvar.app
 *   Webhooks: POST https://my.keelvar.app/api/webhooks
 *   Events:   GET  https://my.keelvar.app/api/sourcing-events
 *   Bids:     GET  https://my.keelvar.app/api/bids
 *
 * Field mapping — Keelvar → A2CN goods_procurement:
 *
 *   Keelvar field                        A2CN goods_procurement field
 *   ───────────────────────────────────────────────────────────────────────
 *   event.line_items[].description       line_items[].description
 *   event.line_items[].quantity          line_items[].quantity
 *   event.line_items[].unit_of_measure   line_items[].unit_of_measure
 *   event.line_items[].unit_price (USD)  line_items[].unit_price (cents)
 *   event.line_items[].lot_id            line_items[].internal_part_number
 *   event.currency                       currency
 *   Computed from line items             total_value (cents)
 *   default_delivery_days param          delivery_days
 *   Hardcoded default 30                 payment_terms.net_days
 */

import { createHmac, timingSafeEqual } from "node:crypto";

import type { Dict } from "../a2cn/messages.js";

/**
 * Translates between Keelvar sourcing event data and A2CN protocol messages.
 *
 * Integration pattern (Path B — supplier-side, zero Keelvar platform changes):
 *
 *     Keelvar fires SOURCING_EVENTS_FEED_UPDATED webhook
 *         -> KeelvarEventParser.parseSourcingEventWebhook(payload)
 *             -> Returns event summary with event_id, line items, deadline
 *         -> KeelvarEventParser.sourcingEventToGoodsProcurementTerms(payload)
 *             -> Returns A2CN goods_procurement terms dict
 *         -> A2CN Session Invitation accepted / SessionInit sent
 *         -> A2CN negotiation completes
 *         -> KeelvarEventParser.termsToKeelvarBidResponse(agreedTerms, eventId)
 *             -> Returns Keelvar bid response payload
 *         -> POST bid response to Keelvar API
 *
 * Keelvar docs: https://docs.keelvar.app
 * Keelvar webhook API: https://my.keelvar.app/api/webhooks
 */
export class KeelvarEventParser {
  /**
   * Parse a Keelvar SOURCING_EVENTS_FEED_UPDATED webhook payload into a
   * clean summary dict.
   *
   * Expected payload shape (from Keelvar sourcing events feed):
   *   event_id:    str
   *   event_name:  str
   *   buyer_org:   str
   *   deadline:    str | null   (ISO 8601)
   *   currency:    str          (ISO 4217, default 'USD')
   *   line_items:  list of {description, quantity, unit_of_measure,
   *                         unit_price (optional, USD), lot_id (optional)}
   */
  static parseSourcingEventWebhook(payload: Dict): Dict {
    const lineItemsRaw = (payload.line_items as Dict[]) ?? [];
    const lineItems: Dict[] = [];
    for (const item of lineItemsRaw) {
      const unitPriceRaw = item.unit_price;
      const unitPriceCents =
        unitPriceRaw !== null && unitPriceRaw !== undefined
          ? Math.trunc(Number(unitPriceRaw) * 100)
          : null;
      lineItems.push({
        description: item.description ?? "",
        quantity: Math.trunc(Number(item.quantity ?? 1)),
        unit_of_measure: item.unit_of_measure ?? "EA",
        unit_price_cents: unitPriceCents,
        lot_id: item.lot_id ?? "",
      });
    }

    return {
      event_id: payload.event_id ?? "",
      event_name: payload.event_name ?? "",
      buyer_org: payload.buyer_org ?? "",
      deadline: payload.deadline || null,
      currency: payload.currency ?? "USD",
      line_items: lineItems,
      raw_payload: payload,
    };
  }

  /**
   * Translate a Keelvar SOURCING_EVENTS_FEED_UPDATED webhook payload into
   * A2CN goods_procurement terms suitable for a first-round offer or
   * SessionInit.proposed_terms_summary.
   *
   * If no unit_price is present in the payload, total_value is 0 —
   * the supplier will set their own opening price in the A2CN session.
   */
  static sourcingEventToGoodsProcurementTerms(
    webhookPayload: Dict,
    defaultDeliveryDays = 14,
  ): Dict {
    const lineItemsRaw = (webhookPayload.line_items as Dict[]) ?? [];
    const lineItems: Dict[] = [];
    let totalCents = 0;

    for (const item of lineItemsRaw) {
      const qty = Math.trunc(Number(item.quantity ?? 1));
      const unitPriceRaw = item.unit_price;
      const unitPriceCents =
        unitPriceRaw !== null && unitPriceRaw !== undefined
          ? Math.trunc(Number(unitPriceRaw) * 100)
          : 0;
      const lineTotal = qty * unitPriceCents;
      totalCents += lineTotal;

      const lineItem: Dict = {
        description: item.description ?? "",
        quantity: qty,
        unit_of_measure: item.unit_of_measure ?? "EA",
        unit_price: unitPriceCents,
        total: lineTotal,
      };
      if (item.lot_id) {
        lineItem.internal_part_number = item.lot_id;
      }
      lineItems.push(lineItem);
    }

    return {
      total_value: totalCents,
      currency: webhookPayload.currency ?? "USD",
      line_items: lineItems,
      delivery_days: defaultDeliveryDays,
      payment_terms: { net_days: 30 },
    };
  }

  /**
   * Translate A2CN agreed_terms from a completed transaction record into a
   * Keelvar bid response payload ready for submission to the Keelvar API.
   *
   * Returns a bid response dict with prices in dollars (not cents), suitable
   * for submission to the Keelvar sourcing event bid API.
   */
  static termsToKeelvarBidResponse(
    agreedTerms: Dict,
    eventId: string,
    supplierId: string | null = null,
  ): Dict {
    const lineItemsRaw = (agreedTerms.line_items as Dict[]) ?? [];
    const responseLineItems: Dict[] = [];

    for (const item of lineItemsRaw) {
      const entry: Dict = {
        description: item.description ?? "",
        quantity: item.quantity ?? 1,
        unit_of_measure: item.unit_of_measure ?? "EA",
        unit_price: ((item.unit_price as number) ?? 0) / 100.0,
        total_price: ((item.total as number) ?? 0) / 100.0,
      };
      if (item.internal_part_number) {
        entry.lot_id = item.internal_part_number;
      }
      responseLineItems.push(entry);
    }

    const netDays = ((agreedTerms.payment_terms as Dict) ?? {}).net_days ?? 30;

    const result: Dict = {
      event_id: eventId,
      total_price: ((agreedTerms.total_value as number) ?? 0) / 100.0,
      currency: agreedTerms.currency ?? "USD",
      line_items: responseLineItems,
      delivery_days: agreedTerms.delivery_days ?? 14,
      payment_terms: `Net ${netDays}`,
      status: "submitted",
    };
    if (supplierId !== null) {
      result.supplier_id = supplierId;
    }
    return result;
  }

  /**
   * Verify the HMAC_SHA256 signature on a Keelvar webhook delivery.
   *
   * Keelvar signs the raw request body with the webhook signing key and
   * sends the hex digest in the X-Signature header.
   *
   * Always call this before processing any webhook payload to prevent
   * replay and forgery attacks.
   */
  static verifyWebhookSignature(
    payloadBytes: Buffer | Uint8Array,
    signatureHeader: string,
    signingKey: string,
  ): boolean {
    const expected = createHmac("sha256", Buffer.from(signingKey, "utf-8"))
      .update(payloadBytes)
      .digest("hex");
    const expectedBuf = Buffer.from(expected, "utf-8");
    const receivedBuf = Buffer.from(signatureHeader, "utf-8");
    return expectedBuf.length === receivedBuf.length && timingSafeEqual(expectedBuf, receivedBuf);
  }
}
