/**
 * Fairmarkit → A2CN translation layer.
 *
 * Translates Fairmarkit webhook payloads and API responses into A2CN
 * message structures, and vice versa.
 *
 * No I/O in this module — pure data translation, fully testable offline.
 *
 * Fairmarkit API reference:
 *   Webhooks: developers.fairmarkit.com/docs/webhooks
 *   Responses: GET /self-service/api/v3/responses/request/{request_id}/
 */

import type { Dict } from "../a2cn/messages.js";

export class FairmakitEventParser {
  /**
   * Parse a Fairmarkit BID_CREATED webhook payload into an A2CN
   * proposed_terms_summary for a SessionInvitation.
   *
   * Expected payload fields:
   *   request_id: str
   *   tenant_id: str
   *   status: str ("submitted")
   *   items: list of {description, quantity, uom, unit_price (optional)}
   *   deadline: str  # ISO 8601
   *
   * Returns dict suitable for SessionInvitation.proposed_terms_summary.
   */
  static parseBidCreatedWebhook(payload: Dict): Dict {
    const items = (payload.items as Dict[]) ?? [];
    const descriptionParts = items
      .slice(0, 3)
      .map((item) => String(item.description ?? "").slice(0, 50));
    let description = descriptionParts.join("; ");
    if (items.length > 3) {
      description += ` (+${items.length - 3} more items)`;
    }

    let estimatedValue = 0;
    for (const item of items) {
      const qty = Number(item.quantity ?? 0);
      const price = Number(item.unit_price ?? 0);
      estimatedValue += Math.trunc(qty * price * 100); // convert to cents
    }

    return {
      description,
      estimated_value: estimatedValue,
      currency: "USD",
      item_count: items.length,
      deadline: payload.deadline ?? "",
      fairmarkit_request_id: payload.request_id ?? "",
    };
  }

  /**
   * Parse a Fairmarkit BID_CREATED payload into A2CN goods_procurement
   * terms suitable for a first-round offer.
   *
   * Maps Fairmarkit items to A2CN line_items.
   * Fairmarkit UOM passes through directly to A2CN unit_of_measure.
   */
  static bidCreatedToGoodsProcurementTerms(payload: Dict): Dict {
    const items = (payload.items as Dict[]) ?? [];
    const lineItems: Dict[] = [];
    let totalCents = 0;

    for (const item of items) {
      const qty = Number(item.quantity ?? 1);
      const unitPriceCents = Math.trunc(Number(item.unit_price ?? 0) * 100);
      const lineTotal = Math.trunc(qty * unitPriceCents);
      totalCents += lineTotal;

      const lineItem: Dict = {
        description: item.description ?? "",
        quantity: Math.trunc(qty),
        unit_price: unitPriceCents,
        total: lineTotal,
        unit_of_measure: item.uom ?? "EA",
      };
      if (item.mfg_part_number) {
        lineItem.manufacturer_part_number = item.mfg_part_number;
      }
      if (item.internal_part_number) {
        lineItem.internal_part_number = item.internal_part_number;
      }
      lineItems.push(lineItem);
    }

    return {
      total_value: totalCents,
      currency: "USD",
      line_items: lineItems,
      delivery_days: 14, // default; override with actual requirements
      payment_terms: { net_days: 30 },
    };
  }

  /**
   * Translate A2CN agreed_terms from a completed transaction record
   * into a Fairmarkit response submission payload.
   *
   * Output can be submitted to:
   * POST /self-service/api/v3/responses/request/{request_id}/
   *
   * Converts cents to dollars (Fairmarkit uses decimal prices).
   */
  static termsToFairmarkitResponse(agreedTerms: Dict, sessionId: string, requestId: string): Dict {
    const lineItems = (agreedTerms.line_items as Dict[]) ?? [];
    const responseItems: Dict[] = [];

    for (const item of lineItems) {
      responseItems.push({
        description: item.description ?? "",
        quantity: item.quantity ?? 1,
        unit_price: ((item.unit_price as number) ?? 0) / 100.0,
        total_price: ((item.total as number) ?? 0) / 100.0,
        uom: item.unit_of_measure ?? "EA",
        manufacturer_part_number: item.manufacturer_part_number ?? "",
        internal_part_number: item.internal_part_number ?? "",
        delivery_days: agreedTerms.delivery_days ?? 14,
      });
    }

    const netDays = ((agreedTerms.payment_terms as Dict) ?? {}).net_days ?? 30;

    return {
      request_id: requestId,
      a2cn_session_id: sessionId,
      status: "submitted",
      items: responseItems,
      total_price: ((agreedTerms.total_value as number) ?? 0) / 100.0,
      currency: agreedTerms.currency ?? "USD",
      payment_terms: `Net ${netDays}`,
      delivery_days: agreedTerms.delivery_days ?? 14,
      notes: `Negotiated via A2CN session ${sessionId}`,
    };
  }
}
