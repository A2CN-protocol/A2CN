/**
 * SAP Ariba -> A2CN translation layer.
 *
 * Translates SAP Ariba Sourcing / Discovery RFx event payloads into A2CN
 * goods_procurement terms, and translates agreed A2CN terms into Ariba-shaped bid
 * or acknowledgement payloads.
 *
 * SAP public documentation used for this adapter:
 *   Event Management API:
 *     GET /events
 *     GET /events/{eventId}/items
 *   Discovery RFx Publication TO External Marketplace API:
 *     GetNextRfxEvent -> GetRfxAttachment -> UpdateRfxEvent -> Acknowledge
 *
 * No core protocol changes are required. This module keeps the platform mapping
 * offline-testable, while small auth helpers document the OAuth/API-key shape
 * needed when wiring it into a live SAP Ariba environment.
 */

import type { Dict } from "../a2cn/messages.js";

function moneyToCents(value: unknown): number {
  if (value === null || value === undefined || value === "") {
    return 0;
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    value = (value as Dict).amount ?? 0;
  }
  return Math.trunc(Number(value) * 100);
}

function intValue(value: unknown, defaultValue = 0): number {
  if (value === null || value === undefined || value === "") {
    return defaultValue;
  }
  return Math.trunc(Number(value));
}

function first(mapping: Dict, names: string[], defaultValue: unknown = null): unknown {
  for (const name of names) {
    if (name in mapping && mapping[name] !== null && mapping[name] !== undefined) {
      return mapping[name];
    }
  }
  return defaultValue;
}

function itemsFromPayload(payload: Dict): Dict[] {
  let items =
    payload.items ?? payload.lineItems ?? payload.line_items ?? payload.lots ?? [];
  if (items !== null && typeof items === "object" && !Array.isArray(items)) {
    const obj = items as Dict;
    items = obj.items ?? obj.lineItems ?? obj.results ?? [];
  }
  return [...(items as Dict[])];
}

function normalizeItem(item: Dict, defaultCurrency: string): Dict {
  const itemId = first(item, ["itemId", "item_id", "lineItemId", "internalId", "id"], "");
  const lotId = first(item, ["lotId", "lot_id", "lot", "lotNumber"], "");
  const quantity = intValue(first(item, ["quantity", "qty", "amount"], 1), 1);
  const unitPriceRaw = first(
    item,
    ["unitPrice", "unit_price", "targetPrice", "target_price", "estimatedUnitPrice", "price"],
    0,
  );
  const unitPriceCents = moneyToCents(unitPriceRaw);
  const totalRaw = first(item, ["totalPrice", "total_price", "extendedPrice"], null);
  const totalCents = totalRaw !== null ? moneyToCents(totalRaw) : quantity * unitPriceCents;
  const lineItem: Dict = {
    description: first(item, ["title", "description", "name", "itemName"], ""),
    quantity,
    unit_of_measure: first(item, ["unitOfMeasure", "unit_of_measure", "uom"], "EA"),
    unit_price: unitPriceCents,
    total: totalCents,
  };
  const internalRef = lotId || itemId;
  if (internalRef) {
    lineItem.internal_part_number = String(internalRef);
  }
  if (itemId) {
    lineItem.ariba_item_id = String(itemId);
  }
  if (lotId) {
    lineItem.ariba_lot_id = String(lotId);
  }
  if (item.currency) {
    lineItem.currency = item.currency;
  } else {
    lineItem.currency = defaultCurrency;
  }
  return lineItem;
}

/**
 * Translates SAP Ariba sourcing/RFx events into A2CN session inputs.
 */
export class AribaEventParser {
  /**
   * Parse an SAP Ariba event or Discovery RFx payload into a clean summary.
   *
   * The parser accepts tolerant aliases from Event Management responses
   * (event id/header/items) and Discovery RFx publications (RFx id/lots).
   */
  static parseSourcingEvent(payload: Dict): Dict {
    const event = ((payload.event ?? payload.rfxEvent) as Dict) ?? payload;
    const currency = first(event, ["currency", "currencyCode"], "USD") as string;
    const rawItems = itemsFromPayload(event);
    const lineItems = rawItems.map((item) => normalizeItem(item, currency));
    const totalCents = lineItems.reduce((sum, item) => sum + (item.total as number), 0);
    const eventId = first(event, ["eventId", "event_id", "internalId", "rfxId", "id"], "");

    return {
      event_id: eventId,
      external_rfx_id: first(
        event,
        ["externalSystemCorrelationId", "externalRfxId", "rfxReference"],
        "",
      ),
      event_name: first(event, ["title", "name", "eventName", "rfxTitle"], ""),
      buyer_org: first(event, ["buyerOrg", "buyerOrganization", "owner"], ""),
      deadline: first(event, ["biddingEndDate", "deadline", "closeDate"], null),
      currency,
      line_items: lineItems,
      estimated_value: totalCents,
      raw_payload: payload,
    };
  }

  /**
   * Translate an SAP Ariba sourcing/RFx event into A2CN goods_procurement terms.
   */
  static sourcingEventToGoodsProcurementTerms(
    payload: Dict,
    defaultDeliveryDays = 14,
    defaultNetDays = 30,
  ): Dict {
    const event = ((payload.event ?? payload.rfxEvent) as Dict) ?? payload;
    const parsed = AribaEventParser.parseSourcingEvent(payload);
    const deliveryDays = intValue(
      first(event, ["deliveryDays", "delivery_days", "leadTimeDays"], defaultDeliveryDays),
      defaultDeliveryDays,
    );
    const netDays = intValue(
      first(event, ["paymentTermsNetDays", "netDays", "paymentTermDays"], defaultNetDays),
      defaultNetDays,
    );
    return {
      total_value: parsed.estimated_value,
      currency: parsed.currency,
      line_items: (parsed.line_items as Dict[]).map((item) =>
        Object.fromEntries(Object.entries(item).filter(([key]) => key !== "currency")),
      ),
      delivery_days: deliveryDays,
      payment_terms: { net_days: netDays },
      custom_terms: {
        ariba: {
          event_id: parsed.event_id,
          external_rfx_id: parsed.external_rfx_id,
          source: first(event, ["source"], "sap_ariba"),
        },
      },
    };
  }

  /**
   * Return both A2CN session params and initial goods_procurement terms.
   */
  static sourcingEventToSessionInputs(payload: Dict, maxRounds = 5, defaultDeliveryDays = 14): Dict {
    const parsed = AribaEventParser.parseSourcingEvent(payload);
    const terms = AribaEventParser.sourcingEventToGoodsProcurementTerms(
      payload,
      defaultDeliveryDays,
    );
    return {
      event_id: parsed.event_id,
      session_params: {
        deal_type: "goods_procurement",
        currency: parsed.currency,
        max_rounds: maxRounds,
        session_timeout_seconds: 3600,
        round_timeout_seconds: 900,
        ariba_event_id: parsed.event_id,
        ariba_external_rfx_id: parsed.external_rfx_id,
        buyer_org: parsed.buyer_org,
      },
      initial_terms: terms,
      raw_payload: payload,
    };
  }
}

/**
 * Translate agreed A2CN goods_procurement terms into an Ariba bid payload.
 */
export function a2cnTermsToAribaBid(
  agreedTerms: Dict,
  eventId: string,
  supplierId: string | null = null,
  status = "submitted",
): Dict {
  const responseItems: Dict[] = [];
  for (const item of (agreedTerms.line_items as Dict[]) ?? []) {
    const entry: Dict = {
      itemId: item.ariba_item_id ?? item.internal_part_number ?? "",
      lotId: item.ariba_lot_id ?? item.internal_part_number ?? "",
      description: item.description ?? "",
      quantity: item.quantity ?? 1,
      unitOfMeasure: item.unit_of_measure ?? "EA",
      unitPrice: ((item.unit_price as number) ?? 0) / 100.0,
      totalPrice: ((item.total as number) ?? 0) / 100.0,
      currency: agreedTerms.currency ?? "USD",
    };
    responseItems.push(
      Object.fromEntries(Object.entries(entry).filter(([, value]) => value !== "")),
    );
  }

  const netDays = ((agreedTerms.payment_terms as Dict) ?? {}).net_days ?? 30;
  const payload: Dict = {
    eventId,
    status,
    currency: agreedTerms.currency ?? "USD",
    totalAmount: ((agreedTerms.total_value as number) ?? 0) / 100.0,
    items: responseItems,
    deliveryDays: agreedTerms.delivery_days ?? 14,
    paymentTerms: `Net ${netDays}`,
  };
  if (supplierId !== null) {
    payload.supplierId = supplierId;
  }
  return payload;
}

/**
 * Build the Discovery RFx Publication TO External Marketplace Acknowledge shape.
 */
export function aribaAcknowledgementPayload(
  eventId: string,
  externalReference: string,
  status = "ACKNOWLEDGED",
  message = "Accepted for A2CN negotiation.",
): Dict {
  return {
    eventId,
    externalReference,
    status,
    message,
  };
}

/**
 * Build SAP Ariba Open API auth headers.
 */
export function aribaAuthHeaders(accessToken: string, apiKey: string | null = null): Dict {
  const key = apiKey || process.env.ARIBA_API_KEY;
  if (!key) {
    throw new Error("ARIBA_API_KEY environment variable is required.");
  }
  return {
    Authorization: `Bearer ${accessToken}`,
    apiKey: key,
    Accept: "application/json",
    "Content-Type": "application/json",
  };
}

/**
 * Fetch an OAuth client-credentials token for SAP Ariba Open APIs.
 */
export async function fetchAribaAccessToken(
  tokenUrl: string | null = null,
  fetchFn: typeof fetch = fetch,
): Promise<string> {
  const clientId = process.env.ARIBA_CLIENT_ID;
  const clientSecret = process.env.ARIBA_CLIENT_SECRET;
  const resolvedTokenUrl = tokenUrl || process.env.ARIBA_TOKEN_URL;
  if (!clientId || !clientSecret || !resolvedTokenUrl) {
    throw new Error("ARIBA_CLIENT_ID, ARIBA_CLIENT_SECRET, and ARIBA_TOKEN_URL are required.");
  }
  const response = await fetchFn(resolvedTokenUrl, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "client_credentials" }),
    headers: {
      Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`, "utf-8").toString("base64")}`,
    },
  });
  if (response.status >= 400) {
    throw new Error(`Ariba token request failed: HTTP ${response.status}`);
  }
  const data = (await response.json()) as Dict;
  return data.access_token as string;
}
