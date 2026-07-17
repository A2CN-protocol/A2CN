/**
 * JAGGAER ASO -> A2CN translation layer.
 *
 * Translates JAGGAER Advanced Sourcing Optimizer (ASO) customer-host / sourcing
 * event payloads into A2CN goods_procurement terms, and translates agreed A2CN
 * terms into JAGGAER-shaped bid response payloads.
 *
 * Public documentation used for this adapter:
 *   ASO API documentation:
 *     Customer Host Entity Service - query ASO events for a customer host
 *     Event Entity Service - interact with a specific ASO event
 *     Async upload endpoints - entity imports for rate and bid
 *   Integration via JAGGAER Public APIs:
 *     REST/JSON integrations, request/response or event-driven push
 *
 * No core protocol changes are required. This module keeps platform mapping
 * offline-testable, while small auth/request helpers document the OAuth/API-key
 * shape needed when wiring it into a live JAGGAER environment.
 */

import type { Dict } from "../a2cn/messages.js";

function moneyToCents(value: unknown): number {
  if (value === null || value === undefined || value === "") {
    return 0;
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Dict;
    value = obj.amount ?? obj.value ?? 0;
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

function eventFromPayload(payload: Dict): Dict {
  return ((payload.event ??
    payload.asoEvent ??
    payload.sourcingEvent ??
    payload.apiEvent ??
    payload.data) as Dict) ?? payload;
}

function itemsFromPayload(payload: Dict): Dict[] {
  let items =
    payload.items ??
    payload.lineItems ??
    payload.line_items ??
    payload.eventItems ??
    payload.lots ??
    [];
  if (items !== null && typeof items === "object" && !Array.isArray(items)) {
    const obj = items as Dict;
    items = obj.items ?? obj.lineItems ?? obj.eventItems ?? obj.results ?? [];
  }
  return [...(items as Dict[])];
}

function normalizeItem(item: Dict, defaultCurrency: string): Dict {
  const itemId = first(
    item,
    ["itemId", "item_id", "lineItemId", "line_item_id", "bidItemId", "id"],
    "",
  );
  const lotId = first(item, ["lotId", "lot_id", "lotNumber", "lot"], "");
  const quantity = intValue(first(item, ["quantity", "qty", "amount"], 1), 1);
  const unitPriceRaw = first(
    item,
    ["unitPrice", "unit_price", "targetPrice", "target_price", "reservePrice", "price"],
    0,
  );
  const unitPriceCents = moneyToCents(unitPriceRaw);
  const totalRaw = first(item, ["totalPrice", "total_price", "extendedPrice"], null);
  const totalCents = totalRaw !== null ? moneyToCents(totalRaw) : quantity * unitPriceCents;

  const lineItem: Dict = {
    description: first(item, ["description", "name", "title", "itemName"], ""),
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
    lineItem.jaggaer_item_id = String(itemId);
  }
  if (lotId) {
    lineItem.jaggaer_lot_id = String(lotId);
  }
  lineItem.currency = item.currency ?? item.currencyCode ?? defaultCurrency;
  return lineItem;
}

/**
 * Translates JAGGAER ASO sourcing events into A2CN session inputs.
 */
export class JaggaerEventParser {
  /**
   * Parse a JAGGAER push event or polled ASO event into a clean summary.
   *
   * The parser accepts tolerant aliases from push-webhook payloads and ASO
   * CHES/EES event responses. Tenant-specific integrations should normalize
   * their exact JAGGAER schema before calling this helper.
   */
  static parseSourcingEvent(payload: Dict, mode = "push"): Dict {
    const event = eventFromPayload(payload);
    const currency = first(event, ["currency", "currencyCode"], "USD") as string;
    const lineItems = itemsFromPayload(event).map((item) => normalizeItem(item, currency));
    const totalCents = lineItems.reduce((sum, item) => sum + (item.total as number), 0);
    const eventId = first(
      event,
      ["eventId", "event_id", "apiEventId", "sourcingEventId", "rfqId", "id"],
      "",
    );

    return {
      event_id: eventId !== "" ? String(eventId) : "",
      customer_host_id: first(event, ["customerHostId", "customer_host_id", "chostId"], ""),
      event_name: first(event, ["name", "eventName", "title", "rfxTitle"], ""),
      buyer_org: first(event, ["buyerOrg", "buyerOrganization", "owner", "eventOwner"], ""),
      deadline: first(event, ["biddingClose", "deadline", "closeDate", "dueDate"], null),
      currency,
      line_items: lineItems,
      estimated_value: totalCents,
      mode,
      raw_payload: payload,
    };
  }

  /**
   * Translate a JAGGAER ASO event into A2CN goods_procurement terms.
   */
  static sourcingEventToGoodsProcurementTerms(
    payload: Dict,
    defaultDeliveryDays = 14,
    defaultNetDays = 30,
    mode = "push",
  ): Dict {
    const event = eventFromPayload(payload);
    const parsed = JaggaerEventParser.parseSourcingEvent(payload, mode);
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
        jaggaer: {
          event_id: parsed.event_id,
          customer_host_id: parsed.customer_host_id,
          source: first(event, ["source"], "jaggaer_aso"),
          mode,
        },
      },
    };
  }

  /**
   * Return both A2CN session params and initial goods_procurement terms.
   */
  static sourcingEventToSessionInputs(
    payload: Dict,
    maxRounds = 5,
    defaultDeliveryDays = 14,
    mode = "push",
  ): Dict {
    const parsed = JaggaerEventParser.parseSourcingEvent(payload, mode);
    const terms = JaggaerEventParser.sourcingEventToGoodsProcurementTerms(
      payload,
      defaultDeliveryDays,
      30,
      mode,
    );
    return {
      event_id: parsed.event_id,
      session_params: {
        deal_type: "goods_procurement",
        currency: parsed.currency,
        max_rounds: maxRounds,
        session_timeout_seconds: 3600,
        round_timeout_seconds: 900,
        jaggaer_event_id: parsed.event_id,
        jaggaer_customer_host_id: parsed.customer_host_id,
        buyer_org: parsed.buyer_org,
      },
      initial_terms: terms,
      raw_payload: payload,
    };
  }
}

/**
 * Translate agreed A2CN goods_procurement terms into a JAGGAER bid response.
 */
export function a2cnTermsToJaggaerResponse(
  agreedTerms: Dict,
  eventId: string,
  supplierId: string | null = null,
  status = "submitted",
): Dict {
  const responseItems: Dict[] = [];
  for (const item of (agreedTerms.line_items as Dict[]) ?? []) {
    const entry: Dict = {
      itemId: item.jaggaer_item_id ?? item.internal_part_number ?? "",
      lotId: item.jaggaer_lot_id ?? item.internal_part_number ?? "",
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
 * Build the documented ASO CHES request shape for polling customer-host events.
 */
export function jaggaerPollRequest(
  customerHostId: string,
  userId: string,
  baseUrl: string | null = null,
): Dict {
  const resolvedBaseUrl = (baseUrl || process.env.JAGGAER_CHES_BASE_URL || "").replace(/\/+$/, "");
  if (!resolvedBaseUrl) {
    throw new Error("JAGGAER_CHES_BASE_URL or base_url is required.");
  }
  return {
    method: "GET",
    url: `${resolvedBaseUrl}/chost/${customerHostId}/user/${userId}/apiEvents`,
    headers: {
      Accept: "application/vnd.sciquest.com.ches+json",
    },
  };
}

/**
 * Build JAGGAER ASO API auth headers.
 */
export function jaggaerAuthHeaders(accessToken: string, apiKey: string | null = null): Dict {
  const key = apiKey || process.env.JAGGAER_API_KEY;
  if (!key) {
    throw new Error("JAGGAER_API_KEY environment variable is required.");
  }
  return {
    Authorization: `Bearer ${accessToken}`,
    "X-API-Key": key,
    Accept: "application/json",
    "Content-Type": "application/json",
  };
}

/**
 * Fetch an OAuth client-credentials bearer access token for JAGGAER ASO APIs.
 */
export async function fetchJaggaerAccessToken(
  tokenUrl: string | null = null,
  fetchFn: typeof fetch = fetch,
): Promise<string> {
  const clientId = process.env.JAGGAER_CLIENT_ID;
  const clientSecret = process.env.JAGGAER_CLIENT_SECRET;
  const apiKey = process.env.JAGGAER_API_KEY;
  const resolvedTokenUrl = tokenUrl || process.env.JAGGAER_TOKEN_URL;
  const scope = process.env.JAGGAER_SCOPE;
  if (!clientId || !clientSecret || !apiKey || !resolvedTokenUrl) {
    throw new Error(
      "JAGGAER_CLIENT_ID, JAGGAER_CLIENT_SECRET, JAGGAER_API_KEY, " +
        "and JAGGAER_TOKEN_URL are required.",
    );
  }

  const data: Record<string, string> = { grant_type: "client_credentials" };
  if (scope) {
    data.scope = scope;
  }
  const response = await fetchFn(resolvedTokenUrl, {
    method: "POST",
    body: new URLSearchParams(data),
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "X-API-Key": apiKey,
      Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`, "utf-8").toString("base64")}`,
    },
  });
  if (response.status >= 400) {
    throw new Error(`JAGGAER token request failed: HTTP ${response.status}`);
  }
  return ((await response.json()) as Dict).access_token as string;
}
