/**
 * Conga CPQ/CLM -> A2CN translation layer.
 *
 * Translates Conga CPQ quote / cart payloads into A2CN terms, and translates
 * agreed A2CN terms back into Conga quote update payloads.
 *
 * Public documentation used for this adapter:
 *   Conga Documentation Portal:
 *     CPQ REST API Version 5 - Quote, Cart Items, Order, Assets
 *     CLM for REST API Developers - agreement records and lifecycle actions
 *   Conga Developer Portal:
 *     Advantage Platform REST APIs use predictable REST URLs and JSON payloads
 *
 * No core protocol changes are required. This module keeps platform mapping
 * offline-testable, while auth helpers document the Salesforce/Advantage OAuth
 * shape used by live Conga integrations.
 */

import type { Dict } from "../a2cn/messages.js";

const SUBSCRIPTION_KEYWORDS = ["license", "subscription", "seat", "renewal", "term"];

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

function lineItemsFromQuote(quote: Dict, fieldMap: Record<string, string>): Dict[] {
  let items = first(
    quote,
    [
      fieldMap.line_items_field,
      "lineItems",
      "LineItems",
      "quoteLineItems",
      "cartItems",
      "items",
      "records",
    ],
    [],
  );
  if (items !== null && typeof items === "object" && !Array.isArray(items)) {
    const obj = items as Dict;
    items =
      obj.lineItems ?? obj.quoteLineItems ?? obj.cartItems ?? obj.records ?? obj.items ?? [];
  }
  return [...(items as Dict[])];
}

function isSubscriptionItem(item: Dict, fieldMap: Record<string, string>): boolean {
  const productName = String(
    first(
      item,
      [
        fieldMap.product_name_field,
        "productName",
        "ProductName",
        "Name",
        "Description",
        "Apttus_Config2__Description__c",
      ],
      "",
    ),
  ).toLowerCase();
  const chargeType = String(
    first(item, ["chargeType", "ChargeType", "pricingType", "Apttus_Config2__ChargeType__c"], ""),
  ).toLowerCase();
  return SUBSCRIPTION_KEYWORDS.some(
    (keyword) => productName.includes(keyword) || chargeType.includes(keyword),
  );
}

/**
 * Translates Conga CPQ / CLM records into A2CN session terms and write-back
 * payloads.
 */
export class CongaAdapter {
  static DEFAULT_FIELD_MAP: Record<string, string> = {
    quote_id_field: "id",
    agreement_id_field: "agreementId",
    account_id_field: "accountId",
    opportunity_id_field: "opportunityId",
    total_value_field: "totalAmount",
    currency_field: "currency",
    line_items_field: "lineItems",
    line_item_id_field: "id",
    product_id_field: "productId",
    product_name_field: "productName",
    quantity_field: "quantity",
    unit_price_field: "unitPrice",
    total_price_field: "totalPrice",
    unit_of_measure_field: "unitOfMeasure",
    start_date_field: "startDate",
    end_date_field: "endDate",
    term_months_field: "termMonths",
  };

  /**
   * Return both A2CN session params and initial terms for a Conga quote.
   */
  static quoteToSessionInputs(
    quote: Dict,
    maxRounds = 5,
    fieldMap: Record<string, string> | null = null,
    defaultDeliveryDays = 14,
  ): Dict {
    const fm = { ...CongaAdapter.DEFAULT_FIELD_MAP, ...(fieldMap ?? {}) };
    const terms = congaQuoteToA2cnTerms(quote, fm, defaultDeliveryDays);
    const quoteId = first(
      quote,
      [fm.quote_id_field, "quoteId", "QuoteId", "Id", "Apttus_Proposal__Proposal__c"],
      "",
    );
    return {
      quote_id: quoteId !== "" ? String(quoteId) : "",
      session_params: {
        deal_type: "seat_count" in terms ? "saas_renewal" : "goods_procurement",
        currency: terms.currency ?? "USD",
        max_rounds: maxRounds,
        session_timeout_seconds: 3600,
        round_timeout_seconds: 900,
        conga_quote_id: quoteId !== "" ? String(quoteId) : "",
        conga_account_id: first(
          quote,
          [fm.account_id_field, "account", "AccountId", "Apttus_Proposal__Account__c"],
          "",
        ),
        conga_opportunity_id: first(
          quote,
          [fm.opportunity_id_field, "opportunity", "OpportunityId", "Apttus_Proposal__Opportunity__c"],
          "",
        ),
      },
      initial_terms: terms,
      raw_payload: quote,
    };
  }
}

/**
 * Translate a Conga CPQ quote/cart response into A2CN terms.
 *
 * The default field map accepts simple REST JSON names while the alias list
 * covers common Conga/Salesforce-style names for quote and line-item records.
 */
export function congaQuoteToA2cnTerms(
  quote: Dict,
  fieldMap: Record<string, string> | null = null,
  defaultDeliveryDays = 14,
  defaultNetDays = 30,
): Dict {
  const fm = { ...CongaAdapter.DEFAULT_FIELD_MAP, ...(fieldMap ?? {}) };
  const itemsRaw = lineItemsFromQuote(quote, fm);
  const lineItems: Dict[] = [];
  let totalCents = 0;

  for (const item of itemsRaw) {
    const quantity = intValue(
      first(item, [fm.quantity_field, "Quantity", "Apttus_Config2__Quantity__c"], 1),
      1,
    );
    const unitPriceCents = moneyToCents(
      first(
        item,
        [
          fm.unit_price_field,
          "UnitPrice",
          "netUnitPrice",
          "NetUnitPrice",
          "ListPrice",
          "Apttus_Config2__NetUnitPrice__c",
          "Apttus_Config2__NetPrice__c",
        ],
        0,
      ),
    );
    const totalRaw = first(
      item,
      [
        fm.total_price_field,
        "netAmount",
        "NetAmount",
        "TotalPrice",
        "lineTotal",
        "Apttus_Config2__NetAmount__c",
      ],
      null,
    );
    const lineTotal = totalRaw !== null ? moneyToCents(totalRaw) : quantity * unitPriceCents;
    totalCents += lineTotal;
    const lineItem: Dict = {
      description: first(
        item,
        [
          fm.product_name_field,
          "ProductName",
          "Name",
          "Description",
          "Apttus_Config2__Description__c",
        ],
        "",
      ),
      quantity,
      unit_price: unitPriceCents,
      total: lineTotal,
    };
    const uom = first(item, [fm.unit_of_measure_field, "Uom", "uom"], null);
    if (uom) {
      lineItem.unit_of_measure = String(uom);
    }
    const lineId = first(
      item,
      [fm.line_item_id_field, "lineItemId", "LineItemId", "Id", "Apttus_Config2__LineItemId__c"],
      "",
    );
    const productId = first(
      item,
      [fm.product_id_field, "ProductId", "product", "Apttus_Config2__ProductId__c"],
      "",
    );
    if (lineId) {
      lineItem.conga_line_item_id = String(lineId);
      lineItem.internal_part_number = String(lineId);
    }
    if (productId) {
      lineItem.conga_product_id = String(productId);
    }
    lineItems.push(lineItem);
  }

  const headerTotalCents = moneyToCents(
    first(
      quote,
      [
        fm.total_value_field,
        "grandTotal",
        "netAmount",
        "totalPrice",
        "TotalPrice",
        "NetAmount",
        "GrandTotal",
        "Apttus_Proposal__Net_Amount__c",
      ],
      0,
    ),
  );
  totalCents = totalCents || headerTotalCents;
  const currency = String(
    first(
      quote,
      [
        fm.currency_field,
        "currencyCode",
        "CurrencyCode",
        "currencyIsoCode",
        "CurrencyIsoCode",
        "Apttus_Proposal__CurrencyIsoCode__c",
      ],
      "USD",
    ),
  );

  const dealType = itemsRaw.some((item) => isSubscriptionItem(item, fm))
    ? "saas_renewal"
    : "goods_procurement";
  const terms: Dict = {
    total_value: totalCents,
    currency,
    line_items: lineItems,
    payment_terms: {
      net_days: intValue(
        first(quote, ["paymentTermsNetDays", "netDays", "paymentTermDays"], defaultNetDays),
        defaultNetDays,
      ),
    },
    custom_terms: {
      conga: {
        quote_id: String(first(quote, [fm.quote_id_field, "quoteId", "Id"], "")),
        agreement_id: String(first(quote, [fm.agreement_id_field, "AgreementId", "contractId"], "")),
        source: String(first(quote, ["source"], "conga_cpq")),
      },
    },
  };

  const startDate = first(quote, [fm.start_date_field, "StartDate", "effectiveDate"], null);
  const endDate = first(quote, [fm.end_date_field, "EndDate", "expirationDate"], null);
  if (startDate && endDate) {
    terms.contract_duration = {
      start_date: startDate,
      end_date: endDate,
    };
  }

  if (dealType === "saas_renewal") {
    terms.seat_count = intValue(
      first(
        itemsRaw.length > 0 ? itemsRaw[0] : {},
        [fm.quantity_field, "Quantity", "Apttus_Config2__Quantity__c"],
        1,
      ),
      1,
    );
    const firstItem = itemsRaw.length > 0 ? itemsRaw[0] : {};
    terms.subscription_tier = String(
      first(firstItem, [fm.product_name_field, "ProductName", "Name"], ""),
    );
    const termMonths = first(
      quote,
      [fm.term_months_field, "sellingTerm", "SellingTerm", "Apttus_QPConfig__ProposalTerm__c"],
      null,
    );
    if (termMonths !== null) {
      terms.term_months = intValue(termMonths);
    }
  } else {
    terms.delivery_days = intValue(
      first(quote, ["deliveryDays", "delivery_days", "leadTimeDays"], defaultDeliveryDays),
      defaultDeliveryDays,
    );
  }

  return terms;
}

/**
 * Translate agreed A2CN terms into a Conga quote update payload.
 */
export function a2cnTermsToCongaQuote(
  agreedTerms: Dict,
  quoteId: string,
  agreementId: string | null = null,
  status = "Accepted",
): Dict {
  const lineItems: Dict[] = [];
  for (const item of (agreedTerms.line_items as Dict[]) ?? []) {
    const entry: Dict = {
      id: item.conga_line_item_id ?? item.internal_part_number ?? "",
      productId: item.conga_product_id ?? "",
      description: item.description ?? "",
      quantity: item.quantity ?? 1,
      unitPrice: ((item.unit_price as number) ?? 0) / 100.0,
      totalPrice: ((item.total as number) ?? 0) / 100.0,
    };
    if (item.unit_of_measure) {
      entry.unitOfMeasure = item.unit_of_measure;
    }
    lineItems.push(Object.fromEntries(Object.entries(entry).filter(([, value]) => value !== "")));
  }

  const payload: Dict = {
    quoteId,
    status,
    currency: agreedTerms.currency ?? "USD",
    totalAmount: ((agreedTerms.total_value as number) ?? 0) / 100.0,
    lineItems,
    paymentTerms: `Net ${((agreedTerms.payment_terms as Dict) ?? {}).net_days ?? 30}`,
  };
  if (agreementId !== null) {
    payload.agreementId = agreementId;
  }
  if ("seat_count" in agreedTerms) {
    payload.seatCount = agreedTerms.seat_count;
  }
  if ("delivery_days" in agreedTerms) {
    payload.deliveryDays = agreedTerms.delivery_days;
  }
  const duration = (agreedTerms.contract_duration as Dict) ?? {};
  if (duration.start_date) {
    payload.startDate = duration.start_date;
  }
  if (duration.end_date) {
    payload.endDate = duration.end_date;
  }
  if (agreedTerms.term_months) {
    payload.termMonths = agreedTerms.term_months;
  }
  return payload;
}

/**
 * Build a CLM agreement metadata update payload linked to an A2CN record.
 */
export function congaAgreementUpdatePayload(
  agreementId: string,
  a2cnSessionId: string,
  recordHash: string,
  status = "Ready for Contracting",
): Dict {
  return {
    agreementId,
    status,
    externalReferences: {
      a2cn_session_id: a2cnSessionId,
      a2cn_record_hash: recordHash,
    },
  };
}

/**
 * Build Conga REST API auth headers for Salesforce or Advantage API calls.
 */
export function congaAuthHeaders(accessToken: string): Dict {
  return {
    Authorization: `Bearer ${accessToken}`,
    Accept: "application/json",
    "Content-Type": "application/json",
  };
}

/**
 * Fetch an OAuth client-credentials bearer token for Conga REST APIs.
 */
export async function fetchCongaAccessToken(
  tokenUrl: string | null = null,
  fetchFn: typeof fetch = fetch,
): Promise<string> {
  const clientId = process.env.CONGA_CLIENT_ID;
  const clientSecret = process.env.CONGA_CLIENT_SECRET;
  const resolvedTokenUrl = tokenUrl || process.env.CONGA_TOKEN_URL;
  const scope = process.env.CONGA_SCOPE;
  if (!clientId || !clientSecret || !resolvedTokenUrl) {
    throw new Error("CONGA_CLIENT_ID, CONGA_CLIENT_SECRET, and CONGA_TOKEN_URL are required.");
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
      Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`, "utf-8").toString("base64")}`,
    },
  });
  if (response.status >= 400) {
    throw new Error(`Conga token request failed: HTTP ${response.status}`);
  }
  return ((await response.json()) as Dict).access_token as string;
}
