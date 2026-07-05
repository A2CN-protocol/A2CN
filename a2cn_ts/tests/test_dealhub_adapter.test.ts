/** Tests for DealHub CPQ platform adapter. */

import { afterEach, describe, expect, test, vi } from "vitest";

import { DealHubEventParser } from "../src/adapters/dealhub_adapter.js";
import type { Dict } from "../src/a2cn/messages.js";

// ---------------------------------------------------------------------------
// Sample payloads
// ---------------------------------------------------------------------------

const SAMPLE_QUOTE_READY_SAAS: Dict = {
  event_info: { webhook_id: "wh-001", event_id: "evt-001", api_version: "1.0" },
  dealhub_quote_id: "dh-q-001",
  dealhub_opportunity_id: "dh-opp-001",
  execution_date: "2026-04-28T10:00:00Z",
  executed_by: "rep@company.com",
  currency: "USD",
  // items enriched from quote API (PATH A)
  items: [
    { product_name: "Enterprise Subscription 500 seats", quantity: 500, unit_price: 200.0 },
  ],
};

const SAMPLE_QUOTE_READY_GOODS: Dict = {
  event_info: { webhook_id: "wh-002", event_id: "evt-002", api_version: "1.0" },
  dealhub_quote_id: "dh-q-002",
  dealhub_opportunity_id: "dh-opp-002",
  execution_date: "2026-04-28T11:00:00Z",
  executed_by: "rep@company.com",
  currency: "USD",
  items: [
    { product_name: "Industrial Hydraulic Pump", quantity: 10, unit_price: 1500.0 },
    { product_name: "O-Ring Seal Kit", quantity: 50, unit_price: 25.0 },
  ],
};

const SAMPLE_QUOTE_RESPONSE: Dict = {
  total_price: 100000.0,
  currency: "USD",
  line_items: [
    { product_name: "Analytics Platform License", quantity: 100, unit_price: 950.0 },
    { product_name: "Support Package", quantity: 1, unit_price: 5000.0 },
  ],
};

const SAMPLE_QUOTE_RESPONSE_GOODS: Dict = {
  total_price: 18000.0,
  currency: "EUR",
  line_items: [
    { product_name: "Hydraulic fluid 200L drums", quantity: 50, unit_price: 360.0 },
  ],
};

// ---------------------------------------------------------------------------
// HTTP mock helper
// ---------------------------------------------------------------------------

function makeJsonFetch(jsonData: Dict, statusCode = 200): typeof fetch {
  return (async () => new Response(JSON.stringify(jsonData), { status: statusCode })) as typeof fetch;
}

afterEach(() => {
  vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------
// TestDealHubWebhookToSessionParams
// ---------------------------------------------------------------------------

describe("DealHubWebhookToSessionParams", () => {
  test("subscription products yield saas renewal", () => {
    const params = DealHubEventParser.quoteReadyWebhookToSessionParams(SAMPLE_QUOTE_READY_SAAS);
    expect(params.deal_type).toBe("saas_renewal");
  });

  test("physical goods yield goods procurement", () => {
    const params = DealHubEventParser.quoteReadyWebhookToSessionParams(SAMPLE_QUOTE_READY_GOODS);
    expect(params.deal_type).toBe("goods_procurement");
  });

  test("session params include quote and opportunity ids", () => {
    const params = DealHubEventParser.quoteReadyWebhookToSessionParams(SAMPLE_QUOTE_READY_SAAS);
    expect(params.dealhub_quote_id).toBe("dh-q-001");
    expect(params.dealhub_opportunity_id).toBe("dh-opp-001");
  });

  test("session params currency passthrough", () => {
    const params = DealHubEventParser.quoteReadyWebhookToSessionParams(SAMPLE_QUOTE_READY_GOODS);
    expect(params.currency).toBe("USD");
  });

  test("no items defaults to goods procurement", () => {
    const payload = {
      dealhub_quote_id: "dh-q-003",
      dealhub_opportunity_id: "dh-opp-003",
    };
    const params = DealHubEventParser.quoteReadyWebhookToSessionParams(payload);
    expect(params.deal_type).toBe("goods_procurement");
  });

  test("max rounds default is five", () => {
    const params = DealHubEventParser.quoteReadyWebhookToSessionParams(SAMPLE_QUOTE_READY_SAAS);
    expect(params.max_rounds).toBe(5);
  });

  test("max rounds configurable", () => {
    const params = DealHubEventParser.quoteReadyWebhookToSessionParams(SAMPLE_QUOTE_READY_SAAS, 3);
    expect(params.max_rounds).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// TestDealHubQuoteToOfferTerms
// ---------------------------------------------------------------------------

describe("DealHubQuoteToOfferTerms", () => {
  test("default field map extracts total value in cents", () => {
    // 100 * $950 + 1 * $5000 = $100,000 = 10,000,000 cents
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(SAMPLE_QUOTE_RESPONSE);
    expect(terms.total_value).toBe(10_000_000);
  });

  test("default field map extracts currency", () => {
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(SAMPLE_QUOTE_RESPONSE);
    expect(terms.currency).toBe("USD");
  });

  test("saas renewal terms include seat count", () => {
    // "Analytics Platform License" contains "license" → saas_renewal → seat_count included
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(SAMPLE_QUOTE_RESPONSE);
    expect("seat_count" in terms).toBe(true);
    expect(terms.seat_count).toBe(100); // quantity from first line item
  });

  test("goods procurement terms include delivery days", () => {
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(SAMPLE_QUOTE_RESPONSE_GOODS);
    expect("delivery_days" in terms).toBe(true);
    expect(terms.delivery_days).toBe(14);
  });

  test("custom field map overrides product name field", () => {
    const quote = {
      grand_total: 5000.0,
      ccy: "GBP",
      items: [{ name: "Widget Pro", qty: 10, price: 500.0 }],
    };
    const customMap = {
      total_value_field: "grand_total",
      currency_field: "ccy",
      line_items_field: "items",
      product_name_field: "name",
      quantity_field: "qty",
      unit_price_field: "price",
    };
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(quote, customMap);
    expect(terms.currency).toBe("GBP");
    expect((terms.line_items as Dict[])[0].description).toBe("Widget Pro");
    expect((terms.line_items as Dict[])[0].quantity).toBe(10);
    // $500 → 50000 cents
    expect((terms.line_items as Dict[])[0].unit_price).toBe(50_000);
  });

  test("line items prices converted to cents", () => {
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(SAMPLE_QUOTE_RESPONSE_GOODS);
    // $360.0 → 36000 cents
    expect((terms.line_items as Dict[])[0].unit_price).toBe(36_000);
  });

  test("total fallback to header when line items empty", () => {
    const quote = { total_price: 7500.0, currency: "USD", line_items: [] };
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(quote);
    expect(terms.total_value).toBe(750_000); // $7500 in cents
  });

  test("unit of measure included when present", () => {
    const quote = {
      total_price: 5000.0,
      currency: "USD",
      line_items: [
        {
          product_name: "Industrial Hydraulic Pump",
          quantity: 10,
          unit_price: 500.0,
          unit_of_measure: "EA",
        },
      ],
    };
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(quote);
    expect((terms.line_items as Dict[])[0].unit_of_measure).toBe("EA");
  });

  test("unit of measure omitted when absent", () => {
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(SAMPLE_QUOTE_RESPONSE_GOODS);
    expect("unit_of_measure" in (terms.line_items as Dict[])[0]).toBe(false);
  });

  test("custom unit of measure field name", () => {
    const quote = {
      total_price: 1000.0,
      currency: "USD",
      line_items: [{ product_name: "Widget", quantity: 5, unit_price: 200.0, uom: "KG" }],
    };
    const terms = DealHubEventParser.quoteToA2cnOfferTerms(quote, {
      unit_of_measure_field: "uom",
    });
    expect((terms.line_items as Dict[])[0].unit_of_measure).toBe("KG");
  });
});

// ---------------------------------------------------------------------------
// TestDealHubMandateBounds
// ---------------------------------------------------------------------------

describe("DealHubMandateBounds", () => {
  test("floor is ceiling minus discount", async () => {
    const fetchFn = makeJsonFetch({ total_price: 100000.0, currency: "USD", line_items: [] });
    vi.stubEnv("DEALHUB_AUTH_TOKEN", "test-token");
    vi.stubEnv("DEALHUB_BASE_URL", "https://test.dealhub.io");

    const result = await DealHubEventParser.simulateQuoteForMandateBounds(
      "pb-001",
      { product_id: "prod-001", quantity: 1 },
      0.15,
      fetchFn,
    );

    const ceiling = result.ceiling_value_cents as number;
    const floor = result.floor_value_cents as number;
    expect(floor).toBe(Math.trunc(ceiling * 0.85));
  });

  test("floor discount pct applied correctly", async () => {
    const fetchFn = makeJsonFetch({ total_price: 10000.0, currency: "USD", line_items: [] });
    vi.stubEnv("DEALHUB_AUTH_TOKEN", "tok");
    vi.stubEnv("DEALHUB_BASE_URL", "https://test.dealhub.io");

    const result = await DealHubEventParser.simulateQuoteForMandateBounds("pb-001", {}, 0.2, fetchFn);

    // $10,000 → 1,000,000 cents ceiling; 80% of ceiling = 800,000 floor
    expect(result.ceiling_value_cents).toBe(1_000_000);
    expect(result.floor_value_cents).toBe(800_000);
  });

  test("simulate raises on empty playbook id", async () => {
    await expect(
      DealHubEventParser.simulateQuoteForMandateBounds("", {}),
    ).rejects.toThrow(/playbook_id is required/);
  });

  test("simulate raises on missing env vars", async () => {
    vi.stubEnv("DEALHUB_AUTH_TOKEN", "");
    vi.stubEnv("DEALHUB_BASE_URL", "");
    await expect(
      DealHubEventParser.simulateQuoteForMandateBounds("pb-001", {}),
    ).rejects.toThrow(/DEALHUB_AUTH_TOKEN/);
  });
});

// ---------------------------------------------------------------------------
// TestDealHubActionsApi
// ---------------------------------------------------------------------------

describe("DealHubActionsApi", () => {
  test("action payload includes session id", async () => {
    const fetchFn = makeJsonFetch({ status: "success" });
    vi.stubEnv("DEALHUB_AUTH_TOKEN", "test-token");
    vi.stubEnv("DEALHUB_BASE_URL", "https://test.dealhub.io");

    const result = await DealHubEventParser.agreedTermsToDealhubAction(
      "dh-q-001",
      "sess-abc-123",
      "deadbeef".repeat(8),
      fetchFn,
    );

    expect((result.action_payload_sent as Dict).note).toContain("sess-abc-123");
  });

  test("action payload includes record hash", async () => {
    const fetchFn = makeJsonFetch({ status: "success" });
    vi.stubEnv("DEALHUB_AUTH_TOKEN", "test-token");
    vi.stubEnv("DEALHUB_BASE_URL", "https://test.dealhub.io");

    const result = await DealHubEventParser.agreedTermsToDealhubAction(
      "dh-q-001",
      "sess-abc-123",
      "cafebabe".repeat(8),
      fetchFn,
    );

    expect((result.action_payload_sent as Dict).note).toContain("cafebabe".repeat(8));
  });

  test("action uses sign externally action", async () => {
    const fetchFn = makeJsonFetch({});
    vi.stubEnv("DEALHUB_AUTH_TOKEN", "tok");
    vi.stubEnv("DEALHUB_BASE_URL", "https://test.dealhub.io");

    const result = await DealHubEventParser.agreedTermsToDealhubAction(
      "dh-q-001",
      "sess-001",
      "hash-001",
      fetchFn,
    );

    expect((result.action_payload_sent as Dict).action).toBe("signExternally");
  });
});

// ---------------------------------------------------------------------------
// TestDealHubFetchQuoteDetails
// ---------------------------------------------------------------------------

describe("DealHubFetchQuoteDetails", () => {
  test("raises on missing env vars", async () => {
    vi.stubEnv("DEALHUB_AUTH_TOKEN", "");
    vi.stubEnv("DEALHUB_BASE_URL", "");
    await expect(DealHubEventParser.fetchQuoteDetails("dh-q-001")).rejects.toThrow(
      /DEALHUB_AUTH_TOKEN/,
    );
  });

  test("returns json on success", async () => {
    const fetchFn = makeJsonFetch({ dealhub_quote_id: "dh-q-001" }, 200);
    vi.stubEnv("DEALHUB_AUTH_TOKEN", "tok");
    vi.stubEnv("DEALHUB_BASE_URL", "https://test.dealhub.io");

    const result = await DealHubEventParser.fetchQuoteDetails("dh-q-001", fetchFn);

    expect(result.dealhub_quote_id).toBe("dh-q-001");
  });
});
