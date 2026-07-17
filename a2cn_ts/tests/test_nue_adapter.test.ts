/** Tests for Nue.io Revenue Lifecycle platform adapter. */

import { afterEach, describe, expect, test, vi } from "vitest";

import { NueEventParser } from "../src/adapters/nue_adapter.js";
import type { Dict } from "../src/a2cn/messages.js";

// ---------------------------------------------------------------------------
// Sample data
// ---------------------------------------------------------------------------

const SAMPLE_NUE_PRICING: Dict = {
  productId: "prod-analytics-001",
  priceBookId: "pb-enterprise-2026",
  // FIELD NOTE: listPrice field name verified against Nue sandbox
  listPrice: 1000.0,
  currency: "USD",
  quantity: 50,
};

const SAMPLE_NUE_SUBSCRIPTION: Dict = {
  subscriptionId: "sub-001",
  customerId: "cust-techcorp",
  productId: "prod-analytics-001",
  // FIELD NOTE: productTier, quantity, totalValue, autoRenew, termMonths
  // should be verified against live Nue sandbox instance.
  productTier: "enterprise",
  quantity: 100,
  totalValue: 100000.0,
  currency: "USD",
  termMonths: 12,
  autoRenew: true,
};

const SAMPLE_A2CN_AGREED_TERMS: Dict = {
  deal_type: "saas_renewal",
  total_value: 10_500_000, // $105,000 in cents
  currency: "USD",
  seat_count: 100,
  term_months: 12,
  line_items: [
    {
      description: "Analytics Platform Enterprise",
      quantity: 100,
      unit_price: 105_000, // cents per seat per year
      total: 10_500_000,
    },
  ],
};

function makeJsonFetch(jsonData: unknown, statusCode = 200): typeof fetch {
  return (async () => new Response(JSON.stringify(jsonData), { status: statusCode })) as typeof fetch;
}

afterEach(() => {
  vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------
// TestNuePricingToMandateBounds
// ---------------------------------------------------------------------------

describe("NuePricingToMandateBounds", () => {
  test("floor is less than ceiling", () => {
    const bounds = NueEventParser.pricingToMandateBounds(SAMPLE_NUE_PRICING);
    expect(bounds.floor_value_cents as number).toBeLessThan(bounds.ceiling_value_cents as number);
  });

  test("ceiling equals list price in cents", () => {
    // 50 seats × $1000 = $50,000 = 5,000,000 cents
    const bounds = NueEventParser.pricingToMandateBounds(SAMPLE_NUE_PRICING);
    expect(bounds.ceiling_value_cents).toBe(5_000_000);
  });

  test("default floor discount ten percent", () => {
    const bounds = NueEventParser.pricingToMandateBounds(SAMPLE_NUE_PRICING);
    expect(bounds.floor_value_cents).toBe(Math.trunc(5_000_000 * 0.9));
  });

  test("custom floor discount pct", () => {
    const bounds = NueEventParser.pricingToMandateBounds(SAMPLE_NUE_PRICING, 0.2);
    expect(bounds.floor_value_cents).toBe(Math.trunc(5_000_000 * 0.8));
  });

  test("currency passthrough", () => {
    const bounds = NueEventParser.pricingToMandateBounds(SAMPLE_NUE_PRICING);
    expect(bounds.currency).toBe("USD");
  });

  test("single unit pricing", () => {
    const pricing = { listPrice: 2000.0, currency: "EUR" };
    const bounds = NueEventParser.pricingToMandateBounds(pricing, 0.15);
    expect(bounds.ceiling_value_cents).toBe(200_000);
    expect(bounds.floor_value_cents).toBe(Math.trunc(200_000 * 0.85));
  });

  test("custom field map list price field", () => {
    const pricing = { unitListPrice: 500.0, currency: "GBP", qty: 10 };
    const bounds = NueEventParser.pricingToMandateBounds(pricing, 0.1, 0.0, {
      list_price_field: "unitListPrice",
      quantity_field: "qty",
    });
    // 10 × $500 = $5000 = 500,000 cents
    expect(bounds.ceiling_value_cents).toBe(500_000);
    expect(bounds.currency).toBe("GBP");
  });

  test("custom field map currency field", () => {
    const pricing = { listPrice: 100.0, ccy: "JPY" };
    const bounds = NueEventParser.pricingToMandateBounds(pricing, 0.1, 0.0, {
      currency_field: "ccy",
    });
    expect(bounds.currency).toBe("JPY");
  });
});

// ---------------------------------------------------------------------------
// TestNueSubscriptionToRenewalTerms
// ---------------------------------------------------------------------------

describe("NueSubscriptionToRenewalTerms", () => {
  test("deal type is saas renewal", () => {
    const terms = NueEventParser.subscriptionToRenewalTerms(SAMPLE_NUE_SUBSCRIPTION);
    expect(terms.deal_type).toBe("saas_renewal");
  });

  test("renewal markup applied correctly", () => {
    // $100,000 * 100 cents * 1.05 = 10,500,000 cents
    const terms = NueEventParser.subscriptionToRenewalTerms(SAMPLE_NUE_SUBSCRIPTION, 0.05);
    expect(terms.total_value).toBe(Math.trunc(100_000.0 * 100 * 1.05));
  });

  test("seat count from subscription quantity", () => {
    const terms = NueEventParser.subscriptionToRenewalTerms(SAMPLE_NUE_SUBSCRIPTION);
    expect(terms.seat_count).toBe(100);
  });

  test("subscription tier extracted", () => {
    const terms = NueEventParser.subscriptionToRenewalTerms(SAMPLE_NUE_SUBSCRIPTION);
    expect(terms.subscription_tier).toBe("enterprise");
  });

  test("auto renew terms included", () => {
    const terms = NueEventParser.subscriptionToRenewalTerms(SAMPLE_NUE_SUBSCRIPTION);
    expect((terms.auto_renew_terms as Dict).auto_renew).toBe(true);
  });

  test("term months included", () => {
    const terms = NueEventParser.subscriptionToRenewalTerms(SAMPLE_NUE_SUBSCRIPTION);
    expect(terms.term_months).toBe(12);
  });

  test("zero markup preserves current value", () => {
    const terms = NueEventParser.subscriptionToRenewalTerms(SAMPLE_NUE_SUBSCRIPTION, 0.0);
    expect(terms.total_value).toBe(Math.trunc(100_000.0 * 100));
  });

  test("custom field map total value field", () => {
    const sub = {
      contractValue: 50000.0,
      seats: 50,
      tier: "standard",
      renew: false,
      months: 24,
      currency: "EUR",
    };
    const terms = NueEventParser.subscriptionToRenewalTerms(sub, 0.0, {
      total_value_field: "contractValue",
      quantity_field: "seats",
      tier_field: "tier",
      auto_renew_field: "renew",
      term_months_field: "months",
    });
    expect(terms.seat_count).toBe(50);
    expect(terms.subscription_tier).toBe("standard");
    expect(terms.term_months).toBe(24);
    expect(terms.total_value).toBe(Math.trunc(50_000.0 * 100));
  });
});

// ---------------------------------------------------------------------------
// TestNueOrderCreation
// ---------------------------------------------------------------------------

describe("NueOrderCreation", () => {
  test("external reference contains session id", async () => {
    const fetchFn = makeJsonFetch({ orderId: "nue-order-001", status: "created" });
    vi.stubEnv("NUE_API_KEY", "test-api-key");
    vi.stubEnv("NUE_BASE_URL", "https://api.nue.io");

    const result = await NueEventParser.a2cnTermsToNueOrder(
      SAMPLE_A2CN_AGREED_TERMS,
      "cust-techcorp",
      "pb-enterprise-2026",
      "prod-analytics-001",
      "sess-xyz-789",
      "abc123".repeat(10),
      null,
      fetchFn,
    );

    expect((result.order_payload_sent as Dict).externalReference).toContain("sess-xyz-789");
  });

  test("notes contain record hash", async () => {
    const recordHash = "feedcafe".repeat(8);
    const fetchFn = makeJsonFetch({ orderId: "nue-order-001", status: "created" });
    vi.stubEnv("NUE_API_KEY", "test-api-key");
    vi.stubEnv("NUE_BASE_URL", "https://api.nue.io");

    const result = await NueEventParser.a2cnTermsToNueOrder(
      SAMPLE_A2CN_AGREED_TERMS,
      "cust-001",
      "pb-001",
      "prod-001",
      "sess-001",
      recordHash,
      null,
      fetchFn,
    );

    expect((result.order_payload_sent as Dict).notes).toContain(recordHash);
  });

  test("start date defaults to today", async () => {
    const today = new Date().toISOString().slice(0, 10);
    const fetchFn = makeJsonFetch({ orderId: "nue-order-001", status: "created" });
    vi.stubEnv("NUE_API_KEY", "test-api-key");
    vi.stubEnv("NUE_BASE_URL", "https://api.nue.io");

    const result = await NueEventParser.a2cnTermsToNueOrder(
      SAMPLE_A2CN_AGREED_TERMS,
      "cust-001",
      "pb-001",
      "prod-001",
      "sess-001",
      "hash-001",
      null,
      fetchFn,
    );

    expect((result.order_payload_sent as Dict).startDate).toBe(today);
  });

  test("explicit start date honoured", async () => {
    const fetchFn = makeJsonFetch({ orderId: "nue-order-001", status: "created" });
    vi.stubEnv("NUE_API_KEY", "test-api-key");
    vi.stubEnv("NUE_BASE_URL", "https://api.nue.io");

    const result = await NueEventParser.a2cnTermsToNueOrder(
      SAMPLE_A2CN_AGREED_TERMS,
      "cust-001",
      "pb-001",
      "prod-001",
      "sess-001",
      "hash-001",
      "2026-07-01",
      fetchFn,
    );

    expect((result.order_payload_sent as Dict).startDate).toBe("2026-07-01");
  });

  test("line item prices converted to dollars", async () => {
    const fetchFn = makeJsonFetch({ orderId: "nue-order-001", status: "created" });
    vi.stubEnv("NUE_API_KEY", "test-api-key");
    vi.stubEnv("NUE_BASE_URL", "https://api.nue.io");

    const result = await NueEventParser.a2cnTermsToNueOrder(
      SAMPLE_A2CN_AGREED_TERMS,
      "cust-001",
      "pb-001",
      "prod-001",
      "sess-001",
      "hash-001",
      null,
      fetchFn,
    );

    // 105_000 cents → $1050.00
    expect(((result.order_payload_sent as Dict).lines as Dict[])[0].unitPrice).toBeCloseTo(1050.0);
  });

  test("fallback unit price is per seat not total", async () => {
    // $105,000 total / 100 seats = $1050.00 per seat
    const termsNoLineItems = {
      deal_type: "saas_renewal",
      total_value: 10_500_000, // cents
      seat_count: 100,
      term_months: 12,
      line_items: [],
    };
    const fetchFn = makeJsonFetch({ orderId: "nue-order-002", status: "created" });
    vi.stubEnv("NUE_API_KEY", "test-api-key");
    vi.stubEnv("NUE_BASE_URL", "https://api.nue.io");

    const result = await NueEventParser.a2cnTermsToNueOrder(
      termsNoLineItems,
      "cust-001",
      "pb-001",
      "prod-001",
      "sess-002",
      "hash-002",
      null,
      fetchFn,
    );

    const line = ((result.order_payload_sent as Dict).lines as Dict[])[0];
    expect(line.quantity).toBe(100);
    // $105,000 / 100 seats = $1050.00 per seat
    expect(line.unitPrice).toBeCloseTo(1050.0);
  });

  test("fallback single seat unit price equals total", async () => {
    const termsSingle = {
      total_value: 50_000, // $500 in cents
      seat_count: 1,
      term_months: 12,
      line_items: [],
    };
    const fetchFn = makeJsonFetch({ orderId: "nue-order-003", status: "created" });
    vi.stubEnv("NUE_API_KEY", "test-api-key");
    vi.stubEnv("NUE_BASE_URL", "https://api.nue.io");

    const result = await NueEventParser.a2cnTermsToNueOrder(
      termsSingle,
      "cust-001",
      "pb-001",
      "prod-001",
      "sess-003",
      "hash-003",
      null,
      fetchFn,
    );

    const line = ((result.order_payload_sent as Dict).lines as Dict[])[0];
    expect(line.quantity).toBe(1);
    expect(line.unitPrice).toBeCloseTo(500.0);
  });
});

// ---------------------------------------------------------------------------
// TestNueFetchCustomerSubscriptions
// ---------------------------------------------------------------------------

describe("NueFetchCustomerSubscriptions", () => {
  test("raises on missing api key", async () => {
    vi.stubEnv("NUE_API_KEY", "");
    vi.stubEnv("NUE_BASE_URL", "");
    await expect(NueEventParser.fetchCustomerSubscriptions("cust-001")).rejects.toThrow(
      /NUE_API_KEY/,
    );
  });

  test("returns list when api returns list", async () => {
    const subs = [{ subscriptionId: "sub-001" }, { subscriptionId: "sub-002" }];
    const fetchFn = makeJsonFetch(subs);
    vi.stubEnv("NUE_API_KEY", "test-key");
    vi.stubEnv("NUE_BASE_URL", "https://api.nue.io");

    const result = await NueEventParser.fetchCustomerSubscriptions("cust-001", fetchFn);

    expect(result.length).toBe(2);
    expect(result[0].subscriptionId).toBe("sub-001");
  });

  test("returns list when api wraps in dict", async () => {
    const fetchFn = makeJsonFetch({ subscriptions: [{ subscriptionId: "sub-003" }] });
    vi.stubEnv("NUE_API_KEY", "test-key");
    vi.stubEnv("NUE_BASE_URL", "https://api.nue.io");

    const result = await NueEventParser.fetchCustomerSubscriptions("cust-001", fetchFn);

    expect(result[0].subscriptionId).toBe("sub-003");
  });
});
