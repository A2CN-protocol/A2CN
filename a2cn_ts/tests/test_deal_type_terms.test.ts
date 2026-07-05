/** Tests for deal-type-specific terms validation (OQ-004, v0.2.0). */

import { describe, expect, test } from "vitest";

import { validateDealTypeTerms } from "../src/a2cn/messages.js";

describe("GoodsProcurementTerms", () => {
  test("valid terms returns empty errors", () => {
    const terms = {
      total_value: 1800000,
      currency: "USD",
      line_items: [
        {
          description: "Hydraulic fluid",
          quantity: 50,
          unit_price: 36000,
          total: 1800000,
          unit_of_measure: "EA",
        },
      ],
      delivery_days: 14,
      payment_terms: { net_days: 30 },
    };
    expect(validateDealTypeTerms("goods_procurement", terms)).toEqual([]);
  });

  test("missing delivery days returns error", () => {
    const terms = { total_value: 100, currency: "USD", line_items: [] };
    const errors = validateDealTypeTerms("goods_procurement", terms);
    expect(errors.some((e) => e.includes("delivery_days"))).toBe(true);
  });

  test("invalid delivery days type", () => {
    const terms = {
      total_value: 100,
      currency: "USD",
      line_items: [],
      delivery_days: "two weeks",
    };
    const errors = validateDealTypeTerms("goods_procurement", terms);
    expect(errors.length).toBeGreaterThan(0);
  });

  test("zero delivery days returns error", () => {
    const terms = { total_value: 100, currency: "USD", line_items: [], delivery_days: 0 };
    const errors = validateDealTypeTerms("goods_procurement", terms);
    expect(errors.length).toBeGreaterThan(0);
  });

  test("negative delivery days returns error", () => {
    const terms = { total_value: 100, currency: "USD", line_items: [], delivery_days: -5 };
    const errors = validateDealTypeTerms("goods_procurement", terms);
    expect(errors.length).toBeGreaterThan(0);
  });

  test("bool delivery days rejected", () => {
    // Booleans are not valid integer values — must be rejected
    const terms = { total_value: 100, currency: "USD", line_items: [], delivery_days: true };
    const errors = validateDealTypeTerms("goods_procurement", terms);
    expect(errors.length).toBeGreaterThan(0);
  });
});

describe("SaaSRenewalTerms", () => {
  test("valid terms returns empty errors", () => {
    const terms = {
      total_value: 9500000,
      currency: "USD",
      line_items: [
        { description: "Analytics Platform", quantity: 100, unit_price: 95000, total: 9500000 },
      ],
      payment_terms: { net_days: 30 },
      seat_count: 100,
      subscription_tier: "enterprise",
    };
    expect(validateDealTypeTerms("saas_renewal", terms)).toEqual([]);
  });

  test("missing seat count returns error", () => {
    const terms = { total_value: 100, currency: "USD", line_items: [] };
    const errors = validateDealTypeTerms("saas_renewal", terms);
    expect(errors.some((e) => e.includes("seat_count"))).toBe(true);
  });

  test("zero seat count returns error", () => {
    const terms = { total_value: 100, currency: "USD", line_items: [], seat_count: 0 };
    const errors = validateDealTypeTerms("saas_renewal", terms);
    expect(errors.length).toBeGreaterThan(0);
  });

  test("negative seat count returns error", () => {
    const terms = { total_value: 100, currency: "USD", line_items: [], seat_count: -1 };
    const errors = validateDealTypeTerms("saas_renewal", terms);
    expect(errors.length).toBeGreaterThan(0);
  });

  test("string seat count returns error", () => {
    const terms = { total_value: 100, currency: "USD", line_items: [], seat_count: "hundred" };
    const errors = validateDealTypeTerms("saas_renewal", terms);
    expect(errors.length).toBeGreaterThan(0);
  });

  test("bool seat count rejected", () => {
    const terms = { total_value: 100, currency: "USD", line_items: [], seat_count: true };
    const errors = validateDealTypeTerms("saas_renewal", terms);
    expect(errors.length).toBeGreaterThan(0);
  });

  test("optional fields do not cause errors", () => {
    const terms = {
      total_value: 100,
      currency: "USD",
      line_items: [],
      seat_count: 50,
      subscription_tier: "professional",
      support_tier: "premium",
      uptime_sla_percent: 9999,
      auto_renew_terms: { enabled: true, notice_days: 30 },
    };
    expect(validateDealTypeTerms("saas_renewal", terms)).toEqual([]);
  });
});

describe("UnknownDealType", () => {
  test("unknown deal type permissive", () => {
    const errors = validateDealTypeTerms("custom_deal_type_xyz", { total_value: 100 });
    expect(errors).toEqual([]);
  });

  test("empty terms unknown deal type permissive", () => {
    expect(validateDealTypeTerms("freight_rate", {})).toEqual([]);
  });
});
