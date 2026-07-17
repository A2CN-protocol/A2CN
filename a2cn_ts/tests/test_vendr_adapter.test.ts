/** Tests for Vendr MCP/webhook platform adapter. */

import { createHmac } from "node:crypto";
import { describe, expect, test } from "vitest";

import { validateDealTypeTerms } from "../src/a2cn/messages.js";
import type { Dict } from "../src/a2cn/messages.js";
import {
  VendrWebhookParser,
  a2cnTermsToVendrSummary,
  vendrPricingToA2cnTerms,
  webhookBodyForSignature,
} from "../src/adapters/vendr_adapter.js";

const SAMPLE_VENDR_PRICING: Dict = {
  vendor: "Acme Analytics",
  product: "Enterprise Analytics Suite",
  list_price: 1200.0,
  seat_count: 100,
  currency: "USD",
  term_months: 12,
  observed_discount_band: { min: 0.15, max: 0.25 },
  benchmark_range: { low: 85000.0, median: 95000.0, high: 110000.0 },
  source: "vendr_mcp",
};

const SAMPLE_VENDR_WEBHOOK: Dict = {
  event_id: "vendr-evt-001",
  event_type: "renewal.workflow.updated",
  workflow_id: "vendr-wf-001",
  buyer_org: "TechCorp",
  renewal_date: "2026-07-01",
  vendor: "Acme Analytics",
  product: "Enterprise Analytics Suite",
  list_price: 1200.0,
  seat_count: 100,
  currency: "USD",
  term_months: 12,
  observed_discount_band: { min: 0.15, max: 0.25 },
};

describe("VendrPricingToA2CNTerms", () => {
  test("pricing maps to saas renewal terms", () => {
    const terms = vendrPricingToA2cnTerms(SAMPLE_VENDR_PRICING);

    expect(terms.deal_type).toBe("saas_renewal");
    expect(terms.currency).toBe("USD");
    expect(terms.seat_count).toBe(100);
    expect(terms.subscription_tier).toBe("Enterprise Analytics Suite");
    expect(validateDealTypeTerms("saas_renewal", terms)).toEqual([]);
  });

  test("discount midpoint applied and converted to cents", () => {
    const terms = vendrPricingToA2cnTerms(SAMPLE_VENDR_PRICING);

    // $1200 list * 20% midpoint discount = $960 per seat.
    expect((terms.line_items as Dict[])[0].unit_price).toBe(96_000);
    expect(terms.total_value).toBe(9_600_000);
  });

  test("benchmark range converted to cents", () => {
    const terms = vendrPricingToA2cnTerms(SAMPLE_VENDR_PRICING);

    const benchmark = ((terms.custom_terms as Dict).vendr as Dict).benchmark_range as Dict;
    expect(benchmark.low).toBe(8_500_000);
    expect(benchmark.median).toBe(9_500_000);
    expect(benchmark.high).toBe(11_000_000);
    expect(((terms.custom_terms as Dict).vendr as Dict).source).toBe("vendr_mcp");
  });

  test("percentage discount values are supported", () => {
    const pricing = {
      product: "Security Platform",
      list_price: 1000.0,
      seat_count: 10,
      observed_discount_band: { min: 10, max: 20 },
    };

    const terms = vendrPricingToA2cnTerms(pricing);

    expect((terms.line_items as Dict[])[0].unit_price).toBe(85_000);
    expect(terms.total_value).toBe(850_000);
  });

  test("flat observed discount field is supported", () => {
    const terms = vendrPricingToA2cnTerms({
      product: "AI Contract Review",
      list_price: 2000.0,
      seat_count: 5,
      observed_discount: 0.25,
    });

    expect((terms.line_items as Dict[])[0].unit_price).toBe(150_000);
    expect(terms.total_value).toBe(750_000);
    expect(((terms.custom_terms as Dict).vendr as Dict).observed_discount).toBe(0.25);
  });

  test("missing seat count defaults to one valid seat", () => {
    const terms = vendrPricingToA2cnTerms({ list_price: 500.0 });

    expect(terms.seat_count).toBe(1);
    expect(validateDealTypeTerms("saas_renewal", terms)).toEqual([]);
  });
});

describe("VendrWebhookParser", () => {
  test("webhook parse returns session params and terms", () => {
    const parsed = VendrWebhookParser.parseRenewalWebhook(SAMPLE_VENDR_WEBHOOK);

    expect(parsed.event_id).toBe("vendr-evt-001");
    expect(parsed.workflow_id).toBe("vendr-wf-001");
    expect((parsed.session_params as Dict).deal_type).toBe("saas_renewal");
    expect((parsed.session_params as Dict).vendr_event_id).toBe("vendr-evt-001");
    expect((parsed.session_params as Dict).vendr_workflow_id).toBe("vendr-wf-001");
    expect((parsed.initial_terms as Dict).total_value).toBe(9_600_000);
  });

  test("webhook nested pricing shape supported", () => {
    const payload = {
      event_id: "vendr-evt-002",
      workflowId: "vendr-wf-002",
      buyerOrg: "MegaBuyer",
      renewalDate: "2026-09-01",
      pricing: SAMPLE_VENDR_PRICING,
    };

    const parsed = VendrWebhookParser.parseRenewalWebhook(payload, 3);

    expect((parsed.session_params as Dict).max_rounds).toBe(3);
    expect((parsed.session_params as Dict).buyer_org).toBe("MegaBuyer");
    expect((parsed.session_params as Dict).renewal_date).toBe("2026-09-01");
    expect((parsed.initial_terms as Dict).seat_count).toBe(100);
  });

  test("webhook signature accepts prefixed sha256 digest", () => {
    const body = webhookBodyForSignature(SAMPLE_VENDR_WEBHOOK);
    const secret = "vendr-secret";
    const digest = createHmac("sha256", secret).update(body).digest("hex");

    expect(VendrWebhookParser.verifyWebhookSignature(body, `sha256=${digest}`, secret)).toBe(true);
  });

  test("webhook signature accepts v1 prefixed digest", () => {
    const body = webhookBodyForSignature(SAMPLE_VENDR_WEBHOOK);
    const secret = "vendr-secret";
    const digest = createHmac("sha256", secret).update(body).digest("hex");

    expect(VendrWebhookParser.verifyWebhookSignature(body, `v1=${digest}`, secret)).toBe(true);
  });

  test("webhook signature rejects wrong digest", () => {
    const body = webhookBodyForSignature(SAMPLE_VENDR_WEBHOOK);

    expect(
      VendrWebhookParser.verifyWebhookSignature(body, "sha256=not-the-real-digest", "vendr-secret"),
    ).toBe(false);
  });
});

describe("VendrRoundTripSummary", () => {
  test("terms to vendr summary converts cents to dollars", () => {
    const terms = vendrPricingToA2cnTerms(SAMPLE_VENDR_PRICING);
    const summary = a2cnTermsToVendrSummary(
      terms,
      "sess-vendr-001",
      "deadbeef".repeat(8),
      "vendr-wf-001",
    );

    expect(summary.source).toBe("a2cn");
    expect(summary.a2cn_session_id).toBe("sess-vendr-001");
    expect(summary.workflow_id).toBe("vendr-wf-001");
    expect(summary.total_value).toBe(96_000.0);
    expect(summary.unit_price).toBe(960.0);
    expect(summary.payment_terms).toBe("Net 30");
  });

  test("summary preserves vendr vendor and product", () => {
    const terms = vendrPricingToA2cnTerms(SAMPLE_VENDR_PRICING);
    const summary = a2cnTermsToVendrSummary(terms, "sess-vendr-002", "cafebabe".repeat(8));

    expect(summary.vendor).toBe("Acme Analytics");
    expect(summary.product).toBe("Enterprise Analytics Suite");
    expect(summary.status).toBe("negotiated");
  });
});
