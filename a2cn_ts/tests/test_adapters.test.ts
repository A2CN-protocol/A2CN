/** Tests for platform integration adapters (v0.2.0). */

import { createHmac } from "node:crypto";
import { describe, expect, test } from "vitest";

import { FairmakitEventParser } from "../src/adapters/fairmarkit_adapter.js";
import { KeelvarEventParser } from "../src/adapters/keelvar_adapter.js";
import { RevenueCloudAdapter } from "../src/adapters/revenue_cloud_adapter.js";
import type { Dict } from "../src/a2cn/messages.js";

const SAMPLE_BID_CREATED: Dict = {
  request_id: "req-abc-123",
  tenant_id: "acme-corp",
  status: "submitted",
  items: [
    { description: "Hydraulic fluid 200L drums", quantity: 50, uom: "EA", unit_price: 360.0 },
    { description: "Sealing compound", quantity: 10, uom: "KG", unit_price: 45.0 },
  ],
  deadline: "2026-04-10T17:00:00Z",
};

const SAMPLE_PRICING_RESPONSE: Dict = {
  totalAmount: 95000.0,
  currency: "USD",
  lineItems: [
    {
      productId: "01tXXX",
      productName: "Analytics Platform",
      quantity: 100,
      unitPrice: 950.0,
      totalPrice: 95000.0,
      startDate: "2026-07-01",
      endDate: "2027-06-30",
    },
  ],
};

describe("FairmakitAdapter", () => {
  test("parse bid created summary", () => {
    const result = FairmakitEventParser.parseBidCreatedWebhook(SAMPLE_BID_CREATED);
    expect(result.item_count).toBe(2);
    expect(result.fairmarkit_request_id).toBe("req-abc-123");
    // 50 * $360 = $18,000 = 1,800,000 cents; 10 * $45 = $450 = 45,000 cents
    expect(result.estimated_value).toBe(50 * 36000 + 10 * 4500);
  });

  test("parse bid created summary currency", () => {
    const result = FairmakitEventParser.parseBidCreatedWebhook(SAMPLE_BID_CREATED);
    expect(result.currency).toBe("USD");
  });

  test("parse bid created summary deadline", () => {
    const result = FairmakitEventParser.parseBidCreatedWebhook(SAMPLE_BID_CREATED);
    expect(result.deadline).toBe("2026-04-10T17:00:00Z");
  });

  test("parse empty items", () => {
    const result = FairmakitEventParser.parseBidCreatedWebhook({
      request_id: "r1",
      items: [],
      deadline: "2026-04-10T17:00:00Z",
    });
    expect(result.item_count).toBe(0);
    expect(result.estimated_value).toBe(0);
  });

  test("bid created to goods procurement terms", () => {
    const terms = FairmakitEventParser.bidCreatedToGoodsProcurementTerms(SAMPLE_BID_CREATED);
    expect(terms.currency).toBe("USD");
    expect((terms.line_items as Dict[]).length).toBe(2);
    expect((terms.line_items as Dict[])[0].unit_of_measure).toBe("EA");
    expect((terms.line_items as Dict[])[1].unit_of_measure).toBe("KG");
    expect("delivery_days" in terms).toBe(true);
  });

  test("bid created line item prices in cents", () => {
    const terms = FairmakitEventParser.bidCreatedToGoodsProcurementTerms(SAMPLE_BID_CREATED);
    // $360.0 → 36000 cents
    expect((terms.line_items as Dict[])[0].unit_price).toBe(36000);
  });

  test("bid created total value in cents", () => {
    const terms = FairmakitEventParser.bidCreatedToGoodsProcurementTerms(SAMPLE_BID_CREATED);
    // 50 * 36000 + 10 * 4500
    expect(terms.total_value).toBe(50 * 36000 + 10 * 4500);
  });

  test("terms to fairmarkit response", () => {
    const terms = FairmakitEventParser.bidCreatedToGoodsProcurementTerms(SAMPLE_BID_CREATED);
    const response = FairmakitEventParser.termsToFairmarkitResponse(
      terms,
      "sess-001",
      "req-abc-123",
    );
    expect(response.request_id).toBe("req-abc-123");
    expect(response.a2cn_session_id).toBe("sess-001");
    expect(response.currency).toBe("USD");
    expect((response.items as Dict[]).length).toBe(2);
  });

  test("fairmarkit response prices in dollars", () => {
    const terms = FairmakitEventParser.bidCreatedToGoodsProcurementTerms(SAMPLE_BID_CREATED);
    const response = FairmakitEventParser.termsToFairmarkitResponse(
      terms,
      "sess-001",
      "req-abc-123",
    );
    // 36000 cents → $360.0
    expect((response.items as Dict[])[0].unit_price).toBe(360.0);
  });

  test("fairmarkit response uom passthrough", () => {
    const terms = FairmakitEventParser.bidCreatedToGoodsProcurementTerms(SAMPLE_BID_CREATED);
    const response = FairmakitEventParser.termsToFairmarkitResponse(terms, "sess-001", "r1");
    expect((response.items as Dict[])[0].uom).toBe("EA");
    expect((response.items as Dict[])[1].uom).toBe("KG");
  });
});

describe("RevenueCloudAdapter", () => {
  test("pricing response to saas renewal terms", () => {
    const terms = RevenueCloudAdapter.pricingResponseToA2cnTerms(
      SAMPLE_PRICING_RESPONSE,
      "saas_renewal",
    );
    expect(terms.total_value).toBe(9500000); // $95,000 in cents
    expect(terms.currency).toBe("USD");
    expect(terms.seat_count).toBe(100);
    expect((terms.contract_duration as Dict).start_date).toBe("2026-07-01");
    expect((terms.contract_duration as Dict).end_date).toBe("2027-06-30");
  });

  test("pricing response line items", () => {
    const terms = RevenueCloudAdapter.pricingResponseToA2cnTerms(SAMPLE_PRICING_RESPONSE);
    expect((terms.line_items as Dict[]).length).toBe(1);
    expect((terms.line_items as Dict[])[0].description).toBe("Analytics Platform");
    expect((terms.line_items as Dict[])[0].unit_price).toBe(95000); // $950 in cents
  });

  test("pricing response no seat count for other deal type", () => {
    const terms = RevenueCloudAdapter.pricingResponseToA2cnTerms(
      SAMPLE_PRICING_RESPONSE,
      "goods_procurement",
    );
    expect("seat_count" in terms).toBe(false);
  });

  test("a2cn terms to order payload", () => {
    const terms = RevenueCloudAdapter.pricingResponseToA2cnTerms(SAMPLE_PRICING_RESPONSE);
    const order = RevenueCloudAdapter.a2cnTermsToOrderPayload(terms, "001XXX", "01sXXX");
    expect(order.transactionType).toBe("Order");
    expect(order.accountId).toBe("001XXX");
    expect((order.lineItems as Dict[]).length).toBe(1);
    expect((order.lineItems as Dict[])[0].unitPrice).toBe(950.0);
  });

  test("a2cn terms to quote payload type", () => {
    const terms = RevenueCloudAdapter.pricingResponseToA2cnTerms(SAMPLE_PRICING_RESPONSE);
    const quote = RevenueCloudAdapter.a2cnTermsToQuotePayload(terms, "001XXX", "01sXXX", "Quote");
    expect(quote.transactionType).toBe("Quote");
  });

  test("a2cn terms to quote includes dates", () => {
    const terms = RevenueCloudAdapter.pricingResponseToA2cnTerms(SAMPLE_PRICING_RESPONSE);
    const payload = RevenueCloudAdapter.a2cnTermsToQuotePayload(terms, "001XXX", "01sXXX");
    expect(payload.startDate).toBe("2026-07-01");
    expect(payload.endDate).toBe("2027-06-30");
  });

  test("pricing response uses total amount fallback", () => {
    // When lineItems have 0 prices, fall back to totalAmount
    const response = {
      totalAmount: 5000.0,
      currency: "USD",
      lineItems: [{ productName: "X", quantity: 1, unitPrice: 0.0, totalPrice: 0.0 }],
    };
    const terms = RevenueCloudAdapter.pricingResponseToA2cnTerms(response);
    expect(terms.total_value).toBe(500000); // $5000 in cents
  });
});

// ---------------------------------------------------------------------------
// Keelvar adapter tests
// ---------------------------------------------------------------------------

const SAMPLE_SOURCING_EVENT: Dict = {
  event_id: "evt-keelvar-001",
  event_name: "Q3 2026 Industrial Supplies RFQ",
  buyer_org: "AcmeBuyer Corp",
  deadline: "2026-05-01T17:00:00Z",
  currency: "EUR",
  line_items: [
    {
      description: "Hydraulic fluid 200L drums",
      quantity: 50,
      unit_of_measure: "EA",
      unit_price: 360.0,
      lot_id: "LOT-HF-001",
    },
    {
      description: "Sealing compound 5kg tubs",
      quantity: 20,
      unit_of_measure: "KG",
      unit_price: 85.0,
      lot_id: "LOT-SC-002",
    },
    {
      description: "Safety gloves (box of 100)",
      quantity: 10,
      unit_of_measure: "BX",
      unit_price: 45.0,
      // no lot_id — optional field
    },
  ],
};

const SAMPLE_SOURCING_EVENT_NO_PRICE: Dict = {
  event_id: "evt-keelvar-002",
  event_name: "Open Bid — Supplier Sets Price",
  buyer_org: "GlobalBuyer Ltd",
  deadline: null,
  currency: "USD",
  line_items: [
    {
      description: "Custom machined bracket",
      quantity: 100,
      unit_of_measure: "EA",
      // unit_price intentionally absent — buyer hasn't set benchmark
      lot_id: "LOT-MB-007",
    },
  ],
};

describe("KeelvarAdapter", () => {
  test("parse sourcing event webhook basic", () => {
    const result = KeelvarEventParser.parseSourcingEventWebhook(SAMPLE_SOURCING_EVENT);
    expect(result.event_id).toBe("evt-keelvar-001");
    expect(result.event_name).toBe("Q3 2026 Industrial Supplies RFQ");
    expect(result.buyer_org).toBe("AcmeBuyer Corp");
    expect(result.deadline).toBe("2026-05-01T17:00:00Z");
    expect(result.currency).toBe("EUR");
    expect((result.line_items as Dict[]).length).toBe(3);
    expect((result.line_items as Dict[])[0].description).toBe("Hydraulic fluid 200L drums");
    expect((result.line_items as Dict[])[0].quantity).toBe(50);
    expect((result.line_items as Dict[])[0].lot_id).toBe("LOT-HF-001");
    expect(result.raw_payload).toBe(SAMPLE_SOURCING_EVENT);
  });

  test("parse sourcing event webhook price in cents", () => {
    const result = KeelvarEventParser.parseSourcingEventWebhook(SAMPLE_SOURCING_EVENT);
    // $360.0 → 36000 cents
    expect((result.line_items as Dict[])[0].unit_price_cents).toBe(36000);
    expect((result.line_items as Dict[])[1].unit_price_cents).toBe(8500);
  });

  test("parse sourcing event webhook missing price", () => {
    const result = KeelvarEventParser.parseSourcingEventWebhook(SAMPLE_SOURCING_EVENT_NO_PRICE);
    expect((result.line_items as Dict[])[0].unit_price_cents).toBeNull();
  });

  test("sourcing event to goods procurement terms total value", () => {
    // 50 * $360 = $18,000 = 1,800,000 cents
    // 20 * $85  =  $1,700 =   170,000 cents
    // 10 * $45  =    $450 =    45,000 cents
    // total = 2,015,000 cents
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_SOURCING_EVENT);
    expect(terms.total_value).toBe(50 * 36_000 + 20 * 8_500 + 10 * 4_500);
  });

  test("sourcing event to goods procurement terms currency", () => {
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_SOURCING_EVENT);
    expect(terms.currency).toBe("EUR");
  });

  test("sourcing event to goods procurement terms default delivery", () => {
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_SOURCING_EVENT);
    expect(terms.delivery_days).toBe(14);
    expect(terms.payment_terms).toEqual({ net_days: 30 });
  });

  test("sourcing event to goods procurement terms custom delivery", () => {
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(
      SAMPLE_SOURCING_EVENT,
      21,
    );
    expect(terms.delivery_days).toBe(21);
  });

  test("sourcing event to goods procurement terms zero price", () => {
    // When unit_price is absent total_value must be 0.
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(
      SAMPLE_SOURCING_EVENT_NO_PRICE,
    );
    expect(terms.total_value).toBe(0);
    expect((terms.line_items as Dict[])[0].unit_price).toBe(0);
  });

  test("sourcing event lot id to internal part number", () => {
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_SOURCING_EVENT);
    expect((terms.line_items as Dict[])[0].internal_part_number).toBe("LOT-HF-001");
    expect((terms.line_items as Dict[])[1].internal_part_number).toBe("LOT-SC-002");
    // third item has no lot_id — field should be absent
    expect("internal_part_number" in (terms.line_items as Dict[])[2]).toBe(false);
  });

  test("terms to keelvar bid response structure", () => {
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_SOURCING_EVENT);
    const response = KeelvarEventParser.termsToKeelvarBidResponse(terms, "evt-keelvar-001");
    expect(response.event_id).toBe("evt-keelvar-001");
    expect(response.currency).toBe("EUR");
    expect(response.status).toBe("submitted");
    expect(response.delivery_days).toBe(14);
    expect((response.line_items as Dict[]).length).toBe(3);
  });

  test("terms to keelvar bid response price conversion", () => {
    // Prices must be in dollars (not cents) in the bid response.
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_SOURCING_EVENT);
    const response = KeelvarEventParser.termsToKeelvarBidResponse(terms, "evt-keelvar-001");
    // 36000 cents → $360.0
    expect((response.line_items as Dict[])[0].unit_price).toBe(360.0);
    // total_value in cents → dollars
    const expectedTotal = (50 * 36_000 + 20 * 8_500 + 10 * 4_500) / 100.0;
    expect(response.total_price).toBeCloseTo(expectedTotal);
  });

  test("terms to keelvar bid response supplier id", () => {
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_SOURCING_EVENT);
    const response = KeelvarEventParser.termsToKeelvarBidResponse(terms, "evt-001", "sup-xyz-999");
    expect(response.supplier_id).toBe("sup-xyz-999");
  });

  test("terms to keelvar bid response no supplier id", () => {
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_SOURCING_EVENT);
    const response = KeelvarEventParser.termsToKeelvarBidResponse(terms, "evt-001");
    expect("supplier_id" in response).toBe(false);
  });

  test("verify webhook signature valid", () => {
    const signingKey = "keelvar-secret-signing-key";
    const body = Buffer.from(JSON.stringify({ event_id: "evt-001" }), "utf-8");
    const expectedSig = createHmac("sha256", signingKey).update(body).digest("hex");
    expect(KeelvarEventParser.verifyWebhookSignature(body, expectedSig, signingKey)).toBe(true);
  });

  test("verify webhook signature invalid", () => {
    const body = Buffer.from('{"event_id": "evt-001"}', "utf-8");
    expect(KeelvarEventParser.verifyWebhookSignature(body, "wrong-signature", "correct-key")).toBe(
      false,
    );
  });

  test("verify webhook signature wrong key", () => {
    const body = Buffer.from('{"event_id": "evt-001"}', "utf-8");
    const realSig = createHmac("sha256", "real-key").update(body).digest("hex");
    expect(KeelvarEventParser.verifyWebhookSignature(body, realSig, "wrong-key")).toBe(false);
  });

  test("field mapping completeness", () => {
    // Round-trip: parse → terms → bid response preserves all line item data.
    const terms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_SOURCING_EVENT);
    const response = KeelvarEventParser.termsToKeelvarBidResponse(
      terms,
      SAMPLE_SOURCING_EVENT.event_id as string,
    );

    // Every source line item maps to a response line item
    expect((response.line_items as Dict[]).length).toBe(
      (SAMPLE_SOURCING_EVENT.line_items as Dict[]).length,
    );

    // Descriptions survive the round-trip unchanged
    const srcDescs = (SAMPLE_SOURCING_EVENT.line_items as Dict[]).map((li) => li.description);
    const outDescs = (response.line_items as Dict[]).map((li) => li.description);
    expect(srcDescs).toEqual(outDescs);

    // lot_id → internal_part_number → lot_id in bid response
    expect((response.line_items as Dict[])[0].lot_id).toBe("LOT-HF-001");
    expect((response.line_items as Dict[])[1].lot_id).toBe("LOT-SC-002");

    // unit_of_measure passes through
    expect((response.line_items as Dict[])[0].unit_of_measure).toBe("EA");
    expect((response.line_items as Dict[])[1].unit_of_measure).toBe("KG");
  });
});
