/** Tests for Conga CPQ/CLM platform adapter. */

import { afterEach, describe, expect, test, vi } from "vitest";

import { validateDealTypeTerms } from "../src/a2cn/messages.js";
import type { Dict } from "../src/a2cn/messages.js";
import {
  CongaAdapter,
  a2cnTermsToCongaQuote,
  congaAgreementUpdatePayload,
  congaAuthHeaders,
  congaQuoteToA2cnTerms,
  fetchCongaAccessToken,
} from "../src/adapters/conga_adapter.js";

const SAMPLE_CONGA_SAAS_QUOTE: Dict = {
  id: "conga-q-001",
  agreementId: "clm-agreement-001",
  accountId: "001xx000003DGbY",
  opportunityId: "006xx000004TqVQ",
  currency: "USD",
  startDate: "2026-07-01",
  endDate: "2027-06-30",
  termMonths: 12,
  paymentTermsNetDays: 45,
  lineItems: [
    {
      id: "qli-001",
      productId: "prod-001",
      productName: "Enterprise Subscription License",
      quantity: 100,
      unitPrice: 950.0,
      totalPrice: 95_000.0,
    },
    {
      id: "qli-002",
      productId: "prod-002",
      productName: "Premium Support",
      quantity: 1,
      unitPrice: 5_000.0,
      totalPrice: 5_000.0,
    },
  ],
};

const SAMPLE_CONGA_GOODS_QUOTE: Dict = {
  Id: "a1Qxx0000009abc",
  CurrencyIsoCode: "EUR",
  deliveryDays: 21,
  records: [
    {
      Id: "a2Lxx0000001",
      ProductId: "01txx0000001",
      Name: "Hydraulic fluid 200L drums",
      Quantity: 50,
      NetUnitPrice: 360.0,
      NetAmount: 18_000.0,
      Uom: "EA",
    },
  ],
};

interface CapturedRequest {
  url: string;
  params: URLSearchParams;
  headers: Record<string, string>;
}

function makeTokenFetch(jsonData: Dict): { fetchFn: typeof fetch; captured: CapturedRequest[] } {
  const captured: CapturedRequest[] = [];
  const fetchFn = (async (url: string | URL | Request, init?: RequestInit) => {
    captured.push({
      url: String(url),
      params: init?.body as URLSearchParams,
      headers: (init?.headers as Record<string, string>) ?? {},
    });
    return new Response(JSON.stringify(jsonData), { status: 200 });
  }) as typeof fetch;
  return { fetchFn, captured };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("CongaQuoteToTerms", () => {
  test("saas quote maps to saas renewal terms", () => {
    const terms = congaQuoteToA2cnTerms(SAMPLE_CONGA_SAAS_QUOTE);

    expect(terms.currency).toBe("USD");
    expect(terms.total_value).toBe(10_000_000);
    expect(terms.seat_count).toBe(100);
    expect(terms.subscription_tier).toBe("Enterprise Subscription License");
    expect(terms.term_months).toBe(12);
    expect("contract_term_months" in terms).toBe(false);
    expect((terms.payment_terms as Dict).net_days).toBe(45);
    expect(terms.contract_duration).toEqual({
      start_date: "2026-07-01",
      end_date: "2027-06-30",
    });
    expect(validateDealTypeTerms("saas_renewal", terms)).toEqual([]);
  });

  test("line item ids and product ids are preserved", () => {
    const terms = congaQuoteToA2cnTerms(SAMPLE_CONGA_SAAS_QUOTE);

    expect((terms.line_items as Dict[])[0].conga_line_item_id).toBe("qli-001");
    expect((terms.line_items as Dict[])[0].conga_product_id).toBe("prod-001");
    expect((terms.line_items as Dict[])[0].internal_part_number).toBe("qli-001");
    expect(((terms.custom_terms as Dict).conga as Dict).quote_id).toBe("conga-q-001");
    expect(((terms.custom_terms as Dict).conga as Dict).agreement_id).toBe("clm-agreement-001");
  });

  test("goods quote maps to goods procurement terms", () => {
    const terms = congaQuoteToA2cnTerms(SAMPLE_CONGA_GOODS_QUOTE);

    expect(terms.currency).toBe("EUR");
    expect(terms.delivery_days).toBe(21);
    expect((terms.line_items as Dict[])[0].description).toBe("Hydraulic fluid 200L drums");
    expect((terms.line_items as Dict[])[0].unit_of_measure).toBe("EA");
    expect((terms.line_items as Dict[])[0].unit_price).toBe(36_000);
    expect((terms.line_items as Dict[])[0].total).toBe(1_800_000);
    expect(validateDealTypeTerms("goods_procurement", terms)).toEqual([]);
  });

  test("header total used when line items have no prices", () => {
    const quote = {
      id: "conga-q-empty-price",
      totalAmount: 7_500.0,
      currency: "USD",
      lineItems: [{ productName: "Widget", quantity: 1, unitPrice: 0.0, totalPrice: 0.0 }],
    };

    const terms = congaQuoteToA2cnTerms(quote);

    expect(terms.total_value).toBe(750_000);
  });

  test("custom field map overrides tenant names", () => {
    const quote = {
      quote_total: 5_000.0,
      ccy: "GBP",
      rows: [{ label: "Widget Pro", qty: 10, price: 500.0, row_total: 5_000.0 }],
    };
    const fieldMap = {
      total_value_field: "quote_total",
      currency_field: "ccy",
      line_items_field: "rows",
      product_name_field: "label",
      quantity_field: "qty",
      unit_price_field: "price",
      total_price_field: "row_total",
    };

    const terms = congaQuoteToA2cnTerms(quote, fieldMap);

    expect(terms.currency).toBe("GBP");
    expect((terms.line_items as Dict[])[0].description).toBe("Widget Pro");
    expect((terms.line_items as Dict[])[0].quantity).toBe(10);
    expect((terms.line_items as Dict[])[0].unit_price).toBe(50_000);
  });

  test("advantage platform casing aliases supported", () => {
    const quote = {
      Id: "cart-001",
      CurrencyCode: "CAD",
      LineItems: [
        {
          Id: "line-001",
          ProductName: "Managed Service Subscription",
          Quantity: 2,
          UnitPrice: 1_200.0,
          TotalPrice: 2_400.0,
        },
      ],
    };

    const terms = congaQuoteToA2cnTerms(quote);

    expect(terms.currency).toBe("CAD");
    expect(terms.total_value).toBe(240_000);
    expect(terms.seat_count).toBe(2);
    expect((terms.line_items as Dict[])[0].unit_price).toBe(120_000);
  });
});

describe("CongaSessionAndWriteBack", () => {
  test("quote to session inputs sets saas deal type", () => {
    const parsed = CongaAdapter.quoteToSessionInputs(SAMPLE_CONGA_SAAS_QUOTE, 3);

    expect(parsed.quote_id).toBe("conga-q-001");
    expect((parsed.session_params as Dict).deal_type).toBe("saas_renewal");
    expect((parsed.session_params as Dict).max_rounds).toBe(3);
    expect((parsed.session_params as Dict).conga_quote_id).toBe("conga-q-001");
    expect((parsed.session_params as Dict).conga_account_id).toBe("001xx000003DGbY");
    expect((parsed.session_params as Dict).conga_opportunity_id).toBe("006xx000004TqVQ");
  });

  test("a2cn terms to conga quote converts cents to dollars", () => {
    const terms = congaQuoteToA2cnTerms(SAMPLE_CONGA_SAAS_QUOTE);

    const payload = a2cnTermsToCongaQuote(terms, "conga-q-001", "clm-agreement-001");

    expect(payload.quoteId).toBe("conga-q-001");
    expect(payload.agreementId).toBe("clm-agreement-001");
    expect(payload.totalAmount).toBe(100_000.0);
    expect(payload.seatCount).toBe(100);
    expect(payload.termMonths).toBe(12);
    expect((payload.lineItems as Dict[])[0].id).toBe("qli-001");
    expect((payload.lineItems as Dict[])[0].productId).toBe("prod-001");
    expect((payload.lineItems as Dict[])[0].unitPrice).toBe(950.0);
    expect((payload.lineItems as Dict[])[0].totalPrice).toBe(95_000.0);
    expect(payload.paymentTerms).toBe("Net 45");
  });

  test("goods terms to conga quote includes delivery days", () => {
    const terms = congaQuoteToA2cnTerms(SAMPLE_CONGA_GOODS_QUOTE);

    const payload = a2cnTermsToCongaQuote(terms, "a1Qxx0000009abc");

    expect(payload.deliveryDays).toBe(21);
    expect((payload.lineItems as Dict[])[0].id).toBe("a2Lxx0000001");
    expect((payload.lineItems as Dict[])[0].unitOfMeasure).toBe("EA");
  });

  test("agreement update payload links a2cn record", () => {
    const payload = congaAgreementUpdatePayload("clm-agreement-001", "sess-001", "record-hash");

    expect(payload).toEqual({
      agreementId: "clm-agreement-001",
      status: "Ready for Contracting",
      externalReferences: {
        a2cn_session_id: "sess-001",
        a2cn_record_hash: "record-hash",
      },
    });
  });
});

describe("CongaAuthHelpers", () => {
  test("conga auth headers", () => {
    const headers = congaAuthHeaders("access-token");

    expect(headers.Authorization).toBe("Bearer access-token");
    expect(headers.Accept).toBe("application/json");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  test("fetch conga access token requires env", async () => {
    vi.stubEnv("CONGA_CLIENT_ID", "");
    vi.stubEnv("CONGA_CLIENT_SECRET", "");
    vi.stubEnv("CONGA_TOKEN_URL", "");

    await expect(fetchCongaAccessToken()).rejects.toThrow(/CONGA_CLIENT_ID/);
  });

  test("fetch conga access token uses client credentials", async () => {
    const { fetchFn, captured } = makeTokenFetch({ access_token: "token-123" });
    vi.stubEnv("CONGA_CLIENT_ID", "client-id");
    vi.stubEnv("CONGA_CLIENT_SECRET", "client-secret");
    vi.stubEnv("CONGA_TOKEN_URL", "https://auth.example.com/oauth2/token");
    vi.stubEnv("CONGA_SCOPE", "");

    const token = await fetchCongaAccessToken(null, fetchFn);

    expect(token).toBe("token-123");
    const request = captured[0];
    expect(request.params.get("grant_type")).toBe("client_credentials");
    expect(request.params.get("scope")).toBeNull();
    const expectedBasic = `Basic ${Buffer.from("client-id:client-secret", "utf-8").toString("base64")}`;
    expect(request.headers.Authorization).toBe(expectedBasic);
  });

  test("fetch conga access token includes scope when present", async () => {
    const { fetchFn, captured } = makeTokenFetch({ access_token: "token-123" });
    vi.stubEnv("CONGA_CLIENT_ID", "client-id");
    vi.stubEnv("CONGA_CLIENT_SECRET", "client-secret");
    vi.stubEnv("CONGA_SCOPE", "api cpq");

    const token = await fetchCongaAccessToken("https://auth.example.com/oauth2/token", fetchFn);

    expect(token).toBe("token-123");
    const request = captured[0];
    expect(request.params.get("grant_type")).toBe("client_credentials");
    expect(request.params.get("scope")).toBe("api cpq");
  });
});
