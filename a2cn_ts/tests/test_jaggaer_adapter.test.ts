/** Tests for JAGGAER ASO platform adapter. */

import { afterEach, describe, expect, test, vi } from "vitest";

import { validateDealTypeTerms } from "../src/a2cn/messages.js";
import type { Dict } from "../src/a2cn/messages.js";
import {
  JaggaerEventParser,
  a2cnTermsToJaggaerResponse,
  fetchJaggaerAccessToken,
  jaggaerAuthHeaders,
  jaggaerPollRequest,
} from "../src/adapters/jaggaer_adapter.js";

const SAMPLE_JAGGAER_PUSH_EVENT: Dict = {
  event: {
    eventId: "aso-10003",
    customerHostId: "275",
    name: "Industrial Supplies RFQ",
    eventOwner: "Global Manufacturing Inc.",
    biddingClose: "2026-08-01T17:00:00Z",
    currency: "USD",
    deliveryDays: 21,
    paymentTermsNetDays: 45,
    items: [
      {
        itemId: "10",
        lotId: "LOT-HF-001",
        description: "Hydraulic fluid 200L drums",
        quantity: 50,
        unitOfMeasure: "EA",
        targetPrice: 360.0,
      },
      {
        itemId: "20",
        lotId: "LOT-SC-002",
        description: "Sealing compound 5kg tubs",
        quantity: 20,
        unitOfMeasure: "KG",
        targetPrice: 85.0,
      },
    ],
  },
};

const SAMPLE_JAGGAER_POLLED_EVENT: Dict = {
  eventId: 10004,
  customerHostId: 275,
  title: "Public sector pump sourcing event",
  buyerOrganization: "City Procurement Office",
  closeDate: "2026-09-15T17:00:00Z",
  currencyCode: "EUR",
  lineItems: {
    results: [
      {
        id: "item-001",
        lotNumber: "lot-001",
        name: "Industrial hydraulic pump",
        qty: 10,
        uom: "EA",
        unitPrice: { amount: 1500.0, currency: "EUR" },
      },
    ],
  },
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

describe("JaggaerEventParser", () => {
  test("parse push event payload", () => {
    const parsed = JaggaerEventParser.parseSourcingEvent(SAMPLE_JAGGAER_PUSH_EVENT);

    expect(parsed.event_id).toBe("aso-10003");
    expect(parsed.customer_host_id).toBe("275");
    expect(parsed.event_name).toBe("Industrial Supplies RFQ");
    expect(parsed.buyer_org).toBe("Global Manufacturing Inc.");
    expect(parsed.currency).toBe("USD");
    expect(parsed.mode).toBe("push");
    expect((parsed.line_items as Dict[]).length).toBe(2);
  });

  test("event to goods procurement terms converts prices to cents", () => {
    const terms = JaggaerEventParser.sourcingEventToGoodsProcurementTerms(
      SAMPLE_JAGGAER_PUSH_EVENT,
    );

    expect(terms.currency).toBe("USD");
    expect(terms.delivery_days).toBe(21);
    expect((terms.payment_terms as Dict).net_days).toBe(45);
    expect((terms.line_items as Dict[])[0].unit_price).toBe(36_000);
    expect((terms.line_items as Dict[])[0].total).toBe(1_800_000);
    expect(terms.total_value).toBe(1_970_000);
    expect(validateDealTypeTerms("goods_procurement", terms)).toEqual([]);
  });

  test("item and lot ids are preserved for bid reconstruction", () => {
    const terms = JaggaerEventParser.sourcingEventToGoodsProcurementTerms(
      SAMPLE_JAGGAER_PUSH_EVENT,
    );

    expect((terms.line_items as Dict[])[0].internal_part_number).toBe("LOT-HF-001");
    expect((terms.line_items as Dict[])[0].jaggaer_item_id).toBe("10");
    expect((terms.line_items as Dict[])[0].jaggaer_lot_id).toBe("LOT-HF-001");
    expect(((terms.custom_terms as Dict).jaggaer as Dict).event_id).toBe("aso-10003");
    expect(((terms.custom_terms as Dict).jaggaer as Dict).source).toBe("jaggaer_aso");
  });

  test("polled event aliases supported", () => {
    const parsed = JaggaerEventParser.sourcingEventToSessionInputs(
      SAMPLE_JAGGAER_POLLED_EVENT,
      3,
      14,
      "poll",
    );

    expect((parsed.session_params as Dict).deal_type).toBe("goods_procurement");
    expect((parsed.session_params as Dict).max_rounds).toBe(3);
    expect((parsed.session_params as Dict).jaggaer_event_id).toBe("10004");
    expect((parsed.session_params as Dict).jaggaer_customer_host_id).toBe(275);
    expect((parsed.initial_terms as Dict).currency).toBe("EUR");
    expect((parsed.initial_terms as Dict).total_value).toBe(1_500_000);
    expect((((parsed.initial_terms as Dict).custom_terms as Dict).jaggaer as Dict).mode).toBe(
      "poll",
    );
    expect(validateDealTypeTerms("goods_procurement", parsed.initial_terms as Dict)).toEqual([]);
  });

  test("total price overrides computed line total when present", () => {
    const event = {
      eventId: "evt-total",
      currency: "USD",
      items: [
        {
          itemId: "1",
          description: "Configured assembly",
          quantity: 3,
          unitPrice: 100.0,
          totalPrice: 275.0,
        },
      ],
    };

    const terms = JaggaerEventParser.sourcingEventToGoodsProcurementTerms(event);

    expect((terms.line_items as Dict[])[0].unit_price).toBe(10_000);
    expect((terms.line_items as Dict[])[0].total).toBe(27_500);
    expect(terms.total_value).toBe(27_500);
  });
});

describe("JaggaerWriteBackPayloads", () => {
  test("terms to jaggaer response converts cents to dollars", () => {
    const terms = JaggaerEventParser.sourcingEventToGoodsProcurementTerms(
      SAMPLE_JAGGAER_PUSH_EVENT,
    );

    const response = a2cnTermsToJaggaerResponse(terms, "aso-10003", "supplier-001");

    expect(response.eventId).toBe("aso-10003");
    expect(response.supplierId).toBe("supplier-001");
    expect(response.totalAmount).toBe(19_700.0);
    expect((response.items as Dict[])[0].itemId).toBe("10");
    expect((response.items as Dict[])[0].lotId).toBe("LOT-HF-001");
    expect((response.items as Dict[])[0].unitPrice).toBe(360.0);
    expect((response.items as Dict[])[0].totalPrice).toBe(18_000.0);
    expect(response.paymentTerms).toBe("Net 45");
  });

  test("poll request builds customer host api events path", () => {
    const request = jaggaerPollRequest("275", "user-123", "https://ches.demo-api.example.com/");

    expect(request).toEqual({
      method: "GET",
      url: "https://ches.demo-api.example.com/chost/275/user/user-123/apiEvents",
      headers: {
        Accept: "application/vnd.sciquest.com.ches+json",
      },
    });
  });
});

describe("JaggaerAuthHelpers", () => {
  test("jaggaer auth headers include api key", () => {
    const headers = jaggaerAuthHeaders("access-token", "api-key");

    expect(headers.Authorization).toBe("Bearer access-token");
    expect(headers["X-API-Key"]).toBe("api-key");
    expect(headers.Accept).toBe("application/json");
  });

  test("jaggaer auth headers reads api key from env", () => {
    vi.stubEnv("JAGGAER_API_KEY", "env-api-key");
    const headers = jaggaerAuthHeaders("access-token");

    expect(headers["X-API-Key"]).toBe("env-api-key");
  });

  test("jaggaer auth headers require api key", () => {
    vi.stubEnv("JAGGAER_API_KEY", "");
    expect(() => jaggaerAuthHeaders("access-token")).toThrow(/JAGGAER_API_KEY/);
  });

  test("fetch jaggaer access token uses client credentials", async () => {
    const { fetchFn, captured } = makeTokenFetch({ access_token: "token-123" });
    vi.stubEnv("JAGGAER_CLIENT_ID", "client-id");
    vi.stubEnv("JAGGAER_CLIENT_SECRET", "client-secret");
    vi.stubEnv("JAGGAER_API_KEY", "api-key");
    vi.stubEnv("JAGGAER_TOKEN_URL", "https://auth.demo-api.example.com/oauth2/token");
    vi.stubEnv("JAGGAER_SCOPE", "");

    const token = await fetchJaggaerAccessToken(null, fetchFn);

    expect(token).toBe("token-123");
    const request = captured[0];
    expect(request.params.get("grant_type")).toBe("client_credentials");
    expect(request.params.get("scope")).toBeNull();
    const expectedBasic = `Basic ${Buffer.from("client-id:client-secret", "utf-8").toString("base64")}`;
    expect(request.headers.Authorization).toBe(expectedBasic);
    expect(request.headers["X-API-Key"]).toBe("api-key");
  });

  test("fetch jaggaer access token includes scope when present", async () => {
    const { fetchFn, captured } = makeTokenFetch({ access_token: "token-123" });
    vi.stubEnv("JAGGAER_CLIENT_ID", "client-id");
    vi.stubEnv("JAGGAER_CLIENT_SECRET", "client-secret");
    vi.stubEnv("JAGGAER_API_KEY", "api-key");
    vi.stubEnv("JAGGAER_SCOPE", "tenant-aso 275");

    const token = await fetchJaggaerAccessToken(
      "https://auth.demo-api.example.com/oauth2/token",
      fetchFn,
    );

    expect(token).toBe("token-123");
    const request = captured[0];
    expect(request.params.get("grant_type")).toBe("client_credentials");
    expect(request.params.get("scope")).toBe("tenant-aso 275");
  });
});
