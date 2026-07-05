/** Tests for SAP Ariba Sourcing platform adapter. */

import { afterEach, describe, expect, test, vi } from "vitest";

import { validateDealTypeTerms } from "../src/a2cn/messages.js";
import type { Dict } from "../src/a2cn/messages.js";
import {
  AribaEventParser,
  a2cnTermsToAribaBid,
  aribaAcknowledgementPayload,
  aribaAuthHeaders,
  fetchAribaAccessToken,
} from "../src/adapters/ariba_adapter.js";

const SAMPLE_ARIBA_EVENT: Dict = {
  eventId: "evt-ariba-001",
  externalSystemCorrelationId: "RFQ-2026-001",
  title: "Q3 Industrial Supplies RFQ",
  buyerOrg: "Global Manufacturing Inc.",
  biddingEndDate: "2026-08-01T17:00:00Z",
  currency: "USD",
  deliveryDays: 21,
  paymentTermsNetDays: 45,
  items: [
    {
      itemId: "10",
      lotId: "LOT-HF-001",
      title: "Hydraulic fluid 200L drums",
      quantity: 50,
      unitOfMeasure: "EA",
      targetPrice: 360.0,
    },
    {
      itemId: "20",
      lotId: "LOT-SC-002",
      title: "Sealing compound 5kg tubs",
      quantity: 20,
      unitOfMeasure: "KG",
      targetPrice: 85.0,
    },
  ],
};

const SAMPLE_DISCOVERY_RFX: Dict = {
  rfxId: "rfx-001",
  externalRfxId: "DISC-2026-001",
  rfxTitle: "Public sector pump sourcing event",
  buyerOrganization: "City Procurement Office",
  closeDate: "2026-09-15T17:00:00Z",
  currencyCode: "EUR",
  lots: [
    {
      id: "lot-001",
      name: "Industrial hydraulic pump",
      qty: 10,
      uom: "EA",
      unitPrice: 1500.0,
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

describe("AribaEventParser", () => {
  test("parse event management payload", () => {
    const parsed = AribaEventParser.parseSourcingEvent(SAMPLE_ARIBA_EVENT);

    expect(parsed.event_id).toBe("evt-ariba-001");
    expect(parsed.external_rfx_id).toBe("RFQ-2026-001");
    expect(parsed.event_name).toBe("Q3 Industrial Supplies RFQ");
    expect(parsed.buyer_org).toBe("Global Manufacturing Inc.");
    expect(parsed.currency).toBe("USD");
    expect((parsed.line_items as Dict[]).length).toBe(2);
  });

  test("event to goods procurement terms converts prices to cents", () => {
    const terms = AribaEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_ARIBA_EVENT);

    expect(terms.currency).toBe("USD");
    expect(terms.delivery_days).toBe(21);
    expect((terms.payment_terms as Dict).net_days).toBe(45);
    expect((terms.line_items as Dict[])[0].unit_price).toBe(36_000);
    expect((terms.line_items as Dict[])[0].total).toBe(1_800_000);
    expect(terms.total_value).toBe(1_970_000);
    expect(validateDealTypeTerms("goods_procurement", terms)).toEqual([]);
  });

  test("item lot id maps to internal part number", () => {
    const terms = AribaEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_ARIBA_EVENT);

    expect((terms.line_items as Dict[])[0].internal_part_number).toBe("LOT-HF-001");
    expect((terms.line_items as Dict[])[0].ariba_item_id).toBe("10");
    expect((terms.line_items as Dict[])[0].ariba_lot_id).toBe("LOT-HF-001");
    expect(((terms.custom_terms as Dict).ariba as Dict).event_id).toBe("evt-ariba-001");
  });

  test("discovery rfx aliases supported", () => {
    const parsed = AribaEventParser.sourcingEventToSessionInputs(SAMPLE_DISCOVERY_RFX, 3);

    expect((parsed.session_params as Dict).deal_type).toBe("goods_procurement");
    expect((parsed.session_params as Dict).max_rounds).toBe(3);
    expect((parsed.session_params as Dict).ariba_event_id).toBe("rfx-001");
    expect((parsed.session_params as Dict).ariba_external_rfx_id).toBe("DISC-2026-001");
    expect((parsed.initial_terms as Dict).currency).toBe("EUR");
    expect((parsed.initial_terms as Dict).total_value).toBe(1_500_000);
    expect(validateDealTypeTerms("goods_procurement", parsed.initial_terms as Dict)).toEqual([]);
  });

  test("total price overrides computed line total when present", () => {
    const event = {
      eventId: "evt-total",
      currency: "USD",
      items: [
        {
          itemId: "1",
          title: "Configured assembly",
          quantity: 3,
          unitPrice: 100.0,
          totalPrice: 275.0,
        },
      ],
    };

    const terms = AribaEventParser.sourcingEventToGoodsProcurementTerms(event);

    expect((terms.line_items as Dict[])[0].unit_price).toBe(10_000);
    expect((terms.line_items as Dict[])[0].total).toBe(27_500);
    expect(terms.total_value).toBe(27_500);
  });
});

describe("AribaWriteBackPayloads", () => {
  test("terms to ariba bid converts cents to dollars", () => {
    const terms = AribaEventParser.sourcingEventToGoodsProcurementTerms(SAMPLE_ARIBA_EVENT);

    const bid = a2cnTermsToAribaBid(terms, "evt-ariba-001", "supplier-001");

    expect(bid.eventId).toBe("evt-ariba-001");
    expect(bid.supplierId).toBe("supplier-001");
    expect(bid.totalAmount).toBe(19_700.0);
    expect((bid.items as Dict[])[0].itemId).toBe("10");
    expect((bid.items as Dict[])[0].lotId).toBe("LOT-HF-001");
    expect((bid.items as Dict[])[0].unitPrice).toBe(360.0);
    expect((bid.items as Dict[])[0].totalPrice).toBe(18_000.0);
    expect(bid.paymentTerms).toBe("Net 45");
  });

  test("acknowledgement payload shape", () => {
    const ack = aribaAcknowledgementPayload("rfx-001", "a2cn-session-sess-001");

    expect(ack).toEqual({
      eventId: "rfx-001",
      externalReference: "a2cn-session-sess-001",
      status: "ACKNOWLEDGED",
      message: "Accepted for A2CN negotiation.",
    });
  });
});

describe("AribaAuthHelpers", () => {
  test("ariba auth headers include api key", () => {
    const headers = aribaAuthHeaders("access-token", "app-key");

    expect(headers.Authorization).toBe("Bearer access-token");
    expect(headers.apiKey).toBe("app-key");
    expect(headers.Accept).toBe("application/json");
  });

  test("ariba auth headers reads api key from env", () => {
    vi.stubEnv("ARIBA_API_KEY", "env-app-key");
    const headers = aribaAuthHeaders("access-token");

    expect(headers.apiKey).toBe("env-app-key");
  });

  test("ariba auth headers require api key", () => {
    vi.stubEnv("ARIBA_API_KEY", "");
    expect(() => aribaAuthHeaders("access-token")).toThrow(/ARIBA_API_KEY/);
  });

  test("fetch ariba access token uses client credentials", async () => {
    const { fetchFn, captured } = makeTokenFetch({ access_token: "token-123" });
    vi.stubEnv("ARIBA_CLIENT_ID", "client-id");
    vi.stubEnv("ARIBA_CLIENT_SECRET", "client-secret");
    vi.stubEnv("ARIBA_TOKEN_URL", "https://api.ariba.com/oauth/token");

    const token = await fetchAribaAccessToken(null, fetchFn);

    expect(token).toBe("token-123");
    const request = captured[0];
    expect(request.params.get("grant_type")).toBe("client_credentials");
    const expectedBasic = `Basic ${Buffer.from("client-id:client-secret", "utf-8").toString("base64")}`;
    expect(request.headers.Authorization).toBe(expectedBasic);
  });

  test("fetch ariba access token accepts explicit token url", async () => {
    const { fetchFn, captured } = makeTokenFetch({ access_token: "token-456" });
    vi.stubEnv("ARIBA_CLIENT_ID", "client-id");
    vi.stubEnv("ARIBA_CLIENT_SECRET", "client-secret");
    vi.stubEnv("ARIBA_TOKEN_URL", "");

    const token = await fetchAribaAccessToken("https://example.ariba.com/oauth/token", fetchFn);

    expect(token).toBe("token-456");
    expect(captured.length).toBe(1);
    expect(captured[0].url).toBe("https://example.ariba.com/oauth/token");
  });

  test("fetch ariba access token requires env", async () => {
    vi.stubEnv("ARIBA_CLIENT_ID", "");
    vi.stubEnv("ARIBA_CLIENT_SECRET", "");
    vi.stubEnv("ARIBA_TOKEN_URL", "");

    await expect(fetchAribaAccessToken()).rejects.toThrow(/ARIBA_CLIENT_ID/);
  });
});
