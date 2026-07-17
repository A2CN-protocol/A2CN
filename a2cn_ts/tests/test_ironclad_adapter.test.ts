/** Tests for Ironclad CLM platform adapter. */

import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { afterEach, describe, expect, test, vi } from "vitest";

import { validateDealTypeTerms } from "../src/a2cn/messages.js";
import type { Dict } from "../src/a2cn/messages.js";
import {
  IroncladWebhookParser,
  a2cnTermsToIroncladRecord,
  a2cnTermsToIroncladWorkflow,
  updateIroncladWorkflowMetadata,
} from "../src/adapters/ironclad_adapter.js";

const SAMPLE_RENEWAL_WORKFLOW: Dict = {
  eventId: "evt-ironclad-001",
  eventType: "workflow.updated",
  workflow: {
    id: "wf-001",
    ironcladId: "IC-001",
    title: "Enterprise Subscription Renewal - Acme Analytics",
    step: "Review",
    status: "active",
    attributes: {
      counterpartyName: "Acme Analytics",
      contractValue: { currency: "USD", amount: 105000.0 },
      seatCount: 100,
      termMonths: 12,
      product: "Analytics Platform Enterprise",
      paymentTermsNetDays: 45,
    },
  },
};

const SAMPLE_GOODS_WORKFLOW: Dict = {
  eventId: "evt-ironclad-002",
  eventType: "workflow.updated",
  workflow: {
    id: "wf-002",
    ironcladId: "IC-002",
    title: "Master Supply Agreement - Pumps",
    step: "Review",
    attributes: {
      counterpartyName: "Pump Supplier LLC",
      contractValue: { currency: "EUR", amount: 18000.0 },
      product: "Industrial hydraulic pumps",
      deliveryDays: 21,
    },
  },
};

const SAMPLE_AGREED_TERMS: Dict = {
  deal_type: "saas_renewal",
  total_value: 10_500_000,
  currency: "USD",
  seat_count: 100,
  subscription_tier: "enterprise",
  term_months: 12,
  payment_terms: { net_days: 45 },
  custom_terms: {
    ironclad: {
      workflow_id: "wf-001",
      ironclad_id: "IC-001",
      counterparty_name: "Acme Analytics",
    },
  },
};

function compactJson(body: Dict): string {
  return JSON.stringify(body);
}

interface CapturedRequest {
  url: string;
  body: string;
  headers: Record<string, string>;
  method: string;
}

function makeJsonFetch(jsonData: Dict): { fetchFn: typeof fetch; captured: CapturedRequest[] } {
  const captured: CapturedRequest[] = [];
  const fetchFn = (async (url: string | URL | Request, init?: RequestInit) => {
    captured.push({
      url: String(url),
      body: String(init?.body ?? ""),
      headers: (init?.headers as Record<string, string>) ?? {},
      method: init?.method ?? "GET",
    });
    return new Response(JSON.stringify(jsonData), { status: 200 });
  }) as typeof fetch;
  return { fetchFn, captured };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("IroncladWebhookParser", () => {
  test("renewal workflow maps to saas renewal terms", () => {
    const parsed = IroncladWebhookParser.workflowEventToSessionInputs(SAMPLE_RENEWAL_WORKFLOW);

    expect(parsed.workflow_id).toBe("wf-001");
    expect((parsed.session_params as Dict).deal_type).toBe("saas_renewal");
    expect((parsed.session_params as Dict).ironclad_id).toBe("IC-001");
    expect((parsed.initial_terms as Dict).total_value).toBe(10_500_000);
    expect((parsed.initial_terms as Dict).seat_count).toBe(100);
    expect(((parsed.initial_terms as Dict).payment_terms as Dict).net_days).toBe(45);
    expect(validateDealTypeTerms("saas_renewal", parsed.initial_terms as Dict)).toEqual([]);
  });

  test("non renewal workflow maps to goods procurement terms", () => {
    const parsed = IroncladWebhookParser.workflowEventToSessionInputs(SAMPLE_GOODS_WORKFLOW);

    expect((parsed.session_params as Dict).deal_type).toBe("goods_procurement");
    expect((parsed.initial_terms as Dict).currency).toBe("EUR");
    expect((parsed.initial_terms as Dict).delivery_days).toBe(21);
    expect(((parsed.initial_terms as Dict).line_items as Dict[])[0].unit_price).toBe(1_800_000);
    expect(validateDealTypeTerms("goods_procurement", parsed.initial_terms as Dict)).toEqual([]);
  });

  test("signed webhook verification accepts valid signature", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const eventId = "evt-ironclad-003";
    const nonce = "nonce-123";
    const body: Dict = { workflow: { id: "wf-003" }, eventType: "workflow.updated" };
    const signedData = Buffer.from(eventId + compactJson(body) + nonce, "utf-8");
    const signature = cryptoSign("sha256", signedData, privateKey);
    const verificationHeader = JSON.stringify({
      nonce,
      signAlgorithm: "RSA-SHA256",
      signature: signature.toString("base64"),
      encoding: "base64",
    });

    expect(
      IroncladWebhookParser.verifyWebhookSignature(eventId, verificationHeader, body, publicPem),
    ).toBe(true);
  });

  test("signed webhook verification rejects tampered body", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const eventId = "evt-ironclad-004";
    const nonce = "nonce-456";
    const body: Dict = { workflow: { id: "wf-004" } };
    const signedData = Buffer.from(eventId + compactJson(body) + nonce, "utf-8");
    const signature = cryptoSign("sha256", signedData, privateKey);
    const verificationHeader = JSON.stringify({
      nonce,
      signAlgorithm: "RSA-SHA256",
      signature: signature.toString("base64"),
      encoding: "base64",
    });

    expect(
      IroncladWebhookParser.verifyWebhookSignature(
        eventId,
        verificationHeader,
        { workflow: { id: "wf-tampered" } },
        publicPem,
      ),
    ).toBe(false);
  });
});

describe("IroncladWriteBackPayloads", () => {
  test("terms to workflow update payload shape", () => {
    const update = a2cnTermsToIroncladWorkflow(
      SAMPLE_AGREED_TERMS,
      "wf-001",
      "sess-001",
      "deadbeef".repeat(8),
    );

    const payload = update.payload as Dict;
    expect(update.endpoint).toBe("/workflows/wf-001/attributes");
    expect((payload.updates as Dict[])[0]).toEqual({
      action: "set",
      path: "contractValue",
      value: { currency: "USD", amount: 105000.0 },
    });
    expect(payload.updates as Dict[]).toContainEqual({
      action: "set",
      path: "a2cnSessionId",
      value: "sess-001",
    });
  });

  test("terms to workflow update supports field map", () => {
    const update = a2cnTermsToIroncladWorkflow(
      SAMPLE_AGREED_TERMS,
      "wf-001",
      "sess-002",
      "cafebabe".repeat(8),
      { contract_value: "fee", a2cn_record_hash: "a2cnHash" },
    );

    const paths = new Set(
      ((update.payload as Dict).updates as Dict[]).map((item) => item.path as string),
    );
    expect(paths.has("fee")).toBe(true);
    expect(paths.has("a2cnHash")).toBe(true);
  });

  test("terms to record payload shape", () => {
    const record = a2cnTermsToIroncladRecord(
      SAMPLE_AGREED_TERMS,
      "vendorAgreement",
      "A2CN Renewal - Acme Analytics",
      "sess-003",
      "feedface".repeat(8),
    );

    expect(record.type).toBe("vendorAgreement");
    expect(record.name).toBe("A2CN Renewal - Acme Analytics");
    const properties = record.properties as Dict;
    expect((properties.contractValue as Dict).type).toBe("monetary_amount");
    expect(((properties.contractValue as Dict).value as Dict).amount).toBe(105000.0);
    expect((properties.a2cnSessionId as Dict).value).toBe("sess-003");
  });
});

describe("IroncladHttpUpdate", () => {
  test("update workflow metadata uses env token and actor", async () => {
    const { fetchFn, captured } = makeJsonFetch({ id: "wf-001" });
    vi.stubEnv("IRONCLAD_API_TOKEN", "test-token");
    vi.stubEnv("IRONCLAD_BASE_URL", "https://demo.ironcladapp.com/public/api/v1");
    vi.stubEnv("IRONCLAD_AS_USER_EMAIL", "legal@example.com");

    const result = await updateIroncladWorkflowMetadata("wf-001", { updates: [] }, null, fetchFn);

    expect(result.id).toBe("wf-001");
    const request = captured[0];
    expect(request.headers.Authorization).toBe("Bearer test-token");
    expect(request.headers["x-as-user-email"]).toBe("legal@example.com");
    expect(JSON.parse(request.body)).toEqual({ updates: [] });
  });

  test("update workflow metadata omits actor header when absent", async () => {
    const { fetchFn, captured } = makeJsonFetch({ id: "wf-002" });
    vi.stubEnv("IRONCLAD_API_TOKEN", "test-token");
    vi.stubEnv("IRONCLAD_BASE_URL", "https://demo.ironcladapp.com/public/api/v1");
    vi.stubEnv("IRONCLAD_AS_USER_EMAIL", "");

    const result = await updateIroncladWorkflowMetadata("wf-002", { updates: [] }, null, fetchFn);

    expect(result.id).toBe("wf-002");
    const request = captured[0];
    expect("x-as-user-email" in request.headers).toBe(false);
  });

  test("update workflow metadata requires token", async () => {
    vi.stubEnv("IRONCLAD_API_TOKEN", "");

    await expect(updateIroncladWorkflowMetadata("wf-001", { updates: [] })).rejects.toThrow(
      /IRONCLAD_API_TOKEN/,
    );
  });
});
