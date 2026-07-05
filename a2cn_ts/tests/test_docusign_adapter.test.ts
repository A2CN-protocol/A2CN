/** Tests for DocuSign eSignature / Connect adapter. */

import { createHmac, generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, test, vi } from "vitest";

import {
  DOCUSIGN_JWT_GRANT_TYPE,
  DocuSignConnectParser,
  a2cnRecordToDocusignEnvelope,
  docusignAuthHeaders,
  docusignEnvelopeCreateRequest,
  fetchDocusignAccessToken,
} from "../src/adapters/docusign_adapter.js";
import { b64urlDecode } from "../src/a2cn/crypto.js";
import type { Dict } from "../src/a2cn/messages.js";

const SAMPLE_RECORD: Dict = {
  record_type: "a2cn_transaction_record",
  record_id: "record-001",
  session_id: "sess-001",
  record_hash: "abc123".repeat(10),
  deal_type: "saas_renewal",
  currency: "USD",
  parties: {
    initiator: {
      organization_name: "Buyer Co",
      did: "did:web:buyer.example",
    },
    responder: {
      organization_name: "Seller Co",
      did: "did:web:seller.example",
    },
  },
  agreed_terms: {
    total_value: 10_000_000,
    currency: "USD",
    seat_count: 100,
    subscription_tier: "Enterprise",
    term_months: 12,
    payment_terms: { net_days: 45 },
    line_items: [
      {
        description: "Enterprise Subscription",
        quantity: 100,
        unit_price: 95_000,
        total: 9_500_000,
      },
      {
        description: "Premium Support",
        quantity: 1,
        unit_price: 500_000,
        total: 500_000,
      },
    ],
  },
};

const SIGNER_CONTACTS: Record<string, Dict> = {
  "did:web:buyer.example": {
    name: "Buyer Legal",
    email: "legal@buyer.example",
  },
  "did:web:seller.example": {
    name: "Seller Legal",
    email: "legal@seller.example",
  },
};

function privateKeyPem(): string {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

interface CapturedTokenRequest {
  url: string;
  params: URLSearchParams;
  headers: Record<string, string>;
}

function makeTokenFetch(jsonData: Dict): {
  fetchFn: typeof fetch;
  captured: CapturedTokenRequest[];
} {
  const captured: CapturedTokenRequest[] = [];
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

function decodeJwtPayload(token: string): Dict {
  return JSON.parse(b64urlDecode(token.split(".")[1]).toString("utf-8"));
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("DocuSignEnvelopeMapping", () => {
  test("record to envelope maps documents recipients and custom fields", () => {
    const envelope = a2cnRecordToDocusignEnvelope(SAMPLE_RECORD, SIGNER_CONTACTS, {
      connectUrl: "https://middleware.example.com/docusign/connect",
    });

    expect(envelope.status).toBe("sent");
    expect(envelope.emailSubject).toBe("A2CN agreement for session sess-001");
    const documents = envelope.documents as Dict[];
    expect(documents[0].documentId).toBe("1");
    expect(documents[0].fileExtension).toBe("txt");
    const signers = (envelope.recipients as Dict).signers as Dict[];
    expect(signers[0].email).toBe("legal@buyer.example");
    expect(signers[0].name).toBe("Buyer Legal");
    expect(signers[1].email).toBe("legal@seller.example");
    expect(signers[1].name).toBe("Seller Legal");
    const fields = (envelope.customFields as Dict).textCustomFields as Dict[];
    expect(fields).toContainEqual({ name: "a2cn_session_id", value: "sess-001", show: "false" });
    expect(fields).toContainEqual({
      name: "a2cn_record_hash",
      value: SAMPLE_RECORD.record_hash,
      show: "false",
    });
    expect((envelope.eventNotification as Dict).url).toBe(
      "https://middleware.example.com/docusign/connect",
    );
  });

  test("generated document contains record hash and terms", () => {
    const envelope = a2cnRecordToDocusignEnvelope(SAMPLE_RECORD, SIGNER_CONTACTS);
    const documentText = Buffer.from(
      (envelope.documents as Dict[])[0].documentBase64 as string,
      "base64",
    ).toString("utf-8");

    expect(documentText).toContain("A2CN Transaction Terms Summary");
    expect(documentText).toContain("Session ID: sess-001");
    expect(documentText).toContain(`Record Hash: ${SAMPLE_RECORD.record_hash}`);
    expect(documentText).toContain("Seat count: 100");
    expect(documentText).toContain("Term months: 12");
    expect(documentText).toContain("\\s1\\");
    expect(documentText).toContain("\\s2\\");
  });

  test("missing signer email is rejected", () => {
    expect(() =>
      a2cnRecordToDocusignEnvelope(SAMPLE_RECORD, {
        "did:web:buyer.example": { email: "legal@buyer.example" },
      }),
    ).toThrow(/Missing signer email/);
  });

  test("envelope create request uses v21 account path", () => {
    const envelope = a2cnRecordToDocusignEnvelope(SAMPLE_RECORD, SIGNER_CONTACTS);

    const request = docusignEnvelopeCreateRequest("acct-001", envelope, "https://demo.docusign.net/");

    expect(request.method).toBe("POST");
    expect(request.url).toBe("https://demo.docusign.net/restapi/v2.1/accounts/acct-001/envelopes");
    expect(request.json).toEqual(envelope);
  });
});

describe("DocuSignConnectParser", () => {
  test("parse completed envelope event", () => {
    const payload = {
      event: "envelope-completed",
      data: {
        envelopeId: "env-001",
        envelopeSummary: {
          status: "completed",
          customFields: {
            textCustomFields: [
              { name: "a2cn_session_id", value: "sess-001" },
              { name: "a2cn_record_hash", value: "hash-001" },
            ],
          },
        },
      },
    };

    const update = DocuSignConnectParser.parseEnvelopeEvent(payload);

    expect(update.provider).toBe("docusign");
    expect(update.event).toBe("envelope-completed");
    expect(update.envelope_id).toBe("env-001");
    expect(update.envelope_status).toBe("completed");
    expect(update.post_commitment_status).toBe("signature_completed");
    expect(update.a2cn_session_id).toBe("sess-001");
    expect(update.a2cn_record_hash).toBe("hash-001");
    expect(update.completed).toBe(true);
  });

  test("parse declined envelope event", () => {
    const update = DocuSignConnectParser.parseEnvelopeEvent({
      event: "envelope-declined",
      data: {
        envelopeId: "env-002",
        envelopeStatus: "declined",
      },
    });

    expect(update.post_commitment_status).toBe("signature_declined");
    expect(update.completed).toBe(false);
  });

  test("parse completed event name without explicit status", () => {
    const update = DocuSignConnectParser.parseEnvelopeEvent({
      event: "envelope-completed",
      data: {
        envelopeId: "env-003",
      },
    });

    expect(update.envelope_status).toBe("completed");
    expect(update.post_commitment_status).toBe("signature_completed");
    expect(update.completed).toBe(true);
  });

  test("verify hmac signature accepts valid signature", () => {
    const payloadBytes = Buffer.from(JSON.stringify({ event: "envelope-completed" }), "utf-8");
    const signature = createHmac("sha256", "secret").update(payloadBytes).digest("base64");

    expect(DocuSignConnectParser.verifyHmacSignature(payloadBytes, signature, "secret")).toBe(true);
  });

  test("verify hmac signature rejects tampered payload", () => {
    const payloadBytes = Buffer.from(JSON.stringify({ event: "envelope-completed" }), "utf-8");
    const signature = createHmac("sha256", "secret").update(payloadBytes).digest("base64");

    expect(
      DocuSignConnectParser.verifyHmacSignature(
        Buffer.from('{"event":"envelope-voided"}', "utf-8"),
        signature,
        "secret",
      ),
    ).toBe(false);
  });
});

describe("DocuSignAuthHelpers", () => {
  test("docusign auth headers", () => {
    const headers = docusignAuthHeaders("access-token");

    expect(headers).toEqual({
      Authorization: "Bearer access-token",
      Accept: "application/json",
      "Content-Type": "application/json",
    });
  });

  test("fetch docusign access token uses jwt bearer grant", async () => {
    const { fetchFn, captured } = makeTokenFetch({ access_token: "token-123" });
    const privateKey = privateKeyPem();
    vi.stubEnv("DOCUSIGN_INTEGRATION_KEY", "integration-key");
    vi.stubEnv("DOCUSIGN_USER_ID", "user-guid");
    vi.stubEnv("DOCUSIGN_PRIVATE_KEY", privateKey);
    vi.stubEnv("DOCUSIGN_AUTH_BASE_URI", "https://account-d.docusign.com");
    vi.stubEnv("DOCUSIGN_SCOPE", "");

    const token = await fetchDocusignAccessToken(null, 1_700_000_000, fetchFn);

    expect(token).toBe("token-123");
    const request = captured[0];
    expect(request.params.get("grant_type")).toBe(DOCUSIGN_JWT_GRANT_TYPE);
    const decoded = decodeJwtPayload(request.params.get("assertion")!);
    expect(decoded.iss).toBe("integration-key");
    expect(decoded.sub).toBe("user-guid");
    expect(decoded.aud).toBe("account-d.docusign.com");
    expect(decoded.scope).toBe("signature impersonation");
    expect(request.headers).toEqual({ Accept: "application/json" });
  });

  test("fetch docusign access token uses custom scope and auth uri", async () => {
    const { fetchFn, captured } = makeTokenFetch({ access_token: "token-123" });
    const privateKey = privateKeyPem();
    vi.stubEnv("DOCUSIGN_INTEGRATION_KEY", "integration-key");
    vi.stubEnv("DOCUSIGN_USER_ID", "user-guid");
    vi.stubEnv("DOCUSIGN_PRIVATE_KEY", privateKey);
    vi.stubEnv("DOCUSIGN_SCOPE", "signature impersonation click.manage");

    const token = await fetchDocusignAccessToken(
      "https://account.docusign.com",
      1_700_000_000,
      fetchFn,
    );

    expect(token).toBe("token-123");
    const request = captured[0];
    const decoded = decodeJwtPayload(request.params.get("assertion")!);
    expect(decoded.aud).toBe("account.docusign.com");
    expect(decoded.scope).toBe("signature impersonation click.manage");
    expect(request.url).toBe("https://account.docusign.com/oauth/token");
  });

  test("fetch docusign access token requires env", async () => {
    vi.stubEnv("DOCUSIGN_INTEGRATION_KEY", "");
    vi.stubEnv("DOCUSIGN_USER_ID", "");
    vi.stubEnv("DOCUSIGN_PRIVATE_KEY", "");

    await expect(fetchDocusignAccessToken()).rejects.toThrow(/DOCUSIGN_INTEGRATION_KEY/);
  });
});
