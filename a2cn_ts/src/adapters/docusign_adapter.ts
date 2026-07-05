/**
 * DocuSign eSignature/CLM -> A2CN formalization adapter.
 *
 * Translates an A2CN transaction record into a DocuSign eSignature envelope
 * definition, and translates DocuSign Connect webhook notifications into a small
 * post-commitment status update shape.
 *
 * Public documentation used for this adapter:
 *   eSignature REST API:
 *     POST /restapi/v2.1/accounts/{accountId}/envelopes
 *     EnvelopeDefinition: status, emailSubject, documents, recipients
 *   DocuSign Connect:
 *     envelope event notifications, completed envelope events, HMAC signatures
 *   OAuth:
 *     JWT bearer grant with integration key, user ID, account ID, and RSA key
 *
 * No core protocol changes are required. A2CN remains the neutral bilateral
 * transaction record; DocuSign executes signature and downstream CLM workflow.
 */

import { createHmac, createPrivateKey, timingSafeEqual } from "node:crypto";
import { SignJWT } from "jose";

import type { Dict } from "../a2cn/messages.js";

export const DOCUSIGN_JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
export const DOCUSIGN_DEMO_AUTH_BASE_URI = "https://account-d.docusign.com";
export const DOCUSIGN_PROD_AUTH_BASE_URI = "https://account.docusign.com";

function moneyToDecimal(cents: unknown): number {
  if (cents === null || cents === undefined || cents === "") {
    return 0.0;
  }
  return Number(cents) / 100.0;
}

function titleCase(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function partyLabel(role: string, party: Dict): string {
  const organization = (party.organization_name as string) || titleCase(role);
  const did = (party.did as string) ?? "";
  return did ? `${organization} (${did})` : organization;
}

function getContact(party: Dict, signerContacts: Record<string, Dict> | null): Dict {
  const did = (party.did as string) ?? "";
  const contact = (signerContacts ?? {})[did] ?? {};
  const name = (contact.name as string) || (party.organization_name as string) || did;
  const email = (contact.email as string) || (party.email as string);
  if (!email) {
    throw new Error(`Missing signer email for party DID ${JSON.stringify(did)}.`);
  }
  return { name, email };
}

function termsSummaryText(record: Dict): string {
  const terms = (record.agreed_terms as Dict) ?? {};
  const parties = (record.parties as Dict) ?? {};
  const lines = [
    "A2CN Transaction Terms Summary",
    "",
    `Session ID: ${record.session_id ?? ""}`,
    `Record Hash: ${record.record_hash ?? ""}`,
    `Deal Type: ${record.deal_type ?? ""}`,
    `Currency: ${record.currency ?? terms.currency ?? ""}`,
    `Total Value: ${moneyToDecimal(terms.total_value ?? 0).toFixed(2)}`,
    "",
    "Parties:",
    `- Initiator: ${partyLabel("initiator", (parties.initiator as Dict) ?? {})}`,
    `- Responder: ${partyLabel("responder", (parties.responder as Dict) ?? {})}`,
    "",
    "Agreed Terms:",
  ];
  if (terms.seat_count !== null && terms.seat_count !== undefined) {
    lines.push(`- Seat count: ${terms.seat_count}`);
  }
  if (terms.subscription_tier) {
    lines.push(`- Subscription tier: ${terms.subscription_tier}`);
  }
  if (terms.term_months !== null && terms.term_months !== undefined) {
    lines.push(`- Term months: ${terms.term_months}`);
  }
  if (terms.delivery_days !== null && terms.delivery_days !== undefined) {
    lines.push(`- Delivery days: ${terms.delivery_days}`);
  }
  const paymentTerms = (terms.payment_terms as Dict) ?? {};
  if (paymentTerms.net_days !== null && paymentTerms.net_days !== undefined) {
    lines.push(`- Payment terms: Net ${paymentTerms.net_days}`);
  }
  if (terms.contract_duration) {
    const duration = terms.contract_duration as Dict;
    lines.push(
      `- Contract duration: ${duration.start_date ?? ""} to ${duration.end_date ?? ""}`,
    );
  }
  const lineItems = (terms.line_items as Dict[]) ?? [];
  if (lineItems.length > 0) {
    lines.push("");
    lines.push("Line Items:");
    for (const item of lineItems) {
      lines.push(
        "- " +
          `${item.description ?? ""}: ` +
          `qty ${item.quantity ?? 1}, ` +
          `unit ${moneyToDecimal(item.unit_price ?? 0).toFixed(2)}, ` +
          `total ${moneyToDecimal(item.total ?? 0).toFixed(2)}`,
      );
    }
  }
  lines.push("", "This document is generated from the A2CN dual-signed transaction record.", "\\s1\\", "\\s2\\");
  return lines.join("\n");
}

/**
 * Build a DocuSign eSignature envelope definition for an A2CN record.
 *
 * `signerContacts` maps party DID to `{"name": ..., "email": ...}`.
 * The record itself remains the canonical agreement; the envelope signs a
 * generated terms-summary document that references the A2CN record hash.
 */
export function a2cnRecordToDocusignEnvelope(
  record: Dict,
  signerContacts: Record<string, Dict>,
  options: { emailSubject?: string | null; status?: string; connectUrl?: string | null } = {},
): Dict {
  const { emailSubject = null, status = "sent", connectUrl = null } = options;
  const parties = (record.parties as Dict) ?? {};
  const initiator = (parties.initiator as Dict) ?? {};
  const responder = (parties.responder as Dict) ?? {};
  const initiatorContact = getContact(initiator, signerContacts);
  const responderContact = getContact(responder, signerContacts);
  const summaryText = termsSummaryText(record);
  const documentB64 = Buffer.from(summaryText, "utf-8").toString("base64");

  const envelope: Dict = {
    emailSubject: emailSubject ?? `A2CN agreement for session ${record.session_id ?? ""}`,
    status,
    documents: [
      {
        documentBase64: documentB64,
        name: "A2CN Transaction Terms Summary.txt",
        fileExtension: "txt",
        documentId: "1",
      },
    ],
    recipients: {
      signers: [
        {
          email: initiatorContact.email,
          name: initiatorContact.name,
          recipientId: "1",
          routingOrder: "1",
          tabs: {
            signHereTabs: [
              {
                anchorString: "\\s1\\",
                anchorUnits: "pixels",
                anchorXOffset: "0",
                anchorYOffset: "0",
              },
            ],
          },
        },
        {
          email: responderContact.email,
          name: responderContact.name,
          recipientId: "2",
          routingOrder: "1",
          tabs: {
            signHereTabs: [
              {
                anchorString: "\\s2\\",
                anchorUnits: "pixels",
                anchorXOffset: "0",
                anchorYOffset: "0",
              },
            ],
          },
        },
      ],
    },
    customFields: {
      textCustomFields: [
        {
          name: "a2cn_session_id",
          value: record.session_id ?? "",
          show: "false",
        },
        {
          name: "a2cn_record_hash",
          value: record.record_hash ?? "",
          show: "false",
        },
        {
          name: "a2cn_record_id",
          value: record.record_id ?? "",
          show: "false",
        },
      ],
    },
  };
  if (connectUrl) {
    envelope.eventNotification = {
      url: connectUrl,
      loggingEnabled: "true",
      requireAcknowledgment: "true",
      includeDocuments: "false",
      includeCertificateOfCompletion: "true",
      envelopeEvents: [
        { envelopeEventStatusCode: "completed" },
        { envelopeEventStatusCode: "declined" },
        { envelopeEventStatusCode: "voided" },
      ],
    };
  }
  return envelope;
}

/**
 * Parses DocuSign Connect webhook notifications into A2CN status updates.
 */
export class DocuSignConnectParser {
  static verifyHmacSignature(
    payloadBytes: Buffer | Uint8Array,
    signatureHeader: string,
    secret: string | Buffer,
  ): boolean {
    if (!payloadBytes || payloadBytes.length === 0 || !signatureHeader || !secret) {
      return false;
    }
    const key = typeof secret === "string" ? Buffer.from(secret, "utf-8") : secret;
    const expected = createHmac("sha256", key).update(payloadBytes).digest("base64");
    const candidates = signatureHeader
      .replaceAll(",", " ")
      .split(/\s+/)
      .map((part) => part.trim())
      .filter((part) => part.length > 0);
    const expectedBuf = Buffer.from(expected, "utf-8");
    return candidates.some((candidate) => {
      const candidateBuf = Buffer.from(candidate, "utf-8");
      return (
        candidateBuf.length === expectedBuf.length && timingSafeEqual(expectedBuf, candidateBuf)
      );
    });
  }

  /**
   * Parse a DocuSign Connect JSON payload into a post-commitment update.
   */
  static parseEnvelopeEvent(payload: Dict): Dict {
    const data = (payload.data as Dict) ?? {};
    const envelopeSummary =
      (data.envelopeSummary as Dict) ?? (payload.envelopeSummary as Dict) ?? {};
    const envelopeId =
      (data.envelopeId as string) ||
      (envelopeSummary.envelopeId as string) ||
      (payload.envelopeId as string) ||
      "";
    const status =
      (data.envelopeStatus as string) ||
      (envelopeSummary.status as string) ||
      (payload.status as string) ||
      (payload.event as string) ||
      "";
    const statusNormalized = normalizeEnvelopeStatus(status);
    const customFields = customFieldsFromPayload(data, envelopeSummary, payload);
    const eventName = (payload.event as string) || (payload.eventName as string) || "";
    return {
      provider: "docusign",
      event: eventName,
      envelope_id: envelopeId,
      envelope_status: statusNormalized,
      post_commitment_status: postCommitmentStatus(statusNormalized),
      a2cn_session_id: customFields.a2cn_session_id ?? "",
      a2cn_record_hash: customFields.a2cn_record_hash ?? "",
      completed: statusNormalized === "completed",
      raw_payload: payload,
    };
  }
}

function customFieldsFromPayload(...sections: Dict[]): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const section of sections) {
    const customFields = (section.customFields as Dict) ?? {};
    let textFields = customFields.textCustomFields ?? [];
    if (textFields !== null && typeof textFields === "object" && !Array.isArray(textFields)) {
      textFields = (textFields as Dict).textCustomField ?? [];
    }
    for (const item of (textFields as Dict[]) ?? []) {
      const name = item.name;
      const value = item.value;
      if (name) {
        fields[String(name)] = value === null || value === undefined ? "" : String(value);
      }
    }
  }
  return fields;
}

function normalizeEnvelopeStatus(status: unknown): string {
  let normalized = String(status).toLowerCase();
  if (normalized.startsWith("envelope-")) {
    normalized = normalized.slice("envelope-".length);
  }
  return normalized;
}

function postCommitmentStatus(envelopeStatus: string): string {
  if (envelopeStatus === "completed") {
    return "signature_completed";
  }
  if (envelopeStatus === "declined") {
    return "signature_declined";
  }
  if (envelopeStatus === "voided") {
    return "signature_voided";
  }
  return "signature_pending";
}

/**
 * Build the documented eSignature create-envelope request shape.
 */
export function docusignEnvelopeCreateRequest(
  accountId: string,
  envelopeDefinition: Dict,
  baseUri: string | null = null,
): Dict {
  const resolvedBaseUri = (baseUri || process.env.DOCUSIGN_BASE_URI || "").replace(/\/+$/, "");
  if (!resolvedBaseUri) {
    throw new Error("DOCUSIGN_BASE_URI or base_uri is required.");
  }
  return {
    method: "POST",
    url: `${resolvedBaseUri}/restapi/v2.1/accounts/${accountId}/envelopes`,
    json: envelopeDefinition,
  };
}

export function docusignAuthHeaders(accessToken: string): Dict {
  return {
    Authorization: `Bearer ${accessToken}`,
    Accept: "application/json",
    "Content-Type": "application/json",
  };
}

/**
 * Fetch a DocuSign OAuth JWT bearer token.
 */
export async function fetchDocusignAccessToken(
  authBaseUri: string | null = null,
  now: number | null = null,
  fetchFn: typeof fetch = fetch,
): Promise<string> {
  const integrationKey = process.env.DOCUSIGN_INTEGRATION_KEY;
  const userId = process.env.DOCUSIGN_USER_ID;
  const privateKeyPem = process.env.DOCUSIGN_PRIVATE_KEY;
  const scope = process.env.DOCUSIGN_SCOPE || "signature impersonation";
  const resolvedAuthBaseUri = (
    authBaseUri ||
    process.env.DOCUSIGN_AUTH_BASE_URI ||
    DOCUSIGN_DEMO_AUTH_BASE_URI
  ).replace(/\/+$/, "");
  if (!integrationKey || !userId || !privateKeyPem) {
    throw new Error(
      "DOCUSIGN_INTEGRATION_KEY, DOCUSIGN_USER_ID, and DOCUSIGN_PRIVATE_KEY are required.",
    );
  }

  const issuedAt = Math.trunc(now !== null ? now : Date.now() / 1000);
  const audience = resolvedAuthBaseUri.replace(/^https:\/\//, "");
  const key = createPrivateKey(privateKeyPem);
  const assertion = await new SignJWT({
    iss: integrationKey,
    sub: userId,
    aud: audience,
    iat: issuedAt,
    exp: issuedAt + 3600,
    scope,
  })
    .setProtectedHeader({ alg: "RS256" })
    .sign(key);

  const response = await fetchFn(`${resolvedAuthBaseUri}/oauth/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: DOCUSIGN_JWT_GRANT_TYPE,
      assertion,
    }),
    headers: { Accept: "application/json" },
  });
  if (response.status >= 400) {
    throw new Error(`DocuSign token request failed: HTTP ${response.status}`);
  }
  const body = (await response.json()) as Dict;
  return body.access_token as string;
}
