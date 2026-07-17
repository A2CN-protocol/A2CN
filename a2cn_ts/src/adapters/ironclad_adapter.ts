/**
 * Ironclad CLM -> A2CN translation layer.
 *
 * Translates Ironclad workflow/webhook payloads into A2CN terms, and translates
 * completed A2CN terms back into Ironclad workflow metadata updates.
 *
 * Ironclad public API references used for this adapter:
 *   Docs index:        https://developer.ironcladapp.com/llms.txt
 *   Retrieve workflow: GET   /public/api/v1/workflows/{id}
 *   Update metadata:   PATCH /public/api/v1/workflows/{id}/attributes
 *   Create record:     POST  /public/api/v1/records
 *   Webhooks:          GET   /public/api/v1/webhooks/verification-key
 *
 * No core protocol changes are required; this module is a platform translation
 * layer with deterministic helpers and optional HTTP write-back.
 */

import { createPublicKey, verify as cryptoVerify } from "node:crypto";

import type { Dict } from "../a2cn/messages.js";

const SAAS_KEYWORDS = ["renewal", "subscription", "license", "seat", "saas"];

function moneyToCents(value: unknown): number {
  if (value === null || value === undefined || value === "") {
    return 0;
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    value = (value as Dict).amount ?? 0;
  }
  return Math.trunc(Number(value) * 100);
}

function intValue(value: unknown, defaultValue = 0): number {
  if (value === null || value === undefined || value === "") {
    return defaultValue;
  }
  return Math.trunc(Number(value));
}

function field(attributes: Dict, names: string[], defaultValue: unknown = null): unknown {
  for (const name of names) {
    if (name in attributes) {
      return attributes[name];
    }
  }
  return defaultValue;
}

/**
 * Match the compact JSON.stringify(body) form used in Ironclad's example.
 */
function jsonStringifyBody(body: Dict): string {
  return JSON.stringify(body);
}

function dealTypeFromWorkflow(workflow: Dict): string {
  const haystack = [
    workflow.title ?? "",
    workflow.template ?? "",
    workflow.workflowType ?? "",
    workflow.type ?? "",
  ]
    .map((part) => String(part).toLowerCase())
    .join(" ");
  return SAAS_KEYWORDS.some((key) => haystack.includes(key)) ? "saas_renewal" : "goods_procurement";
}

/**
 * Verifies and translates Ironclad workflow webhook payloads.
 *
 * Ironclad signs webhooks with a verification header containing nonce,
 * signAlgorithm, signature, and encoding. The signed payload is:
 * X-Ironclad-Webhook-Event-Id + JSON.stringify(body) + nonce.
 */
export class IroncladWebhookParser {
  static verifyWebhookSignature(
    eventId: string,
    verificationHeader: string,
    body: Dict,
    publicKeyPem: string | Buffer,
  ): boolean {
    if (!eventId || !verificationHeader || !publicKeyPem) {
      return false;
    }
    try {
      const verification = JSON.parse(verificationHeader) as Dict;
      if (!("nonce" in verification) || !("signAlgorithm" in verification) || !("signature" in verification)) {
        return false;
      }
      const nonce = verification.nonce;
      const algorithm = String(verification.signAlgorithm).toUpperCase().replaceAll("-", "");
      const signature = verification.signature as string;
      const encoding = String(verification.encoding ?? "base64").toLowerCase();
      let signatureBytes: Buffer;
      if (encoding === "base64") {
        signatureBytes = Buffer.from(signature, "base64");
      } else if (encoding === "hex") {
        signatureBytes = Buffer.from(signature, "hex");
      } else {
        return false;
      }
      if (algorithm !== "RSASHA256" && algorithm !== "SHA256") {
        return false;
      }

      const publicKey = createPublicKey(
        typeof publicKeyPem === "string" ? publicKeyPem : publicKeyPem.toString("utf-8"),
      );
      const signedData = Buffer.from(eventId + jsonStringifyBody(body) + String(nonce), "utf-8");
      return cryptoVerify("sha256", signedData, publicKey, signatureBytes);
    } catch {
      return false;
    }
  }

  /**
   * Translate an Ironclad workflow event into A2CN session params and terms.
   *
   * Accepts either a full workflow object or a webhook wrapper containing
   * `workflow` / `data`. Workflow attributes follow the shape returned by
   * Ironclad's Retrieve Workflow endpoint.
   */
  static workflowEventToSessionInputs(
    payload: Dict,
    maxRounds = 5,
    defaultDeliveryDays = 14,
  ): Dict {
    const workflow = ((payload.workflow ?? payload.data) as Dict) ?? payload;
    const attributes = (workflow.attributes as Dict) ?? {};
    const dealType = dealTypeFromWorkflow(workflow);

    const counterparty = field(attributes, ["counterpartyName", "counterparty", "vendorName"], "");
    let currency = field(attributes, ["currency"], null);
    const amount = field(attributes, ["contractValue", "amount", "fee", "totalValue"], 0);
    if (amount !== null && typeof amount === "object" && !Array.isArray(amount)) {
      currency = (amount as Dict).currency ?? currency;
    }
    currency = currency || "USD";
    const totalCents = moneyToCents(amount);
    const seatCount = Math.max(intValue(field(attributes, ["seatCount", "seat_count"], 1), 1), 1);
    const termMonths = Math.max(intValue(field(attributes, ["termMonths", "term_months"], 12), 12), 1);
    const product = field(
      attributes,
      ["product", "productName", "subscriptionTier"],
      workflow.title ?? "Ironclad workflow",
    );

    const terms: Dict = {
      deal_type: dealType,
      total_value: totalCents,
      currency,
      line_items: [
        {
          description: product,
          quantity: dealType === "saas_renewal" ? seatCount : 1,
          unit_price:
            dealType === "saas_renewal"
              ? Math.trunc(totalCents / Math.max(seatCount, 1))
              : totalCents,
          total: totalCents,
        },
      ],
      payment_terms: {
        net_days: intValue(field(attributes, ["paymentTermsNetDays", "netDays"], 30), 30),
      },
      custom_terms: {
        ironclad: {
          workflow_id: workflow.id ?? payload.workflowId ?? "",
          ironclad_id: workflow.ironcladId ?? "",
          counterparty_name: counterparty,
        },
      },
    };
    if (dealType === "saas_renewal") {
      terms.seat_count = seatCount;
      terms.subscription_tier = String(product);
      terms.term_months = termMonths;
    } else {
      terms.delivery_days = intValue(
        field(attributes, ["deliveryDays", "delivery_days"], defaultDeliveryDays),
        defaultDeliveryDays,
      );
    }

    const sessionParams: Dict = {
      deal_type: dealType,
      currency,
      max_rounds: maxRounds,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
      ironclad_workflow_id: workflow.id ?? payload.workflowId ?? "",
      ironclad_id: workflow.ironcladId ?? "",
      counterparty_name: counterparty,
    };

    return {
      event_id: payload.eventId ?? payload.event_id ?? "",
      event_type: payload.eventType ?? payload.event_type ?? "",
      workflow_id: sessionParams.ironclad_workflow_id,
      session_params: sessionParams,
      initial_terms: terms,
      raw_payload: payload,
    };
  }
}

/**
 * Build the PATCH /workflows/{id}/attributes payload for agreed A2CN terms.
 *
 * Ironclad requires an `updates` array with `set` or `remove` actions.
 * Field keys are configurable because workflow attribute IDs are tenant and
 * template specific.
 */
export function a2cnTermsToIroncladWorkflow(
  agreedTerms: Dict,
  workflowId: string,
  a2cnSessionId: string,
  recordHash: string,
  fieldMap: Dict | null = null,
): Dict {
  const fields: Record<string, string> = {
    contract_value: "contractValue",
    currency: "currency",
    term_months: "termMonths",
    counterparty_name: "counterpartyName",
    a2cn_session_id: "a2cnSessionId",
    a2cn_record_hash: "a2cnRecordHash",
    payment_terms_net_days: "paymentTermsNetDays",
    ...((fieldMap as Record<string, string>) ?? {}),
  };
  const ironcladMeta = (((agreedTerms.custom_terms as Dict) ?? {}).ironclad as Dict) ?? {};
  const updates: Dict[] = [
    {
      action: "set",
      path: fields.contract_value,
      value: {
        currency: agreedTerms.currency ?? "USD",
        amount: ((agreedTerms.total_value as number) ?? 0) / 100.0,
      },
    },
    { action: "set", path: fields.currency, value: agreedTerms.currency ?? "USD" },
    { action: "set", path: fields.a2cn_session_id, value: a2cnSessionId },
    { action: "set", path: fields.a2cn_record_hash, value: recordHash },
    {
      action: "set",
      path: fields.payment_terms_net_days,
      value: ((agreedTerms.payment_terms as Dict) ?? {}).net_days ?? 30,
    },
  ];
  if (agreedTerms.term_months !== null && agreedTerms.term_months !== undefined) {
    updates.push({
      action: "set",
      path: fields.term_months,
      value: agreedTerms.term_months,
    });
  }
  if (ironcladMeta.counterparty_name) {
    updates.push({
      action: "set",
      path: fields.counterparty_name,
      value: ironcladMeta.counterparty_name,
    });
  }

  return {
    workflow_id: workflowId,
    endpoint: `/workflows/${workflowId}/attributes`,
    payload: {
      updates,
      comment:
        `A2CN negotiation completed. Session ${a2cnSessionId}; ` +
        `record hash ${recordHash}.`,
    },
  };
}

/**
 * Build the POST /records payload for formalizing an A2CN transaction record.
 */
export function a2cnTermsToIroncladRecord(
  agreedTerms: Dict,
  recordType: string,
  name: string,
  a2cnSessionId: string,
  recordHash: string,
): Dict {
  const ironcladMeta = (((agreedTerms.custom_terms as Dict) ?? {}).ironclad as Dict) ?? {};
  return {
    type: recordType,
    name,
    properties: {
      counterpartyName: {
        type: "string",
        value: ironcladMeta.counterparty_name ?? "",
      },
      contractValue: {
        type: "monetary_amount",
        value: {
          currency: agreedTerms.currency ?? "USD",
          amount: ((agreedTerms.total_value as number) ?? 0) / 100.0,
        },
      },
      a2cnSessionId: { type: "string", value: a2cnSessionId },
      a2cnRecordHash: { type: "string", value: recordHash },
    },
  };
}

/**
 * Submit an Ironclad workflow metadata update using IRONCLAD_API_TOKEN.
 */
export async function updateIroncladWorkflowMetadata(
  workflowId: string,
  updatePayload: Dict,
  asUserEmail: string | null = null,
  fetchFn: typeof fetch = fetch,
): Promise<Dict> {
  const token = process.env.IRONCLAD_API_TOKEN;
  const baseUrl = process.env.IRONCLAD_BASE_URL ?? "https://na1.ironcladapp.com/public/api/v1";
  const actorEmail = asUserEmail || process.env.IRONCLAD_AS_USER_EMAIL;
  if (!token) {
    throw new Error("IRONCLAD_API_TOKEN environment variable is required.");
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
  if (actorEmail) {
    headers["x-as-user-email"] = actorEmail;
  }

  const url = `${baseUrl.replace(/\/+$/, "")}/workflows/${workflowId}/attributes`;
  const response = await fetchFn(url, {
    method: "PATCH",
    body: JSON.stringify(updatePayload),
    headers,
  });
  if (response.status >= 400) {
    throw new Error(`Ironclad metadata update failed: HTTP ${response.status}`);
  }
  return (await response.json()) as Dict;
}
