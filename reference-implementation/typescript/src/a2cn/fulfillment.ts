/**
 * Concordia FulfillmentAttestation composition helpers.
 *
 * The A2CN session remains the agreement pointer; this module emits the
 * Concordia-shaped fulfillment artifact that downstream Concordia tooling can
 * verify.
 */

import { randomUUID, sign as cryptoSign } from "node:crypto";

import { canonicalize, b64urlEncode, isEd25519, type SigningPrivateKey } from "./crypto.js";
import type { Dict } from "./messages.js";

export const FULFILLMENT_ATTESTATION_SCHEMA: Dict = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "urn:concordia:schema:fulfillment_attestation:v0.5",
  title: "Concordia Fulfillment Attestation",
  description:
    "A standalone signed artifact emitted after settlement, recording whether " +
    "an agreement was honored. Distinct from the in-line `fulfillment` block " +
    "on a reputation attestation (SPEC.md Section 9.6.4) - this is the A2CN-aligned " +
    "shape emitted on a discrete DELIVERY_ACKNOWLEDGED boundary, linking back " +
    "to the agreement attestation via `references[]` with `relationship: " +
    '"fulfills"`. Introduced in v0.5 per A2A Discussion #1737. See ' +
    "docs/A2CN_FULFILLMENT.md for the integrator walkthrough and SPEC.md " +
    "Section 9.6.4 for the relationship with the in-line fulfillment block.",
  type: "object",
  required: [
    "attestation_type",
    "id",
    "issued_at",
    "agreement_attestation_id",
    "fulfillment",
    "references",
    "signature",
  ],
  properties: {
    attestation_type: { type: "string", const: "FulfillmentAttestation" },
    id: { type: "string", minLength: 1 },
    issued_at: { type: "string", format: "date-time" },
    agreement_attestation_id: { type: "string", minLength: 1 },
    fulfillment: {
      type: "object",
      required: ["status"],
      additionalProperties: true,
      properties: {
        status: {
          type: "string",
          enum: ["fulfilled_clean", "fulfilled_with_mediation", "failed", "disputed_unresolved"],
        },
        settled_at: { type: "string", format: "date-time" },
      },
    },
    references: {
      type: "array",
      minItems: 1,
      contains: {
        type: "object",
        required: ["relationship"],
        properties: { relationship: { const: "fulfills" } },
      },
      items: {
        type: "object",
        required: ["id", "type", "relationship"],
        properties: {
          id: { type: "string" },
          type: { type: "string" },
          relationship: { type: "string" },
        },
        additionalProperties: true,
      },
    },
    meta: {
      type: "object",
      additionalProperties: true,
      properties: {
        mediator_invoked: { type: "boolean" },
        resolution_outcome: { type: "string" },
        resolver_did: { type: "string" },
        resolution_timestamp: { type: "string", format: "date-time" },
        fulfillment_evidence: { type: "array", items: { type: "string" } },
      },
    },
    signature: {
      type: "object",
      required: ["alg", "value"],
      additionalProperties: true,
      properties: {
        alg: { type: "string", enum: ["Ed25519"] },
        value: { type: "string", minLength: 1 },
        signer_did: { type: "string" },
      },
    },
  },
  allOf: [
    {
      if: {
        properties: {
          fulfillment: {
            properties: { status: { const: "fulfilled_with_mediation" } },
            required: ["status"],
          },
        },
        required: ["fulfillment"],
      },
      then: {
        properties: {
          meta: {
            type: "object",
            properties: { mediator_invoked: { const: true } },
            required: ["mediator_invoked"],
          },
        },
        required: ["meta"],
      },
    },
  ],
  additionalProperties: true,
};

/**
 * Build and Ed25519-sign a Concordia FulfillmentAttestation.
 *
 * `sessionRecord["session_id"]` is used as Concordia's
 * agreement_attestation_id pointer for the A2CN composition.
 */
export function buildFulfillmentAttestation(
  sessionRecord: Dict,
  options: {
    privateKey: SigningPrivateKey;
    signerDid?: string | null;
    disputeResolvedMessage?: Dict | null;
    issuedAt?: string | null;
  },
): Dict {
  const { privateKey, signerDid = null, disputeResolvedMessage = null, issuedAt = null } = options;
  if (!isEd25519(privateKey)) {
    throw new Error("FulfillmentAttestation signing requires an Ed25519 private key");
  }

  const sessionId = sessionRecord.session_id;
  if (typeof sessionId !== "string" || !sessionId) {
    throw new Error("session_record must include a non-empty session_id");
  }

  const now = issuedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const fulfillment: Dict = {
    status: fulfillmentStatus(disputeResolvedMessage),
  };

  let settledAt: unknown;
  if (disputeResolvedMessage !== null) {
    settledAt = disputeResolvedMessage.resolution_timestamp;
  } else {
    const deliveryAck = (sessionRecord.delivery_acknowledged as Dict) ?? {};
    settledAt = deliveryAck.acknowledgment_timestamp;
  }
  if (typeof settledAt === "string" && settledAt) {
    fulfillment.settled_at = settledAt;
  }

  const attestation: Dict = {
    attestation_type: "FulfillmentAttestation",
    id: `urn:concordia:fulfillment:${randomUUID()}`,
    issued_at: now,
    agreement_attestation_id: sessionId,
    fulfillment,
    references: [
      { type: "receipt", id: sessionId, relationship: "fulfills" },
      {
        type: "chain_session",
        id: `urn:a2cn:session:${sessionId}`,
        relationship: "references",
      },
    ],
  };

  const meta = metaFromDisputeResolution(disputeResolvedMessage);
  if (meta) {
    attestation.meta = meta;
  }

  attestation.signature = signAttestation(attestation, privateKey, signerDid);
  validateFulfillmentAttestation(attestation);
  return attestation;
}

/**
 * Validate the structural requirements of the Concordia schema.
 * (Mirrors the Python module's optional jsonschema validation.)
 */
export function validateFulfillmentAttestation(attestation: Dict): void {
  const required = [
    "attestation_type",
    "id",
    "issued_at",
    "agreement_attestation_id",
    "fulfillment",
    "references",
    "signature",
  ];
  for (const key of required) {
    if (!(key in attestation)) {
      throw new Error(`FulfillmentAttestation missing required field: ${key}`);
    }
  }
  if (attestation.attestation_type !== "FulfillmentAttestation") {
    throw new Error("attestation_type must be 'FulfillmentAttestation'");
  }
  const fulfillment = attestation.fulfillment as Dict;
  const validStatuses = [
    "fulfilled_clean",
    "fulfilled_with_mediation",
    "failed",
    "disputed_unresolved",
  ];
  if (!validStatuses.includes(fulfillment.status as string)) {
    throw new Error(`Invalid fulfillment status: ${String(fulfillment.status)}`);
  }
  const references = attestation.references as Dict[];
  if (!Array.isArray(references) || references.length < 1) {
    throw new Error("references must be a non-empty array");
  }
  if (!references.some((ref) => ref.relationship === "fulfills")) {
    throw new Error("references must contain a 'fulfills' relationship");
  }
  const signature = attestation.signature as Dict;
  if (signature.alg !== "Ed25519" || !signature.value) {
    throw new Error("signature must have alg 'Ed25519' and a non-empty value");
  }
  if (fulfillment.status === "fulfilled_with_mediation") {
    const meta = attestation.meta as Dict | undefined;
    if (!meta || meta.mediator_invoked !== true) {
      throw new Error("fulfilled_with_mediation requires meta.mediator_invoked = true");
    }
  }
}

function fulfillmentStatus(disputeResolvedMessage: Dict | null): string {
  if (disputeResolvedMessage === null) {
    return "fulfilled_clean";
  }

  const outcome = disputeResolvedMessage.resolution_outcome;
  if (["buyer_prevails", "seller_prevails", "mutual_settlement"].includes(outcome as string)) {
    return "fulfilled_with_mediation";
  }
  throw new Error(
    `Unsupported resolution_outcome for fulfillment attestation: ${JSON.stringify(outcome)}`,
  );
}

function metaFromDisputeResolution(disputeResolvedMessage: Dict | null): Dict | null {
  if (disputeResolvedMessage === null) {
    return null;
  }

  const meta: Dict = { mediator_invoked: true };
  const mappings: Array<[string, string]> = [
    ["resolution_outcome", "resolution_outcome"],
    ["resolver_did", "resolver_did"],
    ["resolution_timestamp", "resolution_timestamp"],
    ["evidence_references", "fulfillment_evidence"],
  ];
  for (const [sourceKey, targetKey] of mappings) {
    const value = disputeResolvedMessage[sourceKey];
    const truthy = Array.isArray(value) ? value.length > 0 : Boolean(value);
    if (truthy) {
      meta[targetKey] = value;
    }
  }
  return meta;
}

function signAttestation(
  attestation: Dict,
  privateKey: SigningPrivateKey,
  signerDid: string | null,
): Dict {
  const unsigned: Dict = structuredClone(attestation);
  delete unsigned.signature;
  const signature: Dict = {
    alg: "Ed25519",
    value: b64urlEncode(cryptoSign(null, canonicalize(unsigned), privateKey)),
  };
  if (signerDid) {
    signature.signer_did = signerDid;
  }
  return signature;
}
