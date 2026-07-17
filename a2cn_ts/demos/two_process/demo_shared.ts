/** Shared constants and helpers for the two-process A2CN HTTP demo. */

import { randomUUID, type KeyObject } from "node:crypto";

import {
  createJwt,
  createPublicKeyFromPrivate,
  hashObject,
  privateKeyFromJwk,
  publicKeyToJwk,
  signJws,
} from "../../src/a2cn/crypto.js";
import type { Session } from "../../src/a2cn/session.js";
import type { Dict } from "../../src/a2cn/messages.js";

export const BUYER_DID = "did:web:buyer.demo";
export const SUPPLIER_DID = "did:web:supplier.demo";

export const BUYER_PORT = 8001;
export const SUPPLIER_PORT = 8002;
export const BUYER_URL = `http://127.0.0.1:${BUYER_PORT}`;
export const SUPPLIER_URL = `http://127.0.0.1:${SUPPLIER_PORT}`;

export const BUYER_KEY_ID = `${BUYER_DID}#key-1`;
export const SUPPLIER_KEY_ID = `${SUPPLIER_DID}#key-1`;

// Demo-only keys. They are committed so the two separate demo processes can
// verify each other's JWTs without external DID hosting; never use them in
// production or for real counterparty authentication.
export const BUYER_PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "yBqAozmK34lgmawkZJiql8cV8mBdLvmyVH8AHrThJHo",
  y: "YlgfTYFme_XeFKLxzh0LLOKi-q7x6sqZAyGBVbglaX4",
  d: "XZJC7OiOPA9RvV6yobPgm1kZdg9htDWgIxXP0wDT6b0",
};

// Demo-only key; see warning above.
export const SUPPLIER_PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "6vLBotDYauSe6zbkEWMLxM84MYXIXbsvqRU-yfvdOAM",
  y: "iENZCpZVUyC63C9Y7fhtZ6z367TNAm1Iebia49zfGzY",
  d: "Fp0yOmzWBBlaSTbhggddYAZEt97_mGyjSI6BUBywS9k",
};

/** Build a token factory that mints a fresh A2CN ES256 bearer JWT per request. */
export function freshJwtFactory(
  issuerDid: string,
  audienceDid: string,
  privateKey: KeyObject,
  kid: string,
): () => Promise<string> {
  return () => createJwt(issuerDid, audienceDid, privateKey, { kid, expSeconds: 300 });
}

/** Wrap fetch so every request carries a fresh bearer JWT. */
export function authedFetch(tokenFactory: () => Promise<string>): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    const headers = {
      ...((init?.headers as Record<string, string>) ?? {}),
      Authorization: `Bearer ${await tokenFactory()}`,
    };
    return fetch(url, { ...init, headers });
  }) as typeof fetch;
}

export function buyerPrivateKey(): KeyObject {
  return privateKeyFromJwk(BUYER_PRIVATE_JWK);
}

export function supplierPrivateKey(): KeyObject {
  return privateKeyFromJwk(SUPPLIER_PRIVATE_JWK);
}

export function didDocument(did: string, keyId: string, privateKey: KeyObject): Dict {
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: publicKeyToJwk(createPublicKeyFromPrivate(privateKey)),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
  };
}

export function buyerAgentInfo(): Dict {
  return {
    organization_name: "TechCorp Inc",
    did: BUYER_DID,
    verification_method: BUYER_KEY_ID,
    agent_id: "procurement-agent-techcorp-demo",
    endpoint: BUYER_URL,
  };
}

export function supplierAgentInfo(): Dict {
  return {
    organization_name: "Acme Corp",
    did: SUPPLIER_DID,
    verification_method: SUPPLIER_KEY_ID,
    agent_id: "sales-agent-acme-demo",
    endpoint: SUPPLIER_URL,
  };
}

export function buyerMandate(): Dict {
  return {
    mandate_type: "declared",
    agent_id: "procurement-agent-techcorp-demo",
    principal_organization: "TechCorp Inc",
    principal_did: BUYER_DID,
    authorized_deal_types: ["saas_renewal"],
    max_commitment_value: 15_000_000,
    max_commitment_currency: "USD",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-12-31T00:00:00Z",
  };
}

export function supplierMandate(): Dict {
  return {
    mandate_type: "declared",
    agent_id: "sales-agent-acme-demo",
    principal_organization: "Acme Corp",
    principal_did: SUPPLIER_DID,
    authorized_deal_types: ["saas_renewal"],
    max_commitment_value: 20_000_000,
    max_commitment_currency: "USD",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-12-31T00:00:00Z",
  };
}

export function sessionParams(): Dict {
  return {
    deal_type: "saas_renewal",
    currency: "USD",
    subject: "Acme Analytics Platform - annual renewal FY2027",
    subject_reference: "CONTRACT-2024-ACME-001",
    estimated_value: 12_000_000,
    max_rounds: 4,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
  };
}

export function renewalTerms(totalValue: number, netDays: number): Dict {
  return {
    total_value: totalValue,
    currency: "USD",
    line_items: [
      {
        id: "li-1",
        description: "Acme Analytics Platform - 12 months",
        quantity: 1,
        unit: "year",
        unit_price: totalValue,
        total: totalValue,
      },
    ],
    payment_terms: { net_days: netDays },
    contract_duration: {
      start_date: "2026-07-01",
      end_date: "2027-06-30",
      auto_renewal: false,
      cancellation_notice_days: 60,
    },
  };
}

export function nowIso(offsetSeconds = 0): string {
  return new Date(Date.now() + offsetSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function supplierCounteroffer(session: Session, terms: Dict, inReplyTo: string): Dict {
  const sequenceNumber = session.sequence_number + 1;
  const roundNumber = session.round_number + 1;
  const messageId = randomUUID();
  const timestamp = nowIso();
  const expiresAt = nowIso(900);
  const privateKey = supplierPrivateKey();
  const protocolAct = {
    protocol_version: "0.2",
    session_id: session.session_id,
    round_number: roundNumber,
    sequence_number: sequenceNumber,
    message_type: "counteroffer",
    sender_did: SUPPLIER_DID,
    timestamp,
    expires_at: expiresAt,
    terms,
  };
  const protocolActHash = hashObject(protocolAct);
  return {
    message_type: "counteroffer",
    message_id: messageId,
    session_id: session.session_id,
    in_reply_to: inReplyTo,
    round_number: roundNumber,
    sequence_number: sequenceNumber,
    sender_did: SUPPLIER_DID,
    sender_agent_id: supplierAgentInfo().agent_id,
    sender_verification_method: SUPPLIER_KEY_ID,
    timestamp,
    expires_at: expiresAt,
    terms,
    protocol_act_hash: protocolActHash,
    protocol_act_signature: signJws(protocolActHash, privateKey, SUPPLIER_KEY_ID),
  };
}
