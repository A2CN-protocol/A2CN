/** Shared test fixtures and helpers (port of tests/conftest.py). */

import type { KeyObject } from "node:crypto";

import {
  createJwt,
  generateKeypair,
  generateEd25519Keypair,
  publicKeyToJwk,
} from "../src/a2cn/crypto.js";
import { createServerContext, type ServerContext } from "../src/a2cn/server.js";
import type { Dict } from "../src/a2cn/messages.js";

export const INITIATOR_DID = "did:web:techcorp.example";
export const RESPONDER_DID = "did:web:acme-corp.com";
export const SERVER_DID = "did:web:localhost";

/** Build a minimal W3C-compliant DID document. */
export function makeDidDocument(
  did: string,
  keyId: string,
  publicKeyJwk: Record<string, unknown>,
): Dict {
  const vmId = `${did}#${keyId}`;
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: vmId,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk,
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
}

export interface ResponderConfig {
  agent_info: Dict;
  mandate: Dict;
  deal_types: string[];
  max_rounds_by_deal_type: Record<string, number>;
  private_key: KeyObject;
  fulfillment_private_key: KeyObject;
  [key: string]: unknown;
}

export function makeResponderConfig(responderKeypair: {
  privateKey: KeyObject;
  publicKey: KeyObject;
}): ResponderConfig {
  const { privateKey } = responderKeypair;
  const { privateKey: fulfillmentPriv } = generateEd25519Keypair();
  return {
    agent_info: {
      organization_name: "Acme Corp",
      did: RESPONDER_DID,
      verification_method: `${RESPONDER_DID}#key-2026-01`,
      agent_id: "sales-agent-acme-007",
      endpoint: "http://localhost:8000",
    },
    mandate: {
      mandate_type: "declared",
      agent_id: "sales-agent-acme-007",
      principal_organization: "Acme Corp",
      principal_did: RESPONDER_DID,
      authorized_deal_types: ["saas_renewal"],
      max_commitment_value: 20_000_000,
      max_commitment_currency: "USD",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2026-12-31T00:00:00Z",
    },
    deal_types: ["saas_renewal"],
    max_rounds_by_deal_type: { saas_renewal: 5 },
    private_key: privateKey,
    fulfillment_private_key: fulfillmentPriv,
  };
}

/** Convenience: fresh initiator DID document for a keypair. */
export function makeInitiatorDidDoc(initiatorKeypair: {
  privateKey: KeyObject;
  publicKey: KeyObject;
}): Dict {
  return makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(initiatorKeypair.publicKey));
}

/** Convenience: fresh responder DID document for a keypair. */
export function makeResponderDidDoc(responderKeypair: {
  privateKey: KeyObject;
  publicKey: KeyObject;
}): Dict {
  return makeDidDocument(RESPONDER_DID, "key-2026-01", publicKeyToJwk(responderKeypair.publicKey));
}

let sessionInitCounter = 0;

export function makeSessionInit(messageId?: string | null): Dict {
  sessionInitCounter += 1;
  return {
    message_type: "session_init",
    message_id: messageId ?? `si-${Date.now()}-${sessionInitCounter}-${Math.random().toString(36).slice(2)}`,
    protocol_version: "0.2",
    session_params: {
      deal_type: "saas_renewal",
      currency: "USD",
      subject: "Test negotiation",
      max_rounds: 4,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
    },
    initiator: {
      organization_name: "TechCorp Inc",
      did: INITIATOR_DID,
      verification_method: `${INITIATOR_DID}#key-1`,
      agent_id: "test-agent",
      endpoint: "https://techcorp.example/api/a2cn",
    },
    initiator_mandate: {
      mandate_type: "declared",
      agent_id: "test-agent",
      principal_organization: "TechCorp Inc",
      principal_did: INITIATOR_DID,
      authorized_deal_types: ["saas_renewal"],
      max_commitment_value: 15_000_000,
      max_commitment_currency: "USD",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2026-12-31T00:00:00Z",
    },
  };
}

// ---------------------------------------------------------------------------
// Server test client (port of the httpx ASGI test_client fixtures)
// ---------------------------------------------------------------------------

export interface TestResponse {
  statusCode: number;
  headers: Record<string, string | string[] | number | undefined>;
  body: string;
  json(): Dict;
}

export interface TestClient {
  get(
    path: string,
    options?: { params?: Record<string, string | number>; headers?: Record<string, string> },
  ): Promise<TestResponse>;
  post(
    path: string,
    options?: { json?: unknown; headers?: Record<string, string> },
  ): Promise<TestResponse>;
}

interface BearerAuth {
  issuerDid: string;
  audienceDid: string;
  privateKey: KeyObject;
  kid: string;
}

/**
 * In-process test client over app.inject().
 * When `auth` is set, a fresh JWT (unique jti) is generated per request so
 * anti-replay never fires within a test (mirror of conftest._BearerAuth).
 */
export function makeTestClient(ctx: ServerContext, auth: BearerAuth | null = null): TestClient {
  async function authHeaders(): Promise<Record<string, string>> {
    if (!auth) {
      return {};
    }
    const token = await createJwt(auth.issuerDid, auth.audienceDid, auth.privateKey, {
      kid: auth.kid,
      expSeconds: 3600,
    });
    return { Authorization: `Bearer ${token}` };
  }

  function toResponse(res: {
    statusCode: number;
    headers: Record<string, string | string[] | number | undefined>;
    body: string;
  }): TestResponse {
    return {
      statusCode: res.statusCode,
      headers: res.headers,
      body: res.body,
      json: () => JSON.parse(res.body) as Dict,
    };
  }

  return {
    async get(path, options = {}) {
      const res = await ctx.app.inject({
        method: "GET",
        url: path,
        query: options.params
          ? Object.fromEntries(Object.entries(options.params).map(([k, v]) => [k, String(v)]))
          : undefined,
        headers: { ...(await authHeaders()), ...(options.headers ?? {}) },
      });
      return toResponse(res);
    },
    async post(path, options = {}) {
      const headers: Record<string, string> = {
        "Content-Type": "application/a2cn+json",
        ...(await authHeaders()),
        ...(options.headers ?? {}),
      };
      const res = await ctx.app.inject({
        method: "POST",
        url: path,
        payload: options.json !== undefined ? JSON.stringify(options.json) : "",
        headers,
      });
      return toResponse(res);
    },
  };
}

export interface ServerFixture {
  ctx: ServerContext;
  initiatorKeypair: { privateKey: KeyObject; publicKey: KeyObject };
  responderKeypair: { privateKey: KeyObject; publicKey: KeyObject };
  initiatorDidDoc: Dict;
  responderDidDoc: Dict;
  responderConfig: ResponderConfig;
  /** Authenticated as INITIATOR_DID (fresh JWT per request). */
  client: TestClient;
  /** No Authorization header — for negative auth tests. */
  rawClient: TestClient;
  /** Registers the responder DID doc, then returns a client authed as RESPONDER_DID. */
  makeResponderClient(): TestClient;
}

/**
 * Fresh server + fixtures (mirror of conftest test_client / raw_test_client /
 * responder_test_client). Each call is fully isolated.
 */
export function freshServer(): ServerFixture {
  const ctx = createServerContext();
  const initiatorKeypair = generateKeypair();
  const responderKeypair = generateKeypair();
  const initiatorDidDoc = makeInitiatorDidDoc(initiatorKeypair);
  const responderDidDoc = makeResponderDidDoc(responderKeypair);
  const responderConfig = makeResponderConfig(responderKeypair);

  ctx.configureResponder(responderConfig);
  ctx.SERVER_DID = SERVER_DID;
  ctx.registerDidDocument(INITIATOR_DID, initiatorDidDoc);

  const client = makeTestClient(ctx, {
    issuerDid: INITIATOR_DID,
    audienceDid: SERVER_DID,
    privateKey: initiatorKeypair.privateKey,
    kid: `${INITIATOR_DID}#key-1`,
  });
  const rawClient = makeTestClient(ctx, null);

  return {
    ctx,
    initiatorKeypair,
    responderKeypair,
    initiatorDidDoc,
    responderDidDoc,
    responderConfig,
    client,
    rawClient,
    makeResponderClient() {
      ctx.registerDidDocument(RESPONDER_DID, responderDidDoc);
      return makeTestClient(ctx, {
        issuerDid: RESPONDER_DID,
        audienceDid: SERVER_DID,
        privateKey: responderKeypair.privateKey,
        kid: `${RESPONDER_DID}#key-2026-01`,
      });
    },
  };
}

/** Build a fake fetch function serving canned JSON responses by URL. */
export function fakeFetch(
  routes: Record<string, { status: number; json?: unknown }>,
): (url: string) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }> {
  return async (url: string) => {
    const route = routes[url];
    if (!route) {
      throw new Error(`fakeFetch: no route for ${url}`);
    }
    return {
      ok: route.status >= 200 && route.status < 300,
      status: route.status,
      json: async () => route.json,
    };
  };
}
