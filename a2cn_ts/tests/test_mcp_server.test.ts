/**
 * Tests for mcp_server — six A2CN MCP tools.
 *
 * All outgoing HTTP calls are routed through an injectable fake fetch so no
 * real server is needed. Each test builds a fresh context (fresh session store).
 */

import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";

import { createMcpContext, type McpContext } from "../src/mcp_server.js";
import { A2CNClient } from "../src/a2cn/client.js";
import type { Dict } from "../src/a2cn/messages.js";

// ---------------------------------------------------------------------------
// Constants shared across tests
// ---------------------------------------------------------------------------

const COUNTERPARTY_DID = "did:web:acme-corp.com";
const BASE_URL = "https://acme-corp.com";
const SESSION_ID = "test-session-00000000-0000-0000-0000";

const DISCOVERY_DOC: Dict = {
  a2cn_version: "0.2",
  agent_did: COUNTERPARTY_DID,
  conformance_level: 2,
  deal_types: ["saas_renewal"],
  mandate_methods: ["declared"],
  endpoint: BASE_URL,
  agent_id: "sales-agent-acme-007",
  verification_method: `${COUNTERPARTY_DID}#key-1`,
};

const SESSION_ACK: Dict = {
  message_type: "session_ack",
  message_id: randomUUID(),
  session_id: SESSION_ID,
  in_reply_to: "init-001",
  protocol_version: "0.2",
  session_params_accepted: {
    deal_type: "saas_renewal",
    currency: "USD",
    max_rounds: 6,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
  },
  responder: {
    organization_name: "Acme Corp",
    did: COUNTERPARTY_DID,
    verification_method: `${COUNTERPARTY_DID}#key-1`,
    agent_id: "sales-agent-acme-007",
    endpoint: BASE_URL,
  },
  responder_mandate: { mandate_type: "declared" },
  session_created_at: "2026-04-01T10:00:00Z",
  current_turn: "initiator",
};

const SAMPLE_CP_OFFER: Dict = {
  message_id: "seller-offer-001",
  message_type: "counteroffer",
  session_id: SESSION_ID,
  sequence_number: 2,
  round_number: 2,
  sender_did: COUNTERPARTY_DID,
  terms: {
    total_value: 11_500_000,
    currency: "USD",
    payment_terms: { net_days: 30 },
  },
  protocol_act_hash: "def456abc",
  protocol_act_signature: "eyJ...",
  timestamp: "2026-04-01T10:01:00Z",
  expires_at: "2030-01-01T00:00:00Z",
};

const TRANSACTION_RECORD: Dict = {
  record_id: `rec-${SESSION_ID}`,
  session_id: SESSION_ID,
  record_hash: `sha256-${"a".repeat(40)}`,
  generated_at: "2026-04-01T10:03:00Z",
  outcome: "COMPLETED",
};

// ---------------------------------------------------------------------------
// Fake fetch routing
// ---------------------------------------------------------------------------

type Route = {
  method: string;
  pattern: RegExp;
  status: number;
  json?: unknown;
  error?: Error;
};

function routedFetch(routes: Route[]): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const urlStr = String(url);
    for (const route of routes) {
      if (route.method === method && route.pattern.test(urlStr)) {
        if (route.error) {
          throw route.error;
        }
        return new Response(route.json !== undefined ? JSON.stringify(route.json) : null, {
          status: route.status,
          headers: { "Content-Type": "application/a2cn+json" },
        });
      }
    }
    throw new Error(`routedFetch: no route for ${method} ${urlStr}`);
  }) as typeof fetch;
}

/**
 * Inject a fake session into ctx.sessions.
 *
 * Used by tests that need an active session without going through
 * a2cn_initiate_session (which requires full HTTP mocking).
 */
function seedSession(
  ctx: McpContext,
  options: { sessionId?: string; status?: string; cpOffer?: Dict | null } = {},
): void {
  const { sessionId = SESSION_ID, status = "NEGOTIATING", cpOffer = null } = options;

  const client = new A2CNClient({
    agentInfo: {
      organization_name: "Test Buyer",
      did: ctx.agentDid,
      verification_method: `${ctx.agentDid}#key-1`,
      agent_id: "test-buyer",
      endpoint: "https://test-buyer.example",
    },
    privateKey: ctx.privateKey,
    mandate: { mandate_type: "declared" },
    fetchFn: ctx.fetchFn,
  });
  // Bootstrap the client's internal session state
  client._sessions[sessionId] = {
    session_init: {},
    session_ack: SESSION_ACK,
    sequence_number: 1,
    round_number: 1,
    latest_offer: {
      message_id: "offer-001",
      message_type: "offer",
      terms: {
        total_value: 9_500_000,
        currency: "USD",
        payment_terms: { net_days: 30 },
      },
      protocol_act_hash: "abc123",
    },
    offer_chain: ["abc123"],
    message_log: [],
    current_turn: "responder",
  };

  ctx.sessions[sessionId] = {
    client,
    endpoint: BASE_URL,
    counterparty_did: COUNTERPARTY_DID,
    deal_type: "saas_renewal",
    session_ack: SESSION_ACK,
    my_did: ctx.agentDid,
    my_last_offer_cents: 9_500_000,
    my_last_offer_net_days: 30,
    counterparty_last_offer_cents: cpOffer
      ? (((cpOffer.terms as Dict).total_value as number) ?? null)
      : null,
    counterparty_last_offer_net_days: cpOffer
      ? (((((cpOffer.terms as Dict).payment_terms as Dict) ?? {}).net_days as number) ?? null)
      : null,
    counterparty_last_offer_message: cpOffer,
    round_number: 1,
    status,
    transaction_record: null,
    tokenFactory: null,
  };
}

// ---------------------------------------------------------------------------
// Tool 1: a2cn_discover
// ---------------------------------------------------------------------------

test("discover a2cn capable", async () => {
  // Valid A2CN endpoint returns capability document.
  const ctx = createMcpContext({
    fetchFn: routedFetch([
      {
        method: "GET",
        pattern: new RegExp(`${BASE_URL}/.well-known/a2cn-agent`),
        status: 200,
        json: DISCOVERY_DOC,
      },
    ]),
  });
  const result = await ctx.a2cnDiscover(COUNTERPARTY_DID);

  expect(result.a2cn_capable).toBe(true);
  expect(result.a2cn_version).toBe("0.2");
  expect(result.conformance_level).toBe(2);
  expect(result.deal_types).toContain("saas_renewal");
  expect(result.agent_did).toBe(COUNTERPARTY_DID);
});

test("discover not a2cn capable 404", async () => {
  // 404 on discovery endpoint → not_a2cn_capable error.
  const ctx = createMcpContext({
    fetchFn: routedFetch([
      { method: "GET", pattern: new RegExp(`${BASE_URL}/.well-known/a2cn-agent`), status: 404 },
    ]),
  });
  const result = await ctx.a2cnDiscover(COUNTERPARTY_DID);

  expect(result.error).toBe("not_a2cn_capable");
});

test("discover unreachable endpoint", async () => {
  // Network error → discovery_failed error.
  const ctx = createMcpContext({
    fetchFn: routedFetch([
      {
        method: "GET",
        pattern: new RegExp(`${BASE_URL}/.well-known/a2cn-agent`),
        status: 0,
        error: new Error("Connection refused"),
      },
    ]),
  });
  const result = await ctx.a2cnDiscover(COUNTERPARTY_DID);

  expect("error" in result).toBe(true);
  expect(["discovery_failed", "not_a2cn_capable"]).toContain(result.error);
});

test("discover invalid did", async () => {
  // Non-DID-web identifier → invalid_did error, no HTTP call.
  const ctx = createMcpContext();
  const result = await ctx.a2cnDiscover("mailto:agent@example.com");
  expect(result.error).toBe("invalid_did");
});

// ---------------------------------------------------------------------------
// Tool 2: a2cn_initiate_session
// ---------------------------------------------------------------------------

test("initiate session success", async () => {
  // Full happy path: discovery → POST /sessions → POST /sessions/{id}/messages.
  const ctx = createMcpContext({
    fetchFn: routedFetch([
      {
        method: "GET",
        pattern: new RegExp(`${BASE_URL}/.well-known/a2cn-agent`),
        status: 200,
        json: DISCOVERY_DOC,
      },
      {
        method: "POST",
        pattern: new RegExp(`${BASE_URL}/sessions/.+/messages`),
        status: 200,
        json: { status: "received" },
      },
      { method: "POST", pattern: new RegExp(`${BASE_URL}/sessions$`), status: 201, json: SESSION_ACK },
    ]),
  });

  const result = await ctx.a2cnInitiateSession({
    counterparty_did: COUNTERPARTY_DID,
    deal_type: "saas_renewal",
    my_did: ctx.agentDid,
    initial_offer_total_value_cents: 9_500_000,
    currency: "USD",
    max_rounds: 6,
    payment_terms_net_days: 30,
    subject: "Test negotiation",
  });

  expect("error" in result).toBe(false);
  expect(result.status).toBe("ACTIVE");
  const sid = result.session_id as string;
  expect(sid in ctx.sessions).toBe(true);
  const entry = ctx.sessions[sid];
  expect(entry.status).toBe("NEGOTIATING");
  expect(entry.my_last_offer_cents).toBe(9_500_000);
  expect(entry.deal_type).toBe("saas_renewal");
});

test("initiate session invalid deal type", async () => {
  // Unsupported deal_type → error without any HTTP call.
  const ctx = createMcpContext();
  const result = await ctx.a2cnInitiateSession({
    counterparty_did: COUNTERPARTY_DID,
    deal_type: "freight_rate",
    my_did: ctx.agentDid,
    initial_offer_total_value_cents: 9_500_000,
    currency: "USD",
    max_rounds: 6,
    payment_terms_net_days: 30,
    subject: "Invalid deal type test",
  });
  expect(result.error).toBe("invalid_deal_type");
  expect(Object.keys(ctx.sessions).length).toBe(0);
});

test("initiate session invalid max rounds", async () => {
  // max_rounds outside 1-20 → error.
  const ctx = createMcpContext();
  const result = await ctx.a2cnInitiateSession({
    counterparty_did: COUNTERPARTY_DID,
    deal_type: "saas_renewal",
    my_did: ctx.agentDid,
    initial_offer_total_value_cents: 9_500_000,
    currency: "USD",
    max_rounds: 25,
    payment_terms_net_days: 30,
    subject: "Max rounds test",
  });
  expect(result.error).toBe("invalid_max_rounds");
});

test("initiate session server error", async () => {
  // Server returns 403 → session_init_failed, no session stored.
  const ctx = createMcpContext({
    fetchFn: routedFetch([
      {
        method: "GET",
        pattern: new RegExp(`${BASE_URL}/.well-known/a2cn-agent`),
        status: 200,
        json: DISCOVERY_DOC,
      },
      {
        method: "POST",
        pattern: new RegExp(`${BASE_URL}/sessions$`),
        status: 403,
        json: { error: { code: "DEAL_TYPE_NOT_SUPPORTED" } },
      },
    ]),
  });

  const result = await ctx.a2cnInitiateSession({
    counterparty_did: COUNTERPARTY_DID,
    deal_type: "saas_renewal",
    my_did: ctx.agentDid,
    initial_offer_total_value_cents: 9_500_000,
    currency: "USD",
    max_rounds: 6,
    payment_terms_net_days: 30,
    subject: "Server error test",
  });

  expect(result.error).toBe("session_init_failed");
  expect(Object.keys(ctx.sessions).length).toBe(0);
});

// ---------------------------------------------------------------------------
// Tool 3: a2cn_send_offer
// ---------------------------------------------------------------------------

test("send offer success", async () => {
  // Active session + mocked server → offer sent, round_number incremented.
  const ctx = createMcpContext({
    fetchFn: routedFetch([
      {
        method: "POST",
        pattern: new RegExp(`${BASE_URL}/sessions/.+/messages`),
        status: 200,
        json: { status: "received" },
      },
    ]),
  });
  seedSession(ctx);

  const result = await ctx.a2cnSendOffer({
    session_id: SESSION_ID,
    total_value_cents: 9_800_000,
    payment_terms_net_days: 30,
  });

  expect("error" in result).toBe(false);
  expect(result.status).toBe("offer_sent");
  expect(result.your_offer_cents).toBe(9_800_000);
  const entry = ctx.sessions[SESSION_ID];
  expect(entry.my_last_offer_cents).toBe(9_800_000);
});

test("send offer session not found", async () => {
  // Unknown session_id → session_not_found error.
  const ctx = createMcpContext();
  const result = await ctx.a2cnSendOffer({
    session_id: "nonexistent-id",
    total_value_cents: 9_800_000,
    payment_terms_net_days: 30,
  });
  expect(result.error).toBe("session_not_found");
});

test("send offer terminal session", async () => {
  // Terminal session → session_already_terminal error.
  const ctx = createMcpContext();
  seedSession(ctx, { status: "COMPLETED" });

  const result = await ctx.a2cnSendOffer({
    session_id: SESSION_ID,
    total_value_cents: 9_800_000,
    payment_terms_net_days: 30,
  });
  expect(result.error).toBe("session_already_terminal");
  expect(result.status).toBe("COMPLETED");
});

// ---------------------------------------------------------------------------
// Tool 4: a2cn_accept
// ---------------------------------------------------------------------------

test("accept success", async () => {
  // Session with counterparty offer → acceptance sent, status COMPLETED.
  const ctx = createMcpContext({
    fetchFn: routedFetch([
      {
        method: "POST",
        pattern: new RegExp(`${BASE_URL}/sessions/.+/messages`),
        status: 200,
        json: { status: "accepted" },
      },
      {
        method: "GET",
        pattern: new RegExp(`${BASE_URL}/sessions/.+/record`),
        status: 200,
        json: TRANSACTION_RECORD,
      },
    ]),
  });
  seedSession(ctx, { cpOffer: SAMPLE_CP_OFFER });

  const result = await ctx.a2cnAccept(SESSION_ID);

  expect("error" in result).toBe(false);
  expect(result.status).toBe("COMPLETED");
  expect(result.record_hash).toBe(TRANSACTION_RECORD.record_hash);
  expect(result.agreed_total_cents).toBe((SAMPLE_CP_OFFER.terms as Dict).total_value);
  expect(ctx.sessions[SESSION_ID].status).toBe("COMPLETED");
});

test("accept no counterparty offer", async () => {
  // No counterparty offer yet → no_counterparty_offer error.
  const ctx = createMcpContext();
  seedSession(ctx, { cpOffer: null });

  const result = await ctx.a2cnAccept(SESSION_ID);
  expect(result.error).toBe("no_counterparty_offer");
});

test("accept terminal session", async () => {
  // Already completed session → session_already_terminal.
  const ctx = createMcpContext();
  seedSession(ctx, { status: "WITHDRAWN", cpOffer: SAMPLE_CP_OFFER });

  const result = await ctx.a2cnAccept(SESSION_ID);
  expect(result.error).toBe("session_already_terminal");
});

test("accept session not found", async () => {
  const ctx = createMcpContext();
  const result = await ctx.a2cnAccept("no-such-session");
  expect(result.error).toBe("session_not_found");
});

// ---------------------------------------------------------------------------
// Tool 5: a2cn_reject
// ---------------------------------------------------------------------------

test("reject success", async () => {
  // Active session → rejection sent, status REJECTED_FINAL.
  const ctx = createMcpContext({
    fetchFn: routedFetch([
      {
        method: "POST",
        pattern: new RegExp(`${BASE_URL}/sessions/.+/messages`),
        status: 200,
        json: { status: "received" },
      },
    ]),
  });
  seedSession(ctx, { cpOffer: SAMPLE_CP_OFFER });

  const result = await ctx.a2cnReject(SESSION_ID, "Price too high");

  expect("error" in result).toBe(false);
  expect(result.status).toBe("REJECTED_FINAL");
  expect(ctx.sessions[SESSION_ID].status).toBe("REJECTED_FINAL");
});

test("reject terminal guard", async () => {
  // Rejecting an already-terminal session → error.
  const ctx = createMcpContext();
  seedSession(ctx, { status: "REJECTED_FINAL" });

  const result = await ctx.a2cnReject(SESSION_ID);
  expect(result.error).toBe("session_already_terminal");
});

// ---------------------------------------------------------------------------
// Tool 6: a2cn_get_session_status
// ---------------------------------------------------------------------------

test("get status no counterparty offer", async () => {
  // Active session without any counterparty offer.
  const ctx = createMcpContext();
  seedSession(ctx, { cpOffer: null });

  const result = await ctx.a2cnGetSessionStatus(SESSION_ID);

  expect(result.status).toBe("NEGOTIATING");
  expect(result.session_id).toBe(SESSION_ID);
  expect(result.has_counterparty_offer).toBe(false);
  expect(result.counterparty_last_offer).toBeNull();
  expect((result.my_last_offer as Dict).total_cents).toBe(9_500_000);
});

test("get status with counterparty offer", async () => {
  // Session with a counterparty offer shows the offer details.
  const ctx = createMcpContext();
  seedSession(ctx, { cpOffer: SAMPLE_CP_OFFER });

  const result = await ctx.a2cnGetSessionStatus(SESSION_ID);

  expect(result.has_counterparty_offer).toBe(true);
  const cp = result.counterparty_last_offer as Dict;
  expect(cp).not.toBeNull();
  expect(cp.total_cents).toBe((SAMPLE_CP_OFFER.terms as Dict).total_value);
  expect(cp.net_days).toBe(
    (((SAMPLE_CP_OFFER.terms as Dict).payment_terms as Dict) ?? {}).net_days,
  );
});

test("get status completed", async () => {
  // Completed session includes transaction_record.
  const ctx = createMcpContext();
  seedSession(ctx, { status: "COMPLETED" });
  ctx.sessions[SESSION_ID].transaction_record = TRANSACTION_RECORD;

  const result = await ctx.a2cnGetSessionStatus(SESSION_ID);

  expect(result.status).toBe("COMPLETED");
  expect(result.transaction_record).toEqual(TRANSACTION_RECORD);
});

test("get status not found", async () => {
  const ctx = createMcpContext();
  const result = await ctx.a2cnGetSessionStatus("ghost-session");
  expect(result.error).toBe("session_not_found");
});

// ---------------------------------------------------------------------------
// injectCounterpartyOffer helper
// ---------------------------------------------------------------------------

test("inject counterparty offer updates store", () => {
  // injectCounterpartyOffer updates session store and client state.
  const ctx = createMcpContext();
  seedSession(ctx);

  ctx.injectCounterpartyOffer(SESSION_ID, SAMPLE_CP_OFFER);

  const entry = ctx.sessions[SESSION_ID];
  expect(entry.counterparty_last_offer_message).toEqual(SAMPLE_CP_OFFER);
  expect(entry.counterparty_last_offer_cents).toBe((SAMPLE_CP_OFFER.terms as Dict).total_value);

  // client internal state also updated
  const clientState = entry.client._sessions[SESSION_ID];
  expect(clientState.latest_offer).toEqual(SAMPLE_CP_OFFER);
});

test("inject counterparty offer unknown session", () => {
  const ctx = createMcpContext();
  expect(() => ctx.injectCounterpartyOffer("no-such-session", SAMPLE_CP_OFFER)).toThrow();
});
