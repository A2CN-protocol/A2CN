/**
 * A2CN MCP Server — Agent-to-Agent Commercial Negotiation Protocol
 *
 * Exposes A2CN negotiation capabilities as MCP tools, enabling any
 * MCP-compatible agent framework to negotiate commercial terms autonomously.
 *
 * Compatible with:
 * - Claude Desktop (stdio transport)
 * - Cursor and other MCP clients (stdio transport)
 * - Any MCP-compliant agent framework
 *
 * Architecture (per spec Section 13.9):
 *     LLM reasoning layer (the agent calling these tools)
 *         → decides: what to offer, whether to accept, when to reject
 *     MCP tool layer (this file) — the deterministic protocol adapter
 *         → handles: DID resolution, message construction, signing,
 *           schema validation, sequence tracking, session state
 *
 * The LLM never sees or generates protocol internals (hashes, signatures,
 * sequence numbers). Those are computed here, deterministically.
 *
 * Usage (stdio, for Claude Desktop / Cursor):
 *     npx tsx src/mcp_server.ts
 *
 * Tools exposed:
 *     a2cn_discover              Check if counterparty supports A2CN
 *     a2cn_initiate_session      Start a negotiation session
 *     a2cn_send_offer            Send a counteroffer
 *     a2cn_accept                Accept current counterparty offer
 *     a2cn_reject                Reject and end session
 *     a2cn_get_session_status    Poll for counterparty response
 */

import { randomUUID, type KeyObject } from "node:crypto";
import { fileURLToPath } from "node:url";

import { A2CNClient, HttpStatusError } from "./a2cn/client.js";
import { generateKeypair, publicKeyToJwk, createJwt } from "./a2cn/crypto.js";
import { now } from "./a2cn/session.js";
import type { Dict } from "./a2cn/messages.js";

const TERMINAL_STATES = new Set([
  "COMPLETED",
  "REJECTED_FINAL",
  "WITHDRAWN",
  "IMPASSE",
  "TIMED_OUT",
  "ERROR",
]);

const VALID_DEAL_TYPES = new Set([
  "saas_renewal",
  "goods_procurement",
  "services_engagement",
  "logistics_rate",
]);

export interface McpSessionEntry {
  client: A2CNClient;
  endpoint: string;
  counterparty_did: string;
  deal_type: string;
  session_ack: Dict;
  my_did: string;
  my_last_offer_cents: number | null;
  my_last_offer_net_days: number | null;
  counterparty_last_offer_cents: number | null;
  counterparty_last_offer_net_days: number | null;
  counterparty_last_offer_message: Dict | null;
  round_number: number;
  status: string;
  transaction_record: Dict | null;
  /** Fresh-JWT-per-request factory (anti-replay safe); null for seeded tests. */
  tokenFactory: (() => Promise<string>) | null;
}

export interface McpContext {
  agentDid: string;
  agentId: string;
  agentOrg: string;
  verificationMethod: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** Public DID document for counterparty servers to pre-register. */
  agentDidDocument: Dict;
  /** In-memory session store: session_id → entry. */
  sessions: Record<string, McpSessionEntry>;
  fetchFn: typeof fetch;
  injectCounterpartyOffer(sessionId: string, offerMessage: Dict): void;
  a2cnDiscover(counterpartyDid: string): Promise<Dict>;
  a2cnInitiateSession(args: {
    counterparty_did: string;
    deal_type: string;
    my_did: string;
    initial_offer_total_value_cents: number;
    currency: string;
    max_rounds: number;
    payment_terms_net_days: number;
    subject: string;
    custom_terms?: Dict | null;
    impasse_threshold?: number | null;
  }): Promise<Dict>;
  a2cnSendOffer(args: {
    session_id: string;
    total_value_cents: number;
    payment_terms_net_days: number;
    custom_terms?: Dict | null;
    reason_description?: string | null;
  }): Promise<Dict>;
  a2cnAccept(sessionId: string): Promise<Dict>;
  a2cnReject(sessionId: string, reasonDescription?: string | null): Promise<Dict>;
  a2cnGetSessionStatus(sessionId: string): Promise<Dict>;
}

/** Convert a did:web DID to its HTTPS base URL. */
export function didToBaseUrl(did: string): string {
  if (!did.startsWith("did:web:")) {
    throw new Error(`Not a did:web DID: ${JSON.stringify(did)}`);
  }
  const remainder = did.slice("did:web:".length);
  const parts = remainder.split(":");
  const domain = parts[0];
  if (parts.length > 1) {
    return `https://${domain}/${parts.slice(1).join("/")}`;
  }
  return `https://${domain}`;
}

/**
 * Build a fresh MCP tool context with an ephemeral agent identity.
 *
 * Agent identity — ephemeral by default; configure via environment variables:
 *   A2CN_AGENT_DID      Your agent's DID (default: did:web:mcp-agent.local)
 *   A2CN_AGENT_ID       Your agent's ID string (default: mcp-agent-001)
 *   A2CN_AGENT_ORG      Your organization name (default: MCP Agent)
 */
export function createMcpContext(options: { fetchFn?: typeof fetch } = {}): McpContext {
  const { privateKey, publicKey } = generateKeypair();
  const publicKeyJwk = publicKeyToJwk(publicKey);

  const agentDid = process.env.A2CN_AGENT_DID ?? "did:web:mcp-agent.local";
  const agentId = process.env.A2CN_AGENT_ID ?? "mcp-agent-001";
  const agentOrg = process.env.A2CN_AGENT_ORG ?? "MCP Agent";
  const verificationMethod = `${agentDid}#key-1`;

  const agentDidDocument: Dict = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: agentDid,
    verificationMethod: [
      {
        id: verificationMethod,
        type: "JsonWebKey2020",
        controller: agentDid,
        publicKeyJwk,
      },
    ],
    authentication: [verificationMethod],
    assertionMethod: [verificationMethod],
  };

  const sessions: Record<string, McpSessionEntry> = {};

  function makeMandate(dealType: string): Dict {
    return {
      mandate_type: "declared",
      agent_id: agentId,
      principal_organization: agentOrg,
      principal_did: agentDid,
      authorized_deal_types: [dealType],
      max_commitment_value: parseInt(process.env.A2CN_MAX_COMMITMENT ?? "100000000", 10),
      max_commitment_currency: "USD",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2027-12-31T00:00:00Z",
    };
  }

  function makeAgentInfo(myDid: string): Dict {
    return {
      organization_name: agentOrg,
      did: myDid,
      verification_method: `${myDid}#key-1`,
      agent_id: agentId,
      endpoint: `https://${myDid.replace("did:web:", "")}`,
    };
  }

  function sessionNotFound(sessionId: string): Dict {
    return {
      error: "session_not_found",
      message:
        `No active session with id ${JSON.stringify(sessionId)}. ` +
        "Use a2cn_initiate_session to start a new session.",
    };
  }

  function sessionTerminal(sessionId: string, status: string): Dict {
    return {
      error: "session_already_terminal",
      message: `Session ${JSON.stringify(sessionId)} is already in terminal state ${JSON.stringify(status)}.`,
      status,
      session_id: sessionId,
    };
  }

  const ctx: McpContext = {
    agentDid,
    agentId,
    agentOrg,
    verificationMethod,
    privateKey,
    publicKey,
    agentDidDocument,
    sessions,
    fetchFn: options.fetchFn ?? fetch,

    /**
     * Record a counterparty offer in the session store.
     *
     * In production: call this from your A2CN server's message handler when
     * the counterparty POSTs a counteroffer to your /sessions/{id}/messages.
     * In the MCP demo: call this directly after simulating the seller's response.
     */
    injectCounterpartyOffer(sessionId: string, offerMessage: Dict): void {
      const entry = sessions[sessionId];
      if (entry === undefined) {
        throw new Error(`Session ${JSON.stringify(sessionId)} not found in MCP session store`);
      }
      const terms = (offerMessage.terms as Dict) ?? {};
      const payment = (terms.payment_terms as Dict) ?? {};
      entry.counterparty_last_offer_cents = (terms.total_value as number) ?? null;
      entry.counterparty_last_offer_net_days = (payment.net_days as number) ?? null;
      entry.counterparty_last_offer_message = offerMessage;
      // Keep the A2CNClient's internal state in sync (for record generation)
      entry.client.processIncoming(sessionId, offerMessage);
    },

    /**
     * Fetch the A2CN discovery document from a counterparty to check
     * whether they support A2CN.
     */
    async a2cnDiscover(counterpartyDid: string): Promise<Dict> {
      let baseUrl: string;
      try {
        baseUrl = didToBaseUrl(counterpartyDid);
      } catch (exc) {
        return {
          error: "invalid_did",
          message: exc instanceof Error ? exc.message : String(exc),
          counterparty_did: counterpartyDid,
        };
      }

      const discoveryUrl = `${baseUrl}/.well-known/a2cn-agent`;
      try {
        const resp = await ctx.fetchFn(discoveryUrl, { signal: AbortSignal.timeout(10_000) });
        if (resp.status === 404) {
          return {
            error: "not_a2cn_capable",
            message:
              `Counterparty ${JSON.stringify(counterpartyDid)} has no discovery document ` +
              `at ${discoveryUrl}. They may not support A2CN.`,
          };
        }
        if (resp.status >= 400) {
          return {
            error: "discovery_http_error",
            message: `HTTP ${resp.status} fetching discovery from ${discoveryUrl}`,
          };
        }
        const doc = (await resp.json()) as Dict;
        return {
          a2cn_capable: true,
          a2cn_version: doc.a2cn_version,
          conformance_level: doc.conformance_level,
          deal_types: doc.deal_types ?? [],
          mandate_methods: doc.mandate_methods ?? ["declared"],
          endpoint: doc.endpoint || baseUrl,
          agent_did: doc.agent_did ?? counterpartyDid,
        };
      } catch (exc) {
        return {
          error: "discovery_failed",
          message: `Could not reach ${discoveryUrl}: ${exc}`,
        };
      }
    },

    /**
     * Initiate an A2CN commercial negotiation session with a counterparty
     * and send the opening offer (round 1).
     */
    async a2cnInitiateSession(args): Promise<Dict> {
      const {
        counterparty_did: counterpartyDid,
        deal_type: dealType,
        my_did: myDid,
        initial_offer_total_value_cents: initialOfferTotalValueCents,
        currency,
        max_rounds: maxRounds,
        payment_terms_net_days: paymentTermsNetDays,
        subject,
        custom_terms: customTerms = null,
        impasse_threshold: impasseThreshold = null,
      } = args;

      if (!VALID_DEAL_TYPES.has(dealType)) {
        return {
          error: "invalid_deal_type",
          message:
            `deal_type ${JSON.stringify(dealType)} is not recognised. ` +
            `Valid types: ${[...VALID_DEAL_TYPES].sort().join(", ")}`,
        };
      }
      if (!(maxRounds >= 1 && maxRounds <= 20)) {
        return { error: "invalid_max_rounds", message: "max_rounds must be between 1 and 20" };
      }

      let baseUrl: string;
      try {
        baseUrl = didToBaseUrl(counterpartyDid);
      } catch (exc) {
        return { error: "invalid_did", message: exc instanceof Error ? exc.message : String(exc) };
      }

      // Fetch discovery to get the server's own DID (used as JWT audience).
      // Falls back to env override or counterparty DID if discovery fails.
      let serverDid = process.env.A2CN_COUNTERPARTY_SERVER_DID ?? "";
      if (!serverDid) {
        try {
          const discResp = await ctx.fetchFn(`${baseUrl}/.well-known/a2cn-agent`, {
            signal: AbortSignal.timeout(5_000),
          });
          if (discResp.status === 200) {
            serverDid = (((await discResp.json()) as Dict).agent_did as string) ?? counterpartyDid;
          }
        } catch {
          // fall through to counterparty DID
        }
        if (!serverDid) {
          serverDid = counterpartyDid;
        }
      }

      const sessionParams: Dict = {
        deal_type: dealType,
        currency,
        subject,
        max_rounds: maxRounds,
        session_timeout_seconds: 3600,
        round_timeout_seconds: 900,
      };
      if (impasseThreshold !== null && impasseThreshold !== undefined) {
        sessionParams.impasse_threshold = impasseThreshold;
      }

      const tokenFactory = () =>
        createJwt(agentDid, serverDid, privateKey, {
          kid: verificationMethod,
          expSeconds: 300,
        });

      const client = new A2CNClient({
        agentInfo: makeAgentInfo(myDid),
        privateKey,
        mandate: makeMandate(dealType),
        fetchFn: ctx.fetchFn,
        authTokenFactory: tokenFactory,
      });

      let ack: Dict;
      try {
        ack = await client.initiateSession(baseUrl, counterpartyDid, sessionParams);
      } catch (exc) {
        if (exc instanceof HttpStatusError) {
          let detail: unknown = {};
          try {
            detail = JSON.parse(exc.body);
          } catch {
            // ignore
          }
          return {
            error: "session_init_failed",
            message: `Counterparty returned HTTP ${exc.status}`,
            detail,
          };
        }
        return { error: "session_init_error", message: String(exc) };
      }

      const sessionId = ack.session_id as string;

      // Build and send the opening offer (round 1)
      const terms: Dict = {
        total_value: initialOfferTotalValueCents,
        currency,
        payment_terms: { net_days: paymentTermsNetDays },
      };
      if (customTerms) {
        Object.assign(terms, customTerms);
      }

      try {
        await client.sendOffer(baseUrl, counterpartyDid, sessionId, terms);
      } catch (exc) {
        // Session created but opening offer failed — store partial state
        sessions[sessionId] = {
          client,
          endpoint: baseUrl,
          counterparty_did: counterpartyDid,
          deal_type: dealType,
          session_ack: ack,
          my_did: myDid,
          my_last_offer_cents: null,
          my_last_offer_net_days: null,
          counterparty_last_offer_cents: null,
          counterparty_last_offer_net_days: null,
          counterparty_last_offer_message: null,
          round_number: 0,
          status: "ACTIVE",
          transaction_record: null,
          tokenFactory,
        };
        return {
          error: "opening_offer_failed",
          message: `Session created (id=${JSON.stringify(sessionId)}) but opening offer failed: ${exc}`,
          session_id: sessionId,
        };
      }

      sessions[sessionId] = {
        client,
        endpoint: baseUrl,
        counterparty_did: counterpartyDid,
        deal_type: dealType,
        session_ack: ack,
        my_did: myDid,
        my_last_offer_cents: initialOfferTotalValueCents,
        my_last_offer_net_days: paymentTermsNetDays,
        counterparty_last_offer_cents: null,
        counterparty_last_offer_net_days: null,
        counterparty_last_offer_message: null,
        round_number: 1,
        status: "NEGOTIATING",
        transaction_record: null,
        tokenFactory,
      };

      const accepted = (ack.session_params_accepted as Dict) ?? {};
      return {
        status: "ACTIVE",
        session_id: sessionId,
        deal_type: dealType,
        currency,
        my_opening_offer_cents: initialOfferTotalValueCents,
        my_opening_offer_net_days: paymentTermsNetDays,
        max_rounds: accepted.max_rounds ?? maxRounds,
        awaiting_counterparty_response: true,
        counterparty_did: counterpartyDid,
      };
    },

    /**
     * Send a counteroffer in an active A2CN negotiation session.
     */
    async a2cnSendOffer(args): Promise<Dict> {
      const {
        session_id: sessionId,
        total_value_cents: totalValueCents,
        payment_terms_net_days: paymentTermsNetDays,
        custom_terms: customTerms = null,
      } = args;

      const entry = sessions[sessionId];
      if (entry === undefined) {
        return sessionNotFound(sessionId);
      }
      if (TERMINAL_STATES.has(entry.status)) {
        return sessionTerminal(sessionId, entry.status);
      }

      const terms: Dict = {
        total_value: totalValueCents,
        currency:
          (((entry.session_ack.session_params_accepted as Dict) ?? {}).currency as string) ?? "USD",
        payment_terms: { net_days: paymentTermsNetDays },
      };
      if (customTerms) {
        Object.assign(terms, customTerms);
      }

      let inReplyTo: string | null = null;
      const cpOffer = entry.counterparty_last_offer_message;
      if (cpOffer) {
        inReplyTo = (cpOffer.message_id as string) ?? null;
      }

      try {
        await entry.client.sendOffer(
          entry.endpoint,
          entry.counterparty_did,
          sessionId,
          terms,
          inReplyTo,
        );
      } catch (exc) {
        if (exc instanceof HttpStatusError) {
          let detail: unknown = {};
          try {
            detail = JSON.parse(exc.body);
          } catch {
            // ignore
          }
          return {
            error: "offer_rejected_by_server",
            message: `Counterparty server returned HTTP ${exc.status}`,
            detail,
            session_id: sessionId,
          };
        }
        return { error: "offer_send_failed", message: String(exc), session_id: sessionId };
      }

      entry.my_last_offer_cents = totalValueCents;
      entry.my_last_offer_net_days = paymentTermsNetDays;
      entry.status = "NEGOTIATING";
      entry.round_number += 1;

      return {
        status: "offer_sent",
        session_id: sessionId,
        round_number: entry.round_number,
        your_offer_cents: totalValueCents,
        your_offer_net_days: paymentTermsNetDays,
        awaiting_counterparty_response: true,
      };
    },

    /**
     * Accept the counterparty's most recent offer, completing the negotiation.
     */
    async a2cnAccept(sessionId: string): Promise<Dict> {
      const entry = sessions[sessionId];
      if (entry === undefined) {
        return sessionNotFound(sessionId);
      }
      if (TERMINAL_STATES.has(entry.status)) {
        return sessionTerminal(sessionId, entry.status);
      }

      const offer = entry.counterparty_last_offer_message;
      if (offer === null) {
        return {
          error: "no_counterparty_offer",
          message:
            "There is no counterparty offer to accept yet. " +
            "Call a2cn_get_session_status to check for a response, " +
            "or a2cn_send_offer to send your own counteroffer.",
          session_id: sessionId,
        };
      }

      const client = entry.client;
      try {
        await client.sendAcceptance(entry.endpoint, entry.counterparty_did, sessionId, offer);
      } catch (exc) {
        if (exc instanceof HttpStatusError) {
          let detail: unknown = {};
          try {
            detail = JSON.parse(exc.body);
          } catch {
            // ignore
          }
          return {
            error: "acceptance_rejected_by_server",
            message: `Counterparty server returned HTTP ${exc.status}`,
            detail,
            session_id: sessionId,
          };
        }
        return { error: "acceptance_failed", message: String(exc), session_id: sessionId };
      }

      // Fetch the authoritative transaction record from the counterparty's server
      let record: Dict = {};
      try {
        record = await client.getTransactionRecord(entry.endpoint, sessionId);
      } catch {
        record = {};
      }

      const agreedTerms = (offer.terms as Dict) ?? {};
      entry.status = "COMPLETED";
      entry.transaction_record = record;

      return {
        status: "COMPLETED",
        session_id: sessionId,
        record_hash: (record.record_hash as string) ?? "",
        agreed_total_cents: agreedTerms.total_value,
        agreed_net_days: ((agreedTerms.payment_terms as Dict) ?? {}).net_days,
        agreed_terms: agreedTerms,
        transaction_record: record,
      };
    },

    /**
     * Reject the counterparty's most recent offer and end the session.
     */
    async a2cnReject(sessionId: string, reasonDescription: string | null = null): Promise<Dict> {
      const entry = sessions[sessionId];
      if (entry === undefined) {
        return sessionNotFound(sessionId);
      }
      if (TERMINAL_STATES.has(entry.status)) {
        return sessionTerminal(sessionId, entry.status);
      }

      const client = entry.client;
      const clientState = client._sessions[sessionId] ?? {
        sequence_number: 0,
        round_number: 1,
      };
      const seq = (clientState.sequence_number ?? 0) + 1;
      const rnd = clientState.round_number ?? 1;

      const cpOffer = entry.counterparty_last_offer_message;
      const rejectedOfferId = cpOffer ? ((cpOffer.message_id as string) ?? "") : "";
      const inReplyTo = rejectedOfferId;

      const rejection: Dict = {
        message_type: "rejection",
        message_id: randomUUID(),
        session_id: sessionId,
        in_reply_to: inReplyTo,
        round_number: rnd,
        sequence_number: seq,
        rejected_offer_id: rejectedOfferId,
        sender_did: entry.my_did,
        sender_agent_id: agentId,
        timestamp: now(),
        reason_code: "PRICE_OUT_OF_RANGE",
      };
      if (reasonDescription) {
        rejection.reason_description = reasonDescription;
      }

      const headers: Record<string, string> = {
        "Content-Type": "application/a2cn+json",
        "Idempotency-Key": rejection.message_id as string,
      };
      if (entry.tokenFactory) {
        headers.Authorization = `Bearer ${await entry.tokenFactory()}`;
      }

      try {
        const resp = await ctx.fetchFn(`${entry.endpoint}/sessions/${sessionId}/messages`, {
          method: "POST",
          body: JSON.stringify(rejection),
          headers,
        });
        if (resp.status >= 400) {
          return {
            error: "rejection_failed",
            message: `Counterparty server returned HTTP ${resp.status}`,
            session_id: sessionId,
          };
        }
      } catch (exc) {
        return { error: "rejection_failed", message: String(exc), session_id: sessionId };
      }

      entry.status = "REJECTED_FINAL";
      return {
        status: "REJECTED_FINAL",
        session_id: sessionId,
        reason: reasonDescription ?? "Offer rejected.",
      };
    },

    /**
     * Get the current status of an A2CN negotiation session.
     */
    async a2cnGetSessionStatus(sessionId: string): Promise<Dict> {
      const entry = sessions[sessionId];
      if (entry === undefined) {
        return sessionNotFound(sessionId);
      }

      const ack = entry.session_ack ?? {};
      const accepted = (ack.session_params_accepted as Dict) ?? {};
      const maxRounds = (accepted.max_rounds as number) ?? 10;
      const roundsRemaining = Math.max(0, maxRounds - entry.round_number);

      const result: Dict = {
        status: entry.status,
        session_id: sessionId,
        round_number: entry.round_number,
        rounds_remaining: roundsRemaining,
        deal_type: entry.deal_type,
        my_last_offer: {
          total_cents: entry.my_last_offer_cents,
          net_days: entry.my_last_offer_net_days,
        },
        counterparty_last_offer: null,
        has_counterparty_offer: false,
        transaction_record: entry.transaction_record,
      };

      const cpOffer = entry.counterparty_last_offer_message;
      if (cpOffer !== null) {
        result.has_counterparty_offer = true;
        result.counterparty_last_offer = {
          total_cents: entry.counterparty_last_offer_cents,
          net_days: entry.counterparty_last_offer_net_days,
          terms: (cpOffer.terms as Dict) ?? {},
        };
      }

      return result;
    },
  };

  return ctx;
}

// ---------------------------------------------------------------------------
// MCP server wiring (stdio transport)
// ---------------------------------------------------------------------------

export async function runStdioServer(ctx: McpContext): Promise<void> {
  const { McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  const { z } = await import("zod");

  const server = new McpServer({ name: "a2cn", version: "0.3.0" });

  const asResult = (data: Dict) => ({
    content: [{ type: "text" as const, text: JSON.stringify(data) }],
    structuredContent: data,
  });

  server.registerTool(
    "a2cn_discover",
    {
      description:
        "Fetch the A2CN discovery document from a counterparty to check whether they " +
        "support A2CN and what deal types and conformance level they advertise.",
      inputSchema: { counterparty_did: z.string() },
    },
    async ({ counterparty_did }) => asResult(await ctx.a2cnDiscover(counterparty_did)),
  );

  server.registerTool(
    "a2cn_initiate_session",
    {
      description:
        "Initiate an A2CN commercial negotiation session with a counterparty and send " +
        "the opening offer.",
      inputSchema: {
        counterparty_did: z.string(),
        deal_type: z.string(),
        my_did: z.string(),
        initial_offer_total_value_cents: z.number().int(),
        currency: z.string(),
        max_rounds: z.number().int(),
        payment_terms_net_days: z.number().int(),
        subject: z.string(),
        custom_terms: z.record(z.string(), z.unknown()).nullish(),
        impasse_threshold: z.number().int().nullish(),
      },
    },
    async (args) =>
      asResult(
        await ctx.a2cnInitiateSession(
          args as Parameters<McpContext["a2cnInitiateSession"]>[0],
        ),
      ),
  );

  server.registerTool(
    "a2cn_send_offer",
    {
      description: "Send a counteroffer in an active A2CN negotiation session.",
      inputSchema: {
        session_id: z.string(),
        total_value_cents: z.number().int(),
        payment_terms_net_days: z.number().int(),
        custom_terms: z.record(z.string(), z.unknown()).nullish(),
        reason_description: z.string().nullish(),
      },
    },
    async (args) =>
      asResult(await ctx.a2cnSendOffer(args as Parameters<McpContext["a2cnSendOffer"]>[0])),
  );

  server.registerTool(
    "a2cn_accept",
    {
      description:
        "Accept the counterparty's most recent offer in an A2CN session, completing the " +
        "negotiation. Terminal action.",
      inputSchema: { session_id: z.string() },
    },
    async ({ session_id }) => asResult(await ctx.a2cnAccept(session_id)),
  );

  server.registerTool(
    "a2cn_reject",
    {
      description:
        "Reject the counterparty's most recent offer and end the session without " +
        "agreement. Terminal action.",
      inputSchema: { session_id: z.string(), reason_description: z.string().nullish() },
    },
    async ({ session_id, reason_description }) =>
      asResult(await ctx.a2cnReject(session_id, reason_description ?? null)),
  );

  server.registerTool(
    "a2cn_get_session_status",
    {
      description:
        "Get the current status of an A2CN negotiation session, including the latest " +
        "counterparty offer if one has arrived.",
      inputSchema: { session_id: z.string() },
    },
    async ({ session_id }) => asResult(await ctx.a2cnGetSessionStatus(session_id)),
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const ctx = createMcpContext();
  runStdioServer(ctx).catch((exc) => {
    console.error(exc);
    process.exit(1);
  });
}
