/**
 * A2CN Responder — Fastify server (Section 12.1.1)
 *
 * Endpoints:
 *   POST   /sessions                              — SessionInit
 *   GET    /sessions/{session_id}                — Session state
 *   POST   /sessions/{session_id}/messages       — Send any session message
 *   POST   /sessions/{session_id}/approval-receipt — Release human approval pause
 *   GET    /sessions/{session_id}/messages       — Message history (paginated)
 *   GET    /sessions/{session_id}/record         — Transaction record (COMPLETED only)
 *   GET    /sessions/{session_id}/evidence       — Session evidence (any terminal state)
 *   GET    /sessions/{session_id}/audit          — Audit log (any terminal state)
 *   POST   /invitations                          — Receive inbound invitation (v0.2.0)
 *   POST   /invitations/create                   — Create outbound invitation (v0.2.0)
 *   POST   /invitations/{invitation_id}/accept   — Accept invitation (v0.2.0)
 *   POST   /invitations/{invitation_id}/decline  — Decline invitation (v0.2.0)
 *   GET    /invitations/{invitation_id}          — Get invitation status (v0.2.0)
 *
 * JWT authentication is enforced on all state-modifying endpoints (Section 12.1.4).
 * All endpoints return Content-Type: application/a2cn+json.
 */

import { randomUUID, type KeyObject } from "node:crypto";
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from "fastify";
import { decodeJwt, decodeProtectedHeader } from "jose";

import { Session, SessionManager, SessionState, A2CNError, now, parseIsoMs } from "./session.js";
import { generateTransactionRecord, generateAuditLog } from "./record.js";
import { generateSessionEvidenceRecord } from "./evidence.js";
import { InvitationStore } from "./invitation.js";
import { buildFulfillmentAttestation } from "./fulfillment.js";
import {
  WebhookPayload,
  INVITATION_NOT_FOUND,
  INVITATION_EXPIRED,
  INVITATION_ALREADY_ANSWERED,
  INVITATION_SIGNATURE_INVALID,
  INVITATION_VERSION_MISMATCH,
  type Dict,
} from "./messages.js";
import {
  hashBytes,
  publicKeyToJwk,
  signJws,
  verifyJwt,
  verifyInvitationSignature,
  createPublicKeyFromPrivate,
} from "./crypto.js";
import { resolveDidWeb, getVerificationMethod, getPublicKey } from "./did.js";
import { InMemorySessionStore, type SessionStore } from "./session_store.js";

export const A2CN_CONTENT_TYPE = "application/a2cn+json";

export interface ResponderConfig {
  agent_info?: Dict;
  mandate?: Dict;
  deal_types?: string[];
  max_rounds_by_deal_type?: Record<string, number>;
  private_key?: KeyObject;
  fulfillment_private_key?: KeyObject;
  webhook_url?: string;
  [key: string]: unknown;
}

export interface ServerContext {
  app: FastifyInstance;
  manager: SessionManager;
  invitationStore: InvitationStore;
  sessionStore: SessionStore;
  responderConfig: ResponderConfig;
  SERVER_DID: string;
  /** Anti-replay cache: "iss\0jti" → expiry epoch seconds */
  jtiStore: Map<string, number>;
  /** Pre-registered DID documents: did → did_document dict. */
  didDocOverride: Record<string, Dict>;
  /** Injectable fetch for DID resolution and webhook/invitation delivery. */
  fetchFn: typeof fetch;
  configureResponder(config: ResponderConfig, sessionStore?: SessionStore | null): void;
  registerDidDocument(did: string, didDocument: Dict): void;
  deliverWebhook(
    url: string,
    eventType: string,
    sessionId: string,
    payload: Dict,
    retryConfig?: Dict | null,
    options?: {
      senderDid?: string | null;
      senderVerificationMethod?: string | null;
      privateKey?: KeyObject | null;
      backoffSeconds?: number[];
    },
  ): Promise<void>;
}

/**
 * Build a fresh A2CN responder server with isolated state.
 * (Mirror of the Python module-level app + importlib.reload pattern.)
 */
export function createServerContext(): ServerContext {
  const app = Fastify({ logger: false });
  const manager = new SessionManager();
  const invitationStore = new InvitationStore();

  const ctx: ServerContext = {
    app,
    manager,
    invitationStore,
    // Post-commitment data store (delivery notices, dispute notices, lifecycle status).
    sessionStore: new InMemorySessionStore(),
    responderConfig: {},
    // This server's own DID, used as JWT audience.
    SERVER_DID: process.env.A2CN_SERVER_DID ?? "did:web:localhost",
    jtiStore: new Map(),
    didDocOverride: {},
    fetchFn: fetch,

    /** Set responder identity info (DID, agent info, mandate, private key, etc.). */
    configureResponder(config: ResponderConfig, sessionStore: SessionStore | null = null): void {
      ctx.responderConfig = config;
      const agentInfo = (config.agent_info as Dict) ?? {};
      const privateKey = config.private_key;
      const did = agentInfo.did as string | undefined;
      const verificationMethod = agentInfo.verification_method as string | undefined;
      if (did && verificationMethod && privateKey) {
        manager.registerDidDocument(did, {
          id: did,
          verificationMethod: [
            {
              id: verificationMethod,
              type: "JsonWebKey2020",
              controller: did,
              publicKeyJwk: publicKeyToJwk(createPublicKeyFromPrivate(privateKey)),
            },
          ],
          authentication: [verificationMethod],
          assertionMethod: [verificationMethod],
        });
      }
      if (sessionStore !== null) {
        ctx.sessionStore = sessionStore;
      }
    },

    /** Pre-register a DID document so JWT verification skips HTTP resolution. */
    registerDidDocument(did: string, didDocument: Dict): void {
      ctx.didDocOverride[did] = didDocument;
      manager.registerDidDocument(did, didDocument);
    },

    // Webhook signing: DID-key JWS over the exact request body hash.
    // Receivers MUST verify X-A2CN-Signature against X-A2CN-Sender-Verification-Method
    // before processing webhook payloads.
    async deliverWebhook(url, eventType, sessionId, payload, retryConfig = null, options = {}) {
      const bodyBytes = Buffer.from(sortedCompactJson(payload), "utf-8");
      const agentInfo = (ctx.responderConfig.agent_info as Dict) ?? {};
      const senderDid = options.senderDid ?? ((agentInfo.did as string) || "");
      const senderVerificationMethod =
        options.senderVerificationMethod ?? ((agentInfo.verification_method as string) || "");
      const privateKey = options.privateKey ?? ctx.responderConfig.private_key ?? null;
      if (!senderDid || !senderVerificationMethod || privateKey === null) {
        console.error(
          `Webhook delivery to ${url} skipped: sender DID signing material is not configured`,
        );
        return;
      }

      const bodyHash = hashBytes(bodyBytes);
      const signatureJws = signJws(bodyHash, privateKey, senderVerificationMethod);
      const timestamp = now();
      const headers = {
        "Content-Type": A2CN_CONTENT_TYPE,
        "X-A2CN-Timestamp": timestamp,
        "X-A2CN-Session-ID": sessionId,
        "X-A2CN-Event-Type": eventType,
        "X-A2CN-Sender-DID": senderDid,
        "X-A2CN-Sender-Verification-Method": senderVerificationMethod,
        "X-A2CN-Body-SHA256": bodyHash,
        "X-A2CN-Signature": signatureJws,
      };
      const maxRetries = ((retryConfig ?? {}).max_retries as number) ?? 3;
      const backoffSeconds = options.backoffSeconds ?? [1, 4, 16];
      for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
          const resp = await ctx.fetchFn(url, {
            method: "POST",
            body: bodyBytes,
            headers,
            signal: AbortSignal.timeout(10_000),
          });
          if (resp.status < 300) {
            return;
          }
          console.warn(`Webhook delivery attempt ${attempt + 1} returned ${resp.status}`);
        } catch (exc) {
          console.warn(`Webhook delivery attempt ${attempt + 1} failed: ${exc}`);
        }
        if (attempt < maxRetries - 1) {
          await sleep(backoffSeconds[attempt] * 1000);
        }
      }
      console.error(`Webhook delivery to ${url} failed after ${maxRetries} attempts`);
    },
  };

  installParsers(app);
  installHooks(ctx);
  installRoutes(ctx);

  return ctx;
}

// ---------------------------------------------------------------------------
// Body parsing — accept any content type; JSON parsing happens per-route so
// malformed bodies surface as A2CN INTERNAL_ERROR responses (Python parity).
// ---------------------------------------------------------------------------

function installParsers(app: FastifyInstance): void {
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("*", { parseAs: "buffer" }, (_req, body, done) => {
    done(null, body);
  });
}

function parseBody(request: FastifyRequest): Dict {
  const raw = request.body;
  try {
    if (Buffer.isBuffer(raw)) {
      return JSON.parse(raw.toString("utf-8")) as Dict;
    }
    if (typeof raw === "string") {
      return JSON.parse(raw) as Dict;
    }
    if (raw !== null && typeof raw === "object") {
      return raw as Dict;
    }
    throw new Error("empty body");
  } catch {
    throw new A2CNError("INTERNAL_ERROR", "Invalid JSON in request body", 400);
  }
}

// ---------------------------------------------------------------------------
// Middleware: transport auth (Section 14.1) + Content-Type enforcement
// ---------------------------------------------------------------------------

function installHooks(ctx: ServerContext): void {
  const { app } = ctx;

  /**
   * Enforce Bearer JWT on all state-mutating requests (POST, PUT, PATCH).
   * Only validates token shape here; full DID-based signature verification
   * is performed by verifyJwtAuth on each protected endpoint.
   * Inbound invitation delivery is the cold-start exception: POST /invitations
   * authenticates with invitation_signature instead of transport JWT.
   */
  app.addHook("onRequest", async (request, reply) => {
    if (["POST", "PUT", "PATCH"].includes(request.method)) {
      const path = request.url.split("?")[0];
      if (request.method === "POST" && path === "/invitations") {
        return;
      }
      const auth = request.headers.authorization ?? "";
      if (!auth.startsWith("Bearer ")) {
        return reply.code(401).send(
          JSON.stringify({
            error: {
              code: "INVALID_JWT",
              message: "Authorization: Bearer <token> header is required",
              spec_ref: "Section 14.1",
            },
          }),
        );
      }
      const token = auth.slice(7);
      const parts = token.split(".");
      if (parts.length !== 3 || !parts.every((p) => p.length > 0)) {
        return reply.code(401).send(
          JSON.stringify({
            error: {
              code: "INVALID_JWT",
              message: "Bearer token is not a valid JWT",
              spec_ref: "Section 14.1",
            },
          }),
        );
      }
      // Verify each segment is valid base64url
      for (const part of parts) {
        if (!/^[A-Za-z0-9_-]+$/.test(part)) {
          return reply.code(401).send(
            JSON.stringify({
              error: {
                code: "INVALID_JWT",
                message: "Bearer token is not a valid JWT",
                spec_ref: "Section 14.1",
              },
            }),
          );
        }
      }
    }
  });

  /** Set Content-Type on all A2CN responses. Discovery doc uses application/json. */
  app.addHook("onSend", async (request, reply, payload) => {
    const path = request.url.split("?")[0];
    if (path === "/.well-known/a2cn-agent") {
      reply.header("content-type", "application/json");
    } else {
      reply.header("content-type", A2CN_CONTENT_TYPE);
    }
    return payload;
  });

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof A2CNError) {
      return sendError(reply, error.code, error.message, error.httpStatus, {
        detail: error.detail,
        sessionId: error.sessionId,
        messageId: error.messageId,
      });
    }
    return sendError(reply, "INTERNAL_ERROR", String((error as Error)?.message ?? error), 500);
  });
}

// ---------------------------------------------------------------------------
// JWT auth — Section 12.1.4
// ---------------------------------------------------------------------------

function cleanExpiredJtis(ctx: ServerContext): void {
  const nowSec = Date.now() / 1000;
  for (const [key, exp] of ctx.jtiStore) {
    if (exp < nowSec) {
      ctx.jtiStore.delete(key);
    }
  }
}

/**
 * Verifies ES256/EdDSA Bearer JWT on every protected endpoint.
 *
 * Steps:
 *   1. Extract Bearer token from Authorization header.
 *   2. Decode unverified header/claims to get kid and iss.
 *   3. Resolve issuer DID document (didDocOverride first, then HTTP).
 *   4. Find verification method matching kid; extract public key.
 *   5. Verify JWT signature, expiry, and audience (SERVER_DID).
 *   6. Enforce anti-replay via (iss, jti) tuple.
 *
 * Throws A2CNError("INVALID_JWT", ..., 401) on any failure.
 */
async function verifyJwtAuth(ctx: ServerContext, request: FastifyRequest): Promise<Dict> {
  const auth = request.headers.authorization ?? "";
  if (!auth.startsWith("Bearer ")) {
    throw new A2CNError("INVALID_JWT", "Missing or invalid Authorization header", 401);
  }

  const token = auth.slice(7);

  try {
    let kid = "";
    let iss = "";
    try {
      const header = decodeProtectedHeader(token);
      kid = (header.kid as string) ?? "";
      const unverified = decodeJwt(token);
      iss = (unverified.iss as string) ?? "";
    } catch (exc) {
      throw new A2CNError("INVALID_JWT", `JWT processing error: ${exc}`, 401);
    }

    if (!iss) {
      throw new A2CNError("INVALID_JWT", "JWT missing iss claim", 401);
    }

    // Resolve DID document (override dict first, then HTTP)
    let didDoc: Dict;
    if (iss in ctx.didDocOverride) {
      didDoc = ctx.didDocOverride[iss];
    } else {
      try {
        didDoc = await resolveDidWeb(iss, ctx.fetchFn);
        ctx.manager.registerDidDocument(iss, didDoc);
      } catch (exc) {
        throw new A2CNError("INVALID_JWT", `Could not resolve issuer DID: ${exc}`, 401);
      }
    }

    // Find verification method and extract public key
    let pubKey;
    try {
      const vm = getVerificationMethod(didDoc, kid);
      pubKey = getPublicKey(vm);
    } catch (exc) {
      throw new A2CNError("INVALID_JWT", `Verification method not found: ${exc}`, 401);
    }

    // Verify signature, expiry, and audience
    let claims: Dict;
    try {
      claims = (await verifyJwt(token, pubKey, {
        expectedAudience: ctx.SERVER_DID,
      })) as Dict;
    } catch (exc) {
      throw new A2CNError("INVALID_JWT", `JWT validation failed: ${exc}`, 401);
    }

    // Anti-replay: reject reuse of any (iss, jti) pair
    const jti = (claims.jti as string) ?? "";
    if (jti) {
      cleanExpiredJtis(ctx);
      const key = `${iss}\0${jti}`;
      if (ctx.jtiStore.has(key)) {
        throw new A2CNError("INVALID_JWT", "JWT already used (replay detected)", 401);
      }
      const exp = Number(claims.exp ?? Date.now() / 1000 + 600);
      ctx.jtiStore.set(key, exp);
    }

    return claims;
  } catch (exc) {
    if (exc instanceof A2CNError) {
      throw exc;
    }
    throw new A2CNError("INVALID_JWT", `JWT processing error: ${exc}`, 401);
  }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

function sendA2cn(reply: FastifyReply, data: Dict, statusCode = 200): FastifyReply {
  return reply
    .code(statusCode)
    .header("content-type", A2CN_CONTENT_TYPE)
    .send(JSON.stringify(data));
}

function sendError(
  reply: FastifyReply,
  code: string,
  message: string,
  httpStatus: number,
  options: {
    detail?: string;
    sessionId?: string | null;
    messageId?: string | null;
    specRef?: string | null;
  } = {},
): FastifyReply {
  const { detail = "", sessionId = null, messageId = null, specRef = null } = options;
  const errorBody: Dict = {
    code,
    message,
    detail,
    timestamp: now(),
    session_id: sessionId,
    message_id: messageId,
  };
  if (specRef !== null) {
    errorBody.spec_ref = specRef;
  }
  return reply
    .code(httpStatus)
    .header("content-type", A2CN_CONTENT_TYPE)
    .send(JSON.stringify({ error: errorBody }));
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

function installRoutes(ctx: ServerContext): void {
  const { app, manager, invitationStore } = ctx;

  function getSessionOr404(sessionId: string): Session {
    const session = manager.getSession(sessionId);
    if (session === null) {
      throw new A2CNError("SESSION_NOT_FOUND", `Session ${JSON.stringify(sessionId)} not found`, 404, {
        sessionId,
      });
    }
    return session;
  }

  function requireFields(body: Dict, fields: string[]): void {
    for (const f of fields) {
      if (!(f in body)) {
        throw new A2CNError("INTERNAL_ERROR", `Missing required field: ${JSON.stringify(f)}`, 400);
      }
    }
  }

  /** Basic Tier 1 mandate validation. Returns error string or null. */
  function validateMandate(mandate: Dict, sessionParams: Dict): string | null {
    const mandateType = mandate.mandate_type;
    if (mandateType !== "declared" && mandateType !== "did_vc") {
      return `Unknown mandate_type: ${JSON.stringify(mandateType)}`;
    }

    if (mandateType === "declared") {
      const validUntil = (mandate.valid_until as string) ?? "";
      const expiryMs = typeof validUntil === "string" && validUntil ? parseIsoMs(validUntil) : NaN;
      if (Number.isNaN(expiryMs)) {
        return "Invalid valid_until format";
      }
      if (expiryMs < Date.now()) {
        return `Mandate expired at ${validUntil}`;
      }

      const authorizedTypes = (mandate.authorized_deal_types as string[]) ?? [];
      if (!authorizedTypes.includes(sessionParams.deal_type as string)) {
        return `Deal type '${sessionParams.deal_type}' not in authorized_deal_types`;
      }
    }

    return null;
  }

  /** Return a signed FulfillmentAttestation, or null if no Ed25519 key is configured. */
  function buildServerFulfillmentAttestation(
    sessionId: string,
    pcData: Dict,
    disputeResolvedMessage: Dict | null = null,
  ): Dict | null {
    const agentInfo = (ctx.responderConfig.agent_info as Dict) ?? {};
    const privateKey = ctx.responderConfig.fulfillment_private_key;
    if (!privateKey) {
      return null;
    }

    const sessionRecord: Dict = { ...pcData };
    sessionRecord.session_id = sessionId;
    return buildFulfillmentAttestation(sessionRecord, {
      privateKey,
      signerDid: (agentInfo.did as string) ?? null,
      disputeResolvedMessage,
    });
  }

  const TERMINAL_EVENT_MAP: Record<string, string> = {
    [SessionState.COMPLETED]: "session.completed",
    [SessionState.REJECTED_FINAL]: "session.rejected",
    [SessionState.WITHDRAWN]: "session.withdrawn",
    [SessionState.IMPASSE]: "session.impasse",
    [SessionState.TIMED_OUT]: "session.timed_out",
    [SessionState.ERROR]: "session.error",
  };

  /** Build and deliver a terminal-state webhook payload. */
  async function fireTerminalWebhook(session: Session, webhookUrl: string): Promise<void> {
    const eventType = TERMINAL_EVENT_MAP[session.state] ?? "session.error";
    let recordHash = "";
    if (session.state === SessionState.COMPLETED) {
      try {
        const record = generateTransactionRecord(session);
        recordHash = (record.record_hash as string) ?? "";
      } catch {
        // non-fatal
      }
    }

    const payload = new WebhookPayload({
      event_type: eventType,
      session_id: session.session_id,
      occurred_at: now(),
      session_state: session.state,
      terminal: true,
      record_hash: recordHash,
    });
    await ctx.deliverWebhook(webhookUrl, eventType, session.session_id, payload.toDict());
  }

  // -------------------------------------------------------------------
  // GET /.well-known/a2cn-agent — Discovery document (Component 1, Section 4.3)
  // -------------------------------------------------------------------

  app.get("/.well-known/a2cn-agent", async (_request, reply) => {
    const cfg = ctx.responderConfig;
    const agentInfo = (cfg.agent_info as Dict) ?? {};
    return sendA2cn(reply, {
      a2cn_version: "0.2",
      agent_did: (agentInfo.did as string) ?? "",
      conformance_level: 2,
      deal_types: (cfg.deal_types as string[]) ?? ["saas_renewal"],
      mandate_methods: ["declared"],
      endpoint: (agentInfo.endpoint as string) ?? "",
      agent_id: (agentInfo.agent_id as string) ?? "",
      verification_method: (agentInfo.verification_method as string) ?? "",
    });
  });

  // -------------------------------------------------------------------
  // POST /sessions — SessionInit
  // -------------------------------------------------------------------

  app.post("/sessions", async (request, reply) => {
    const jwtClaims = await verifyJwtAuth(ctx, request);
    const body = parseBody(request);
    const messageId = (body.message_id as string) ?? "";

    // Idempotency check (Section 6.1)
    if (manager.hasInitResponse(messageId)) {
      return sendA2cn(reply, manager.getInitResponse(messageId), 200);
    }

    // Validate required fields
    requireFields(body, [
      "message_type",
      "message_id",
      "protocol_version",
      "session_params",
      "initiator",
      "initiator_mandate",
    ]);

    const initiatorDid = (((body.initiator as Dict) ?? {}).did as string) ?? "";
    if (initiatorDid && initiatorDid !== ((jwtClaims.iss as string) ?? "")) {
      return sendError(
        reply,
        "SENDER_DID_MISMATCH",
        "JWT issuer does not match initiator.did in request body",
        401,
        { detail: "Section 14.1", messageId },
      );
    }

    if (body.message_type !== "session_init") {
      return sendError(reply, "WRONG_MESSAGE_TYPE", "Expected message_type 'session_init'", 400, {
        messageId,
      });
    }

    if (body.protocol_version !== "0.2") {
      return sendError(
        reply,
        "PROTOCOL_VERSION_MISMATCH",
        "Only protocol_version '0.2' is supported",
        400,
        { messageId },
      );
    }

    const sessionParams = (body.session_params as Dict) ?? {};
    const cfg = ctx.responderConfig;

    // Validate deal type
    const supportedDealTypes = (cfg.deal_types as string[]) ?? ["saas_renewal"];
    if (!supportedDealTypes.includes(sessionParams.deal_type as string)) {
      return sendError(
        reply,
        "DEAL_TYPE_NOT_SUPPORTED",
        `Deal type '${sessionParams.deal_type}' not supported`,
        403,
        { messageId },
      );
    }

    // Validate mandate
    const mandate = (body.initiator_mandate as Dict) ?? {};
    const mandateError = validateMandate(mandate, sessionParams);
    if (mandateError) {
      return sendError(reply, "MANDATE_INVALID", mandateError, 403, { messageId });
    }

    // Build SessionAck
    const sessionId = randomUUID();
    const nowTs = now();

    const responderInfo = (cfg.agent_info as Dict) ?? {};
    const responderMandate = (cfg.mandate as Dict) ?? {};

    const maxRoundsByDealType = (cfg.max_rounds_by_deal_type as Record<string, number>) ?? {};
    const sessionAck: Dict = {
      message_type: "session_ack",
      message_id: randomUUID(),
      session_id: sessionId,
      in_reply_to: messageId,
      protocol_version: "0.2",
      session_params_accepted: {
        deal_type: sessionParams.deal_type,
        currency: sessionParams.currency,
        max_rounds: Math.min(
          (sessionParams.max_rounds as number) ?? 10,
          maxRoundsByDealType[sessionParams.deal_type as string] ?? 10,
        ),
        session_timeout_seconds: sessionParams.session_timeout_seconds,
        round_timeout_seconds: sessionParams.round_timeout_seconds,
      },
      responder: responderInfo,
      responder_mandate: responderMandate,
      session_created_at: nowTs,
      current_turn: "initiator",
    };

    if ("impasse_threshold" in sessionParams) {
      (sessionAck.session_params_accepted as Dict).impasse_threshold =
        sessionParams.impasse_threshold;
    }

    // Create session
    manager.createSession(sessionId, body, sessionAck, nowTs);

    manager.storeInitResponse(messageId, sessionAck);
    return sendA2cn(reply, sessionAck, 201);
  });

  // -------------------------------------------------------------------
  // GET /sessions/{session_id}
  // -------------------------------------------------------------------

  app.get("/sessions/:session_id", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    return sendA2cn(reply, session.toStateDict());
  });

  // -------------------------------------------------------------------
  // POST /sessions/{session_id}/messages — send any session message
  // -------------------------------------------------------------------

  app.post("/sessions/:session_id/messages", async (request, reply) => {
    const jwtClaims = await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    const body = parseBody(request);

    // Bind JWT issuer to session and sender identity (Section 14.1)
    const bodySessionId = body.session_id;
    if (bodySessionId !== undefined && bodySessionId !== null && bodySessionId !== sessionId) {
      return sendError(
        reply,
        "SESSION_ID_MISMATCH",
        "session_id in request body does not match URL path",
        400,
        { sessionId },
      );
    }
    const bodySenderDid = (body.sender_did as string) ?? "";
    if (bodySenderDid && bodySenderDid !== ((jwtClaims.iss as string) ?? "")) {
      return sendError(
        reply,
        "SENDER_DID_MISMATCH",
        "JWT issuer does not match sender_did in request body",
        401,
        { detail: "Section 14.1", sessionId },
      );
    }

    let response: Dict;
    try {
      response = manager.processMessage(session, body);
    } catch (exc) {
      if (exc instanceof A2CNError) {
        return sendError(reply, exc.code, exc.message, exc.httpStatus, {
          detail: exc.detail,
          sessionId: exc.sessionId,
          messageId: exc.messageId,
        });
      }
      throw exc;
    }

    // v0.2.0: Async webhook delivery for terminal transitions (Level 2 REQUIRED)
    if (session.isTerminal()) {
      const webhookUrl = ctx.responderConfig.webhook_url;
      if (webhookUrl) {
        void fireTerminalWebhook(session, webhookUrl);
      }
    }

    return sendA2cn(reply, response);
  });

  // -------------------------------------------------------------------
  // POST /sessions/{session_id}/approval-receipt
  // -------------------------------------------------------------------

  app.post("/sessions/:session_id/approval-receipt", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    const body = parseBody(request);

    if (body.session_id !== undefined && body.session_id !== null && body.session_id !== sessionId) {
      return sendError(
        reply,
        "SESSION_ID_MISMATCH",
        "session_id in request body does not match URL path",
        400,
        { sessionId },
      );
    }

    let response: Dict;
    try {
      response = manager.applyApprovalReceipt(session, body);
    } catch (exc) {
      if (exc instanceof A2CNError) {
        return sendError(reply, exc.code, exc.message, exc.httpStatus, {
          detail: exc.detail,
          sessionId: exc.sessionId,
          messageId: exc.messageId,
        });
      }
      throw exc;
    }

    return sendA2cn(reply, response);
  });

  // -------------------------------------------------------------------
  // GET /sessions/{session_id}/messages — message history
  // -------------------------------------------------------------------

  app.get("/sessions/:session_id/messages", async (request, reply) => {
    const jwtClaims = await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    const query = request.query as Record<string, string | undefined>;
    const afterSequence = parseInt(query.after_sequence ?? "0", 10) || 0;
    const limit = parseInt(query.limit ?? "50", 10) || 50;

    const jwtIss = (jwtClaims.iss as string) ?? "";
    if (jwtIss !== session.initiator_info.did && jwtIss !== session.responder_info.did) {
      return sendError(reply, "NOT_SESSION_PARTY", "JWT issuer is not a party to this session", 403, {
        sessionId,
      });
    }
    const allMessages = session._message_log;
    const filtered = allMessages.filter(
      (m) => ((m.sequence_number as number) ?? 0) > afterSequence,
    );
    const page = filtered.slice(0, limit);
    const nextCursor =
      filtered.length > limit && page.length > 0
        ? (page[page.length - 1].sequence_number ?? null)
        : null;

    return sendA2cn(reply, {
      session_id: sessionId,
      messages: page,
      next_cursor: nextCursor,
    });
  });

  // -------------------------------------------------------------------
  // GET /sessions/{session_id}/record — transaction record
  // -------------------------------------------------------------------

  app.get("/sessions/:session_id/record", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    if (session.state !== SessionState.COMPLETED) {
      return sendError(
        reply,
        "SESSION_WRONG_STATE",
        "Transaction record is only available for COMPLETED sessions",
        409,
        { sessionId },
      );
    }
    const record = generateTransactionRecord(session);
    return sendA2cn(reply, record);
  });

  // -------------------------------------------------------------------
  // GET /sessions/{session_id}/evidence — producer-sealed session evidence
  // -------------------------------------------------------------------

  app.get("/sessions/:session_id/evidence", async (request, reply) => {
    const jwtClaims = await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    const jwtIss = (jwtClaims.iss as string) ?? "";
    if (jwtIss !== session.initiator_info.did && jwtIss !== session.responder_info.did) {
      return sendError(reply, "NOT_SESSION_PARTY", "JWT issuer is not a party to this session", 403, {
        sessionId,
      });
    }
    if (!session.isTerminal()) {
      return sendError(
        reply,
        "SESSION_WRONG_STATE",
        "Session evidence is only available for sessions in a terminal state",
        409,
        { sessionId },
      );
    }

    const agentInfo = (ctx.responderConfig.agent_info as Dict) ?? {};
    const privateKey = ctx.responderConfig.private_key;
    const producerDid = (agentInfo.did as string) ?? "";
    const verificationMethod = (agentInfo.verification_method as string) ?? "";
    if (!privateKey || !producerDid || !verificationMethod) {
      return sendError(
        reply,
        "INTERNAL_ERROR",
        "Server evidence signing material is not configured",
        500,
        { sessionId },
      );
    }

    const evidence = generateSessionEvidenceRecord(session, {
      producerPrivateKey: privateKey,
      producerDid,
      producerAgentId: (agentInfo.agent_id as string) ?? "",
      producerVerificationMethod: verificationMethod,
    });
    return sendA2cn(reply, evidence);
  });

  // -------------------------------------------------------------------
  // GET /sessions/{session_id}/audit — audit log
  // -------------------------------------------------------------------

  app.get("/sessions/:session_id/audit", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    if (!session.isTerminal()) {
      return sendError(
        reply,
        "SESSION_WRONG_STATE",
        "Audit log is only available for sessions in a terminal state",
        409,
        { sessionId },
      );
    }
    const log = generateAuditLog(session);
    return sendA2cn(reply, log);
  });

  // -------------------------------------------------------------------
  // v0.2.0: Post-commitment lifecycle endpoints (OQ-017; Level 3 conformance)
  // -------------------------------------------------------------------

  app.post("/sessions/:session_id/delivery-notice", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    const body = parseBody(request);

    if (body.session_id !== undefined && body.session_id !== null && body.session_id !== sessionId) {
      return sendError(
        reply,
        "SESSION_ID_MISMATCH",
        "session_id in request body does not match URL path",
        400,
        { sessionId },
      );
    }

    if (body.message_type !== "delivery_notice") {
      return sendError(reply, "WRONG_MESSAGE_TYPE", "message_type must be 'delivery_notice'", 400, {
        sessionId,
      });
    }

    if (session.state !== SessionState.COMPLETED) {
      return sendError(
        reply,
        "SESSION_WRONG_STATE",
        "Delivery notice requires a COMPLETED session",
        409,
        { sessionId },
      );
    }

    let record: Dict;
    try {
      record = generateTransactionRecord(session);
    } catch (exc) {
      return sendError(
        reply,
        "INTERNAL_ERROR",
        `Could not generate transaction record: ${exc}`,
        500,
        { sessionId },
      );
    }

    if (body.transaction_record_hash !== record.record_hash) {
      return sendError(
        reply,
        "INVALID_RECORD_HASH",
        "transaction_record_hash does not match the agreed transaction record",
        409,
        { sessionId },
      );
    }

    const messageId = (body.message_id as string) ?? randomUUID();
    const pcData = ctx.sessionStore.get(sessionId) ?? {};
    pcData.delivery_notice = body;
    pcData.delivery_notice_message_id = messageId;
    ctx.sessionStore.save(sessionId, pcData);

    return sendA2cn(reply, {
      delivery_notice_message_id: messageId,
      session_id: sessionId,
      status: "DELIVERY_NOTICE_RECORDED",
    });
  });

  app.post("/sessions/:session_id/delivery-acknowledged", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    const body = parseBody(request);

    if (body.session_id !== undefined && body.session_id !== null && body.session_id !== sessionId) {
      return sendError(
        reply,
        "SESSION_ID_MISMATCH",
        "session_id in request body does not match URL path",
        400,
        { sessionId },
      );
    }

    if (body.message_type !== "delivery_acknowledged") {
      return sendError(
        reply,
        "WRONG_MESSAGE_TYPE",
        "message_type must be 'delivery_acknowledged'",
        400,
        { sessionId },
      );
    }

    const pcData = ctx.sessionStore.get(sessionId) ?? {};

    if (!("delivery_notice" in pcData)) {
      return sendError(reply, "NO_DELIVERY_NOTICE", "No delivery notice found for this session", 409, {
        sessionId,
      });
    }

    const storedNoticeId = pcData.delivery_notice_message_id;
    if (body.delivery_notice_message_id !== storedNoticeId) {
      return sendError(
        reply,
        "INVALID_REFERENCE",
        "delivery_notice_message_id does not match the stored delivery notice",
        409,
        { sessionId },
      );
    }

    let record: Dict;
    try {
      record = generateTransactionRecord(session);
    } catch (exc) {
      return sendError(
        reply,
        "INTERNAL_ERROR",
        `Could not generate transaction record: ${exc}`,
        500,
        { sessionId },
      );
    }

    if (body.transaction_record_hash !== record.record_hash) {
      return sendError(
        reply,
        "INVALID_RECORD_HASH",
        "transaction_record_hash does not match the agreed transaction record",
        409,
        { sessionId },
      );
    }

    const accepted = (body.accepted as boolean) ?? false;
    const postCommitmentStatus = accepted ? "CLOSED" : "DISPUTED";
    const messageId = (body.message_id as string) ?? randomUUID();

    pcData.post_commitment_status = postCommitmentStatus;
    pcData.delivery_acknowledged = body;
    if (!accepted) {
      pcData.dispute_reason = (body.notes as string) ?? "";
    } else {
      const attestation = buildServerFulfillmentAttestation(sessionId, pcData);
      if (attestation !== null) {
        pcData.fulfillment_attestation = attestation;
      }
    }
    pcData.acknowledgment_message_id = messageId;
    ctx.sessionStore.save(sessionId, pcData);

    return sendA2cn(reply, {
      acknowledgment_message_id: messageId,
      session_id: sessionId,
      post_commitment_status: postCommitmentStatus,
    });
  });

  app.post("/sessions/:session_id/dispute-notice", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    const body = parseBody(request);

    if (body.session_id !== undefined && body.session_id !== null && body.session_id !== sessionId) {
      return sendError(
        reply,
        "SESSION_ID_MISMATCH",
        "session_id in request body does not match URL path",
        400,
        { sessionId },
      );
    }

    if (body.message_type !== "dispute_notice") {
      return sendError(reply, "WRONG_MESSAGE_TYPE", "message_type must be 'dispute_notice'", 400, {
        sessionId,
      });
    }

    const pcData = ctx.sessionStore.get(sessionId) ?? {};

    if (session.state !== SessionState.COMPLETED && !("delivery_notice" in pcData)) {
      return sendError(
        reply,
        "SESSION_WRONG_STATE",
        "Dispute notice requires a COMPLETED session or a recorded delivery notice",
        409,
        { sessionId },
      );
    }

    let record: Dict;
    try {
      record = generateTransactionRecord(session);
    } catch (exc) {
      return sendError(
        reply,
        "INTERNAL_ERROR",
        `Could not generate transaction record: ${exc}`,
        500,
        { sessionId },
      );
    }

    if (body.transaction_record_hash !== record.record_hash) {
      return sendError(
        reply,
        "INVALID_RECORD_HASH",
        "transaction_record_hash does not match the agreed transaction record",
        409,
        { sessionId },
      );
    }

    const messageId = (body.message_id as string) ?? randomUUID();
    pcData.dispute_notice = body;
    pcData.post_commitment_status = "DISPUTED";
    pcData.dispute_notice_message_id = messageId;
    ctx.sessionStore.save(sessionId, pcData);

    return sendA2cn(reply, {
      dispute_notice_message_id: messageId,
      session_id: sessionId,
      post_commitment_status: "DISPUTED",
      note: "Dispute recorded. Route to a designated neutral resolver or dispute resolution service.",
    });
  });

  app.post("/sessions/:session_id/dispute-resolved", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    const session = getSessionOr404(sessionId);
    const body = parseBody(request);

    if (body.session_id !== undefined && body.session_id !== null && body.session_id !== sessionId) {
      return sendError(
        reply,
        "SESSION_ID_MISMATCH",
        "session_id in request body does not match URL path",
        400,
        { sessionId },
      );
    }

    if (body.message_type !== "dispute_resolved") {
      return sendError(reply, "WRONG_MESSAGE_TYPE", "message_type must be 'dispute_resolved'", 400, {
        sessionId,
      });
    }

    const pcData = ctx.sessionStore.get(sessionId) ?? {};

    if (pcData.post_commitment_status !== "DISPUTED") {
      return sendError(
        reply,
        "NOT_IN_DISPUTED_STATUS",
        "dispute_resolved requires an open dispute_notice",
        400,
        { sessionId, specRef: "Section 11" },
      );
    }

    const storedDisputeId = pcData.dispute_notice_message_id;
    if (body.dispute_notice_message_id !== storedDisputeId) {
      return sendError(
        reply,
        "INVALID_REFERENCE",
        "dispute_notice_message_id does not match the stored dispute notice",
        409,
        { sessionId },
      );
    }

    let record: Dict;
    try {
      record = generateTransactionRecord(session);
    } catch (exc) {
      return sendError(
        reply,
        "INTERNAL_ERROR",
        `Could not generate transaction record: ${exc}`,
        500,
        { sessionId },
      );
    }

    if (body.transaction_record_hash !== record.record_hash) {
      return sendError(
        reply,
        "INVALID_RECORD_HASH",
        "transaction_record_hash does not match the agreed transaction record",
        409,
        { sessionId },
      );
    }

    const VALID_OUTCOMES = new Set(["buyer_prevails", "seller_prevails", "mutual_settlement"]);
    const resolutionOutcome = body.resolution_outcome;
    if (typeof resolutionOutcome !== "string" || !VALID_OUTCOMES.has(resolutionOutcome)) {
      return sendError(
        reply,
        "INVALID_RESOLUTION_OUTCOME",
        "resolution_outcome must be one of: buyer_prevails, seller_prevails, mutual_settlement",
        400,
        { sessionId },
      );
    }

    const resolverDid = body.resolver_did;
    if (typeof resolverDid !== "string" || !resolverDid) {
      return sendError(
        reply,
        "MISSING_REQUIRED_FIELD",
        "resolver_did is required and must be a non-empty string",
        400,
        { sessionId },
      );
    }

    const resolutionTimestamp = body.resolution_timestamp;
    if (typeof resolutionTimestamp !== "string" || !resolutionTimestamp) {
      return sendError(
        reply,
        "MISSING_REQUIRED_FIELD",
        "resolution_timestamp is required and must be a non-empty string",
        400,
        { sessionId },
      );
    }

    const messageId = (body.message_id as string) ?? randomUUID();

    pcData.dispute_resolution = body;
    pcData.post_commitment_status = "RESOLVED";
    pcData.dispute_resolved_message_id = messageId;
    const attestation = buildServerFulfillmentAttestation(sessionId, pcData, body);
    if (attestation !== null) {
      pcData.fulfillment_attestation = attestation;
    }
    ctx.sessionStore.save(sessionId, pcData);

    return sendA2cn(reply, {
      dispute_resolved_message_id: messageId,
      session_id: sessionId,
      resolution_outcome: resolutionOutcome,
      post_commitment_status: "RESOLVED",
    });
  });

  app.get("/sessions/:session_id/fulfillment-attestation", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { session_id: sessionId } = request.params as { session_id: string };
    getSessionOr404(sessionId);
    const pcData = ctx.sessionStore.get(sessionId) ?? {};
    const attestation = pcData.fulfillment_attestation as Dict | undefined;
    if (attestation) {
      return sendA2cn(reply, attestation);
    }

    if (pcData.post_commitment_status === "DISPUTED") {
      return sendError(
        reply,
        "FULFILLMENT_ATTESTATION_PENDING",
        "Session is disputed and has no DISPUTE_RESOLVED attestation yet",
        409,
        { sessionId },
      );
    }

    return sendError(
      reply,
      "FULFILLMENT_ATTESTATION_NOT_FOUND",
      "No fulfillment attestation has been emitted for this session",
      404,
      { sessionId },
    );
  });

  // -------------------------------------------------------------------
  // v0.2.0: Invitation endpoints (Component 8)
  // -------------------------------------------------------------------

  /**
   * Create and sign an outbound SessionInvitation.
   * The caller delivers it via their chosen channel.
   * If recipient_endpoint is provided, also POSTs it directly.
   */
  app.post("/invitations/create", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const body = parseBody(request);
    const cfg = ctx.responderConfig;
    const agentInfo = (cfg.agent_info as Dict) ?? {};
    const privateKey = cfg.private_key;

    if (!privateKey) {
      return sendError(reply, "INTERNAL_ERROR", "Server private key not configured", 500);
    }

    const invitation = invitationStore.createInvitation({
      inviterDid: (agentInfo.did as string) ?? "",
      inviterEndpoint: (agentInfo.endpoint as string) ?? "",
      inviterDiscoveryUrl: `${(agentInfo.endpoint as string) ?? ""}/.well-known/a2cn-agent`,
      inviterVerificationMethod: (agentInfo.verification_method as string) ?? "",
      privateKey,
      proposedDealType: (body.proposed_deal_type as string) ?? "",
      proposedSessionParams: (body.proposed_session_params as Dict) ?? {},
      proposedTermsSummary: (body.proposed_terms_summary as Dict) ?? {},
      inviterMandateSummary: (body.inviter_mandate_summary as Dict) ?? {},
      expiresHours: parseInt(String(body.expires_hours ?? 24), 10),
      baseUrl: (agentInfo.endpoint as string) || "http://localhost:8000",
    });

    const invitationDict = invitation.toDict();

    // Optionally deliver directly to recipient
    const recipientEndpoint = body.recipient_endpoint as string | undefined;
    if (recipientEndpoint) {
      try {
        await ctx.fetchFn(`${recipientEndpoint}/invitations`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(invitationDict),
          signal: AbortSignal.timeout(10_000),
        });
      } catch (exc) {
        console.warn(`Failed to deliver invitation to ${recipientEndpoint}: ${exc}`);
      }
    }

    return sendA2cn(reply, invitationDict, 201);
  });

  /**
   * Receive an inbound SessionInvitation from a counterparty.
   * Verifies the signature, then stores with PENDING status.
   */
  app.post("/invitations", async (request, reply) => {
    const body = parseBody(request);

    if (body.a2cn_version !== "0.2") {
      return sendError(
        reply,
        INVITATION_VERSION_MISMATCH,
        `Unsupported a2cn_version: ${JSON.stringify(body.a2cn_version)}`,
        400,
      );
    }

    // Signature verification is REQUIRED (Section 9.3)
    const inviterDid = (body.inviter_did as string) ?? "";
    if (!inviterDid) {
      return sendError(reply, "MISSING_INVITER_DID", "inviter_did is required", 400);
    }
    const vmId = (body.inviter_verification_method as string) ?? "";
    if (!vmId) {
      return sendError(
        reply,
        "MISSING_VERIFICATION_METHOD",
        "inviter_verification_method is required",
        400,
      );
    }
    if (!body.invitation_signature) {
      return sendError(
        reply,
        "MISSING_INVITATION_SIGNATURE",
        "invitation_signature is required",
        400,
      );
    }

    // Resolve DID document (didDocOverride first, then HTTP)
    let didDoc: Dict;
    if (inviterDid in ctx.didDocOverride) {
      didDoc = ctx.didDocOverride[inviterDid];
    } else {
      try {
        didDoc = await resolveDidWeb(inviterDid, ctx.fetchFn);
      } catch (exc) {
        if (exc instanceof Error && /HTTP 404/.test(exc.message)) {
          return sendError(reply, INVITATION_SIGNATURE_INVALID, "Inviter DID not found", 403);
        }
        return sendError(reply, "DID_RESOLUTION_FAILED", "Temporary DID resolution failure", 503);
      }
    }

    let pubKey;
    try {
      const vm = getVerificationMethod(didDoc, vmId);
      pubKey = getPublicKey(vm);
    } catch (exc) {
      return sendError(
        reply,
        INVITATION_SIGNATURE_INVALID,
        `Verification method not found: ${exc instanceof Error ? exc.message : exc}`,
        400,
      );
    }

    if (!verifyInvitationSignature(body, pubKey)) {
      return sendError(reply, INVITATION_SIGNATURE_INVALID, "Invitation signature is invalid", 400);
    }

    invitationStore.storeInbound(body);
    return sendA2cn(reply, { invitation_id: body.invitation_id, status: "pending" }, 201);
  });

  /** Accept a stored invitation. */
  app.post("/invitations/:invitation_id/accept", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { invitation_id: invitationId } = request.params as { invitation_id: string };
    const body = parseBody(request);
    const cfg = ctx.responderConfig;
    const agentInfo = (cfg.agent_info as Dict) ?? {};
    const privateKey = cfg.private_key;

    if (!privateKey) {
      return sendError(reply, "INTERNAL_ERROR", "Server private key not configured", 500);
    }

    let acceptance;
    try {
      acceptance = invitationStore.acceptInvitation({
        invitationId,
        acceptorDid: (body.acceptor_did as string) ?? ((agentInfo.did as string) || ""),
        acceptorA2cnEndpoint:
          (body.acceptor_a2cn_endpoint as string) ?? ((agentInfo.endpoint as string) || ""),
        acceptorDiscoveryUrl:
          (body.acceptor_discovery_url as string) ??
          `${(agentInfo.endpoint as string) ?? ""}/.well-known/a2cn-agent`,
        acceptorVerificationMethod:
          (body.acceptor_verification_method as string) ??
          ((agentInfo.verification_method as string) || ""),
        privateKey,
      });
    } catch (exc) {
      const code = exc instanceof Error ? exc.message : String(exc);
      const status =
        {
          [INVITATION_NOT_FOUND]: 404,
          [INVITATION_EXPIRED]: 410,
          [INVITATION_ALREADY_ANSWERED]: 409,
        }[code] ?? 400;
      return sendError(reply, code, code.replaceAll("_", " ").toLowerCase(), status);
    }

    return sendA2cn(reply, acceptance.toDict());
  });

  /** Decline a stored invitation. */
  app.post("/invitations/:invitation_id/decline", async (request, reply) => {
    await verifyJwtAuth(ctx, request);
    const { invitation_id: invitationId } = request.params as { invitation_id: string };
    const body = parseBody(request);

    let decline;
    try {
      decline = invitationStore.declineInvitation(
        invitationId,
        (body.reason_code as string) ?? "OTHER",
        (body.reason_message as string) ?? "",
      );
    } catch (exc) {
      const code = exc instanceof Error ? exc.message : String(exc);
      const status =
        {
          [INVITATION_NOT_FOUND]: 404,
          [INVITATION_EXPIRED]: 410,
          [INVITATION_ALREADY_ANSWERED]: 409,
        }[code] ?? 400;
      return sendError(reply, code, code.replaceAll("_", " ").toLowerCase(), status);
    }

    return sendA2cn(reply, decline.toDict());
  });

  /** Get status of any invitation (inbound or outbound). */
  app.get("/invitations/:invitation_id", async (request, reply) => {
    const { invitation_id: invitationId } = request.params as { invitation_id: string };
    const entry = invitationStore.getInvitation(invitationId);
    if (entry === null) {
      return sendError(
        reply,
        INVITATION_NOT_FOUND,
        `Invitation ${JSON.stringify(invitationId)} not found`,
        404,
      );
    }
    return sendA2cn(reply, {
      invitation_id: invitationId,
      status: entry.status,
      invitation: entry.invitation,
      created_at: entry.created_at,
      answered_at: entry.answered_at,
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** JSON with sorted keys and no whitespace (mirror of Python json.dumps sort_keys/compact). */
function sortedCompactJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}
