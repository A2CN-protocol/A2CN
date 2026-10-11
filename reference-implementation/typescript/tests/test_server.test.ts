/** Tests for a2cn/server — Fastify endpoints. */

import { randomUUID, type KeyObject } from "node:crypto";
import { expect, test } from "vitest";

import {
  createJwt,
  generateEd25519Keypair,
  generateKeypair,
  hashBytes,
  hashObject,
  publicKeyToJwk,
  signApprovalReceipt,
  signInvitation,
  signJws,
  verifyJws,
  b64urlDecode,
} from "../src/a2cn/crypto.js";
import { createServerContext } from "../src/a2cn/server.js";
import type { Dict } from "../src/a2cn/messages.js";
import {
  INITIATOR_DID,
  RESPONDER_DID,
  SERVER_DID,
  makeDidDocument,
  makeSessionInit,
  makeTestClient,
  freshServer,
  signDecline,
  type TestClient,
} from "./conftest.js";

function initHeaders(messageId: string): Record<string, string> {
  return { "Content-Type": "application/a2cn+json", "Idempotency-Key": messageId };
}

// ---------------------------------------------------------------------------
// GET /.well-known/a2cn-agent — discovery
// ---------------------------------------------------------------------------

test("discovery document", async () => {
  const { client } = freshServer();
  const r = await client.get("/.well-known/a2cn-agent");
  expect(r.statusCode).toBe(200);
  const doc = r.json();
  expect(doc.a2cn_version).toBe("0.3");
  expect(doc.deal_types).toContain("saas_renewal");
  expect(doc.conformance_level).toBe(2);
  expect(doc.agent_did).toBe(RESPONDER_DID);
});

// ---------------------------------------------------------------------------
// POST /sessions
// ---------------------------------------------------------------------------

test("session init returns 201", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  expect(r.statusCode).toBe(201);
  const data = r.json();
  expect(data.message_type).toBe("session_ack");
  expect("session_id" in data).toBe(true);
  expect(data.current_turn).toBe("initiator");
});

test("session init accepts ed25519 jwt", async () => {
  const { ctx, rawClient } = freshServer();

  const { privateKey, publicKey } = generateEd25519Keypair();
  ctx.registerDidDocument(
    INITIATOR_DID,
    makeDidDocument(INITIATOR_DID, "ed25519-1", publicKeyToJwk(publicKey)),
  );

  const body = makeSessionInit();
  (body.initiator as Dict).verification_method = `${INITIATOR_DID}#ed25519-1`;
  const token = await createJwt(INITIATOR_DID, SERVER_DID, privateKey, {
    kid: `${INITIATOR_DID}#ed25519-1`,
    expSeconds: 3600,
  });
  const headers = initHeaders(body.message_id as string);
  headers.Authorization = `Bearer ${token}`;

  const r = await rawClient.post("/sessions", { json: body, headers });

  expect(r.statusCode).toBe(201);
  expect(r.json().current_turn).toBe("initiator");
});

test("session init rejects initiator did mismatch", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  (body.initiator as Dict).did = "did:web:impostor.example";

  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });

  expect(r.statusCode).toBe(401);
  const error = r.json().error as Dict;
  expect(error.code).toBe("SENDER_DID_MISMATCH");
  expect(error.message).toContain("initiator.did");
});

test("session init content type", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  expect(String(r.headers["content-type"])).toContain("application/a2cn+json");
});

test("session init idempotency", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  const h = initHeaders(body.message_id as string);
  const r1 = await client.post("/sessions", { json: body, headers: h });
  const r2 = await client.post("/sessions", { json: body, headers: h });
  expect(r1.json().session_id).toBe(r2.json().session_id);
});

test("session init wrong deal type", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  (body.session_params as Dict).deal_type = "freight_rate"; // not supported
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  expect(r.statusCode).toBe(403);
  expect((r.json().error as Dict).code).toBe("DEAL_TYPE_NOT_SUPPORTED");
});

// ---------------------------------------------------------------------------
// POST /invitations — signature-authenticated cold-start delivery
// ---------------------------------------------------------------------------

test("receive invitation does not require bearer token", async () => {
  const { ctx, rawClient } = freshServer();

  const { privateKey: inviterPriv, publicKey: inviterPub } = generateKeypair();
  const inviterDid = "did:web:buyer.example";
  const vmId = `${inviterDid}#key-1`;
  ctx.registerDidDocument(
    inviterDid,
    makeDidDocument(inviterDid, "key-1", publicKeyToJwk(inviterPub)),
  );
  const invitation: Dict = {
    message_type: "session_invitation",
    invitation_id: randomUUID(),
    a2cn_version: "0.3",
    inviter_did: inviterDid,
    inviter_endpoint: "https://buyer.example/a2cn",
    inviter_discovery_url: "https://buyer.example/.well-known/a2cn-agent",
    proposed_deal_type: "saas_renewal",
    proposed_session_params: {
      currency: "USD",
      max_rounds: 4,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
    },
    proposed_terms_summary: { total_value: 9_500_000, currency: "USD" },
    inviter_mandate_summary: { mandate_type: "declared" },
    invitation_expires_at: "2030-01-01T00:00:00Z",
    accept_endpoint: "https://buyer.example/a2cn/invitations/test/accept",
    decline_endpoint: "https://buyer.example/a2cn/invitations/test/decline",
    inviter_verification_method: vmId,
    invitation_signature: "",
  };
  invitation.invitation_signature = signInvitation(invitation, inviterPriv);

  const r = await rawClient.post("/invitations", { json: invitation });

  expect(r.statusCode).toBe(201);
  expect(r.json()).toEqual({
    invitation_id: invitation.invitation_id,
    status: "pending",
  });
});

test("invitation create still requires bearer token", async () => {
  const { rawClient } = freshServer();
  const r = await rawClient.post("/invitations/create", { json: {} });

  expect(r.statusCode).toBe(401);
  expect((r.json().error as Dict).code).toBe("INVALID_JWT");
});

test("session init expired mandate", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  (body.initiator_mandate as Dict).valid_until = "2020-01-01T00:00:00Z"; // in the past
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  expect(r.statusCode).toBe(403);
  expect((r.json().error as Dict).code).toBe("MANDATE_INVALID");
});

test("session init wrong protocol version", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  body.protocol_version = "0.1";
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  expect(r.statusCode).toBe(400);
  expect((r.json().error as Dict).code).toBe("PROTOCOL_VERSION_MISMATCH");
});

test("session init at a superseded version is refused", async () => {
  // "0.2" is recognised for verifying records, never for establishing a session
  // (Section 11.2.1).
  const { client } = freshServer();
  const body = makeSessionInit();
  body.protocol_version = "0.2";
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  expect(r.statusCode).toBe(400);
  expect((r.json().error as Dict).code).toBe("PROTOCOL_VERSION_MISMATCH");
  expect((r.json().error as Dict).message).toBe("Only protocol_version '0.3' is supported");
  expect("session_id" in r.json()).toBe(false);
});

test("invitation at a superseded version is refused", async () => {
  const { rawClient } = freshServer();
  const r = await rawClient.post("/invitations", {
    json: { message_type: "session_invitation", a2cn_version: "0.2" },
  });
  expect(r.statusCode).toBe(400);
  expect((r.json().error as Dict).code).toBe("INVITATION_VERSION_MISMATCH");
});

// ---------------------------------------------------------------------------
// GET /sessions/{session_id}
// ---------------------------------------------------------------------------

test("get session state", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  const sessionId = r.json().session_id as string;

  const r2 = await client.get(`/sessions/${sessionId}`);
  expect(r2.statusCode).toBe(200);
  const data = r2.json();
  expect(data.session_id).toBe(sessionId);
  expect(data.state).toBe("ACTIVE");
});

test("get session not found", async () => {
  const { client } = freshServer();
  const r = await client.get("/sessions/nonexistent-id");
  expect(r.statusCode).toBe(404);
  expect((r.json().error as Dict).code).toBe("SESSION_NOT_FOUND");
});

// ---------------------------------------------------------------------------
// Webhook delivery
// ---------------------------------------------------------------------------

test("deliver webhook uses did key jws signature", async () => {
  const { ctx } = freshServer();
  const { privateKey, publicKey } = generateKeypair();

  const captured: Array<{ url: string; body: Buffer; headers: Record<string, string> }> = [];
  ctx.fetchFn = (async (url: string | URL | Request, init?: RequestInit) => {
    captured.push({
      url: String(url),
      body: Buffer.from(init?.body as Buffer),
      headers: (init?.headers as Record<string, string>) ?? {},
    });
    return new Response(null, { status: 204 });
  }) as typeof fetch;

  const payload = {
    event_type: "session.completed",
    session_id: "session-123",
    occurred_at: "2026-05-20T05:00:00Z",
    session_state: "COMPLETED",
    terminal: true,
    a2cn_version: "0.3",
  };

  await ctx.deliverWebhook(
    "https://receiver.example/a2cn/callbacks",
    "session.completed",
    "session-123",
    payload,
    { max_retries: 1 },
    {
      senderDid: INITIATOR_DID,
      senderVerificationMethod: `${INITIATOR_DID}#key-1`,
      privateKey,
    },
  );

  expect(captured.length).toBe(1);
  const request = captured[0];
  const bodyHash = hashBytes(request.body);

  expect(request.headers["X-A2CN-Sender-DID"]).toBe(INITIATOR_DID);
  expect(request.headers["X-A2CN-Sender-Verification-Method"]).toBe(`${INITIATOR_DID}#key-1`);
  expect(request.headers["X-A2CN-Body-SHA256"]).toBe(bodyHash);
  const signatureHeader = JSON.parse(
    b64urlDecode(request.headers["X-A2CN-Signature"].split(".")[0]).toString("utf-8"),
  );
  expect(signatureHeader.alg).toBe("ES256");
  expect(signatureHeader.kid).toBe(`${INITIATOR_DID}#key-1`);
  expect(verifyJws(request.headers["X-A2CN-Signature"], publicKey)).toBe(bodyHash);
});

// ---------------------------------------------------------------------------
// POST /sessions/{session_id}/messages
// ---------------------------------------------------------------------------

async function createSession(client: TestClient): Promise<string> {
  const body = makeSessionInit();
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  return r.json().session_id as string;
}

function makeOfferMsg(
  sessionId: string,
  seq: number,
  rnd: number,
  senderDid: string,
  privateKey: KeyObject,
  options: { msgType?: string; inReplyTo?: string | null; msgId?: string | null } = {},
): Dict {
  const { msgType = "offer", inReplyTo = null } = options;
  const msgId = options.msgId ?? randomUUID();
  const timestamp = "2026-03-24T10:01:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const terms = { total_value: 9_500_000, currency: "USD" };
  const protocolAct = {
    protocol_version: "0.3",
    session_id: sessionId,
    round_number: rnd,
    sequence_number: seq,
    message_type: msgType,
    sender_did: senderDid,
    timestamp,
    expires_at: expiresAt,
    terms,
  };
  const pah = hashObject(protocolAct);
  const verificationMethod =
    senderDid === INITIATOR_DID ? `${INITIATOR_DID}#key-1` : `${RESPONDER_DID}#key-2026-01`;
  const msg: Dict = {
    message_type: msgType,
    message_id: msgId,
    session_id: sessionId,
    round_number: rnd,
    sequence_number: seq,
    sender_did: senderDid,
    sender_agent_id: "test-agent",
    sender_verification_method: verificationMethod,
    timestamp,
    expires_at: expiresAt,
    terms,
    protocol_act_hash: pah,
    protocol_act_signature: signJws(pah, privateKey, verificationMethod),
  };
  if (inReplyTo) {
    msg.in_reply_to = inReplyTo;
  }
  return msg;
}

test("send offer succeeds", async () => {
  const { client, initiatorKeypair } = freshServer();
  const sessionId = await createSession(client);
  const offer = makeOfferMsg(sessionId, 1, 1, INITIATOR_DID, initiatorKeypair.privateKey);
  const r = await client.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: initHeaders(offer.message_id as string),
  });
  expect(r.statusCode).toBe(200);
});

test("not your turn", async () => {
  const fixture = freshServer();
  const sessionId = await createSession(fixture.client);
  const responderClient = fixture.makeResponderClient();
  // Responder tries to send before initiator
  const offer = makeOfferMsg(sessionId, 1, 1, RESPONDER_DID, fixture.responderKeypair.privateKey);
  const r = await responderClient.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: initHeaders(offer.message_id as string),
  });
  expect(r.statusCode).toBe(409);
  expect((r.json().error as Dict).code).toBe("NOT_YOUR_TURN");
});

test("sequence error", async () => {
  const { client, initiatorKeypair } = freshServer();
  const sessionId = await createSession(client);
  const offer = makeOfferMsg(sessionId, 5, 1, INITIATOR_DID, initiatorKeypair.privateKey); // wrong seq
  const r = await client.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: initHeaders(offer.message_id as string),
  });
  expect(r.statusCode).toBe(422);
  expect((r.json().error as Dict).code).toBe("SEQUENCE_ERROR");
});

test("message idempotency", async () => {
  const { client, initiatorKeypair } = freshServer();
  const sessionId = await createSession(client);
  const offer = makeOfferMsg(sessionId, 1, 1, INITIATOR_DID, initiatorKeypair.privateKey);
  const h = initHeaders(offer.message_id as string);
  const r1 = await client.post(`/sessions/${sessionId}/messages`, { json: offer, headers: h });
  const r2 = await client.post(`/sessions/${sessionId}/messages`, { json: offer, headers: h });
  expect(r1.json()).toEqual(r2.json());
});

test("get messages cursor tolerates sequence less page item", async () => {
  const { client, initiatorKeypair } = freshServer();
  const sessionId = await createSession(client);
  const offer = makeOfferMsg(sessionId, 1, 1, INITIATOR_DID, initiatorKeypair.privateKey);
  await client.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: initHeaders(offer.message_id as string),
  });

  const r = await client.get(`/sessions/${sessionId}/messages`, {
    params: { after_sequence: -1, limit: 1 },
  });

  expect(r.statusCode).toBe(200);
  expect(r.json().next_cursor).toBeNull();
});

const APPROVER_DID = "did:web:approver.example";
const { privateKey: APPROVER_PRIVATE_KEY, publicKey: APPROVER_PUBLIC_KEY } = generateEd25519Keypair();

/** A session whose initiator offer is paused for an operator's approval. */
async function pausedOverHttp(
  fixture: ReturnType<typeof freshServer> = freshServer(),
  approvers: string[] = [APPROVER_DID],
): Promise<{
  client: TestClient;
  sessionId: string;
  offer: Dict;
  mandate: Dict;
  initiatorKeypair: { privateKey: KeyObject };
}> {
  const { ctx, client, initiatorKeypair } = fixture;
  ctx.registerDidDocument(
    APPROVER_DID,
    makeDidDocument(APPROVER_DID, "key-1", publicKeyToJwk(APPROVER_PUBLIC_KEY)),
  );
  const body = makeSessionInit();
  (body.initiator_mandate as Dict).requires_human_approval_above = 9_000_000;
  (body.initiator_mandate as Dict).approval_operator_dids = [...approvers];
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  const sessionId = r.json().session_id as string;

  const offer = makeOfferMsg(sessionId, 1, 1, INITIATOR_DID, initiatorKeypair.privateKey);
  const offerR = await client.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: initHeaders(offer.message_id as string),
  });
  expect(offerR.statusCode).toBe(200);
  expect(offerR.json().state).toBe("AWAITING_HUMAN_APPROVAL");
  return { client, sessionId, offer, mandate: body.initiator_mandate as Dict, initiatorKeypair };
}

function httpReceipt(
  sessionId: string,
  offer: Dict,
  mandate: Dict,
  approverDid: string,
  receiptId = "urn:concordia:receipt:test",
): Dict {
  return {
    artifact_type: "ApprovalReceipt",
    id: receiptId,
    scope: {
      decision: "approve",
      offer_hash: offer.protocol_act_hash,
      amount: "95000.00 USD",
      threshold_crossed: "90000.00 USD",
    },
    references: [
      {
        type: "negotiation_session",
        id: `a2cn:session:${sessionId}`,
        relationship: "approves",
      },
      {
        type: "mandate",
        id: hashObject(mandate),
        relationship: "fulfills",
      },
    ],
    approver_did: approverDid,
    expires_at: "2030-01-01T00:00:00Z",
  };
}

test("approval receipt endpoint releases human approval pause", async () => {
  const { client, sessionId, offer, mandate } = await pausedOverHttp();
  const receipt = httpReceipt(sessionId, offer, mandate, APPROVER_DID);
  receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);

  const receiptR = await client.post(`/sessions/${sessionId}/approval-receipt`, {
    json: receipt,
    headers: initHeaders("approval-receipt-test"),
  });

  expect(receiptR.statusCode).toBe(200);
  expect(receiptR.json().state).toBe("NEGOTIATING");
  expect(receiptR.json().current_turn).toBe("responder");
  expect(receiptR.json().approval_receipt_id).toBe("urn:concordia:receipt:test");
});

test("a session party cannot release its own pause with an unsigned receipt", async () => {
  // The paused agent posts an unsigned receipt naming an authorised approver.
  // It is refused and the session stays paused.
  const { client, sessionId, offer, mandate } = await pausedOverHttp();
  const receipt = httpReceipt(sessionId, offer, mandate, APPROVER_DID);

  const receiptR = await client.post(`/sessions/${sessionId}/approval-receipt`, {
    json: receipt,
    headers: initHeaders("approval-receipt-unsigned"),
  });

  expect(receiptR.statusCode).toBe(400);
  expect((receiptR.json().error as Dict).code).toBe("APPROVAL_RECEIPT_UNSIGNED");
  const state = (await client.get(`/sessions/${sessionId}`)).json();
  expect(state.state).toBe("AWAITING_HUMAN_APPROVAL");
});

test("a receipt signed with the paused agents own key is refused", async () => {
  const { client, sessionId, offer, mandate, initiatorKeypair } = await pausedOverHttp();
  const receipt = httpReceipt(sessionId, offer, mandate, APPROVER_DID);
  receipt.signature = signApprovalReceipt(receipt, initiatorKeypair.privateKey);

  const receiptR = await client.post(`/sessions/${sessionId}/approval-receipt`, {
    json: receipt,
    headers: initHeaders("approval-receipt-self-signed"),
  });

  expect(receiptR.statusCode).toBe(400);
  expect((receiptR.json().error as Dict).code).toBe("APPROVAL_RECEIPT_SIGNATURE_INVALID");
  const state = (await client.get(`/sessions/${sessionId}`)).json();
  expect(state.state).toBe("AWAITING_HUMAN_APPROVAL");
});

// ---------------------------------------------------------------------------
// GET /sessions/{session_id}/record — COMPLETED only
// ---------------------------------------------------------------------------

test("record not available for active session", async () => {
  const { client } = freshServer();
  const sessionId = await createSession(client);
  const r = await client.get(`/sessions/${sessionId}/record`);
  expect(r.statusCode).toBe(409);
  expect((r.json().error as Dict).code).toBe("SESSION_WRONG_STATE");
});

// ---------------------------------------------------------------------------
// GET /sessions/{session_id}/evidence — terminal only
// ---------------------------------------------------------------------------

test("evidence not available for active session", async () => {
  const { client } = freshServer();
  const sessionId = await createSession(client);
  const r = await client.get(`/sessions/${sessionId}/evidence`);
  expect(r.statusCode).toBe(409);
  expect((r.json().error as Dict).code).toBe("SESSION_WRONG_STATE");
});

test("evidence available after withdrawal", async () => {
  const { client, initiatorKeypair } = freshServer();
  const sessionId = await createSession(client);
  const withdrawal = {
    message_type: "withdrawal",
    message_id: randomUUID(),
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "test-agent",
    timestamp: "2026-03-24T10:02:00Z",
    reason_code: "STRATEGY_DECISION",
  };
  const signedWithdrawal = signDecline(
    withdrawal,
    initiatorKeypair.privateKey,
    `${INITIATOR_DID}#key-1`,
  );
  await client.post(`/sessions/${sessionId}/messages`, {
    json: signedWithdrawal,
    headers: initHeaders(withdrawal.message_id),
  });

  const r = await client.get(`/sessions/${sessionId}/evidence`);

  expect(r.statusCode).toBe(200);
  const data = r.json();
  expect(data.record_type).toBe("a2cn_session_evidence_record");
  expect((data.terminal as Dict).outcome).toBe("WITHDRAWN");
  expect(data.evidence_level).toBe("unilateral");
  expect((data.producer as Dict).did).toBe(RESPONDER_DID);
  expect(data.producer_signature).toBeTruthy();
});

test("evidence rejects authenticated nonparty", async () => {
  const { ctx, client, initiatorKeypair } = freshServer();
  const sessionId = await createSession(client);
  const withdrawal = {
    message_type: "withdrawal",
    message_id: randomUUID(),
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    timestamp: "2026-03-24T10:02:00Z",
    reason_code: "STRATEGY_DECISION",
  };
  const signedWithdrawal = signDecline(
    withdrawal,
    initiatorKeypair.privateKey,
    `${INITIATOR_DID}#key-1`,
  );
  await client.post(`/sessions/${sessionId}/messages`, {
    json: signedWithdrawal,
    headers: initHeaders(withdrawal.message_id),
  });

  const outsiderDid = "did:web:observer.example";
  const outsiderKeypair = generateKeypair();
  ctx.registerDidDocument(
    outsiderDid,
    makeDidDocument(outsiderDid, "key-1", publicKeyToJwk(outsiderKeypair.publicKey)),
  );
  const outsider = makeTestClient(ctx, {
    issuerDid: outsiderDid,
    audienceDid: SERVER_DID,
    privateKey: outsiderKeypair.privateKey,
    kid: `${outsiderDid}#key-1`,
  });

  const response = await outsider.get(`/sessions/${sessionId}/evidence`);

  expect(response.statusCode).toBe(403);
  expect((response.json().error as Dict).code).toBe("NOT_SESSION_PARTY");
});

test("an incomplete unsigned withdrawal is refused on the wire", async () => {
  // A live withdrawal must be signed, and one this incomplete cannot even be
  // rebuilt. It was once accepted and recorded as an unsigned observation with
  // null message_id and timestamp. A party's own decline is now signed (Section
  // 7.6), so the session stays open; the evidence record's handling of an
  // incomplete unsigned act is covered where such an act is recorded.
  const { client } = freshServer();
  const sessionId = await createSession(client);
  const withdrawal = {
    message_type: "withdrawal",
    round_number: 1,
    sender_did: INITIATOR_DID,
  };
  const response = await client.post(`/sessions/${sessionId}/messages`, {
    json: withdrawal,
    headers: initHeaders("incomplete-withdrawal"),
  });

  expect(response.statusCode).toBe(400);
  expect((response.json().error as Dict).code).toBe("INVALID_SIGNATURE");
  const evidenceResponse = await client.get(`/sessions/${sessionId}/evidence`);
  expect(evidenceResponse.statusCode).toBe(409);
});

// ---------------------------------------------------------------------------
// GET /sessions/{session_id}/audit — terminal only
// ---------------------------------------------------------------------------

test("audit not available for active session", async () => {
  const { client } = freshServer();
  const sessionId = await createSession(client);
  const r = await client.get(`/sessions/${sessionId}/audit`);
  expect(r.statusCode).toBe(409);
});

test("audit available after withdrawal", async () => {
  const { client, initiatorKeypair } = freshServer();
  const sessionId = await createSession(client);
  const withdrawal = {
    message_type: "withdrawal",
    message_id: randomUUID(),
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "test-agent",
    timestamp: "2026-03-24T10:02:00Z",
    reason_code: "STRATEGY_DECISION",
  };
  const signedWithdrawal = signDecline(
    withdrawal,
    initiatorKeypair.privateKey,
    `${INITIATOR_DID}#key-1`,
  );
  await client.post(`/sessions/${sessionId}/messages`, {
    json: signedWithdrawal,
    headers: initHeaders(withdrawal.message_id),
  });
  const r = await client.get(`/sessions/${sessionId}/audit`);
  expect(r.statusCode).toBe(200);
  const data = r.json();
  expect(data.session_outcome).toBe("WITHDRAWN");
});

// --- The approver's DID document is resolved per receipt, after the cheap checks. ---

const DYNAMIC_APPROVER_DID = "did:web:dyn-approver.example";
const DYNAMIC_APPROVER_URL = "https://dyn-approver.example/.well-known/did.json";

/** Serve DID documents from `documents` by URL, counting every fetch. */
function serveDidDocuments(
  ctx: ReturnType<typeof freshServer>["ctx"],
  documents: Record<string, Dict>,
): { calls: string[] } {
  const calls: string[] = [];
  ctx.fetchFn = (async (url: string | URL | Request) => {
    const target = String(url);
    calls.push(target);
    const document = documents[target];
    return document === undefined
      ? new Response("not found", { status: 404 })
      : new Response(JSON.stringify(document), { status: 200, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return { calls };
}

async function postReceipt(client: TestClient, sessionId: string, receipt: Dict, key: KeyObject) {
  const signed = { ...receipt, signature: signApprovalReceipt(receipt, key) };
  return client.post(`/sessions/${sessionId}/approval-receipt`, {
    json: signed,
    headers: initHeaders(`receipt-${randomUUID()}`),
  });
}

test("an unregistered did web approver is resolved for the receipt", async () => {
  const fixture = freshServer();
  const { privateKey: key, publicKey } = generateEd25519Keypair();
  const { calls } = serveDidDocuments(fixture.ctx, {
    [DYNAMIC_APPROVER_URL]: makeDidDocument(DYNAMIC_APPROVER_DID, "key-1", publicKeyToJwk(publicKey)),
  });
  const { client, sessionId, offer, mandate } = await pausedOverHttp(fixture, [DYNAMIC_APPROVER_DID]);
  const r = await postReceipt(client, sessionId, httpReceipt(sessionId, offer, mandate, DYNAMIC_APPROVER_DID), key);
  expect(r.statusCode).toBe(200);
  expect(r.json().state).toBe("NEGOTIATING");
  expect(calls.filter((u) => u === DYNAMIC_APPROVER_URL)).toHaveLength(1);
});

test("a rotated approver key takes effect on the next receipt", async () => {
  const fixture = freshServer();
  const { privateKey: oldKey, publicKey: oldPublic } = generateEd25519Keypair();
  const { privateKey: newKey, publicKey: newPublic } = generateEd25519Keypair();
  const documents: Record<string, Dict> = {
    [DYNAMIC_APPROVER_URL]: makeDidDocument(DYNAMIC_APPROVER_DID, "key-1", publicKeyToJwk(oldPublic)),
  };
  serveDidDocuments(fixture.ctx, documents);
  const first = await pausedOverHttp(fixture, [DYNAMIC_APPROVER_DID]);
  const ok = await postReceipt(first.client, first.sessionId, httpReceipt(first.sessionId, first.offer, first.mandate, DYNAMIC_APPROVER_DID), oldKey);
  expect(ok.statusCode).toBe(200);

  // The approver rotates: its document now lists only the new key.
  documents[DYNAMIC_APPROVER_URL] = makeDidDocument(DYNAMIC_APPROVER_DID, "key-2", publicKeyToJwk(newPublic));
  const second = await pausedOverHttp(fixture, [DYNAMIC_APPROVER_DID]);
  const old = await postReceipt(second.client, second.sessionId, httpReceipt(second.sessionId, second.offer, second.mandate, DYNAMIC_APPROVER_DID, "urn:r:old"), oldKey);
  const fresh = await postReceipt(second.client, second.sessionId, httpReceipt(second.sessionId, second.offer, second.mandate, DYNAMIC_APPROVER_DID, "urn:r:new"), newKey);
  expect(old.statusCode).toBe(400);
  expect((old.json().error as Dict).code).toBe("APPROVAL_RECEIPT_SIGNATURE_INVALID");
  expect(fresh.statusCode).toBe(200);
  expect(fresh.json().state).toBe("NEGOTIATING");
});

test("a did url approver is resolved from its base did", async () => {
  const fixture = freshServer();
  const { privateKey: key, publicKey } = generateEd25519Keypair();
  const approver = `${DYNAMIC_APPROVER_DID}#key-1`;
  const { calls } = serveDidDocuments(fixture.ctx, {
    [DYNAMIC_APPROVER_URL]: makeDidDocument(DYNAMIC_APPROVER_DID, "key-1", publicKeyToJwk(publicKey)),
  });
  const { client, sessionId, offer, mandate } = await pausedOverHttp(fixture, [approver]);
  const r = await postReceipt(client, sessionId, httpReceipt(sessionId, offer, mandate, approver), key);
  expect(r.statusCode).toBe(200);
  expect(calls.filter((u) => u === DYNAMIC_APPROVER_URL)).toHaveLength(1);
});

test("an approver outside did web is never fetched", async () => {
  const fixture = freshServer();
  const { privateKey: key } = generateEd25519Keypair();
  const approver = "did:example:approver";
  const { calls } = serveDidDocuments(fixture.ctx, {});
  const { client, sessionId, offer, mandate } = await pausedOverHttp(fixture, [approver]);
  const before = calls.length;
  const r = await postReceipt(client, sessionId, httpReceipt(sessionId, offer, mandate, approver), key);
  expect(r.statusCode).toBe(400);
  expect((r.json().error as Dict).code).toBe("APPROVAL_RECEIPT_KEY_UNRESOLVED");
  expect(calls.length).toBe(before);
});

test("a receipt failing a check that needs no key causes no fetch", async () => {
  const fixture = freshServer();
  const { privateKey: key, publicKey } = generateEd25519Keypair();
  const { calls } = serveDidDocuments(fixture.ctx, {
    [DYNAMIC_APPROVER_URL]: makeDidDocument(DYNAMIC_APPROVER_DID, "key-1", publicKeyToJwk(publicKey)),
  });
  const { client, sessionId, offer, mandate } = await pausedOverHttp(fixture); // approver not authorised
  const r = await postReceipt(client, sessionId, httpReceipt(sessionId, offer, mandate, DYNAMIC_APPROVER_DID), key);
  expect(r.statusCode).toBe(403);
  expect((r.json().error as Dict).code).toBe("UNAUTHORIZED_APPROVER");
  expect(calls.filter((u) => u === DYNAMIC_APPROVER_URL)).toHaveLength(0);
});

for (const [label, body] of [
  ["null", null],
  ["array", []],
  ["string", "receipt"],
  ["number", 5],
  ["boolean", true],
] as const) {
  test(`a non object receipt body is refused cleanly: ${label}`, async () => {
    const { client, sessionId } = await pausedOverHttp();
    const r = await client.post(`/sessions/${sessionId}/approval-receipt`, {
      json: body,
      headers: initHeaders("receipt-non-object"),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("APPROVAL_RECEIPT_INVALID");
  });
}
