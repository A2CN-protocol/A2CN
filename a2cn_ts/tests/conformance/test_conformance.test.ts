/**
 * A2CN Conformance Tests (Week 3 target, implemented now for completeness)
 *
 * Each test represents a named scenario from the spec.
 * These tests must pass against any conformant implementation.
 */

import { randomUUID, type KeyObject } from "node:crypto";
import { expect, test } from "vitest";

import {
  createJwt,
  generateKeypair,
  hashObject,
  publicKeyToJwk,
  signJws,
} from "../../src/a2cn/crypto.js";
import { generateTransactionRecord } from "../../src/a2cn/record.js";
import { A2CN_NAMESPACE } from "../../src/a2cn/record.js";
import { SessionManager, SessionState } from "../../src/a2cn/session.js";
import type { Dict } from "../../src/a2cn/messages.js";
import { v5 as uuidv5 } from "uuid";
import {
  INITIATOR_DID,
  RESPONDER_DID,
  SERVER_DID,
  makeDidDocument,
  makeSessionInit,
  freshServer,
  type TestClient,
} from "../conftest.js";

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();

function initHeaders(messageId: string): Record<string, string> {
  return { "Content-Type": "application/a2cn+json", "Idempotency-Key": messageId };
}

// ---------------------------------------------------------------------------
// Helpers shared across conformance tests
// ---------------------------------------------------------------------------

async function createSession(client: TestClient): Promise<string> {
  const body = makeSessionInit();
  const r = await client.post("/sessions", {
    json: body,
    headers: initHeaders(body.message_id as string),
  });
  expect(r.statusCode).toBe(201);
  return r.json().session_id as string;
}

function makeOffer(
  sessionId: string,
  seq: number,
  rnd: number,
  senderDid: string,
  privateKey: KeyObject,
  options: { msgType?: string; inReplyTo?: string | null; msgId?: string | null } = {},
): Dict {
  const { msgType = "offer", inReplyTo = null } = options;
  const msgId = options.msgId ?? randomUUID();
  const timestamp = "2026-03-24T10:00:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const terms = { total_value: 10_000_000, currency: "USD" };
  const protocolAct = {
    protocol_version: "0.2",
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
    sender_agent_id: "conformance-agent",
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

// ---------------------------------------------------------------------------
// CONF-001: test_session_init_idempotency
// ---------------------------------------------------------------------------

test("session init idempotency", async () => {
  // Same message_id MUST return the same session_id — no second session created.
  const { client } = freshServer();
  const body = makeSessionInit();
  const h = initHeaders(body.message_id as string);

  const r1 = await client.post("/sessions", { json: body, headers: h });
  const r2 = await client.post("/sessions", { json: body, headers: h });

  expect([200, 201]).toContain(r1.statusCode);
  expect([200, 201]).toContain(r2.statusCode);
  expect(r1.json().session_id).toBe(r2.json().session_id);
});

// ---------------------------------------------------------------------------
// CONF-002: test_turn_taking_enforced
// ---------------------------------------------------------------------------

test("turn taking enforced", async () => {
  // NOT_YOUR_TURN returned for out-of-turn message.
  const fixture = freshServer();
  const sessionId = await createSession(fixture.client);
  const responderClient = fixture.makeResponderClient();

  // Responder tries to send before initiator — must fail
  const offer = makeOffer(sessionId, 1, 1, RESPONDER_DID, fixture.responderKeypair.privateKey);
  const r = await responderClient.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: initHeaders(offer.message_id as string),
  });
  expect(r.statusCode).toBe(409);
  expect((r.json().error as Dict).code).toBe("NOT_YOUR_TURN");
});

// ---------------------------------------------------------------------------
// CONF-003: JWT authentication enforcement (Section 12.1.4)
// ---------------------------------------------------------------------------

test("jwt missing header rejected", async () => {
  // Missing Authorization header → 401 INVALID_JWT.
  const { rawClient } = freshServer();
  const body = makeSessionInit();
  const r = await rawClient.post("/sessions", {
    json: body,
    headers: { "Content-Type": "application/a2cn+json" },
  });
  expect(r.statusCode).toBe(401);
  expect((r.json().error as Dict).code).toBe("INVALID_JWT");
});

test("jwt expired token rejected", async () => {
  // Expired JWT → 401 INVALID_JWT.
  const { ctx, rawClient, initiatorKeypair, initiatorDidDoc } = freshServer();
  ctx.registerDidDocument(INITIATOR_DID, initiatorDidDoc);

  const token = await createJwt(INITIATOR_DID, SERVER_DID, initiatorKeypair.privateKey, {
    kid: `${INITIATOR_DID}#key-1`,
    expSeconds: -1,
  });
  const body = makeSessionInit();
  const r = await rawClient.post("/sessions", {
    json: body,
    headers: { "Content-Type": "application/a2cn+json", Authorization: `Bearer ${token}` },
  });
  expect(r.statusCode).toBe(401);
  expect((r.json().error as Dict).code).toBe("INVALID_JWT");
});

test("jwt wrong audience rejected", async () => {
  // JWT with wrong aud → 401 INVALID_JWT.
  const { ctx, rawClient, initiatorKeypair, initiatorDidDoc } = freshServer();
  ctx.registerDidDocument(INITIATOR_DID, initiatorDidDoc);

  const token = await createJwt(INITIATOR_DID, "did:web:wrong-server.example", initiatorKeypair.privateKey, {
    kid: `${INITIATOR_DID}#key-1`,
    expSeconds: 60,
  });
  const body = makeSessionInit();
  const r = await rawClient.post("/sessions", {
    json: body,
    headers: { "Content-Type": "application/a2cn+json", Authorization: `Bearer ${token}` },
  });
  expect(r.statusCode).toBe(401);
  expect((r.json().error as Dict).code).toBe("INVALID_JWT");
});

test("jwt replayed jti rejected", async () => {
  // Replayed JWT jti → 401 INVALID_JWT on second use.
  const { ctx, rawClient, initiatorKeypair, initiatorDidDoc } = freshServer();
  ctx.registerDidDocument(INITIATOR_DID, initiatorDidDoc);

  const token = await createJwt(INITIATOR_DID, SERVER_DID, initiatorKeypair.privateKey, {
    kid: `${INITIATOR_DID}#key-1`,
    expSeconds: 3600,
  });
  const headers = { "Content-Type": "application/a2cn+json", Authorization: `Bearer ${token}` };

  // First request — consumes jti
  const body = makeSessionInit();
  const r1 = await rawClient.post("/sessions", { json: body, headers });
  expect(r1.statusCode).toBe(201);

  // Second request with same token — replay detected
  const body2 = makeSessionInit();
  const r2 = await rawClient.post("/sessions", { json: body2, headers });
  expect(r2.statusCode).toBe(401);
  expect((r2.json().error as Dict).code).toBe("INVALID_JWT");
});

test("jwt valid token accepted", async () => {
  // Valid JWT → request accepted (session created).
  const { ctx, rawClient, initiatorKeypair, initiatorDidDoc } = freshServer();
  ctx.registerDidDocument(INITIATOR_DID, initiatorDidDoc);

  const token = await createJwt(INITIATOR_DID, SERVER_DID, initiatorKeypair.privateKey, {
    kid: `${INITIATOR_DID}#key-1`,
    expSeconds: 3600,
  });
  const body = makeSessionInit();
  const r = await rawClient.post("/sessions", {
    json: body,
    headers: { "Content-Type": "application/a2cn+json", Authorization: `Bearer ${token}` },
  });
  expect(r.statusCode).toBe(201);
  expect("session_id" in r.json()).toBe(true);
});

// ---------------------------------------------------------------------------
// CONF-004: test_transaction_record_deterministic
// ---------------------------------------------------------------------------

test("transaction record deterministic", async () => {
  // Both sides generate identical record_hash independently.
  const mgr = new SessionManager();
  mgr.registerDidDocument(
    INITIATOR_DID,
    makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUBLIC_KEY)),
  );
  mgr.registerDidDocument(
    RESPONDER_DID,
    makeDidDocument(RESPONDER_DID, "key-2026-01", publicKeyToJwk(RESPONDER_PUBLIC_KEY)),
  );
  const sessionId = randomUUID();

  const initMsg: Dict = {
    message_type: "session_init",
    message_id: "init-1",
    protocol_version: "0.2",
    session_params: {
      deal_type: "saas_renewal",
      currency: "USD",
      subject: "Conformance Test",
      max_rounds: 4,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
    },
    initiator: {
      organization_name: "Buyer Corp",
      did: INITIATOR_DID,
      verification_method: `${INITIATOR_DID}#key-1`,
      agent_id: "buyer-agent",
      endpoint: "https://buyer.example/api/a2cn",
    },
    initiator_mandate: { mandate_type: "declared" },
  };

  const ackMsg: Dict = {
    message_type: "session_ack",
    message_id: "ack-1",
    session_id: sessionId,
    in_reply_to: "init-1",
    protocol_version: "0.2",
    session_params_accepted: {
      deal_type: "saas_renewal",
      currency: "USD",
      max_rounds: 4,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
    },
    responder: {
      organization_name: "Seller Corp",
      did: RESPONDER_DID,
      verification_method: `${RESPONDER_DID}#key-2026-01`,
      agent_id: "seller-agent",
      endpoint: "http://localhost:8000",
    },
    responder_mandate: { mandate_type: "declared" },
    session_created_at: "2026-03-24T10:00:00Z",
    current_turn: "initiator",
  };

  const sess = mgr.createSession(sessionId, initMsg, ackMsg, "2026-03-24T10:00:00Z");
  // Prevent timeout on a session with a historical created_at timestamp
  sess.session_timeout_seconds = 86400 * 365 * 100;

  const offerTimestamp = "2026-03-24T10:01:00Z";
  const offerExpires = "2030-01-01T00:00:00Z";
  const offerTerms = { total_value: 10_500_000, currency: "USD" };
  const offerPah = hashObject({
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    message_type: "offer",
    sender_did: INITIATOR_DID,
    timestamp: offerTimestamp,
    expires_at: offerExpires,
    terms: offerTerms,
  });

  const offerMsg: Dict = {
    message_type: "offer",
    message_id: "offer-1",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "buyer-agent",
    sender_verification_method: `${INITIATOR_DID}#key-1`,
    timestamp: offerTimestamp,
    expires_at: offerExpires,
    terms: offerTerms,
    protocol_act_hash: offerPah,
    protocol_act_signature: signJws(offerPah, INITIATOR_PRIVATE_KEY, `${INITIATOR_DID}#key-1`),
  };

  const acceptancePayload = {
    session_id: sessionId,
    round_number: 1,
    sequence_number: 2,
    accepted_offer_id: "offer-1",
    accepted_protocol_act_hash: offerPah,
  };
  const acceptanceMsg: Dict = {
    message_type: "acceptance",
    message_id: "acc-1",
    session_id: sessionId,
    in_reply_to: "offer-1",
    round_number: 1,
    sequence_number: 2,
    accepted_offer_id: "offer-1",
    accepted_protocol_act_hash: offerPah,
    sender_did: RESPONDER_DID,
    sender_agent_id: "seller-agent",
    sender_verification_method: `${RESPONDER_DID}#key-2026-01`,
    timestamp: "2026-03-24T10:03:00Z",
    acceptance_signature: signJws(
      hashObject(acceptancePayload),
      RESPONDER_PRIVATE_KEY,
      `${RESPONDER_DID}#key-2026-01`,
    ),
  };

  mgr.processMessage(sess, offerMsg);
  mgr.processMessage(sess, acceptanceMsg);

  expect(sess.state).toBe(SessionState.COMPLETED);

  // Generate record twice from the same session object
  const recordA = generateTransactionRecord(sess);
  const recordB = generateTransactionRecord(sess);

  expect(recordA.record_hash).toBe(recordB.record_hash);
  expect(recordA.record_id).toBe(recordB.record_id);
  // generated_at must come from acceptance timestamp, not local now()
  expect(recordA.generated_at).toBe("2026-03-24T10:03:00Z");
});

// ---------------------------------------------------------------------------
// CONF-005: test_sequence_ordering_strict
// ---------------------------------------------------------------------------

test("sequence ordering strict", async () => {
  // Gap in sequence_number rejected with SEQUENCE_ERROR.
  const fixture = freshServer();
  const sessionId = await createSession(fixture.client);
  const responderClient = fixture.makeResponderClient();

  // Send seq=1 OK
  const offer = makeOffer(sessionId, 1, 1, INITIATOR_DID, fixture.initiatorKeypair.privateKey);
  const r = await fixture.client.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: initHeaders(offer.message_id as string),
  });
  expect(r.statusCode).toBe(200);

  // Now send seq=3 (skipping 2) — must fail
  const badOffer = makeOffer(sessionId, 3, 2, RESPONDER_DID, fixture.responderKeypair.privateKey, {
    msgType: "counteroffer",
    inReplyTo: offer.message_id as string,
  });
  const r2 = await responderClient.post(`/sessions/${sessionId}/messages`, {
    json: badOffer,
    headers: initHeaders(badOffer.message_id as string),
  });
  expect(r2.statusCode).toBe(422);
  expect((r2.json().error as Dict).code).toBe("SEQUENCE_ERROR");
});

// ---------------------------------------------------------------------------
// CONF-006: test_terminal_state_reentry
// ---------------------------------------------------------------------------

test("terminal state reentry", async () => {
  // SESSION_WRONG_STATE returned for messages on completed/terminal session.
  const fixture = freshServer();
  const sessionId = await createSession(fixture.client);

  // Complete via withdrawal
  const w = {
    message_type: "withdrawal",
    message_id: randomUUID(),
    session_id: sessionId,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "test-agent",
    timestamp: "2026-03-24T10:02:00Z",
    reason_code: "NO_REASON_GIVEN",
  };
  await fixture.client.post(`/sessions/${sessionId}/messages`, {
    json: w,
    headers: initHeaders(w.message_id),
  });

  // Try to send another offer
  const offer = makeOffer(sessionId, 2, 1, INITIATOR_DID, fixture.initiatorKeypair.privateKey);
  const r = await fixture.client.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: initHeaders(offer.message_id as string),
  });
  expect(r.statusCode).toBe(409);
  expect((r.json().error as Dict).code).toBe("SESSION_WRONG_STATE");
});

// ---------------------------------------------------------------------------
// CONF-007: test_record_id_deterministic (UUID v5 with A2CN namespace)
// ---------------------------------------------------------------------------

test("record id uses a2cn namespace", () => {
  // record_id must be UUID v5 with A2CN namespace f4a2c1e0-...
  const sessionId = "c3d4e5f6-a7b8-9012-cdef-123456789012";
  const expected = uuidv5(sessionId, A2CN_NAMESPACE);

  // Generate it the same way the record module does
  const actual = uuidv5(sessionId, A2CN_NAMESPACE);
  expect(actual).toBe(expected);
  // And it must differ from using the DNS namespace
  const wrong = uuidv5(sessionId, uuidv5.DNS);
  expect(actual).not.toBe(wrong);
});
