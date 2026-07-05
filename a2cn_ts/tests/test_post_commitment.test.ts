/**
 * Tests for post-commitment lifecycle endpoints:
 *   POST /sessions/{id}/delivery-notice
 *   POST /sessions/{id}/delivery-acknowledged
 *   POST /sessions/{id}/dispute-notice
 *   POST /sessions/{id}/dispute-resolved
 *
 * Also covers message class instantiation and JSON schema validation.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { randomUUID, type KeyObject } from "node:crypto";
import { describe, expect, test } from "vitest";

import { hashObject, signJws } from "../src/a2cn/crypto.js";
import { validateFulfillmentAttestation } from "../src/a2cn/fulfillment.js";
import {
  DeliveryNoticeMessage,
  DeliveryAcknowledgedMessage,
  DisputeNoticeMessage,
  DisputeResolvedMessage,
  FulfillmentAttestation,
  type Dict,
} from "../src/a2cn/messages.js";
import {
  INITIATOR_DID,
  RESPONDER_DID,
  freshServer,
  makeSessionInit,
  type ServerFixture,
  type TestClient,
} from "./conftest.js";

const A2CN_CT = "application/a2cn+json";
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function h(messageId: string): Record<string, string> {
  return { "Content-Type": A2CN_CT, "Idempotency-Key": messageId };
}

// ---------------------------------------------------------------------------
// Helpers — complete a session end-to-end via HTTP
// ---------------------------------------------------------------------------

async function createSession(client: TestClient): Promise<string> {
  const body = makeSessionInit();
  const r = await client.post("/sessions", { json: body, headers: h(body.message_id as string) });
  expect(r.statusCode).toBe(201);
  return r.json().session_id as string;
}

function deliveryNoticeBody(sessionId: string, recordHash: string, msgId?: string): Dict {
  const mid = msgId ?? randomUUID();
  return {
    message_type: "delivery_notice",
    message_id: mid,
    session_id: sessionId,
    transaction_record_hash: recordHash,
    delivery_timestamp: "2026-04-02T08:00:00Z",
    delivery_reference: "TRK-001",
  };
}

function deliveryAckBody(
  sessionId: string,
  recordHash: string,
  noticeId: string,
  accepted: boolean,
  msgId?: string,
): Dict {
  const mid = msgId ?? randomUUID();
  return {
    message_type: "delivery_acknowledged",
    message_id: mid,
    session_id: sessionId,
    transaction_record_hash: recordHash,
    delivery_notice_message_id: noticeId,
    acknowledgment_timestamp: "2026-04-03T09:00:00Z",
    accepted,
  };
}

function disputeNoticeBody(sessionId: string, recordHash: string, msgId?: string): Dict {
  const mid = msgId ?? randomUUID();
  return {
    message_type: "dispute_notice",
    message_id: mid,
    session_id: sessionId,
    transaction_record_hash: recordHash,
    raised_by: "buyer",
    dispute_type: "non_delivery",
    description: "Goods not received after 30 days.",
    dispute_timestamp: "2026-04-05T10:00:00Z",
  };
}

// ---------------------------------------------------------------------------
// DeliveryNoticeMessage class
// ---------------------------------------------------------------------------

describe("DeliveryNoticeDataclass", () => {
  test("instantiation with required fields", () => {
    const msg = new DeliveryNoticeMessage({
      message_id: "msg-1",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      delivery_timestamp: "2026-04-02T08:00:00Z",
    });
    expect(msg.message_type).toBe("delivery_notice");
    expect(msg.protocol_version).toBe("0.2");
    expect(msg.delivery_reference).toBeNull();
  });

  test("to dict omits none fields", () => {
    const msg = new DeliveryNoticeMessage({
      message_id: "msg-1",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      delivery_timestamp: "2026-04-02T08:00:00Z",
    });
    const d = msg.toDict();
    expect("delivery_reference" in d).toBe(false);
    expect("notes" in d).toBe(false);
    expect(d.message_type).toBe("delivery_notice");
  });

  test("optional fields included when set", () => {
    const msg = new DeliveryNoticeMessage({
      message_id: "msg-1",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      delivery_timestamp: "2026-04-02T08:00:00Z",
      delivery_reference: "TRK-999",
      notes: "Handle with care",
    });
    const d = msg.toDict();
    expect(d.delivery_reference).toBe("TRK-999");
    expect(d.notes).toBe("Handle with care");
  });
});

// ---------------------------------------------------------------------------
// DeliveryAcknowledgedMessage class
// ---------------------------------------------------------------------------

describe("DeliveryAcknowledgedDataclass", () => {
  test("instantiation with required fields", () => {
    const msg = new DeliveryAcknowledgedMessage({
      message_id: "msg-2",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      delivery_notice_message_id: "msg-1",
      acknowledgment_timestamp: "2026-04-03T09:00:00Z",
      accepted: true,
    });
    expect(msg.message_type).toBe("delivery_acknowledged");
    expect(msg.accepted).toBe(true);
    expect(msg.notes).toBeNull();
  });

  test("accepted false included in dict", () => {
    const msg = new DeliveryAcknowledgedMessage({
      message_id: "msg-2",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      delivery_notice_message_id: "msg-1",
      acknowledgment_timestamp: "2026-04-03T09:00:00Z",
      accepted: false,
    });
    const d = msg.toDict();
    expect(d.accepted).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// FulfillmentAttestation class
// ---------------------------------------------------------------------------

describe("FulfillmentAttestationDataclass", () => {
  test("instantiation with required fields", () => {
    const msg = new FulfillmentAttestation({
      attestation_type: "FulfillmentAttestation",
      id: `urn:concordia:fulfillment:${randomUUID()}`,
      issued_at: "2026-04-03T09:00:00Z",
      agreement_attestation_id: "sess-1",
      fulfillment: { status: "fulfilled_clean" },
      references: [{ type: "receipt", id: "sess-1", relationship: "fulfills" }],
      signature: { alg: "Ed25519", value: "abc" },
    });
    const d = msg.toDict();
    expect(d.attestation_type).toBe("FulfillmentAttestation");
    expect((d.references as Dict[])[0].relationship).toBe("fulfills");
    expect("meta" in d).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DisputeNoticeMessage class
// ---------------------------------------------------------------------------

describe("DisputeNoticeDataclass", () => {
  test("instantiation with required fields", () => {
    const msg = new DisputeNoticeMessage({
      message_id: "msg-3",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      raised_by: "buyer",
      dispute_type: "non_delivery",
      description: "Goods not received.",
    });
    expect(msg.message_type).toBe("dispute_notice");
    expect(msg.evidence_references).toEqual([]);
    expect(msg.resolution_requested).toBeNull();
    expect(msg.dispute_timestamp).not.toBeNull();
  });

  test("dispute timestamp auto set", () => {
    const msg = new DisputeNoticeMessage({
      message_id: "msg-3",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      raised_by: "seller",
      dispute_type: "payment_failure",
      description: "Payment overdue.",
    });
    expect(msg.dispute_timestamp).not.toBeNull();
    expect(msg.dispute_timestamp).toContain("T"); // ISO 8601 format
  });

  test("explicit dispute timestamp preserved", () => {
    const msg = new DisputeNoticeMessage({
      message_id: "msg-3",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      raised_by: "buyer",
      dispute_type: "quality",
      description: "Quality issue.",
      dispute_timestamp: "2026-04-05T10:00:00Z",
    });
    expect(msg.dispute_timestamp).toBe("2026-04-05T10:00:00Z");
  });

  test("evidence references default empty list", () => {
    const msg = new DisputeNoticeMessage({
      message_id: "msg-3",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      raised_by: "buyer",
      dispute_type: "other",
      description: "Other issue.",
    });
    expect(msg.evidence_references).toEqual([]);
  });

  test("to dict includes evidence references", () => {
    const msg = new DisputeNoticeMessage({
      message_id: "msg-3",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      raised_by: "buyer",
      dispute_type: "non_delivery",
      description: "Dispute.",
      evidence_references: ["hash:abc123", "https://evidence.example/doc1"],
    });
    const d = msg.toDict();
    expect(d.evidence_references).toEqual(["hash:abc123", "https://evidence.example/doc1"]);
  });
});

// ---------------------------------------------------------------------------
// JSON schema validation
// ---------------------------------------------------------------------------

describe("JsonSchemaValidation", () => {
  test("delivery notice schema valid", () => {
    const schemaPath = join(REPO_ROOT, "spec", "schemas", "delivery_notice.schema.json");
    const schema = JSON.parse(readFileSync(schemaPath, "utf-8"));
    expect(schema.properties.message_type.const).toBe("delivery_notice");
    expect(schema.required).toContain("transaction_record_hash");
    expect(schema.additionalProperties).toBe(false);
  });

  test("delivery acknowledged schema valid", () => {
    const schemaPath = join(REPO_ROOT, "spec", "schemas", "delivery_acknowledged.schema.json");
    const schema = JSON.parse(readFileSync(schemaPath, "utf-8"));
    expect(schema.properties.message_type.const).toBe("delivery_acknowledged");
    expect(schema.required).toContain("accepted");
    expect(schema.additionalProperties).toBe(false);
  });

  test("dispute notice schema valid", () => {
    const schemaPath = join(REPO_ROOT, "spec", "schemas", "dispute_notice.schema.json");
    const schema = JSON.parse(readFileSync(schemaPath, "utf-8"));
    expect(schema.properties.message_type.const).toBe("dispute_notice");
    expect(schema.required).toContain("raised_by");
    expect(schema.required).toContain("dispute_type");
    const validTypes = schema.properties.dispute_type.enum;
    expect(validTypes).toContain("non_delivery");
    expect(validTypes).toContain("payment_failure");
    expect(schema.additionalProperties).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Helpers — complete a session with two clients (avoids SENDER_DID_MISMATCH)
// ---------------------------------------------------------------------------

interface CompletionClients {
  initiatorClient: TestClient;
  responderClient: TestClient;
  initiatorPrivateKey: KeyObject;
  responderPrivateKey: KeyObject;
}

function completionClients(fixture: ServerFixture): CompletionClients {
  return {
    initiatorClient: fixture.client,
    responderClient: fixture.makeResponderClient(),
    initiatorPrivateKey: fixture.initiatorKeypair.privateKey,
    responderPrivateKey: fixture.responderKeypair.privateKey,
  };
}

/** Complete a session using the correct JWT for each party. Returns [sessionId, recordHash]. */
async function completeSession(clients: CompletionClients): Promise<[string, string]> {
  const { initiatorClient, responderClient, initiatorPrivateKey, responderPrivateKey } = clients;
  const sessionId = await createSession(initiatorClient);

  const timestamp = "2026-04-01T10:00:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const terms = { total_value: 10_000_000, currency: "USD", seat_count: 50 };
  const offerId = randomUUID();
  const protocolAct = {
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    message_type: "offer",
    sender_did: INITIATOR_DID,
    timestamp,
    expires_at: expiresAt,
    terms,
  };
  const pah = hashObject(protocolAct);
  const offer = {
    message_type: "offer",
    message_id: offerId,
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "test-agent",
    sender_verification_method: `${INITIATOR_DID}#key-1`,
    timestamp,
    expires_at: expiresAt,
    terms,
    protocol_act_hash: pah,
    protocol_act_signature: signJws(pah, initiatorPrivateKey, `${INITIATOR_DID}#key-1`),
  };
  const r1 = await initiatorClient.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: h(offerId),
  });
  expect(r1.statusCode, r1.body).toBe(200);

  const accId = randomUUID();
  const acceptancePayload = {
    session_id: sessionId,
    round_number: 1,
    sequence_number: 2,
    accepted_offer_id: offerId,
    accepted_protocol_act_hash: pah,
  };
  const acceptance = {
    message_type: "acceptance",
    message_id: accId,
    session_id: sessionId,
    in_reply_to: offerId,
    round_number: 1,
    sequence_number: 2,
    accepted_offer_id: offerId,
    accepted_protocol_act_hash: pah,
    sender_did: RESPONDER_DID,
    sender_agent_id: "test-agent",
    sender_verification_method: `${RESPONDER_DID}#key-2026-01`,
    timestamp: "2026-04-01T10:01:00Z",
    acceptance_signature: signJws(
      hashObject(acceptancePayload),
      responderPrivateKey,
      `${RESPONDER_DID}#key-2026-01`,
    ),
  };
  const r2 = await responderClient.post(`/sessions/${sessionId}/messages`, {
    json: acceptance,
    headers: h(accId),
  });
  expect(r2.statusCode, r2.body).toBe(200);

  const r3 = await initiatorClient.get(`/sessions/${sessionId}/record`);
  expect(r3.statusCode, r3.body).toBe(200);
  const recordHash = r3.json().record_hash as string;
  return [sessionId, recordHash];
}

/** Complete a session and open a dispute_notice. Returns [sessionId, recordHash, disputeNoticeId]. */
async function setupDisputedSession(clients: CompletionClients): Promise<[string, string, string]> {
  const [sessionId, recordHash] = await completeSession(clients);
  const body = disputeNoticeBody(sessionId, recordHash);
  const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-notice`, {
    json: body,
    headers: h(body.message_id as string),
  });
  expect(r.statusCode, r.body).toBe(200);
  const disputeNoticeId = r.json().dispute_notice_message_id as string;
  return [sessionId, recordHash, disputeNoticeId];
}

function disputeResolvedBody(
  sessionId: string,
  recordHash: string,
  disputeNoticeId: string,
  outcome = "buyer_prevails",
  msgId?: string,
): Dict {
  const mid = msgId ?? randomUUID();
  return {
    message_type: "dispute_resolved",
    message_id: mid,
    session_id: sessionId,
    transaction_record_hash: recordHash,
    dispute_notice_message_id: disputeNoticeId,
    resolution_outcome: outcome,
    resolver_did: "did:web:resolver.neutral.example",
    resolution_timestamp: "2026-04-10T12:00:00Z",
  };
}

// ---------------------------------------------------------------------------
// Server endpoint tests: delivery_notice
// ---------------------------------------------------------------------------

describe("DeliveryNoticeEndpoint", () => {
  test("valid delivery notice accepted", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = deliveryNoticeBody(sessionId, recordHash);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(200);
    const data = r.json();
    expect(data.status).toBe("DELIVERY_NOTICE_RECORDED");
    expect(data.session_id).toBe(sessionId);
    expect("delivery_notice_message_id" in data).toBe(true);
  });

  test("delivery notice rejected if not completed", async () => {
    const { client } = freshServer();
    const sessionId = await createSession(client);
    const body = deliveryNoticeBody(sessionId, "a".repeat(64));
    const r = await client.post(`/sessions/${sessionId}/delivery-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(409);
    expect((r.json().error as Dict).code).toBe("SESSION_WRONG_STATE");
  });

  test("delivery notice rejected if hash mismatch", async () => {
    const clients = completionClients(freshServer());
    const [sessionId] = await completeSession(clients);
    const badHash = "b".repeat(64); // wrong hash
    const body = deliveryNoticeBody(sessionId, badHash);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(409);
    expect((r.json().error as Dict).code).toBe("INVALID_RECORD_HASH");
  });

  test("delivery notice wrong message type rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = deliveryNoticeBody(sessionId, recordHash);
    body.message_type = "DELIVERY_NOTICE";
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("WRONG_MESSAGE_TYPE");
  });
});

// ---------------------------------------------------------------------------
// Server endpoint tests: delivery_acknowledged
// ---------------------------------------------------------------------------

describe("DeliveryAcknowledgedEndpoint", () => {
  /** Complete a session and record a delivery notice. Returns [sessionId, recordHash, noticeId]. */
  async function setup(clients: CompletionClients): Promise<[string, string, string]> {
    const [sessionId, recordHash] = await completeSession(clients);
    const noticeBody = deliveryNoticeBody(sessionId, recordHash);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-notice`, {
      json: noticeBody,
      headers: h(noticeBody.message_id as string),
    });
    expect(r.statusCode).toBe(200);
    const noticeId = r.json().delivery_notice_message_id as string;
    return [sessionId, recordHash, noticeId];
  }

  test("valid delivery acknowledged accepted", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setup(clients);
    const body = deliveryAckBody(sessionId, recordHash, noticeId, true);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-acknowledged`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(200);
    const data = r.json();
    expect(data.post_commitment_status).toBe("CLOSED");
  });

  test("accepted true sets closed", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setup(clients);
    const body = deliveryAckBody(sessionId, recordHash, noticeId, true);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-acknowledged`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.json().post_commitment_status).toBe("CLOSED");
  });

  test("accepted false sets disputed", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setup(clients);
    const body = deliveryAckBody(sessionId, recordHash, noticeId, false);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-acknowledged`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(200);
    expect(r.json().post_commitment_status).toBe("DISPUTED");
  });

  test("rejected if no delivery notice", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = deliveryAckBody(sessionId, recordHash, "nonexistent-notice-id", true);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-acknowledged`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(409);
    expect((r.json().error as Dict).code).toBe("NO_DELIVERY_NOTICE");
  });

  test("delivery acknowledged wrong message type rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setup(clients);
    const body = deliveryAckBody(sessionId, recordHash, noticeId, true);
    body.message_type = "DELIVERY_ACKNOWLEDGED";
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-acknowledged`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("WRONG_MESSAGE_TYPE");
  });
});

// ---------------------------------------------------------------------------
// Server endpoint tests: FulfillmentAttestation
// ---------------------------------------------------------------------------

describe("FulfillmentAttestationEndpoint", () => {
  async function setupDeliveryNotice(clients: CompletionClients): Promise<[string, string, string]> {
    const [sessionId, recordHash] = await completeSession(clients);
    const noticeBody = deliveryNoticeBody(sessionId, recordHash);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-notice`, {
      json: noticeBody,
      headers: h(noticeBody.message_id as string),
    });
    expect(r.statusCode, r.body).toBe(200);
    return [sessionId, recordHash, r.json().delivery_notice_message_id as string];
  }

  async function cleanAttestation(clients: CompletionClients): Promise<Dict> {
    const [sessionId, recordHash, noticeId] = await setupDeliveryNotice(clients);
    const body = deliveryAckBody(sessionId, recordHash, noticeId, true);
    const r1 = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-acknowledged`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r1.statusCode, r1.body).toBe(200);
    const r2 = await clients.initiatorClient.get(`/sessions/${sessionId}/fulfillment-attestation`);
    expect(r2.statusCode, r2.body).toBe(200);
    return r2.json();
  }

  test("fulfillment attestation emitted on clean delivery", async () => {
    const clients = completionClients(freshServer());
    const attestation = await cleanAttestation(clients);
    expect(attestation.attestation_type).toBe("FulfillmentAttestation");
    expect((attestation.fulfillment as Dict).status).toBe("fulfilled_clean");
    expect((attestation.references as Dict[])[0].relationship).toBe("fulfills");
    expect((attestation.signature as Dict).alg).toBe("Ed25519");
    expect((attestation.signature as Dict).value).toBeTruthy();
  });

  test("fulfillment attestation not emitted on rejected delivery", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDeliveryNotice(clients);
    const body = deliveryAckBody(sessionId, recordHash, noticeId, false);
    const r1 = await clients.initiatorClient.post(`/sessions/${sessionId}/delivery-acknowledged`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r1.statusCode, r1.body).toBe(200);
    const r2 = await clients.initiatorClient.get(`/sessions/${sessionId}/fulfillment-attestation`);
    expect(r2.statusCode).toBe(409);
    expect((r2.json().error as Dict).code).toBe("FULFILLMENT_ATTESTATION_PENDING");
  });

  test("fulfillment attestation emitted after dispute resolved", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    const r1 = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r1.statusCode, r1.body).toBe(200);
    const r2 = await clients.initiatorClient.get(`/sessions/${sessionId}/fulfillment-attestation`);
    expect(r2.statusCode, r2.body).toBe(200);
    const attestation = r2.json();
    expect((attestation.fulfillment as Dict).status).toBe("fulfilled_with_mediation");
    expect((attestation.meta as Dict).mediator_invoked).toBe(true);
    expect((attestation.meta as Dict).resolver_did).toBe("did:web:resolver.neutral.example");
  });

  test("fulfillment attestation schema valid", async () => {
    const clients = completionClients(freshServer());
    const attestation = await cleanAttestation(clients);
    expect(() => validateFulfillmentAttestation(attestation)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Server endpoint tests: dispute_notice
// ---------------------------------------------------------------------------

describe("DisputeNoticeEndpoint", () => {
  test("valid dispute notice accepted", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = disputeNoticeBody(sessionId, recordHash);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(200);
    const data = r.json();
    expect(data.post_commitment_status).toBe("DISPUTED");
    expect(data.session_id).toBe(sessionId);
    expect("dispute_notice_message_id" in data).toBe(true);
  });

  test("dispute sets post commitment status to disputed", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = disputeNoticeBody(sessionId, recordHash);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.json().post_commitment_status).toBe("DISPUTED");
  });

  test("dispute stores raised by and dispute type", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = disputeNoticeBody(sessionId, recordHash);
    body.raised_by = "seller";
    body.dispute_type = "payment_failure";
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(200);
  });

  test("dispute rejected if not completed", async () => {
    const { client } = freshServer();
    const sessionId = await createSession(client);
    const body = disputeNoticeBody(sessionId, "a".repeat(64));
    const r = await client.post(`/sessions/${sessionId}/dispute-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(409);
    expect((r.json().error as Dict).code).toBe("SESSION_WRONG_STATE");
  });

  test("dispute note references neutral resolver", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = disputeNoticeBody(sessionId, recordHash);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.json().note).toContain("neutral resolver");
  });

  test("dispute notice wrong message type rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = disputeNoticeBody(sessionId, recordHash);
    body.message_type = "DISPUTE_NOTICE";
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-notice`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("WRONG_MESSAGE_TYPE");
  });
});

// ---------------------------------------------------------------------------
// DisputeResolvedMessage class
// ---------------------------------------------------------------------------

describe("DisputeResolvedDataclass", () => {
  test("instantiation with required fields", () => {
    const msg = new DisputeResolvedMessage({
      message_id: "msg-4",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      dispute_notice_message_id: "msg-3",
      resolution_outcome: "buyer_prevails",
      resolver_did: "did:web:resolver.example",
    });
    expect(msg.message_type).toBe("dispute_resolved");
    expect(msg.protocol_version).toBe("0.2");
    expect(msg.evidence_references).toEqual([]);
    expect(msg.resolution_notes).toBeNull();
  });

  test("resolution timestamp auto set on creation", () => {
    const msg = new DisputeResolvedMessage({
      message_id: "msg-4",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      dispute_notice_message_id: "msg-3",
      resolution_outcome: "seller_prevails",
      resolver_did: "did:web:resolver.example",
    });
    expect(msg.resolution_timestamp).not.toBeNull();
    expect(msg.resolution_timestamp).toContain("T"); // ISO 8601 format
  });

  test("explicit resolution timestamp preserved", () => {
    const msg = new DisputeResolvedMessage({
      message_id: "msg-4",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      dispute_notice_message_id: "msg-3",
      resolution_outcome: "mutual_settlement",
      resolver_did: "did:web:resolver.example",
      resolution_timestamp: "2026-04-10T12:00:00Z",
    });
    expect(msg.resolution_timestamp).toBe("2026-04-10T12:00:00Z");
  });

  test("evidence references default empty list", () => {
    const msg = new DisputeResolvedMessage({
      message_id: "msg-4",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      dispute_notice_message_id: "msg-3",
      resolution_outcome: "buyer_prevails",
      resolver_did: "did:web:resolver.example",
    });
    expect(msg.evidence_references).toEqual([]);
  });

  test("to dict includes resolution outcome", () => {
    const msg = new DisputeResolvedMessage({
      message_id: "msg-4",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      dispute_notice_message_id: "msg-3",
      resolution_outcome: "mutual_settlement",
      resolver_did: "did:web:resolver.example",
      resolution_timestamp: "2026-04-10T12:00:00Z",
    });
    const d = msg.toDict();
    expect(d.resolution_outcome).toBe("mutual_settlement");
    expect(d.resolver_did).toBe("did:web:resolver.example");
    expect(d.dispute_notice_message_id).toBe("msg-3");
    expect(d.message_type).toBe("dispute_resolved");
  });

  test("to dict omits none resolution notes", () => {
    const msg = new DisputeResolvedMessage({
      message_id: "msg-4",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      dispute_notice_message_id: "msg-3",
      resolution_outcome: "buyer_prevails",
      resolver_did: "did:web:resolver.example",
      resolution_timestamp: "2026-04-10T12:00:00Z",
    });
    const d = msg.toDict();
    expect("resolution_notes" in d).toBe(false);
  });

  test("to dict includes evidence references when set", () => {
    const msg = new DisputeResolvedMessage({
      message_id: "msg-4",
      session_id: "sess-1",
      transaction_record_hash: "a".repeat(64),
      dispute_notice_message_id: "msg-3",
      resolution_outcome: "seller_prevails",
      resolver_did: "did:web:resolver.example",
      resolution_timestamp: "2026-04-10T12:00:00Z",
      evidence_references: ["hash:abc123", "https://evidence.example/ruling"],
    });
    const d = msg.toDict();
    expect(d.evidence_references).toEqual(["hash:abc123", "https://evidence.example/ruling"]);
  });
});

// ---------------------------------------------------------------------------
// JSON schema validation — DisputeResolvedMessage
// ---------------------------------------------------------------------------

describe("DisputeResolvedSchema", () => {
  test("dispute resolved schema valid", () => {
    const schemaPath = join(REPO_ROOT, "spec", "schemas", "dispute_resolved.schema.json");
    const schema = JSON.parse(readFileSync(schemaPath, "utf-8"));
    expect(schema.properties.message_type.const).toBe("dispute_resolved");
    expect(schema.required).toContain("transaction_record_hash");
    expect(schema.required).toContain("dispute_notice_message_id");
    expect(schema.required).toContain("resolver_did");
    expect(schema.required).toContain("resolution_timestamp");
    const outcomes = schema.properties.resolution_outcome.enum;
    expect(outcomes).toContain("buyer_prevails");
    expect(outcomes).toContain("seller_prevails");
    expect(outcomes).toContain("mutual_settlement");
    expect(schema.additionalProperties).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Server endpoint tests: dispute_resolved
// ---------------------------------------------------------------------------

describe("DisputeResolvedEndpoint", () => {
  test("valid dispute resolved accepted", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(200);
    const data = r.json();
    expect(data.post_commitment_status).toBe("RESOLVED");
    expect(data.session_id).toBe(sessionId);
    expect("dispute_resolved_message_id" in data).toBe(true);
  });

  test("dispute resolved rejected if not in disputed status", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, "nonexistent-notice-id");
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("NOT_IN_DISPUTED_STATUS");
  });

  test("dispute resolved rejected if notice id mismatch", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, "wrong-notice-id");
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(409);
    expect((r.json().error as Dict).code).toBe("INVALID_REFERENCE");
  });

  test("dispute resolved rejected if hash mismatch", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, , noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, "b".repeat(64), noticeId);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(409);
    expect((r.json().error as Dict).code).toBe("INVALID_RECORD_HASH");
  });

  test("buyer prevails outcome stored", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId, "buyer_prevails");
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(200);
    expect(r.json().resolution_outcome).toBe("buyer_prevails");
  });

  test("seller prevails outcome stored", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId, "seller_prevails");
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(200);
    expect(r.json().resolution_outcome).toBe("seller_prevails");
  });

  test("mutual settlement outcome stored", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId, "mutual_settlement");
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(200);
    expect(r.json().resolution_outcome).toBe("mutual_settlement");
  });

  test("post commitment status set to resolved", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.json().post_commitment_status).toBe("RESOLVED");
  });

  test("not in disputed status error includes spec ref", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash] = await completeSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, "irrelevant-notice-id");
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    const error = r.json().error as Dict;
    expect(error.code).toBe("NOT_IN_DISPUTED_STATUS");
    expect(error.spec_ref).toBe("Section 11");
  });

  test("invalid resolution outcome rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId, "everyone_wins");
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("INVALID_RESOLUTION_OUTCOME");
  });

  test("missing resolution outcome rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    delete body.resolution_outcome;
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("INVALID_RESOLUTION_OUTCOME");
  });

  test("missing resolver did rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    delete body.resolver_did;
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("MISSING_REQUIRED_FIELD");
  });

  test("missing resolution timestamp rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    delete body.resolution_timestamp;
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("MISSING_REQUIRED_FIELD");
  });

  test("wrong message type rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    body.message_type = "dispute_notice";
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("WRONG_MESSAGE_TYPE");
  });

  test("missing message type rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    delete body.message_type;
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("WRONG_MESSAGE_TYPE");
  });

  test("non string resolution outcome rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    body.resolution_outcome = ["buyer_prevails"]; // array instead of string
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("INVALID_RESOLUTION_OUTCOME");
  });

  test("non string resolver did rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    body.resolver_did = 12345; // integer instead of string
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("MISSING_REQUIRED_FIELD");
  });

  test("non string resolution timestamp rejected", async () => {
    const clients = completionClients(freshServer());
    const [sessionId, recordHash, noticeId] = await setupDisputedSession(clients);
    const body = disputeResolvedBody(sessionId, recordHash, noticeId);
    body.resolution_timestamp = { ts: "2026-04-10" }; // object instead of string
    const r = await clients.initiatorClient.post(`/sessions/${sessionId}/dispute-resolved`, {
      json: body,
      headers: h(body.message_id as string),
    });
    expect(r.statusCode).toBe(400);
    expect((r.json().error as Dict).code).toBe("MISSING_REQUIRED_FIELD");
  });
});
