/** Tests for transaction record generation and verification. */

import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";

import { generateKeypair, hashObject, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import { generateTransactionRecord, verifyTransactionRecord } from "../src/a2cn/record.js";
import { Session, SessionManager } from "../src/a2cn/session.js";
import type { Dict } from "../src/a2cn/messages.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument } from "./conftest.js";

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();

function makeSession(): [SessionManager, Session, Record<string, Dict>] {
  const sessionId = randomUUID();
  const sessionInit: Dict = {
    message_type: "session_init",
    message_id: "init-1",
    protocol_version: "0.2",
    session_params: {
      deal_type: "saas_renewal",
      currency: "USD",
      subject: "Record verification test",
      max_rounds: 4,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
    },
    initiator: {
      organization_name: "TechCorp",
      did: INITIATOR_DID,
      verification_method: `${INITIATOR_DID}#key-1`,
      agent_id: "buyer-agent",
      endpoint: "https://techcorp.example/api/a2cn",
    },
    initiator_mandate: { mandate_type: "declared" },
  };
  const sessionAck: Dict = {
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
      organization_name: "Acme",
      did: RESPONDER_DID,
      verification_method: `${RESPONDER_DID}#key-2026-01`,
      agent_id: "seller-agent",
      endpoint: "http://localhost:8000",
    },
    responder_mandate: { mandate_type: "declared" },
    session_created_at: "2026-03-24T10:00:00Z",
    current_turn: "initiator",
  };

  const manager = new SessionManager();
  const didDocuments: Record<string, Dict> = {
    [INITIATOR_DID]: makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUBLIC_KEY)),
    [RESPONDER_DID]: makeDidDocument(
      RESPONDER_DID,
      "key-2026-01",
      publicKeyToJwk(RESPONDER_PUBLIC_KEY),
    ),
  };
  for (const [did, didDocument] of Object.entries(didDocuments)) {
    manager.registerDidDocument(did, didDocument);
  }

  const session = manager.createSession(sessionId, sessionInit, sessionAck, "2026-03-24T10:00:00Z");
  session.session_timeout_seconds = 86400 * 365 * 100;
  return [manager, session, didDocuments];
}

function makeOffer(
  sessionId: string,
  options: {
    senderDid?: string;
    sequenceNumber?: number;
    roundNumber?: number;
    messageType?: string;
    messageId?: string;
    inReplyTo?: string | null;
  } = {},
): Dict {
  const {
    senderDid = INITIATOR_DID,
    sequenceNumber = 1,
    roundNumber = 1,
    messageType = "offer",
    messageId = "offer-1",
    inReplyTo = null,
  } = options;
  const timestamp = "2026-03-24T10:01:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const terms = { total_value: 9_500_000, currency: "USD" };
  const protocolAct = {
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: roundNumber,
    sequence_number: sequenceNumber,
    message_type: messageType,
    sender_did: senderDid,
    timestamp,
    expires_at: expiresAt,
    terms,
  };
  const protocolActHash = hashObject(protocolAct);
  const privateKey = senderDid === INITIATOR_DID ? INITIATOR_PRIVATE_KEY : RESPONDER_PRIVATE_KEY;
  const verificationMethod =
    senderDid === INITIATOR_DID ? `${INITIATOR_DID}#key-1` : `${RESPONDER_DID}#key-2026-01`;
  const offer: Dict = {
    message_type: messageType,
    message_id: messageId,
    session_id: sessionId,
    round_number: roundNumber,
    sequence_number: sequenceNumber,
    sender_did: senderDid,
    sender_agent_id: "buyer-agent",
    sender_verification_method: verificationMethod,
    timestamp,
    expires_at: expiresAt,
    terms,
    protocol_act_hash: protocolActHash,
    protocol_act_signature: signJws(protocolActHash, privateKey, verificationMethod),
  };
  if (inReplyTo) {
    offer.in_reply_to = inReplyTo;
  }
  return offer;
}

function makeAcceptance(
  sessionId: string,
  offer: Dict,
  options: { senderDid?: string; messageId?: string; sequenceNumber?: number } = {},
): Dict {
  const {
    senderDid = RESPONDER_DID,
    messageId = "acceptance-1",
    sequenceNumber = 2,
  } = options;
  const privateKey = senderDid === INITIATOR_DID ? INITIATOR_PRIVATE_KEY : RESPONDER_PRIVATE_KEY;
  const verificationMethod =
    senderDid === INITIATOR_DID ? `${INITIATOR_DID}#key-1` : `${RESPONDER_DID}#key-2026-01`;
  const payload = {
    session_id: sessionId,
    round_number: offer.round_number,
    sequence_number: sequenceNumber,
    accepted_offer_id: offer.message_id,
    accepted_protocol_act_hash: offer.protocol_act_hash,
  };
  return {
    message_type: "acceptance",
    message_id: messageId,
    session_id: sessionId,
    in_reply_to: offer.message_id,
    round_number: offer.round_number,
    sequence_number: sequenceNumber,
    accepted_offer_id: offer.message_id,
    accepted_protocol_act_hash: offer.protocol_act_hash,
    sender_did: senderDid,
    sender_agent_id: "seller-agent",
    sender_verification_method: verificationMethod,
    timestamp: "2026-03-24T10:03:00Z",
    acceptance_signature: signJws(hashObject(payload), privateKey, verificationMethod),
  };
}

function completedRecord(): [Dict, Record<string, Dict>, string[]] {
  const [manager, session, didDocuments] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  manager.processMessage(session, makeAcceptance(session.session_id, offer));
  return [generateTransactionRecord(session), didDocuments, [...session._offer_chain]];
}

function completedMultiroundRecord(): [Dict, Record<string, Dict>, string[]] {
  const [manager, session, didDocuments] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  const counteroffer = makeOffer(session.session_id, {
    senderDid: RESPONDER_DID,
    sequenceNumber: 2,
    roundNumber: 2,
    messageType: "counteroffer",
    messageId: "counteroffer-1",
    inReplyTo: offer.message_id as string,
  });
  manager.processMessage(session, counteroffer);
  const acceptance = makeAcceptance(session.session_id, counteroffer, {
    senderDid: INITIATOR_DID,
    messageId: "acceptance-2",
    sequenceNumber: 3,
  });
  manager.processMessage(session, acceptance);
  return [generateTransactionRecord(session), didDocuments, [...session._offer_chain]];
}

function withRecomputedRecordHash(record: Dict): Dict {
  const copy = structuredClone(record);
  copy.record_hash = "";
  copy.record_hash = hashObject(copy);
  return copy;
}

test("verify transaction record accepts valid record", () => {
  const [record, didDocuments, offerHashes] = completedRecord();

  expect(verifyTransactionRecord(record, didDocuments, offerHashes)).toBe(true);
});

test("verify transaction record accepts callable did resolver", () => {
  const [record, didDocuments, offerHashes] = completedRecord();

  expect(
    verifyTransactionRecord(record, (did: string) => didDocuments[did], offerHashes),
  ).toBe(true);
});

test("verify transaction record rejects tampered record hash input", () => {
  const [record, didDocuments, offerHashes] = completedRecord();
  (record.agreed_terms as Dict).total_value = ((record.agreed_terms as Dict).total_value as number) + 1;

  expect(verifyTransactionRecord(record, didDocuments, offerHashes)).toBe(false);
});

test("verify transaction record rejects tampered final offer signature", () => {
  let [record, didDocuments, offerHashes] = completedRecord();
  (record.final_offer as Dict).protocol_act_signature = (record.final_acceptance as Dict)
    .acceptance_signature;
  record = withRecomputedRecordHash(record);

  expect(verifyTransactionRecord(record, didDocuments, offerHashes)).toBe(false);
});

test("verify transaction record rejects tampered acceptance signature", () => {
  let [record, didDocuments, offerHashes] = completedRecord();
  (record.final_acceptance as Dict).acceptance_signature = (record.final_offer as Dict)
    .protocol_act_signature;
  record = withRecomputedRecordHash(record);

  expect(verifyTransactionRecord(record, didDocuments, offerHashes)).toBe(false);
});

test("verify transaction record rejects acceptance jws with wrong payload", () => {
  let [record, didDocuments, offerHashes] = completedRecord();
  (record.final_acceptance as Dict).acceptance_signature = signJws(
    "not-the-acceptance-payload",
    RESPONDER_PRIVATE_KEY,
    `${RESPONDER_DID}#key-2026-01`,
  );
  record = withRecomputedRecordHash(record);

  expect(verifyTransactionRecord(record, didDocuments, offerHashes)).toBe(false);
});

test("verify transaction record rejects accepted hash mismatch", () => {
  let [record, didDocuments, offerHashes] = completedRecord();
  (record.final_acceptance as Dict).accepted_protocol_act_hash = "sha256-tampered";
  record = withRecomputedRecordHash(record);

  expect(verifyTransactionRecord(record, didDocuments, offerHashes)).toBe(false);
});

test("verify transaction record rejects offer chain hash mismatch", () => {
  let [record, didDocuments, offerHashes] = completedRecord();
  record.offer_chain_hash = "sha256-tampered";
  record = withRecomputedRecordHash(record);

  expect(verifyTransactionRecord(record, didDocuments, offerHashes)).toBe(false);
});

test("verify transaction record accepts multiround offer chain", () => {
  const [record, didDocuments, offerHashes] = completedMultiroundRecord();

  expect(verifyTransactionRecord(record, didDocuments, offerHashes)).toBe(true);
  expect(verifyTransactionRecord(record, didDocuments)).toBe(false);
});

test("verify transaction record rejects missing required fields", () => {
  let [record, didDocuments, offerHashes] = completedRecord();
  delete (record.final_offer as Dict).protocol_act_signature;
  record = withRecomputedRecordHash(record);

  expect(verifyTransactionRecord(record, didDocuments, offerHashes)).toBe(false);
});
