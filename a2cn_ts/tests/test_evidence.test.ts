/** Tests for producer-sealed Session Evidence Records. */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import {
  canonicalize,
  generateKeypair,
  hashBytes,
  hashObject,
  privateKeyFromJwk,
  publicKeyToJwk,
  signJws,
} from "../src/a2cn/crypto.js";
import {
  assessSessionEvidenceRecord,
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
} from "../src/a2cn/evidence.js";
import { generateTransactionRecord, verifyTransactionRecord } from "../src/a2cn/record.js";
import { Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import type { Dict } from "../src/a2cn/messages.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument } from "./conftest.js";

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();
const { privateKey: THIRD_PARTY_PRIVATE_KEY, publicKey: THIRD_PARTY_PUBLIC_KEY } =
  generateKeypair();

const INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;
const THIRD_PARTY_DID = "did:example:payment-processor";
const THIRD_PARTY_VM = `${THIRD_PARTY_DID}#key-1`;

function makeSession(): [SessionManager, Session, Record<string, Dict>] {
  const sessionId = randomUUID();
  const sessionInit: Dict = {
    message_type: "session_init",
    message_id: "init-1",
    protocol_version: "0.2",
    session_params: {
      deal_type: "saas_renewal",
      currency: "USD",
      subject: "Session evidence test",
      max_rounds: 4,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
    },
    initiator: {
      organization_name: "TechCorp",
      did: INITIATOR_DID,
      verification_method: INITIATOR_VM,
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
      verification_method: RESPONDER_VM,
      agent_id: "seller-agent",
      endpoint: "https://acme.example/api/a2cn",
    },
    responder_mandate: { mandate_type: "declared" },
    session_created_at: "2026-03-24T10:00:00Z",
    current_turn: "initiator",
  };

  const manager = new SessionManager();
  const didDocuments: Record<string, Dict> = {
    [INITIATOR_DID]: makeDidDocument(
      INITIATOR_DID,
      "key-1",
      publicKeyToJwk(INITIATOR_PUBLIC_KEY),
    ),
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
    timestamp?: string;
    inReplyTo?: string | null;
  } = {},
): Dict {
  const {
    senderDid = INITIATOR_DID,
    sequenceNumber = 1,
    roundNumber = 1,
    messageType = "offer",
    messageId = "offer-1",
    timestamp = "2026-03-24T10:01:00Z",
    inReplyTo = null,
  } = options;
  const terms = { total_value: 9_500_000, currency: "USD" };
  const verificationMethod = senderDid === INITIATOR_DID ? INITIATOR_VM : RESPONDER_VM;
  const privateKey =
    senderDid === INITIATOR_DID ? INITIATOR_PRIVATE_KEY : RESPONDER_PRIVATE_KEY;
  const protocolAct = {
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: roundNumber,
    sequence_number: sequenceNumber,
    message_type: messageType,
    sender_did: senderDid,
    timestamp,
    expires_at: "2030-01-01T00:00:00Z",
    terms,
  };
  const protocolActHash = hashObject(protocolAct);
  const message: Dict = {
    message_type: messageType,
    message_id: messageId,
    session_id: sessionId,
    round_number: roundNumber,
    sequence_number: sequenceNumber,
    sender_did: senderDid,
    sender_agent_id: senderDid === INITIATOR_DID ? "buyer-agent" : "seller-agent",
    sender_verification_method: verificationMethod,
    timestamp,
    expires_at: "2030-01-01T00:00:00Z",
    terms,
    protocol_act_hash: protocolActHash,
    protocol_act_signature: signJws(protocolActHash, privateKey, verificationMethod),
  };
  if (inReplyTo) {
    message.in_reply_to = inReplyTo;
  }
  return message;
}

function makeAcceptance(sessionId: string, offer: Dict): Dict {
  const payload = {
    session_id: sessionId,
    round_number: offer.round_number,
    sequence_number: 2,
    accepted_offer_id: offer.message_id,
    accepted_protocol_act_hash: offer.protocol_act_hash,
  };
  return {
    message_type: "acceptance",
    message_id: "acceptance-1",
    session_id: sessionId,
    in_reply_to: offer.message_id,
    round_number: offer.round_number,
    sequence_number: 2,
    accepted_offer_id: offer.message_id,
    accepted_protocol_act_hash: offer.protocol_act_hash,
    sender_did: RESPONDER_DID,
    sender_agent_id: "seller-agent",
    sender_verification_method: RESPONDER_VM,
    timestamp: "2026-03-24T10:03:00Z",
    acceptance_signature: signJws(hashObject(payload), RESPONDER_PRIVATE_KEY, RESPONDER_VM),
  };
}

function markTimedOut(session: Session): void {
  session.state = SessionState.TIMED_OUT;
  session.current_turn = "none";
  session.terminal_reason = "session_timeout";
  session.terminal_message_id = null;
  session.state_updated_at = "2026-03-24T10:10:00Z";
}

function generateEvidence(session: Session, observedActs: Dict[] | null = null): Dict {
  return generateSessionEvidenceRecord(session, {
    producerPrivateKey: INITIATOR_PRIVATE_KEY,
    producerDid: INITIATOR_DID,
    producerAgentId: "buyer-agent",
    producerVerificationMethod: INITIATOR_VM,
    observedActs,
  });
}

function externalCounteroffer(): Dict {
  return {
    sequence_number: 2,
    round_number: 2,
    message_type: "counteroffer",
    message_id: "external-counteroffer-1",
    sender_did: RESPONDER_DID,
    timestamp: "2026-03-24T10:02:00Z",
    source_protocol: "commerce_api",
    act: {
      message_type: "counteroffer",
      message_id: "external-counteroffer-1",
      session_id: "external-commerce-session-7",
      sender_did: RESPONDER_DID,
      timestamp: "2026-03-24T10:02:00Z",
      terms: { total_value: 90_300, currency: "USD" },
    },
  };
}

function thirdPartyOffer(sessionId: string): Dict {
  const protocolAct = {
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 3,
    message_type: "offer",
    sender_did: THIRD_PARTY_DID,
    timestamp: "2026-03-24T10:03:00Z",
    expires_at: "2030-01-01T00:00:00Z",
    terms: { total_value: 1, currency: "USD" },
  };
  const protocolActHash = hashObject(protocolAct);
  return {
    ...protocolAct,
    message_id: "third-party-offer-1",
    sender_verification_method: THIRD_PARTY_VM,
    source_protocol: "commerce_api",
    protocol_act_hash: protocolActHash,
    protocol_act_signature: signJws(
      protocolActHash,
      THIRD_PARTY_PRIVATE_KEY,
      THIRD_PARTY_VM,
    ),
  };
}

function malformedSignedObservation(
  sessionId: string,
  options: { omitRoundFields?: boolean; nullField?: string } = {},
): Dict {
  const act = makeOffer(sessionId, {
    senderDid: RESPONDER_DID,
    sequenceNumber: 2,
    roundNumber: 2,
    messageType: "counteroffer",
    messageId: "malformed-counteroffer",
    timestamp: "2026-03-24T10:02:00Z",
    inReplyTo: "offer-1",
  });
  if (options.omitRoundFields) {
    delete act.round_number;
    delete act.sequence_number;
  }
  if (options.nullField !== undefined) {
    act[options.nullField] = null;
  }

  const protocolAct = {
    protocol_version: "0.2",
    session_id: (act.session_id as string) ?? "",
    round_number: act.round_number,
    sequence_number: act.sequence_number,
    message_type: (act.message_type as string) ?? "",
    sender_did: (act.sender_did as string) ?? "",
    timestamp: (act.timestamp as string) ?? "",
    expires_at: (act.expires_at as string) ?? "",
    terms: (act.terms as Dict) ?? {},
  };
  const protocolActHash = hashObject(protocolAct);
  act.protocol_act_hash = protocolActHash;
  act.protocol_act_signature = signJws(
    protocolActHash,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
  );
  return {
    sequence_number: 2,
    round_number: 2,
    message_type: "counteroffer",
    message_id: "malformed-counteroffer",
    sender_did: RESPONDER_DID,
    timestamp: "2026-03-24T10:02:00Z",
    source_protocol: "commerce_api",
    act,
  };
}

function mixedRecord(): [Dict, Record<string, Dict>] {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  return [generateEvidence(session, [externalCounteroffer()]), didDocuments];
}

test("fully signed completed session is bilateral and cross-links transaction record", () => {
  const [manager, session, didDocuments] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  manager.processMessage(session, makeAcceptance(session.session_id, offer));

  const transactionRecord = generateTransactionRecord(session);
  const evidence = generateEvidence(session);

  expect(evidence.evidence_level).toBe("bilateral");
  expect(evidence.transaction_record_hash).toBe(transactionRecord.record_hash);
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
  expect(verifyTransactionRecord(transactionRecord, didDocuments, session._offer_chain)).toBe(true);
});

test("external unsigned counteroffer produces valid mixed evidence", () => {
  const [evidence, didDocuments] = mixedRecord();

  const assessment = assessSessionEvidenceRecord(evidence, didDocuments);

  expect(assessment).toEqual({
    valid: true,
    evidence_level: "mixed",
    verified_acts: 1,
    unsigned_acts: 1,
    invalid_acts: 0,
  });
  const acts = evidence.acts as Dict[];
  expect(acts[1].attribution).toBe("unsigned_observation");
  expect(acts[1].signature).toBeNull();
  expect(((acts[1].act as Dict).terms as Dict).total_value).toBe(90_300);
});

test("verified nonparty act does not make unsigned party acts mixed", () => {
  const [, session, didDocuments] = makeSession();
  session._message_log = [
    {
      message_type: "rejection",
      message_id: "unsigned-initiator-rejection",
      session_id: session.session_id,
      round_number: 1,
      sequence_number: 1,
      sender_did: INITIATOR_DID,
      timestamp: "2026-03-24T10:01:00Z",
    },
    {
      message_type: "withdrawal",
      message_id: "unsigned-responder-withdrawal",
      session_id: session.session_id,
      sequence_number: 2,
      sender_did: RESPONDER_DID,
      timestamp: "2026-03-24T10:02:00Z",
    },
  ];
  markTimedOut(session);
  didDocuments[THIRD_PARTY_DID] = makeDidDocument(
    THIRD_PARTY_DID,
    "key-1",
    publicKeyToJwk(THIRD_PARTY_PUBLIC_KEY),
  );

  const evidence = generateEvidence(session, [thirdPartyOffer(session.session_id)]);

  expect(evidence.evidence_level).toBe("unilateral");
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("tampering with unsigned counterparty act invalidates record", () => {
  const [evidence, didDocuments] = mixedRecord();
  const acts = evidence.acts as Dict[];
  const terms = (acts[1].act as Dict).terms as Dict;
  terms.total_value = 70_300;

  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(false);
});

test("signed local offer and timeout are unilateral", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);

  const evidence = generateEvidence(session);

  expect(evidence.evidence_level).toBe("unilateral");
  expect(evidence.transaction_record_hash).toBeNull();
  expect(evidence.terminal).toEqual({
    outcome: "TIMED_OUT",
    reason: "session_timeout",
    message_id: null,
    timestamp: "2026-03-24T10:10:00Z",
  });
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("timestamp and message id are nullable for incomplete unsigned terminal act", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, {
    message_type: "withdrawal",
    sender_did: INITIATOR_DID,
  });

  const evidence = generateEvidence(session);
  const terminal = evidence.terminal as Dict;
  const entry = (evidence.acts as Dict[])[0];
  const act = entry.act as Dict;

  expect(terminal.outcome).toBe(SessionState.WITHDRAWN);
  expect(terminal.message_id).toBeNull();
  expect(entry.message_id).toBeNull();
  expect(entry.timestamp).toBeNull();
  expect("message_id" in act).toBe(false);
  expect("timestamp" in act).toBe(false);
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("tampered producer seal or record hash fails verification", () => {
  const [evidence, didDocuments] = mixedRecord();
  const tamperedSignature = structuredClone(evidence);
  tamperedSignature.producer_signature = "not-a-jws";
  const tamperedHash = structuredClone(evidence);
  tamperedHash.record_hash = "tampered";

  expect(verifySessionEvidenceRecord(tamperedSignature, didDocuments)).toBe(false);
  expect(verifySessionEvidenceRecord(tamperedHash, didDocuments)).toBe(false);
});

test("present but invalid counterparty signature fails instead of downgrading", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);

  const invalidCounteroffer = makeOffer(session.session_id, {
    senderDid: RESPONDER_DID,
    sequenceNumber: 2,
    roundNumber: 2,
    messageType: "counteroffer",
    messageId: "invalid-counteroffer",
    timestamp: "2026-03-24T10:02:00Z",
    inReplyTo: "offer-1",
  });
  invalidCounteroffer.protocol_act_signature = signJws(
    invalidCounteroffer.protocol_act_hash as string,
    INITIATOR_PRIVATE_KEY,
    RESPONDER_VM,
  );

  const evidence = generateEvidence(session, [invalidCounteroffer]);
  const assessment = assessSessionEvidenceRecord(evidence, didDocuments);

  expect((evidence.acts as Dict[])[1].attribution).toBe("verified_signature");
  expect(assessment.valid).toBe(false);
  expect(assessment.invalid_acts).toBe(1);
});

test("signed observed act requires round and sequence in complete act", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  const observed = malformedSignedObservation(session.session_id, {
    omitRoundFields: true,
  });

  const evidence = generateEvidence(session, [observed]);

  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(false);
});

test.each(["session_id", "expires_at", "terms"])(
  "signed observed act rejects null %s",
  (nullField) => {
    const [manager, session, didDocuments] = makeSession();
    manager.processMessage(session, makeOffer(session.session_id));
    markTimedOut(session);
    const observed = malformedSignedObservation(session.session_id, { nullField });

    const evidence = generateEvidence(session, [observed]);

    expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(false);
  },
);

test("signed observed act from another session fails even if relabelled", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  const foreignAct = makeOffer(randomUUID(), {
    senderDid: RESPONDER_DID,
    sequenceNumber: 2,
    roundNumber: 2,
    messageType: "counteroffer",
    messageId: "foreign-counteroffer",
    timestamp: "2026-03-24T10:02:00Z",
    inReplyTo: "offer-1",
  });
  foreignAct.source_protocol = "commerce_api";

  const evidence = generateEvidence(session, [foreignAct]);

  expect(evidence.evidence_level).toBe("mixed");
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(false);
});

test("generator rejects a present signature without a supported type", () => {
  const [manager, session] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  const observed = externalCounteroffer();
  observed.signature = "present-but-untyped";

  expect(() => generateEvidence(session, [observed])).toThrow(/signature_type/);
});

test("removing or reordering an act invalidates chain and record", () => {
  const [evidence, didDocuments] = mixedRecord();
  const removed = structuredClone(evidence);
  (removed.acts as Dict[]).pop();
  const reordered = structuredClone(evidence);
  (reordered.acts as Dict[]).reverse();

  expect(verifySessionEvidenceRecord(removed, didDocuments)).toBe(false);
  expect(verifySessionEvidenceRecord(reordered, didDocuments)).toBe(false);
});

test("unsequenced acts are ordered by RFC 3339 instant", () => {
  const [, session, didDocuments] = makeSession();
  markTimedOut(session);
  const observed: Dict[] = [
    {
      message_type: "counteroffer",
      message_id: "middle",
      sender_did: RESPONDER_DID,
      timestamp: "2026-03-24T09:30:00Z",
      source_protocol: "commerce_api",
      act: {
        message_type: "counteroffer",
        message_id: "middle",
        sender_did: RESPONDER_DID,
        timestamp: "2026-03-24T09:30:00Z",
      },
    },
    {
      message_type: "offer",
      message_id: "earliest",
      sender_did: INITIATOR_DID,
      timestamp: "2026-03-24T10:00:00+01:00",
      source_protocol: "commerce_api",
      act: {
        message_type: "offer",
        message_id: "earliest",
        sender_did: INITIATOR_DID,
        timestamp: "2026-03-24T10:00:00+01:00",
      },
    },
    {
      message_type: "counteroffer",
      message_id: "latest",
      sender_did: RESPONDER_DID,
      timestamp: "2026-03-24T10:00:00-01:00",
      source_protocol: "commerce_api",
      act: {
        message_type: "counteroffer",
        message_id: "latest",
        sender_did: RESPONDER_DID,
        timestamp: "2026-03-24T10:00:00-01:00",
      },
    },
  ];

  const evidence = generateEvidence(session, observed);

  expect((evidence.acts as Dict[]).map((entry) => entry.message_id)).toEqual([
    "earliest",
    "middle",
    "latest",
  ]);
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("generator rejects null party metadata", () => {
  const [, session] = makeSession();
  markTimedOut(session);
  (session._session_init!.initiator as Dict).organization_name = null;

  expect(() => generateEvidence(session)).toThrow(/organization_name/);
});

test("evidence level must match verified content even with a fresh seal", () => {
  const [evidence, didDocuments] = mixedRecord();
  evidence.evidence_level = "bilateral";
  evidence.record_hash = "";
  evidence.producer_signature = "";
  evidence.record_hash = hashObject(evidence);
  evidence.producer_signature = signJws(
    evidence.record_hash as string,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_VM,
  );

  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(false);
});

test("unknown record version is rejected even with a fresh seal", () => {
  const [evidence, didDocuments] = mixedRecord();
  evidence.record_version = "999";
  evidence.record_hash = "";
  evidence.producer_signature = "";
  evidence.record_hash = hashObject(evidence);
  evidence.producer_signature = signJws(
    evidence.record_hash as string,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_VM,
  );

  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(false);
});

test("generator rejects nonterminal sessions", () => {
  const [, session] = makeSession();

  expect(() => generateEvidence(session)).toThrow(/terminal/);
});

test.each([
  SessionState.REJECTED_FINAL,
  SessionState.WITHDRAWN,
  SessionState.TIMED_OUT,
  SessionState.IMPASSE,
  SessionState.ERROR,
])("%s produces unilateral evidence with no transaction cross-link", (terminalState) => {
  const [, session, didDocuments] = makeSession();
  session.state = terminalState;
  session.current_turn = "none";
  session.terminal_reason = `test_${terminalState.toLowerCase()}`;
  session.state_updated_at = "2026-03-24T10:10:00Z";

  const evidence = generateEvidence(session);

  expect((evidence.terminal as Dict).outcome).toBe(terminalState);
  expect(evidence.transaction_record_hash).toBeNull();
  expect(evidence.evidence_level).toBe("unilateral");
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("shared session evidence vector has Python/TypeScript hash parity", () => {
  const fixturePath = join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
    "spec",
    "test-vectors",
    "session-evidence-record-parity.json",
  );
  const fixture = JSON.parse(readFileSync(fixturePath, "utf-8")) as Dict;
  const source = fixture.session as Dict;
  const producer = fixture.producer as Dict;
  const session = new Session({
    session_id: source.session_id as string,
    state: source.state as string,
    current_turn: "none",
    terminal_reason: source.terminal_reason as string,
    terminal_message_id: source.terminal_message_id as null,
    session_created_at: source.session_created_at as string,
    state_updated_at: source.state_updated_at as string,
    session_params: source.session_params as Dict,
    initiator_mandate: source.initiator_mandate as Dict,
    responder_mandate: source.responder_mandate as Dict,
    _session_init: source.session_init as Dict,
    _session_ack: source.session_ack as Dict,
    _message_log: source.message_log as Dict[],
  });
  const privateKey = privateKeyFromJwk(fixture.producer_private_jwk as Dict);

  const record = generateSessionEvidenceRecord(session, {
    producerPrivateKey: privateKey,
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs: fixture.observed_acts as Dict[],
  });
  const expected = fixture.expected as Dict;

  expect(record.evidence_id).toBe(expected.evidence_id);
  expect(record.generated_at).toBe(expected.generated_at);
  expect(record.evidence_level).toBe(expected.evidence_level);
  expect((record.acts as Dict[]).map((entry) => entry.act_hash)).toEqual(expected.act_hashes);
  expect(record.act_chain_hash).toBe(expected.act_chain_hash);
  expect(record.record_hash).toBe(expected.record_hash);
  expect(
    verifySessionEvidenceRecord(record, fixture.did_documents as Record<string, Dict>),
  ).toBe(true);

  const invalidRecord = structuredClone(record);
  const invalidTimestamp = (fixture.invalid_cases as Dict).non_rfc3339_timestamp;
  const invalidEntry = (invalidRecord.acts as Dict[])[1];
  invalidEntry.timestamp = invalidTimestamp;
  (invalidEntry.act as Dict).timestamp = invalidTimestamp;
  invalidEntry.act_hash = hashObject(invalidEntry.act);
  invalidRecord.act_chain_hash = hashBytes(
    canonicalize((invalidRecord.acts as Dict[]).map((entry) => entry.act_hash)),
  );
  invalidRecord.record_hash = "";
  invalidRecord.producer_signature = "";
  invalidRecord.record_hash = hashObject(invalidRecord);
  invalidRecord.producer_signature = signJws(
    invalidRecord.record_hash as string,
    privateKey,
    producer.verification_method as string,
  );

  expect(invalidRecord.record_hash).toBe(expected.invalid_non_rfc3339_record_hash);
  expect(
    verifySessionEvidenceRecord(
      invalidRecord,
      fixture.did_documents as Record<string, Dict>,
    ),
  ).toBe(false);
});
