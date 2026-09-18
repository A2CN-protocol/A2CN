/** Tests for producer-sealed Session Evidence Records. */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, vi } from "vitest";

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
  type GenerateSessionEvidenceOptions,
} from "../src/a2cn/evidence.js";
import { v5 as uuidv5 } from "uuid";

import {
  A2CN_NAMESPACE,
  generateTransactionRecord,
  verifyTransactionRecord,
} from "../src/a2cn/record.js";
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

// ---------------------------------------------------------------------------
// Conformance fixtures for the three additive Section 9A extensions:
// identity-light responder, recomputable money basis, controls-halt outcome.
// ---------------------------------------------------------------------------

const OBSERVED_RESPONDER: Dict = {
  identity_source: "supplier_ordering_portal",
  organization_name: "Northwind Supply",
  observed_credential: {
    type: "vat_number",
    digest: hashBytes(new TextEncoder().encode("GB123456789")),
  },
};

const MONEY_BASIS: Dict = {
  raw_amounts: ["70000.00", "25000.00"],
  currency: "USD",
  minor_unit_exponent: 2,
  basis: "net",
  normalized_total_minor: 9_500_000,
};

function generateEvidenceWith(
  session: Session,
  observedActs: Dict[] | null,
  extra: Partial<GenerateSessionEvidenceOptions>,
): Dict {
  return generateSessionEvidenceRecord(session, {
    producerPrivateKey: INITIATOR_PRIVATE_KEY,
    producerDid: INITIATOR_DID,
    producerAgentId: "buyer-agent",
    producerVerificationMethod: INITIATOR_VM,
    observedActs,
    ...extra,
  });
}

/** The same session, except the responder holds no A2CN identity at all. */
function makeIdentityLightSession(): [SessionManager, Session, Record<string, Dict>] {
  const [manager, session, didDocuments] = makeSession();
  (session._session_ack as Dict).responder = { organization_name: "Northwind Supply" };
  (session._session_ack as Dict).responder_mandate = {};
  session.responder_mandate = {};
  delete didDocuments[RESPONDER_DID];
  return [manager, session, didDocuments];
}

function observedQuote(
  options: {
    senderDid?: string | null;
    totalValue?: number;
    moneyBasis?: Dict | null;
    messageId?: string;
  } = {},
): Dict {
  const {
    senderDid = RESPONDER_DID,
    totalValue = 9_500_000,
    moneyBasis = null,
    messageId = "portal-quote-1",
  } = options;
  const entry: Dict = {
    sequence_number: 2,
    round_number: 2,
    message_type: "counteroffer",
    message_id: messageId,
    sender_did: senderDid,
    timestamp: "2026-03-24T10:02:00Z",
    source_protocol: "supplier_portal",
    act: {
      message_type: "counteroffer",
      message_id: messageId,
      timestamp: "2026-03-24T10:02:00Z",
      terms: { total_value: totalValue, currency: "USD" },
    },
  };
  if (moneyBasis !== null) {
    entry.money_basis = structuredClone(moneyBasis);
  }
  return entry;
}

/** Re-derive the chain hash and producer seal after editing a record. */
function reseal(evidence: Dict): Dict {
  evidence.act_chain_hash = hashBytes(
    canonicalize((evidence.acts as Dict[]).map((entry) => entry.act_hash)),
  );
  evidence.record_hash = "";
  evidence.producer_signature = "";
  evidence.record_hash = hashObject(evidence);
  evidence.producer_signature = signJws(
    evidence.record_hash as string,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_VM,
  );
  return evidence;
}

function pricedRecord(): [Dict, Record<string, Dict>] {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  return [generateEvidence(session, [observedQuote({ moneyBasis: MONEY_BASIS })]), didDocuments];
}

function haltedRecord(): [Dict, Record<string, Dict>] {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  session.state = SessionState.WITHDRAWN;
  session.current_turn = "none";
  session.terminal_message_id = null;
  session.state_updated_at = "2026-03-24T10:10:00Z";
  const evidence = generateEvidenceWith(session, null, {
    terminalOutcome: "HALTED_BY_CONTROLS",
    terminalReason: "buyer_spend_control:max_session_commitment",
  });
  return [evidence, didDocuments];
}

// --- Fixture (i) -----------------------------------------------------------

test("observed_party responder with unsigned acts is valid unilateral evidence", () => {
  const [manager, session, didDocuments] = makeIdentityLightSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);

  const evidence = generateEvidenceWith(session, [observedQuote({ senderDid: null })], {
    observedResponder: OBSERVED_RESPONDER,
  });

  expect((evidence.parties as Dict).responder).toEqual({
    identity_source: "supplier_ordering_portal",
    organization_name: "Northwind Supply",
    observed_credential: {
      type: "vat_number",
      digest: hashBytes(new TextEncoder().encode("GB123456789")),
    },
    did_declared: false,
    a2cn_endpoint_declared: false,
    mandate_declared: false,
  });
  expect((evidence.acts as Dict[])[1].sender_did).toBeNull();
  expect((evidence.acts as Dict[])[1].attribution).toBe("unsigned_observation");
  expect(assessSessionEvidenceRecord(evidence, didDocuments)).toEqual({
    valid: true,
    evidence_level: "unilateral",
    verified_acts: 1,
    unsigned_acts: 1,
    invalid_acts: 0,
  });
});

test("the verifier never resolves the observed identity", () => {
  const [manager, session, didDocuments] = makeIdentityLightSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  const evidence = generateEvidenceWith(session, [observedQuote({ senderDid: null })], {
    observedResponder: OBSERVED_RESPONDER,
  });
  const requested: string[] = [];

  const recordingResolver = (did: string): Dict => {
    requested.push(did);
    return didDocuments[did];
  };

  expect(verifySessionEvidenceRecord(evidence, recordingResolver)).toBe(true);
  expect([...new Set(requested)]).toEqual([INITIATOR_DID]);
});

// --- Fixture (ii) ----------------------------------------------------------

test("an observed responder claiming a verified signature is rejected", () => {
  const [manager, session, didDocuments] = makeIdentityLightSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  // The counterparty's key IS resolvable here, so the refusal below cannot be
  // blamed on a signature that failed to check out.
  didDocuments[RESPONDER_DID] = makeDidDocument(
    RESPONDER_DID,
    "key-2026-01",
    publicKeyToJwk(RESPONDER_PUBLIC_KEY),
  );

  const healthy = generateEvidenceWith(session, [observedQuote({ senderDid: null })], {
    observedResponder: OBSERVED_RESPONDER,
  });
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const signedAct = makeOffer(session.session_id, {
    senderDid: RESPONDER_DID,
    sequenceNumber: 2,
    roundNumber: 2,
    messageType: "counteroffer",
    messageId: "portal-quote-1",
    timestamp: "2026-03-24T10:02:00Z",
  });
  const attack = structuredClone(healthy);
  (attack.acts as Dict[])[1] = {
    sequence_number: 2,
    round_number: 2,
    message_type: "counteroffer",
    message_id: "portal-quote-1",
    sender_did: RESPONDER_DID,
    timestamp: "2026-03-24T10:02:00Z",
    source_protocol: "supplier_portal",
    act: signedAct,
    act_hash: hashObject(signedAct),
    sender_verification_method: RESPONDER_VM,
    signature_type: "protocol_act_signature",
    signature: signedAct.protocol_act_signature,
    attribution: "verified_signature",
  };
  reseal(attack);

  const assessment = assessSessionEvidenceRecord(attack, didDocuments);

  // Assert the reason before the verdict: the signature really does verify, so
  // the rejection is the identity-light coupling and not a broken act.
  expect(assessment.invalid_acts).toBe(0);
  expect(assessment.verified_acts).toBe(2);
  expect(assessment.evidence_level).toBe("unilateral");
  expect(assessment.valid).toBe(false);
});

test("generator refuses an observed party for a responder that declared identity", () => {
  const [manager, session] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);

  expect(() =>
    generateEvidenceWith(session, null, { observedResponder: OBSERVED_RESPONDER }),
  ).toThrow(/declared a DID/);
});

test("generator never fabricates a DID for a signed identity-light act", () => {
  const [manager, session] = makeIdentityLightSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  const unattributable = observedQuote({ senderDid: null });
  (unattributable.act as Dict).protocol_act_signature = "present-but-unattributable";

  expect(() =>
    generateEvidenceWith(session, [unattributable], {
      observedResponder: OBSERVED_RESPONDER,
    }),
  ).toThrow(/sender_did/);
});

// --- Fixture (iii) ---------------------------------------------------------

test("money_basis recomputing to the signed total is valid", () => {
  const [evidence, didDocuments] = pricedRecord();

  expect((evidence.acts as Dict[])[1].money_basis).toEqual(MONEY_BASIS);
  // The basis is a producer annotation about the act, never inside the act the
  // act_hash protects.
  expect((evidence.acts as Dict[])[1].act).not.toHaveProperty("money_basis");
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("money_basis on the terminal quote binds to the named act", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  session.state = SessionState.IMPASSE;
  session.current_turn = "none";
  session.terminal_reason = "no_movement";
  session.terminal_message_id = "portal-quote-1";
  session.state_updated_at = "2026-03-24T10:10:00Z";

  const evidence = generateEvidenceWith(session, [observedQuote()], {
    terminalMoneyBasis: MONEY_BASIS,
  });
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);

  const unresolvable = structuredClone(evidence);
  (unresolvable.terminal as Dict).message_id = "no-such-act";
  reseal(unresolvable);
  expect(verifySessionEvidenceRecord(unresolvable, didDocuments)).toBe(false);

  expect(() =>
    generateEvidenceWith(session, [observedQuote({ totalValue: 9_400_000 })], {
      terminalMoneyBasis: MONEY_BASIS,
    }),
  ).toThrow(/money_basis/);
});

// --- Fixture (iv) ----------------------------------------------------------

test("money_basis that does not recompute is rejected", () => {
  const [healthy, didDocuments] = pricedRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);
  // Re-sealing must itself produce verifiable records, or every red below would
  // prove only that the reseal helper is broken.
  expect(verifySessionEvidenceRecord(reseal(structuredClone(healthy)), didDocuments)).toBe(
    true,
  );

  const tamperedRaw = structuredClone(healthy);
  ((tamperedRaw.acts as Dict[])[1].money_basis as Dict).raw_amounts = [
    "70000.00",
    "25000.01",
  ];
  reseal(tamperedRaw);

  const tamperedTotal = structuredClone(healthy);
  ((tamperedTotal.acts as Dict[])[1].money_basis as Dict).normalized_total_minor = 9_500_001;
  reseal(tamperedTotal);

  expect(verifySessionEvidenceRecord(tamperedRaw, didDocuments)).toBe(false);
  expect(verifySessionEvidenceRecord(tamperedTotal, didDocuments)).toBe(false);
});

test("money_basis is never converted between net and gross", () => {
  const [healthy, didDocuments] = pricedRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  // Relabelling net as gross must not make the arithmetic move: the label is
  // checked, never applied.
  const relabelled = structuredClone(healthy);
  ((relabelled.acts as Dict[])[1].money_basis as Dict).basis = "gross";
  reseal(relabelled);
  expect(verifySessionEvidenceRecord(relabelled, didDocuments)).toBe(true);

  // A gross total that only balances if a tax rate were applied stays rejected.
  const grossedUp = structuredClone(healthy);
  ((grossedUp.acts as Dict[])[1].money_basis as Dict).basis = "gross";
  ((grossedUp.acts as Dict[])[1].money_basis as Dict).normalized_total_minor = 11_400_000;
  reseal(grossedUp);
  expect(verifySessionEvidenceRecord(grossedUp, didDocuments)).toBe(false);

  const unknownLabel = structuredClone(healthy);
  ((unknownLabel.acts as Dict[])[1].money_basis as Dict).basis = "vat_exclusive_maybe";
  reseal(unknownLabel);
  expect(verifySessionEvidenceRecord(unknownLabel, didDocuments)).toBe(false);
});

test("money_basis refuses amounts finer than the stated minor unit", () => {
  const [healthy, didDocuments] = pricedRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const subMinor = structuredClone(healthy);
  ((subMinor.acts as Dict[])[1].money_basis as Dict).raw_amounts = [
    "70000.001",
    "25000.00",
  ];
  reseal(subMinor);

  // Chosen so that DISCARDING the sub-minor digit lands exactly on the signed
  // total: rounding to fit is the failure mode, and it would read as a clean
  // recompute.
  expect(verifySessionEvidenceRecord(subMinor, didDocuments)).toBe(false);
});

test("money_basis currency must match the act it describes", () => {
  const [healthy, didDocuments] = pricedRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const wrongCurrency = structuredClone(healthy);
  ((wrongCurrency.acts as Dict[])[1].money_basis as Dict).currency = "EUR";
  reseal(wrongCurrency);

  expect(verifySessionEvidenceRecord(wrongCurrency, didDocuments)).toBe(false);
});

// A net or gross money_basis must agree with the basis the act itself states
// (Section 9A.9). The other labels, and an act that states none, are not compared.

/** An observed quote whose terms state `actBasis`, with a money_basis labelled `label`. */
function quoteStatingBasis(actBasis: unknown, label: string): Dict {
  const entry = observedQuote({ moneyBasis: { ...MONEY_BASIS, basis: label } });
  ((entry.act as Dict).terms as Dict).basis = actBasis;
  return entry;
}

test("money_basis contradicting the act's basis is refused and rejected", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);

  // The quote says gross, so a net money_basis contradicts it. The generator
  // refuses it exactly as it refuses a currency mismatch.
  expect(() => generateEvidence(session, [quoteStatingBasis("gross", "net")])).toThrow(
    /money_basis/,
  );

  const healthy = generateEvidence(session, [quoteStatingBasis("gross", "gross")]);
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const relabelled = structuredClone(healthy);
  ((relabelled.acts as Dict[])[1].money_basis as Dict).basis = "net";
  reseal(relabelled);
  expect(verifySessionEvidenceRecord(relabelled, didDocuments)).toBe(false);
});

test("terminal money_basis contradicting the act's basis is refused and rejected", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  session.state = SessionState.IMPASSE;
  session.current_turn = "none";
  session.terminal_reason = "no_movement";
  session.terminal_message_id = "portal-quote-1";
  session.state_updated_at = "2026-03-24T10:10:00Z";
  const quote = observedQuote();
  ((quote.act as Dict).terms as Dict).basis = "gross";

  expect(() =>
    generateEvidenceWith(session, [quote], {
      terminalMoneyBasis: { ...MONEY_BASIS, basis: "net" },
    }),
  ).toThrow(/money_basis/);

  const healthy = generateEvidenceWith(session, [quote], {
    terminalMoneyBasis: { ...MONEY_BASIS, basis: "gross" },
  });
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const relabelled = structuredClone(healthy);
  ((relabelled.terminal as Dict).money_basis as Dict).basis = "net";
  reseal(relabelled);
  expect(verifySessionEvidenceRecord(relabelled, didDocuments)).toBe(false);
});

test.each(["per_unit", "line_total", "unspecified"])(
  "labels other than net and gross are not compared with the act's basis: %s",
  (label) => {
    const [manager, session, didDocuments] = makeSession();
    manager.processMessage(session, makeOffer(session.session_id));
    markTimedOut(session);

    const evidence = generateEvidence(session, [quoteStatingBasis("gross", label)]);

    expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
  },
);

test.each(["net", "gross"])(
  "an act that states no basis gets no basis comparison: %s",
  (label) => {
    const [manager, session, didDocuments] = makeSession();
    manager.processMessage(session, makeOffer(session.session_id));
    markTimedOut(session);

    const evidence = generateEvidence(session, [
      observedQuote({ moneyBasis: { ...MONEY_BASIS, basis: label } }),
    ]);

    expect(((evidence.acts as Dict[])[1].act as Dict).terms).not.toHaveProperty("basis");
    expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
  },
);

// --- Fixture (v) -----------------------------------------------------------

test("money_basis claiming a total with no raw amounts fails closed", () => {
  const [healthy, didDocuments] = pricedRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const absent = structuredClone(healthy);
  delete ((absent.acts as Dict[])[1].money_basis as Dict).raw_amounts;
  reseal(absent);

  const empty = structuredClone(healthy);
  ((empty.acts as Dict[])[1].money_basis as Dict).raw_amounts = [];
  reseal(empty);

  expect(verifySessionEvidenceRecord(absent, didDocuments)).toBe(false);
  expect(verifySessionEvidenceRecord(empty, didDocuments)).toBe(false);
});

test("a zero-total money_basis still requires its raw amounts", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  const zeroBasis: Dict = {
    raw_amounts: ["0.00"],
    currency: "USD",
    minor_unit_exponent: 2,
    basis: "line_total",
    normalized_total_minor: 0,
  };

  const healthy = generateEvidence(session, [
    observedQuote({ totalValue: 0, moneyBasis: zeroBasis }),
  ]);
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  // Zero is the one total that absent raw amounts would sum to by themselves,
  // so it separates a fail-closed rule from an arithmetic accident.
  const absent = structuredClone(healthy);
  delete ((absent.acts as Dict[])[1].money_basis as Dict).raw_amounts;
  reseal(absent);

  expect(verifySessionEvidenceRecord(absent, didDocuments)).toBe(false);
});

// --- Fixture (vi) ----------------------------------------------------------

test("the controls-halt outcome is accepted", () => {
  const [evidence, didDocuments] = haltedRecord();

  expect((evidence.terminal as Dict).outcome).toBe("HALTED_BY_CONTROLS");
  expect((evidence.terminal as Dict).reason).toBe(
    "buyer_spend_control:max_session_commitment",
  );
  expect(evidence.transaction_record_hash).toBeNull();
  expect(evidence.evidence_level).toBe("unilateral");
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("a COMPLETED session cannot be relabelled as halted", () => {
  const [manager, session] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  manager.processMessage(session, makeAcceptance(session.session_id, offer));

  expect(() =>
    generateEvidenceWith(session, null, { terminalOutcome: "HALTED_BY_CONTROLS" }),
  ).toThrow(/COMPLETED/);
});

// --- Fixture (vii) ---------------------------------------------------------

test("an unrecognized terminal outcome is still rejected", () => {
  const [healthy, didDocuments] = haltedRecord();
  // The control proves the outcome gate is not simply refusing everything: the
  // newly recognized member passes through it.
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const unknown = structuredClone(healthy);
  (unknown.terminal as Dict).outcome = "HALTED_BY_VIBES";
  reseal(unknown);

  expect(verifySessionEvidenceRecord(unknown, didDocuments)).toBe(false);
});

test("AWAITING_COUNTERPARTY_SIGNATURE is not a terminal outcome", () => {
  const [healthy, didDocuments] = haltedRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const paused = structuredClone(healthy);
  (paused.terminal as Dict).outcome = "AWAITING_COUNTERPARTY_SIGNATURE";
  reseal(paused);

  expect(verifySessionEvidenceRecord(paused, didDocuments)).toBe(false);
});

// --- extensions ------------------------------------------------------------

test("namespaced extensions are sealed and never interpreted", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);

  const evidence = generateEvidenceWith(session, null, {
    extensions: { "acme.procurement": { requisition_id: "REQ-42", arbitrary: [1, 2] } },
  });

  expect(evidence.extensions).toEqual({
    "acme.procurement": { requisition_id: "REQ-42", arbitrary: [1, 2] },
  });
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);

  const edited = structuredClone(evidence);
  ((edited.extensions as Dict)["acme.procurement"] as Dict).requisition_id = "REQ-43";
  expect(verifySessionEvidenceRecord(edited, didDocuments)).toBe(false);
});

test("unnamespaced extension keys are refused by generator and verifier", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);

  expect(() =>
    generateEvidenceWith(session, null, { extensions: { requisition_id: "REQ-42" } }),
  ).toThrow(/namespaced/);

  const healthy = generateEvidenceWith(session, null, {
    extensions: { "acme.procurement": { ok: true } },
  });
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const bare = structuredClone(healthy);
  bare.extensions = { requisition_id: "REQ-42" };
  reseal(bare);
  expect(verifySessionEvidenceRecord(bare, didDocuments)).toBe(false);
});

test("unnamespaced top-level fields remain closed", () => {
  const [healthy, didDocuments] = pricedRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const widened = structuredClone(healthy);
  widened.acme_procurement = { requisition_id: "REQ-42" };
  reseal(widened);

  expect(verifySessionEvidenceRecord(widened, didDocuments)).toBe(false);
});

// --- inputs that would silently pass if a guard were absent -----------------

test("an observed responder cannot ride a COMPLETED record to bilateral", () => {
  const [manager, session, didDocuments] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  manager.processMessage(session, makeAcceptance(session.session_id, offer));

  const bilateral = generateEvidence(session);
  expect(bilateral.evidence_level).toBe("bilateral");
  expect(verifySessionEvidenceRecord(bilateral, didDocuments)).toBe(true);

  // Strip the counterparty's identity and its signed acceptance. What remains is
  // one party whose every act is signed. Two rules refuse it: the level of a
  // record whose responder is an observed_party is asserted unilateral (Section
  // 9A.5), so the recomputed level contradicts this claim, and the explicit
  // unilateral coupling refuses it as well.
  const forged = structuredClone(bilateral);
  (forged.parties as Dict).responder = {
    identity_source: "supplier_ordering_portal",
    did_declared: false,
    a2cn_endpoint_declared: false,
    mandate_declared: false,
  };
  forged.acts = [(forged.acts as Dict[])[0]];
  reseal(forged);

  const assessment = assessSessionEvidenceRecord(forged, didDocuments);

  expect(assessment.invalid_acts).toBe(0);
  expect(assessment.evidence_level).toBe("bilateral");
  expect(assessment.valid).toBe(false);
});

/**
 * Nullable sender_did must not open a hole in signed attribution.
 *
 * Measured, not assumed: both constructions below are already rejected at the
 * act level by guards that predate this change -- the entry/act field comparison
 * when the act keeps its own sender_did, and the signed-payload requirement when
 * it does not. The shape check added alongside observed_party makes the
 * invariant local; it is defence in depth, not the sole defence.
 */
test("a verified act can never carry a null sender_did", () => {
  const [healthy, didDocuments] = pricedRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);
  expect((healthy.acts as Dict[])[0].attribution).toBe("verified_signature");

  const entryOnly = structuredClone(healthy);
  (entryOnly.acts as Dict[])[0].sender_did = null;
  reseal(entryOnly);

  const entryAndAct = structuredClone(healthy);
  (entryAndAct.acts as Dict[])[0].sender_did = null;
  delete ((entryAndAct.acts as Dict[])[0].act as Dict).sender_did;
  (entryAndAct.acts as Dict[])[0].act_hash = hashObject((entryAndAct.acts as Dict[])[0].act);
  reseal(entryAndAct);

  for (const record of [entryOnly, entryAndAct]) {
    const assessment = assessSessionEvidenceRecord(record, didDocuments);
    expect(assessment.invalid_acts).toBe(1);
    expect(assessment.valid).toBe(false);
  }
});

test("extension vectors have Python/TypeScript hash parity", () => {
  const fixturePath = join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
    "spec",
    "test-vectors",
    "session-evidence-record-extensions.json",
  );
  const fixture = JSON.parse(readFileSync(fixturePath, "utf-8")) as Dict;
  const producer = fixture.producer as Dict;
  const privateKey = privateKeyFromJwk(fixture.producer_private_jwk as Dict);
  const vectors = fixture.vectors as Record<string, Dict>;

  expect(Object.keys(vectors).sort()).toEqual([
    "halted_by_controls",
    "money_basis",
    "observed_party_responder",
  ]);

  // The vector file speaks snake_case; the TypeScript option names are mapped
  // explicitly so a renamed option cannot be silently ignored.
  const OPTION_NAMES: Record<string, keyof GenerateSessionEvidenceOptions> = {
    observed_responder: "observedResponder",
    terminal_outcome: "terminalOutcome",
    terminal_reason: "terminalReason",
    terminal_money_basis: "terminalMoneyBasis",
    extensions: "extensions",
  };

  for (const [name, vector] of Object.entries(vectors)) {
    const sessionAck = (fixture.session_acks as Dict)[vector.session_ack as string] as Dict;
    const session = new Session({
      session_id: fixture.session_id as string,
      state: vector.state as string,
      current_turn: "none",
      terminal_reason: vector.terminal_reason as string,
      terminal_message_id: vector.terminal_message_id as string | null,
      session_created_at: fixture.session_created_at as string,
      state_updated_at: vector.state_updated_at as string,
      session_params: fixture.session_params as Dict,
      initiator_mandate: (fixture.session_init as Dict).initiator_mandate as Dict,
      responder_mandate: sessionAck.responder_mandate as Dict,
      _session_init: fixture.session_init as Dict,
      _session_ack: sessionAck,
      _message_log: vector.message_log as Dict[],
    });

    const options: GenerateSessionEvidenceOptions = {
      producerPrivateKey: privateKey,
      producerDid: producer.did as string,
      producerAgentId: producer.agent_id as string,
      producerVerificationMethod: producer.verification_method as string,
      observedActs: vector.observed_acts as Dict[],
    };
    for (const [snakeName, value] of Object.entries(vector.options as Dict)) {
      const optionName = OPTION_NAMES[snakeName];
      expect(optionName, `unmapped vector option ${snakeName}`).toBeDefined();
      (options as unknown as Record<string, unknown>)[optionName] = value;
    }

    const record = generateSessionEvidenceRecord(session, options);
    const expected = vector.expected as Dict;

    expect(record.evidence_id, name).toBe(expected.evidence_id);
    expect(record.generated_at, name).toBe(expected.generated_at);
    expect(record.evidence_level, name).toBe(expected.evidence_level);
    expect((record.terminal as Dict).outcome, name).toBe(expected.terminal_outcome);
    expect((record.acts as Dict[]).map((entry) => entry.act_hash), name).toEqual(
      expected.act_hashes,
    );
    expect(record.act_chain_hash, name).toBe(expected.act_chain_hash);
    expect(record.record_hash, name).toBe(expected.record_hash);
    expect(
      verifySessionEvidenceRecord(record, fixture.did_documents as Record<string, Dict>),
      name,
    ).toBe(true);
  }
});

const EXTENSION_VECTORS = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "spec",
      "test-vectors",
      "session-evidence-record-extensions.json",
    ),
    "utf-8",
  ),
) as Dict;
const MONEY_BASIS_ACT_BASIS_CASES = EXTENSION_VECTORS.money_basis_act_basis_cases as Dict;

/** The base vector's record, with the case's act basis and `label` on its money_basis. */
function moneyBasisCaseRecord(moneyBasisCase: Dict, label: string): Dict {
  const fixture = EXTENSION_VECTORS;
  const vector = structuredClone(
    (fixture.vectors as Record<string, Dict>)[MONEY_BASIS_ACT_BASIS_CASES.base_vector as string],
  );
  const quote = (vector.observed_acts as Dict[])[0];
  if (Object.prototype.hasOwnProperty.call(moneyBasisCase, "act_terms_basis")) {
    ((quote.act as Dict).terms as Dict).basis = moneyBasisCase.act_terms_basis;
  }
  // The Python suite passes the base vector's options straight through; its only
  // option is the terminal money_basis, so a new one would have to be mapped here.
  const vectorOptions = vector.options as Dict;
  expect(Object.keys(vectorOptions)).toEqual(["terminal_money_basis"]);
  let terminalMoneyBasis: Dict | null = null;
  if (moneyBasisCase.placement === "act") {
    (quote.money_basis as Dict).basis = label;
  } else {
    delete quote.money_basis;
    terminalMoneyBasis = { ...(vectorOptions.terminal_money_basis as Dict), basis: label };
  }

  const sessionAck = (fixture.session_acks as Dict)[vector.session_ack as string] as Dict;
  const session = new Session({
    session_id: fixture.session_id as string,
    state: vector.state as string,
    current_turn: "none",
    terminal_reason: vector.terminal_reason as string,
    terminal_message_id: vector.terminal_message_id as string | null,
    session_created_at: fixture.session_created_at as string,
    state_updated_at: vector.state_updated_at as string,
    session_params: fixture.session_params as Dict,
    initiator_mandate: (fixture.session_init as Dict).initiator_mandate as Dict,
    responder_mandate: sessionAck.responder_mandate as Dict,
    _session_init: fixture.session_init as Dict,
    _session_ack: sessionAck,
    _message_log: vector.message_log as Dict[],
  });
  const producer = fixture.producer as Dict;
  return generateSessionEvidenceRecord(session, {
    producerPrivateKey: privateKeyFromJwk(fixture.producer_private_jwk as Dict),
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs: vector.observed_acts as Dict[],
    terminalMoneyBasis,
  });
}

test.each(
  (MONEY_BASIS_ACT_BASIS_CASES.cases as Dict[]).map(
    (moneyBasisCase): [string, Dict] => [moneyBasisCase.name as string, moneyBasisCase],
  ),
)("money_basis act-basis vectors have Python/TypeScript parity: %s", (_name, moneyBasisCase) => {
  const fixture = EXTENSION_VECTORS;
  const didDocuments = fixture.did_documents as Record<string, Dict>;
  const label = moneyBasisCase.money_basis_basis as string;
  if (moneyBasisCase.valid) {
    const record = moneyBasisCaseRecord(moneyBasisCase, label);
    expect(record.record_hash).toBe(moneyBasisCase.record_hash);
    expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
    return;
  }

  expect(() => moneyBasisCaseRecord(moneyBasisCase, label)).toThrow(/money_basis/);

  // The same record with the label the generator refused, resealed by hand.
  const record = moneyBasisCaseRecord(moneyBasisCase, "unspecified");
  const holder =
    moneyBasisCase.placement === "act" ? (record.acts as Dict[])[1] : (record.terminal as Dict);
  (holder.money_basis as Dict).basis = label;
  record.record_hash = "";
  record.producer_signature = "";
  record.record_hash = hashObject(record);
  record.producer_signature = signJws(
    record.record_hash as string,
    privateKeyFromJwk(fixture.producer_private_jwk as Dict),
    (fixture.producer as Dict).verification_method as string,
  );

  expect(record.record_hash).toBe(moneyBasisCase.resealed_record_hash);
  expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(false);
});

// ---------------------------------------------------------------------------
// External-channel completion (Section 9A.12): a COMPLETED record whose
// completion witness is an external_commitment_reference, at record_version
// "0.3". The counterparty holds no A2CN identity, so there is no bilateral
// TransactionRecord to cross-link.
// ---------------------------------------------------------------------------

const EXTERNAL_COMMITMENT_REFERENCE: Dict = {
  external_order_id: "ORD-2026-000123",
  locator: "https://shop.example/.well-known/ucp",
};

function hasKey(object: unknown, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

/** The seller's order confirmation, observed through its commerce API, unsigned. */
function orderConfirmation(): Dict {
  return {
    sequence_number: null,
    round_number: null,
    message_type: "order_confirmation",
    message_id: "order-confirmation-1",
    sender_did: null,
    timestamp: "2026-03-24T10:05:00Z",
    source_protocol: "ucp",
    act: {
      message_type: "order_confirmation",
      message_id: "order-confirmation-1",
      timestamp: "2026-03-24T10:05:00Z",
      order: { id: "ORD-2026-000123", status: "confirmed" },
    },
  };
}

function markCompletedExternally(session: Session): void {
  session.state = SessionState.COMPLETED;
  session.current_turn = "none";
  session.terminal_reason = "external_order_confirmed";
  session.terminal_message_id = "order-confirmation-1";
  session.state_updated_at = "2026-03-24T10:05:00Z";
}

/** An identity-light session whose seller confirmed an order outside A2CN. */
function externalChannelSession(): [Session, Record<string, Dict>] {
  const [manager, session, didDocuments] = makeIdentityLightSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markCompletedExternally(session);
  return [session, didDocuments];
}

function externalChannelRecord(
  extra: Partial<GenerateSessionEvidenceOptions> = {},
): [Dict, Record<string, Dict>] {
  const [session, didDocuments] = externalChannelSession();
  return [
    generateEvidenceWith(session, [orderConfirmation()], {
      observedResponder: OBSERVED_RESPONDER,
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
      ...extra,
    }),
    didDocuments,
  ];
}

function bilateralRecord(): [Dict, Record<string, Dict>, Session] {
  const [manager, session, didDocuments] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  manager.processMessage(session, makeAcceptance(session.session_id, offer));
  return [generateEvidence(session), didDocuments, session];
}

// --- (i) and (ii): each completion witness on its own ------------------------

test("a bilateral COMPLETED record keeps its transaction record hash at 0.2", () => {
  const [evidence, didDocuments, session] = bilateralRecord();

  expect(evidence.record_version).toBe("0.2");
  expect(evidence.transaction_record_hash).toBe(generateTransactionRecord(session).record_hash);
  expect(hasKey(evidence, "external_commitment_reference")).toBe(false);
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("an external-channel COMPLETED record is valid at 0.3", () => {
  const [session, didDocuments] = externalChannelSession();
  // No TransactionRecord exists for this session: the counterparty never signed
  // an A2CN act. So the record below is produced without generating one.
  expect(() => generateTransactionRecord(session)).toThrow();

  const evidence = generateEvidenceWith(session, [orderConfirmation()], {
    observedResponder: OBSERVED_RESPONDER,
    externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
  });

  expect(evidence.record_version).toBe("0.3");
  expect((evidence.terminal as Dict).outcome).toBe(SessionState.COMPLETED);
  expect(evidence.transaction_record_hash).toBeNull();
  expect(evidence.external_commitment_reference).toStrictEqual(EXTERNAL_COMMITMENT_REFERENCE);
  expect(hasKey((evidence.parties as Dict).responder, "did")).toBe(false);
  expect(assessSessionEvidenceRecord(evidence, didDocuments)).toEqual({
    valid: true,
    evidence_level: "unilateral",
    verified_acts: 1,
    unsigned_acts: 1,
    invalid_acts: 0,
  });
});

// --- (iii) to (vi): the completion-witness rule and its coupling -------------

test("a COMPLETED record with both witnesses is rejected", () => {
  const [healthy, didDocuments] = externalChannelRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);
  // Re-sealing must itself produce a verifiable record, or the red below would
  // prove only that the reseal helper is broken.
  expect(verifySessionEvidenceRecord(reseal(structuredClone(healthy)), didDocuments)).toBe(
    true,
  );

  const both = structuredClone(healthy);
  both.transaction_record_hash = hashBytes(new TextEncoder().encode("a transaction record"));
  reseal(both);

  expect(verifySessionEvidenceRecord(both, didDocuments)).toBe(false);
});

test("a COMPLETED record with neither witness is rejected", () => {
  const [healthy, didDocuments] = externalChannelRecord();

  const neither = structuredClone(healthy);
  delete neither.external_commitment_reference;
  neither.record_version = "0.2";
  reseal(neither);

  expect(verifySessionEvidenceRecord(neither, didDocuments)).toBe(false);

  // A bilateral record that loses its TransactionRecord hash is refused too.
  const [bilateral, bilateralDocuments] = bilateralRecord();
  expect(verifySessionEvidenceRecord(bilateral, bilateralDocuments)).toBe(true);
  bilateral.transaction_record_hash = null;
  reseal(bilateral);

  expect(verifySessionEvidenceRecord(bilateral, bilateralDocuments)).toBe(false);
});

test.each([
  SessionState.REJECTED_FINAL,
  SessionState.WITHDRAWN,
  SessionState.TIMED_OUT,
  SessionState.IMPASSE,
  SessionState.ERROR,
  "HALTED_BY_CONTROLS",
])("a reference on any other outcome is rejected: %s", (outcome) => {
  const [healthy, didDocuments] = externalChannelRecord();

  const relabelled = structuredClone(healthy);
  (relabelled.terminal as Dict).outcome = outcome;
  reseal(relabelled);

  expect(verifySessionEvidenceRecord(relabelled, didDocuments)).toBe(false);
});

test("a transaction record hash on any other outcome is still rejected", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  const healthy = generateEvidence(session);
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const crossLinked = structuredClone(healthy);
  crossLinked.transaction_record_hash = hashBytes(
    new TextEncoder().encode("a transaction record"),
  );
  reseal(crossLinked);

  expect(verifySessionEvidenceRecord(crossLinked, didDocuments)).toBe(false);
});

test("a reference with a DID-bearing responder is rejected", () => {
  const [healthy, didDocuments] = externalChannelRecord();

  const identified = structuredClone(healthy);
  (identified.parties as Dict).responder = {
    organization_name: "Acme",
    did: RESPONDER_DID,
    agent_id: "seller-agent",
    verification_method: RESPONDER_VM,
    mandate_type: "declared",
  };
  reseal(identified);

  const assessment = assessSessionEvidenceRecord(identified, didDocuments);

  // Assert the reason before the verdict: every act verifies, and with the
  // seller's act unsigned the record is still unilateral, so what refuses it is
  // the rule that a reference needs an observed responder.
  expect(assessment.invalid_acts).toBe(0);
  expect(assessment.verified_acts).toBe(1);
  expect(assessment.unsigned_acts).toBe(1);
  expect(assessment.evidence_level).toBe("unilateral");
  expect(assessment.valid).toBe(false);
});

test.each(["mixed", "bilateral"])(
  "a reference with evidence other than unilateral is rejected: %s",
  (evidenceLevel) => {
    const [healthy, didDocuments] = externalChannelRecord();

    const promoted = structuredClone(healthy);
    promoted.evidence_level = evidenceLevel;
    reseal(promoted);

    expect(verifySessionEvidenceRecord(promoted, didDocuments)).toBe(false);
  },
);

/**
 * The producer's own signed acts never make an observed-responder record bilateral.
 *
 * The level of such a record is asserted unilateral (Section 9A.5), so the
 * recomputed level contradicts a bilateral claim. Section 9A.8 and the
 * reference's own coupling (Section 9A.12) refuse it as well.
 */
test("a reference cannot ride a fully signed record to bilateral", () => {
  const [healthy, didDocuments] = externalChannelRecord();

  const forged = structuredClone(healthy);
  forged.acts = [(forged.acts as Dict[])[0]];
  forged.evidence_level = "bilateral";
  reseal(forged);

  const assessment = assessSessionEvidenceRecord(forged, didDocuments);

  expect(assessment.invalid_acts).toBe(0);
  expect(assessment.verified_acts).toBe(1);
  expect(assessment.valid).toBe(false);
});

// --- record_version follows the reference, in both directions ----------------

test.each(["0.2", "0.1"])("a reference on a record that is not 0.3 is rejected: %s", (version) => {
  const [healthy, didDocuments] = externalChannelRecord();

  const relabelled = structuredClone(healthy);
  relabelled.record_version = version;
  reseal(relabelled);

  expect(verifySessionEvidenceRecord(relabelled, didDocuments)).toBe(false);
});

test("a 0.3 record without a reference is rejected", () => {
  const [bilateral, bilateralDocuments] = bilateralRecord();
  const [timedOut, timedOutDocuments] = mixedRecord();

  for (const [record, didDocuments] of [
    [bilateral, bilateralDocuments],
    [timedOut, timedOutDocuments],
  ] as [Dict, Record<string, Dict>][]) {
    expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
    const relabelled = structuredClone(record);
    relabelled.record_version = "0.3";
    reseal(relabelled);
    expect(verifySessionEvidenceRecord(relabelled, didDocuments)).toBe(false);
  }
});

// --- the seal, and what the verifier must not do ----------------------------

test("editing the reference after sealing invalidates the record", () => {
  const [healthy, didDocuments] = externalChannelRecord({
    externalCommitmentReference: { ...EXTERNAL_COMMITMENT_REFERENCE, reference_note: "confirmed" },
  });
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  for (const [field, value] of [
    ["external_order_id", "ORD-2026-000124"],
    ["locator", "https://other.example/.well-known/ucp"],
    ["reference_note", "cancelled"],
  ]) {
    const edited = structuredClone(healthy);
    (edited.external_commitment_reference as Dict)[field] = value;
    expect(verifySessionEvidenceRecord(edited, didDocuments), field).toBe(false);
  }

  const dropped = structuredClone(healthy);
  delete (dropped.external_commitment_reference as Dict).reference_note;
  expect(verifySessionEvidenceRecord(dropped, didDocuments)).toBe(false);
});

test("the verifier never dereferences the locator", () => {
  const [evidence, didDocuments] = externalChannelRecord();
  const requested: string[] = [];
  const recordingResolver = (did: string): Dict => {
    requested.push(did);
    return didDocuments[did];
  };
  const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(() => {
    throw new Error("the verifier reached for the network");
  });

  try {
    expect(verifySessionEvidenceRecord(evidence, recordingResolver)).toBe(true);
    expect([...new Set(requested)]).toEqual([INITIATOR_DID]);
    expect(fetchSpy).not.toHaveBeenCalled();
  } finally {
    fetchSpy.mockRestore();
  }
});

/**
 * TypeScript can hold a key whose value is undefined. canonicalize drops such a
 * key, so a record that gains one still matches its seal; only the rules that
 * look at key presence can refuse it, and they must.
 */
test("a reference key that is present but undefined is not read as absent", () => {
  // An undefined option is not supplied, so the observed completion lacks one.
  const [session] = externalChannelSession();
  expect(() =>
    generateEvidenceWith(session, [orderConfirmation()], {
      observedResponder: OBSERVED_RESPONDER,
      externalCommitmentReference: undefined,
    }),
  ).toThrow(/requires externalCommitmentReference/);
  // An undefined member is a present key whose value is not a string.
  expect(() =>
    generateEvidenceWith(session, [orderConfirmation()], {
      observedResponder: OBSERVED_RESPONDER,
      externalCommitmentReference: { external_order_id: "ORD-2026-000123", locator: undefined },
    }),
  ).toThrow(/must be an object/);

  const [orderIdOnly, didDocuments] = externalChannelRecord({
    externalCommitmentReference: { external_order_id: "ORD-2026-000123" },
  });
  expect(verifySessionEvidenceRecord(orderIdOnly, didDocuments)).toBe(true);
  const undefinedMember = structuredClone(orderIdOnly);
  (undefinedMember.external_commitment_reference as Dict).locator = undefined;
  expect(hashObject({ ...undefinedMember, record_hash: "", producer_signature: "" })).toBe(
    orderIdOnly.record_hash,
  );
  expect(verifySessionEvidenceRecord(undefinedMember, didDocuments)).toBe(false);

  const [plain, plainDocuments] = mixedRecord();
  const undefinedReference = structuredClone(plain);
  undefinedReference.external_commitment_reference = undefined;
  expect(hashObject({ ...undefinedReference, record_hash: "", producer_signature: "" })).toBe(
    plain.record_hash,
  );
  expect(verifySessionEvidenceRecord(undefinedReference, plainDocuments)).toBe(false);
});

// --- what the generator refuses to seal -------------------------------------

test("the generator refuses a reference for a DID-bearing responder", () => {
  const [manager, session] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  manager.processMessage(session, makeAcceptance(session.session_id, offer));

  expect(() =>
    generateEvidenceWith(session, null, {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/completes with its TransactionRecord/);
});

test.each([
  ["omitted", {}],
  ["null", { externalCommitmentReference: null }],
] as [string, Partial<GenerateSessionEvidenceOptions>][])(
  "the generator refuses an observed completion without a reference: %s",
  (_name, extra) => {
    const [session] = externalChannelSession();

    expect(() =>
      generateEvidenceWith(session, [orderConfirmation()], {
        observedResponder: OBSERVED_RESPONDER,
        ...extra,
      }),
    ).toThrow(/requires externalCommitmentReference/);
  },
);

test("the generator refuses a reference on any other outcome", () => {
  // An observed responder, so only the outcome is wrong.
  const [identityLightManager, identityLightSession] = makeIdentityLightSession();
  identityLightManager.processMessage(
    identityLightSession,
    makeOffer(identityLightSession.session_id),
  );
  markTimedOut(identityLightSession);
  expect(() =>
    generateEvidenceWith(identityLightSession, [orderConfirmation()], {
      observedResponder: OBSERVED_RESPONDER,
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/only for a COMPLETED session/);

  // A run the producer's controls halted did not complete either.
  identityLightSession.state = SessionState.WITHDRAWN;
  expect(() =>
    generateEvidenceWith(identityLightSession, null, {
      observedResponder: OBSERVED_RESPONDER,
      terminalOutcome: "HALTED_BY_CONTROLS",
      terminalReason: "buyer_spend_control:max_session_commitment",
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/only for a COMPLETED session/);

  // A DID-bearing responder on another outcome is refused for the outcome.
  const [manager, session] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);
  expect(() =>
    generateEvidenceWith(session, null, {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/only for a COMPLETED session/);
});

test("the generator refuses a reference that is not an object", () => {
  const [session] = externalChannelSession();

  // Anchored, so the refusal is the object check and not the shape check behind it.
  expect(() =>
    generateEvidenceWith(session, [orderConfirmation()], {
      observedResponder: OBSERVED_RESPONDER,
      externalCommitmentReference: "ORD-2026-000123" as unknown as Dict,
    }),
  ).toThrow(/must be an object$/);
});

test("the generator seals a copy of the reference", () => {
  const reference = structuredClone(EXTERNAL_COMMITMENT_REFERENCE);
  const [evidence, didDocuments] = externalChannelRecord({
    externalCommitmentReference: reference,
  });

  reference.external_order_id = "ORD-2026-999999";

  expect(evidence.external_commitment_reference).toStrictEqual(EXTERNAL_COMMITMENT_REFERENCE);
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("a null reference is not supplied", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);

  const evidence = generateEvidenceWith(session, null, { externalCommitmentReference: null });

  expect(evidence.record_version).toBe("0.2");
  expect(hasKey(evidence, "external_commitment_reference")).toBe(false);
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

/**
 * The completion witness matches the responder in both directions (Section 9A.2).
 *
 * A TransactionRecord is bilateral (Section 9.3), so a session whose responder is
 * an observed_party has none, and a record that claims one for such a session is
 * refused at every version. The generators that predate the external commitment
 * reference sealed exactly this record, over a TransactionRecord whose responder
 * was empty.
 */
test.each(["0.2", "0.1"])(
  "an observed completion with a transaction record hash is rejected: %s",
  (version) => {
    const [healthy, didDocuments] = externalChannelRecord();

    const earlierShape = structuredClone(healthy);
    delete earlierShape.external_commitment_reference;
    earlierShape.record_version = version;
    earlierShape.transaction_record_hash = hashBytes(
      new TextEncoder().encode("a transaction record"),
    );
    reseal(earlierShape);

    expect(verifySessionEvidenceRecord(earlierShape, didDocuments)).toBe(false);
    // A DID-bearing responder carrying the same witness still verifies.
    const [bilateral, bilateralDocuments] = bilateralRecord();
    expect(verifySessionEvidenceRecord(bilateral, bilateralDocuments)).toBe(true);
  },
);

/**
 * A responder with no DID signs no TransactionRecord, so none can be cross-linked.
 *
 * The generators that predate the external commitment reference sealed this
 * record anyway, hashing a TransactionRecord whose responder was empty.
 */
test("the generator refuses a COMPLETED record whose responder has no DID", () => {
  const [manager, session] = makeIdentityLightSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  manager.processMessage(session, makeAcceptance(session.session_id, offer));
  expect(session.state).toBe(SessionState.COMPLETED);

  expect(() => generateEvidence(session)).toThrow(/DID-bearing responder/);
});

// --- the evidence level is asserted, and one producer act is required --------

/**
 * The producer's signed offer plus the order reference, with nothing observed.
 *
 * A record whose responder is an observed_party is unilateral by assertion
 * (Section 9A.5) rather than by counting acts, so this record has a level it can
 * carry. Before, the classifier called it bilateral and no level verified.
 */
test("an external-channel record of producer acts only is unilateral", () => {
  const [session, didDocuments] = externalChannelSession();

  const evidence = generateEvidenceWith(session, null, {
    observedResponder: OBSERVED_RESPONDER,
    externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
  });

  expect((evidence.acts as Dict[]).map((entry) => entry.attribution)).toEqual([
    "verified_signature",
  ]);
  expect(evidence.evidence_level).toBe("unilateral");
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("an external-channel record without a producer-signed act is rejected", () => {
  // Section 9A.12: at least one act is signed by the initiator that sealed it.
  const [healthy, didDocuments] = externalChannelRecord();

  const actLess = structuredClone(healthy);
  actLess.acts = [];
  reseal(actLess);

  const unsignedOnly = structuredClone(healthy);
  unsignedOnly.acts = [structuredClone((healthy.acts as Dict[])[1])];
  reseal(unsignedOnly);

  expect(verifySessionEvidenceRecord(actLess, didDocuments)).toBe(false);
  expect(verifySessionEvidenceRecord(unsignedOnly, didDocuments)).toBe(false);
});

test("the generator refuses an external-channel record with no producer act", () => {
  const [session] = externalChannelSession();
  session._message_log = [];

  expect(() =>
    generateEvidenceWith(session, [orderConfirmation()], {
      observedResponder: OBSERVED_RESPONDER,
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/at least one act signed by/);
});

// --- the producer of an external-channel record is its initiator -------------

/** The record resealed by a DID that is not a session party. */
function sealedByThirdParty(record: Dict): Dict {
  record.producer = {
    did: THIRD_PARTY_DID,
    agent_id: "recorder-agent",
    verification_method: THIRD_PARTY_VM,
  };
  record.evidence_id = uuidv5(
    `session-evidence:${record.session_id as string}:${THIRD_PARTY_DID}`,
    A2CN_NAMESPACE,
  );
  record.act_chain_hash = hashBytes(
    canonicalize((record.acts as Dict[]).map((entry) => entry.act_hash)),
  );
  record.record_hash = "";
  record.producer_signature = "";
  record.record_hash = hashObject(record);
  record.producer_signature = signJws(
    record.record_hash as string,
    THIRD_PARTY_PRIVATE_KEY,
    THIRD_PARTY_VM,
  );
  return record;
}

test("an external-channel record sealed by a third party is rejected", () => {
  // Section 9A.12: the seal is the only cryptographic evidence, so it is the initiator's.
  const [healthy, didDocuments] = externalChannelRecord();
  didDocuments[THIRD_PARTY_DID] = makeDidDocument(
    THIRD_PARTY_DID,
    "key-1",
    publicKeyToJwk(THIRD_PARTY_PUBLIC_KEY),
  );

  const reseated = sealedByThirdParty(structuredClone(healthy));

  const assessment = assessSessionEvidenceRecord(reseated, didDocuments);

  // The acts verify and the seal itself is sound, so the producer binding is
  // what refuses the record.
  expect(assessment.invalid_acts).toBe(0);
  expect(assessment.verified_acts).toBe(1);
  expect(assessment.valid).toBe(false);
});

test("the generator refuses to seal an external-channel record for another party", () => {
  const [session] = externalChannelSession();

  expect(() =>
    generateSessionEvidenceRecord(session, {
      producerPrivateKey: THIRD_PARTY_PRIVATE_KEY,
      producerDid: THIRD_PARTY_DID,
      producerAgentId: "recorder-agent",
      producerVerificationMethod: THIRD_PARTY_VM,
      observedActs: [orderConfirmation()],
      observedResponder: OBSERVED_RESPONDER,
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/sealed by/);
});

// --- the shared external-channel vector --------------------------------------

const EXTERNAL_CHANNEL_VECTOR = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "spec",
      "test-vectors",
      "session-evidence-record-external-channel.json",
    ),
    "utf-8",
  ),
) as Dict;
const EXTERNAL_CHANNEL_KEY = privateKeyFromJwk(EXTERNAL_CHANNEL_VECTOR.producer_private_jwk as Dict);
const EXTERNAL_CHANNEL_DID_DOCUMENTS = EXTERNAL_CHANNEL_VECTOR.did_documents as Record<string, Dict>;

/** The record the vector's session generates, optionally with another reference. */
function externalChannelVectorRecord(
  reference: unknown = (EXTERNAL_CHANNEL_VECTOR.options as Dict).external_commitment_reference,
  observedActs: Dict[] = EXTERNAL_CHANNEL_VECTOR.observed_acts as Dict[],
): Dict {
  const fixture = EXTERNAL_CHANNEL_VECTOR;
  const source = fixture.session as Dict;
  const session = new Session({
    session_id: source.session_id as string,
    state: source.state as string,
    current_turn: "none",
    terminal_reason: source.terminal_reason as string,
    terminal_message_id: source.terminal_message_id as string | null,
    session_created_at: source.session_created_at as string,
    state_updated_at: source.state_updated_at as string,
    session_params: source.session_params as Dict,
    initiator_mandate: source.initiator_mandate as Dict,
    responder_mandate: source.responder_mandate as Dict,
    _session_init: source.session_init as Dict,
    _session_ack: source.session_ack as Dict | null,
    _message_log: source.message_log as Dict[],
  });
  // The Python suite passes the vector's options straight through; each one is
  // mapped here by name, so a new one would have to be added.
  const options = fixture.options as Dict;
  expect(Object.keys(options).sort()).toEqual(["external_commitment_reference", "observed_responder"]);
  const producer = fixture.producer as Dict;
  return generateSessionEvidenceRecord(session, {
    producerPrivateKey: EXTERNAL_CHANNEL_KEY,
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs,
    observedResponder: structuredClone(options.observed_responder as Dict),
    externalCommitmentReference: structuredClone(reference) as Dict | null,
  });
}

/** Reseal, with the producer the case names or the vector's own. */
function resealExternalChannel(record: Dict, sealingCase: Dict | null = null): Dict {
  const sealedBy = sealingCase?.sealed_by as string | undefined;
  const producer = sealedBy
    ? (EXTERNAL_CHANNEL_VECTOR[sealedBy] as Dict)
    : (EXTERNAL_CHANNEL_VECTOR.producer as Dict);
  const key = sealedBy ? privateKeyFromJwk(producer.private_jwk as Dict) : EXTERNAL_CHANNEL_KEY;
  record.act_chain_hash = hashBytes(
    canonicalize((record.acts as Dict[]).map((entry) => entry.act_hash)),
  );
  record.record_hash = "";
  record.producer_signature = "";
  record.record_hash = hashObject(record);
  record.producer_signature = signJws(
    record.record_hash as string,
    key,
    producer.verification_method as string,
  );
  return record;
}

/** Set each path in `changes.set` to its value and delete each path in `changes.remove`. */
function applyChanges(record: Dict, changes: Dict): Dict {
  const holderOf = (path: string[]): Dict =>
    path.slice(0, -1).reduce((current: Dict, key) => current[key] as Dict, record);
  for (const change of (changes.set ?? []) as Dict[]) {
    const path = change.path as string[];
    let value = change.value;
    if (value === "OBSERVED_ACTS_ONLY") {
      // The record's observed act alone, so no act is the producer's.
      value = [(record.acts as Dict[])[1]];
    }
    holderOf(path)[path[path.length - 1]] = structuredClone(value);
  }
  for (const path of (changes.remove ?? []) as string[][]) {
    delete holderOf(path)[path[path.length - 1]];
  }
  return record;
}

test("external-channel vector has Python/TypeScript parity", () => {
  const expected = EXTERNAL_CHANNEL_VECTOR.expected as Dict;

  const record = externalChannelVectorRecord();

  expect(record.record_version).toBe(expected.record_version);
  expect(record.evidence_id).toBe(expected.evidence_id);
  expect(record.generated_at).toBe(expected.generated_at);
  expect(record.evidence_level).toBe(expected.evidence_level);
  expect((record.acts as Dict[]).map((entry) => entry.act_hash)).toEqual(expected.act_hashes);
  expect(record.act_chain_hash).toBe(expected.act_chain_hash);
  expect(record.record_hash).toBe(expected.record_hash);
  // Ed25519 signatures are deterministic, so the whole sealed record matches,
  // the producer seal included.
  expect(record).toStrictEqual(expected.record);
  expect(verifySessionEvidenceRecord(record, EXTERNAL_CHANNEL_DID_DOCUMENTS)).toBe(true);
  // Resealing the same bytes reproduces the same record.
  expect(resealExternalChannel(structuredClone(record))).toStrictEqual(record);
});

test.each(
  (EXTERNAL_CHANNEL_VECTOR.valid_references as Dict[]).map((entry): [string, Dict] => [
    entry.name as string,
    entry,
  ]),
)("external-channel valid reference has Python/TypeScript parity: %s", (_name, entry) => {
  const record = externalChannelVectorRecord(entry.external_commitment_reference);

  expect(record.external_commitment_reference).toStrictEqual(entry.external_commitment_reference);
  expect(record.record_hash).toBe(entry.record_hash);
  expect(verifySessionEvidenceRecord(record, EXTERNAL_CHANNEL_DID_DOCUMENTS)).toBe(true);
});

test.each(
  (EXTERNAL_CHANNEL_VECTOR.invalid_references as Dict[]).map((entry): [string, Dict] => [
    entry.name as string,
    entry,
  ]),
)("external-channel malformed reference is refused and rejected: %s", (_name, entry) => {
  const reference = entry.external_commitment_reference;
  // null is not supplied, so the generator refuses the session for lacking one.
  expect(() => externalChannelVectorRecord(reference)).toThrow(
    reference === null ? /requires externalCommitmentReference/ : /must be an object/,
  );

  const record = structuredClone((EXTERNAL_CHANNEL_VECTOR.expected as Dict).record as Dict);
  record.external_commitment_reference = structuredClone(reference);
  resealExternalChannel(record);

  expect(record.record_hash).toBe(entry.resealed_record_hash);
  expect(verifySessionEvidenceRecord(record, EXTERNAL_CHANNEL_DID_DOCUMENTS)).toBe(false);
});

test.each(
  (EXTERNAL_CHANNEL_VECTOR.invalid_records as Dict[]).map((entry): [string, Dict] => [
    entry.name as string,
    entry,
  ]),
)("external-channel invalid record has Python/TypeScript parity: %s", (_name, entry) => {
  const record = applyChanges(
    structuredClone((EXTERNAL_CHANNEL_VECTOR.expected as Dict).record as Dict),
    entry,
  );
  resealExternalChannel(record, entry);

  expect(record.record_hash).toBe(entry.resealed_record_hash);
  expect(verifySessionEvidenceRecord(record, EXTERNAL_CHANNEL_DID_DOCUMENTS)).toBe(false);
});

test.each(
  (EXTERNAL_CHANNEL_VECTOR.valid_variants as Dict[]).map((entry): [string, Dict] => [
    entry.name as string,
    entry,
  ]),
)("external-channel valid variant has Python/TypeScript parity: %s", (_name, entry) => {
  const record = externalChannelVectorRecord(
    (EXTERNAL_CHANNEL_VECTOR.options as Dict).external_commitment_reference,
    entry.observed_acts as Dict[],
  );

  expect(record.evidence_level).toBe(entry.evidence_level);
  expect(record.record_hash).toBe(entry.record_hash);
  expect(verifySessionEvidenceRecord(record, EXTERNAL_CHANNEL_DID_DOCUMENTS)).toBe(true);
});
