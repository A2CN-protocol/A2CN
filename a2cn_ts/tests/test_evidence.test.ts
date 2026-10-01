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
  verifyJws,
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
import { PROTOCOL_ACT_VERSION, signedActHash, type Dict } from "../src/a2cn/messages.js";
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
    protocol_version: "0.3",
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
    protocol_version: "0.3",
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
    protocol_version: "0.3",
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
  const acceptance: Dict = {
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
  };
  // Signed over the act's own envelope (Section 7.3.1): the common header plus
  // an acceptance's payload, accepted_offer_id and accepted_protocol_act_hash.
  acceptance.acceptance_signature = signJws(
    signedActHash(acceptance, { versionWhenAbsent: PROTOCOL_ACT_VERSION }) as string,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
  );
  return acceptance;
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
    protocol_version: "0.3",
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
    protocol_version: "0.3",
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
  // A live withdrawal must now be signed, so an incomplete unsigned one reaches a
  // record only as a stored act, not through the state machine (Section 7.6).
  const [, session, didDocuments] = makeSession();
  session._message_log.push({
    message_type: "withdrawal",
    round_number: 1,
    sender_did: INITIATOR_DID,
  });
  session.state = SessionState.WITHDRAWN;
  session.current_turn = "none";
  session.terminal_reason = "withdrawal";
  session.terminal_message_id = null;

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

const DECLINE_PARITY_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "spec",
  "test-vectors",
  "session-evidence-record-decline.json",
);

/** The record the decline vector's session produces — generated, not loaded. */
function declineParityRecord(fixture: Dict): Dict {
  const source = fixture.session as Dict;
  const producer = fixture.producer as Dict;
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
    _session_ack: source.session_ack as Dict,
    _message_log: source.message_log as Dict[],
  });
  return generateSessionEvidenceRecord(session, {
    producerPrivateKey: privateKeyFromJwk(fixture.producer_private_jwk as Dict),
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs: fixture.observed_acts as Dict[] | null,
  });
}

test("decline-bearing record has Python/TypeScript hash parity", () => {
  // Both implementations EMIT identical bytes for a record carrying a signed
  // decline. Generate-and-compare, never load-and-verify: this family exists to
  // prove that today's two generators agree, and a loaded record would pass
  // while proving neither implementation generated anything.
  //
  // Signed declines are this change's headline feature and nothing crossed them
  // with the repository's cross-language byte-parity property: decline ACTS had
  // a shared vector (signed-decline-acts.json), decline-bearing RECORDS had
  // none. The pinned values were produced by the Python generator, so a failure
  // here is a real divergence rather than a stale fixture.
  const fixture = JSON.parse(readFileSync(DECLINE_PARITY_PATH, "utf-8")) as Dict;
  const record = declineParityRecord(fixture);
  const expected = fixture.expected as Dict;

  expect(record.record_version).toBe(expected.record_version);
  expect(record.evidence_id).toBe(expected.evidence_id);
  expect(record.generated_at).toBe(expected.generated_at);
  expect(record.evidence_level).toBe(expected.evidence_level);
  expect((record.acts as Dict[]).map((entry) => entry.act_hash)).toEqual(expected.act_hashes);
  expect(record.act_chain_hash).toBe(expected.act_chain_hash);
  expect(record.record_hash).toBe(expected.record_hash);
  expect(verifySessionEvidenceRecord(record, fixture.did_documents as Record<string, Dict>)).toBe(
    true,
  );
});

test("the decline parity vector actually carries decline vocabulary", () => {
  // A guard on the fixture, so the parity test above cannot come to prove
  // nothing. Without it, an edit that dropped the signature from the stored
  // rejection would leave the hash comparison passing on an ordinary record,
  // silently retiring the only cross-language coverage a signed decline has.
  const fixture = JSON.parse(readFileSync(DECLINE_PARITY_PATH, "utf-8")) as Dict;
  const record = declineParityRecord(fixture);

  const signatureTypes = (record.acts as Dict[]).map((entry) => entry.signature_type);
  expect(signatureTypes).toContain("rejection_signature");
  expect(record.record_version).toBe("0.5");
  expect((record.acts as Dict[]).every((e) => e.attribution === "verified_signature")).toBe(true);
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
  // Recorded as a record states an act: with the wire version it was signed under.
  signedAct.protocol_version = PROTOCOL_ACT_VERSION;
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
  external_commitment_id: "ORD-2026-000123",
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

test("a bilateral COMPLETED record keeps its transaction record hash", () => {
  const [evidence, didDocuments, session] = bilateralRecord();

  expect(evidence.record_version).toBe("0.5");
  expect(evidence.transaction_record_hash).toBe(generateTransactionRecord(session).record_hash);
  expect(hasKey(evidence, "external_commitment_reference")).toBe(false);
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("an external-channel COMPLETED record is valid", () => {
  const [session, didDocuments] = externalChannelSession();
  // No TransactionRecord exists for this session: the counterparty never signed
  // an A2CN act. So the record below is produced without generating one.
  expect(() => generateTransactionRecord(session)).toThrow();

  const evidence = generateEvidenceWith(session, [orderConfirmation()], {
    observedResponder: OBSERVED_RESPONDER,
    externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
  });

  expect(evidence.record_version).toBe("0.5");
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

test("a 0.5 COMPLETED record with neither witness is rejected", () => {
  // The case above relabels to "0.2" precisely so the version rule passes and
  // only the witness rule can fire. From "0.4" on that isolation is free: the
  // reference is OPTIONAL there, so removing it leaves the version rule silent
  // and nothing but Section 9A.6 step 9 to refuse the record. Nothing else
  // covered the version the generator actually produces. Named for the emitted
  // version deliberately: a name that outlives its referent reads as coverage
  // of a version nobody emits any more.
  const [healthy, didDocuments] = externalChannelRecord();
  expect(healthy.record_version).toBe("0.5");
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);

  const neither = structuredClone(healthy);
  delete neither.external_commitment_reference;
  reseal(neither);

  // No relabel: the record is refused while still carrying the version it was
  // generated with.
  expect(neither.record_version).toBe("0.5");
  expect(verifySessionEvidenceRecord(neither, didDocuments)).toBe(false);
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

test("a reference with a DID-bearing responder is admitted unless bilateral", () => {
  // The relationship survives; what changed is what it permits. Before "0.5" a
  // DID-bearing responder refused the reference outright. That gate was an
  // IDENTITY PROXY for the property that no counterparty signature witnesses
  // the completion, and a counterparty whose identity verifies but whose acts
  // are unsigned satisfies it exactly as fully as one with no identity at all.
  //
  // bilateral still refuses the record, since that level asserts both parties'
  // material acts are attributable — precisely the claim an external witness
  // cannot make. It is NOT what keeps a counterparty SIGNATURE out, though, and
  // reading it that way is what left a gap here: bilateral requires nothing to
  // be unsigned, so one unsigned observed act leaves a fully signed session at
  // mixed, which is admitted. The counterparty-signature exclusion is a check of
  // its own, covered further down this file. Every arm below carries an unsigned
  // observed act whose sender is null or the responder and no signature of the
  // responder's, so none of them exercises that check.
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

  // Arm one: the counterparty's observed act carries no DID of its own, so the
  // classifier counts one represented party and the level stays unilateral.
  const assessment = assessSessionEvidenceRecord(identified, didDocuments);
  expect(assessment.invalid_acts).toBe(0);
  expect(assessment.verified_acts).toBe(1);
  expect(assessment.unsigned_acts).toBe(1);
  expect(assessment.evidence_level).toBe("unilateral");
  expect(assessment.valid).toBe(true);

  // Arm two: attribute the observed act to the responder's DID and both parties
  // are represented, so the level is mixed — admitted as well. Both conditions
  // widened at "0.5", and both were identity proxies on the same property; a
  // producer must not have to discard a verified DID to reach an admitted
  // classification.
  const mixed = structuredClone(identified);
  const observed = (mixed.acts as Dict[]).find(
    (entry) => entry.attribution === "unsigned_observation",
  ) as Dict;
  observed.sender_did = RESPONDER_DID;
  mixed.evidence_level = "mixed";
  reseal(mixed);

  expect(verifySessionEvidenceRecord(mixed, didDocuments)).toBe(true);

  // Arm three: bilateral, and nothing else, still refuses. It differs from arm
  // two in EXACTLY ONE FIELD, so the refusal is attributable to the label — and
  // the external-commitment rule runs before the recomputed-level comparison,
  // so it is that rule which fires, not a classification mismatch.
  const bilateral = structuredClone(mixed);
  bilateral.evidence_level = "bilateral";
  reseal(bilateral);

  expect(verifySessionEvidenceRecord(bilateral, didDocuments)).toBe(false);
});

// Unchanged by the "0.5" relaxation, and refused by a different rule: an
// OBSERVED responder is still coupled to unilateral evidence by Section 9A.8,
// which this change does not touch, so both levels are refused before the
// external-commitment rule is consulted. Named for the observed responder now —
// the old name overclaimed a rule that no longer holds in general.
test.each(["mixed", "bilateral"])(
  "a reference with an observed responder requires unilateral evidence: %s",
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
    ["external_commitment_id", "ORD-2026-000124"],
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
      externalCommitmentReference: { external_commitment_id: "ORD-2026-000123", locator: undefined },
    }),
  ).toThrow(/must be an object/);

  const [orderIdOnly, didDocuments] = externalChannelRecord({
    externalCommitmentReference: { external_commitment_id: "ORD-2026-000123" },
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

test("the generator refuses a reference for a bilateral session", () => {
  // A genuinely bilateral session cannot claim an external witness.
  //
  // Both parties signed, and the responder signed the ACCEPTANCE — the
  // completion. A completion both parties signed is a TransactionRecord, so the
  // acceptance rule refuses the reference: a verified acceptance is admitted only
  // when the initiator signed it and the responder signed no act.
  //
  // This once exercised the bilateral level exclusion instead, because the
  // session has nothing unsigned. It cannot any more: the classifier never
  // returns bilateral for a record carrying the reference, so this session
  // classifies mixed and the level check never objects. The rules that keep a
  // counterparty-signed completion out are tested further down this file.
  const [manager, session] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  manager.processMessage(session, makeAcceptance(session.session_id, offer));

  expect(() =>
    generateEvidenceWith(session, null, {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/admits a signed acceptance only/);
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

  reference.external_commitment_id = "ORD-2026-999999";

  expect(evidence.external_commitment_reference).toStrictEqual(EXTERNAL_COMMITMENT_REFERENCE);
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("a null reference is not supplied", () => {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markTimedOut(session);

  const evidence = generateEvidenceWith(session, null, { externalCommitmentReference: null });

  expect(evidence.record_version).toBe("0.5");
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
test.each(["0.4", "0.2", "0.1"])(
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

/**
 * Set each path in `changes.set` to its value and delete each path in `changes.remove`.
 *
 * The `string[]` casts below are DELIBERATE AND LOAD-BEARING, and they understate
 * the runtime type: a path element may be a string (object key) or a NUMBER (array
 * index). The `mixed` external-channel case targets `["acts", 1, "sender_did"]`,
 * where `1` is a JSON number, and JS array indexing accepts it unchanged.
 *
 * DO NOT "fix" these to a stricter type. Three harnesses walk these paths -- this
 * one, `_apply_changes` and `_with_changes` on the Python side -- and the vectors
 * are the CROSS-LANGUAGE contract, so all three must accept the same paths.
 * Tighten `path` here and that case breaks in TypeScript ALONE, which is exactly
 * the divergence the shared vectors exist to close.
 */
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

// The bucket that mirrors invalid_records and MUST verify. Same shape, same
// derivation, opposite verdict: each case applies its changes to expected.record
// and reseals exactly as invalid_records does, so a case migrating between the
// two buckets is a move rather than a rewrite. It exists because valid_variants
// varies only observed_acts, and a structure carrying two contracts cannot tell
// a reader which dimension an entry varies.
test.each(
  (EXTERNAL_CHANNEL_VECTOR.valid_records as Dict[]).map((entry): [string, Dict] => [
    entry.name as string,
    entry,
  ]),
)("external-channel valid record has Python/TypeScript parity: %s", (_name, entry) => {
  const record = applyChanges(
    structuredClone((EXTERNAL_CHANNEL_VECTOR.expected as Dict).record as Dict),
    entry,
  );
  resealExternalChannel(record, entry);

  expect(record.record_hash).toBe(entry.record_hash);
  expect(verifySessionEvidenceRecord(record, EXTERNAL_CHANNEL_DID_DOCUMENTS)).toBe(true);
});

// ---------------------------------------------------------------------------
// Mandate-only completion: a verified counterparty whose acts are unsigned
// (Section 9A.12). The Python mirror is tests/test_mandate_only_completion.py;
// these live here rather than in a file of their own because the TypeScript
// suite has no cross-test imports and every fixture below is module-local.
//
// A counterparty can hold a resolvable DID and a mandate that verifies and
// still never sign an act. That responder is a DID-bearing full party, never an
// observed_party -- that descriptor requires the declared-markers to be
// literally false -- and with its acts unsigned there is no bilateral
// TransactionRecord either. The property the external-channel witness protects
// is NO COUNTERPARTY SIGNATURE WITNESSES THE COMPLETION; observed_party plus
// unilateral was an identity proxy narrower than that property.
//
// WHAT ENFORCES IT is a check of its own, added once the proxies were relaxed
// and covered at the end of this section. Neither the producer-signed-act rule
// nor the exactly-one-witness rule excludes a counterparty signature — the first
// asks for an act of the INITIATOR'S, which a record where both parties signed
// supplies, and the second is satisfied by a producer that suppresses a
// transaction_record_hash it could have carried. While the proxies stood, the
// unilateral level and the observed_party requirement did the excluding between
// them; relaxing both at once left the property unenforced.
// ---------------------------------------------------------------------------

/** A session whose responder holds a DID and a mandate but signed nothing. */
function mandateOnlySession(): [Session, Record<string, Dict>] {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markCompletedExternally(session);
  return [session, didDocuments];
}

/**
 * The default is senderDid=null, which is what the buyer actually emits.
 *
 * Both levels are admitted; the default is the a2cn-natural construction.
 *
 * A mandate-only counterparty holds a resolvable DID. Whether the record is
 * mixed or unilateral depends on how the producer projects the act, and BOTH
 * are honest: carrying the counterparty's verified DID on an act attributed
 * unsigned_observation gives two represented parties, so mixed — the default
 * here, and what an act arriving over the A2CN wire looks like; recording no
 * sender_did at all gives one, so unilateral, which today's buyer does by
 * construction. Admitting only one of them would make a producer choose its
 * classification over its evidence.
 */
function mandateOnlyRecord(
  senderDid: string | null = RESPONDER_DID,
): [Dict, Record<string, Dict>] {
  const [session, didDocuments] = mandateOnlySession();
  return [
    generateEvidenceWith(session, [observedQuote({ senderDid })], {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
    didDocuments,
  ];
}

test("a mandate-only COMPLETED record verifies", () => {
  const [record, didDocuments] = mandateOnlyRecord();

  // Preconditions, asserted rather than assumed: acceptance below means nothing
  // unless this really is the mandate-only shape.
  const responder = (record.parties as Dict).responder as Dict;
  expect(responder.did).toBe(RESPONDER_DID);
  expect(hasKey(responder, "identity_source")).toBe(false);
  expect((record.terminal as Dict).outcome).toBe(SessionState.COMPLETED);
  expect(record.transaction_record_hash).toBeNull();
  expect(record.external_commitment_reference).toStrictEqual(EXTERNAL_COMMITMENT_REFERENCE);

  expect(record.record_version).toBe("0.5");
  expect(record.evidence_level).toBe("mixed");
  expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
});

test("the counterparty act of a mandate-only record stays unsigned", () => {
  // No attribution inflation: a verified DID does not sign an act for its
  // holder. The identity verifies; the ACTS do not.
  const [record, didDocuments] = mandateOnlyRecord();

  const attributions = Object.fromEntries(
    (record.acts as Dict[]).map((entry) => [entry.message_type, entry.attribution]),
  );
  expect(attributions).toStrictEqual({
    offer: "verified_signature",
    counteroffer: "unsigned_observation",
  });
  expect(assessSessionEvidenceRecord(record, didDocuments)).toStrictEqual({
    valid: true,
    evidence_level: "mixed",
    verified_acts: 1,
    unsigned_acts: 1,
    invalid_acts: 0,
  });
});

test("a mandate-only completion whose counterparty act carries no DID is unilateral", () => {
  // The cross-product cell a mixed-only test would leave unexercised. A producer
  // may record the counterparty's act without a sender_did — an act observed
  // through a channel that carried no identity, which is what today's buyer
  // emits by construction. The classifier then counts one represented party,
  // not two, so the level is unilateral rather than mixed. The widening is
  // therefore load-bearing for a FULL-PARTY responder at unilateral too, not
  // merely carrying Tier 0 along.
  //
  // HISTORY, because a later reader will be tempted to narrow this again. A
  // narrower rule was drafted and briefly held: evidence_level unchanged at
  // unilateral, on the measured ground that today's buyer records counterparty
  // acts with no sender_did and so never produces mixed. THE MEASUREMENT WAS
  // CORRECT AND THE RULE BUILT ON IT WAS STILL WRONG. It would have obliged a
  // producer to omit a DID it had verified — to record less than it knows in
  // order to reach an admitted classification — which is the same defect, one
  // level up, that widening the responder condition removes. It would also have
  // pinned the spec to a producer behaviour already logged as an open item, so
  // the day that projection changed, every record that producer emitted would
  // have stopped being emittable.
  //
  // Admitting both levels is also the only option that does not silently settle
  // a separate question: whether an act's SENDER and its SIGNER should be the
  // same field at all. Attaching a DID to an act nobody signed really is
  // attribution inflation, and a missing sender_did really may be the honest
  // projection given no signature. The spec declines to force either.
  //
  // Its sibling above is the same shape with the DID present. The two together
  // pin that BOTH projections are admitted — neither alone distinguishes "this
  // level is what the producer happens to emit" from "this level is what the
  // rule requires".
  const [record, didDocuments] = mandateOnlyRecord(null);

  expect(((record.parties as Dict).responder as Dict).did).toBe(RESPONDER_DID);
  expect(record.evidence_level).toBe("unilateral");
  expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
});

test("the generator witnesses a mandate-only completion with the reference alone", () => {
  // The session's responder is DID-bearing, which before this change was the
  // generator's test for "completes with a TransactionRecord". That test was
  // wrong for this tier: a TransactionRecord needs the counterparty's signed
  // acceptance, which a mandate-only session does not have.
  const [session] = mandateOnlySession();
  expect(() => generateTransactionRecord(session)).toThrow();

  const [record] = mandateOnlyRecord();

  expect(record.transaction_record_hash).toBeNull();
  expect(hasKey(record, "external_commitment_reference")).toBe(true);
});

test("a mandate-only COMPLETED record carrying both witnesses is refused", () => {
  const [healthy, didDocuments] = mandateOnlyRecord();
  expect(verifySessionEvidenceRecord(healthy, didDocuments)).toBe(true);
  // The reseal helper must itself produce a verifiable record, or the refusal
  // below would prove only that resealing is broken.
  expect(verifySessionEvidenceRecord(reseal(structuredClone(healthy)), didDocuments)).toBe(true);

  const both = structuredClone(healthy);
  both.transaction_record_hash = "A".repeat(43);
  reseal(both);

  expect(both.transaction_record_hash).not.toBeNull();
  expect(hasKey(both, "external_commitment_reference")).toBe(true);
  expect(verifySessionEvidenceRecord(both, didDocuments)).toBe(false);
});

test("a mandate-only COMPLETED record carrying neither witness is refused", () => {
  const [healthy, didDocuments] = mandateOnlyRecord();

  const neither = structuredClone(healthy);
  delete neither.external_commitment_reference;
  reseal(neither);

  expect(neither.transaction_record_hash).toBeNull();
  expect(hasKey(neither, "external_commitment_reference")).toBe(false);
  expect(verifySessionEvidenceRecord(neither, didDocuments)).toBe(false);
});

test("a mandate-only completion with no producer-signed act is refused", () => {
  // mixed is admitted only alongside a producer-signed act. The relaxation
  // widens WHO the responder may be; it does not weaken what the producer must
  // have signed. With no signed act of its own the seal alone would carry the
  // COMPLETED claim.
  const [healthy, didDocuments] = mandateOnlyRecord();

  const actLess = structuredClone(healthy);
  actLess.acts = (actLess.acts as Dict[]).filter(
    (entry) => entry.attribution !== "verified_signature",
  );
  reseal(actLess);

  // The semantic precondition: this record really does carry acts, and none of
  // them is signed. An empty acts list would satisfy the rule vacuously.
  expect((actLess.acts as Dict[]).length).toBeGreaterThan(0);
  expect((actLess.acts as Dict[]).every((e) => e.attribution !== "verified_signature")).toBe(true);
  expect(verifySessionEvidenceRecord(actLess, didDocuments)).toBe(false);
});

test("stamping a verified_signature on an unsigned counterparty act is refused", () => {
  // The presence-versus-verification hazard, at the tier that invites it: a
  // mandate-only counterparty HAS a resolvable key, which is exactly what makes
  // this the place someone would relabel its unsigned act as verified.
  const [healthy, didDocuments] = mandateOnlyRecord();

  const inflated = structuredClone(healthy);
  const counterparty = (inflated.acts as Dict[]).find(
    (entry) => entry.attribution === "unsigned_observation",
  ) as Dict;
  counterparty.attribution = "verified_signature";
  reseal(inflated);

  expect(counterparty.signature).toBeNull();
  expect(verifySessionEvidenceRecord(inflated, didDocuments)).toBe(false);
});

// ---------------------------------------------------------------------------
// The property the relaxation had to start enforcing directly
//
// Widening the responder condition removed the two IDENTITY PROXIES —
// observed_party and unilateral — that had incidentally excluded a counterparty
// signature, and nothing took over the property they stood for: NO COUNTERPARTY
// SIGNATURE WITNESSES THE COMPLETION.
//
// That property is about the COMPLETION, not about every act. A counterparty that
// signed a counteroffer negotiated; it completed nothing, and no TransactionRecord
// exists for such a session (Section 9.3). What completes an A2CN session is an
// acceptance, so Section 9A.12 keys the rule on it: a verified acceptance is
// admitted only when the INITIATOR signed it and the responder signed no act at
// all. A completion both parties signed is a TransactionRecord, not an external
// witness.
//
// mixed is what made this load-bearing rather than theoretical.
// classifyEvidenceLevel returned bilateral only when NOTHING was unsigned, so a
// single unsigned observed act — which an external-channel flow carries by
// construction — demoted a fully signed session to mixed, which condition 3
// admits, and a counterparty's signed acceptance could ride in under an admitted
// classification. The classifier now never returns bilateral for a record
// carrying the reference, so the level cannot do the excluding at all: the
// acceptance rule is what does.
//
// The Python mirror is tests/test_mandate_only_completion.py.
// ---------------------------------------------------------------------------

const COUNTERPARTY_ENVELOPE = [
  "sequence_number",
  "round_number",
  "message_type",
  "message_id",
  "timestamp",
] as const;

/**
 * An observed counterparty act carrying no signature of any kind.
 *
 * The mandate-only projection: the responder's DID is recorded, because it
 * verifies, and the act is an unsigned observation, because nobody signed it.
 */
function unsignedCounterpartyAct(
  messageType: string,
  messageId: string,
  envelope: { sequenceNumber: number; roundNumber: number; timestamp: string },
): Dict {
  return {
    sequence_number: envelope.sequenceNumber,
    round_number: envelope.roundNumber,
    message_type: messageType,
    message_id: messageId,
    sender_did: RESPONDER_DID,
    timestamp: envelope.timestamp,
    source_protocol: "supplier_portal",
    act: {
      message_type: messageType,
      message_id: messageId,
      timestamp: envelope.timestamp,
    },
  };
}

const UNSIGNED_COUNTEROFFER = {
  messageType: "counteroffer",
  messageId: "counteroffer-1",
  envelope: { sequenceNumber: 2, roundNumber: 2, timestamp: "2026-03-24T10:02:00Z" },
};
const UNSIGNED_ACCEPTANCE = {
  messageType: "acceptance",
  messageId: "acceptance-1",
  envelope: { sequenceNumber: 2, roundNumber: 1, timestamp: "2026-03-24T10:03:00Z" },
};

/** The record this change admits, and its session, for one counterparty act type. */
function mandateOnlyPair(
  shape: typeof UNSIGNED_COUNTEROFFER,
): [Dict, Record<string, Dict>, Session] {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markCompletedExternally(session);
  const record = generateEvidenceWith(
    session,
    [
      unsignedCounterpartyAct(shape.messageType, shape.messageId, shape.envelope),
      orderConfirmation(),
    ],
    { externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE },
  );
  return [record, didDocuments, session];
}

/**
 * Replace the counterparty's unsigned observation with its real signed act.
 *
 * Hand-attached rather than generated, because the generator refuses to build
 * this record — which is the generator-leg assertion below, not a gap. What
 * lands here is the counterparty's genuine signature over its own envelope, so
 * the act VERIFIES; the tests assert that through invalid_acts, since a
 * signature that merely looked present would refuse the record at the act level
 * and prove nothing about the rule under test.
 *
 * evidence_level is deliberately left alone. reseal does not recompute it, so a
 * case whose level SHOULD change would be refused by the classifier-consistency
 * check instead of by the rule it names. Here it must not change: the record is
 * mixed with the counterparty's act unsigned and mixed with it signed, since
 * bilateral needs nothing unsigned and the order confirmation is. The tests
 * assert the level on both sides of the patch.
 */
function attachTheCounterpartySignature(
  record: Dict,
  message: Dict,
  signatureType: string,
): Dict {
  const entry = (record.acts as Dict[]).find(
    (item) => item.sender_did === RESPONDER_DID,
  ) as Dict;
  // Recorded as a record states an act: with the wire version it was signed under.
  const act = { protocol_version: PROTOCOL_ACT_VERSION, ...structuredClone(message) };
  entry.act = act;
  entry.act_hash = hashObject(act);
  entry.sender_verification_method = message.sender_verification_method;
  entry.signature_type = signatureType;
  entry.signature = message[signatureType];
  entry.attribution = "verified_signature";
  for (const field of COUNTERPARTY_ENVELOPE) {
    entry[field] = message[field];
  }
  return reseal(record);
}

function signedCounteroffer(sessionId: string): Dict {
  return makeOffer(sessionId, {
    senderDid: RESPONDER_DID,
    sequenceNumber: 2,
    roundNumber: 2,
    messageType: "counteroffer",
    messageId: "counteroffer-1",
    timestamp: "2026-03-24T10:02:00Z",
  });
}

test("a completion whose counterparty signed a counteroffer verifies as mixed", () => {
  // A signed negotiation that completes off-protocol is an honest mixed record.
  //
  // The initiator signed its offer, the responder signed a COUNTEROFFER, and the
  // order was confirmed outside A2CN. Both parties have authenticated negotiation
  // evidence; nobody signed the completion, whose only witness is the external
  // reference. No acceptance means no TransactionRecord exists at all
  // (Section 9.3), so the reference is not a weaker witness chosen over a
  // stronger one — it is the only one there is.
  //
  // The record is mixed, never bilateral: the completion is the producer's
  // account, not an act either party signed.
  //
  // Its twin is mandateOnlyPair unpatched: the same session, the same three acts,
  // the same reference, the same mixed level, and the counterparty's signature
  // the only difference. Both verify.
  const [honest, didDocuments, session] = mandateOnlyPair(UNSIGNED_COUNTEROFFER);
  expect(honest.evidence_level).toBe("mixed");
  expect(verifySessionEvidenceRecord(honest, didDocuments)).toBe(true);
  expect(() => generateTransactionRecord(session)).toThrow();

  const signed = attachTheCounterpartySignature(
    structuredClone(honest),
    signedCounteroffer(session.session_id),
    "protocol_act_signature",
  );

  const counterparty = (signed.acts as Dict[]).filter(
    (entry) =>
      entry.attribution === "verified_signature" &&
      entry.sender_did === ((signed.parties as Dict).responder as Dict).did,
  );
  expect(counterparty.map((entry) => entry.message_type)).toStrictEqual(["counteroffer"]);
  expect(((signed.parties as Dict).responder as Dict).did).toBe(RESPONDER_DID);
  expect(hasKey((signed.parties as Dict).responder, "identity_source")).toBe(false);
  expect((signed.terminal as Dict).outcome).toBe(SessionState.COMPLETED);
  expect(signed.transaction_record_hash).toBeNull();
  expect(signed.external_commitment_reference).toStrictEqual(EXTERNAL_COMMITMENT_REFERENCE);
  expect((signed.acts as Dict[]).every((entry) => entry.message_type !== "acceptance")).toBe(
    true,
  );
  expect(signed.evidence_level).toBe("mixed");
  expect(assessSessionEvidenceRecord(signed, didDocuments)).toStrictEqual({
    valid: true,
    evidence_level: "mixed",
    verified_acts: 2,
    unsigned_acts: 1,
    invalid_acts: 0,
  });
});

test("the generator emits a signed negotiation completing externally as mixed", () => {
  // The generator builds the same record from the counterparty's real signed act.
  // The signed counteroffer goes in as an observed act, which the generator
  // normalizes to verified_signature from the signature it carries, so this is
  // the ordinary act of recording a negotiation the counterparty signed.
  const [session, didDocuments] = mandateOnlySession();
  const record = generateEvidenceWith(session, signedNegotiation(session), {
    externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
  });

  expect(verifiedActs(record)).toStrictEqual([
    ["offer", INITIATOR_DID],
    ["counteroffer", RESPONDER_DID],
  ]);
  expect(record.evidence_level).toBe("mixed");
  expect(record.transaction_record_hash).toBeNull();
  expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
});

test("a completion whose counterparty signed the acceptance is refused", () => {
  // A responder-signed acceptance is a completion the counterparty signed.
  //
  // The acceptance is A2CN's completion act. A verified acceptance is admitted in
  // an external-channel record only when the INITIATOR signed it and the responder
  // signed no act; this one fails both halves, since the responder signed it and
  // so holds a verified act. The session-party check admits it — its signer is
  // parties.responder.did exactly — so the acceptance rule is the only one that
  // objects. This session does produce a TransactionRecord (Section 9.3): a
  // completion both parties signed belongs there, not behind an external
  // reference.
  const [honest, didDocuments, session] = mandateOnlyPair(UNSIGNED_ACCEPTANCE);
  expect(verifySessionEvidenceRecord(honest, didDocuments)).toBe(true);

  const offer = (honest.acts as Dict[]).find((entry) => entry.message_type === "offer")!
    .act as Dict;
  const signed = attachTheCounterpartySignature(
    structuredClone(honest),
    makeAcceptance(session.session_id, offer),
    "acceptance_signature",
  );

  const counterparty = (signed.acts as Dict[]).filter(
    (entry) =>
      entry.attribution === "verified_signature" && entry.sender_did === RESPONDER_DID,
  );
  expect(counterparty.map((entry) => entry.message_type)).toStrictEqual(["acceptance"]);
  // A session party, so the session-party check is not what refuses it.
  expect(counterparty[0].sender_did).toBe(((signed.parties as Dict).responder as Dict).did);
  expect(honest.evidence_level).toBe("mixed");
  expect(signed.evidence_level).toBe("mixed");
  expect(assessSessionEvidenceRecord(signed, didDocuments).invalid_acts).toBe(0);

  expect(verifySessionEvidenceRecord(signed, didDocuments)).toBe(false);
});

test("the generator refuses a completion whose counterparty signed the acceptance", () => {
  // The generator runs the same rule, so a producer cannot emit one either. The
  // assertion matches the message, which names the rule: a signed acceptance is
  // admitted only from the initiator, and only while the responder signed
  // nothing. The message is part of the contract, which is why a test asserts on
  // it at all.
  const [manager, session] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  markCompletedExternally(session);

  expect(() =>
    generateEvidenceWith(
      session,
      [makeAcceptance(session.session_id, offer), orderConfirmation()],
      { externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE },
    ),
  ).toThrow(/admits a signed acceptance only/);
  // The control: the same call with the signature stripped SUCCEEDS, so the
  // refusal above is the signature's doing and not the observed act's.
  expect(
    generateEvidenceWith(
      session,
      [
        unsignedCounterpartyAct(
          UNSIGNED_ACCEPTANCE.messageType,
          UNSIGNED_ACCEPTANCE.messageId,
          UNSIGNED_ACCEPTANCE.envelope,
        ),
        orderConfirmation(),
      ],
      { externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE },
    ),
  ).toBeTruthy();
});

test("a counterparty signature cannot hide behind an unsigned label", () => {
  // The premise the rule above rests on, guarded rather than assumed. That rule
  // is keyed on attribution, so it would be bypassable if an act could carry an
  // A2CN signature while calling itself an unsigned observation. It cannot:
  // verifyEvidenceAct refuses an unsigned_observation whose complete act still
  // holds any of the four signature fields, and counts the act INVALID.
  // Pre-existing behaviour, pinned here because the new rule's completeness now
  // depends on it.
  //
  // Arm two is the honest shape the same edit produces once the signature really
  // is gone, and arm three is Section 9A.12's deliberate exception: a transport
  // signature the producer merely observed belongs inside the observed act, is
  // recorded as observed rather than verified, and must NOT be read as a
  // counterparty signature.
  const [honest, didDocuments, session] = mandateOnlyPair(UNSIGNED_COUNTEROFFER);
  const signed = attachTheCounterpartySignature(
    structuredClone(honest),
    signedCounteroffer(session.session_id),
    "protocol_act_signature",
  );

  // Arm one: relabelled as unsigned, entry-level fields nulled exactly as
  // Section 9A.3 demands — and the inner act keeps its real signature.
  const hidden = structuredClone(signed);
  const counterparty = (hidden.acts as Dict[]).find(
    (entry) => entry.sender_did === RESPONDER_DID,
  ) as Dict;
  counterparty.attribution = "unsigned_observation";
  counterparty.signature = null;
  counterparty.signature_type = null;
  counterparty.sender_verification_method = null;
  reseal(hidden);

  expect((counterparty.act as Dict).protocol_act_signature).toBeTruthy();
  expect(assessSessionEvidenceRecord(hidden, didDocuments).invalid_acts).toBe(1);
  expect(verifySessionEvidenceRecord(hidden, didDocuments)).toBe(false);

  // Arm two: strip the A2CN signature fields and the act is genuinely unsigned,
  // so the record is the honest mandate-only shape again.
  const stripped = structuredClone(hidden);
  const unsigned = (stripped.acts as Dict[]).find(
    (entry) => entry.sender_did === RESPONDER_DID,
  ) as Dict;
  for (const field of [
    "protocol_act_signature",
    "protocol_act_hash",
    "sender_verification_method",
  ]) {
    delete (unsigned.act as Dict)[field];
  }
  unsigned.act_hash = hashObject(unsigned.act as Dict);
  reseal(stripped);

  expect(assessSessionEvidenceRecord(stripped, didDocuments).invalid_acts).toBe(0);
  expect(verifySessionEvidenceRecord(stripped, didDocuments)).toBe(true);

  // Arm three: a non-A2CN signature the producer observed. Section 9A.12 puts it
  // here on purpose, so it changes nothing.
  const transport = structuredClone(stripped);
  const observed = (transport.acts as Dict[]).find(
    (entry) => entry.sender_did === RESPONDER_DID,
  ) as Dict;
  (observed.act as Dict).x_transport_signature = "opaque-bytes-the-producer-observed";
  observed.act_hash = hashObject(observed.act as Dict);
  reseal(transport);

  expect(observed.attribution).toBe("unsigned_observation");
  expect(verifySessionEvidenceRecord(transport, didDocuments)).toBe(true);
});

// ---------------------------------------------------------------------------
// Session parties only: every verified act in an external-channel record is
// signed by parties.initiator.did or parties.responder.did, compared exactly
//
// Section 9A.8 rule 1 already refuses a verified act "that cannot be placed in a
// known role" for an observed_party responder. The same holds for every
// external-channel record: a verified act from a DID that is neither party is
// refused, whatever the responder's identity tier. The comparison is exact string
// equality with no DID normalization, so a DID URL naming a party's own key is
// not that party's DID and is refused too.
//
// The Python mirror is tests/test_mandate_only_completion.py.
// ---------------------------------------------------------------------------

/**
 * The evidence entry the generator builds for a flat signed message.
 *
 * Hand-built because the generator now REFUSES these records, which is the
 * generator-leg assertion below rather than a gap. Validated against the
 * generator's own output: for the same message object this reproduces its entry
 * exactly, act_hash included. The message object must be REUSED rather than
 * rebuilt — the third party's key is ES256, whose signatures are randomised, so a
 * second call would differ in signature, act and act_hash at once.
 */
function signedEntry(message: Dict, signatureType: string): Dict {
  // The generator records every act with the wire version it was signed under.
  const act: Dict = { protocol_version: PROTOCOL_ACT_VERSION, ...structuredClone(message) };
  return {
    sequence_number: act.sequence_number ?? null,
    round_number: act.round_number ?? null,
    message_type: act.message_type,
    message_id: act.message_id ?? null,
    sender_did: act.sender_did,
    timestamp: act.timestamp ?? null,
    source_protocol: act.source_protocol ?? null,
    act,
    act_hash: hashObject(act),
    sender_verification_method: act.sender_verification_method,
    signature_type: signatureType,
    signature: act[signatureType],
    attribution: "verified_signature",
  };
}

/**
 * Append one act and reseal, leaving evidence_level alone.
 *
 * The level must not move, or the classifier-consistency check would refuse the
 * record instead of the rule under test. It does not: the classifier counts only
 * session parties, so an act from a non-party changes neither the represented nor
 * the verified set, and a responder act spelled as a DID URL is not the
 * responder's DID either. Both are asserted at each call site.
 */
function withExtraAct(record: Dict, entry: Dict): Dict {
  const appended = structuredClone(record);
  appended.acts = [...(appended.acts as Dict[]), structuredClone(entry)];
  return reseal(appended);
}

/** A mandate-only session whose resolver also knows a non-party DID. */
function thirdPartyResolvingSession(): [Session, Record<string, Dict>] {
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markCompletedExternally(session);
  // The third party's DID must RESOLVE, or its act would be refused as invalid
  // and the refusal would say nothing about the rule under test.
  didDocuments[THIRD_PARTY_DID] = makeDidDocument(
    THIRD_PARTY_DID,
    "key-1",
    publicKeyToJwk(THIRD_PARTY_PUBLIC_KEY),
  );
  return [session, didDocuments];
}

function mandateOnlyWithReference(session: Session): Dict {
  return generateEvidenceWith(session, [observedQuote({ senderDid: RESPONDER_DID })], {
    externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
  });
}

test("a completion carrying a third-party signature is refused", () => {
  // A verified act that is nobody's role in the session (Section 9A.8 rule 1).
  //
  // THE ACT MUST BE GENUINELY SIGNED, AND THAT IS EASY TO GET WRONG HERE. The
  // cheap way to write this test is to take an unsigned observation and relabel its
  // sender_did to an unrelated DID. That does NOT exercise this rule: the act stays
  // unsigned_observation, no DID is ever resolved, invalid_acts stays 0, and what
  // refuses the record is the evidence_level recomputation, because dropping the
  // responder from the represented set makes a claimed mixed disagree with the
  // computed unilateral. The record is refused, so such a test PASSES, while saying
  // nothing about the signer.
  //
  // So this builds a REAL signature from a DID that is neither party, which
  // RESOLVES and VERIFIES, and asserts invalid_acts === 0 and an unchanged level to
  // rule both alternatives out. Do not simplify it back.
  const [session, didDocuments] = thirdPartyResolvingSession();
  const honest = mandateOnlyWithReference(session);
  expect(verifySessionEvidenceRecord(honest, didDocuments)).toBe(true);

  const thirdPartyMessage = thirdPartyOffer(session.session_id);
  const signed = withExtraAct(honest, signedEntry(thirdPartyMessage, "protocol_act_signature"));

  // Preconditions. The signature is real and VERIFIES, so nothing is refused at
  // the act level; and the level is unchanged, so the classifier-consistency check
  // is satisfied. Whatever refuses this record refuses it for the signer.
  const entry = (signed.acts as Dict[])[(signed.acts as Dict[]).length - 1];
  expect(entry.attribution).toBe("verified_signature");
  expect(entry.signature).toBeTruthy();
  expect(entry.sender_did).toBe(THIRD_PARTY_DID);
  expect([
    ((signed.parties as Dict).initiator as Dict).did,
    ((signed.parties as Dict).responder as Dict).did,
  ]).not.toContain(entry.sender_did);
  expect(honest.evidence_level).toBe("mixed");
  expect(signed.evidence_level).toBe("mixed");
  expect(assessSessionEvidenceRecord(signed, didDocuments)).toStrictEqual({
    valid: false,
    evidence_level: "mixed",
    verified_acts: 2,
    unsigned_acts: 1,
    invalid_acts: 0,
  });

  expect(verifySessionEvidenceRecord(signed, didDocuments)).toBe(false);
});

test("the generator refuses a completion carrying a third-party signature", () => {
  const [session] = thirdPartyResolvingSession();
  const observed = [observedQuote({ senderDid: RESPONDER_DID })];

  expect(() =>
    generateEvidenceWith(session, [...observed, thirdPartyOffer(session.session_id)], {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/session party/);
  // The control: the same call without the third party's act SUCCEEDS, so the
  // refusal above is that act's doing and not the observed quote's.
  expect(
    generateEvidenceWith(session, observed, {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toBeTruthy();
});

/** The responder's real acceptance, with sender_did spelled as given. */
function acceptanceSignedAs(sessionId: string, offer: Dict, senderDid: string): Dict {
  const acceptance: Dict = {
    message_type: "acceptance",
    message_id: "acceptance-1",
    session_id: sessionId,
    in_reply_to: offer.message_id,
    round_number: offer.round_number,
    sequence_number: 3,
    accepted_offer_id: offer.message_id,
    accepted_protocol_act_hash: offer.protocol_act_hash,
    sender_did: senderDid,
    sender_agent_id: "seller-agent",
    sender_verification_method: RESPONDER_VM,
    timestamp: "2026-03-24T10:03:00Z",
  };
  acceptance.acceptance_signature = signJws(
    signedActHash(acceptance, { versionWhenAbsent: PROTOCOL_ACT_VERSION }) as string,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
  );
  return acceptance;
}

/**
 * Resolve the base DID of a DID URL, as W3C DID URL dereferencing does.
 *
 * Not a broken resolver: it is what the resolver the JavaScript ecosystem uses
 * does when handed a DID URL, and Section 9A.6 imposes no syntax on sender_did.
 * The resolver is the CALLER'S, which is why a rule comparing sender_did to one
 * DID by string equality cannot carry the property.
 */
function dereferencingResolver(didDocuments: Record<string, Dict>): (did: string) => Dict {
  return (did: string) => didDocuments[did.split("#")[0].split("?")[0]];
}

/** The responder's real signed counteroffer, with sender_did spelled as given. */
function responderCounterofferSpelledAs(sessionId: string, senderDid: string): Dict {
  return makeOffer(sessionId, {
    senderDid,
    sequenceNumber: 3,
    roundNumber: 2,
    messageType: "counteroffer",
    messageId: "counteroffer-spelled",
    timestamp: "2026-03-24T10:03:00Z",
  });
}

test("a responder signature spelled as a DID URL is refused", () => {
  // The responder signs a counteroffer and the producer writes sender_did as
  // did:web:acme-corp.com#key-2026-01 rather than did:web:acme-corp.com. Same key,
  // same party, same signature; only the spelling differs.
  // verificationMethodControlledBy accepts it because the method equals the sender
  // string, so the signature VERIFIES — and the string is neither
  // parties.initiator.did nor parties.responder.did, so the session-party check
  // refuses it. No DID is normalized.
  //
  // A COUNTEROFFER on purpose. A signed counteroffer by a session party is
  // admitted, so the bare spelling below VERIFIES and the spelling is the only
  // variable between the two arms. An acceptance would be refused under both
  // spellings by the acceptance rule, which would leave this refusal with two
  // causes; that case is the next test.
  //
  // UNDER A DEREFERENCING RESOLVER ON PURPOSE. Under an exact-match resolver the
  // DID URL does not resolve, the act is INVALID, and the record is refused for a
  // reason that says nothing about the rule. Arm one asserts invalid_acts is 0 to
  // rule that out, and arm two holds the resolver fixed while changing only the
  // spelling.
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markCompletedExternally(session);
  const resolver = dereferencingResolver(didDocuments);
  const honest = mandateOnlyWithReference(session);
  expect(verifySessionEvidenceRecord(honest, resolver)).toBe(true);

  const urlSigned = withExtraAct(
    honest,
    signedEntry(
      responderCounterofferSpelledAs(session.session_id, RESPONDER_VM),
      "protocol_act_signature",
    ),
  );

  const entry = (urlSigned.acts as Dict[])[(urlSigned.acts as Dict[]).length - 1];
  expect(entry.sender_did).toBe(RESPONDER_VM);
  expect([INITIATOR_DID, RESPONDER_DID]).not.toContain(entry.sender_did);
  expect(urlSigned.evidence_level).toBe("mixed");
  expect(honest.evidence_level).toBe("mixed");
  const assessment = assessSessionEvidenceRecord(urlSigned, resolver);
  expect(assessment.invalid_acts).toBe(0);
  expect(assessment.verified_acts).toBe(2);

  expect(verifySessionEvidenceRecord(urlSigned, resolver)).toBe(false);

  // Arm two, resolver held fixed: the bare spelling is the responder's own DID,
  // so the same counteroffer is a session party's negotiation act and VERIFIES.
  const bareSigned = withExtraAct(
    honest,
    signedEntry(
      responderCounterofferSpelledAs(session.session_id, RESPONDER_DID),
      "protocol_act_signature",
    ),
  );
  expect(bareSigned.evidence_level).toBe("mixed");
  expect(verifySessionEvidenceRecord(bareSigned, resolver)).toBe(true);
});

test("a responder acceptance is refused under either spelling", () => {
  // A signed acceptance by the responder never rides in, however it is written.
  // The bare spelling is parties.responder.did, which the session-party check
  // admits, and the acceptance rule refuses it. The DID-URL spelling is refused by
  // both. Either way the verdict does not turn on how the DID is written.
  const [manager, session, didDocuments] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  markCompletedExternally(session);
  const resolver = dereferencingResolver(didDocuments);
  const honest = mandateOnlyWithReference(session);
  expect(verifySessionEvidenceRecord(honest, resolver)).toBe(true);

  for (const senderDid of [RESPONDER_VM, RESPONDER_DID]) {
    const signed = withExtraAct(
      honest,
      signedEntry(acceptanceSignedAs(session.session_id, offer, senderDid), "acceptance_signature"),
    );
    expect((signed.acts as Dict[])[(signed.acts as Dict[]).length - 1].sender_did).toBe(
      senderDid,
    );
    expect(assessSessionEvidenceRecord(signed, resolver).invalid_acts).toBe(0);
    expect(verifySessionEvidenceRecord(signed, resolver)).toBe(false);
  }
});

/** A SECOND act of the INITIATOR's own, sender_did spelled as given. */
function initiatorActSpelledAs(sessionId: string, senderDid: string): Dict {
  const verificationMethod = senderDid.includes("#") ? senderDid : INITIATOR_VM;
  const act: Dict = {
    protocol_version: PROTOCOL_ACT_VERSION,
    session_id: sessionId,
    round_number: 1,
    sequence_number: 4,
    message_type: "offer",
    sender_did: senderDid,
    timestamp: "2026-03-24T10:04:00Z",
    expires_at: "2030-01-01T00:00:00Z",
    terms: { total_value: 9_400_000, currency: "USD" },
  };
  const actHash = hashObject(act);
  return {
    ...act,
    message_id: "initiator-revision-1",
    sender_verification_method: verificationMethod,
    source_protocol: "a2cn",
    protocol_act_hash: actHash,
    protocol_act_signature: signJws(actHash, INITIATOR_PRIVATE_KEY, verificationMethod),
  };
}

test("the initiator signing under two spellings of its own did is refused", () => {
  // The comparison is EXACT, and that is the ruled behaviour, not an oversight.
  //
  // The initiator signs twice: once with sender_did equal to
  // parties.initiator.did, once under its own DID URL. Both signatures are genuine
  // and both verify under a resolver that dereferences DID URLs, and condition 6 is
  // satisfied by the bare-DID act — so this rule is the only thing that objects, and
  // the record is REFUSED.
  //
  // DELIBERATE AND RULED. The rule compares sender_did to the session parties' DIDs
  // by exact string equality and performs no DID normalization. That is the same
  // property that makes it proof against the evasion the sibling test above pins:
  // once a verifier treats a DID URL as equal to its base DID, whether a record is
  // admitted depends on how the caller's resolver behaves rather than on the record.
  // Section 9A.12 imposes no syntax on sender_did, so the fail-closed direction is
  // the safe one — a producer that wants this act counted writes the DID the record
  // already names. This is the cost side of that choice, pinned here so it cannot be
  // "fixed" by adding normalization without the ruling being revisited.
  //
  // NOT to be confused with the initiator's ONLY act being spelled as a DID URL.
  // That record is refused by condition 6 — no act carries the initiator's did at
  // all — and was refused before this rule existed, so it pins nothing about this
  // one. Here the bare-DID act is asserted present precisely to rule that out.
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markCompletedExternally(session);
  const resolver = dereferencingResolver(didDocuments);
  const honest = mandateOnlyWithReference(session);
  expect(verifySessionEvidenceRecord(honest, resolver)).toBe(true);

  const twoSpellings = withExtraAct(
    honest,
    signedEntry(
      initiatorActSpelledAs(session.session_id, INITIATOR_VM),
      "protocol_act_signature",
    ),
  );

  // Preconditions, all asserted before the verdict.
  const entry = (twoSpellings.acts as Dict[])[(twoSpellings.acts as Dict[]).length - 1];
  expect(entry.sender_did).toBe(INITIATOR_VM);
  expect(entry.sender_did).not.toBe(INITIATOR_DID);
  // Condition 6 holds: an act DOES carry parties.initiator.did exactly.
  expect(
    (twoSpellings.acts as Dict[]).some(
      (item) =>
        item.attribution === "verified_signature" &&
        item.sender_did === ((twoSpellings.parties as Dict).initiator as Dict).did,
    ),
  ).toBe(true);
  // The level is coherent on both sides of the patch: a DID URL is not a party DID,
  // so the classifier counts neither a new represented nor a new verified party.
  expect(honest.evidence_level).toBe("mixed");
  expect(twoSpellings.evidence_level).toBe("mixed");
  // Both signatures verify: nothing is refused at the act level.
  const assessment = assessSessionEvidenceRecord(twoSpellings, resolver);
  expect(assessment.invalid_acts).toBe(0);
  expect(assessment.verified_acts).toBe(2);

  expect(verifySessionEvidenceRecord(twoSpellings, resolver)).toBe(false);
});

// ---------------------------------------------------------------------------
// The acceptance rule: a completion both parties signed is a TransactionRecord
//
// The acceptance is A2CN's completion act. In a record carrying
// external_commitment_reference, a verified acceptance is admitted only when its
// signer is the INITIATOR, by exact DID, and the RESPONDER has no verified act in
// the record. Refused when a verified acceptance is present and either
//
//   (i)  its signer is not parties.initiator.did, or
//   (ii) parties.responder has any verified act.
//
// What it admits is the shape an external channel actually produces: the
// initiator signs its own acceptance of terms it observed, and the counterparty
// confirms the order outside A2CN. What it refuses is any record from which a
// bilateral completion could be assembled — the counterparty signing the
// acceptance, or the initiator signing an acceptance while the counterparty's
// signatures sit beside it. An UNSIGNED acceptance is not a signature and
// witnesses nothing, so it is admitted.
//
// Each refusal below has a twin that differs from it in ONE signature and
// VERIFIES, so the refusal is that signature's doing and nothing else's. The
// predicate is module-private in TypeScript, so the "rule switched off, the same
// bytes verify" half is shown by mutation rather than in the suite.
// ---------------------------------------------------------------------------

/**
 * The responder's real signed counteroffer, then between, then the confirmation.
 *
 * Observed acts for a mandateOnlySession, whose initiator has already signed its
 * offer; the caller generates.
 */
function signedNegotiation(
  session: Session,
  between: Dict[] = [],
  confirmation = true,
): Dict[] {
  const observed = [signedCounteroffer(session.session_id), ...between];
  if (confirmation) {
    observed.push(orderConfirmation());
  }
  return observed;
}

type Signer = "initiator" | "responder" | "third_party";

/** A real acceptance of the act named, signed per Section 7.3.1 by signer. */
function acceptanceBy(
  sessionId: string,
  options: {
    acceptedId: string;
    acceptedHash: string;
    roundNumber: number;
    sequenceNumber?: number;
    timestamp?: string;
    messageId?: string;
    signer?: Signer;
  },
): Dict {
  const {
    acceptedId,
    acceptedHash,
    roundNumber,
    sequenceNumber = 3,
    timestamp = "2026-03-24T10:03:00Z",
    messageId = "acceptance-2",
    signer = "initiator",
  } = options;
  const [senderDid, verificationMethod, privateKey, agentId] = {
    initiator: [INITIATOR_DID, INITIATOR_VM, INITIATOR_PRIVATE_KEY, "buyer-agent"],
    responder: [RESPONDER_DID, RESPONDER_VM, RESPONDER_PRIVATE_KEY, "seller-agent"],
    third_party: [THIRD_PARTY_DID, THIRD_PARTY_VM, THIRD_PARTY_PRIVATE_KEY, "processor-agent"],
  }[signer] as [string, string, typeof INITIATOR_PRIVATE_KEY, string];
  const acceptance: Dict = {
    message_type: "acceptance",
    message_id: messageId,
    session_id: sessionId,
    in_reply_to: acceptedId,
    round_number: roundNumber,
    sequence_number: sequenceNumber,
    accepted_offer_id: acceptedId,
    accepted_protocol_act_hash: acceptedHash,
    sender_did: senderDid,
    sender_agent_id: agentId,
    sender_verification_method: verificationMethod,
    timestamp,
  };
  acceptance.acceptance_signature = signJws(
    signedActHash(acceptance, { versionWhenAbsent: PROTOCOL_ACT_VERSION }) as string,
    privateKey,
    verificationMethod,
  );
  return acceptance;
}

/** The same act as an unsigned observation: its envelope, and no signature. */
function unsignedObservationOf(message: Dict): Dict {
  const entry: Dict = {};
  for (const field of COUNTERPARTY_ENVELOPE) {
    entry[field] = message[field];
  }
  return {
    ...entry,
    sender_did: message.sender_did,
    source_protocol: "supplier_portal",
    act: {
      message_type: message.message_type,
      message_id: message.message_id,
      timestamp: message.timestamp,
    },
  };
}

/**
 * Replace the unsigned observation of message with message itself, signed.
 *
 * The twin of each refusal below is generated with the act unsigned; this swaps
 * in the real signature at the same position, so ordering, envelope and level
 * are untouched and the signature is the only difference.
 */
function signObservedAct(record: Dict, message: Dict, signatureType: string): Dict {
  const patched = structuredClone(record);
  const entry = (patched.acts as Dict[]).find(
    (item) => item.message_id === message.message_id,
  ) as Dict;
  const act = { protocol_version: PROTOCOL_ACT_VERSION, ...structuredClone(message) };
  entry.act = act;
  entry.act_hash = hashObject(act);
  entry.sender_verification_method = message.sender_verification_method;
  entry.signature_type = signatureType;
  entry.signature = message[signatureType];
  entry.attribution = "verified_signature";
  return reseal(patched);
}

function verifiedActs(record: Dict): [unknown, unknown][] {
  return (record.acts as Dict[])
    .filter((entry) => entry.attribution === "verified_signature")
    .map((entry) => [entry.message_type, entry.sender_did]);
}

function counterofferAcceptance(sessionId: string, signer: Signer): Dict {
  const counteroffer = signedCounteroffer(sessionId);
  return acceptanceBy(sessionId, {
    acceptedId: counteroffer.message_id as string,
    acceptedHash: counteroffer.protocol_act_hash as string,
    roundNumber: counteroffer.round_number as number,
    signer,
  });
}

test("the responder's signed acceptance after a signed negotiation is refused", () => {
  // A counterparty-signed acceptance cannot ride in behind a signed negotiation.
  //
  // The responder signed a counteroffer, and then signed an acceptance. Both are
  // session-party acts, so the session-party check admits them; the classifier
  // gives mixed, which condition 3 admits; and the reference is the only witness,
  // which the exactly-one-witness rule admits. The acceptance rule is the only
  // thing that objects, and both of its clauses do.
  //
  // The twin is the same record with the acceptance UNSIGNED — an observation
  // witnesses nothing — and it verifies.
  const [session, didDocuments] = mandateOnlySession();
  const acceptance = counterofferAcceptance(session.session_id, "responder");
  // The responder accepting its own counteroffer is not a coherent negotiation,
  // and does not need to be: the rule judges who signed an acceptance, not what
  // it accepted, and any accepted act gives the same verdict.
  const twin = generateEvidenceWith(
    session,
    signedNegotiation(session, [unsignedObservationOf(acceptance)]),
    { externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE },
  );
  expect(twin.evidence_level).toBe("mixed");
  expect(verifySessionEvidenceRecord(twin, didDocuments)).toBe(true);

  const signed = signObservedAct(twin, acceptance, "acceptance_signature");

  expect(verifiedActs(signed)).toStrictEqual([
    ["offer", INITIATOR_DID],
    ["counteroffer", RESPONDER_DID],
    ["acceptance", RESPONDER_DID],
  ]);
  expect(signed.evidence_level).toBe("mixed");
  expect(assessSessionEvidenceRecord(signed, didDocuments).invalid_acts).toBe(0);
  expect(verifySessionEvidenceRecord(signed, didDocuments)).toBe(false);

  expect(() =>
    generateEvidenceWith(
      session,
      [signedCounteroffer(session.session_id), acceptance, orderConfirmation()],
      { externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE },
    ),
  ).toThrow(/admits a signed acceptance only/);
});

test("the initiator's signed acceptance of a signed counteroffer is refused", () => {
  // Clause (ii): the initiator accepting what the counterparty SIGNED.
  //
  // The signer is the initiator, so clause (i) holds. But the counterparty signed
  // the counteroffer being accepted, so both parties have signed the agreement:
  // that is a TransactionRecord, not an external witness, and clause (ii) refuses
  // it because the responder holds a verified act.
  //
  // The twin differs in ONE signature, the counteroffer's: with the counteroffer
  // unsigned the same initiator-signed acceptance VERIFIES, which is the shape an
  // external channel produces. So the counterparty's signature is the cause.
  const [session, didDocuments] = mandateOnlySession();
  const acceptance = counterofferAcceptance(session.session_id, "initiator");
  const counteroffer = signedCounteroffer(session.session_id);

  const twin = generateEvidenceWith(
    session,
    [
      unsignedCounterpartyAct(
        UNSIGNED_COUNTEROFFER.messageType,
        UNSIGNED_COUNTEROFFER.messageId,
        UNSIGNED_COUNTEROFFER.envelope,
      ),
      acceptance,
      orderConfirmation(),
    ],
    { externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE },
  );
  expect(verifiedActs(twin)).toStrictEqual([
    ["offer", INITIATOR_DID],
    ["acceptance", INITIATOR_DID],
  ]);
  expect(verifySessionEvidenceRecord(twin, didDocuments)).toBe(true);

  const signed = signObservedAct(twin, counteroffer, "protocol_act_signature");

  expect(verifiedActs(signed)).toStrictEqual([
    ["offer", INITIATOR_DID],
    ["counteroffer", RESPONDER_DID],
    ["acceptance", INITIATOR_DID],
  ]);
  expect(twin.evidence_level).toBe("mixed");
  expect(signed.evidence_level).toBe("mixed");
  expect(assessSessionEvidenceRecord(signed, didDocuments).invalid_acts).toBe(0);
  expect(verifySessionEvidenceRecord(signed, didDocuments)).toBe(false);

  expect(() =>
    generateEvidenceWith(session, [counteroffer, acceptance, orderConfirmation()], {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/admits a signed acceptance only/);
});

test("the initiator's acceptance after any responder signature is refused", () => {
  // Clause (ii) at its boundary: fail-closed, and deliberately stricter than
  // needed.
  //
  // The responder signed an EARLIER counteroffer; the initiator then accepted a
  // LATER offer of the responder's that is unsigned. Strictly, nobody signed both
  // halves of the agreement accepted here, so no TransactionRecord could be
  // assembled from it. The rule refuses it anyway: clause (ii) asks whether the
  // responder holds ANY verified act, not whether it signed the act accepted.
  // Tracing which act an acceptance accepts would make admission depend on
  // reference-chasing a producer controls; refusing whenever both a signed
  // acceptance and a counterparty signature are present does not. Such a session
  // completes on the TransactionRecord path or records its acceptance unsigned.
  //
  // The twin differs in ONE signature, the earlier counteroffer's, and verifies.
  const [session, didDocuments] = mandateOnlySession();
  const laterOffer = unsignedCounterpartyAct("counteroffer", "counteroffer-2", {
    sequenceNumber: 3,
    roundNumber: 3,
    timestamp: "2026-03-24T10:03:00Z",
  });
  const acceptance = acceptanceBy(session.session_id, {
    acceptedId: "counteroffer-2",
    acceptedHash: hashObject(laterOffer.act),
    roundNumber: 3,
    sequenceNumber: 4,
    timestamp: "2026-03-24T10:04:00Z",
  });
  const counteroffer = signedCounteroffer(session.session_id);

  const twin = generateEvidenceWith(
    session,
    [
      unsignedCounterpartyAct(
        UNSIGNED_COUNTEROFFER.messageType,
        UNSIGNED_COUNTEROFFER.messageId,
        UNSIGNED_COUNTEROFFER.envelope,
      ),
      laterOffer,
      acceptance,
      orderConfirmation(),
    ],
    { externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE },
  );
  expect(verifySessionEvidenceRecord(twin, didDocuments)).toBe(true);

  const signed = signObservedAct(twin, counteroffer, "protocol_act_signature");

  const later = (signed.acts as Dict[]).find((entry) => entry.message_id === "counteroffer-2")!;
  expect(later.attribution).toBe("unsigned_observation");
  expect(verifiedActs(signed)).toStrictEqual([
    ["offer", INITIATOR_DID],
    ["counteroffer", RESPONDER_DID],
    ["acceptance", INITIATOR_DID],
  ]);
  expect(twin.evidence_level).toBe("mixed");
  expect(signed.evidence_level).toBe("mixed");
  expect(assessSessionEvidenceRecord(signed, didDocuments).invalid_acts).toBe(0);
  expect(verifySessionEvidenceRecord(signed, didDocuments)).toBe(false);
});

test("a third-party signed acceptance is refused", () => {
  // An acceptance signed by a DID that is neither party. Refused by the
  // session-party check, and by clause (i) as well, since its signer is not the
  // initiator. The twin is the same acceptance signed by the INITIATOR, with
  // nothing of the responder's signed, and it verifies.
  const [session, didDocuments] = thirdPartyResolvingSession();
  const quote = observedQuote({ senderDid: RESPONDER_DID });
  const accepted = {
    acceptedId: quote.message_id as string,
    acceptedHash: hashObject(quote.act),
    roundNumber: quote.round_number as number,
  };
  const byInitiator = generateEvidenceWith(
    session,
    [quote, acceptanceBy(session.session_id, { ...accepted, signer: "initiator" })],
    { externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE },
  );
  expect(verifySessionEvidenceRecord(byInitiator, didDocuments)).toBe(true);

  const thirdPartyAcceptance = acceptanceBy(session.session_id, {
    ...accepted,
    signer: "third_party",
  });
  const signed = signObservedAct(
    generateEvidenceWith(session, [quote, unsignedObservationOf(thirdPartyAcceptance)], {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
    thirdPartyAcceptance,
    "acceptance_signature",
  );

  const entry = (signed.acts as Dict[]).find((item) => item.message_type === "acceptance")!;
  expect(entry.attribution).toBe("verified_signature");
  expect(entry.sender_did).toBe(THIRD_PARTY_DID);
  expect(assessSessionEvidenceRecord(signed, didDocuments).invalid_acts).toBe(0);
  expect(verifySessionEvidenceRecord(signed, didDocuments)).toBe(false);

  expect(() =>
    generateEvidenceWith(session, [quote, thirdPartyAcceptance], {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/session party/);
});

test("an unsigned acceptance is admitted in an external-channel record", () => {
  // An observation witnesses nothing, so the acceptance rule does not reach it.
  // Two shapes: the responder's unsigned acceptance after a signed negotiation,
  // and after an unsigned one. Both verify, and both are mixed.
  const [session, didDocuments] = mandateOnlySession();
  const acceptance = counterofferAcceptance(session.session_id, "responder");
  const afterSigned = generateEvidenceWith(
    session,
    signedNegotiation(session, [unsignedObservationOf(acceptance)]),
    { externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE },
  );
  const observedAcceptance = (afterSigned.acts as Dict[]).find(
    (entry) => entry.message_type === "acceptance",
  )!;
  expect(observedAcceptance.attribution).toBe("unsigned_observation");
  expect(observedAcceptance.sender_did).toBe(RESPONDER_DID);
  expect(afterSigned.evidence_level).toBe("mixed");
  expect(verifySessionEvidenceRecord(afterSigned, didDocuments)).toBe(true);

  const [afterUnsigned, unsignedDidDocuments] = mandateOnlyPair(UNSIGNED_ACCEPTANCE);
  expect(afterUnsigned.evidence_level).toBe("mixed");
  expect(verifySessionEvidenceRecord(afterUnsigned, unsignedDidDocuments)).toBe(true);
});

for (const responder of ["observed_party", "did_bearing"] as const) {
  for (const path of ["negotiated", "after_the_fact"] as const) {
    test(`the initiator's acceptance of an observed offer verifies [${path}-${responder}]`, () => {
      // The shape an external channel produces, admitted at both responder tiers.
      //
      // The initiator signs its own acceptance of the counterparty's offer, which
      // it OBSERVED — the counterparty signed nothing — and the order is confirmed
      // outside A2CN. negotiated carries the initiator's signed offer before it;
      // after_the_fact carries the acceptance alone, as a producer does that
      // records a commitment after the fact. The acceptance's signer is the
      // initiator and the responder holds no verified act, so the acceptance rule
      // admits it; nothing in it is the counterparty's signature, so the record is
      // unilateral.
      const [manager, session, didDocuments] =
        responder === "observed_party" ? makeIdentityLightSession() : makeSession();
      if (path === "negotiated") {
        manager.processMessage(session, makeOffer(session.session_id));
      }
      markCompletedExternally(session);
      const quote = observedQuote({ senderDid: null });
      const acceptance = acceptanceBy(session.session_id, {
        acceptedId: quote.message_id as string,
        acceptedHash: hashObject(quote.act),
        roundNumber: quote.round_number as number,
      });
      const observed = path === "negotiated" ? [quote, acceptance] : [acceptance];

      const record = generateEvidenceWith(session, [...observed, orderConfirmation()], {
        externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
        ...(responder === "observed_party" ? { observedResponder: OBSERVED_RESPONDER } : {}),
      });

      const expected: [unknown, unknown][] = [["acceptance", INITIATOR_DID]];
      if (path === "negotiated") {
        expected.unshift(["offer", INITIATOR_DID]);
      }
      expect(verifiedActs(record)).toStrictEqual(expected);
      expect(record.evidence_level).toBe("unilateral");
      expect(record.record_version).toBe("0.5");
      expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
    });
  }
}

test("an external-channel record never classifies bilateral", () => {
  // Both parties signed and nothing is unsigned, and the record is still mixed.
  //
  // Without the reference this act list is what bilateral describes: both session
  // parties have verified acts and no act is unsigned. With the reference, the
  // completion is the producer's account rather than an act either party signed,
  // so the classifier caps the level at mixed. A record that claims bilateral here
  // is refused, whatever its seal.
  const [session, didDocuments] = mandateOnlySession();
  const record = generateEvidenceWith(session, signedNegotiation(session, [], false), {
    externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
  });

  expect(verifiedActs(record)).toStrictEqual([
    ["offer", INITIATOR_DID],
    ["counteroffer", RESPONDER_DID],
  ]);
  expect((record.acts as Dict[]).every((entry) => entry.attribution === "verified_signature")).toBe(
    true,
  );
  expect(record.evidence_level).toBe("mixed");
  expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);

  const claimed = structuredClone(record);
  claimed.evidence_level = "bilateral";
  reseal(claimed);
  expect(verifySessionEvidenceRecord(claimed, didDocuments)).toBe(false);
});

for (const version of ["0.3", "0.4"]) {
  test(`a signed negotiation record relabelled below 0.5 is refused [${version}]`, () => {
    // A counterparty-signed negotiation behind a reference is a "0.5" shape too.
    const [session, didDocuments] = mandateOnlySession();
    const record = generateEvidenceWith(session, signedNegotiation(session), {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    });
    expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);

    const relabelledRecord = relabelled(record, version);
    expectSealedAndOtherwiseSound(relabelledRecord, didDocuments, "mixed");
    expect(verifySessionEvidenceRecord(relabelledRecord, didDocuments)).toBe(false);
  });
}

test("a transaction_record_hash still requires a DID-bearing responder", () => {
  // The direction this change does not touch. A TransactionRecord is bilateral
  // by construction (Section 9.3), so a responder with no A2CN identity cannot
  // have one, and a record claiming one for such a session is refused at every
  // version. Mirrors the Python row of the same name; without it the TypeScript
  // side would carry no guard on this direction at all.
  const [healthy, didDocuments] = externalChannelRecord();

  const claimed = structuredClone(healthy);
  claimed.transaction_record_hash = "A".repeat(43);
  delete claimed.external_commitment_reference;
  reseal(claimed);

  // The semantic precondition: the responder really is the observed shape, so
  // the refusal below is the witness-direction rule and not something else.
  expect(hasKey((claimed.parties as Dict).responder, "identity_source")).toBe(true);
  expect(verifySessionEvidenceRecord(claimed, didDocuments)).toBe(false);
});

test("a mandate-only relaxation leaves the no-DID external-channel record unchanged", () => {
  // A relaxation can widen past its target, and nothing else would notice.
  const [record, didDocuments] = externalChannelRecord();

  expect(((record.parties as Dict).responder as Dict).did_declared).toBe(false);
  expect(record.evidence_level).toBe("unilateral");
  expect(record.transaction_record_hash).toBeNull();
  expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
});

test("an observed responder still requires the reference to complete", () => {
  // The session must be the identity-light one. Passing observedResponder for a
  // session whose responder declared a DID is refused earlier and for a
  // different reason, a guard this change does not touch.
  const [manager, session] = makeIdentityLightSession();
  manager.processMessage(session, makeOffer(session.session_id));
  markCompletedExternally(session);

  expect(() =>
    generateEvidenceWith(session, [orderConfirmation()], {
      observedResponder: OBSERVED_RESPONDER,
    }),
  ).toThrow(/requires externalCommitmentReference/);
});

test("a reference is still refused for a non-COMPLETED outcome", () => {
  const [manager, session] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  session.state = SessionState.WITHDRAWN;
  session.current_turn = "none";
  session.terminal_message_id = null;
  session.state_updated_at = "2026-03-24T10:10:00Z";

  expect(() =>
    generateEvidenceWith(session, [observedQuote({})], {
      externalCommitmentReference: EXTERNAL_COMMITMENT_REFERENCE,
    }),
  ).toThrow(/only for a COMPLETED session/);
});

test("the producer still seals a mandate-only record as initiator", () => {
  const [record] = mandateOnlyRecord();

  expect((record.producer as Dict).did).toBe(INITIATOR_DID);
  expect(((record.parties as Dict).initiator as Dict).did).toBe(INITIATOR_DID);
});

// ---------------------------------------------------------------------------
// The shape is bound to the version whose schema admits it
//
// A DID-bearing responder on a record carrying external_commitment_reference is
// admitted from "0.5", the first version whose schema admits it; "0.3" and "0.4"
// require an observed_party there. A "0.5" record relabelled to an earlier
// version and resealed is a record THAT version's schema refuses, so the
// verifier refuses it too. Each negative pins every other outcome of
// verification as a precondition. The Python mirror also lowers the floor and
// shows the same bytes then verify; the TypeScript constant is module-private,
// so that half is shown here by mutation rather than in the suite.
// ---------------------------------------------------------------------------

function relabelled(record: Dict, version: string): Dict {
  const copy = structuredClone(record);
  copy.record_version = version;
  return reseal(copy);
}

/** Everything but the version binding, asserted rather than assumed. */
function expectSealedAndOtherwiseSound(
  record: Dict,
  didDocuments: Record<string, Dict>,
  level: string,
): void {
  const unsealed = { ...record, record_hash: "", producer_signature: "" };
  expect(hashObject(unsealed)).toBe(record.record_hash);
  expect(verifyJws(record.producer_signature as string, INITIATOR_PUBLIC_KEY)).toBe(
    record.record_hash,
  );
  expect(assessSessionEvidenceRecord(record, didDocuments).invalid_acts).toBe(0);
  // The acts and parties are those of a record that verified at "0.5", and the
  // classifier reads no version, so the level is still the coherent one.
  expect(record.evidence_level).toBe(level);
}

const MANDATE_ONLY_LEVELS: [string, string | null, string][] = [
  ["mixed", RESPONDER_DID, "mixed"],
  ["unilateral", null, "unilateral"],
];

test.each(MANDATE_ONLY_LEVELS)(
  "a mandate-only record verifies at 0.5: %s",
  (_name, senderDid, level) => {
    const [record, didDocuments] = mandateOnlyRecord(senderDid);

    expect(record.record_version).toBe("0.5");
    expectSealedAndOtherwiseSound(record, didDocuments, level);
    expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
  },
);

test.each(
  MANDATE_ONLY_LEVELS.flatMap(([name, senderDid, level]) =>
    ["0.3", "0.4"].map((version): [string, string, string | null, string] => [
      name,
      version,
      senderDid,
      level,
    ]),
  ),
)(
  "a mandate-only record relabelled below 0.5 is refused: %s at %s",
  (_name, version, senderDid, level) => {
    const [record, didDocuments] = mandateOnlyRecord(senderDid);
    const relabelledRecord = relabelled(record, version);

    expect(hasKey((relabelledRecord.parties as Dict).responder, "identity_source")).toBe(false);
    expect(hasKey(relabelledRecord, "external_commitment_reference")).toBe(true);
    expectSealedAndOtherwiseSound(relabelledRecord, didDocuments, level);
    expect(verifySessionEvidenceRecord(relabelledRecord, didDocuments)).toBe(false);
  },
);

test.each(["0.3", "0.4", "0.5"])(
  "an observed responder with the reference verifies from 0.3: %s",
  (version) => {
    // The floor binds the DID-bearing responder only; observed_party keeps "0.3".
    const [record, didDocuments] = externalChannelRecord();
    const relabelledRecord = relabelled(record, version);

    expect(((relabelledRecord.parties as Dict).responder as Dict).did_declared).toBe(false);
    expect(verifySessionEvidenceRecord(relabelledRecord, didDocuments)).toBe(true);
  },
);
