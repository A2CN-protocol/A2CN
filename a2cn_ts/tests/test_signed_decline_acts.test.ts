/**
 * Rejection and withdrawal can be signed in band, and are verified like any act.
 *
 * Before the envelope these two act types had no signature slot at all: a party
 * that signed its own withdrawal had nowhere conformant to put the signature,
 * so an evidence record either called the act unsigned — stating that nobody
 * signed an act the party did in fact sign — or carried a signature the
 * verifier had no rule for and silently ignored.
 *
 * Signing a decline is OPTIONAL on the wire: an unsigned decline is still a
 * conformant message, and is still recorded as an unsigned observation. What is
 * not optional is the check. Once an act carries a signature, the rebuild
 * decides, and nothing about the act's own content can turn the check off.
 *
 * The Python suite runs the same cases.
 */

import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";

import { generateKeypair, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import {
  assessSessionEvidenceRecord,
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
} from "../src/a2cn/evidence.js";
import {
  SIGNED_ACT_SIGNATURE_FIELDS,
  rebuildSignedAct,
  signedActHash,
  type Dict,
} from "../src/a2cn/messages.js";
import { Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument } from "./conftest.js";

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();
const { privateKey: OTHER_PRIVATE_KEY } = generateKeypair();

const INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;

function makeSession(): [Session, Record<string, Dict>] {
  const sessionId = randomUUID();
  const sessionInit: Dict = {
    message_type: "session_init",
    message_id: "init-1",
    protocol_version: "0.2",
    session_params: {
      deal_type: "saas_renewal",
      currency: "USD",
      subject: "Signed decline test",
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
  return [session, didDocuments];
}

function markTimedOut(session: Session): void {
  session.state = SessionState.TIMED_OUT;
  session.current_turn = "none";
  session.terminal_reason = "session_timeout";
  session.terminal_message_id = null;
  session.state_updated_at = "2026-03-24T10:10:00Z";
}

function generateEvidence(session: Session): Dict {
  return generateSessionEvidenceRecord(session, {
    producerPrivateKey: INITIATOR_PRIVATE_KEY,
    producerDid: INITIATOR_DID,
    producerAgentId: "buyer-agent",
    producerVerificationMethod: INITIATOR_VM,
    observedActs: null,
  });
}

/** Sign an act over its own rebuilt envelope, as a conformant sender would. */
function sign(act: Dict, privateKey: Parameters<typeof signJws>[1], verificationMethod: string): Dict {
  const signed = structuredClone(act);
  signed.sender_verification_method = verificationMethod;
  signed[SIGNED_ACT_SIGNATURE_FIELDS[act.message_type as string]] = signJws(
    signedActHash(signed) as string,
    privateKey,
    verificationMethod,
  );
  return signed;
}

function rejection(sessionId: string): Dict {
  return {
    message_type: "rejection",
    message_id: randomUUID(),
    session_id: sessionId,
    in_reply_to: "offer-1",
    round_number: 1,
    sequence_number: 2,
    rejected_offer_id: "offer-1",
    sender_did: RESPONDER_DID,
    sender_agent_id: "seller-agent",
    timestamp: "2026-03-24T10:05:00Z",
    reason_code: "PRICE_TOO_HIGH",
    reason_description: "above mandate",
  };
}

function withdrawal(sessionId: string): Dict {
  return {
    message_type: "withdrawal",
    message_id: randomUUID(),
    session_id: sessionId,
    in_reply_to: "offer-1",
    round_number: 1,
    sequence_number: 2,
    sender_did: INITIATOR_DID,
    sender_agent_id: "buyer-agent",
    timestamp: "2026-03-24T10:05:00Z",
    reason_code: "STRATEGY_DECISION",
    reason_description: "walking away",
  };
}

// ---------------------------------------------------------------------------
// A signed decline verifies, and is attributed to its signer
// ---------------------------------------------------------------------------

test("a signed rejection is a verified act", () => {
  const [session, didDocuments] = makeSession();
  session._message_log = [sign(rejection(session.session_id), RESPONDER_PRIVATE_KEY, RESPONDER_VM)];
  markTimedOut(session);

  const evidence = generateEvidence(session);

  expect((evidence.acts as Dict[])[0].attribution).toBe("verified_signature");
  expect((evidence.acts as Dict[])[0].signature_type).toBe("rejection_signature");
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("a signed withdrawal is a verified act", () => {
  const [session, didDocuments] = makeSession();
  session._message_log = [
    sign(withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM),
  ];
  markTimedOut(session);

  const evidence = generateEvidence(session);

  expect((evidence.acts as Dict[])[0].attribution).toBe("verified_signature");
  expect((evidence.acts as Dict[])[0].signature_type).toBe("withdrawal_signature");
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

test("a signed withdrawal no longer forces an invalid record", () => {
  // The recorded gap: a party's own signed act, unprovable. Before
  // the slot existed, a signed withdrawal could only be carried as an unsigned
  // observation or as an act the verifier counted invalid. Neither stated the
  // truth, and the most common ending to a session was the one that could not
  // verify.
  const [session, didDocuments] = makeSession();
  session._message_log = [
    sign(withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM),
  ];
  markTimedOut(session);

  const assessment = assessSessionEvidenceRecord(generateEvidence(session), didDocuments);

  expect(assessment.valid).toBe(true);
  expect(assessment.invalid_acts).toBe(0);
  expect(assessment.verified_acts).toBe(1);
});

// ---------------------------------------------------------------------------
// An unsigned decline stays conformant, and stays honestly unsigned
// ---------------------------------------------------------------------------

test("an unsigned decline is still an unsigned observation", () => {
  const [session, didDocuments] = makeSession();
  session._message_log = [withdrawal(session.session_id)];
  markTimedOut(session);

  const evidence = generateEvidence(session);

  expect((evidence.acts as Dict[])[0].attribution).toBe("unsigned_observation");
  expect((evidence.acts as Dict[])[0].signature).toBeNull();
  expect(verifySessionEvidenceRecord(evidence, didDocuments)).toBe(true);
});

// ---------------------------------------------------------------------------
// What the rebuild refuses
// ---------------------------------------------------------------------------

test("a decline signed by the wrong key is refused", () => {
  const [session, didDocuments] = makeSession();
  session._message_log = [sign(withdrawal(session.session_id), OTHER_PRIVATE_KEY, INITIATOR_VM)];
  markTimedOut(session);

  expect(verifySessionEvidenceRecord(generateEvidence(session), didDocuments)).toBe(false);
});

test("a decline whose reason_code was altered after signing is refused", () => {
  // reason_code is inside the signed scope, so restating why is not possible.
  const [session, didDocuments] = makeSession();
  const signed = sign(withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM);
  signed.reason_code = "COMPLIANCE_FAILURE";
  session._message_log = [signed];
  markTimedOut(session);

  expect(verifySessionEvidenceRecord(generateEvidence(session), didDocuments)).toBe(false);
});

test("a decline whose reason_description changed still verifies", () => {
  // It is outside the signed scope, deliberately, and nothing pretends otherwise.
  const [session] = makeSession();
  const signed = sign(withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM);
  const before = signedActHash(signed);
  signed.reason_description = "something else entirely";

  expect(signedActHash(signed)).toBe(before);
});

test("a rejection relabelled as a withdrawal is refused", () => {
  // The signature field names the act type it was made under.
  const [session] = makeSession();
  const signed = sign(rejection(session.session_id), RESPONDER_PRIVATE_KEY, RESPONDER_VM);
  const relabelled = structuredClone(signed);
  relabelled.message_type = "withdrawal";

  expect(signedActHash(relabelled)).not.toBe(signedActHash(signed));
  expect(relabelled).toHaveProperty("rejection_signature");
  expect(relabelled).not.toHaveProperty("withdrawal_signature");
});

test("moving a decline signature into the other slot is refused", () => {
  const [session, didDocuments] = makeSession();
  const signed = sign(withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM);
  const moved = structuredClone(signed);
  moved.rejection_signature = moved.withdrawal_signature;
  delete moved.withdrawal_signature;
  moved.message_type = "rejection";
  moved.rejected_offer_id = "offer-1";
  session._message_log = [moved];
  markTimedOut(session);

  expect(verifySessionEvidenceRecord(generateEvidence(session), didDocuments)).toBe(false);
});

test("a withdrawal without round_number cannot be rebuilt", () => {
  // round_number is REQUIRED on a withdrawal so the common header applies.
  // Section 7.6's message did not carry one, so the header could not be rebuilt
  // from a withdrawal's own fields; it is now required, and an act that omits
  // it is refused rather than rebuilt over a guessed round.
  const withoutRound = withdrawal("session-1");
  delete withoutRound.round_number;

  expect(rebuildSignedAct(withoutRound)).toBeNull();
});
