/**
 * A decline's signature, once present, is verified like any other act's.
 *
 * Signing a rejection or withdrawal is OPTIONAL: an unsigned decline is a
 * conformant message and stays accepted, recorded as an unsigned observation.
 * What is not optional is the check. The signature slots were added without any
 * verification call site, so verifySenderSignature ran for offers and
 * acceptances only: a decline carrying a forged signature was accepted with no
 * check at all, advanced the session, and entered the message log — from where
 * a receiver's own evidence record counts it an invalid act. A counterparty
 * could therefore degrade a third party's durable artifact with one junk
 * string, holding no key material and producing no valid signature.
 *
 * Every forgery below is a real JWS over the act's own correct hash, signed by
 * a key the sender does not control. A syntactically broken string would be
 * refused by a parse failure and would prove nothing about verification.
 *
 * Two invariants pull against each other and both are tested: a signature that
 * is present MUST be verified, and an act carrying no signature MUST still be
 * accepted. Making decline signatures mandatory would satisfy the first and
 * break the second, so the unsigned cases are controls, not decoration.
 *
 * The Python suite runs the same cases.
 */

import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";

import { generateKeypair, hashObject, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import { signedActHash, type Dict } from "../src/a2cn/messages.js";
import { A2CNError, Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument } from "./conftest.js";

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();
// A key no party in the session controls.
const { privateKey: ATTACKER_PRIVATE_KEY } = generateKeypair();

const INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;

const SIGNATURE_FIELD: Record<string, string> = {
  rejection: "rejection_signature",
  withdrawal: "withdrawal_signature",
};

const SESSION_INIT: Dict = {
  message_type: "session_init",
  message_id: "init-msg-id",
  protocol_version: "0.3",
  session_params: {
    deal_type: "saas_renewal",
    currency: "USD",
    subject: "Test",
    max_rounds: 4,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
  },
  initiator: {
    organization_name: "TechCorp",
    did: INITIATOR_DID,
    verification_method: INITIATOR_VM,
    agent_id: "tc-agent",
    endpoint: "https://techcorp.example/api/a2cn",
  },
  initiator_mandate: { mandate_type: "declared" },
};

const SESSION_ACK: Dict = {
  message_type: "session_ack",
  message_id: "ack-msg-id",
  session_id: "sess-001",
  in_reply_to: "init-msg-id",
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
    agent_id: "acme-agent",
    endpoint: "http://localhost:8000",
  },
  responder_mandate: { mandate_type: "declared" },
  session_created_at: "2026-03-24T10:00:00Z",
  current_turn: "initiator",
};

/** A real signed offer, built the way the state machine expects to receive one. */
function makeOffer(sessionId: string, seq: number, rnd: number, senderDid: string): Dict {
  const timestamp = "2026-03-24T10:01:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const terms = { total_value: 9_500_000, currency: "USD" };
  const protocolAct = {
    protocol_version: "0.3",
    session_id: sessionId,
    round_number: rnd,
    sequence_number: seq,
    message_type: "offer",
    sender_did: senderDid,
    timestamp,
    expires_at: expiresAt,
    terms,
  };
  const pah = hashObject(protocolAct);
  const privateKey = senderDid === INITIATOR_DID ? INITIATOR_PRIVATE_KEY : RESPONDER_PRIVATE_KEY;
  const verificationMethod = senderDid === INITIATOR_DID ? INITIATOR_VM : RESPONDER_VM;
  return {
    message_type: "offer",
    message_id: randomUUID(),
    session_id: sessionId,
    round_number: rnd,
    sequence_number: seq,
    sender_did: senderDid,
    sender_agent_id: "agent",
    sender_verification_method: verificationMethod,
    timestamp,
    expires_at: expiresAt,
    terms,
    protocol_act_hash: pah,
    protocol_act_signature: signJws(pah, privateKey, verificationMethod),
  };
}

/** A real session advanced by a real signed offer, via processMessage. */
function sessionAtNegotiating(): [SessionManager, Session] {
  const mgr = new SessionManager();
  mgr.registerDidDocument(
    INITIATOR_DID,
    makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUBLIC_KEY)),
  );
  mgr.registerDidDocument(
    RESPONDER_DID,
    makeDidDocument(RESPONDER_DID, "key-2026-01", publicKeyToJwk(RESPONDER_PUBLIC_KEY)),
  );
  const sess = mgr.createSession("sess-001", SESSION_INIT, SESSION_ACK, "2026-03-24T10:00:00Z");
  // The fixtures use a historical created_at; a large timeout keeps the session
  // from expiring mid-test.
  sess.session_timeout_seconds = 86400 * 365 * 100;
  mgr.processMessage(sess, makeOffer("sess-001", 1, 1, INITIATOR_DID));
  return [mgr, sess];
}

function rejection(sessionId: string): Dict {
  return {
    message_type: "rejection",
    message_id: randomUUID(),
    session_id: sessionId,
    protocol_version: "0.3",
    round_number: 1,
    sequence_number: 2,
    rejected_offer_id: "offer-1",
    sender_did: RESPONDER_DID,
    sender_agent_id: "acme-agent",
    timestamp: "2026-03-24T10:05:00Z",
    reason_code: "PRICE_TOO_HIGH",
  };
}

function withdrawal(sessionId: string, withSequence = true): Dict {
  const act: Dict = {
    message_type: "withdrawal",
    message_id: randomUUID(),
    session_id: sessionId,
    protocol_version: "0.3",
    round_number: 1,
    sender_did: RESPONDER_DID,
    sender_agent_id: "acme-agent",
    timestamp: "2026-03-24T10:05:00Z",
    reason_code: "STRATEGY_DECISION",
  };
  if (withSequence) {
    act.sequence_number = 2;
  }
  return act;
}

/** Sign the act's own rebuilt envelope with the given key. */
function signWith(act: Dict, privateKey: Parameters<typeof signJws>[1]): Dict {
  const signed: Dict = { ...act };
  signed.sender_verification_method = RESPONDER_VM;
  const payloadHash = signedActHash(signed);
  expect(payloadHash, "fixture must be rebuildable to be signed honestly").not.toBeNull();
  signed[SIGNATURE_FIELD[signed.message_type as string]] = signJws(
    payloadHash as string,
    privateKey,
    RESPONDER_VM,
  );
  return signed;
}

function expectA2CNError(fn: () => unknown): A2CNError {
  try {
    fn();
  } catch (exc) {
    if (exc instanceof A2CNError) {
      return exc;
    }
    throw exc;
  }
  throw new Error("expected an A2CNError, but the call succeeded");
}

// ---------------------------------------------------------------------------
// A forged decline signature is refused
// ---------------------------------------------------------------------------

test("a forged rejection signature is refused", () => {
  const [mgr, sess] = sessionAtNegotiating();
  const forged = signWith(rejection(sess.session_id), ATTACKER_PRIVATE_KEY);

  const err = expectA2CNError(() => mgr.processMessage(sess, forged));

  expect(err.code).toBe("INVALID_SIGNATURE");
  expect(sess._message_log).not.toContain(forged);
});

test("a forged withdrawal signature is refused", () => {
  const [mgr, sess] = sessionAtNegotiating();
  const forged = signWith(withdrawal(sess.session_id), ATTACKER_PRIVATE_KEY);

  const err = expectA2CNError(() => mgr.processMessage(sess, forged));

  expect(err.code).toBe("INVALID_SIGNATURE");
  expect(sess.state).not.toBe(SessionState.WITHDRAWN);
});

test("a forged withdrawal without a sequence_number is refused", () => {
  // The loosest dispatch path: withdrawal is dispatched ahead of the turn and
  // approval guards, and its sequence check runs only when sequence_number is
  // present. An act omitting it reaches the handler by the shortest route, so a
  // verification call placed after any of those guards would miss it.
  const [mgr, sess] = sessionAtNegotiating();
  const act = withdrawal(sess.session_id, false);
  act.sender_verification_method = RESPONDER_VM;
  // Unrebuildable, so signed over a stand-in payload exactly as an attacker
  // stripping the field would have to.
  act.withdrawal_signature = signJws("0".repeat(43), ATTACKER_PRIVATE_KEY, RESPONDER_VM);

  const err = expectA2CNError(() => mgr.processMessage(sess, act));

  expect(err.code).toBe("INVALID_SIGNATURE");
  expect(sess.state).not.toBe(SessionState.WITHDRAWN);
});

test("a stripped rejection is refused by validation before the signature check", () => {
  // Which layer refuses it, recorded rather than assumed. round_number and
  // timestamp are required on the wire, so validation refuses a stripped
  // rejection before verification is reached — defence in depth, not the
  // signature check doing its job. Written expecting INVALID_SIGNATURE and
  // measured INVALID_REQUEST, so it is pinned to the layer that actually
  // refuses. It passes both before and after the fix: a boundary guard, not a
  // fix-proving test. The reachable unrebuildable case is the withdrawal above.
  const [mgr, sess] = sessionAtNegotiating();
  const act = rejection(sess.session_id);
  delete act.round_number;
  delete act.timestamp;
  expect(
    signedActHash(act),
    "fixture must be unrebuildable for this test to mean anything",
  ).toBeNull();
  act.sender_verification_method = RESPONDER_VM;
  act.rejection_signature = signJws("0".repeat(43), ATTACKER_PRIVATE_KEY, RESPONDER_VM);

  const err = expectA2CNError(() => mgr.processMessage(sess, act));

  expect(err.code).toBe("INVALID_REQUEST");
});

// ---------------------------------------------------------------------------
// An honestly signed decline still works
// ---------------------------------------------------------------------------

test("an honestly signed rejection is accepted", () => {
  const [mgr, sess] = sessionAtNegotiating();
  const signed = signWith(rejection(sess.session_id), RESPONDER_PRIVATE_KEY);

  mgr.processMessage(sess, signed);

  expect(sess._message_log).toContain(signed);
});

test("an honestly signed withdrawal is accepted", () => {
  const [mgr, sess] = sessionAtNegotiating();
  const signed = signWith(withdrawal(sess.session_id), RESPONDER_PRIVATE_KEY);

  mgr.processMessage(sess, signed);

  expect(sess.state).toBe(SessionState.WITHDRAWN);
});

// ---------------------------------------------------------------------------
// Controls: signing a decline is optional, and must stay optional
// ---------------------------------------------------------------------------

test("an unsigned rejection is still accepted", () => {
  const [mgr, sess] = sessionAtNegotiating();
  const unsigned = rejection(sess.session_id);

  mgr.processMessage(sess, unsigned);

  expect(sess._message_log).toContain(unsigned);
});

test("an unsigned withdrawal is still accepted", () => {
  const [mgr, sess] = sessionAtNegotiating();
  const unsigned = withdrawal(sess.session_id);

  mgr.processMessage(sess, unsigned);

  expect(sess.state).toBe(SessionState.WITHDRAWN);
});
