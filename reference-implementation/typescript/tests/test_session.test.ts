/** Tests for a2cn/session — state machine, turn-taking, idempotency. */

import { randomUUID, type KeyObject } from "node:crypto";
import { expect, test, vi } from "vitest";

import { Session, SessionManager, SessionState, A2CNError } from "../src/a2cn/session.js";
import {
  generateEd25519Keypair,
  generateKeypair,
  hashObject,
  publicKeyToJwk,
  signApprovalReceipt,
  signJws,
  verifyApprovalReceiptSignature,
} from "../src/a2cn/crypto.js";
import { generateAuditLog } from "../src/a2cn/record.js";
import { PROTOCOL_ACT_VERSION, signedActHash, type Dict } from "../src/a2cn/messages.js";
import { makeDidDocument, signDecline } from "./conftest.js";

const INITIATOR_DID = "did:web:techcorp.example";
const RESPONDER_DID = "did:web:acme-corp.com";

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
    verification_method: `${INITIATOR_DID}#key-1`,
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
    verification_method: `${RESPONDER_DID}#key-2026-01`,
    agent_id: "acme-agent",
    endpoint: "http://localhost:8000",
  },
  responder_mandate: { mandate_type: "declared" },
  session_created_at: "2026-03-24T10:00:00Z",
  current_turn: "initiator",
};

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();

function makeOffer(
  sessionId: string,
  seq: number,
  rnd: number,
  senderDid: string,
  options: { msgType?: string; inReplyTo?: string | null; terms?: Dict | null } = {},
): Dict {
  const { msgType = "offer", inReplyTo = null } = options;
  const timestamp = "2026-03-24T10:01:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const terms = options.terms ?? { total_value: 9_500_000, currency: "USD" };
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
  const privateKey = senderDid === INITIATOR_DID ? INITIATOR_PRIVATE_KEY : RESPONDER_PRIVATE_KEY;
  const verificationMethod =
    senderDid === INITIATOR_DID ? `${INITIATOR_DID}#key-1` : `${RESPONDER_DID}#key-2026-01`;
  const msg: Dict = {
    message_type: msgType,
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
  if (inReplyTo) {
    msg.in_reply_to = inReplyTo;
  }
  return msg;
}

function resignOffer(offer: Dict): void {
  const protocolAct = {
    protocol_version: "0.3",
    session_id: offer.session_id,
    round_number: offer.round_number,
    sequence_number: offer.sequence_number,
    message_type: offer.message_type,
    sender_did: offer.sender_did,
    timestamp: offer.timestamp,
    expires_at: offer.expires_at,
    terms: offer.terms,
  };
  offer.protocol_act_hash = hashObject(protocolAct);
  const privateKey =
    offer.sender_did === INITIATOR_DID ? INITIATOR_PRIVATE_KEY : RESPONDER_PRIVATE_KEY;
  offer.protocol_act_signature = signJws(
    offer.protocol_act_hash as string,
    privateKey,
    offer.sender_verification_method as string,
  );
}

function makeAcceptance(sess: Session, offer: Dict, msgId = "acc-1"): Dict {
  const senderDid = RESPONDER_DID;
  const verificationMethod = `${RESPONDER_DID}#key-2026-01`;
  const acceptance: Dict = {
    message_type: "acceptance",
    message_id: msgId,
    session_id: sess.session_id,
    in_reply_to: offer.message_id,
    round_number: offer.round_number,
    sequence_number: sess.sequence_number + 1,
    accepted_offer_id: offer.message_id,
    accepted_protocol_act_hash: offer.protocol_act_hash,
    sender_did: senderDid,
    sender_agent_id: "acme-agent",
    sender_verification_method: verificationMethod,
    timestamp: "2026-03-24T10:05:00Z",
  };
  // Signed over the act's own envelope (Section 7.3.1), built from the very
  // message the state machine receives.
  acceptance.acceptance_signature = signJws(
    signedActHash(acceptance, { versionWhenAbsent: PROTOCOL_ACT_VERSION }) as string,
    RESPONDER_PRIVATE_KEY,
    verificationMethod,
  );
  return acceptance;
}

function newSession(sessionId = "sess-001"): [SessionManager, Session] {
  const mgr = new SessionManager();
  mgr.registerDidDocument(
    INITIATOR_DID,
    makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUBLIC_KEY)),
  );
  mgr.registerDidDocument(
    RESPONDER_DID,
    makeDidDocument(RESPONDER_DID, "key-2026-01", publicKeyToJwk(RESPONDER_PUBLIC_KEY)),
  );
  const sess = mgr.createSession(sessionId, SESSION_INIT, SESSION_ACK, "2026-03-24T10:00:00Z");
  // Tests use a historical created_at; give them a large timeout so they never expire
  sess.session_timeout_seconds = 86400 * 365 * 100;
  return [mgr, sess];
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
  throw new Error("Expected A2CNError to be thrown");
}

// ---------------------------------------------------------------------------
// Session creation
// ---------------------------------------------------------------------------

test("create session state", () => {
  const [, sess] = newSession();
  expect(sess.state).toBe(SessionState.ACTIVE);
  expect(sess.current_turn).toBe("initiator");
  expect(sess.round_number).toBe(0);
  expect(sess.sequence_number).toBe(0);
});

// ---------------------------------------------------------------------------
// Turn-taking (Section 3.2)
// ---------------------------------------------------------------------------

test("offer from wrong turn raises not your turn", () => {
  const [mgr, sess] = newSession();
  // Responder tries to send an offer before initiator
  const offer = makeOffer(sess.session_id, 1, 1, RESPONDER_DID);
  const err = expectA2CNError(() => mgr.processMessage(sess, offer));
  expect(err.code).toBe("NOT_YOUR_TURN");
});

test("offer from correct turn accepted", () => {
  const [mgr, sess] = newSession();
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);
  expect(sess.state).toBe(SessionState.NEGOTIATING);
  expect(sess.current_turn).toBe("responder");
  expect(sess.round_number).toBe(1);
});

test("turn flips after counteroffer", () => {
  const [mgr, sess] = newSession();
  const o1 = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, o1);
  expect(sess.current_turn).toBe("responder");

  const co1 = makeOffer(sess.session_id, 2, 2, RESPONDER_DID, {
    msgType: "counteroffer",
    inReplyTo: o1.message_id as string,
  });
  mgr.processMessage(sess, co1);
  expect(sess.current_turn).toBe("initiator");
  expect(sess.round_number).toBe(2);
});

test("impasse counts only full rounds with no change", () => {
  const [mgr, sess] = newSession();
  sess.max_rounds = 6;
  sess.impasse_threshold = 2;

  const totals: Array<[string, number]> = [
    [INITIATOR_DID, 10_000_000],
    [RESPONDER_DID, 9_900_000],
    [INITIATOR_DID, 10_000_000],
    [RESPONDER_DID, 9_900_000],
    [INITIATOR_DID, 10_000_000],
    [RESPONDER_DID, 9_900_000],
  ];

  let previous: string | null = null;
  for (let index = 1; index <= totals.length; index++) {
    const [senderDid, totalValue] = totals[index - 1];
    const message = makeOffer(sess.session_id, index, index, senderDid, {
      msgType: index === 1 ? "offer" : "counteroffer",
      inReplyTo: previous,
      terms: { total_value: totalValue, currency: "USD" },
    });
    mgr.processMessage(sess, message);
    previous = message.message_id as string;

    if (index === 3) {
      expect(sess.consecutive_non_moving_rounds).toBe(0);
      expect(sess.state).toBe(SessionState.NEGOTIATING);
    }
    if (index === 4) {
      expect(sess.consecutive_non_moving_rounds).toBe(1);
      expect(sess.state).toBe(SessionState.NEGOTIATING);
    }
  }

  expect(sess.state).toBe(SessionState.IMPASSE);
  expect(sess.current_turn).toBe("none");
  expect(sess.consecutive_non_moving_rounds).toBe(2);
});

test("impasse treats any total value change as movement", () => {
  const [mgr, sess] = newSession();
  sess.max_rounds = 6;
  sess.impasse_threshold = 1;

  const totals: Array<[string, number]> = [
    [INITIATOR_DID, 10_000_000],
    [RESPONDER_DID, 9_999_980],
    [INITIATOR_DID, 10_000_020],
    [RESPONDER_DID, 9_999_980],
  ];

  let previous: string | null = null;
  for (let index = 1; index <= totals.length; index++) {
    const [senderDid, totalValue] = totals[index - 1];
    const message = makeOffer(sess.session_id, index, index, senderDid, {
      msgType: index === 1 ? "offer" : "counteroffer",
      inReplyTo: previous,
      terms: { total_value: totalValue, currency: "USD" },
    });
    mgr.processMessage(sess, message);
    previous = message.message_id as string;
  }

  expect(sess.state).toBe(SessionState.NEGOTIATING);
  expect(sess.consecutive_non_moving_rounds).toBe(0);
});

// ---------------------------------------------------------------------------
// Sequence number enforcement (Section 7.1)
// ---------------------------------------------------------------------------

test("wrong sequence number raises", () => {
  const [mgr, sess] = newSession();
  const offer = makeOffer(sess.session_id, 5, 1, INITIATOR_DID); // wrong seq
  const err = expectA2CNError(() => mgr.processMessage(sess, offer));
  expect(err.code).toBe("SEQUENCE_ERROR");
});

test("sequence monotonically increments", () => {
  const [mgr, sess] = newSession();
  const o1 = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, o1);
  expect(sess.sequence_number).toBe(1);

  const co1 = makeOffer(sess.session_id, 2, 2, RESPONDER_DID, {
    msgType: "counteroffer",
    inReplyTo: o1.message_id as string,
  });
  mgr.processMessage(sess, co1);
  expect(sess.sequence_number).toBe(2);
});

// ---------------------------------------------------------------------------
// Idempotency (Section 6.1)
// ---------------------------------------------------------------------------

test("duplicate message returns same response", () => {
  const [mgr, sess] = newSession();
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  const r1 = mgr.processMessage(sess, offer);
  const r2 = mgr.processMessage(sess, offer);
  expect(r1).toEqual(r2);
  expect(sess.sequence_number).toBe(1); // not incremented twice
});

// ---------------------------------------------------------------------------
// Terminal state enforcement
// ---------------------------------------------------------------------------

test("message on terminal session raises", () => {
  const [mgr, sess] = newSession();
  // Force terminal state
  const withdrawal = {
    message_type: "withdrawal",
    message_id: "w-1",
    session_id: sess.session_id,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "tc-agent",
    timestamp: "2026-03-24T10:02:00Z",
    reason_code: "STRATEGY_DECISION",
  };
  const signedWithdrawal = signDecline(withdrawal, INITIATOR_PRIVATE_KEY, `${INITIATOR_DID}#key-1`);
  mgr.processMessage(sess, signedWithdrawal);
  expect(sess.state).toBe(SessionState.WITHDRAWN);

  // Now try to send another message
  const offer = makeOffer(sess.session_id, 2, 1, INITIATOR_DID);
  const err = expectA2CNError(() => mgr.processMessage(sess, offer));
  expect(err.code).toBe("SESSION_WRONG_STATE");
});

// ---------------------------------------------------------------------------
// Acceptance
// ---------------------------------------------------------------------------

test("acceptance transitions to completed", () => {
  const [mgr, sess] = newSession();
  const o1 = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, o1);

  const acceptance = makeAcceptance(sess, o1);
  mgr.processMessage(sess, acceptance);
  expect(sess.state).toBe(SessionState.COMPLETED);
  expect(sess.current_turn).toBe("none");
});

// ---------------------------------------------------------------------------
// WRONG_MESSAGE_TYPE
// ---------------------------------------------------------------------------

test("offer in round2 wrong type raises", () => {
  const [mgr, sess] = newSession();
  const o1 = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, o1);

  // Responder sends "offer" in round 2 (should be "counteroffer")
  const bad = makeOffer(sess.session_id, 2, 2, RESPONDER_DID, {
    msgType: "offer",
    inReplyTo: o1.message_id as string,
  });
  const err = expectA2CNError(() => mgr.processMessage(sess, bad));
  expect(err.code).toBe("WRONG_MESSAGE_TYPE");
});

// ---------------------------------------------------------------------------
// REJECTED_FINAL at max_rounds
// ---------------------------------------------------------------------------

test("rejection at max rounds transitions to rejected final", () => {
  const [mgr, sess] = newSession();
  sess.max_rounds = 1; // single-round session

  const o1 = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, o1);

  const rejection = {
    message_type: "rejection",
    message_id: "rej-1",
    session_id: sess.session_id,
    in_reply_to: o1.message_id,
    round_number: 1,
    sequence_number: 2,
    rejected_offer_id: o1.message_id,
    sender_did: RESPONDER_DID,
    sender_agent_id: "acme-agent",
    timestamp: "2026-03-24T10:05:00Z",
    reason_code: "PRICE_TOO_LOW",
  };
  const signedRejection = signDecline(
    rejection,
    RESPONDER_PRIVATE_KEY,
    `${RESPONDER_DID}#key-2026-01`,
  );
  mgr.processMessage(sess, signedRejection);
  expect(sess.state).toBe(SessionState.REJECTED_FINAL);
});

// ---------------------------------------------------------------------------
// Security fixes (findings 2.8, 2.9, 4.1, 4.2, 4.3, 5.5)
// ---------------------------------------------------------------------------

test("invalid message type rejected", () => {
  // Finding 4.1: unknown message_type raises WRONG_MESSAGE_TYPE.
  const [mgr, sess] = newSession();
  const bad = {
    message_type: "surprise",
    message_id: randomUUID(),
    session_id: sess.session_id,
    sequence_number: 1,
    round_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "agent",
    timestamp: "2026-03-24T10:01:00Z",
  };
  const err = expectA2CNError(() => mgr.processMessage(sess, bad));
  expect(err.code).toBe("WRONG_MESSAGE_TYPE");
  expect(err.httpStatus).toBe(422);
});

test("invalid sender did rejected", () => {
  // Finding 4.1: non-DID sender_did raises INVALID_REQUEST.
  const [mgr, sess] = newSession();
  const bad = {
    message_type: "offer",
    message_id: randomUUID(),
    session_id: sess.session_id,
    sequence_number: 1,
    round_number: 1,
    sender_did: "not-a-did",
    sender_agent_id: "agent",
    timestamp: "2026-03-24T10:01:00Z",
  };
  const err = expectA2CNError(() => mgr.processMessage(sess, bad));
  expect(err.code).toBe("INVALID_REQUEST");
  expect(err.httpStatus).toBe(400);
});

test("unknown sender did raises unauthorized sender", () => {
  // Finding 5.5: DID not party to session raises UNAUTHORIZED_SENDER.
  const [mgr, sess] = newSession();
  const o = makeOffer(sess.session_id, 1, 1, "did:web:stranger.example");
  const err = expectA2CNError(() => mgr.processMessage(sess, o));
  expect(err.code).toBe("UNAUTHORIZED_SENDER");
  expect(err.httpStatus).toBe(403);
});

test("protocol act hash mismatch rejected", () => {
  // Finding 4.3: tampered protocol_act_hash raises INVALID_SIGNATURE.
  const [mgr, sess] = newSession();
  const o = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  o.protocol_act_hash = "sha256-tampered-hash";
  const err = expectA2CNError(() => mgr.processMessage(sess, o));
  expect(err.code).toBe("INVALID_SIGNATURE");
  expect(err.httpStatus).toBe(400);
});

test("protocol act signature mismatch rejected", () => {
  const [mgr, sess] = newSession();
  const o = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  o.protocol_act_signature = signJws(
    o.protocol_act_hash as string,
    RESPONDER_PRIVATE_KEY,
    `${RESPONDER_DID}#key-2026-01`,
  );
  const err = expectA2CNError(() => mgr.processMessage(sess, o));
  expect(err.code).toBe("INVALID_SIGNATURE");
  expect(err.httpStatus).toBe(400);
});

test("acceptance signature mismatch rejected", () => {
  const [mgr, sess] = newSession();
  const o1 = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, o1);

  const acceptance = makeAcceptance(sess, o1);
  acceptance.acceptance_signature = signJws(
    hashObject({
      session_id: acceptance.session_id,
      round_number: acceptance.round_number,
      sequence_number: acceptance.sequence_number,
      accepted_offer_id: acceptance.accepted_offer_id,
      accepted_protocol_act_hash: acceptance.accepted_protocol_act_hash,
    }),
    INITIATOR_PRIVATE_KEY,
    `${INITIATOR_DID}#key-1`,
  );
  const err = expectA2CNError(() => mgr.processMessage(sess, acceptance));
  expect(err.code).toBe("INVALID_SIGNATURE");
  expect(err.httpStatus).toBe(400);
});

test("offer at max commitment value accepted", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    max_commitment_value: 9_500_000,
    max_commitment_currency: "USD",
  };

  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  const result = mgr.processMessage(sess, offer);

  expect(result.state).toBe(SessionState.NEGOTIATING);
  expect(sess.latest_offer_hash).toBe(offer.protocol_act_hash);
});

test("offer over max commitment value rejected", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    max_commitment_value: 9_499_999,
    max_commitment_currency: "USD",
  };

  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  const err = expectA2CNError(() => mgr.processMessage(sess, offer));

  expect(err.code).toBe("MANDATE_INVALID");
  expect(err.httpStatus).toBe(403);
  expect(sess.sequence_number).toBe(0);
  expect(sess.state).toBe(SessionState.ACTIVE);
});

test("offer currency mismatch rejected", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    max_commitment_value: 20_000_000,
    max_commitment_currency: "EUR",
  };

  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  const err = expectA2CNError(() => mgr.processMessage(sess, offer));

  expect(err.code).toBe("MANDATE_INVALID");
  expect(err.httpStatus).toBe(403);
  expect(sess.sequence_number).toBe(0);
});

test("acceptance at max commitment value completes", () => {
  const [mgr, sess] = newSession();
  sess.responder_mandate = {
    mandate_type: "declared",
    principal_did: RESPONDER_DID,
    max_commitment_value: 9_500_000,
    max_commitment_currency: "USD",
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);

  const acceptance = makeAcceptance(sess, offer);
  mgr.processMessage(sess, acceptance);

  expect(sess.state).toBe(SessionState.COMPLETED);
});

test("acceptance over max commitment value rejected", () => {
  const [mgr, sess] = newSession();
  sess.responder_mandate = {
    mandate_type: "declared",
    principal_did: RESPONDER_DID,
    max_commitment_value: 9_499_999,
    max_commitment_currency: "USD",
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);

  const acceptance = makeAcceptance(sess, offer);
  const err = expectA2CNError(() => mgr.processMessage(sess, acceptance));

  expect(err.code).toBe("MANDATE_INVALID");
  expect(err.httpStatus).toBe(403);
  expect(sess.state).toBe(SessionState.NEGOTIATING);
  expect(sess.sequence_number).toBe(1);
  expect(sess._final_acceptance).toBeNull();
});

test("acceptance currency mismatch rejected", () => {
  const [mgr, sess] = newSession();
  sess.responder_mandate = {
    mandate_type: "declared",
    principal_did: RESPONDER_DID,
    max_commitment_value: 20_000_000,
    max_commitment_currency: "EUR",
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);

  const acceptance = makeAcceptance(sess, offer);
  const err = expectA2CNError(() => mgr.processMessage(sess, acceptance));

  expect(err.code).toBe("MANDATE_INVALID");
  expect(err.httpStatus).toBe(403);
  expect(sess.state).toBe(SessionState.NEGOTIATING);
});

test("acceptance in active state raises", () => {
  // Finding 2.8: acceptance in ACTIVE state (before any offer) raises SESSION_WRONG_STATE.
  const [mgr, sess] = newSession();
  expect(sess.state).toBe(SessionState.ACTIVE);
  const acceptance = {
    message_type: "acceptance",
    message_id: randomUUID(),
    session_id: sess.session_id,
    round_number: 1,
    sequence_number: 1,
    accepted_offer_id: "offer-x",
    accepted_protocol_act_hash: "some-hash",
    sender_did: RESPONDER_DID,
    sender_agent_id: "acme-agent",
    sender_verification_method: `${RESPONDER_DID}#key-2026-01`,
    timestamp: "2026-03-24T10:05:00Z",
    acceptance_signature: "eyJ...",
  };
  const err = expectA2CNError(() => mgr.processMessage(sess, acceptance));
  expect(err.code).toBe("SESSION_WRONG_STATE");
});

test("offer expiry check", () => {
  // Finding 4.2: accepting an expired offer raises OFFER_EXPIRED.
  const [mgr, sess] = newSession();
  const o1 = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  // Backdate expiry to force expiration
  o1.expires_at = "2020-01-01T00:00:00Z";
  // Recompute hash/signature with the new expires_at (otherwise signature mismatch fires first)
  resignOffer(o1);
  mgr.processMessage(sess, o1);

  // Update session hash tracker
  sess.latest_offer_hash = o1.protocol_act_hash as string;

  const acceptance = makeAcceptance(sess, o1, randomUUID());
  const err = expectA2CNError(() => mgr.processMessage(sess, acceptance));
  expect(err.code).toBe("OFFER_EXPIRED");
  expect(err.httpStatus).toBe(422);
});

test("session timeout check", () => {
  // Finding 2.9: messages on a timed-out session raise SESSION_WRONG_STATE.
  const [mgr, sess] = newSession();
  // Set session_created_at to well in the past and a short timeout
  sess.session_created_at = "2020-01-01T00:00:00Z";
  sess.session_timeout_seconds = 1;

  const o = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  const err = expectA2CNError(() => mgr.processMessage(sess, o));
  expect(err.code).toBe("SESSION_WRONG_STATE");
  expect(sess.state).toBe(SessionState.TIMED_OUT);
});

test("process message returns state dict", () => {
  // Finding 5.2: processMessage returns session.toStateDict().
  const [mgr, sess] = newSession();
  const o1 = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  const result = mgr.processMessage(sess, o1);
  expect("session_id" in result).toBe(true);
  expect("state" in result).toBe(true);
  expect(result.state).toBe(SessionState.NEGOTIATING);
  expect(result.round_number).toBe(1);
});

// ---------------------------------------------------------------------------
// Human approval pause
// ---------------------------------------------------------------------------

// ApprovalReceipts are signed by an operator-side approver, not by the agent
// under oversight (Section 14.1). The approver has its own key, and the mandate
// that sets the threshold names it in approval_operator_dids.
const APPROVER_DID = "did:web:approver.example";
const { privateKey: APPROVER_PRIVATE_KEY, publicKey: APPROVER_PUBLIC_KEY } = generateEd25519Keypair();
const ES256_APPROVER_DID = "did:web:es256-approver.example";
const { privateKey: ES256_APPROVER_PRIVATE_KEY, publicKey: ES256_APPROVER_PUBLIC_KEY } = generateKeypair();
const OTHER_DID = "did:web:other.example";
const { privateKey: OTHER_PRIVATE_KEY, publicKey: OTHER_PUBLIC_KEY } = generateEd25519Keypair();

function approvalMandate(
  principalDid = INITIATOR_DID,
  approvers: string[] = [APPROVER_DID, ES256_APPROVER_DID],
  extra: Dict = {},
): Dict {
  return {
    mandate_type: "declared",
    principal_did: principalDid,
    requires_human_approval_above: 9_000_000,
    approval_operator_dids: [...approvers],
    ...extra,
  };
}

function registerApprovers(mgr: SessionManager): void {
  mgr.registerDidDocument(
    APPROVER_DID,
    makeDidDocument(APPROVER_DID, "key-1", publicKeyToJwk(APPROVER_PUBLIC_KEY)),
  );
  mgr.registerDidDocument(
    ES256_APPROVER_DID,
    makeDidDocument(ES256_APPROVER_DID, "key-1", publicKeyToJwk(ES256_APPROVER_PUBLIC_KEY)),
  );
  mgr.registerDidDocument(OTHER_DID, makeDidDocument(OTHER_DID, "key-1", publicKeyToJwk(OTHER_PUBLIC_KEY)));
}

/** A session whose initiator offer is paused for human approval. */
function pausedSession(approvers?: string[], extra: Dict = {}): [SessionManager, Session] {
  const [mgr, sess] = newSession();
  registerApprovers(mgr);
  sess.initiator_mandate = approvalMandate(INITIATOR_DID, approvers, extra);
  mgr.processMessage(sess, makeOffer(sess.session_id, 1, 1, INITIATOR_DID));
  expect(sess.state).toBe(SessionState.AWAITING_HUMAN_APPROVAL);
  return [mgr, sess];
}

function approvalReceipt(
  sess: Session,
  {
    offerHash,
    approverDid = APPROVER_DID,
    expiresAt = "2030-01-01T00:00:00Z" as string | null,
    signWith = APPROVER_PRIVATE_KEY as KeyObject | null,
    mandateRef = "hash" as string | null,
    receiptId = "urn:concordia:receipt:test",
    pausedParty = "auto" as string | null,
  }: {
    offerHash?: string;
    approverDid?: string;
    expiresAt?: string | null;
    signWith?: KeyObject | null;
    mandateRef?: string | null;
    receiptId?: string;
    pausedParty?: string | null;
  } = {},
): Dict {
  const references: Dict[] = [
    {
      type: "negotiation_session",
      id: `a2cn:session:${sess.session_id}`,
      relationship: "approves",
    },
  ];
  if (mandateRef === "hash") {
    references.push({
      type: "mandate",
      id: hashObject(sess.approval_pending_mandate),
      relationship: "fulfills",
    });
  } else if (mandateRef !== null) {
    references.push({ type: "mandate", id: mandateRef, relationship: "fulfills" });
  }
  const receipt: Dict = {
    artifact_type: "ApprovalReceipt",
    id: receiptId,
    scope: {
      decision: "approve",
      offer_hash: offerHash ?? sess.approval_pending_offer_hash,
      amount: "95000.00 USD",
      threshold_crossed: "90000.00 USD",
    },
    references,
    approver_did: approverDid,
  };
  let named = pausedParty;
  if (named === "auto") {
    const role = sess.approval_pending_sender_role;
    const info = role === "initiator" ? sess.initiator_info : role === "responder" ? sess.responder_info : null;
    named = info ? ((info as Dict).did as string) : null;
  }
  if (named !== null) {
    references.push({ type: "paused_party", id: named, relationship: "approves" });
  }
  if (expiresAt !== null) {
    receipt.expires_at = expiresAt;
  }
  if (signWith !== null) {
    receipt.signature = signApprovalReceipt(receipt, signWith);
  }
  return receipt;
}

/** Apply a receipt that must be refused; the pause must survive it. */
function refused(mgr: SessionManager, sess: Session, receipt: Dict): string {
  const exc = expectA2CNError(() => mgr.applyApprovalReceipt(sess, receipt));
  expect(sess.state).toBe(SessionState.AWAITING_HUMAN_APPROVAL);
  expect(sess.approval_receipts).toEqual([]);
  return exc.code;
}

test("threshold crossing offer enters awaiting human approval", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = approvalMandate();

  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  const result = mgr.processMessage(sess, offer);

  expect(result.state).toBe(SessionState.AWAITING_HUMAN_APPROVAL);
  expect(sess.current_turn).toBe("initiator");
  expect(sess.approval_pending_offer_id).toBe(offer.message_id);
  expect(sess.approval_pending_offer_hash).toBe(offer.protocol_act_hash);
});

test("approval receipt releases pause and restores counterparty turn", () => {
  const [mgr, sess] = pausedSession();

  const result = mgr.applyApprovalReceipt(sess, approvalReceipt(sess));

  expect(result.state).toBe(SessionState.NEGOTIATING);
  expect(result.current_turn).toBe("responder");
  expect(result.approval_receipt_id).toBe("urn:concordia:receipt:test");
  expect(result.approval_pending_offer_hash).toBeNull();
  expect((sess.approval_receipts[sess.approval_receipts.length - 1] as Dict).id).toBe(
    "urn:concordia:receipt:test",
  );
});

test("es256 signed approval receipt releases pause", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, {
    approverDid: ES256_APPROVER_DID,
    signWith: ES256_APPROVER_PRIVATE_KEY,
  });
  expect((receipt.signature as Dict).alg).toBe("ES256");

  expect(mgr.applyApprovalReceipt(sess, receipt).state).toBe(SessionState.NEGOTIATING);
});

test("approval receipt naming the approver by did url releases pause", () => {
  const [mgr, sess] = pausedSession([`${APPROVER_DID}#key-1`]);
  const receipt = approvalReceipt(sess, { approverDid: `${APPROVER_DID}#key-1` });

  expect(mgr.applyApprovalReceipt(sess, receipt).state).toBe(SessionState.NEGOTIATING);
});

test("approval receipt may reference the mandate hash with the a2cn prefix", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, {
    mandateRef: `a2cn:mandate:${hashObject(sess.approval_pending_mandate)}`,
  });
  expect(mgr.applyApprovalReceipt(sess, receipt).state).toBe(SessionState.NEGOTIATING);
});

test("approval receipt may reference the mandate by its id", () => {
  const [mgr, sess] = pausedSession(undefined, { mandate_id: "m-2026-04-19-0007" });

  const receipt = approvalReceipt(sess, { mandateRef: "a2cn:mandate:m-2026-04-19-0007" });

  expect(mgr.applyApprovalReceipt(sess, receipt).state).toBe(SessionState.NEGOTIATING);
});

test("audit metadata defaults to autonomous without approval receipts", () => {
  const [mgr, sess] = newSession();
  const withdrawal = {
    message_type: "withdrawal",
    message_id: "withdrawal-autonomous",
    session_id: sess.session_id,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "tc-agent",
    timestamp: "2026-03-24T10:02:00Z",
    reason_code: "STRATEGY_DECISION",
  };
  const signedWithdrawal = signDecline(withdrawal, INITIATOR_PRIVATE_KEY, `${INITIATOR_DID}#key-1`);
  mgr.processMessage(sess, signedWithdrawal);

  const metadata = generateAuditLog(sess).audit_metadata as Dict;

  expect(metadata.ai_system_involved).toBe(true);
  expect(metadata.human_oversight_present).toBe(false);
  expect(metadata.autonomous_decision).toBe(true);
});

test("audit metadata reflects human approval receipt", () => {
  const [mgr, sess] = pausedSession();
  mgr.applyApprovalReceipt(sess, approvalReceipt(sess));

  const metadata = generateAuditLog(sess).audit_metadata as Dict;

  expect(metadata.ai_system_involved).toBe(true);
  expect(metadata.human_oversight_present).toBe(true);
  expect(metadata.autonomous_decision).toBe(false);
});

// --- Refusals. Each leaves the session paused with no receipt recorded. ---

test("unsigned approval receipt is refused", () => {
  const [mgr, sess] = pausedSession();
  expect(refused(mgr, sess, approvalReceipt(sess, { signWith: null }))).toBe("APPROVAL_RECEIPT_UNSIGNED");
});

test("approval receipt with malformed signature member is refused", () => {
  const [mgr, sess] = pausedSession();
  for (const bad of ["not-an-object", { alg: "Ed25519" }, { alg: "Ed25519", value: "" }, { value: "abc" }]) {
    const receipt = approvalReceipt(sess);
    receipt.signature = bad;
    expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_UNSIGNED");
  }
});

test("approval receipt with corrupted signature is refused", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess);
  const value = (receipt.signature as Dict).value as string;
  (receipt.signature as Dict).value = (value[0] !== "A" ? "A" : "B") + value.slice(1);
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNATURE_INVALID");
});

test("approval receipt altered after signing is refused", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess);
  (receipt.scope as Dict).amount = "1.00 USD";
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNATURE_INVALID");
});

test("approval receipt signed by a key outside the approver did document is refused", () => {
  const [mgr, sess] = pausedSession();
  const { privateKey: strayPrivateKey } = generateEd25519Keypair();
  const receipt = approvalReceipt(sess, { signWith: strayPrivateKey });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNATURE_INVALID");
});

test("approval receipt signed by another did is refused", () => {
  // Signed with a key another DID controls, naming an authorised approver.
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { signWith: OTHER_PRIVATE_KEY });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNATURE_INVALID");
});

test("approval receipt key listed by the approver but controlled by another did is refused", () => {
  // The approver's document lists another DID's method; that key does not count.
  const [mgr, sess] = pausedSession();
  const foreign = makeDidDocument(OTHER_DID, "key-1", publicKeyToJwk(OTHER_PUBLIC_KEY));
  const approverDoc = makeDidDocument(APPROVER_DID, "unused", publicKeyToJwk(APPROVER_PUBLIC_KEY));
  approverDoc.verificationMethod = foreign.verificationMethod;
  approverDoc.assertionMethod = [`${OTHER_DID}#key-1`];
  approverDoc.authentication = [`${OTHER_DID}#key-1`];
  mgr.registerDidDocument(APPROVER_DID, approverDoc);
  const receipt = approvalReceipt(sess, { signWith: OTHER_PRIVATE_KEY });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNER_MISMATCH");
});

test("approval receipt whose method names another controller is refused", () => {
  const [mgr, sess] = pausedSession();
  const approverDoc = makeDidDocument(APPROVER_DID, "key-1", publicKeyToJwk(OTHER_PUBLIC_KEY));
  ((approverDoc.verificationMethod as Dict[])[0] as Dict).controller = OTHER_DID;
  mgr.registerDidDocument(APPROVER_DID, approverDoc);
  const receipt = approvalReceipt(sess, { signWith: OTHER_PRIVATE_KEY });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNER_MISMATCH");
});

test("approval receipt from an approver with no resolvable did document is refused", () => {
  const [mgr, sess] = pausedSession(["did:example:unregistered"]);
  const receipt = approvalReceipt(sess, { approverDid: "did:example:unregistered" });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_KEY_UNRESOLVED");
});

test("approval receipt whose declared algorithm does not match the key is refused", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess);
  (receipt.signature as Dict).alg = "ES256";
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNATURE_INVALID");
});

test("validly signed approval receipt from an unauthorised approver is refused", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { approverDid: OTHER_DID, signWith: OTHER_PRIVATE_KEY });
  expect(refused(mgr, sess, receipt)).toBe("UNAUTHORIZED_APPROVER");
});

test("approver list given as a string authorises no one", () => {
  // Membership in a string would be a substring test: "did:web:approver.example"
  // is inside "did:web:approver.example.other". Only a list counts.
  const [mgr, sess] = pausedSession([]);
  (sess.approval_pending_mandate as Dict).approval_operator_dids = `${APPROVER_DID}.other`;
  const receipt = approvalReceipt(sess);
  expect(refused(mgr, sess, receipt)).toBe("UNAUTHORIZED_APPROVER");
});

test("approval receipt naming a non string approver is refused", () => {
  const [mgr, sess] = pausedSession();
  ((sess.approval_pending_mandate as Dict).approval_operator_dids as unknown[]).push(["did:web:listed.example"]);
  const receipt = approvalReceipt(sess, { approverDid: ["did:web:listed.example"] as unknown as string });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_INVALID");
});

for (const [label, mutate] of [
  ["scope is a list", (r: Dict) => { r.scope = ["x"]; }],
  ["scope is null", (r: Dict) => { r.scope = null; }],
  ["session reference id is a list", (r: Dict) => { ((r.references as Dict[])[0] as Dict).id = ["a"]; }],
  ["mandate reference id is an object", (r: Dict) => { ((r.references as Dict[])[1] as Dict).id = { a: 1 }; }],
  ["decision only at the top level", (r: Dict) => { (r.scope as Dict).decision = null; r.decision = "approve"; }],
  ["offer hash only at the top level", (r: Dict) => { delete (r.scope as Dict).offer_hash; r.offer_hash = "x"; }],
] as const) {
  test(`malformed signed receipt is refused cleanly: ${label}`, () => {
    // Validly signed by the approver, but malformed: a clean refusal, never a crash.
    const [mgr, sess] = pausedSession();
    const receipt = approvalReceipt(sess, { signWith: null });
    mutate(receipt);
    receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
    expect(["APPROVAL_RECEIPT_INVALID", "OFFER_HASH_MISMATCH"]).toContain(refused(mgr, sess, receipt));
  });
}

for (const [label, editDocument, code] of [
  ["document is not an object", () => ["not", "an", "object"], "APPROVAL_RECEIPT_KEY_UNRESOLVED"],
  ["relationship lists are not lists", (d: Dict) => ({ ...d, assertionMethod: 5, authentication: 5 }), "APPROVAL_RECEIPT_KEY_UNRESOLVED"],
  ["method controller is null", (d: Dict) => ({ ...d, verificationMethod: [{ ...(d.verificationMethod as Dict[])[0], controller: null }] }), "APPROVAL_RECEIPT_SIGNER_MISMATCH"],
] as const) {
  test(`malformed approver did document is refused cleanly: ${label}`, () => {
    const [mgr, sess] = pausedSession();
    const document = makeDidDocument(APPROVER_DID, "key-1", publicKeyToJwk(APPROVER_PUBLIC_KEY));
    mgr.registerDidDocument(APPROVER_DID, editDocument(document) as Dict);
    expect(refused(mgr, sess, approvalReceipt(sess))).toBe(code);
  });
}

// --- An approver is never the paused party; separation is by DID, not by key. ---

test("paused agent cannot approve its own act even with a valid signature", () => {
  const [mgr, sess] = pausedSession([INITIATOR_DID]);
  const receipt = approvalReceipt(sess, { approverDid: INITIATOR_DID, signWith: INITIATOR_PRIVATE_KEY });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SELF_APPROVAL");
});

test("paused agent named by did url cannot approve its own act", () => {
  const [mgr, sess] = pausedSession([`${INITIATOR_DID}#key-1`]);
  const receipt = approvalReceipt(sess, {
    approverDid: `${INITIATOR_DID}#key-1`,
    signWith: INITIATOR_PRIVATE_KEY,
  });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SELF_APPROVAL");
});

test("principal that is the agent itself cannot release the pause", () => {
  // principal_did is the agent's own DID and the only authorised approver: the
  // pause cannot be released, by the agent or by anyone else.
  const [mgr, sess] = pausedSession([]);
  expect((sess.approval_pending_mandate as Dict).principal_did).toBe(INITIATOR_DID);
  const byAgent = approvalReceipt(sess, { approverDid: INITIATOR_DID, signWith: INITIATOR_PRIVATE_KEY });
  expect(refused(mgr, sess, byAgent)).toBe("APPROVAL_RECEIPT_SELF_APPROVAL");
  const byOperator = approvalReceipt(sess);
  expect(refused(mgr, sess, byOperator)).toBe("UNAUTHORIZED_APPROVER");
});

test("principal with its own did releases the pause", () => {
  const [mgr, sess] = pausedSession([]);
  (sess.approval_pending_mandate as Dict).principal_did = APPROVER_DID;
  const receipt = approvalReceipt(sess);
  expect(mgr.applyApprovalReceipt(sess, receipt).state).toBe(SessionState.NEGOTIATING);
});

test("accepting party cannot approve its own paused acceptance", () => {
  const [mgr, sess] = pausedAcceptance();
  ((sess.approval_pending_mandate as Dict).approval_operator_dids as string[]).push(RESPONDER_DID);
  const receipt = approvalReceipt(sess, { approverDid: RESPONDER_DID, signWith: RESPONDER_PRIVATE_KEY });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SELF_APPROVAL");
  expect(sess._final_acceptance).toBeNull();
});

test("pause stays when the paused party cannot be determined", () => {
  const [mgr, sess] = pausedSession();
  sess.approval_pending_sender_role = null;
  expect(refused(mgr, sess, approvalReceipt(sess))).toBe("APPROVAL_RECEIPT_SELF_APPROVAL");
});

test("approval receipt without a mandate reference is refused", () => {
  const [mgr, sess] = pausedSession();
  expect(refused(mgr, sess, approvalReceipt(sess, { mandateRef: null }))).toBe("APPROVAL_RECEIPT_INVALID");
});

test("approval receipt naming a different mandate is refused", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { mandateRef: "a2cn:mandate:some-other-mandate" });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_INVALID");
});

test("expired approval receipt rejected", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { expiresAt: "2020-01-01T00:00:00Z" });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_EXPIRED");
});

test("approval receipt without expiry is refused", () => {
  const [mgr, sess] = pausedSession();
  expect(refused(mgr, sess, approvalReceipt(sess, { expiresAt: null }))).toBe("APPROVAL_RECEIPT_INVALID");
});

test("approval receipt with an expiry lacking a timezone is refused", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { expiresAt: "2030-01-01T00:00:00" });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_INVALID");
});

test("approval receipt wrong offer hash rejected", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { offerHash: "sha256:wrong" });
  expect(refused(mgr, sess, receipt)).toBe("OFFER_HASH_MISMATCH");
});

test("approval receipt wrong session reference rejected", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { signWith: null });
  ((receipt.references as Dict[])[0] as Dict).id = "a2cn:session:different-session";
  receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_INVALID");
});

test("approval receipt requires approval state", () => {
  const [mgr, sess] = newSession();
  registerApprovers(mgr);
  sess.approval_pending_mandate = approvalMandate();

  const exc = expectA2CNError(() => mgr.applyApprovalReceipt(sess, approvalReceipt(sess)));

  expect(exc.code).toBe("NOT_IN_AWAITING_HUMAN_APPROVAL");
});

function pausedAcceptance(): [SessionManager, Session, Dict, Dict] {
  const [mgr, sess] = newSession();
  registerApprovers(mgr);
  sess.responder_mandate = approvalMandate(RESPONDER_DID);
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);
  const acceptance = makeAcceptance(sess, offer, "acc-requires-approval");
  const result = mgr.processMessage(sess, acceptance);
  expect(result.state).toBe(SessionState.AWAITING_HUMAN_APPROVAL);
  return [mgr, sess, offer, acceptance];
}

test("threshold crossing acceptance enters awaiting human approval then completes", () => {
  const [mgr, sess, offer, acceptance] = pausedAcceptance();
  expect(sess.current_turn).toBe("responder");
  expect(sess.approval_pending_offer_id).toBe(offer.message_id);
  expect(sess.approval_pending_offer_hash).toBe(offer.protocol_act_hash);
  expect(sess._final_acceptance).toBeNull();

  const approved = mgr.applyApprovalReceipt(sess, approvalReceipt(sess));

  expect(approved.state).toBe(SessionState.COMPLETED);
  expect(approved.current_turn).toBe("none");
  expect(approved.approval_receipt_id).toBe("urn:concordia:receipt:test");
  expect(sess._final_acceptance).toEqual(acceptance);
});

test("unsigned approval receipt does not complete a paused acceptance", () => {
  const [mgr, sess] = pausedAcceptance();

  expect(refused(mgr, sess, approvalReceipt(sess, { signWith: null }))).toBe("APPROVAL_RECEIPT_UNSIGNED");
  expect(sess._final_acceptance).toBeNull();
  expect(sess.state).not.toBe(SessionState.COMPLETED);
});

// --- A receipt releases at most one pause in a session. ---

/** Both parties' mandates are referenced as "group-default" and authorise one approver. */
function pausedOfferThenAcceptanceSharingAMandateReference(): [SessionManager, Session, Dict] {
  const [mgr, sess] = newSession();
  registerApprovers(mgr);
  sess.initiator_mandate = approvalMandate(INITIATOR_DID, undefined, { mandate_id: "group-default" });
  sess.responder_mandate = approvalMandate(RESPONDER_DID, undefined, { mandate_id: "group-default" });
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);
  return [mgr, sess, offer];
}

/** Like refused, for a session that already holds one released receipt. */
function refusedAfterUse(mgr: SessionManager, sess: Session, receipt: Dict): string {
  const held = [...sess.approval_receipts];
  const exc = expectA2CNError(() => mgr.applyApprovalReceipt(sess, receipt));
  expect(sess.state).toBe(SessionState.AWAITING_HUMAN_APPROVAL);
  expect(sess.approval_receipts).toEqual(held);
  return exc.code;
}

test("a receipt cannot release a second pause in the session", () => {
  const [mgr, sess, offer] = pausedOfferThenAcceptanceSharingAMandateReference();
  const first = approvalReceipt(sess, { mandateRef: "a2cn:mandate:group-default" });
  expect(mgr.applyApprovalReceipt(sess, first).state).toBe(SessionState.NEGOTIATING);

  const acceptance = makeAcceptance(sess, offer, "acc-requires-approval");
  expect(mgr.processMessage(sess, acceptance).state).toBe(SessionState.AWAITING_HUMAN_APPROVAL);
  expect(refusedAfterUse(mgr, sess, first)).toBe("APPROVAL_RECEIPT_REPLAYED");
  expect(sess._final_acceptance).toBeNull();
});

test("a receipt with a reused id is refused even with new content", () => {
  const [mgr, sess, offer] = pausedOfferThenAcceptanceSharingAMandateReference();
  mgr.applyApprovalReceipt(sess, approvalReceipt(sess, { mandateRef: "a2cn:mandate:group-default" }));
  mgr.processMessage(sess, makeAcceptance(sess, offer, "acc-requires-approval"));
  const sameId = approvalReceipt(sess, {
    mandateRef: "a2cn:mandate:group-default",
    expiresAt: "2031-01-01T00:00:00Z",
  });
  expect(refusedAfterUse(mgr, sess, sameId)).toBe("APPROVAL_RECEIPT_REPLAYED");
});

test("a fresh receipt releases the second pause", () => {
  const [mgr, sess, offer] = pausedOfferThenAcceptanceSharingAMandateReference();
  mgr.applyApprovalReceipt(sess, approvalReceipt(sess, { mandateRef: "a2cn:mandate:group-default" }));
  mgr.processMessage(sess, makeAcceptance(sess, offer, "acc-requires-approval"));
  const fresh = approvalReceipt(sess, {
    mandateRef: "a2cn:mandate:group-default",
    receiptId: "urn:concordia:receipt:second",
  });
  expect(mgr.applyApprovalReceipt(sess, fresh).state).toBe(SessionState.COMPLETED);
});

// --- expires_at: the one Section 14.1 form, identical in both implementations. ---

for (const expiresAt of [
  "2030-01-01t00:00:00Z",
  "2030-01-01T00:00:00z",
  "2030-01-01T24:00:00Z",
  "2030-01-01T00:00:60Z",
  "2030-04-31T00:00:00Z",
  "2030-02-30T00:00:00Z",
  "2031-02-29T00:00:00Z",
  "2030-01-01T00:00:00+01:60",
  "0000-01-01T00:00:00Z",
  "2030-01-01T00:00:00.1234567Z",
]) {
  test(`expiry outside the section 14.1 form is refused: ${expiresAt}`, () => {
    const [mgr, sess] = pausedSession();
    expect(refused(mgr, sess, approvalReceipt(sess, { expiresAt }))).toBe("APPROVAL_RECEIPT_INVALID");
  });
}

for (const expiresAt of ["2032-02-29T00:00:00Z", "2030-01-01T00:00:00.123456-05:30", "2099-12-31T23:59:59+14:00"]) {
  test(`expiry in the section 14.1 form is accepted: ${expiresAt}`, () => {
    const [mgr, sess] = pausedSession();
    expect(mgr.applyApprovalReceipt(sess, approvalReceipt(sess, { expiresAt })).state).toBe(SessionState.NEGOTIATING);
  });
}

for (const receiptHash of ["absent", null] as const) {
  test(`a pause with no recorded offer hash cannot be released: receipt hash ${receiptHash}`, () => {
    const [mgr, sess] = pausedSession();
    sess.approval_pending_offer_hash = null;
    const receipt = approvalReceipt(sess, { signWith: null });
    if (receiptHash === "absent") {
      delete (receipt.scope as Dict).offer_hash;
    } else {
      (receipt.scope as Dict).offer_hash = receiptHash;
    }
    receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
    expect(refused(mgr, sess, receipt)).toBe("OFFER_HASH_MISMATCH");
  });
}

// --- Which approver a receipt names, and which list authorises it. ---

for (const [label, present] of [
  ["empty string", ""],
  ["null", null],
  ["zero", 0],
  ["false", false],
  ["empty list", []],
  ["empty object", {}],
] as const) {
  test(`a present but invalid approver_did does not fall back: ${label}`, () => {
    const [mgr, sess] = pausedSession();
    const receipt = approvalReceipt(sess, { signWith: null });
    receipt.approver_did = present;
    receipt.operator_did = APPROVER_DID;
    receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
    expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_INVALID");
  });
}

test("operator_did names the approver when approver_did is absent", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { signWith: null });
  delete receipt.approver_did;
  receipt.operator_did = APPROVER_DID;
  receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
  expect(mgr.applyApprovalReceipt(sess, receipt).state).toBe(SessionState.NEGOTIATING);
});

test("an empty operator list falls through to the trusted list", () => {
  const [mgr, sess] = pausedSession([]);
  (sess.approval_pending_mandate as Dict).trusted_approver_dids = [APPROVER_DID];
  expect(mgr.applyApprovalReceipt(sess, approvalReceipt(sess)).state).toBe(SessionState.NEGOTIATING);
});

// --- Key resolution within the approver's DID document. ---

function approverDocument(
  methods: Array<[string, KeyObject]>,
  { assertion, authentication }: { assertion?: unknown[]; authentication?: unknown[] } = {},
): Dict {
  const vms = methods.map(([frag, key]) => ({
    id: `${APPROVER_DID}#${frag}`,
    type: "JsonWebKey2020",
    controller: APPROVER_DID,
    publicKeyJwk: publicKeyToJwk(key),
  }));
  const ids = vms.map((vm) => vm.id);
  return {
    id: APPROVER_DID,
    verificationMethod: vms,
    assertionMethod: assertion ?? ids,
    authentication: authentication ?? ids,
  };
}

test("a did url approver must sign with the method it names", () => {
  const [mgr, sess] = pausedSession([`${APPROVER_DID}#key-1`]);
  const { publicKey: siblingPublic } = generateEd25519Keypair();
  mgr.registerDidDocument(APPROVER_DID, approverDocument([["key-1", siblingPublic], ["key-2", APPROVER_PUBLIC_KEY]]));
  const receipt = approvalReceipt(sess, { approverDid: `${APPROVER_DID}#key-1` });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNATURE_INVALID");
});

test("an embedded method under another did does not count even without a controller", () => {
  const [mgr, sess] = pausedSession();
  const foreign = { id: `${OTHER_DID}#key-1`, type: "JsonWebKey2020", publicKeyJwk: publicKeyToJwk(OTHER_PUBLIC_KEY) };
  mgr.registerDidDocument(APPROVER_DID, { id: APPROVER_DID, verificationMethod: [], assertionMethod: [foreign], authentication: [] });
  const receipt = approvalReceipt(sess, { signWith: OTHER_PRIVATE_KEY });
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNER_MISMATCH");
});

test("a key listed only under authentication can sign", () => {
  const [mgr, sess] = pausedSession();
  mgr.registerDidDocument(APPROVER_DID, approverDocument([["key-1", APPROVER_PUBLIC_KEY]], { assertion: [] }));
  expect(mgr.applyApprovalReceipt(sess, approvalReceipt(sess)).state).toBe(SessionState.NEGOTIATING);
});

test("any controlled key in a multi key document can sign", () => {
  const [mgr, sess] = pausedSession();
  const { publicKey: unrelatedPublic } = generateEd25519Keypair();
  mgr.registerDidDocument(APPROVER_DID, approverDocument([["key-1", unrelatedPublic], ["key-2", APPROVER_PUBLIC_KEY]]));
  expect(mgr.applyApprovalReceipt(sess, approvalReceipt(sess)).state).toBe(SessionState.NEGOTIATING);
});

test("a paused party with an empty did cannot be released", () => {
  const [mgr, sess] = pausedSession();
  sess.initiator_info = { ...sess.initiator_info, did: "" }; // a copy: the object is shared
  expect(refused(mgr, sess, approvalReceipt(sess))).toBe("APPROVAL_RECEIPT_SELF_APPROVAL");
});

test("an es256 signature labelled ed25519 is refused", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { approverDid: ES256_APPROVER_DID, signWith: ES256_APPROVER_PRIVATE_KEY });
  (receipt.signature as Dict).alg = "Ed25519";
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_SIGNATURE_INVALID");
});

test("es256 receipt signatures always have a low s", () => {
  const order = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
  for (let i = 0; i < 64; i++) {
    const der = Buffer.from(signApprovalReceipt({ id: `receipt-${i}` }, ES256_APPROVER_PRIVATE_KEY).value, "base64url");
    const rLen = der[3];
    const sLen = der[5 + rLen];
    const s = BigInt("0x" + der.subarray(6 + rLen, 6 + rLen + sLen).toString("hex"));
    expect(s <= order / 2n).toBe(true);
  }
});

test("a receipt with an unpaired surrogate cannot be signed or verified", () => {
  const receipt: Dict = { id: "x", note: "\ud800" };
  expect(() => signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY)).toThrow();
  receipt.signature = { alg: "Ed25519", value: "A".repeat(86) };
  expect(verifyApprovalReceiptSignature(receipt, APPROVER_PUBLIC_KEY)).toBe(false);
});

// --- A receipt names the party whose act it approves (one party's act, once). ---

test("a fresh receipt for the initiators offer does not release the responders acceptance", () => {
  // Shared approver, identically referenced mandates: the two pauses carry the
  // same offer hash, and only the named paused party tells them apart.
  const [mgr, sess, offer] = pausedOfferThenAcceptanceSharingAMandateReference();
  mgr.applyApprovalReceipt(sess, approvalReceipt(sess, { mandateRef: "a2cn:mandate:group-default" }));
  mgr.processMessage(sess, makeAcceptance(sess, offer, "acc-requires-approval"));
  const forTheOffer = approvalReceipt(sess, {
    mandateRef: "a2cn:mandate:group-default",
    receiptId: "urn:concordia:receipt:retry",
    pausedParty: INITIATOR_DID,
  });
  expect(refusedAfterUse(mgr, sess, forTheOffer)).toBe("APPROVAL_RECEIPT_INVALID");
  expect(sess._final_acceptance).toBeNull();
});

test("a receipt that names no paused party is refused", () => {
  const [mgr, sess] = pausedSession();
  expect(refused(mgr, sess, approvalReceipt(sess, { pausedParty: null }))).toBe("APPROVAL_RECEIPT_INVALID");
});

test("a receipt that names another party as paused is refused", () => {
  const [mgr, sess] = pausedSession();
  expect(refused(mgr, sess, approvalReceipt(sess, { pausedParty: RESPONDER_DID }))).toBe("APPROVAL_RECEIPT_INVALID");
});

test("a receipt that also names another party as paused is refused", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { signWith: null });
  (receipt.references as Dict[]).push({ type: "paused_party", id: RESPONDER_DID, relationship: "approves" });
  receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_INVALID");
});

// --- Single use, by id or by signed content. ---

function pauseOf(sess: Session): Dict {
  return {
    hash: sess.approval_pending_offer_hash,
    mandate: sess.approval_pending_mandate,
    role: sess.approval_pending_sender_role,
  };
}

/** Re-enter the same pause, as Section 14.2 allows when a receipt expires before release. */
function pauseAgain(sess: Session, pause: Dict): void {
  sess.state = SessionState.AWAITING_HUMAN_APPROVAL;
  sess.approval_pending_offer_hash = pause.hash as string;
  sess.approval_pending_mandate = pause.mandate as Dict;
  sess.approval_pending_sender_role = pause.role as string;
}

function reuseAfterRelease(build: (receipt: Dict) => Dict): [SessionManager, Session, Dict] {
  const [mgr, sess] = pausedSession();
  const pause = pauseOf(sess);
  const first = approvalReceipt(sess, { signWith: null });
  delete first.id;
  first.signature = signApprovalReceipt(first, APPROVER_PRIVATE_KEY);
  mgr.applyApprovalReceipt(sess, first);
  pauseAgain(sess, pause);
  return [mgr, sess, build(first)];
}

test("a receipt without an id is still single use", () => {
  const [mgr, sess, again] = reuseAfterRelease((r) => structuredClone(r));
  expect(refusedAfterUse(mgr, sess, again)).toBe("APPROVAL_RECEIPT_REPLAYED");
});

test("a replayed receipt with a re padded signature is still single use", () => {
  const [mgr, sess, again] = reuseAfterRelease((r) => {
    const copy = structuredClone(r);
    (copy.signature as Dict).value = ((copy.signature as Dict).value as string).replace(/=+$/, "");
    return copy;
  });
  expect(refusedAfterUse(mgr, sess, again)).toBe("APPROVAL_RECEIPT_REPLAYED");
});

test("a receipt reusing an id through approval_receipt_id is single use", () => {
  const [mgr, sess] = pausedSession();
  const pause = pauseOf(sess);
  mgr.applyApprovalReceipt(sess, approvalReceipt(sess, { receiptId: "urn:concordia:receipt:shared" }));
  pauseAgain(sess, pause);
  const again = approvalReceipt(sess, { signWith: null, expiresAt: "2031-01-01T00:00:00Z" });
  delete again.id;
  again.approval_receipt_id = "urn:concordia:receipt:shared";
  again.signature = signApprovalReceipt(again, APPROVER_PRIVATE_KEY);
  expect(refusedAfterUse(mgr, sess, again)).toBe("APPROVAL_RECEIPT_REPLAYED");
});

test("a pause with an empty recorded offer hash cannot be released", () => {
  const [mgr, sess] = pausedSession();
  sess.approval_pending_offer_hash = "";
  const receipt = approvalReceipt(sess, { signWith: null });
  (receipt.scope as Dict).offer_hash = "";
  receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
  expect(refused(mgr, sess, receipt)).toBe("OFFER_HASH_MISMATCH");
});

test("a non object receipt is refused by the library", () => {
  const [mgr, sess] = pausedSession();
  for (const receipt of [[], "receipt", 5, null]) {
    const exc = expectA2CNError(() => mgr.checkApprovalReceipt(sess, receipt as unknown as Dict));
    expect(exc.code).toBe("APPROVAL_RECEIPT_INVALID");
  }
});

// --- expires_at: calendar, offset arithmetic and fractions. ---

for (const expiresAt of ["2100-02-29T00:00:00Z", "2030-01-01T00:00:00+24:00", "2030-01-01T00:00:00-99:00"]) {
  test(`more expiry forms outside section 14.1 are refused: ${expiresAt}`, () => {
    const [mgr, sess] = pausedSession();
    expect(refused(mgr, sess, approvalReceipt(sess, { expiresAt }))).toBe("APPROVAL_RECEIPT_INVALID");
  });
}

/** `ms` written as a date-time in the given offset, to the second. */
function inOffset(ms: number, offsetMinutes: number): string {
  const local = new Date(Math.floor(ms / 1000) * 1000 + offsetMinutes * 60_000);
  const pad = (n: number) => String(n).padStart(2, "0");
  const sign = offsetMinutes < 0 ? "-" : "+";
  const abs = Math.abs(offsetMinutes);
  return (
    `${local.getUTCFullYear()}-${pad(local.getUTCMonth() + 1)}-${pad(local.getUTCDate())}` +
    `T${pad(local.getUTCHours())}:${pad(local.getUTCMinutes())}:${pad(local.getUTCSeconds())}` +
    `${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`
  );
}

for (const offsetMinutes of [330, -540, 1439, -1439]) {
  test(`expiry offsets are applied with the right sign: ${offsetMinutes}`, () => {
    const now = Date.now();
    let [mgr, sess] = pausedSession();
    const ahead = approvalReceipt(sess, { expiresAt: inOffset(now + 2 * 3_600_000, offsetMinutes) });
    expect(mgr.applyApprovalReceipt(sess, ahead).state).toBe(SessionState.NEGOTIATING);
    [mgr, sess] = pausedSession();
    const behind = approvalReceipt(sess, { expiresAt: inOffset(now - 2 * 3_600_000, offsetMinutes) });
    expect(refused(mgr, sess, behind)).toBe("APPROVAL_RECEIPT_EXPIRED");
  });
}

test("a fractional expiry is compared to the millisecond", () => {
  const clock = vi.spyOn(Date, "now");
  try {
    clock.mockReturnValue(Date.parse("2030-01-01T00:00:00.400Z"));
    let [mgr, sess] = pausedSession();
    expect(mgr.applyApprovalReceipt(sess, approvalReceipt(sess, { expiresAt: "2030-01-01T00:00:00.500Z" })).state).toBe(
      SessionState.NEGOTIATING,
    );
    clock.mockReturnValue(Date.parse("2030-01-01T00:00:00.600Z"));
    [mgr, sess] = pausedSession();
    expect(refused(mgr, sess, approvalReceipt(sess, { expiresAt: "2030-01-01T00:00:00.500Z" }))).toBe(
      "APPROVAL_RECEIPT_EXPIRED",
    );
  } finally {
    clock.mockRestore();
  }
});

test("expiry within the same millisecond is not yet expired", () => {
  // Both implementations compare whole milliseconds.
  const clock = vi.spyOn(Date, "now").mockReturnValue(Date.parse("2030-01-01T00:00:00.000Z"));
  try {
    const [mgr, sess] = pausedSession();
    const receipt = approvalReceipt(sess, { expiresAt: "2030-01-01T00:00:00.000400Z" });
    expect(mgr.applyApprovalReceipt(sess, receipt).state).toBe(SessionState.NEGOTIATING);
  } finally {
    clock.mockRestore();
  }
});

// --- Nesting depth, and unpaired surrogates anywhere. ---

function nested(depth: number): Dict {
  const value: Dict = {};
  let inner = value;
  for (let i = 1; i < depth; i++) {
    inner.n = {};
    inner = inner.n as Dict;
  }
  return value;
}

test("a receipt at the depth limit signs and one deeper does not", () => {
  const atLimit: Dict = { id: "deep", payload: nested(63) }; // the receipt object is level 1
  atLimit.signature = signApprovalReceipt(atLimit, APPROVER_PRIVATE_KEY);
  expect(verifyApprovalReceiptSignature(atLimit, APPROVER_PUBLIC_KEY)).toBe(true);
  const tooDeep: Dict = { id: "deeper", payload: nested(64) };
  expect(() => signApprovalReceipt(tooDeep, APPROVER_PRIVATE_KEY)).toThrow();
  tooDeep.signature = atLimit.signature;
  expect(verifyApprovalReceiptSignature(tooDeep, APPROVER_PUBLIC_KEY)).toBe(false);
});

for (const [label, receipt] of [
  ["lone low surrogate", { id: "x", note: "\udc00" }],
  ["surrogate in a member name", { id: "x", ["\ud800key"]: 1 }],
] as const) {
  test(`unpaired surrogates are refused anywhere: ${label}`, () => {
    expect(() => signApprovalReceipt({ ...receipt }, APPROVER_PRIVATE_KEY)).toThrow();
  });
}

for (const [label, oddId] of [
  ["number", 5],
  ["object", { a: 1 }],
  ["array", ["x"]],
  ["boolean", true],
] as const) {
  test(`a non string receipt id is not recorded: ${label}`, () => {
    const [mgr, sess] = pausedSession();
    const receipt = approvalReceipt(sess, { signWith: null });
    receipt.id = oddId;
    receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
    expect(mgr.applyApprovalReceipt(sess, receipt).approval_receipt_id).toBeNull();
  });
}

// --- paused_party is matched exactly, as one string, on a typed entry with an id. ---

for (const named of [`${INITIATOR_DID}#key-1`, INITIATOR_DID.toUpperCase(), ` ${INITIATOR_DID} `]) {
  test(`paused party must be named exactly: ${JSON.stringify(named)}`, () => {
    const [mgr, sess] = pausedSession();
    expect(refused(mgr, sess, approvalReceipt(sess, { pausedParty: named }))).toBe("APPROVAL_RECEIPT_INVALID");
  });
}

for (const entryType of ["xpaused_party", "paused_party_extra", "Paused_Party"]) {
  test(`only an entry of type paused_party counts: ${entryType}`, () => {
    const [mgr, sess] = pausedSession();
    const receipt = approvalReceipt(sess, { signWith: null, pausedParty: null });
    (receipt.references as Dict[]).push({ type: entryType, id: INITIATOR_DID, relationship: "approves" });
    receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
    expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_INVALID");
  });
}

test("a paused party entry without an id is refused even beside a correct one", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { signWith: null });
  (receipt.references as Dict[]).push({ type: "paused_party", relationship: "approves" });
  receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
  expect(refused(mgr, sess, receipt)).toBe("APPROVAL_RECEIPT_INVALID");
});

// --- Depth counts arrays and the signature member; id selection order. ---

function nestedArrays(depth: number): unknown[] {
  const value: unknown[] = [];
  let inner = value;
  for (let i = 1; i < depth; i++) {
    const next: unknown[] = [];
    inner.push(next);
    inner = next;
  }
  return value;
}

test("depth counts arrays too", () => {
  const atLimit: Dict = { id: "arrays", payload: nestedArrays(63) };
  atLimit.signature = signApprovalReceipt(atLimit, APPROVER_PRIVATE_KEY);
  expect(verifyApprovalReceiptSignature(atLimit, APPROVER_PUBLIC_KEY)).toBe(true);
  expect(() => signApprovalReceipt({ id: "arrays", payload: nestedArrays(64) }, APPROVER_PRIVATE_KEY)).toThrow();
});

test("depth counts the signature member", () => {
  const receipt: Dict = { id: "deep-signature" };
  receipt.signature = { ...signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY), x: nested(200) };
  expect(verifyApprovalReceiptSignature(receipt, APPROVER_PUBLIC_KEY)).toBe(false);
});

test("an empty id falls back to approval_receipt_id", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { signWith: null, receiptId: "" });
  receipt.approval_receipt_id = "urn:concordia:receipt:fallback";
  receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
  expect(mgr.applyApprovalReceipt(sess, receipt).approval_receipt_id).toBe("urn:concordia:receipt:fallback");
});

test("id is read before approval_receipt_id", () => {
  const [mgr, sess] = pausedSession();
  const receipt = approvalReceipt(sess, { signWith: null, receiptId: "urn:concordia:receipt:primary" });
  receipt.approval_receipt_id = "urn:concordia:receipt:secondary";
  receipt.signature = signApprovalReceipt(receipt, APPROVER_PRIVATE_KEY);
  expect(mgr.applyApprovalReceipt(sess, receipt).approval_receipt_id).toBe("urn:concordia:receipt:primary");
});
