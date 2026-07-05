/** Tests for a2cn/session — state machine, turn-taking, idempotency. */

import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";

import { Session, SessionManager, SessionState, A2CNError } from "../src/a2cn/session.js";
import { generateKeypair, hashObject, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import { generateAuditLog } from "../src/a2cn/record.js";
import type { Dict } from "../src/a2cn/messages.js";
import { makeDidDocument } from "./conftest.js";

const INITIATOR_DID = "did:web:techcorp.example";
const RESPONDER_DID = "did:web:acme-corp.com";

const SESSION_INIT: Dict = {
  message_type: "session_init",
  message_id: "init-msg-id",
  protocol_version: "0.2",
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
    protocol_version: "0.2",
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
  const payload = {
    session_id: acceptance.session_id,
    round_number: acceptance.round_number,
    sequence_number: acceptance.sequence_number,
    accepted_offer_id: acceptance.accepted_offer_id,
    accepted_protocol_act_hash: acceptance.accepted_protocol_act_hash,
  };
  acceptance.acceptance_signature = signJws(
    hashObject(payload),
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
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "tc-agent",
    timestamp: "2026-03-24T10:02:00Z",
    reason_code: "STRATEGY_DECISION",
  };
  mgr.processMessage(sess, withdrawal);
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
  mgr.processMessage(sess, rejection);
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

function approvalReceipt(
  sess: Session,
  options: { offerHash?: string | null; approverDid?: string; expiresAt?: string } = {},
): Dict {
  const {
    offerHash = null,
    approverDid = INITIATOR_DID,
    expiresAt = "2030-01-01T00:00:00Z",
  } = options;
  return {
    artifact_type: "ApprovalReceipt",
    id: "urn:concordia:receipt:test",
    scope: {
      decision: "approve",
      offer_hash: offerHash ?? sess.approval_pending_offer_hash,
      amount: "95000.00 USD",
      threshold_crossed: "90000.00 USD",
    },
    references: [
      {
        type: "negotiation_session",
        id: `a2cn:session:${sess.session_id}`,
        relationship: "approves",
      },
    ],
    approver_did: approverDid,
    expires_at: expiresAt,
  };
}

test("threshold crossing offer enters awaiting human approval", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    requires_human_approval_above: 9_000_000,
  };

  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  const result = mgr.processMessage(sess, offer);

  expect(result.state).toBe(SessionState.AWAITING_HUMAN_APPROVAL);
  expect(sess.current_turn).toBe("initiator");
  expect(sess.approval_pending_offer_id).toBe(offer.message_id);
  expect(sess.approval_pending_offer_hash).toBe(offer.protocol_act_hash);
});

test("approval receipt releases pause and restores counterparty turn", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    requires_human_approval_above: 9_000_000,
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);

  const result = mgr.applyApprovalReceipt(sess, approvalReceipt(sess));

  expect(result.state).toBe(SessionState.NEGOTIATING);
  expect(result.current_turn).toBe("responder");
  expect(result.approval_receipt_id).toBe("urn:concordia:receipt:test");
  expect(result.approval_pending_offer_hash).toBeNull();
  expect((sess.approval_receipts[sess.approval_receipts.length - 1] as Dict).id).toBe(
    "urn:concordia:receipt:test",
  );
});

test("audit metadata defaults to autonomous without approval receipts", () => {
  const [mgr, sess] = newSession();
  const withdrawal = {
    message_type: "withdrawal",
    message_id: "withdrawal-autonomous",
    session_id: sess.session_id,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "tc-agent",
    timestamp: "2026-03-24T10:02:00Z",
    reason_code: "STRATEGY_DECISION",
  };
  mgr.processMessage(sess, withdrawal);

  const metadata = generateAuditLog(sess).audit_metadata as Dict;

  expect(metadata.ai_system_involved).toBe(true);
  expect(metadata.human_oversight_present).toBe(false);
  expect(metadata.autonomous_decision).toBe(true);
});

test("audit metadata reflects human approval receipt", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    requires_human_approval_above: 9_000_000,
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);
  mgr.applyApprovalReceipt(sess, approvalReceipt(sess));

  const metadata = generateAuditLog(sess).audit_metadata as Dict;

  expect(metadata.ai_system_involved).toBe(true);
  expect(metadata.human_oversight_present).toBe(true);
  expect(metadata.autonomous_decision).toBe(false);
});

test("approval receipt wrong offer hash rejected", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    requires_human_approval_above: 9_000_000,
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);

  const err = expectA2CNError(() =>
    mgr.applyApprovalReceipt(sess, approvalReceipt(sess, { offerHash: "sha256:wrong" })),
  );

  expect(err.code).toBe("OFFER_HASH_MISMATCH");
});

test("approval receipt wrong session reference rejected", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    requires_human_approval_above: 9_000_000,
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);
  const receipt = approvalReceipt(sess);
  ((receipt.references as Dict[])[0] as Dict).id = "a2cn:session:different-session";

  const err = expectA2CNError(() => mgr.applyApprovalReceipt(sess, receipt));

  expect(err.code).toBe("APPROVAL_RECEIPT_INVALID");
});

test("expired approval receipt rejected", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    requires_human_approval_above: 9_000_000,
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);

  const err = expectA2CNError(() =>
    mgr.applyApprovalReceipt(sess, approvalReceipt(sess, { expiresAt: "2020-01-01T00:00:00Z" })),
  );

  expect(err.code).toBe("APPROVAL_RECEIPT_EXPIRED");
});

test("unauthorized approval receipt rejected", () => {
  const [mgr, sess] = newSession();
  sess.initiator_mandate = {
    mandate_type: "declared",
    principal_did: INITIATOR_DID,
    requires_human_approval_above: 9_000_000,
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);

  const err = expectA2CNError(() =>
    mgr.applyApprovalReceipt(
      sess,
      approvalReceipt(sess, { approverDid: "did:web:unauthorized.example" }),
    ),
  );

  expect(err.code).toBe("UNAUTHORIZED_APPROVER");
});

test("approval receipt requires approval state", () => {
  const [mgr, sess] = newSession();

  const err = expectA2CNError(() => mgr.applyApprovalReceipt(sess, approvalReceipt(sess)));

  expect(err.code).toBe("NOT_IN_AWAITING_HUMAN_APPROVAL");
});

test("threshold crossing acceptance enters awaiting human approval then completes", () => {
  const [mgr, sess] = newSession();
  sess.responder_mandate = {
    mandate_type: "declared",
    principal_did: RESPONDER_DID,
    requires_human_approval_above: 9_000_000,
  };
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  mgr.processMessage(sess, offer);

  const acceptance = makeAcceptance(sess, offer, "acc-requires-approval");

  const result = mgr.processMessage(sess, acceptance);
  expect(result.state).toBe(SessionState.AWAITING_HUMAN_APPROVAL);
  expect(result.current_turn).toBe("responder");
  expect(result.approval_pending_offer_id).toBe(offer.message_id);
  expect(result.approval_pending_offer_hash).toBe(offer.protocol_act_hash);
  expect(sess._final_acceptance).toBeNull();

  const receipt = approvalReceipt(sess, { approverDid: RESPONDER_DID });
  const approved = mgr.applyApprovalReceipt(sess, receipt);

  expect(approved.state).toBe(SessionState.COMPLETED);
  expect(approved.current_turn).toBe("none");
  expect(approved.approval_receipt_id).toBe("urn:concordia:receipt:test");
  expect(sess._final_acceptance).toEqual(acceptance);
});
