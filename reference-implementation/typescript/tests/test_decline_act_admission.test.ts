/**
 * What a receiver admits on the two decline paths (Sections 7.5, 7.6).
 *
 * decline-act-admission.json pins two rules, and both suites run every case in
 * it through the state machine.
 *
 * A present signature is always checked. The signed-act guard used to ask
 * whether the signature field was truthy, so an empty string or a zero was read
 * as "unsigned" and skipped the check that a present signature makes mandatory.
 * The act then entered the message log as one the evidence record's classifier
 * calls signed but that cannot verify. A party's own decline must now be signed,
 * so an absent field is refused as well, like any other missing signature; the
 * unsigned path belongs only to an act observed from a party that does not
 * sign, which does not pass through the state machine.
 *
 * A withdrawal carries a valid round_number: the round in progress, so 1
 * before any offer. It is part of the common header
 * every signed act covers and withdrawal.schema.json requires it
 * unconditionally, but the runtime checked round_number on the other act types
 * only, so it accepted a withdrawal the published schema refuses. This suite has
 * no JSON Schema validator, so the Python suite checks each case against the
 * schema; this one holds the runtime to the same schema_valid column.
 *
 * The Python suite runs the same cases.
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { generateKeypair, hashObject, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import {
  PROTOCOL_ACT_VERSION,
  SIGNED_ACT_SIGNATURE_FIELDS,
  Withdrawal,
  signedActHash,
  type Dict,
} from "../src/a2cn/messages.js";
import { A2CNError, Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument, signDecline } from "./conftest.js";
import { REPO_ROOT } from "./support/paths.js";

const VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "decline-act-admission.json"), "utf-8"),
) as Dict;
const WITHDRAWAL_SCHEMA = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "schemas", "withdrawal.schema.json"), "utf-8"),
) as Dict;
const SESSION_FIXTURE = VECTOR.session as Dict;
const ACTS = VECTOR.acts as Record<string, Dict>;
const SIGNATURE_FIELDS = VECTOR.signature_fields as Record<string, string>;
const SIGNATURE_CASES = (VECTOR.signature_presence as Dict).cases as Dict[];
const ROUND_CASES = (VECTOR.withdrawal_round_number as Dict).cases as Dict[];
const UNSIGNED_REFUSAL = (VECTOR.withdrawal_round_number as Dict).unsigned_refusal as Dict;

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();

const INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;

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
  session_id: SESSION_FIXTURE.session_id,
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

/** The initiator's signed round-1 offer at sequence_number 1. */
function makeOffer(sessionId: string): Dict {
  const timestamp = "2026-03-24T10:01:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const terms = { total_value: 9_500_000, currency: "USD" };
  const pah = hashObject({
    protocol_version: "0.3",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    message_type: "offer",
    sender_did: INITIATOR_DID,
    timestamp,
    expires_at: expiresAt,
    terms,
  });
  return {
    message_type: "offer",
    message_id: randomUUID(),
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "agent",
    sender_verification_method: INITIATOR_VM,
    timestamp,
    expires_at: expiresAt,
    terms,
    protocol_act_hash: pah,
    protocol_act_signature: signJws(pah, INITIATOR_PRIVATE_KEY, INITIATOR_VM),
  };
}

/** The vector's session: the initiator's signed round-1 offer, processed. */
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
  const sessionId = SESSION_FIXTURE.session_id as string;
  const sess = mgr.createSession(sessionId, SESSION_INIT, SESSION_ACK, "2026-03-24T10:00:00Z");
  // The fixtures use a historical created_at; a large timeout keeps the session
  // from expiring mid-test.
  sess.session_timeout_seconds = 86400 * 365 * 100;
  mgr.processMessage(sess, makeOffer(sessionId));
  expect(sess.state).toBe(SESSION_FIXTURE.state_before);
  return [mgr, sess];
}

function hasOwn(obj: Dict, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function assertVerdict(mgr: SessionManager, sess: Session, act: Dict, testCase: Dict): void {
  if (testCase.accepted) {
    mgr.processMessage(sess, act);
    expect(sess.state).toBe(testCase.state_after);
    expect(sess._message_log).toContain(act);
    return;
  }
  const stateBefore = sess.state;
  let caught: unknown = null;
  try {
    mgr.processMessage(sess, act);
  } catch (exc) {
    caught = exc;
  }
  expect(caught, "expected an A2CNError, but the call succeeded").toBeInstanceOf(A2CNError);
  const err = caught as A2CNError;
  expect([err.code, err.message]).toEqual([testCase.error_code, testCase.error_message]);
  expect(sess.state).toBe(stateBefore);
  expect(sess._message_log).not.toContain(act);
}

test("the vector matches this implementation and its fixtures", () => {
  expect(SIGNATURE_FIELDS).toEqual({
    rejection: SIGNED_ACT_SIGNATURE_FIELDS.rejection,
    withdrawal: SIGNED_ACT_SIGNATURE_FIELDS.withdrawal,
  });
  expect(SESSION_FIXTURE.initiator_did).toBe(INITIATOR_DID);
  expect(SESSION_FIXTURE.responder_did).toBe(RESPONDER_DID);
  for (const act of Object.values(ACTS)) {
    expect(act.session_id).toBe(SESSION_FIXTURE.session_id);
    expect(act.sender_did).toBe(RESPONDER_DID);
    expect(act.sender_verification_method).toBe(SESSION_FIXTURE.responder_verification_method);
  }
});

// ---------------------------------------------------------------------------
// A present signature is always checked
// ---------------------------------------------------------------------------

for (const testCase of SIGNATURE_CASES) {
  test(`signature presence: ${testCase.name}`, () => {
    const [mgr, sess] = sessionAtNegotiating();
    const act = structuredClone(ACTS[testCase.act_type as string]);
    const field = SIGNATURE_FIELDS[testCase.act_type as string];
    if (hasOwn(testCase, "signature")) {
      act[field] = testCase.signature;
    } else {
      delete act[field];
    }

    assertVerdict(mgr, sess, act, testCase);
  });
}

// ---------------------------------------------------------------------------
// A withdrawal carries a valid round_number, and schema and runtime agree
// ---------------------------------------------------------------------------

function withdrawalFor(testCase: Dict, signed: boolean): Dict {
  const act = structuredClone(ACTS.withdrawal);
  if (hasOwn(testCase, "round_number")) {
    act.round_number = testCase.round_number;
  } else {
    delete act.round_number;
  }
  if (!signed) {
    delete act.sender_verification_method;
    return act;
  }
  const vm = act.sender_verification_method as string;
  // An act that does not rebuild has no hash to sign, so it is signed over a
  // stand-in payload, exactly as a sender that stripped or mangled the field
  // would have to.
  const payloadHash = signedActHash(act, {
    versionWhenAbsent: PROTOCOL_ACT_VERSION,
  }) ?? "0".repeat(43);
  act.withdrawal_signature = signJws(payloadHash, RESPONDER_PRIVATE_KEY, vm);
  return act;
}

/**
 * The verdict for a case, signed or not. A party's own withdrawal must be
 * signed, so unsigned it is always refused: for its invalid round_number first,
 * when it has one, and otherwise as unsigned.
 */
function expectedFor(testCase: Dict, signed: boolean): Dict {
  return signed || !testCase.accepted ? testCase : UNSIGNED_REFUSAL;
}

for (const testCase of ROUND_CASES) {
  for (const signed of [false, true]) {
    test(`withdrawal round_number: ${testCase.name} (${signed ? "signed" : "unsigned"})`, () => {
      const [mgr, sess] = sessionAtNegotiating();
      const act = withdrawalFor(testCase, signed);
      const expected = expectedFor(testCase, signed);

      expect(testCase.schema_valid).toBe(testCase.accepted);
      expect(expected.schema_valid).toBe(expected.accepted);
      assertVerdict(mgr, sess, act, expected);
    });
  }
}

test("withdrawal round_number: the schema requires what the cases assume", () => {
  // The Python suite validates every case against the schema; this pins the
  // schema's own statement of the rule, so a schema edit surfaces here too.
  expect(WITHDRAWAL_SCHEMA.required).toContain("round_number");
  expect((WITHDRAWAL_SCHEMA.properties as Dict).round_number).toMatchObject({
    type: "integer",
    minimum: 1,
  });
});

test("withdrawal round_number cases cover both verdicts", () => {
  // A vector whose cases all agree on one verdict would prove nothing.
  expect(new Set(ROUND_CASES.map((c) => c.accepted))).toEqual(new Set([true, false]));
  expect(ROUND_CASES.some((c) => !hasOwn(c, "round_number"))).toBe(true);
});

// ---------------------------------------------------------------------------
// The library's own Withdrawal type builds what the runtime admits
// ---------------------------------------------------------------------------

test("the withdrawal type builds a withdrawal the runtime accepts", () => {
  // The message class is the other producer of a withdrawal, so it is held to
  // the same rule as the wire: its output must carry round_number.
  const [mgr, sess] = sessionAtNegotiating();
  const act = new Withdrawal({
    message_type: "withdrawal",
    message_id: "typed-wd-1",
    session_id: sess.session_id,
    round_number: 1,
    sequence_number: 2,
    sender_did: RESPONDER_DID,
    sender_agent_id: "acme-agent",
    timestamp: "2026-03-24T10:05:00Z",
    reason_code: "STRATEGY_DECISION",
    in_reply_to: "offer-1",
  }).toDict();
  const signed = signDecline(act, RESPONDER_PRIVATE_KEY, RESPONDER_VM);

  mgr.processMessage(sess, signed);

  expect(act.round_number).toBe(1);
  expect(sess.state).toBe(SessionState.WITHDRAWN);
});

test("the withdrawal type carries round 1 before any offer", () => {
  const mgr = new SessionManager();
  mgr.registerDidDocument(
    INITIATOR_DID,
    makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUBLIC_KEY)),
  );
  const sess = mgr.createSession(
    SESSION_FIXTURE.session_id as string,
    SESSION_INIT,
    SESSION_ACK,
    "2026-03-24T10:00:00Z",
  );
  sess.session_timeout_seconds = 86400 * 365 * 100;
  const act = new Withdrawal({
    message_type: "withdrawal",
    message_id: "typed-wd-pre-offer",
    session_id: sess.session_id,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "tc-agent",
    timestamp: "2026-03-24T10:02:00Z",
    reason_code: "NO_REASON_GIVEN",
  }).toDict();
  const signed = signDecline(act, INITIATOR_PRIVATE_KEY, INITIATOR_VM);

  mgr.processMessage(sess, signed);

  expect(act.round_number).toBe(1);
  expect(sess.state).toBe(SessionState.WITHDRAWN);
});
