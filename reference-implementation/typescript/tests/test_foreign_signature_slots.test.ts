/**
 * An act carries no signature field but its own (Section 7.3.1).
 *
 * The state machine used to look only at the signature field of the act's own
 * type, so an act carrying another type's field — an offer with a
 * rejection_signature, a withdrawal with an acceptance_signature — was admitted
 * with that field never looked at. The evidence record reads every signature
 * field as a signature claim, so the session's record then failed
 * verification, or, beside a valid own signature, could not be generated at
 * all. Every act type had the hole. foreign-signature-slots.json pins the
 * refusal and shows, for every case, that the session still produces an
 * evidence record that verifies.
 *
 * The Python suite runs the same cases.
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { generateKeypair, hashObject, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import {
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
} from "../src/a2cn/evidence.js";
import {
  PROTOCOL_ACT_VERSION,
  RECORD_ENTRY_WIRE_FIELDS,
  RECORD_ENTRY_WRAPPER_FIELDS,
  RESERVED_WIRE_KEYS,
  SIGNED_ACT_HEADER_FIELDS,
  SIGNED_ACT_PAYLOAD_FIELDS,
  SIGNED_ACT_SIGNATURE_FIELDS,
  signedActHash,
  type Dict,
} from "../src/a2cn/messages.js";
import { A2CNError, Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument, signDecline } from "./conftest.js";
import { REPO_ROOT } from "./support/paths.js";

const VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "foreign-signature-slots.json"), "utf-8"),
) as Dict;
const SESSION_FIXTURE = VECTOR.session as Dict;
const CASES = VECTOR.cases as Dict[];

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();

const INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;

const DID_DOCUMENTS: Record<string, Dict> = {
  [INITIATOR_DID]: makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUBLIC_KEY)),
  [RESPONDER_DID]: makeDidDocument(
    RESPONDER_DID,
    "key-2026-01",
    publicKeyToJwk(RESPONDER_PUBLIC_KEY),
  ),
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

function freshSession(): [SessionManager, Session] {
  const mgr = new SessionManager();
  mgr.registerDidDocument(INITIATOR_DID, DID_DOCUMENTS[INITIATOR_DID]);
  mgr.registerDidDocument(RESPONDER_DID, DID_DOCUMENTS[RESPONDER_DID]);
  const sess = mgr.createSession(
    SESSION_FIXTURE.session_id as string,
    SESSION_INIT,
    SESSION_ACK,
    "2026-03-24T10:00:00Z",
  );
  // The fixtures use a historical created_at; a large timeout keeps the session
  // from expiring mid-test.
  sess.session_timeout_seconds = 86400 * 365 * 100;
  return [mgr, sess];
}

/** A real signed offer or counteroffer. */
function makeOffer(sessionId: string, seq: number, rnd: number, senderDid: string, type = "offer"): Dict {
  const timestamp = "2026-03-24T10:01:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const terms = { total_value: 9_500_000, currency: "USD" };
  const pah = hashObject({
    protocol_version: "0.3",
    session_id: sessionId,
    round_number: rnd,
    sequence_number: seq,
    message_type: type,
    sender_did: senderDid,
    timestamp,
    expires_at: expiresAt,
    terms,
  });
  const [privateKey, vm] =
    senderDid === INITIATOR_DID
      ? [INITIATOR_PRIVATE_KEY, INITIATOR_VM]
      : [RESPONDER_PRIVATE_KEY, RESPONDER_VM];
  return {
    message_type: type,
    message_id: randomUUID(),
    session_id: sessionId,
    round_number: rnd,
    sequence_number: seq,
    sender_did: senderDid,
    sender_agent_id: "agent",
    sender_verification_method: vm,
    timestamp,
    expires_at: expiresAt,
    terms,
    protocol_act_hash: pah,
    protocol_act_signature: signJws(pah, privateKey, vm),
  };
}

function makeAcceptance(sess: Session, offer: Dict): Dict {
  const acceptance: Dict = {
    message_type: "acceptance",
    message_id: "acc-1",
    session_id: sess.session_id,
    in_reply_to: offer.message_id,
    round_number: offer.round_number,
    sequence_number: sess.sequence_number + 1,
    accepted_offer_id: offer.message_id,
    accepted_protocol_act_hash: offer.protocol_act_hash,
    sender_did: RESPONDER_DID,
    sender_agent_id: "acme-agent",
    sender_verification_method: RESPONDER_VM,
    timestamp: "2026-03-24T10:05:00Z",
  };
  acceptance.acceptance_signature = signJws(
    signedActHash(acceptance, { versionWhenAbsent: PROTOCOL_ACT_VERSION }) as string,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
  );
  return acceptance;
}

function makeDecline(sessionId: string, actType: string, signed: boolean): Dict {
  const act: Dict = {
    message_type: actType,
    message_id: randomUUID(),
    session_id: sessionId,
    round_number: 1,
    sequence_number: 2,
    sender_did: RESPONDER_DID,
    sender_agent_id: "acme-agent",
    timestamp: "2026-03-24T10:05:00Z",
  };
  if (actType === "rejection") {
    act.rejected_offer_id = "offer-1";
    act.reason_code = "PRICE_TOO_HIGH";
  } else {
    act.reason_code = "STRATEGY_DECISION";
  }
  if (signed) {
    act.sender_verification_method = RESPONDER_VM;
    act[SIGNED_ACT_SIGNATURE_FIELDS[actType]] = signJws(
      signedActHash(act, { versionWhenAbsent: PROTOCOL_ACT_VERSION }) as string,
      RESPONDER_PRIVATE_KEY,
      RESPONDER_VM,
    );
  }
  return act;
}

function hasOwn(obj: Dict, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** Build the case's act as act_setup says, then add its stray field. */
function actFor(mgr: SessionManager, sess: Session, testCase: Dict): Dict {
  const actType = testCase.act_type as string;
  let act: Dict;
  if (actType === "offer") {
    act = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  } else {
    const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
    mgr.processMessage(sess, offer);
    if (actType === "counteroffer") {
      act = makeOffer(sess.session_id, 2, 2, RESPONDER_DID, "counteroffer");
    } else if (actType === "acceptance") {
      act = makeAcceptance(sess, offer);
    } else {
      act = makeDecline(sess.session_id, actType, testCase.signed as boolean);
    }
  }
  if (hasOwn(testCase, "stray_field")) {
    act[testCase.stray_field as string] = testCase.stray_value;
  }
  return act;
}

function closeAndRecord(mgr: SessionManager, sess: Session): Dict {
  if (!sess.isTerminal()) {
    const closer: Dict = {
      message_type: "withdrawal",
      message_id: randomUUID(),
      session_id: sess.session_id,
      round_number: Math.max(sess.round_number, 1),
      sequence_number: sess.sequence_number + 1,
      sender_did: INITIATOR_DID,
      timestamp: "2026-03-24T10:09:00Z",
      reason_code: "STRATEGY_DECISION",
    };
    mgr.processMessage(sess, signDecline(closer, INITIATOR_PRIVATE_KEY, INITIATOR_VM));
  }
  return generateSessionEvidenceRecord(sess, {
    producerPrivateKey: INITIATOR_PRIVATE_KEY,
    producerDid: INITIATOR_DID,
    producerAgentId: "buyer-agent",
    producerVerificationMethod: INITIATOR_VM,
  });
}

test("the vector matches this implementation and its fixtures", () => {
  expect(VECTOR.signature_fields).toEqual(SIGNED_ACT_SIGNATURE_FIELDS);
  expect(SESSION_FIXTURE.initiator_did).toBe(INITIATOR_DID);
  expect(SESSION_FIXTURE.responder_did).toBe(RESPONDER_DID);
  for (const testCase of CASES) {
    if (hasOwn(testCase, "stray_field")) {
      expect(testCase.stray_field).not.toBe(
        SIGNED_ACT_SIGNATURE_FIELDS[testCase.act_type as string],
      );
    }
  }
  // Every act type has a control and at least one refused case.
  for (const actType of Object.keys(SIGNED_ACT_SIGNATURE_FIELDS)) {
    const verdicts = new Set(CASES.filter((c) => c.act_type === actType).map((c) => c.accepted));
    expect(verdicts, actType).toEqual(new Set([true, false]));
  }
});

for (const testCase of CASES) {
  test(`foreign signature slot: ${testCase.name}`, () => {
    const [mgr, sess] = freshSession();
    const act = actFor(mgr, sess, testCase);

    if (testCase.accepted) {
      mgr.processMessage(sess, act);
      expect(sess.state).toBe(testCase.state_after);
      expect(sess._message_log).toContain(act);
    } else {
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

    const record = closeAndRecord(mgr, sess);
    expect(verifySessionEvidenceRecord(record, DID_DOCUMENTS)).toBe(testCase.record_verifies);
  });
}

// ---------------------------------------------------------------------------
// The evidence record's own members are reserved on the wire (Section 7.3.1)
// ---------------------------------------------------------------------------

const RESERVED_VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "reserved-wire-keys.json"), "utf-8"),
) as Dict;
const RESERVED_CASES = RESERVED_VECTOR.cases as Dict[];
const RESERVED_VALUES = RESERVED_VECTOR.values as Dict;

/** The case's act, signed, with its reserved key set as the vector says. */
function reservedAct(mgr: SessionManager, sess: Session, testCase: Dict): Dict {
  const stray: Dict = { act_type: testCase.act_type, signed: true };
  if (hasOwn(testCase, "reserved_key")) {
    stray.stray_field = testCase.reserved_key;
    stray.stray_value = structuredClone(RESERVED_VALUES[testCase.reserved_key as string]);
  }
  return actFor(mgr, sess, stray);
}

test("the reserved keys are the record entry's own members", () => {
  // Derived, not copied: the entry's field set is the wire part plus the reserved
  // part, the two do not overlap, and no field an act carries on the wire is
  // reserved. The evidence module builds its entry set from these two parts.
  const entry = new Set([...RECORD_ENTRY_WIRE_FIELDS, ...RECORD_ENTRY_WRAPPER_FIELDS]);
  expect(entry).toEqual(
    new Set([
      "sequence_number",
      "round_number",
      "message_type",
      "message_id",
      "sender_did",
      "timestamp",
      "source_protocol",
      "act",
      "act_hash",
      "sender_verification_method",
      "signature_type",
      "signature",
      "attribution",
    ]),
  );
  expect([...RECORD_ENTRY_WIRE_FIELDS].filter((k) => RECORD_ENTRY_WRAPPER_FIELDS.has(k))).toEqual(
    [],
  );
  expect(RESERVED_WIRE_KEYS).toEqual(RECORD_ENTRY_WRAPPER_FIELDS);
  expect([...RESERVED_WIRE_KEYS].sort()).toEqual(RESERVED_VECTOR.reserved_keys);
  const carried = new Set<string>([
    ...SIGNED_ACT_HEADER_FIELDS,
    ...Object.values(SIGNED_ACT_SIGNATURE_FIELDS),
    ...Object.values(SIGNED_ACT_PAYLOAD_FIELDS).flat(),
    ...RECORD_ENTRY_WIRE_FIELDS,
    "protocol_act_hash",
    "in_reply_to",
    "sender_agent_id",
  ]);
  expect([...RESERVED_WIRE_KEYS].filter((k) => carried.has(k))).toEqual([]);
});

for (const testCase of RESERVED_CASES) {
  test(`reserved key: ${testCase.name}`, () => {
    const [mgr, sess] = freshSession();
    const act = reservedAct(mgr, sess, testCase);

    expect(testCase.schema_valid).toBe(testCase.accepted);
    if (testCase.accepted) {
      mgr.processMessage(sess, act);
      expect(sess.state).toBe(testCase.state_after);
      expect(sess._message_log).toContain(act);
    } else {
      const stateBefore = sess.state;
      let caught: unknown = null;
      try {
        mgr.processMessage(sess, act);
      } catch (exc) {
        caught = exc;
      }
      expect(caught).toBeInstanceOf(A2CNError);
      const err = caught as A2CNError;
      expect([err.code, err.message]).toEqual([testCase.error_code, testCase.error_message]);
      expect(sess.state).toBe(stateBefore);
      expect(sess._message_log).not.toContain(act);
    }

    const record = closeAndRecord(mgr, sess);
    expect(verifySessionEvidenceRecord(record, DID_DOCUMENTS)).toBe(testCase.record_verifies);
    // Every act the record vouches for is one the runtime admitted, and none is
    // an unsigned observation.
    for (const entry of record.acts as Dict[]) {
      expect(entry.attribution).toBe("verified_signature");
      expect(Object.keys(entry.act as Dict).filter((k) => RESERVED_WIRE_KEYS.has(k))).toEqual([]);
    }
  });
}

test("a retransmission carrying a reserved key is not admitted", () => {
  // The idempotency cache answers a repeated message_id before validation runs,
  // so the altered repeat gets the original's response. It is not processed: the
  // log still holds only the act the runtime first admitted.
  const [mgr, sess] = freshSession();
  const offer = makeOffer(sess.session_id, 1, 1, INITIATOR_DID);
  const first = mgr.processMessage(sess, offer);
  const repeat = { ...structuredClone(offer), act: { message_type: "offer" } };

  expect(mgr.processMessage(sess, repeat)).toEqual(first);
  expect(sess._message_log).toEqual([offer]);
  expect(sess._message_log.every((m) => !("act" in m))).toBe(true);
});

// ---------------------------------------------------------------------------
// A key reached through the prototype is the key
// ---------------------------------------------------------------------------
//
// JSON yields only own properties, but a library caller can hand in an object
// whose prototype carries a reserved key. Every property read sees it, so the
// runtime refuses it as it refuses the own key, and the evidence reader takes
// an entry's wrapper and metadata from own properties only. Python has no
// counterpart: a dict has no prototype.

const SUBSTITUTE: Dict = { message_type: "withdrawal", reason_code: "SUBSTITUTED" };

function inheriting(proto: Dict, own: Dict): Dict {
  return Object.assign(Object.create(proto) as Dict, own);
}

for (const actType of ["rejection", "withdrawal"]) {
  for (const key of [...RESERVED_WIRE_KEYS].sort()) {
    test(`reserved key inherited through the prototype: ${actType} + ${key}`, () => {
      const [mgr, sess] = freshSession();
      mgr.processMessage(sess, makeOffer(sess.session_id, 1, 1, INITIATOR_DID));
      const value = key === "act" ? SUBSTITUTE : structuredClone(RESERVED_VALUES[key]);
      const own = makeDecline(sess.session_id, actType, true);
      const act = inheriting({ [key]: value }, own);
      expect(hasOwn(act, key)).toBe(false);

      let caught: unknown = null;
      try {
        mgr.processMessage(sess, act);
      } catch (exc) {
        caught = exc;
      }
      expect(caught, "expected an A2CNError, but the call succeeded").toBeInstanceOf(A2CNError);
      const err = caught as A2CNError;
      expect([err.code, err.message]).toEqual([
        "INVALID_REQUEST",
        `${actType} carries ${key}, which is reserved for the evidence record`,
      ]);
      expect(sess.state).toBe(SessionState.NEGOTIATING);
      expect(sess._message_log).not.toContain(act);

      const record = closeAndRecord(mgr, sess);
      expect(verifySessionEvidenceRecord(record, DID_DOCUMENTS)).toBe(true);
      for (const entry of record.acts as Dict[]) {
        expect(entry.attribution).toBe("verified_signature");
        expect(entry.act).not.toEqual(SUBSTITUTE);
      }
    });
  }
}

function markTimedOut(session: Session): void {
  session.state = SessionState.TIMED_OUT;
  session.current_turn = "none";
  session.terminal_reason = "session_timeout";
  session.terminal_message_id = null;
  session.state_updated_at = "2026-03-24T10:10:00Z";
}

/** The entry an observed item becomes, after the session's own offer. */
function observedEntry(item: Dict): Dict {
  const [mgr, sess] = freshSession();
  mgr.processMessage(sess, makeOffer(sess.session_id, 1, 1, INITIATOR_DID));
  markTimedOut(sess);
  const record = generateSessionEvidenceRecord(sess, {
    producerPrivateKey: INITIATOR_PRIVATE_KEY,
    producerDid: INITIATOR_DID,
    producerAgentId: "buyer-agent",
    producerVerificationMethod: INITIATOR_VM,
    observedActs: [item],
  });
  expect(verifySessionEvidenceRecord(record, DID_DOCUMENTS)).toBe(true);
  return (record.acts as Dict[])[(record.acts as Dict[]).length - 1];
}

test("an observed act's inherited act is not a wrapper", () => {
  const own = makeDecline("observed-session", "withdrawal", false);
  const entry = observedEntry(inheriting({ act: SUBSTITUTE }, own));
  expect(entry).toEqual(observedEntry(structuredClone(own)));
  expect(entry.act).not.toEqual(expect.objectContaining(SUBSTITUTE));
  expect(entry.act_hash).toBe(hashObject(entry.act));
});

test("an observed act that states its version: an inherited act is not a wrapper", () => {
  // An act that states protocol_version reaches the reader as the caller's own
  // object, prototype and all, so the reader's own-property check is what keeps
  // the inherited act out.
  const own = { ...makeDecline("observed-session", "withdrawal", false), protocol_version: "0.3" };
  const entry = observedEntry(inheriting({ act: SUBSTITUTE }, own));
  expect(entry).toEqual(observedEntry(structuredClone(own)));
  expect(entry.act).toEqual(own);
  expect(entry.act_hash).toBe(hashObject(own));
});

test("an observed wrapper's inherited metadata is inert", () => {
  const own = makeDecline("observed-session", "withdrawal", false);
  const inherited: Dict = {
    signature_type: "withdrawal_signature",
    signature: "not-a-signature",
    attribution: "verified_signature",
    source_protocol: "inherited",
    money_basis: { label: "inherited" },
  };
  const entry = observedEntry(inheriting(inherited, { act: structuredClone(own) }));
  expect(entry).toEqual(observedEntry({ act: structuredClone(own) }));
  expect(entry.attribution).toBe("unsigned_observation");
  expect(hasOwn(entry, "money_basis")).toBe(false);
});
