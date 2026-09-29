/**
 * The wire version a recorded act is rebuilt under (Section 7.3.1).
 *
 * A live act does not state its wire version on the wire, so which version its
 * signature is checked against depends on where the act is read:
 *
 *   - a live act is rebuilt under its session's negotiated version;
 *   - a recorded act that states a version is rebuilt under the version it states;
 *   - a recorded act that states none is rebuilt under the pinned "0.2".
 *
 * A SessionEvidenceRecord used to store its acts as they came off the wire, with
 * no version, and a verifier rebuilt them under whatever version it emitted.
 * Moving the emitted version would then have left every stored record
 * unverifiable. The generator now states each session act's version, and the
 * version-less reading is pinned, so a record verifies the same way under every
 * later emit version.
 *
 * session-evidence-record-wire-version.json pins all three. The Python suite
 * runs the same cases.
 */

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
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
} from "../src/a2cn/evidence.js";
import {
  LEGACY_VERSIONLESS_WIRE_VERSION,
  PROTOCOL_ACT_VERSION,
  SIGNED_ACT_SIGNATURE_FIELDS,
  signedActHash,
  type Dict,
} from "../src/a2cn/messages.js";
import { A2CNError, Session, SessionManager } from "../src/a2cn/session.js";
import { makeDidDocument } from "./conftest.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VECTOR = JSON.parse(
  readFileSync(
    join(REPO_ROOT, "spec", "test-vectors", "session-evidence-record-wire-version.json"),
    "utf-8",
  ),
) as Dict;
const DID_DOCUMENTS = VECTOR.did_documents as Record<string, Dict>;
const PRODUCER = VECTOR.producer as Dict;
const PRODUCER_KEY = privateKeyFromJwk(VECTOR.producer_private_jwk as Dict);
const CURRENT = VECTOR.current as Dict;
const SOURCE = CURRENT.session as Dict;
const EXPECTED = CURRENT.expected as Dict;
const LEGACY_RECORD = VECTOR.legacy_record as Dict;
const OBSERVED = VECTOR.observed as Dict;
const EDIT_CASES = VECTOR.edit_cases as Dict[];

function currentRecord(): Dict {
  return recordFor(SOURCE);
}

function recordFor(source: Dict, observedActs: Dict[] | null = null): Dict {
  const session = new Session({
    session_id: source.session_id as string,
    state: source.state as string,
    current_turn: "none",
    terminal_reason: source.terminal_reason as string,
    terminal_message_id: source.terminal_message_id as string,
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
    producerPrivateKey: PRODUCER_KEY,
    producerDid: PRODUCER.did as string,
    producerAgentId: PRODUCER.agent_id as string,
    producerVerificationMethod: PRODUCER.verification_method as string,
    observedActs,
  });
}

const BASES: Record<string, Dict> = {
  current: EXPECTED.record as Dict,
  legacy: LEGACY_RECORD,
  observed: (OBSERVED.expected as Dict).record as Dict,
};

function edited(testCase: Dict): Dict {
  const base = BASES[testCase.base as string];
  const record = structuredClone(base);
  const entry = (record.acts as Dict[])[testCase.act_index as number];
  const act = entry.act as Dict;
  if (testCase.remove_protocol_version) {
    delete act.protocol_version;
  } else {
    act.protocol_version = testCase.set_protocol_version;
  }
  entry.act_hash = hashObject(act);
  record.act_chain_hash = hashBytes(
    canonicalize((record.acts as Dict[]).map((e) => e.act_hash)),
  );
  record.record_hash = "";
  record.producer_signature = "";
  record.record_hash = hashObject(record);
  record.producer_signature = signJws(
    record.record_hash as string,
    PRODUCER_KEY,
    PRODUCER.verification_method as string,
  );
  return record;
}

test("the emit version is not the pinned legacy version", () => {
  // Without this, every legacy case below would pass by coincidence.
  expect(PROTOCOL_ACT_VERSION).toBe("0.3");
  expect(LEGACY_VERSIONLESS_WIRE_VERSION).toBe("0.2");
  expect((SOURCE.session_ack as Dict).protocol_version).toBe(PROTOCOL_ACT_VERSION);
});

// ---------------------------------------------------------------------------
// A new record states each session act's wire version, and verifies
// ---------------------------------------------------------------------------

test("a new record states each act's wire version and matches the vector", () => {
  const record = currentRecord();
  const acts = record.acts as Dict[];

  expect(acts.map((e) => (e.act as Dict).protocol_version)).toEqual(EXPECTED.stated_versions);
  expect(new Set(EXPECTED.stated_versions as string[])).toEqual(new Set([PROTOCOL_ACT_VERSION]));
  expect(record.record_version).toBe(EXPECTED.record_version);
  expect(acts.map((e) => e.act_hash)).toEqual(EXPECTED.act_hashes);
  expect(record.act_chain_hash).toBe(EXPECTED.act_chain_hash);
  expect(record.record_hash).toBe(EXPECTED.record_hash);
  expect(canonicalize(record).equals(canonicalize(EXPECTED.record))).toBe(true);
  expect(verifySessionEvidenceRecord(record, DID_DOCUMENTS)).toBe(true);
});

test("the session log itself is left as it came off the wire", () => {
  // The version is stated in the record, not written back into the session.
  currentRecord();
  expect((SOURCE.message_log as Dict[]).every((m) => !("protocol_version" in m))).toBe(true);
});

// ---------------------------------------------------------------------------
// A legacy record, whose acts state no version, still verifies
// ---------------------------------------------------------------------------

test("a legacy record whose acts state no version still verifies", () => {
  const acts = LEGACY_RECORD.acts as Dict[];
  expect(acts.every((e) => !("protocol_version" in (e.act as Dict)))).toBe(true);
  expect(acts.some((e) => e.signature)).toBe(true);
  expect(verifySessionEvidenceRecord(LEGACY_RECORD, DID_DOCUMENTS)).toBe(true);
});

// ---------------------------------------------------------------------------
// Each edit to a stated version reaches the vector's hash and verdict
// ---------------------------------------------------------------------------

for (const testCase of EDIT_CASES) {
  test(`an edited stated version: ${testCase.name}`, () => {
    const record = edited(testCase);

    expect(record.record_hash).toBe(testCase.resealed_record_hash);
    expect(verifySessionEvidenceRecord(record, DID_DOCUMENTS)).toBe(testCase.verifies);
  });
}

test("the edit cases cover both verdicts", () => {
  expect(new Set(EDIT_CASES.map((c) => c.verifies))).toEqual(new Set([true, false]));
});

// ---------------------------------------------------------------------------
// A live act is checked under its session's negotiated version
// ---------------------------------------------------------------------------

/** The vector's session, negotiated at the given version. */
function sessionAt(version: string, sessionId: string): [SessionManager, Session] {
  const manager = new SessionManager();
  for (const [did, document] of Object.entries(DID_DOCUMENTS)) {
    manager.registerDidDocument(did, document);
  }
  const init = { ...(SOURCE.session_init as Dict), protocol_version: version };
  const ack = { ...(SOURCE.session_ack as Dict), protocol_version: version };
  // A session at a superseded version exists only as a replay (Section 11.2.1).
  const session = manager.createSession(sessionId, init, ack, SOURCE.session_created_at as string, {
    legacyReplay: version !== PROTOCOL_ACT_VERSION,
  });
  session.session_timeout_seconds = 86400 * 365 * 100;
  return [manager, session];
}

/**
 * A round-1 offer signed under the given version, as it went on the wire.
 *
 * The 0.3 offer is the current session's; the 0.2 offer is the one the legacy
 * record holds, which states no version, exactly as it was received.
 */
function firstOffer(signedUnder: string): Dict {
  const offer =
    signedUnder === PROTOCOL_ACT_VERSION
      ? structuredClone((SOURCE.message_log as Dict[])[0])
      : structuredClone((LEGACY_RECORD.acts as Dict[])[0].act as Dict);
  expect(offer.message_type).toBe("offer");
  expect("protocol_version" in offer).toBe(false);
  return offer;
}

for (const negotiated of [PROTOCOL_ACT_VERSION, LEGACY_VERSIONLESS_WIRE_VERSION]) {
  test(`a live offer is checked under the negotiated version: ${negotiated}`, () => {
    for (const signedUnder of [PROTOCOL_ACT_VERSION, LEGACY_VERSIONLESS_WIRE_VERSION]) {
      const offer = firstOffer(signedUnder);
      const [manager, session] = sessionAt(negotiated, offer.session_id as string);
      expect(session.protocol_version).toBe(negotiated);
      if (signedUnder === negotiated) {
        manager.processMessage(session, offer);
        expect(session._message_log).toContain(offer);
      } else {
        let caught: unknown = null;
        try {
          manager.processMessage(session, offer);
        } catch (exc) {
          caught = exc;
        }
        expect(caught).toBeInstanceOf(A2CNError);
        expect((caught as A2CNError).code).toBe("INVALID_SIGNATURE");
      }
    }
  });
}

test("a live act stating another version is refused", () => {
  const offer = firstOffer(PROTOCOL_ACT_VERSION);
  const [manager, session] = sessionAt(PROTOCOL_ACT_VERSION, offer.session_id as string);
  offer.protocol_version = LEGACY_VERSIONLESS_WIRE_VERSION;

  let caught: unknown = null;
  try {
    manager.processMessage(session, offer);
  } catch (exc) {
    caught = exc;
  }
  expect(caught).toBeInstanceOf(A2CNError);
  expect([(caught as A2CNError).code, (caught as A2CNError).message]).toEqual([
    "PROTOCOL_VERSION_MISMATCH",
    "protocol_version does not match the session's negotiated version",
  ]);
  expect(session._message_log).not.toContain(offer);
});

test("a live act stating its own negotiated version is accepted", () => {
  const offer = firstOffer(PROTOCOL_ACT_VERSION);
  const [manager, session] = sessionAt(PROTOCOL_ACT_VERSION, offer.session_id as string);
  offer.protocol_version = PROTOCOL_ACT_VERSION;

  manager.processMessage(session, offer);

  expect(session._message_log).toContain(offer);
});

// ---------------------------------------------------------------------------
// A caller that signs a new act without naming a version fails closed
// ---------------------------------------------------------------------------

const BUYER_DID = "did:web:techcorp.example";
const SELLER_DID = "did:web:acme-corp.com";
const BUYER_VM = `${BUYER_DID}#key-1`;
const SELLER_VM = `${SELLER_DID}#key-1`;
const { privateKey: BUYER_KEY, publicKey: BUYER_PUBLIC } = generateKeypair();
const { privateKey: SELLER_KEY, publicKey: SELLER_PUBLIC } = generateKeypair();
const FAIL_CLOSED_PARAMS: Dict = {
  deal_type: "saas_renewal",
  currency: "USD",
  subject: "Test",
  max_rounds: 4,
  session_timeout_seconds: 3600,
  round_timeout_seconds: 900,
};
const TERMS: Dict = { total_value: 9_500_000, currency: "USD" };

/** Sign the act as a caller would, naming a version or (null) naming none. */
function signedAs(
  act: Dict,
  key: Parameters<typeof signJws>[1],
  vm: string,
  version: string | null,
): Dict {
  const copy = structuredClone(act);
  copy.sender_verification_method = vm;
  const payloadHash = (
    version === null ? signedActHash(copy) : signedActHash(copy, { versionWhenAbsent: version })
  ) as string;
  if (copy.message_type === "offer" || copy.message_type === "counteroffer") {
    copy.protocol_act_hash = payloadHash;
  }
  copy[SIGNED_ACT_SIGNATURE_FIELDS[copy.message_type as string]] = signJws(payloadHash, key, vm);
  return copy;
}

function failClosedSession(): [SessionManager, Session] {
  const manager = new SessionManager();
  manager.registerDidDocument(
    BUYER_DID,
    makeDidDocument(BUYER_DID, "key-1", publicKeyToJwk(BUYER_PUBLIC)),
  );
  manager.registerDidDocument(
    SELLER_DID,
    makeDidDocument(SELLER_DID, "key-1", publicKeyToJwk(SELLER_PUBLIC)),
  );
  const init: Dict = {
    message_type: "session_init",
    message_id: "fc-init-1",
    protocol_version: PROTOCOL_ACT_VERSION,
    session_params: FAIL_CLOSED_PARAMS,
    initiator: { did: BUYER_DID, verification_method: BUYER_VM },
    initiator_mandate: { mandate_type: "declared" },
  };
  const ack: Dict = {
    message_type: "session_ack",
    message_id: "fc-ack-1",
    session_id: "sess-fail-closed",
    protocol_version: PROTOCOL_ACT_VERSION,
    session_params_accepted: FAIL_CLOSED_PARAMS,
    responder: { did: SELLER_DID, verification_method: SELLER_VM },
    responder_mandate: { mandate_type: "declared" },
  };
  const session = manager.createSession("sess-fail-closed", init, ack, "2026-03-24T10:00:00Z");
  session.session_timeout_seconds = 86400 * 365 * 100;
  return [manager, session];
}

function offerAct(messageType: string, seq: number, rnd: number, did: string): Dict {
  return {
    message_type: messageType,
    message_id: `fc-${messageType}-${seq}`,
    session_id: "sess-fail-closed",
    round_number: rnd,
    sequence_number: seq,
    sender_did: did,
    sender_agent_id: "agent",
    timestamp: `2026-03-24T10:0${seq}:00Z`,
    expires_at: "2099-01-01T00:00:00Z",
    terms: TERMS,
  };
}

function sellerAct(messageType: string, firstOffer: Dict): Dict {
  const base: Dict = {
    message_type: messageType,
    message_id: `fc-${messageType}-2`,
    session_id: "sess-fail-closed",
    round_number: 1,
    sequence_number: 2,
    sender_did: SELLER_DID,
    sender_agent_id: "agent",
    timestamp: "2026-03-24T10:02:00Z",
  };
  if (messageType === "acceptance") {
    base.accepted_offer_id = firstOffer.message_id;
    base.accepted_protocol_act_hash = firstOffer.protocol_act_hash;
  } else if (messageType === "rejection") {
    base.rejected_offer_id = firstOffer.message_id;
    base.reason_code = "PRICE_TOO_HIGH";
  } else {
    base.reason_code = "STRATEGY_DECISION";
  }
  return base;
}

// [act type, error message when signed naming no version, state after the control]
const FAIL_CLOSED_CASES: [string, string, string][] = [
  ["offer", "Protocol act hash does not match message fields", "NEGOTIATING"],
  ["counteroffer", "Protocol act hash does not match message fields", "NEGOTIATING"],
  ["acceptance", "acceptance_signature payload does not match message fields", "COMPLETED"],
  ["rejection", "rejection_signature payload does not match message fields", "NEGOTIATING"],
  ["withdrawal", "withdrawal_signature payload does not match message fields", "WITHDRAWN"],
];

/** The act under test, after whatever the session needs first, signed as asked. */
function actFor(
  messageType: string,
  manager: SessionManager,
  session: Session,
  version: string | null,
): Dict {
  if (messageType === "offer") {
    return signedAs(offerAct("offer", 1, 1, BUYER_DID), BUYER_KEY, BUYER_VM, version);
  }
  const first = signedAs(
    offerAct("offer", 1, 1, BUYER_DID),
    BUYER_KEY,
    BUYER_VM,
    PROTOCOL_ACT_VERSION,
  );
  manager.processMessage(session, first);
  const act =
    messageType === "counteroffer"
      ? offerAct("counteroffer", 2, 2, SELLER_DID)
      : sellerAct(messageType, first);
  return signedAs(act, SELLER_KEY, SELLER_VM, version);
}

for (const [messageType, errorMessage, stateAfter] of FAIL_CLOSED_CASES) {
  const refusedName = "an act signed without naming a version is refused by a current session";
  test(`${refusedName}: ${messageType}`, () => {
    // The default is the pinned legacy version, so it must fail closed, not open. A
    // caller that signs a new act and names no version signs it under "0.2". A
    // session negotiated at the current version refuses it and never logs it.
    const [manager, session] = failClosedSession();
    const unnamed = actFor(messageType, manager, session, null);
    const stateBefore = session.state;
    const logBefore = [...session._message_log];

    let caught: unknown = null;
    try {
      manager.processMessage(session, unnamed);
    } catch (exc) {
      caught = exc;
    }
    expect(caught).toBeInstanceOf(A2CNError);
    expect([(caught as A2CNError).code, (caught as A2CNError).message]).toEqual([
      "INVALID_SIGNATURE",
      errorMessage,
    ]);
    expect(session.state).toBe(stateBefore);
    expect(session._message_log).toEqual(logBefore);
  });

  test(`the same act signed at the negotiated version is accepted: ${messageType}`, () => {
    const [manager, session] = failClosedSession();
    const named = actFor(messageType, manager, session, PROTOCOL_ACT_VERSION);

    manager.processMessage(session, named);

    expect(session.state).toBe(stateAfter);
    expect(session._message_log).toContain(named);
  });
}

// ---------------------------------------------------------------------------
// Observed acts state the negotiated version too
// ---------------------------------------------------------------------------

const OBSERVED_SESSION = OBSERVED.session as Dict;
const OBSERVED_ACTS = OBSERVED.observed_acts as Dict[];
const OBSERVED_EXPECTED = OBSERVED.expected as Dict;

test("a signed observed act is recorded with the negotiated version and verifies", () => {
  expect(OBSERVED_ACTS.every((act) => !("protocol_version" in act))).toBe(true);

  const record = recordFor(OBSERVED_SESSION, structuredClone(OBSERVED_ACTS));
  const acts = record.acts as Dict[];

  expect(acts.map((e) => (e.act as Dict).protocol_version)).toEqual(
    OBSERVED_EXPECTED.stated_versions,
  );
  expect(acts.map((e) => e.attribution)).toEqual(OBSERVED_EXPECTED.attributions);
  expect(acts[1].attribution).toBe("verified_signature");
  expect(acts.map((e) => e.act_hash)).toEqual(OBSERVED_EXPECTED.act_hashes);
  expect(record.record_hash).toBe(OBSERVED_EXPECTED.record_hash);
  expect(canonicalize(record).equals(canonicalize(OBSERVED_EXPECTED.record))).toBe(true);
  expect(verifySessionEvidenceRecord(record, DID_DOCUMENTS)).toBe(true);
});

test("an observed act that states a version keeps it, and a wrong one fails", () => {
  // The generator never overwrites a stated version, so a wrong one fails closed.
  const testCase = OBSERVED.stating_another_version as Dict;
  const observed = structuredClone(OBSERVED_ACTS);
  observed[0].protocol_version = testCase.observed_protocol_version;

  const record = recordFor(OBSERVED_SESSION, observed);

  expect(((record.acts as Dict[])[1].act as Dict).protocol_version).toBe(
    testCase.observed_protocol_version,
  );
  expect(record.record_hash).toBe(testCase.record_hash);
  expect(verifySessionEvidenceRecord(record, DID_DOCUMENTS)).toBe(testCase.verifies);
});

test("a wrapped observed act is stated inside its act", () => {
  // An observed item may wrap its act beside metadata; the version goes on the act.
  const wrapped = [{ act: structuredClone(OBSERVED_ACTS[0]) }];

  const record = recordFor(OBSERVED_SESSION, wrapped);
  const entry = (record.acts as Dict[])[1];

  expect((entry.act as Dict).protocol_version).toBe(PROTOCOL_ACT_VERSION);
  expect(Object.keys(entry).filter((k) => k !== "act")).not.toContain("protocol_version");
  expect(record.record_hash).toBe(OBSERVED_EXPECTED.record_hash);
});

test("an unsigned observed act is stated and stays an unsigned observation", () => {
  const act = structuredClone(OBSERVED_ACTS[0]);
  delete act.protocol_act_signature;
  delete act.sender_verification_method;

  const record = recordFor(OBSERVED_SESSION, [act]);
  const entry = (record.acts as Dict[])[1];

  expect((entry.act as Dict).protocol_version).toBe(PROTOCOL_ACT_VERSION);
  expect(entry.attribution).toBe("unsigned_observation");
  expect(entry.signature).toBeNull();
  expect(verifySessionEvidenceRecord(record, DID_DOCUMENTS)).toBe(true);
});
