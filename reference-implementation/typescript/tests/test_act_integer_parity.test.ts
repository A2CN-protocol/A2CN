/**
 * One protocol, one rule: an act's counters are judged by value on every path.
 *
 * RFC 8785 serializes 2.0 and 2 as the same number, so they are one signed act
 * in two JSON spellings and must reach one verdict. This side always accepted
 * the integral float; Python's evidence path asked isinstance(value, int), a
 * type question rather than a protocol one, and refused it — so the same record
 * bytes assessed valid here and invalid there.
 *
 * act_integer_spellings in transaction-record-basis.json pins the seven
 * verdicts. Until now only test_record_act_binding consumed it, so only the
 * record path was held to them and nothing tested the evidence path at all.
 * Both suites now read the same cases from the same file, so the two
 * implementations cannot drift apart on this rule.
 *
 * WHAT THIS ASSERTS, AND WHY NOT attribution: attribution is stamped at
 * generation on the mere PRESENCE of a signature, so it reads
 * verified_signature for a forged or unrebuildable act too. The verdict that
 * actually moves is the record's.
 *
 * The Python suite runs the same cases.
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { generateKeypair, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import { assessSessionEvidenceRecord, generateSessionEvidenceRecord } from "../src/a2cn/evidence.js";
import {
  PROTOCOL_ACT_VERSION,
  SIGNED_ACT_SIGNATURE_FIELDS,
  isActInteger,
  signedActHash,
  type Dict,
} from "../src/a2cn/messages.js";
import { Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument } from "./conftest.js";
import { REPO_ROOT } from "./support/paths.js";

const VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-basis.json"), "utf-8"),
) as Dict;
const ACT_INTEGER_SPELLINGS = (VECTOR.record_version_0_4_binding as Dict)
  .act_integer_spellings as Dict[];

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();

const INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;

// A spelling that breaks a covered field cannot be rebuilt, so it has no honest
// hash to sign. An attacker in that position signs something; so does this.
const UNREBUILDABLE_STAND_IN = "0".repeat(43);

function makeSession(): [Session, Record<string, Dict>] {
  const sessionId = randomUUID();
  const sessionInit: Dict = {
    message_type: "session_init",
    message_id: "init-1",
    protocol_version: "0.3",
    session_params: {
      deal_type: "saas_renewal",
      currency: "USD",
      subject: "Act integer parity",
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

function spelled(spelling: Dict, sessionId: string): Dict {
  const act = rejection(sessionId);
  if ("value" in spelling) {
    act[spelling.field as string] = spelling.value;
  } else {
    delete act[spelling.field as string];
  }
  return act;
}

function signed(act: Dict): Dict {
  const copy: Dict = structuredClone(act);
  copy.sender_verification_method = RESPONDER_VM;
  const payloadHash = signedActHash(copy, {
    versionWhenAbsent: PROTOCOL_ACT_VERSION,
  }) ?? UNREBUILDABLE_STAND_IN;
  copy[SIGNED_ACT_SIGNATURE_FIELDS.rejection] = signJws(
    payloadHash,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
  );
  return copy;
}

test("an unmutated signed rejection verifies", () => {
  // The control, without which none of the cases below mean anything: if the
  // harness cannot verify an untouched act, every spelling reads as refused and
  // the table passes while proving nothing.
  const [session, didDocuments] = makeSession();
  session._message_log = [signed(rejection(session.session_id))];
  markTimedOut(session);

  const assessment = assessSessionEvidenceRecord(generateEvidence(session), didDocuments);

  expect(assessment.valid).toBe(true);
  expect(assessment.verified_acts).toBe(1);
  expect(assessment.invalid_acts).toBe(0);
});

test.each(ACT_INTEGER_SPELLINGS.map((s) => [s.name as string, s] as const))(
  "the evidence path judges act integer spelling %s by value",
  (_name, spelling) => {
    const [session, didDocuments] = makeSession();
    session._message_log = [signed(spelled(spelling, session.session_id))];
    markTimedOut(session);

    const assessment = assessSessionEvidenceRecord(generateEvidence(session), didDocuments);

    expect(assessment.valid).toBe(spelling.verifies);
  },
);

test("the vector still carries both outcomes", () => {
  // A guard on the vector, so this file cannot silently come to test nothing.
  const verdicts = ACT_INTEGER_SPELLINGS.map((s) => s.verifies);

  expect(verdicts.filter((v) => v === true)).toHaveLength(2);
  expect(verdicts.filter((v) => v === false)).toHaveLength(5);
});

// ---------------------------------------------------------------------------
// The primitive itself
// ---------------------------------------------------------------------------
//
// The vector cases above exercise the rule through the evidence path. They would
// still pass if each path kept its own copy of the predicate and the copies
// happened to agree — which is exactly the state this consolidation ended, and
// exactly the drift it exists to prevent. record.ts now imports this one rather
// than defining its own, and the Python suite pins the same table.

test.each([
  ["int", 2, true],
  ["integral-float", 2.0, true],
  ["exponent-spelling", 1e0, true],
  ["zero", 0, true],
  ["negative-int", -3, true],
  ["fractional", 2.5, false],
  ["string", "2", false],
  ["bool-true", true, false],
  ["bool-false", false, false],
  ["null", null, false],
] as [string, unknown, boolean][])(
  "the act integer primitive judges %s by value",
  (_name, value, accepted) => {
    // typeof excludes a boolean here; Python must exclude it explicitly, which
    // is what keeps the two verdicts identical.
    //
    // The `>= 1` floor is deliberately NOT here. It belongs to the call sites
    // that need it, so this primitive accepts 0 and negatives; folding a floor
    // in would silently make an OPTIONAL null sequence_number mandatory at the
    // sites that guard on null separately.
    expect(isActInteger(value)).toBe(accepted);
  },
);
