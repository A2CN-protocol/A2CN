/**
 * Decline vocabulary binds to record_version "0.4", and a signed decline buys no level.
 *
 * Two properties nothing else in either suite pinned. Measured on the Python
 * side: before these tests the content-to-version rule never fired once across
 * the whole suite, so deleting it left everything green.
 *
 * THE BINDING (Section 9A.6). "0.4" is the first version whose schema admits
 * rejection_signature or withdrawal_signature in acts[].signature_type. A
 * producer seals its own record, so nothing otherwise stops one emitting the new
 * vocabulary under an old label and sealing again: the seal is no defence here,
 * because the party that chooses the label is the party that makes the seal.
 * Such a record would verify while validating against no published schema. The
 * rule is ONE-DIRECTIONAL — the vocabulary requires the version, never the
 * reverse, since an ordinary "0.4" record carries no decline at all.
 *
 * Each refusal below carries its own control: the same session WITHOUT a signed
 * decline, relabelled and resealed identically. Without the control a refusal
 * proves only that something refused, not that this rule did — and at "0.3"
 * something else genuinely does.
 *
 * THE LEVEL (Section 9A.5). bilateral is gated on a COMPLETED outcome, so a
 * fully signed decline path falls to mixed through its locally observed terminal
 * fact. A signed decline therefore costs verification and buys no classification
 * credit.
 *
 * The Python suite runs the same cases.
 */

import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";

import {
  canonicalize,
  generateKeypair,
  hashBytes,
  hashObject,
  publicKeyToJwk,
  signJws,
} from "../src/a2cn/crypto.js";
import {
  assessSessionEvidenceRecord,
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
} from "../src/a2cn/evidence.js";
import { SIGNED_ACT_SIGNATURE_FIELDS, signedActHash, type Dict } from "../src/a2cn/messages.js";
import { Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument } from "./conftest.js";

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();

const INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;

// "0.3" is excluded from the parametrized cases because a "0.3" record that does
// not carry external_commitment_reference is refused by the historical two-way
// rule (Section 9A.2) whether or not it carries decline vocabulary — the right
// verdict for the wrong reason. The test below pins that, so the exclusion
// cannot quietly become a coverage hole.
const UNCONFOUNDED_EARLIER_VERSIONS = ["0.1", "0.2"];

function makeSession(): [SessionManager, Session, Record<string, Dict>] {
  const sessionId = randomUUID();
  const sessionInit: Dict = {
    message_type: "session_init",
    message_id: "init-1",
    protocol_version: "0.2",
    session_params: {
      deal_type: "saas_renewal",
      currency: "USD",
      subject: "Decline record version binding",
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
  return [manager, session, didDocuments];
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
function sign(
  act: Dict,
  privateKey: Parameters<typeof signJws>[1],
  verificationMethod: string,
): Dict {
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

function makeOffer(sessionId: string): Dict {
  const offer: Dict = {
    message_type: "offer",
    message_id: "offer-1",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "buyer-agent",
    sender_verification_method: INITIATOR_VM,
    timestamp: "2026-03-24T10:01:00Z",
    expires_at: "2026-03-25T10:01:00Z",
    terms: { total_value: 9_500_000, currency: "USD" },
  };
  offer.protocol_act_hash = signedActHash(offer) as string;
  offer[SIGNED_ACT_SIGNATURE_FIELDS.offer] = signJws(
    offer.protocol_act_hash as string,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_VM,
  );
  return offer;
}

/** A TIMED_OUT record whose only act is a rejection, signed or not. */
function declineRecord(signed_: boolean): [Dict, Record<string, Dict>] {
  const [, session, didDocuments] = makeSession();
  const act = rejection(session.session_id);
  session._message_log = [signed_ ? sign(act, RESPONDER_PRIVATE_KEY, RESPONDER_VM) : act];
  markTimedOut(session);
  return [generateEvidence(session), didDocuments];
}

/** Relabel and reseal, as a producer rewriting its own record would. */
function relabelled(record: Dict, version: string): Dict {
  const copy = structuredClone(record);
  copy.record_version = version;
  copy.act_chain_hash = hashBytes(canonicalize((copy.acts as Dict[]).map((e) => e.act_hash)));
  copy.record_hash = "";
  copy.producer_signature = "";
  copy.record_hash = hashObject(copy);
  copy.producer_signature = signJws(
    copy.record_hash as string,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_VM,
  );
  return copy;
}

test("a signed decline is emitted at 0.4", () => {
  // The control for everything below: the vocabulary and the version agree.
  const [record, didDocuments] = declineRecord(true);

  expect(record.record_version).toBe("0.4");
  expect((record.acts as Dict[])[0].signature_type).toBe("rejection_signature");
  expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
});

test.each(UNCONFOUNDED_EARLIER_VERSIONS)(
  "decline vocabulary resealed under an earlier version is refused: %s",
  (version) => {
    // The re-seal hole: a producer relabelling its own record and sealing again.
    const [record, didDocuments] = declineRecord(true);

    expect(verifySessionEvidenceRecord(relabelled(record, version), didDocuments)).toBe(false);
  },
);

test.each(UNCONFOUNDED_EARLIER_VERSIONS)(
  "the same record without the vocabulary is accepted there: %s",
  (version) => {
    // The control that makes the refusal above mean something. Identical
    // session, relabel and reseal; only the decline signature differs. Without
    // it, the refusal would be satisfied by a verifier that refused every
    // relabelled record for any reason at all.
    const [record, didDocuments] = declineRecord(false);

    expect((record.acts as Dict[])[0].signature_type).toBeNull();
    expect(verifySessionEvidenceRecord(relabelled(record, version), didDocuments)).toBe(true);
  },
);

test("a 0.3 relabel is refused for its own reason", () => {
  // Why "0.3" is excluded above, pinned rather than left as a silent gap. A
  // "0.3" record carrying no external_commitment_reference is refused by the
  // historical two-way rule with or without decline vocabulary, so that version
  // cannot isolate the binding.
  const [signedRecord, didDocuments] = declineRecord(true);
  const [unsignedRecord] = declineRecord(false);

  expect(verifySessionEvidenceRecord(relabelled(signedRecord, "0.3"), didDocuments)).toBe(false);
  expect(verifySessionEvidenceRecord(relabelled(unsignedRecord, "0.3"), didDocuments)).toBe(false);
});

test("the binding is one-directional", () => {
  // "0.4" does not imply the vocabulary: an ordinary record carries no decline.
  const [record, didDocuments] = declineRecord(false);

  expect(record.record_version).toBe("0.4");
  expect((record.acts as Dict[]).every((entry) => entry.signature_type === null)).toBe(true);
  expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
});

test("a fully signed decline path is mixed, not bilateral", () => {
  // Both parties hold a verified act and no act is unsigned, which is the whole
  // of the bilateral test apart from the outcome — and the outcome is what
  // decides.
  const [manager, session, didDocuments] = makeSession();
  manager.processMessage(session, makeOffer(session.session_id));
  const decline = sign(rejection(session.session_id), RESPONDER_PRIVATE_KEY, RESPONDER_VM);
  (session._message_log as Dict[]).push(decline);
  session.state = SessionState.REJECTED_FINAL;
  session.current_turn = "none";
  session.terminal_reason = "offer_rejected";
  session.terminal_message_id = decline.message_id as string;
  session.state_updated_at = "2026-03-24T10:06:00Z";

  const record = generateEvidence(session);
  const assessment = assessSessionEvidenceRecord(record, didDocuments);

  // Assert the CAUSE before the value. Pinning "mixed" alone would pass just as
  // well when mixed arrives the ordinary way — because some act was unsigned —
  // which is not the property under test. What is under test is that a record
  // with NO unsigned act still fails to reach bilateral, and that the terminal
  // outcome is the only thing standing in its way.
  expect(assessment.valid).toBe(true);
  expect((record.acts as Dict[]).map((entry) => entry.attribution)).toEqual([
    "verified_signature",
    "verified_signature",
  ]);
  expect(assessment.verified_acts).toBe(2);
  expect(assessment.unsigned_acts).toBe(0);
  expect(assessment.invalid_acts).toBe(0);
  expect((record.terminal as Dict).outcome).not.toBe(SessionState.COMPLETED);
  expect((record.terminal as Dict).outcome).toBe(SessionState.REJECTED_FINAL);

  expect(assessment.evidence_level).toBe("mixed");
});
