/**
 * The acceptance rebinds from the record alone (Sections 9.3 and 9.5).
 *
 * The acceptance's signed scope is now the uniform envelope of Section 7.3.1,
 * so its signature covers protocol_version, message_type, sender_did and
 * timestamp beside the five fields it already covered. Of those four the record
 * stored only sender_did, so a "0.3" record cannot rebuild the acceptance's
 * signed object at all.
 *
 * A verifier faced with that has only two bad options: invent the missing
 * fields, or borrow them from final_offer. Both are wrong, and both were
 * demonstrated rather than argued — inventing empty strings produced one wrong
 * hash during the determination, and borrowing the offer's timestamp produced
 * another. A record that cannot rebind an act from that act's own stored fields
 * is not bound.
 *
 * So final_acceptance carries protocol_version, message_type and timestamp, and
 * the record version moves to "0.4". final_offer is untouched: the offer's
 * signed bytes and its protocol_act_hash do not move, so the rebinding of
 * agreed_terms is unaffected.
 *
 * The Python suite runs the same cases.
 */

import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";

import { generateKeypair, hashObject, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import {
  PROTOCOL_ACT_VERSION,
  protocolActObject,
  signedActHash,
  type Dict,
} from "../src/a2cn/messages.js";
import {
  ACCEPTED_TRANSACTION_RECORD_VERSIONS,
  FINAL_ACCEPTANCE_ACT_FIELDS,
  KNOWN_TRANSACTION_RECORD_VERSIONS,
  REASON_ACCEPTANCE_SIGNATURE_INVALID,
  REASON_UNBOUND_RECORD_VERSION,
  TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
  TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE,
  generateTransactionRecord,
  verifyTransactionRecord,
  verifyTransactionRecordReason,
} from "../src/a2cn/record.js";
import { Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument } from "./conftest.js";

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();
const INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;

const OFFER_TIMESTAMP = "2026-03-24T10:01:00Z";
const ACCEPTANCE_TIMESTAMP = "2026-03-24T10:03:00Z";
const TERMS = { total_value: 9_500_000, currency: "USD" };

function makeSession(): [SessionManager, Session, Record<string, Dict>] {
  const sessionId = randomUUID();
  const sessionInit: Dict = {
    message_type: "session_init",
    message_id: "init-1",
    protocol_version: "0.3",
    session_params: {
      deal_type: "saas_renewal",
      currency: "USD",
      subject: "Signed acceptance record",
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
  return [manager, session, didDocuments];
}

function makeOffer(sessionId: string): Dict {
  const act = protocolActObject({
    protocol_version: PROTOCOL_ACT_VERSION,
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    message_type: "offer",
    sender_did: INITIATOR_DID,
    timestamp: OFFER_TIMESTAMP,
    expires_at: "2030-01-01T00:00:00Z",
    terms: TERMS,
  });
  const actHash = hashObject(act);
  return {
    message_type: "offer",
    message_id: "offer-1",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "buyer-agent",
    sender_verification_method: INITIATOR_VM,
    timestamp: OFFER_TIMESTAMP,
    expires_at: "2030-01-01T00:00:00Z",
    terms: TERMS,
    protocol_act_hash: actHash,
    protocol_act_signature: signJws(actHash, INITIATOR_PRIVATE_KEY, INITIATOR_VM),
  };
}

function makeAcceptance(sessionId: string, offer: Dict): Dict {
  const acceptance: Dict = {
    message_type: "acceptance",
    message_id: "acceptance-1",
    session_id: sessionId,
    in_reply_to: offer.message_id,
    round_number: 1,
    sequence_number: 2,
    accepted_offer_id: offer.message_id,
    accepted_protocol_act_hash: offer.protocol_act_hash,
    sender_did: RESPONDER_DID,
    sender_agent_id: "seller-agent",
    sender_verification_method: RESPONDER_VM,
    timestamp: ACCEPTANCE_TIMESTAMP,
  };
  acceptance.acceptance_signature = signJws(
    signedActHash(acceptance, { versionWhenAbsent: PROTOCOL_ACT_VERSION }) as string,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
  );
  return acceptance;
}

interface Built {
  record: Dict;
  didDocuments: Record<string, Dict>;
  offer: Dict;
  acceptance: Dict;
}

function build(): Built {
  const [manager, session, didDocuments] = makeSession();
  const offer = makeOffer(session.session_id);
  manager.processMessage(session, offer);
  const acceptance = makeAcceptance(session.session_id, offer);
  manager.processMessage(session, acceptance);
  expect(session.state).toBe(SessionState.COMPLETED);
  return { record: generateTransactionRecord(session), didDocuments, offer, acceptance };
}

function resealed(record: Dict): Dict {
  const copy = structuredClone(record);
  copy.record_hash = "";
  copy.record_hash = hashObject(copy);
  return copy;
}

/**
 * Rebuild the acceptance's signed act from the record, reading ONLY its own.
 *
 * Spelled out here rather than imported, so the test is an independent check of
 * which fields the record must make available and, just as importantly, of where
 * they come from. Nothing here reads final_offer: an acceptance that can only be
 * rebuilt by borrowing another act's values is not bound by its own signature.
 */
function acceptanceActFromRecord(record: Dict): Dict {
  const finalAcceptance = record.final_acceptance as Dict;
  return {
    protocol_version: finalAcceptance.protocol_version,
    session_id: record.session_id,
    round_number: finalAcceptance.round_number,
    sequence_number: finalAcceptance.sequence_number,
    message_type: finalAcceptance.message_type,
    sender_did: finalAcceptance.sender_did,
    timestamp: finalAcceptance.timestamp,
    accepted_offer_id: finalAcceptance.accepted_offer_id,
    accepted_protocol_act_hash: finalAcceptance.accepted_protocol_act_hash,
  };
}

// ---------------------------------------------------------------------------
// The version, and what the record carries
// ---------------------------------------------------------------------------

test("the bound version is the only accepted one", () => {
  expect(TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE).toBe("0.4");
  expect([...ACCEPTED_TRANSACTION_RECORD_VERSIONS]).toEqual([
    TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE,
  ]);
  // The older shapes stay known — their schemas are published and a reader can
  // still parse them — but knowing a shape is not accepting it.
  expect(KNOWN_TRANSACTION_RECORD_VERSIONS).toContain(TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT);
  expect(KNOWN_TRANSACTION_RECORD_VERSIONS).toContain(TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE);
});

test("a generated record states the bound version", () => {
  const { record } = build();

  expect(record.record_version).toBe(TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE);
});

test("final_acceptance carries the fields its signature covers", () => {
  const { record } = build();
  const finalAcceptance = record.final_acceptance as Dict;

  expect([...FINAL_ACCEPTANCE_ACT_FIELDS]).toEqual([
    "protocol_version",
    "message_type",
    "timestamp",
  ]);
  for (const name of FINAL_ACCEPTANCE_ACT_FIELDS) {
    expect(finalAcceptance).toHaveProperty(name);
  }
  expect(finalAcceptance.message_type).toBe("acceptance");
  expect(finalAcceptance.timestamp).toBe(ACCEPTANCE_TIMESTAMP);
  expect(finalAcceptance.protocol_version).toBe(PROTOCOL_ACT_VERSION);
});

// ---------------------------------------------------------------------------
// The acceptance rebinds, from its own stored fields
// ---------------------------------------------------------------------------

test("the acceptance rebuilds from the record to what was signed", () => {
  const { record, acceptance } = build();

  expect(hashObject(acceptanceActFromRecord(record))).toBe(signedActHash(acceptance, {
    versionWhenAbsent: PROTOCOL_ACT_VERSION,
  }));
});

test("a record verifies end to end", () => {
  const { record, didDocuments, offer } = build();

  expect(
    verifyTransactionRecord(record, didDocuments, [offer.protocol_act_hash as string]),
  ).toBe(true);
});

test("the rebuild reads the acceptance's own timestamp, not the offer's", () => {
  // The anti-borrowing guard, and the reason this version exists. The two wrong
  // hashes produced during the determination both came from a value standing in
  // for one the record did not hold — an empty string, then the offer's
  // timestamp. The offer's timestamp differs from the acceptance's here by
  // design, so a verifier that reached for final_offer would compute a different
  // hash and this would fail.
  const { record, acceptance } = build();

  expect((record.final_offer as Dict).timestamp).not.toBe(
    (record.final_acceptance as Dict).timestamp,
  );

  const borrowed = acceptanceActFromRecord(record);
  borrowed.timestamp = (record.final_offer as Dict).timestamp;

  expect(hashObject(borrowed)).not.toBe(signedActHash(acceptance, {
    versionWhenAbsent: PROTOCOL_ACT_VERSION,
  }));
});

test("altering the acceptance's stored timestamp breaks its signature", () => {
  const { record, didDocuments, offer } = build();
  const tampered = structuredClone(record);
  (tampered.final_acceptance as Dict).timestamp = "2026-03-24T11:00:00Z";

  expect(
    verifyTransactionRecordReason(resealed(tampered), didDocuments, [
      offer.protocol_act_hash as string,
    ]),
  ).toBe(REASON_ACCEPTANCE_SIGNATURE_INVALID);
});

test.each(["protocol_version", "message_type", "timestamp"])(
  "a record missing acceptance act field %s is unbound",
  (fieldName) => {
    const { record, didDocuments, offer } = build();
    const stripped = structuredClone(record);
    delete (stripped.final_acceptance as Dict)[fieldName];

    expect(
      verifyTransactionRecordReason(resealed(stripped), didDocuments, [
        offer.protocol_act_hash as string,
      ]),
    ).toBe(REASON_UNBOUND_RECORD_VERSION);
  },
);

test("a record relabelled to the previous version is refused", () => {
  // "0.3" cannot rebind the acceptance, so it is not an accepted tier.
  const { record, didDocuments, offer } = build();
  const relabelled = structuredClone(record);
  relabelled.record_version = TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT;

  expect(
    verifyTransactionRecordReason(resealed(relabelled), didDocuments, [
      offer.protocol_act_hash as string,
    ]),
  ).toBe(REASON_UNBOUND_RECORD_VERSION);
});

// ---------------------------------------------------------------------------
// The offer side does not move
// ---------------------------------------------------------------------------

test("final_offer is untouched by this version", () => {
  const { record, offer } = build();
  const finalOffer = record.final_offer as Dict;

  expect(finalOffer.protocol_act_hash).toBe(offer.protocol_act_hash);
  expect(Object.keys(finalOffer).sort()).toEqual(
    [
      "message_id",
      "protocol_version",
      "round_number",
      "sequence_number",
      "message_type",
      "sender_did",
      "timestamp",
      "expires_at",
      "protocol_act_hash",
      "protocol_act_signature",
    ].sort(),
  );
});
