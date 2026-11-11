/**
 * Section 9.5 steps 10 to 12: a TransactionRecord is signed one act by each of its two parties.
 *
 * Before these steps a record whose two acts one party signed verified: nothing
 * compared either signer with the other, the acceptance's signed
 * accepted_offer_id was never compared with final_offer.message_id, and
 * negotiation_summary's parties were never read. The live session refuses one
 * party signing both sides by turn order; a record presented to a verifier has
 * no session behind it.
 *
 * Each case in `transaction-record-parties.json` is a record whose hashes and
 * signatures are genuine, so it fails at exactly the step it names, and the
 * Python suite reads the same bytes.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { hashObject, verifyJws } from "../src/a2cn/crypto.js";
import { getPublicKey, getVerificationMethod } from "../src/a2cn/did.js";
import { protocolActObject, rebuildSignedAct, type Dict } from "../src/a2cn/messages.js";
import {
  REASON_ACCEPTANCE_SIGNATURE_INVALID,
  REASON_ACCEPTED_OFFER_ID_MISMATCH,
  REASON_KEY_NOT_FOUND,
  REASON_NOT_BILATERAL,
  REASON_OFFER_SIGNATURE_INVALID,
  REASON_PARTY_SUMMARY_MISMATCH,
  REASON_SAME_SIGNING_KEY,
  generateTransactionRecord,
  isDid,
  verifyTransactionRecord,
  verifyTransactionRecordReason,
  type DidResolver,
} from "../src/a2cn/record.js";
import { SessionManager, SessionState } from "../src/a2cn/session.js";
import { REPO_ROOT } from "./support/paths.js";

const VECTORS = join(REPO_ROOT, "spec", "test-vectors");
const VECTOR = JSON.parse(
  readFileSync(join(VECTORS, "transaction-record-parties.json"), "utf-8"),
) as Dict;
const BASIS = JSON.parse(
  readFileSync(join(VECTORS, "transaction-record-basis.json"), "utf-8"),
) as Dict;
const DIDS = VECTOR.did_documents as Record<string, Dict>;
const ALL_CASES = VECTOR.cases as Dict[];
const CASES: Record<string, Dict> = Object.fromEntries(ALL_CASES.map((c) => [c.name, c]));
const SHAPE_CASES = VECTOR.shape_cases as Dict[];
const ATTACKS = ALL_CASES.filter((c) => !c.verifies);
const NEW_REASONS = new Set([
  REASON_NOT_BILATERAL,
  REASON_ACCEPTED_OFFER_ID_MISMATCH,
  REASON_PARTY_SUMMARY_MISMATCH,
  REASON_SAME_SIGNING_KEY,
]);
const SAME_KEY_CASES = ["one_key_two_spellings", "two_dids_one_key"];

function reason(c: Dict, resolver: DidResolver = DIDS, hashes?: string[]): string | null {
  return verifyTransactionRecordReason(
    c.record as Dict,
    resolver,
    hashes ?? (c.offer_hashes as string[]),
  );
}

function resealed(record: Dict): Dict {
  const copy = structuredClone(record);
  copy.record_hash = "";
  copy.record_hash = hashObject(copy);
  return copy;
}

function recordOf(name: string): Dict {
  return structuredClone(CASES[name].record as Dict);
}

function withRecord(name: string, record: Dict): Dict {
  return { ...CASES[name], record: resealed(record) };
}

test("the reason codes are their names", () => {
  expect(REASON_NOT_BILATERAL).toBe("NOT_BILATERAL");
  expect(REASON_ACCEPTED_OFFER_ID_MISMATCH).toBe("ACCEPTED_OFFER_ID_MISMATCH");
  expect(REASON_PARTY_SUMMARY_MISMATCH).toBe("PARTY_SUMMARY_MISMATCH");
  expect(REASON_SAME_SIGNING_KEY).toBe("SAME_SIGNING_KEY");
});

for (const c of [...ALL_CASES, ...SHAPE_CASES]) {
  test(`the record reaches the stated verdict: ${c.name}`, () => {
    expect(reason(c)).toBe(c.expected_reason);
    expect(verifyTransactionRecord(c.record as Dict, DIDS, c.offer_hashes as string[])).toBe(
      c.verifies,
    );
  });
}

test("the vector covers every new reason and both controls", () => {
  expect(new Set(ATTACKS.map((c) => c.expected_reason))).toEqual(NEW_REASONS);
  expect(CASES.one_round_control.verifies).toBe(true);
  expect(CASES.multi_round_control.verifies).toBe(true);
});

for (const c of ATTACKS) {
  test(`every earlier check passes: ${c.name}`, () => {
    // The record is sealed, its offer rebinds, and the acceptance names the offer's hash.
    const record = c.record as Dict;
    expect(resealed(record).record_hash).toBe(record.record_hash);
    const offer = record.final_offer as Dict;
    const rebuilt = protocolActObject({
      protocol_version: offer.protocol_version as string,
      session_id: record.session_id,
      round_number: offer.round_number,
      sequence_number: offer.sequence_number,
      message_type: offer.message_type,
      sender_did: offer.sender_did,
      timestamp: offer.timestamp,
      expires_at: offer.expires_at,
      terms: record.agreed_terms,
    });
    expect(hashObject(rebuilt)).toBe(offer.protocol_act_hash);
    expect((record.final_acceptance as Dict).accepted_protocol_act_hash).toBe(
      offer.protocol_act_hash,
    );
  });
}

/** Verify one act's signature under its signer's own DID document, independently. */
function signatureIsGenuine(record: Dict, act: "final_offer" | "final_acceptance"): boolean {
  const signed = record[act] as Dict;
  const document = DIDS[signed.sender_did as string];
  const methodId = ((document.verificationMethod as Dict[])[0].id as string) ?? "";
  const key = getPublicKey(getVerificationMethod(document, methodId));
  if (act === "final_offer") {
    return verifyJws(signed.protocol_act_signature as string, key) === signed.protocol_act_hash;
  }
  const rebuilt = rebuildSignedAct({
    protocol_version: signed.protocol_version,
    session_id: record.session_id,
    round_number: signed.round_number,
    sequence_number: signed.sequence_number,
    message_type: signed.message_type,
    sender_did: signed.sender_did,
    timestamp: signed.timestamp,
    accepted_offer_id: signed.accepted_offer_id,
    accepted_protocol_act_hash: signed.accepted_protocol_act_hash,
  });
  return verifyJws(signed.acceptance_signature as string, key) === hashObject(rebuilt);
}

for (const c of ALL_CASES) {
  test(`both signatures are genuine: ${c.name}`, () => {
    // No case is refused for a forged signature: each signer really signed.
    expect(signatureIsGenuine(c.record as Dict, "final_offer")).toBe(true);
    expect(signatureIsGenuine(c.record as Dict, "final_acceptance")).toBe(true);
  });
}

for (const name of SAME_KEY_CASES) {
  test(`one key under two DIDs is one signer: ${name}`, () => {
    const record = CASES[name].record as Dict;
    const offerDid = (record.final_offer as Dict).sender_did as string;
    const acceptanceDid = (record.final_acceptance as Dict).sender_did as string;
    const jwk = (did: string) => (DIDS[did].verificationMethod as Dict[])[0].publicKeyJwk;
    expect(offerDid).not.toBe(acceptanceDid);
    expect(jwk(offerDid)).toEqual(jwk(acceptanceDid));
    expect(reason(CASES[name])).toBe(REASON_SAME_SIGNING_KEY);
  });

  test(`same key waits for both keys: ${name}`, () => {
    // With either signer's key unavailable the keys cannot be compared: KEY_NOT_FOUND.
    const record = CASES[name].record as Dict;
    for (const withheld of [
      (record.final_offer as Dict).sender_did as string,
      (record.final_acceptance as Dict).sender_did as string,
    ]) {
      const documents = Object.fromEntries(
        Object.entries(DIDS).filter(([did]) => did !== withheld),
      );
      expect(reason(CASES[name], documents)).toBe(REASON_KEY_NOT_FOUND);
    }
  });

  test(`same key comes before the offer chain: ${name}`, () => {
    expect(reason(CASES[name], DIDS, ["not-the-chain"])).toBe(REASON_SAME_SIGNING_KEY);
  });

  test(`a signature failure comes before same key: ${name}`, () => {
    const record = recordOf(name);
    (record.final_acceptance as Dict).acceptance_signature = (
      (CASES.one_round_control.record as Dict).final_acceptance as Dict
    ).acceptance_signature;
    expect(reason(withRecord(name, record))).toBe(REASON_ACCEPTANCE_SIGNATURE_INVALID);
  });
}

test("the respelled DID differs only in the host's case", () => {
  const parties = (CASES.one_key_two_spellings.record as Dict).parties as Dict;
  const initiator = (parties.initiator as Dict).did as string;
  const responder = (parties.responder as Dict).did as string;
  expect(initiator).not.toBe(responder);
  expect(initiator.toLowerCase()).toBe(responder.toLowerCase());
});

test("the one-round control is what the reference implementation generates", () => {
  const sessionInit = BASIS.session_init as Dict;
  const sessionAck = BASIS.session_ack as Dict;
  const manager = new SessionManager();
  for (const did of [
    (sessionInit.initiator as Dict).did as string,
    (sessionAck.responder as Dict).did as string,
  ]) {
    manager.registerDidDocument(did, DIDS[did]);
  }
  const session = manager.createSession(
    BASIS.session_id as string,
    sessionInit,
    sessionAck,
    sessionAck.session_created_at as string,
    { legacyReplay: true },
  );
  session.session_timeout_seconds = 86400 * 365 * 100;
  for (const message of structuredClone(VECTOR.one_round_messages as Dict[])) {
    manager.processMessage(session, message);
  }
  expect(session.state).toBe(SessionState.COMPLETED);
  expect(generateTransactionRecord(session)).toEqual(CASES.one_round_control.record);
});

test("the multi-round control is the basis vector's bound record", () => {
  const expected = (BASIS.expected as Dict).record_version_0_4 as Dict;
  expect(CASES.multi_round_control.record).toEqual(expected.full_record);
});

for (const c of ATTACKS.filter((c) => c.expected_reason !== REASON_SAME_SIGNING_KEY)) {
  test(`a structural refusal needs no keys: ${c.name}`, () => {
    const asked: string[] = [];
    const resolver = (did: string): Dict => {
      asked.push(did);
      return DIDS[did];
    };
    expect(reason(c, resolver)).toBe(c.expected_reason);
    expect(asked).toEqual([]);
    expect(reason(c, {})).toBe(c.expected_reason);
  });
}

test("the structural steps come in order", () => {
  // A record failing steps 10, 11 and 12 at once reports step 10, then 11, then 12.
  let record = recordOf("offerer_signs_acceptance");
  (record.final_offer as Dict).message_id = "another-offer";
  (record.negotiation_summary as Dict).initiating_party_did = "did:web:elsewhere.example";
  expect(reason(withRecord("offerer_signs_acceptance", record))).toBe(REASON_NOT_BILATERAL);

  record = recordOf("offer_message_id_changed");
  (record.negotiation_summary as Dict).initiating_party_did = "did:web:elsewhere.example";
  expect(reason(withRecord("offer_message_id_changed", record))).toBe(
    REASON_ACCEPTED_OFFER_ID_MISMATCH,
  );
});

test("a structural step comes before a signature failure", () => {
  // The offer's signature is replaced by one over another act: step 12 is reported first.
  const wrongSignature = ((CASES.multi_round_control.record as Dict).final_offer as Dict)
    .protocol_act_signature;
  const record = recordOf("summary_initiating_party_is_responder");
  (record.final_offer as Dict).protocol_act_signature = wrongSignature;
  expect(reason(withRecord("one_round_control", record))).toBe(REASON_PARTY_SUMMARY_MISMATCH);
  (record.negotiation_summary as Dict).initiating_party_did = (
    (record.parties as Dict).initiator as Dict
  ).did;
  expect(reason(withRecord("one_round_control", record))).toBe(REASON_OFFER_SIGNATURE_INVALID);
});

const RESPELLINGS: Record<string, (did: string) => string> = {
  "trailing-space": (did) => `${did} `,
  "host-case": (did) => did.replace("acme-corp", "Acme-Corp"),
  "did-url": (did) => `${did}#key-2026-01`,
};

for (const [label, respelled] of Object.entries(RESPELLINGS)) {
  test(`party DIDs are compared as exact strings: ${label}`, () => {
    // No normalization: a responder DID spelled otherwise than its signer's is not that signer.
    const record = recordOf("one_round_control");
    const responder = (record.parties as Dict).responder as Dict;
    responder.did = respelled(responder.did as string);
    expect(reason(withRecord("one_round_control", record))).toBe(REASON_NOT_BILATERAL);
  });
}

const SYNTAX_CASES = VECTOR.did_syntax_cases as Dict[];

for (const c of SYNTAX_CASES) {
  test(`a party DID must be DID syntax: ${c.name}`, () => {
    // Section 9.5 step 10: a party DID is a DID by DID Core Section 3.1, not a DID URL.
    expect(isDid(c.party_did)).toBe(c.verifies);
    expect(
      verifyTransactionRecordReason(
        c.record as Dict,
        c.did_documents as Record<string, Dict>,
        c.offer_hashes as string[],
      ),
    ).toBe(c.expected_reason);
  });
}

for (const did of ["did:web:a", "did:example:123", "did:web:a:b", "did:web:a%3Ab", "did:web::a"]) {
  test(`DID syntax admits ${did}`, () => {
    expect(isDid(did)).toBe(true);
  });
}

for (const did of ["did:web:a\n", "did:web:a:", "did::a", "did:web", "did:web:a%2", "did:w-b:a", ""]) {
  test(`DID syntax refuses ${JSON.stringify(did)}`, () => {
    expect(isDid(did)).toBe(false);
  });
}
