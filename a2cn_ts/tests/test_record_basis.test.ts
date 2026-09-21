/**
 * The TransactionRecord basis: recorded beside currency and bound to agreed_terms.basis.
 *
 * spec/test-vectors/transaction-record-basis.json is a session that fixed basis
 * "gross"; each of its offers restates the basis in terms.basis (Section 7.2).
 * The Python suite replays the same signed messages and must reach the same
 * record_hash. Every record this implementation produces is "0.3", because it
 * carries the Section 7.3.1 act fields (Section 9.3), and "0.3" is the only
 * version a verifier accepts. The records earlier implementations produced for
 * the same two sessions are kept in the vector under the version that produced
 * them, with their bytes and hashes intact, and are now refused as unbound:
 * nothing rebinds them to the offering party's signature. Under "0.3" the
 * record carries basis exactly when agreed_terms does, and equal to it (Section
 * 9.5, step 8).
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { A2CNClient } from "../src/a2cn/client.js";
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
  FINAL_OFFER_ACT_FIELDS,
  REASON_BASIS_MISMATCH,
  REASON_UNBOUND_RECORD_VERSION,
  generateTransactionRecord,
  verifyTransactionRecord,
  verifyTransactionRecordReason,
} from "../src/a2cn/record.js";
import { Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import type { Dict } from "../src/a2cn/messages.js";
import {
  INITIATOR_DID,
  RESPONDER_DID,
  freshServer,
  makeDidDocument,
  makeSessionInit,
  type TestClient,
} from "./conftest.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-basis.json"), "utf-8"),
) as Dict;
// A session that fixed no basis, with the record_version "0.1" record an
// implementation that predates basis produced for it, and the "0.3" record this
// implementation produces.
const WITHOUT_BASIS = VECTOR.without_basis as Dict;
const EXPECTED = VECTOR.expected as Dict;
// The record this implementation produces for the basis session, and the "0.2"
// record an implementation that predates the agreed_terms binding produced.
const EXPECTED_0_3 = EXPECTED.record_version_0_3 as Dict;
const EXPECTED_0_2 = EXPECTED.record_version_0_2 as Dict;
const DID_DOCUMENTS = VECTOR.did_documents as Record<string, Dict>;
const MESSAGES = VECTOR.messages as Dict[];
const ABSENT = Symbol("absent");

/** Run recorded messages through the responder state machine to COMPLETED. */
function replay(
  sessionId: string,
  sessionInit: Dict,
  sessionAck: Dict,
  didDocuments: Record<string, Dict>,
  messages: Dict[],
): Session {
  const manager = new SessionManager();
  for (const [did, didDocument] of Object.entries(didDocuments)) {
    manager.registerDidDocument(did, didDocument);
  }
  const session = manager.createSession(
    sessionId,
    sessionInit,
    sessionAck,
    sessionAck.session_created_at as string,
  );
  session.session_timeout_seconds = 86400 * 365 * 100; // the timestamps are in the past
  for (const message of structuredClone(messages)) {
    manager.processMessage(session, message);
  }
  expect(session.state).toBe(SessionState.COMPLETED);
  return session;
}

function replayVector(): Session {
  return replay(
    VECTOR.session_id as string,
    VECTOR.session_init as Dict,
    VECTOR.session_ack as Dict,
    DID_DOCUMENTS,
    MESSAGES,
  );
}

function replayWithoutBasis(): Session {
  return replay(
    WITHOUT_BASIS.session_id as string,
    WITHOUT_BASIS.session_init as Dict,
    WITHOUT_BASIS.session_ack as Dict,
    WITHOUT_BASIS.did_documents as Record<string, Dict>,
    WITHOUT_BASIS.messages as Dict[],
  );
}

function offerHashes(messages: Dict[]): string[] {
  return messages
    .filter((message) => message.message_type === "offer" || message.message_type === "counteroffer")
    .map((message) => message.protocol_act_hash as string);
}

function resealed(record: Dict): Dict {
  const copy = structuredClone(record);
  copy.record_hash = "";
  copy.record_hash = hashObject(copy);
  return copy;
}

function verifies(record: Dict): boolean {
  return verifyTransactionRecord(record, DID_DOCUMENTS, offerHashes(MESSAGES));
}

function verifiesWithoutBasis(record: Dict): boolean {
  return verifyTransactionRecord(
    record,
    WITHOUT_BASIS.did_documents as Record<string, Dict>,
    offerHashes(WITHOUT_BASIS.messages as Dict[]),
  );
}

function reasonFor(record: Dict): string | null {
  return verifyTransactionRecordReason(record, DID_DOCUMENTS, offerHashes(MESSAGES));
}

const BASIS_INITIATOR = generateKeypair();
const BASIS_RESPONDER = generateKeypair();
const BASIS_INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const BASIS_RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;

/**
 * A completed basis session whose two signing keys this test holds.
 *
 * Step 8's cases alter agreed_terms, which also breaks the rebuilt act hash, so
 * they must be re-signed over their own terms to isolate step 8. That needs
 * keys, which the shared vector does not carry for the initiator.
 */
function locallySignedBasisRecord(): [Dict, Record<string, Dict>] {
  const sessionId = randomUUID();
  const params: Dict = {
    deal_type: "saas_renewal",
    currency: "USD",
    basis: "gross",
    max_rounds: 4,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
  };
  const sessionInit: Dict = {
    message_type: "session_init",
    message_id: "basis-local-init",
    protocol_version: "0.2",
    session_params: { ...params, subject: "Local basis record" },
    initiator: {
      organization_name: "TechCorp",
      did: INITIATOR_DID,
      verification_method: BASIS_INITIATOR_VM,
      agent_id: "buyer-agent",
      endpoint: "https://techcorp.example/api/a2cn",
    },
    initiator_mandate: { mandate_type: "declared" },
  };
  const sessionAck: Dict = {
    message_type: "session_ack",
    message_id: "basis-local-ack",
    session_id: sessionId,
    in_reply_to: "basis-local-init",
    protocol_version: "0.2",
    session_params_accepted: params,
    responder: {
      organization_name: "Acme",
      did: RESPONDER_DID,
      verification_method: BASIS_RESPONDER_VM,
      agent_id: "seller-agent",
      endpoint: "http://localhost:8000",
    },
    responder_mandate: { mandate_type: "declared" },
    session_created_at: "2026-03-24T10:00:00Z",
    current_turn: "initiator",
  };
  const didDocuments: Record<string, Dict> = {
    [INITIATOR_DID]: makeDidDocument(
      INITIATOR_DID,
      "key-1",
      publicKeyToJwk(BASIS_INITIATOR.publicKey),
    ),
    [RESPONDER_DID]: makeDidDocument(
      RESPONDER_DID,
      "key-2026-01",
      publicKeyToJwk(BASIS_RESPONDER.publicKey),
    ),
  };
  const manager = new SessionManager();
  for (const [did, didDocument] of Object.entries(didDocuments)) {
    manager.registerDidDocument(did, didDocument);
  }
  const session = manager.createSession(sessionId, sessionInit, sessionAck, "2026-03-24T10:00:00Z");
  session.session_timeout_seconds = 86400 * 365 * 100;

  const terms = { total_value: 9_500_000, currency: "USD", basis: "gross" };
  const actHash = hashObject({
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    message_type: "offer",
    sender_did: INITIATOR_DID,
    timestamp: "2026-03-24T10:01:00Z",
    expires_at: "2030-01-01T00:00:00Z",
    terms,
  });
  manager.processMessage(session, {
    message_type: "offer",
    message_id: "basis-local-offer",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "buyer-agent",
    sender_verification_method: BASIS_INITIATOR_VM,
    timestamp: "2026-03-24T10:01:00Z",
    expires_at: "2030-01-01T00:00:00Z",
    terms,
    protocol_act_hash: actHash,
    protocol_act_signature: signJws(actHash, BASIS_INITIATOR.privateKey, BASIS_INITIATOR_VM),
  });
  const payload = {
    session_id: sessionId,
    round_number: 1,
    sequence_number: 2,
    accepted_offer_id: "basis-local-offer",
    accepted_protocol_act_hash: actHash,
  };
  manager.processMessage(session, {
    message_type: "acceptance",
    message_id: "basis-local-acc",
    in_reply_to: "basis-local-offer",
    ...payload,
    sender_did: RESPONDER_DID,
    sender_agent_id: "seller-agent",
    sender_verification_method: BASIS_RESPONDER_VM,
    timestamp: "2026-03-24T10:03:00Z",
    acceptance_signature: signJws(
      hashObject(payload),
      BASIS_RESPONDER.privateKey,
      BASIS_RESPONDER_VM,
    ),
  });
  expect(session.state).toBe(SessionState.COMPLETED);
  return [generateTransactionRecord(session), didDocuments];
}

/** The Section 7.3.1 act, rebuilt from the record alone. */
function actFromRecord(record: Dict): Dict {
  const finalOffer = record.final_offer as Dict;
  return {
    protocol_version: finalOffer.protocol_version,
    session_id: record.session_id,
    round_number: finalOffer.round_number,
    sequence_number: finalOffer.sequence_number,
    message_type: finalOffer.message_type,
    sender_did: finalOffer.sender_did,
    timestamp: finalOffer.timestamp,
    expires_at: finalOffer.expires_at,
    terms: record.agreed_terms,
  };
}

/** Re-sign both sides over the record's own act, so step 3 passes. */
function resignedOverItsAct(record: Dict): [Dict, string[]] {
  const value = structuredClone(record);
  const actHash = hashObject(actFromRecord(value));
  (value.final_offer as Dict).protocol_act_hash = actHash;
  (value.final_offer as Dict).protocol_act_signature = signJws(
    actHash,
    BASIS_INITIATOR.privateKey,
    BASIS_INITIATOR_VM,
  );
  const acceptance = value.final_acceptance as Dict;
  acceptance.accepted_protocol_act_hash = actHash;
  acceptance.acceptance_signature = signJws(
    hashObject({
      session_id: value.session_id,
      round_number: acceptance.round_number,
      sequence_number: acceptance.sequence_number,
      accepted_offer_id: acceptance.accepted_offer_id,
      accepted_protocol_act_hash: actHash,
    }),
    BASIS_RESPONDER.privateKey,
    BASIS_RESPONDER_VM,
  );
  value.offer_chain_hash = hashBytes(canonicalize([actHash]));
  return [resealed(value), [actHash]];
}

/** The record the initiator's client builds from the vector's messages. */
function clientSideRecord(vector: Dict): Dict {
  const sessionInit = vector.session_init as Dict;
  const client = new A2CNClient({
    agentInfo: sessionInit.initiator as Dict,
    privateKey: generateKeypair().privateKey,
    mandate: sessionInit.initiator_mandate as Dict,
    fetchFn: async () => new Response(null, { status: 503 }),
  });
  const sessionId = vector.session_id as string;
  // The state initiateSession caches, then every message as the client records it.
  client._sessions[sessionId] = {
    session_init: sessionInit,
    session_ack: vector.session_ack as Dict,
    sequence_number: 0,
    round_number: 0,
    current_turn: "initiator",
    offer_chain: [],
    message_log: [],
    latest_offer: null,
  };
  for (const message of structuredClone(vector.messages as Dict[])) {
    client.processIncoming(sessionId, message);
  }
  return client.buildClientSideRecord(sessionId);
}

// ---------------------------------------------------------------------------
// Generation: the shared vector, server side and client side
// ---------------------------------------------------------------------------

test("basis record vector replays to the expected record", () => {
  const record = generateTransactionRecord(replayVector());

  expect(record.basis).toBe(EXPECTED.basis);
  expect(record.basis).toBe(((VECTOR.session_ack as Dict).session_params_accepted as Dict).basis);
  // agreed_terms is the final offer's terms, which restate the basis.
  expect((record.agreed_terms as Dict).basis).toBe(record.basis);
  expect(record).toStrictEqual(EXPECTED_0_3.full_record);
  expect(record.record_hash).toBe(EXPECTED_0_3.record_hash);
  expect(verifies(record)).toBe(true);
});

test("client side record matches the vector", () => {
  const sessionInit = VECTOR.session_init as Dict;
  const client = new A2CNClient({
    agentInfo: sessionInit.initiator as Dict,
    privateKey: generateKeypair().privateKey,
    mandate: sessionInit.initiator_mandate as Dict,
    fetchFn: async () => new Response(null, { status: 503 }),
  });
  const sessionId = VECTOR.session_id as string;
  // The state initiateSession caches, then every message as the client records it.
  client._sessions[sessionId] = {
    session_init: sessionInit,
    session_ack: VECTOR.session_ack as Dict,
    sequence_number: 0,
    round_number: 0,
    current_turn: "initiator",
    offer_chain: [],
    message_log: [],
    latest_offer: null,
  };
  for (const message of structuredClone(MESSAGES)) {
    client.processIncoming(sessionId, message);
  }

  expect(client.buildClientSideRecord(sessionId)).toStrictEqual(EXPECTED_0_3.full_record);
});

test("a session without basis replays to its 0.3 record", () => {
  // A session that fixed no basis carries no basis, at whatever version.
  const record = generateTransactionRecord(replayWithoutBasis());
  const current = WITHOUT_BASIS.record_version_0_3 as Dict;

  expect("basis" in record).toBe(false);
  expect(record.record_version).toBe("0.3");
  // The same fields in the same order: the same bytes, so the same hash (Section 9.2).
  expect(JSON.stringify(record)).toBe(JSON.stringify(current.full_record));
  expect(record.record_hash).toBe(current.record_hash);
  expect(verifiesWithoutBasis(record)).toBe(true);
});

test("client side record for a session without basis matches the vector", () => {
  const record = clientSideRecord(WITHOUT_BASIS);

  expect(JSON.stringify(record)).toBe(
    JSON.stringify((WITHOUT_BASIS.record_version_0_3 as Dict).full_record),
  );
});

test("a record_version 0.1 record is refused as unbound", () => {
  // The record an implementation that predates basis produced, untouched. It
  // carries no act fields, so nothing rebinds agreed_terms to the offering
  // party's signature, and a verifier refuses it rather than reporting it as
  // proof. This is the deliberate break: it must be regenerated.
  const vector = WITHOUT_BASIS;
  const earlier = vector.record_version_0_1 as Dict;
  const dids = vector.did_documents as Record<string, Dict>;
  const hashes = offerHashes(vector.messages as Dict[]);

  expect((earlier.full_record as Dict).record_hash).toBe(earlier.record_hash);
  expect(verifyTransactionRecord(earlier.full_record as Dict, dids, hashes)).toBe(false);
  expect(verifyTransactionRecordReason(earlier.full_record as Dict, dids, hashes)).toBe(
    REASON_UNBOUND_RECORD_VERSION,
  );
});

test("a record_version 0.2 record is refused as unbound", () => {
  // The record an implementation that predates the act binding produced.
  const earlier = EXPECTED_0_2.full_record as Dict;

  expect(earlier.record_version).toBe("0.2");
  expect(earlier.record_hash).toBe(EXPECTED_0_2.record_hash);
  expect(verifies(earlier)).toBe(false);
  expect(reasonFor(earlier)).toBe(REASON_UNBOUND_RECORD_VERSION);
});

test("a session without basis record relabelled 0.2 fails verification", () => {
  // Section 9.5 step 8: a "0.2" record carries basis, and this one has none to carry.
  const relabelled = resealed({
    ...((WITHOUT_BASIS.record_version_0_1 as Dict).full_record as Dict),
    record_version: "0.2",
  });

  expect("basis" in (relabelled.agreed_terms as Dict)).toBe(false);
  expect(relabelled.record_hash).toBe(WITHOUT_BASIS.relabelled_0_2_record_hash);
  expect(verifiesWithoutBasis(relabelled)).toBe(false);
});

test("a session without basis 0.3 record relabelled 0.1 fails verification", () => {
  // Section 9.5 step 3: it still carries the act fields, and "0.1" predates them.
  // Its basis shape already fits "0.1", so nothing else can be what rejects it.
  const current = WITHOUT_BASIS.record_version_0_3 as Dict;
  const relabelled = resealed({ ...(current.full_record as Dict), record_version: "0.1" });

  expect("basis" in relabelled).toBe(false);
  expect(relabelled.record_hash).toBe(current.relabelled_0_1_record_hash);
  expect(verifiesWithoutBasis(relabelled)).toBe(false);
});

/** The record the responder's state machine generates from the vector's messages. */
function serverSideRecord(vector: Dict): Dict {
  return generateTransactionRecord(
    replay(
      vector.session_id as string,
      vector.session_init as Dict,
      vector.session_ack as Dict,
      vector.did_documents as Record<string, Dict>,
      vector.messages as Dict[],
    ),
  );
}

/**
 * without_basis with a SessionInit that proposed `basis` and a SessionAck that omits it.
 *
 * The SessionAck is the one a responder that predates basis sends, so the
 * session's basis is unstated whatever the SessionInit proposed (Section 6.4.1).
 * Neither the SessionInit nor its session_params is inside a signed act, so the
 * recorded offers and acceptance still verify.
 */
function withoutBasisProposing(basis: string): Dict {
  const vector = structuredClone(WITHOUT_BASIS);
  ((vector.session_init as Dict).session_params as Dict).basis = basis;
  expect("basis" in ((vector.session_ack as Dict).session_params_accepted as Dict)).toBe(false);
  return vector;
}

const RECORD_BUILDERS: Record<string, (vector: Dict) => Dict> = {
  client: clientSideRecord,
  server: serverSideRecord,
};
const UNECHOED_CASES: [string, string][] = (
  WITHOUT_BASIS.unechoed_proposed_bases as string[]
).flatMap((basis) =>
  Object.keys(RECORD_BUILDERS)
    .sort()
    .map((builder): [string, string] => [basis, builder]),
);

test.each(UNECHOED_CASES)(
  "a proposed basis the session ack omits is not recorded: %s, %s side",
  (basis, builder) => {
    // Section 9.3: the record's basis follows the SessionAck.
    const record = RECORD_BUILDERS[builder](withoutBasisProposing(basis));
    const current = WITHOUT_BASIS.record_version_0_3 as Dict;

    expect("basis" in record).toBe(false);
    expect(JSON.stringify(record)).toBe(JSON.stringify(current.full_record));
    expect(record.record_hash).toBe(current.record_hash);
    expect(verifiesWithoutBasis(record)).toBe(true);
  },
);

/** Route the client's requests to the in-process server through `client`. */
function fetchVia(client: TestClient): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const requestHeaders = (init?.headers ?? {}) as Record<string, string>;
    const response =
      init?.method === "POST"
        ? await client.post(url.pathname, {
            json: JSON.parse(init.body as string),
            headers: requestHeaders,
          })
        : await client.get(url.pathname, { headers: requestHeaders });
    return new Response(response.body, { status: response.statusCode });
  }) as typeof fetch;
}

test("client side record matches the server record", async () => {
  const fixture = freshServer();
  const responderClient = fixture.makeResponderClient();
  const sessionInit = makeSessionInit();
  const client = new A2CNClient({
    agentInfo: sessionInit.initiator as Dict,
    privateKey: fixture.initiatorKeypair.privateKey,
    mandate: sessionInit.initiator_mandate as Dict,
    fetchFn: fetchVia(fixture.client),
  });
  const ack = await client.initiateSession("http://test", RESPONDER_DID, {
    ...(sessionInit.session_params as Dict),
    basis: "gross",
  });
  const sessionId = ack.session_id as string;
  // The client sends terms as given: the caller restates the session basis.
  await client.sendOffer("http://test", RESPONDER_DID, sessionId, {
    total_value: 9_500_000,
    currency: "USD",
    basis: "gross",
  });
  const offer = client._sessions[sessionId].latest_offer as Dict;

  const responderVm = `${RESPONDER_DID}#key-2026-01`;
  const payload = {
    session_id: sessionId,
    round_number: 1,
    sequence_number: 2,
    accepted_offer_id: offer.message_id,
    accepted_protocol_act_hash: offer.protocol_act_hash,
  };
  const acceptance: Dict = {
    message_type: "acceptance",
    message_id: randomUUID(),
    in_reply_to: offer.message_id,
    ...payload,
    sender_did: RESPONDER_DID,
    sender_agent_id: "sales-agent-acme-007",
    sender_verification_method: responderVm,
    timestamp: offer.timestamp,
    acceptance_signature: signJws(
      hashObject(payload),
      fixture.responderKeypair.privateKey,
      responderVm,
    ),
  };
  const posted = await responderClient.post(`/sessions/${sessionId}/messages`, {
    json: acceptance,
    headers: {
      "Content-Type": "application/a2cn+json",
      "Idempotency-Key": acceptance.message_id as string,
    },
  });
  expect(posted.statusCode).toBe(200);
  client.processIncoming(sessionId, acceptance);

  const r = await fixture.client.get(`/sessions/${sessionId}/record`);
  expect(r.statusCode).toBe(200);
  const serverRecord = r.json();

  expect(serverRecord.basis).toBe("gross");
  expect((serverRecord.agreed_terms as Dict).basis).toBe("gross");
  expect(client.buildClientSideRecord(sessionId)).toStrictEqual(serverRecord);
  expect(
    verifyTransactionRecord(
      serverRecord,
      { [INITIATOR_DID]: fixture.initiatorDidDoc, [RESPONDER_DID]: fixture.responderDidDoc },
      [offer.protocol_act_hash as string],
    ),
  ).toBe(true);
});

// ---------------------------------------------------------------------------
// Verification (Section 9.5): a recorded basis is a basis equal to agreed_terms.basis
// ---------------------------------------------------------------------------

test("flipping the basis of a 0.3 record fails verification", () => {
  const record = structuredClone(EXPECTED_0_3.full_record as Dict);
  record.basis = EXPECTED.tampered_basis;
  const tampered = resealed(record);

  expect(tampered.record_hash).toBe(EXPECTED_0_3.basis_flipped_record_hash);
  expect(verifies(tampered)).toBe(false);
});

test.each([
  ["agreed-terms-basis-absent", "gross", ABSENT],
  ["agreed-terms-basis-differs", "gross", "net"],
  ["both-null", null, null],
  ["both-unrecognized", "vat", "vat"],
  ["both-uppercase", "GROSS", "GROSS"],
] as [string, unknown, unknown][])(
  "record basis must be a basis equal to agreed_terms: %s",
  (_name, recordBasis, agreedBasis) => {
    // Step 8 on a "0.3" record, the only version a verifier accepts. Altering
    // agreed_terms.basis also breaks the rebuilt act hash, so these are
    // re-signed over their own terms: step 3 then passes and step 8 decides.
    const [built, didDocuments] = locallySignedBasisRecord();
    built.basis = recordBasis;
    const agreedTerms = built.agreed_terms as Dict;
    if (agreedBasis === ABSENT) {
      delete agreedTerms.basis;
    } else {
      agreedTerms.basis = agreedBasis;
    }
    const [record, hashes] = resignedOverItsAct(built);

    expect(verifyTransactionRecordReason(record, didDocuments, hashes)).toBe(
      REASON_BASIS_MISMATCH,
    );
  },
);

test("record basis with non-object agreed_terms fails verification", () => {
  const [built, didDocuments] = locallySignedBasisRecord();
  built.agreed_terms = [];

  expect(
    verifyTransactionRecord(resealed(built), didDocuments, [
      (built.final_offer as Dict).protocol_act_hash as string,
    ]),
  ).toBe(false);
});

// ---------------------------------------------------------------------------
// What the earlier versions meant, and that they are no longer accepted
// ---------------------------------------------------------------------------

test.each([
  [
    "0.2-without-basis",
    () => {
      const dropped = structuredClone(EXPECTED_0_2.full_record as Dict);
      delete dropped.basis;
      return resealed(dropped);
    },
  ],
  [
    "0.1-carrying-basis",
    () => resealed({ ...(EXPECTED_0_2.full_record as Dict), record_version: "0.1" }),
  ],
  [
    "0.1-with-agreed-terms-basis-alone",
    () => {
      const earlier = structuredClone(EXPECTED_0_2.full_record as Dict);
      delete earlier.basis;
      earlier.record_version = "0.1";
      return resealed(earlier);
    },
  ],
] as [string, () => Dict][])(
  "an earlier version is refused whatever its basis shape: %s",
  (_name, build) => {
    // Step 1 now decides these, so their basis shape no longer matters. The last
    // case verified before this change: a "0.1" record carrying
    // agreed_terms.basis alone was exactly what an implementation predating
    // basis produced. It is refused now because nothing rebinds it.
    const record = build();

    expect(verifies(record)).toBe(false);
    expect(reasonFor(record)).toBe(REASON_UNBOUND_RECORD_VERSION);
  },
);

test("the pinned earlier hashes are unchanged", () => {
  // The historical bytes are untouched; only the verdict on them moved.
  const dropped = structuredClone(EXPECTED_0_2.full_record as Dict);
  delete dropped.basis;
  const droppedSealed = resealed(dropped);
  const relabelled = resealed({
    ...(EXPECTED_0_2.full_record as Dict),
    record_version: "0.1",
  });

  expect(droppedSealed.record_hash).toBe(EXPECTED_0_2.basis_dropped_record_hash);
  expect(relabelled.record_hash).toBe(EXPECTED_0_2.relabelled_0_1_record_hash);
  expect(resealed({ ...droppedSealed, record_version: "0.1" }).record_hash).toBe(
    EXPECTED_0_2.basis_dropped_0_1_record_hash,
  );
});

// ---------------------------------------------------------------------------
// Under "0.3" the basis follows agreed_terms, which the offer's signature covers
// ---------------------------------------------------------------------------

test("a 0.3 record without basis whose agreed_terms has one fails verification", () => {
  const dropped = structuredClone(EXPECTED_0_3.full_record as Dict);
  delete dropped.basis;

  expect("basis" in (dropped.agreed_terms as Dict)).toBe(true);
  expect(verifies(resealed(dropped))).toBe(false);
});

test("a 0.3 record with basis whose agreed_terms has none fails verification", () => {
  const record = structuredClone(
    (WITHOUT_BASIS.record_version_0_3 as Dict).full_record as Dict,
  );
  record.basis = "gross";

  expect("basis" in (record.agreed_terms as Dict)).toBe(false);
  expect(verifiesWithoutBasis(resealed(record))).toBe(false);
});

test("a 0.3 record relabelled 0.2 fails verification", () => {
  // Section 9.5 step 3: it carries the act fields, and "0.2" predates them. It
  // carries a basis equal to agreed_terms.basis, so step 8 is satisfied and only
  // the act fields can be what rejects it.
  const relabelled = resealed({
    ...(EXPECTED_0_3.full_record as Dict),
    record_version: "0.2",
  });

  expect(relabelled.basis).toBe((relabelled.agreed_terms as Dict).basis);
  expect(relabelled.record_hash).toBe(EXPECTED_0_3.relabelled_0_2_record_hash);
  expect(verifies(relabelled)).toBe(false);
});

test("a 0.3 record without its act fields fails verification", () => {
  const dropped = structuredClone(EXPECTED_0_3.full_record as Dict);
  for (const fieldName of FINAL_OFFER_ACT_FIELDS) {
    delete (dropped.final_offer as Dict)[fieldName];
  }
  const resealedRecord = resealed(dropped);

  expect(resealedRecord.record_version).toBe("0.3");
  expect(resealedRecord.record_hash).toBe(EXPECTED_0_3.act_fields_dropped_record_hash);
  expect(verifies(resealedRecord)).toBe(false);
});

test("altering agreed_terms of a 0.3 record fails verification", () => {
  // The signatures still verify; the act rebuilt from the record does not match.
  const record = structuredClone(EXPECTED_0_3.full_record as Dict);
  (record.agreed_terms as Dict).total_value = EXPECTED.agreed_terms_tampered_total_value;
  const tampered = resealed(record);

  expect(tampered.record_hash).toBe(EXPECTED_0_3.agreed_terms_tampered_record_hash);
  expect(verifies(tampered)).toBe(false);
});

// ---------------------------------------------------------------------------
// The SessionEvidenceRecord seals the basis-carrying record
// ---------------------------------------------------------------------------

test("basis-fixed session evidence record seals the record and verifies", () => {
  const producer = VECTOR.producer as Dict;
  const evidence = generateSessionEvidenceRecord(replayVector(), {
    producerPrivateKey: privateKeyFromJwk(VECTOR.producer_private_jwk as Dict),
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
  });

  expect(evidence.transaction_record_hash).toBe(EXPECTED_0_3.record_hash);
  expect(evidence.record_hash).toBe(EXPECTED_0_3.evidence_record_hash);
  expect(verifySessionEvidenceRecord(evidence, DID_DOCUMENTS)).toBe(true);
});
