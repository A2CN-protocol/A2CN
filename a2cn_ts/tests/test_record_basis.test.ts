/**
 * The TransactionRecord basis: recorded beside currency and bound to agreed_terms.basis.
 *
 * spec/test-vectors/transaction-record-basis.json is a session that fixed basis
 * "gross"; each of its offers restates the basis in terms.basis (Section 7.2).
 * The Python suite replays the same signed messages and must reach the same
 * record_hash. The record_version follows the basis: a record that carries basis
 * is "0.2", and a session that fixed no basis gets a "0.1" record without the
 * key, byte-identical to the record an implementation that predates basis
 * produced for it (Sections 9.3 and 9.5).
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { A2CNClient } from "../src/a2cn/client.js";
import { generateKeypair, hashObject, privateKeyFromJwk, signJws } from "../src/a2cn/crypto.js";
import {
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
} from "../src/a2cn/evidence.js";
import { generateTransactionRecord, verifyTransactionRecord } from "../src/a2cn/record.js";
import { Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import type { Dict } from "../src/a2cn/messages.js";
import {
  INITIATOR_DID,
  RESPONDER_DID,
  freshServer,
  makeSessionInit,
  type TestClient,
} from "./conftest.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-basis.json"), "utf-8"),
) as Dict;
// A session that fixed no basis, with the record_version "0.1" record an
// implementation that predates basis produced for it. This implementation
// produces the same record.
const WITHOUT_BASIS = VECTOR.without_basis as Dict;
const EXPECTED = VECTOR.expected as Dict;
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
  expect(record).toStrictEqual(EXPECTED.full_record);
  expect(record.record_hash).toBe(EXPECTED.record_hash);
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

  expect(client.buildClientSideRecord(sessionId)).toStrictEqual(EXPECTED.full_record);
});

test("a session without basis replays to its 0.1 record", () => {
  // A session that fixed no basis gets exactly the record it got before basis existed.
  const record = generateTransactionRecord(replayWithoutBasis());
  const earlier = WITHOUT_BASIS.record_version_0_1 as Dict;

  expect("basis" in record).toBe(false);
  expect(record.record_version).toBe("0.1");
  // The same fields in the same order: the same bytes, so the same hash (Section 9.2).
  expect(JSON.stringify(record)).toBe(JSON.stringify(earlier.full_record));
  expect(record.record_hash).toBe(earlier.record_hash);
  expect(verifiesWithoutBasis(record)).toBe(true);
});

test("client side record for a session without basis is its 0.1 record", () => {
  const record = clientSideRecord(WITHOUT_BASIS);

  expect(JSON.stringify(record)).toBe(
    JSON.stringify((WITHOUT_BASIS.record_version_0_1 as Dict).full_record),
  );
});

test("a record_version 0.1 record still verifies", () => {
  const vector = WITHOUT_BASIS;
  const earlier = (vector.record_version_0_1 as Dict).full_record as Dict;

  expect(
    verifyTransactionRecord(
      earlier,
      vector.did_documents as Record<string, Dict>,
      offerHashes(vector.messages as Dict[]),
    ),
  ).toBe(true);
});

test("a session without basis record relabelled 0.2 fails verification", () => {
  // Section 9.5 step 7: a "0.2" record carries basis, and this one has none to carry.
  const relabelled = resealed({
    ...((WITHOUT_BASIS.record_version_0_1 as Dict).full_record as Dict),
    record_version: "0.2",
  });

  expect("basis" in (relabelled.agreed_terms as Dict)).toBe(false);
  expect(relabelled.record_hash).toBe(WITHOUT_BASIS.relabelled_0_2_record_hash);
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
    // Section 9.3: the record's basis, and so its version, follows the SessionAck.
    const record = RECORD_BUILDERS[builder](withoutBasisProposing(basis));
    const earlier = WITHOUT_BASIS.record_version_0_1 as Dict;

    expect("basis" in record).toBe(false);
    expect(JSON.stringify(record)).toBe(JSON.stringify(earlier.full_record));
    expect(record.record_hash).toBe(earlier.record_hash);
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

test("flipping the record basis fails verification", () => {
  const record = generateTransactionRecord(replayVector());
  const tampered = structuredClone(record);
  tampered.basis = EXPECTED.tampered_basis;
  const resealedRecord = resealed(tampered);

  expect(resealedRecord.record_hash).toBe(EXPECTED.tampered_record_hash);
  expect(verifies(resealedRecord)).toBe(false);
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
    const record = generateTransactionRecord(replayVector());
    record.basis = recordBasis;
    const agreedTerms = record.agreed_terms as Dict;
    if (agreedBasis === ABSENT) {
      delete agreedTerms.basis;
    } else {
      agreedTerms.basis = agreedBasis;
    }

    expect(verifies(resealed(record))).toBe(false);
  },
);

test("record basis with non-object agreed_terms fails verification", () => {
  const record = generateTransactionRecord(replayVector());
  record.agreed_terms = [];

  expect(verifies(resealed(record))).toBe(false);
});

test("a 0.2 record without basis fails verification", () => {
  // Section 9.5 step 7: a "0.2" record carries basis, whatever agreed_terms holds.
  const dropped = structuredClone(EXPECTED.full_record as Dict);
  delete dropped.basis;
  const resealedRecord = resealed(dropped);

  expect(resealedRecord.record_version).toBe("0.2");
  expect("basis" in (resealedRecord.agreed_terms as Dict)).toBe(true);
  expect(resealedRecord.record_hash).toBe(EXPECTED.basis_dropped_record_hash);
  expect(verifies(resealedRecord)).toBe(false);

  // Key presence: a null agreed_terms.basis counts as carried.
  (dropped.agreed_terms as Dict).basis = null;
  expect(verifies(resealed(dropped))).toBe(false);
  // Nor does it verify once agreed_terms carries no basis either.
  delete (dropped.agreed_terms as Dict).basis;
  expect(verifies(resealed(dropped))).toBe(false);
});

test("a 0.1 record without basis gets no basis check", () => {
  // An implementation that predates basis records agreed_terms.basis alone.
  const earlier = structuredClone(EXPECTED.full_record as Dict);
  delete earlier.basis;
  earlier.record_version = "0.1";
  const resealedRecord = resealed(earlier);

  expect(resealedRecord.record_hash).toBe(EXPECTED.basis_dropped_0_1_record_hash);
  expect(verifies(resealedRecord)).toBe(true);
});

test("a 0.1 record must not carry basis", () => {
  // Section 9.5 step 7: a "0.1" record has no top-level basis, even one equal to agreed_terms.basis.
  const relabelled = resealed({ ...(EXPECTED.full_record as Dict), record_version: "0.1" });

  expect(relabelled.basis).toBe((relabelled.agreed_terms as Dict).basis);
  expect(relabelled.record_hash).toBe(EXPECTED.relabelled_0_1_record_hash);
  expect(verifies(relabelled)).toBe(false);

  // Key presence: a null basis counts as carried.
  expect(verifies(resealed({ ...relabelled, basis: null }))).toBe(false);
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

  expect(evidence.transaction_record_hash).toBe(EXPECTED.record_hash);
  expect(evidence.record_hash).toBe(EXPECTED.evidence_record_hash);
  expect(verifySessionEvidenceRecord(evidence, DID_DOCUMENTS)).toBe(true);
});
