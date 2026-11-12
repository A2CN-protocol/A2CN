/**
 * Lookups keyed by caller input read and write own properties only.
 *
 * A store kept as a plain object inherits names from Object.prototype:
 * `constructor`, `toString` and `__proto__` are present on every plain object,
 * and assigning to `__proto__` replaces the object's prototype instead of adding
 * an entry. Python's dicts have no such names, so an id of `constructor` is an
 * unknown id there and `__proto__` is an ordinary key. Every case below holds
 * the TypeScript implementation to what Python does with the same id, and
 * checks that nothing is ever written to Object.prototype.
 *
 * The Python suite runs the matching cases in tests/test_inherited_name_ids.py.
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { A2CNClient } from "../src/a2cn/client.js";
import {
  generateKeypair,
  hashObject,
  publicKeyToJwk,
  signInvitation,
  verifyInvitationSignature,
} from "../src/a2cn/crypto.js";
import { VerificationMethodNotFoundError, getVerificationMethod } from "../src/a2cn/did.js";
import { assessSessionEvidenceRecord, generateSessionEvidenceRecord } from "../src/a2cn/evidence.js";
import { InvitationStore } from "../src/a2cn/invitation.js";
import { dropNone, rebuildSignedAct, signedActHash, type Dict } from "../src/a2cn/messages.js";
import { verifyTransactionRecordReason } from "../src/a2cn/record.js";
import { A2CNError, Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import { InMemorySessionStore, RedisSessionStore } from "../src/a2cn/session_store.js";
import { a2cnRecordToDocusignEnvelope } from "../src/adapters/docusign_adapter.js";
import { webhookBodyForSignature } from "../src/adapters/vendr_adapter.js";
import { createMcpContext } from "../src/mcp_server.js";
import {
  INITIATOR_DID,
  RESPONDER_DID,
  freshServer,
  makeDidDocument,
  makeSessionInit,
  makeTestClient,
  signDecline,
} from "./conftest.js";
import { REPO_ROOT } from "./support/paths.js";

// The names a plain object inherits that matter here: two functions every
// object has, and the accessor that replaces an object's prototype on write.
const INHERITED_IDS = ["__proto__", "constructor", "toString"] as const;

// Field names a stored entry carries. If a write ever landed on a shared
// prototype, a fresh object would start reporting one of these.
const WATCHED_NAMES = [
  "status",
  "invitation",
  "created_at",
  "answered_at",
  "state",
  "session_ack",
  "session_init",
  "message_log",
  "delivery_notice",
  "post_commitment_status",
  "verificationMethod",
  "authentication",
  "x",
];

const OBJECT_PROTOTYPE_KEYS = Reflect.ownKeys(Object.prototype).map(String).sort();
const OBJECT_KEYS = Reflect.ownKeys(Object).map(String).sort();
const FUNCTION_PROTOTYPE_KEYS = Reflect.ownKeys(Function.prototype).map(String).sort();

function expectNoSharedPrototypeWrites(): void {
  expect(Reflect.ownKeys(Object.prototype).map(String).sort()).toEqual(OBJECT_PROTOTYPE_KEYS);
  expect(Reflect.ownKeys(Object).map(String).sort()).toEqual(OBJECT_KEYS);
  expect(Reflect.ownKeys(Function.prototype).map(String).sort()).toEqual(FUNCTION_PROTOTYPE_KEYS);
  const probe: Dict = {};
  for (const name of WATCHED_NAMES) {
    expect(probe[name]).toBeUndefined();
  }
  expect(Object.getPrototypeOf(probe)).toBe(Object.prototype);
}

beforeEach(() => {
  expectNoSharedPrototypeWrites();
});

afterEach(() => {
  expectNoSharedPrototypeWrites();
});

/** A JSON object with an own `__proto__` member, as JSON.parse builds one. */
function withOwnProto(base: Dict, value: unknown): Dict {
  const parsed = JSON.parse(JSON.stringify(base)) as Dict;
  Object.defineProperty(parsed, "__proto__", {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
  // Round-trip through JSON so the member is exactly what a parser produces.
  return JSON.parse(JSON.stringify(parsed)) as Dict;
}

function hasOwn(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

// ---------------------------------------------------------------------------
// Library fixtures
// ---------------------------------------------------------------------------

const { privateKey: INITIATOR_KEY, publicKey: INITIATOR_PUB } = generateKeypair();
const { publicKey: RESPONDER_PUB } = generateKeypair();
const INITIATOR_VM = `${INITIATOR_DID}#key-1`;

function sessionPair(sessionId: string): [Dict, Dict] {
  const sessionInit: Dict = {
    message_type: "session_init",
    message_id: "init-1",
    protocol_version: "0.3",
    session_params: {
      deal_type: "saas_renewal",
      currency: "USD",
      max_rounds: 4,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
    },
    initiator: { did: INITIATOR_DID, verification_method: INITIATOR_VM, agent_id: "buyer" },
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
    responder: { did: RESPONDER_DID, verification_method: `${RESPONDER_DID}#key-1`, agent_id: "seller" },
    responder_mandate: { mandate_type: "declared" },
    session_created_at: "2026-03-24T10:00:00Z",
    current_turn: "initiator",
  };
  return [sessionInit, sessionAck];
}

function managerWithSession(sessionId = randomUUID()): [SessionManager, Session] {
  const manager = new SessionManager();
  manager.registerDidDocument(
    INITIATOR_DID,
    makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUB)),
  );
  manager.registerDidDocument(
    RESPONDER_DID,
    makeDidDocument(RESPONDER_DID, "key-1", publicKeyToJwk(RESPONDER_PUB)),
  );
  const [init, ack] = sessionPair(sessionId);
  const session = manager.createSession(sessionId, init, ack, "2026-03-24T10:00:00Z");
  session.session_timeout_seconds = 86400 * 365 * 100;
  return [manager, session];
}

function signedWithdrawal(sessionId: string, messageId: string): Dict {
  return signDecline(
    {
      message_type: "withdrawal",
      message_id: messageId,
      session_id: sessionId,
      round_number: 1,
      sequence_number: 1,
      sender_did: INITIATOR_DID,
      sender_agent_id: "buyer",
      timestamp: "2026-03-24T10:02:00Z",
      reason_code: "STRATEGY_DECISION",
    },
    INITIATOR_KEY,
    INITIATOR_VM,
  );
}

function inboundInvitation(invitationId: string): Dict {
  return {
    message_type: "session_invitation",
    invitation_id: invitationId,
    a2cn_version: "0.3",
    inviter_did: "did:web:buyer.example",
    inviter_endpoint: "https://buyer.example/a2cn",
    inviter_discovery_url: "https://buyer.example/.well-known/a2cn-agent",
    proposed_deal_type: "saas_renewal",
    proposed_session_params: { currency: "USD", max_rounds: 4 },
    proposed_terms_summary: { total_value: 9_500_000, currency: "USD" },
    inviter_mandate_summary: { mandate_type: "declared" },
    invitation_expires_at: "2030-01-01T00:00:00Z",
    accept_endpoint: "https://buyer.example/a2cn/invitations/x/accept",
    decline_endpoint: "https://buyer.example/a2cn/invitations/x/decline",
    inviter_verification_method: "did:web:buyer.example#key-1",
    invitation_signature: "",
  };
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

test.each(INHERITED_IDS)("getSession(%j) finds no session", (id) => {
  const [manager] = managerWithSession();
  expect(manager.getSession(id)).toBeNull();
});

test.each(INHERITED_IDS)("a session created under %j is an ordinary entry", (id) => {
  const manager = new SessionManager();
  const [init, ack] = sessionPair(id);
  const session = manager.createSession(id, init, ack, "2026-03-24T10:00:00Z");
  expect(manager.getSession(id)).toBe(session);
  expect(Object.keys(manager._sessions)).toEqual([id]);
  expect(Object.getPrototypeOf(manager._sessions)).toBe(Object.prototype);
  expect(manager.getSession("state")).toBeNull();
});

test.each(INHERITED_IDS)("message_id %j is validated, not answered as a retransmission", (id) => {
  const [manager, session] = managerWithSession();
  let error: unknown;
  try {
    manager.processMessage(session, {
      message_type: "bogus",
      message_id: id,
      sender_did: INITIATOR_DID,
    });
  } catch (exc) {
    error = exc;
  }
  expect(error).toBeInstanceOf(A2CNError);
  expect((error as A2CNError).code).toBe("WRONG_MESSAGE_TYPE");
});

test.each(INHERITED_IDS)("a message with message_id %j is processed and then replayed", (id) => {
  const [manager, session] = managerWithSession();
  const response = manager.processMessage(session, signedWithdrawal(session.session_id, id));
  expect(session.state).toBe(SessionState.WITHDRAWN);
  expect(Object.keys(session._processed_messages)).toEqual([id]);
  expect(Object.getPrototypeOf(session._processed_messages)).toBe(Object.prototype);
  // The retransmission returns the stored response, as for any message id.
  expect(manager.processMessage(session, signedWithdrawal(session.session_id, id))).toBe(response);
});

test.each(INHERITED_IDS)("init response store treats %j as an ordinary key", (id) => {
  const manager = new SessionManager();
  expect(manager.hasInitResponse(id)).toBe(false);
  expect(manager.getInitResponse(id)).toBeUndefined();
  const response = { session_id: "s-1" };
  manager.storeInitResponse(id, response);
  expect(manager.hasInitResponse(id)).toBe(true);
  expect(manager.getInitResponse(id)).toBe(response);
  expect(Object.keys(manager._init_responses)).toEqual([id]);
});

test.each(INHERITED_IDS)("DID document registry treats %j as an ordinary key", (id) => {
  const manager = new SessionManager();
  expect(manager.hasDidDocument(id)).toBe(false);
  manager.registerDidDocument(id, { id });
  expect(manager.hasDidDocument(id)).toBe(true);
  expect(Object.keys(manager._did_documents)).toEqual([id]);
  expect(Object.getPrototypeOf(manager._did_documents)).toBe(Object.prototype);
  expect(manager.hasDidDocument("id")).toBe(false);
});

// ---------------------------------------------------------------------------
// InMemorySessionStore and the persistent stores' serialisation
// ---------------------------------------------------------------------------

test.each(INHERITED_IDS)("InMemorySessionStore.get(%j) is null until saved", (id) => {
  const store = new InMemorySessionStore();
  expect(store.get(id)).toBeNull();
  const data = { delivery_notice: { message_type: "delivery_notice" } };
  store.save(id, data);
  expect(store.get(id)).toBe(data);
  expect(store.listActive()).toEqual([id]);
  expect(store.get("delivery_notice")).toBeNull();
  store.delete(id);
  expect(store.get(id)).toBeNull();
  expect(store.listActive()).toEqual([]);
});

test("RedisSessionStore keeps an own __proto__ member in the stored JSON", () => {
  const written: Record<string, string> = {};
  const store = new RedisSessionStore(
    {
      get: (key) => written[key] ?? null,
      set: (key, value) => {
        written[key] = value;
      },
      scanIter: () => Object.keys(written),
      delete: () => undefined,
    },
    { ttlSeconds: null },
  );
  store.save("s-1", withOwnProto({ b: 1 }, { a: 2 }));
  // json.dumps(sort_keys=True, separators=(",", ":")) writes the same bytes.
  expect(written["a2cn:session:s-1"]).toBe('{"__proto__":{"a":2},"b":1}');
  const loaded = store.get("s-1") as Dict;
  expect(hasOwn(loaded, "__proto__")).toBe(true);
});

// ---------------------------------------------------------------------------
// InvitationStore
// ---------------------------------------------------------------------------

test.each(INHERITED_IDS)("getInvitation(%j) finds nothing", (id) => {
  const store = new InvitationStore();
  expect(store.getInvitation(id)).toBeNull();
});

test.each(INHERITED_IDS)("answering invitation %j is INVITATION_NOT_FOUND", (id) => {
  const store = new InvitationStore();
  const { privateKey } = generateKeypair();
  expect(() =>
    store.acceptInvitation({
      invitationId: id,
      acceptorDid: RESPONDER_DID,
      acceptorA2cnEndpoint: "https://acme.example",
      acceptorDiscoveryUrl: "https://acme.example/.well-known/a2cn-agent",
      acceptorVerificationMethod: `${RESPONDER_DID}#key-1`,
      privateKey,
    }),
  ).toThrow(/^INVITATION_NOT_FOUND$/);
  expect(() => store.declineInvitation(id, "OTHER")).toThrow(/^INVITATION_NOT_FOUND$/);
});

test.each(INHERITED_IDS)("an inbound invitation %j is stored as an ordinary entry", (id) => {
  const store = new InvitationStore();
  store.storeInbound(inboundInvitation(id));
  expect(Object.getPrototypeOf(store._invitations)).toBe(Object.prototype);
  expect(Object.keys(store._invitations)).toEqual([id]);
  expect(store.getInvitation(id)?.status).toBe("pending");
  // A name the entry carries is not an invitation id.
  for (const name of ["status", "invitation", "created_at", "answered_at"]) {
    expect(store.getInvitation(name)).toBeNull();
  }
  expect(() => store.declineInvitation("status", "OTHER")).toThrow(/^INVITATION_NOT_FOUND$/);
  expect(store.declineInvitation(id, "OTHER").invitation_id).toBe(id);
  expect(store.getInvitation(id)?.status).toBe("declined");
});

test("an expired inbound __proto__ invitation is swept like any other", () => {
  const store = new InvitationStore();
  store.storeInbound({ ...inboundInvitation("__proto__"), invitation_expires_at: "2020-01-01T00:00:00Z" });
  expect(store.expirePending()).toBe(1);
  expect(store.getInvitation("__proto__")?.status).toBe("expired");
});

// ---------------------------------------------------------------------------
// DID verification methods
// ---------------------------------------------------------------------------

test.each(INHERITED_IDS)("verification method %j listed by reference only is not found", (id) => {
  const doc = { id: "did:web:x", verificationMethod: [], authentication: [id], assertionMethod: [id] };
  expect(() => getVerificationMethod(doc, id)).toThrow(VerificationMethodNotFoundError);
});

test("a verification method whose id is __proto__ does not lend its fields as methods", () => {
  const method = {
    id: "__proto__",
    type: "JsonWebKey2020",
    controller: "did:web:x",
    publicKeyJwk: publicKeyToJwk(INITIATOR_PUB),
  };
  const doc = {
    id: "did:web:x",
    verificationMethod: [method],
    authentication: ["type", "__proto__"],
  };
  expect(() => getVerificationMethod(doc, "type")).toThrow(VerificationMethodNotFoundError);
  // The method itself is found by its id, as Python finds it.
  expect(getVerificationMethod(doc, "__proto__")).toStrictEqual(method);
});

// ---------------------------------------------------------------------------
// Signed-act field tables
// ---------------------------------------------------------------------------

test.each(INHERITED_IDS)("an act of message_type %j cannot be rebuilt", (id) => {
  const act = {
    protocol_version: "0.3",
    session_id: "s-1",
    round_number: 1,
    sequence_number: 1,
    message_type: id,
    sender_did: INITIATOR_DID,
    timestamp: "2026-03-24T10:02:00Z",
  };
  expect(rebuildSignedAct(act)).toBeNull();
  expect(signedActHash(act)).toBeNull();
});

test.each([...INHERITED_IDS, "bogus"])(
  "a record whose acceptance is of message_type %j is refused as Python refuses it",
  (messageType) => {
    const vector = JSON.parse(
      readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-basis.json"), "utf-8"),
    ) as Dict;
    const record = structuredClone(
      ((vector.expected as Dict).record_version_0_4 as Dict).full_record as Dict,
    );
    (record.final_acceptance as Dict).message_type = messageType;
    record.record_hash = "";
    record.record_hash = hashObject(record);
    expect(
      verifyTransactionRecordReason(record, vector.did_documents as Record<string, Dict>),
    ).toBe("UNBOUND_RECORD_VERSION");
  },
);

test.each(INHERITED_IDS)("an observed act claiming signature_type %j is refused", (id) => {
  const [, session] = managerWithSession();
  session.state = SessionState.WITHDRAWN;
  session.current_turn = "none";
  session.terminal_reason = "withdrawn";
  session.state_updated_at = "2026-03-24T10:10:00Z";
  expect(() =>
    generateSessionEvidenceRecord(session, {
      producerPrivateKey: INITIATOR_KEY,
      producerDid: INITIATOR_DID,
      producerAgentId: "buyer",
      producerVerificationMethod: INITIATOR_VM,
      observedActs: [
        {
          act: {
            message_type: "offer",
            message_id: "observed-1",
            session_id: session.session_id,
            round_number: 1,
            sequence_number: 1,
            sender_did: INITIATOR_DID,
            timestamp: "2026-03-24T10:01:00Z",
          },
          signature_type: id,
          signature: "not-a-signature",
          sender_verification_method: INITIATOR_VM,
        },
      ],
    }),
  ).toThrow(/^Unsupported signature_type/);
});

test.each([...INHERITED_IDS, "valueOf", "hasOwnProperty"])(
  "an observed act claiming signature_type %j is refused even when the act carries the field it would name",
  (id) => {
    const [, session] = managerWithSession();
    session.state = SessionState.WITHDRAWN;
    session.current_turn = "none";
    session.terminal_reason = "withdrawn";
    session.state_updated_at = "2026-03-24T10:10:00Z";
    // The key an inherited-name lookup into the signature-field table would
    // stringify to, so the unfixed path finds a "signature" there.
    const inheritedKey = String((({}) as Dict)[id] ?? "");
    expect(() =>
      generateSessionEvidenceRecord(session, {
        producerPrivateKey: INITIATOR_KEY,
        producerDid: INITIATOR_DID,
        producerAgentId: "buyer",
        producerVerificationMethod: INITIATOR_VM,
        observedActs: [
          {
            act: {
              message_type: "observed_note",
              sender_did: INITIATOR_DID,
              timestamp: "2026-03-24T10:01:00Z",
              session_id: session.session_id,
              sender_verification_method: INITIATOR_VM,
              [inheritedKey]: "sig",
            },
            signature_type: id,
            signature: "sig",
            sender_verification_method: INITIATOR_VM,
            source_protocol: "x",
          },
        ],
      }),
    ).toThrow(`Unsupported signature_type: ${JSON.stringify(id)}`);
  },
);

// A DidResolver object is read by own entries only. A resolver whose documents
// it inherits (here through Object.create) supplies none of them, so every key
// is unavailable: KEY_NOT_FOUND. Python's verifiers read any Mapping, a
// ChainMap included, so they would find chained entries; the difference is
// deliberate, and a TypeScript resolver holds its documents as own entries.
test("the record verifier reads a resolver's own entries only", () => {
  const vector = JSON.parse(
    readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-basis.json"), "utf-8"),
  ) as Dict;
  const record = ((vector.expected as Dict).record_version_0_4 as Dict).full_record as Dict;
  const offers = (vector.messages as Dict[])
    .filter((m) => m.message_type === "offer" || m.message_type === "counteroffer")
    .map((m) => m.protocol_act_hash as string);
  const docs = vector.did_documents as Record<string, Dict>;
  expect(verifyTransactionRecordReason(record, docs, offers)).toBeNull();
  expect(verifyTransactionRecordReason(record, { ...docs }, offers)).toBeNull();
  expect(verifyTransactionRecordReason(record, Object.create(docs) as Record<string, Dict>, offers)).toBe(
    "KEY_NOT_FOUND",
  );
});

test("the evidence verifier reads a resolver's own entries only", () => {
  const [manager, session] = managerWithSession();
  manager.processMessage(session, signedWithdrawal(session.session_id, "w-1"));
  const docs = {
    [INITIATOR_DID]: makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUB)),
  };
  const evidence = generateSessionEvidenceRecord(session, {
    producerPrivateKey: INITIATOR_KEY,
    producerDid: INITIATOR_DID,
    producerAgentId: "buyer",
    producerVerificationMethod: INITIATOR_VM,
  });
  expect(assessSessionEvidenceRecord(evidence, docs).reason).toBeNull();
  const inherited = assessSessionEvidenceRecord(evidence, Object.create(docs) as Record<string, Dict>);
  expect(inherited.reason).toBe("KEY_NOT_FOUND");
  expect(inherited.unresolved_keys).toEqual(
    expect.arrayContaining([{ did: INITIATOR_DID, verification_method: INITIATOR_VM }]),
  );
});

// ---------------------------------------------------------------------------
// Objects rebuilt from caller input keep an own __proto__ member
// ---------------------------------------------------------------------------

test("dropNone keeps an own __proto__ member of any type", () => {
  for (const value of ["member", 7, true, [{ x: 1 }]]) {
    const result = dropNone(withOwnProto({ a: 1 }, value));
    expect(hasOwn(result, "__proto__")).toBe(true);
    expect(result.__proto__).toEqual(value);
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
  }
});

test("dropNone keeps an own __proto__ member, at any depth", () => {
  const nested = withOwnProto({ a: 1 }, { x: 1 });
  const result = dropNone({ top: nested, keep: 2, drop: null });
  expect(Object.keys(result)).toEqual(["top", "keep"]);
  const top = result.top as Dict;
  expect(hasOwn(top, "__proto__")).toBe(true);
  expect(Object.getPrototypeOf(top)).toBe(Object.prototype);
  expect(JSON.stringify(result)).toBe('{"top":{"a":1,"__proto__":{"x":1}},"keep":2}');
});

test("an invitation signature covers an own __proto__ member", () => {
  const { privateKey, publicKey } = generateKeypair();
  const invitation = inboundInvitation(randomUUID());
  invitation.invitation_signature = signInvitation(invitation, privateKey);
  expect(verifyInvitationSignature(invitation, publicKey)).toBe(true);
  // A member added after signing is not covered, whatever its name.
  const extended = withOwnProto(invitation, { inviter_did: "did:web:other.example" });
  expect(verifyInvitationSignature(extended, publicKey)).toBe(false);
  // And one present when signing is covered.
  const signedWith = withOwnProto(inboundInvitation(randomUUID()), "member");
  signedWith.invitation_signature = signInvitation(signedWith, privateKey);
  expect(verifyInvitationSignature(signedWith, publicKey)).toBe(true);
  const without = Object.fromEntries(Object.entries(signedWith).filter(([key]) => key !== "__proto__"));
  expect(hasOwn(without, "__proto__")).toBe(false);
  expect(verifyInvitationSignature(without, publicKey)).toBe(false);
});

test("the Vendr webhook body keeps an own __proto__ member", () => {
  const body = webhookBodyForSignature(withOwnProto({ event: "x" }, { a: 1 })).toString("utf-8");
  expect(body).toBe('{"__proto__":{"a":1},"event":"x"}');
});

test("DocuSign signer contacts are looked up by own DID only", () => {
  const envelope = a2cnRecordToDocusignEnvelope(
    {
      session_id: "s-1",
      record_hash: "h",
      agreed_terms: { total_value: 100, currency: "USD" },
      parties: {
        initiator: { did: "constructor", organization_name: "TechCorp", email: "buyer@techcorp.example" },
        responder: { did: "toString", organization_name: "Acme", email: "seller@acme.example" },
      },
    },
    {},
  );
  const signers = (envelope.recipients as Dict).signers as Dict[];
  expect(signers.map((signer) => [signer.name, signer.email])).toEqual([
    ["TechCorp", "buyer@techcorp.example"],
    ["Acme", "seller@acme.example"],
  ]);
});

// ---------------------------------------------------------------------------
// A2CNClient and the MCP session store
// ---------------------------------------------------------------------------

function ackFetch(sessionId: string): typeof fetch {
  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const sent = JSON.parse(String(init?.body)) as Dict;
    const ack = {
      message_type: "session_ack",
      message_id: randomUUID(),
      session_id: sessionId,
      in_reply_to: sent.message_id,
      protocol_version: sent.protocol_version,
      session_params_accepted: sent.session_params,
      responder: { did: RESPONDER_DID },
      responder_mandate: { mandate_type: "declared" },
      session_created_at: "2026-03-24T10:00:00Z",
      current_turn: "initiator",
    };
    return new Response(JSON.stringify(ack), { status: 201 });
  }) as typeof fetch;
}

test.each(INHERITED_IDS)("the client caches a session acknowledged as %j as an ordinary entry", async (id) => {
  const client = new A2CNClient({
    agentInfo: { did: INITIATOR_DID, verification_method: INITIATOR_VM, agent_id: "buyer" },
    privateKey: INITIATOR_KEY,
    mandate: { mandate_type: "declared" },
    fetchFn: ackFetch(id),
  });
  await client.initiateSession("https://acme.example", RESPONDER_DID, {
    deal_type: "saas_renewal",
    currency: "USD",
    max_rounds: 4,
  });
  expect(Object.getPrototypeOf(client._sessions)).toBe(Object.prototype);
  expect(Object.keys(client._sessions)).toEqual([id]);
  expect(client._sessions[id].session_ack.session_id).toBe(id);
});

test.each(INHERITED_IDS)("MCP tools report session %j as not found", async (id) => {
  const ctx = createMcpContext({ fetchFn: (async () => new Response(null, { status: 503 })) as typeof fetch });
  for (const result of [
    await ctx.a2cnGetSessionStatus(id),
    await ctx.a2cnAccept(id),
    await ctx.a2cnReject(id),
    await ctx.a2cnSendOffer({ session_id: id, total_value_cents: 1, payment_terms_net_days: 30 }),
  ]) {
    expect(result.error).toBe("session_not_found");
  }
  expect(() => ctx.injectCounterpartyOffer(id, {})).toThrow(/not found in MCP session store/);
});

function mcpFetch(sessionId: string, posted: Dict[]): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    const urlStr = String(url);
    if (urlStr.endsWith("/.well-known/a2cn-agent")) {
      return new Response(JSON.stringify({ a2cn_version: "0.3", agent_did: RESPONDER_DID }), {
        status: 200,
      });
    }
    if (urlStr.endsWith("/sessions")) {
      return ackFetch(sessionId)(url, init);
    }
    posted.push(JSON.parse(String(init?.body)) as Dict);
    return new Response(JSON.stringify({ status: "received" }), { status: 200 });
  }) as typeof fetch;
}

async function mcpInitiate(
  ctx: ReturnType<typeof createMcpContext>,
  customTerms: Dict | null = null,
): Promise<Dict> {
  return ctx.a2cnInitiateSession({
    counterparty_did: RESPONDER_DID,
    deal_type: "saas_renewal",
    my_did: ctx.agentDid,
    initial_offer_total_value_cents: 9_500_000,
    currency: "USD",
    max_rounds: 4,
    payment_terms_net_days: 30,
    subject: "renewal",
    custom_terms: customTerms,
  });
}

test.each(INHERITED_IDS)("MCP stores a session acknowledged as %j as an ordinary entry", async (id) => {
  const posted: Dict[] = [];
  const ctx = createMcpContext({ fetchFn: mcpFetch(id, posted) });
  const started = await mcpInitiate(ctx);
  expect(started.error).toBeUndefined();
  expect(started.session_id).toBe(id);
  expect(Object.getPrototypeOf(ctx.sessions)).toBe(Object.prototype);
  expect(Object.keys(ctx.sessions)).toEqual([id]);
  const status = await ctx.a2cnGetSessionStatus(id);
  expect(status.error).toBeUndefined();
  expect((await ctx.a2cnGetSessionStatus("status")).error).toBe("session_not_found");
});

test.each(INHERITED_IDS)("MCP keeps a session %j whose opening offer failed", async (id) => {
  const base = mcpFetch(id, []);
  const fetchFn = (async (url: string | URL | Request, init?: RequestInit) => {
    if (String(url).endsWith("/messages")) {
      return new Response(JSON.stringify({ error: { code: "INTERNAL_ERROR" } }), { status: 500 });
    }
    return base(url, init);
  }) as typeof fetch;
  const ctx = createMcpContext({ fetchFn });
  const started = await mcpInitiate(ctx);
  expect(started.error).toBe("opening_offer_failed");
  expect(Object.getPrototypeOf(ctx.sessions)).toBe(Object.prototype);
  expect(Object.keys(ctx.sessions)).toEqual([id]);
  expect((await ctx.a2cnGetSessionStatus(id)).error).toBeUndefined();
});

test("MCP custom terms keep an own __proto__ member", async () => {
  const posted: Dict[] = [];
  const ctx = createMcpContext({ fetchFn: mcpFetch("s-mcp", posted) });
  const started = await mcpInitiate(ctx, withOwnProto({ seat_count: 10 }, { tier: "gold" }));
  expect(started.error).toBeUndefined();
  const opening = posted[0].terms as Dict;
  expect(hasOwn(opening, "__proto__")).toBe(true);
  expect(Object.getPrototypeOf(opening)).toBe(Object.prototype);
  expect(opening.seat_count).toBe(10);

  const sent = await ctx.a2cnSendOffer({
    session_id: "s-mcp",
    total_value_cents: 9_000_000,
    payment_terms_net_days: 30,
    custom_terms: withOwnProto({ seat_count: 12 }, { tier: "silver" }),
  });
  expect(sent.error).toBeUndefined();
  const counter = posted[1].terms as Dict;
  expect(hasOwn(counter, "__proto__")).toBe(true);
  expect(Object.getPrototypeOf(counter)).toBe(Object.prototype);
});

// ---------------------------------------------------------------------------
// HTTP routes
// ---------------------------------------------------------------------------

const SESSION_ROUTES: Array<["GET" | "POST", string]> = [
  ["GET", ""],
  ["POST", "/messages"],
  ["POST", "/approval-receipt"],
  ["GET", "/messages"],
  ["GET", "/record"],
  ["GET", "/evidence"],
  ["GET", "/audit"],
  ["POST", "/delivery-notice"],
  ["POST", "/delivery-acknowledged"],
  ["POST", "/dispute-notice"],
  ["POST", "/dispute-resolved"],
  ["GET", "/fulfillment-attestation"],
];

const SESSION_ROUTE_CASES = INHERITED_IDS.flatMap((id) =>
  SESSION_ROUTES.map(([method, suffix]) => [method, id, suffix] as const),
);

test.each(SESSION_ROUTE_CASES)("%s /sessions/%s%s is SESSION_NOT_FOUND", async (method, id, suffix) => {
  const { client } = freshServer();
  const path = `/sessions/${id}${suffix}`;
  const res =
    method === "GET"
      ? await client.get(path)
      : await client.post(path, { json: { message_type: "x", message_id: randomUUID() } });
  expect(res.statusCode).toBe(404);
  expect((res.json().error as Dict).code).toBe("SESSION_NOT_FOUND");
});

test.each(INHERITED_IDS)("POST /sessions with message_id %j creates a session", async (id) => {
  const { client } = freshServer();
  const body = makeSessionInit(id);
  const first = await client.post("/sessions", { json: body });
  expect(first.statusCode).toBe(201);
  const sessionId = first.json().session_id as string;
  expect(typeof sessionId).toBe("string");
  const state = await client.get(`/sessions/${sessionId}`);
  expect(state.statusCode).toBe(200);
  // The retransmission is answered from the stored response.
  const again = await client.post("/sessions", { json: body });
  expect(again.statusCode).toBe(200);
  expect(again.json().session_id).toBe(sessionId);
  // Idempotency is keyed on message_id ahead of validation, as in Python.
  const invalid = await client.post("/sessions", { json: { message_id: id } });
  expect(invalid.statusCode).toBe(200);
});

test.each(INHERITED_IDS)("POST /sessions with message_id %j is still validated", async (id) => {
  const { client } = freshServer();
  const res = await client.post("/sessions", { json: { message_id: id } });
  expect(res.statusCode).toBe(400);
  expect((res.json().error as Dict).code).toBe("INTERNAL_ERROR");
});

test.each(INHERITED_IDS)("a session message with message_id %j is validated and applied", async (id) => {
  const { client } = freshServer();
  const created = await client.post("/sessions", { json: makeSessionInit() });
  const sessionId = created.json().session_id as string;

  const bogus = await client.post(`/sessions/${sessionId}/messages`, {
    json: { message_type: "bogus", message_id: id, sender_did: INITIATOR_DID, session_id: sessionId },
  });
  expect(bogus.statusCode).toBe(422);
  expect((bogus.json().error as Dict).code).toBe("WRONG_MESSAGE_TYPE");
});

test.each(INHERITED_IDS)("a signed withdrawal with message_id %j withdraws the session", async (id) => {
  const fixture = freshServer();
  const created = await fixture.client.post("/sessions", { json: makeSessionInit() });
  const sessionId = created.json().session_id as string;
  const withdrawal = signDecline(
    {
      message_type: "withdrawal",
      message_id: id,
      session_id: sessionId,
      round_number: 1,
      sequence_number: 1,
      sender_did: INITIATOR_DID,
      sender_agent_id: "test-agent",
      timestamp: "2026-03-24T10:02:00Z",
      reason_code: "STRATEGY_DECISION",
    },
    fixture.initiatorKeypair.privateKey,
    INITIATOR_VM,
  );
  const res = await fixture.client.post(`/sessions/${sessionId}/messages`, { json: withdrawal });
  expect(res.statusCode).toBe(200);
  const state = await fixture.client.get(`/sessions/${sessionId}`);
  expect(state.json().state).toBe("WITHDRAWN");
});

test.each(INHERITED_IDS)("GET /invitations/%s is INVITATION_NOT_FOUND", async (id) => {
  const { rawClient } = freshServer();
  const res = await rawClient.get(`/invitations/${id}`);
  expect(res.statusCode).toBe(404);
  expect((res.json().error as Dict).code).toBe("INVITATION_NOT_FOUND");
});

test.each(INHERITED_IDS.flatMap((id) => [[id, "accept"], [id, "decline"]] as const))(
  "POST /invitations/%s/%s is INVITATION_NOT_FOUND",
  async (id, action) => {
    const { client } = freshServer();
    const res = await client.post(`/invitations/${id}/${action}`, { json: {} });
    expect(res.statusCode).toBe(404);
    expect((res.json().error as Dict).code).toBe("INVITATION_NOT_FOUND");
  },
);

function signedInbound(
  fixture: ReturnType<typeof freshServer>,
  invitationId: string,
): Dict {
  const { privateKey, publicKey } = generateKeypair();
  const inviterDid = "did:web:buyer.example";
  fixture.ctx.registerDidDocument(inviterDid, makeDidDocument(inviterDid, "key-1", publicKeyToJwk(publicKey)));
  const invitation = inboundInvitation(invitationId);
  invitation.invitation_signature = signInvitation(invitation, privateKey);
  return invitation;
}

test("POST /invitations stores invitation_id __proto__ as an ordinary invitation", async () => {
  const fixture = freshServer();
  const res = await fixture.rawClient.post("/invitations", { json: signedInbound(fixture, "__proto__") });
  expect(res.statusCode).toBe(201);
  expect(res.json()).toEqual({ invitation_id: "__proto__", status: "pending" });

  const store = fixture.ctx.invitationStore;
  expect(Object.getPrototypeOf(store._invitations)).toBe(Object.prototype);
  expect(Object.keys(store._invitations)).toEqual(["__proto__"]);

  const fetched = await fixture.rawClient.get("/invitations/__proto__");
  expect(fetched.statusCode).toBe(200);
  expect(fetched.json().status).toBe("pending");
  for (const name of ["status", "invitation", "created_at", "answered_at", "constructor"]) {
    const other = await fixture.rawClient.get(`/invitations/${name}`);
    expect(other.statusCode).toBe(404);
    const declined = await fixture.client.post(`/invitations/${name}/decline`, { json: {} });
    expect(declined.statusCode).toBe(404);
  }
  const accepted = await fixture.client.post("/invitations/__proto__/accept", { json: {} });
  expect(accepted.statusCode).toBe(200);
  expect(accepted.json().invitation_id).toBe("__proto__");
});

test.each(INHERITED_IDS)("POST /invitations from inviter_did %j is not resolved from the override map", async (id) => {
  const { rawClient } = freshServer();
  const res = await rawClient.post("/invitations", {
    json: {
      ...inboundInvitation(randomUUID()),
      inviter_did: id,
      inviter_verification_method: `${id}#key-1`,
      invitation_signature: "abc",
    },
  });
  expect(res.statusCode).toBe(503);
  expect((res.json().error as Dict).code).toBe("DID_RESOLUTION_FAILED");
});

test("POST /invitations refuses a member added after signing, named __proto__", async () => {
  const fixture = freshServer();
  const invitation = signedInbound(fixture, randomUUID());
  const res = await fixture.rawClient.post("/invitations", {
    json: withOwnProto(invitation, { status: "accepted" }),
  });
  expect(res.statusCode).toBe(400);
  expect((res.json().error as Dict).code).toBe("INVITATION_SIGNATURE_INVALID");
  expect(Object.keys(fixture.ctx.invitationStore._invitations)).toEqual([]);
});

test("POST /invitations/create signs the invitation it returns, own __proto__ member included", async () => {
  const fixture = freshServer();
  const res = await fixture.client.post("/invitations/create", {
    json: {
      proposed_deal_type: "saas_renewal",
      proposed_terms_summary: withOwnProto({ total_value: 9_500_000 }, { tier: "gold" }),
    },
  });
  expect(res.statusCode).toBe(201);
  const invitation = res.json();
  expect(hasOwn(invitation.proposed_terms_summary as Dict, "__proto__")).toBe(true);
  expect(verifyInvitationSignature(invitation, fixture.responderKeypair.publicKey)).toBe(true);
});

test.each(INHERITED_IDS)("a JWT issued by %j is resolved, not read from the override map", async (id) => {
  const fixture = freshServer();
  const client = makeTestClient(fixture.ctx, {
    issuerDid: id,
    audienceDid: fixture.ctx.SERVER_DID,
    privateKey: fixture.initiatorKeypair.privateKey,
    kid: `${id}#key-1`,
  });
  const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
  try {
    const res = await client.get("/sessions/any");
    expect(res.statusCode).toBe(401);
    expect((res.json().error as Dict).code).toBe("INVALID_JWT");
    expect(warn.mock.calls.map((call) => String(call[0]))).toEqual([
      expect.stringMatching(/^Could not resolve issuer DID/),
    ]);
  } finally {
    warn.mockRestore();
  }
});

test.each(INHERITED_IDS)("the server registers a DID document under %j as an ordinary entry", (id) => {
  const fixture = freshServer();
  const before = Object.keys(fixture.ctx.didDocOverride);
  fixture.ctx.registerDidDocument(id, { id });
  expect(Object.getPrototypeOf(fixture.ctx.didDocOverride)).toBe(Object.prototype);
  expect(Object.keys(fixture.ctx.didDocOverride)).toEqual([...before, id]);
  expect(fixture.ctx.manager.hasDidDocument(id)).toBe(true);
});

test("a deal type named constructor takes the default round cap", async () => {
  const fixture = freshServer();
  fixture.ctx.configureResponder({
    ...fixture.responderConfig,
    deal_types: ["constructor"],
    max_rounds_by_deal_type: {},
  });
  const body = makeSessionInit();
  (body.session_params as Dict).deal_type = "constructor";
  (body.initiator_mandate as Dict).authorized_deal_types = ["constructor"];
  const res = await fixture.client.post("/sessions", { json: body });
  expect(res.statusCode).toBe(201);
  expect((res.json().session_params_accepted as Dict).max_rounds).toBe(4);
});

test("a webhook body keeps an own __proto__ member", async () => {
  const fixture = freshServer();
  const bodies: string[] = [];
  fixture.ctx.fetchFn = (async (_url: string | URL | Request, init?: RequestInit) => {
    bodies.push(Buffer.from(init?.body as Buffer).toString("utf-8"));
    return new Response(null, { status: 204 });
  }) as typeof fetch;
  await fixture.ctx.deliverWebhook(
    "https://hooks.example/a2cn",
    "session.completed",
    "s-1",
    withOwnProto({ event_type: "session.completed" }, { a: 1 }),
  );
  expect(bodies).toEqual(['{"__proto__":{"a":1},"event_type":"session.completed"}']);
});
