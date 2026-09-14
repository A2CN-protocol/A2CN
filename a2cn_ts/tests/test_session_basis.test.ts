/**
 * Tests for session_params.basis: carried, enum-checked, and fixed at initiation.
 *
 * Verdicts come from spec/test-vectors/session-params-basis.json, which the
 * Python suite asserts too. basis is a label: nothing here converts net and
 * gross, and an absent basis stays absent (no default).
 */

import { randomUUID, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { A2CNClient } from "../src/a2cn/client.js";
import { generateKeypair, hashObject, signJws } from "../src/a2cn/crypto.js";
import { SessionParams, type Dict } from "../src/a2cn/messages.js";
import { A2CNError, SESSION_BASES, SessionManager } from "../src/a2cn/session.js";
import { INITIATOR_DID, RESPONDER_DID, freshServer, makeSessionInit } from "./conftest.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VECTORS = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "session-params-basis.json"), "utf-8"),
) as {
  valid_bases: unknown[];
  invalid_bases: unknown[];
  invalid_currencies: unknown[];
  malformed_accepted: unknown[];
  malformed_session_params: unknown[];
  malformed_ack_bodies: unknown[];
  ack_cases: Dict[];
};
const INVITATION_SCHEMA = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "schemas", "session-invitation.schema.json"), "utf-8"),
) as Dict;
const NOW = "2026-03-24T10:00:00Z";

function headers(messageId: string): Record<string, string> {
  return { "Content-Type": "application/a2cn+json", "Idempotency-Key": messageId };
}

/** A SessionInit/SessionAck pair that differ only in the given money parameters. */
function initAndAck(proposed: Dict, accepted: Dict): [Dict, Dict] {
  const timing = {
    deal_type: "saas_renewal",
    max_rounds: 4,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
  };
  const sessionInit = makeSessionInit();
  sessionInit.session_params = { ...timing, subject: "Test negotiation", ...proposed };
  const sessionAck: Dict = {
    message_type: "session_ack",
    message_id: randomUUID(),
    session_id: "sess-basis",
    in_reply_to: sessionInit.message_id,
    protocol_version: "0.2",
    session_params_accepted: { ...timing, ...accepted },
    responder: { did: RESPONDER_DID },
    responder_mandate: { mandate_type: "declared" },
    session_created_at: NOW,
    current_turn: "initiator",
  };
  return [sessionInit, sessionAck];
}

/** A signed round-`rnd` offer or counteroffer; its terms carry no basis field. */
function signedOffer(
  sessionId: string,
  rnd: number,
  senderDid: string,
  privateKey: KeyObject,
  inReplyTo: string | null = null,
): Dict {
  const timestamp = "2026-03-24T10:01:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const messageType = rnd === 1 ? "offer" : "counteroffer";
  const terms = { total_value: 9_500_000, currency: "USD" };
  const protocolActHash = hashObject({
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: rnd,
    sequence_number: rnd,
    message_type: messageType,
    sender_did: senderDid,
    timestamp,
    expires_at: expiresAt,
    terms,
  });
  const verificationMethod =
    senderDid === INITIATOR_DID ? `${INITIATOR_DID}#key-1` : `${RESPONDER_DID}#key-2026-01`;
  const msg: Dict = {
    message_type: messageType,
    message_id: randomUUID(),
    session_id: sessionId,
    round_number: rnd,
    sequence_number: rnd,
    sender_did: senderDid,
    sender_agent_id: "test-agent",
    sender_verification_method: verificationMethod,
    timestamp,
    expires_at: expiresAt,
    terms,
    protocol_act_hash: protocolActHash,
    protocol_act_signature: signJws(protocolActHash, privateKey, verificationMethod),
  };
  if (inReplyTo) {
    msg.in_reply_to = inReplyTo;
  }
  return msg;
}

function expectA2CNError(fn: () => unknown): A2CNError {
  try {
    fn();
  } catch (exc) {
    if (exc instanceof A2CNError) {
      return exc;
    }
    throw exc;
  }
  throw new Error("Expected A2CNError to be thrown");
}

// ---------------------------------------------------------------------------
// The enum: vectors, implementation, and schema agree
// ---------------------------------------------------------------------------

test("vector bases match implementation and schema", () => {
  const paramsSchema = (INVITATION_SCHEMA.properties as Dict).proposed_session_params as Dict;
  const basisSchema = (paramsSchema.properties as Dict).basis as Dict;
  expect(VECTORS.valid_bases).toEqual([...SESSION_BASES]);
  expect(basisSchema.enum).toEqual([...SESSION_BASES]);
  expect(paramsSchema.required).not.toContain("basis");
});

// ---------------------------------------------------------------------------
// SessionManager.createSession
// ---------------------------------------------------------------------------

test.each(VECTORS.ack_cases.map((c) => [c.name as string, c]))(
  "session ack money params fixed at initiation: %s",
  (_name, c) => {
    const [sessionInit, sessionAck] = initAndAck(c.proposed as Dict, c.accepted as Dict);
    const manager = new SessionManager();
    if (c.valid) {
      const session = manager.createSession("sess-basis", sessionInit, sessionAck, NOW);
      expect(session.session_params).toEqual(sessionAck.session_params_accepted);
    } else {
      const err = expectA2CNError(() =>
        manager.createSession("sess-basis", sessionInit, sessionAck, NOW),
      );
      expect(err.code).toBe(c.error);
      expect(err.message).toContain(c.changed as string);
      expect(manager.getSession("sess-basis")).toBeNull();
    }
  },
);

test.each(VECTORS.invalid_bases.map((b) => [JSON.stringify(b), b]))(
  "unrecognized basis rejected even when echoed: %s",
  (_label, basis) => {
    const money = { currency: "USD", basis };
    const [sessionInit, sessionAck] = initAndAck(money, money);
    const err = expectA2CNError(() =>
      new SessionManager().createSession("sess-basis", sessionInit, sessionAck, NOW),
    );
    expect(err.code).toBe("INVALID_BASIS");
  },
);

test.each(VECTORS.invalid_currencies.map((c) => [JSON.stringify(c), c]))(
  "malformed currency rejected even when echoed: %s",
  (_label, currency) => {
    const money = { currency };
    const [sessionInit, sessionAck] = initAndAck(money, money);
    const err = expectA2CNError(() =>
      new SessionManager().createSession("sess-basis", sessionInit, sessionAck, NOW),
    );
    expect(err.code).toBe("INVALID_REQUEST");
  },
);

test("missing currency rejected", () => {
  const [sessionInit, sessionAck] = initAndAck({}, {});
  const err = expectA2CNError(() =>
    new SessionManager().createSession("sess-basis", sessionInit, sessionAck, NOW),
  );
  expect(err.code).toBe("INVALID_REQUEST");
  expect(err.message).toContain("currency");
});

test.each(VECTORS.malformed_accepted.map((a) => [JSON.stringify(a), a]))(
  "create session rejects malformed session params accepted: %s",
  (_label, accepted) => {
    const [sessionInit, sessionAck] = initAndAck({ currency: "USD" }, { currency: "USD" });
    sessionAck.session_params_accepted = accepted;
    const err = expectA2CNError(() =>
      new SessionManager().createSession("sess-basis", sessionInit, sessionAck, NOW),
    );
    expect(err.code).toBe("INVALID_REQUEST");
  },
);

test.each(VECTORS.malformed_session_params.map((p) => [JSON.stringify(p), p]))(
  "create session rejects malformed session params: %s",
  (_label, params) => {
    const [sessionInit, sessionAck] = initAndAck({ currency: "USD" }, { currency: "USD" });
    sessionInit.session_params = params;
    const err = expectA2CNError(() =>
      new SessionManager().createSession("sess-basis", sessionInit, sessionAck, NOW),
    );
    expect(err.code).toBe("INVALID_REQUEST");
  },
);

// ---------------------------------------------------------------------------
// POST /sessions (responder)
// ---------------------------------------------------------------------------

test("basis echoed and pinned across rounds", async () => {
  const fixture = freshServer();
  const responderClient = fixture.makeResponderClient();
  const body = makeSessionInit();
  (body.session_params as Dict).basis = "gross";
  const r = await fixture.client.post("/sessions", {
    json: body,
    headers: headers(body.message_id as string),
  });
  expect(r.statusCode).toBe(201);
  expect((r.json().session_params_accepted as Dict).basis).toBe("gross");
  const sessionId = r.json().session_id as string;

  const offer = signedOffer(sessionId, 1, INITIATOR_DID, fixture.initiatorKeypair.privateKey);
  const counter = signedOffer(
    sessionId,
    2,
    RESPONDER_DID,
    fixture.responderKeypair.privateKey,
    offer.message_id as string,
  );
  for (const [client, message] of [
    [fixture.client, offer],
    [responderClient, counter],
  ] as const) {
    const posted = await client.post(`/sessions/${sessionId}/messages`, {
      json: message,
      headers: headers(message.message_id as string),
    });
    expect(posted.statusCode).toBe(200);
    const state = (await fixture.client.get(`/sessions/${sessionId}`)).json();
    expect(state.round_number).toBe(message.round_number);
    expect((state.session_params as Dict).basis).toBe("gross");
  }
});

test("absent basis is no signal", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  expect("basis" in (body.session_params as Dict)).toBe(false);
  const r = await client.post("/sessions", { json: body, headers: headers(body.message_id as string) });
  expect(r.statusCode).toBe(201);
  expect("basis" in (r.json().session_params_accepted as Dict)).toBe(false);
  const state = (await client.get(`/sessions/${r.json().session_id as string}`)).json();
  expect("basis" in (state.session_params as Dict)).toBe(false);
});

test("unrecognized basis rejected at session init", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  (body.session_params as Dict).basis = "vat";
  const r = await client.post("/sessions", { json: body, headers: headers(body.message_id as string) });
  expect(r.statusCode).toBe(400);
  expect((r.json().error as Dict).code).toBe("INVALID_BASIS");
});

test("missing currency rejected at session init", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  delete (body.session_params as Dict).currency;
  const r = await client.post("/sessions", { json: body, headers: headers(body.message_id as string) });
  expect(r.statusCode).toBe(400);
  expect((r.json().error as Dict).code).toBe("INVALID_REQUEST");
});

// ---------------------------------------------------------------------------
// A2CNClient.initiateSession (the initiator receives the SessionAck)
// ---------------------------------------------------------------------------

const OMITTED = Symbol("omitted");

/** An initiator whose responder answers every request with `respond`. */
function clientWith(respond: typeof fetch): A2CNClient {
  return new A2CNClient({
    agentInfo: {
      did: INITIATOR_DID,
      verification_method: `${INITIATOR_DID}#key-1`,
      agent_id: "test-agent",
    },
    privateKey: generateKeypair().privateKey,
    mandate: { mandate_type: "declared" },
    fetchFn: respond,
  });
}

/**
 * An initiator whose responder answers any SessionInit with `accepted` params.
 * `OMITTED` leaves session_params_accepted out of the SessionAck.
 */
function clientAnsweringWith(accepted: unknown): A2CNClient {
  const respond: typeof fetch = async (_input, init) => {
    const ack: Dict = {
      message_type: "session_ack",
      message_id: randomUUID(),
      session_id: "sess-basis",
      in_reply_to: (JSON.parse(init?.body as string) as Dict).message_id,
      protocol_version: "0.2",
      responder: { did: RESPONDER_DID },
      responder_mandate: { mandate_type: "declared" },
      session_created_at: NOW,
      current_turn: "initiator",
    };
    if (accepted !== OMITTED) {
      ack.session_params_accepted = accepted;
    }
    return new Response(JSON.stringify(ack), { status: 201 });
  };
  return clientWith(respond);
}

test.each(VECTORS.ack_cases.map((c) => [c.name as string, c]))(
  "client checks session ack money params: %s",
  async (_name, c) => {
    const [sessionInit, sessionAck] = initAndAck(c.proposed as Dict, c.accepted as Dict);
    const client = clientAnsweringWith(sessionAck.session_params_accepted);
    const proposed = sessionInit.session_params as Dict;
    if (c.valid) {
      const ack = await client.initiateSession("https://acme.example", RESPONDER_DID, proposed);
      expect(ack.session_params_accepted).toEqual(sessionAck.session_params_accepted);
      expect("sess-basis" in client._sessions).toBe(true);
    } else {
      const err = await client
        .initiateSession("https://acme.example", RESPONDER_DID, proposed)
        .catch((exc: unknown) => exc);
      expect(err).toBeInstanceOf(A2CNError);
      expect((err as A2CNError).code).toBe(c.error);
      expect((err as A2CNError).message).toContain(c.changed as string);
      expect(client._sessions).toEqual({});
    }
  },
);

const MALFORMED_ACKS: [string, unknown][] = [
  ...VECTORS.malformed_accepted.map((a): [string, unknown] => [JSON.stringify(a), a]),
  ["omitted", OMITTED],
];

test.each(MALFORMED_ACKS)(
  "client rejects malformed session params accepted: %s",
  async (_label, accepted) => {
    const client = clientAnsweringWith(accepted);
    const params = { ...(makeSessionInit().session_params as Dict), basis: "gross" };
    const err = await client
      .initiateSession("https://acme.example", RESPONDER_DID, params)
      .catch((exc: unknown) => exc);
    expect(err).toBeInstanceOf(A2CNError);
    expect((err as A2CNError).code).toBe("INVALID_REQUEST");
    expect(client._sessions).toEqual({});
  },
);

test.each(VECTORS.malformed_ack_bodies.map((b) => [JSON.stringify(b), b]))(
  "client rejects malformed ack body: %s",
  async (_label, body) => {
    const client = clientWith(async () => new Response(JSON.stringify(body), { status: 201 }));
    const params = { ...(makeSessionInit().session_params as Dict), basis: "gross" };
    const err = await client
      .initiateSession("https://acme.example", RESPONDER_DID, params)
      .catch((exc: unknown) => exc);
    expect(err).toBeInstanceOf(A2CNError);
    expect((err as A2CNError).code).toBe("INVALID_REQUEST");
    expect(client._sessions).toEqual({});
  },
);

// ---------------------------------------------------------------------------
// SessionParams and the SessionInvitation schema
// ---------------------------------------------------------------------------

test("session params carry basis only when set", () => {
  const fields = {
    deal_type: "saas_renewal",
    currency: "USD",
    subject: "Test",
    max_rounds: 4,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
  };
  expect(new SessionParams({ ...fields, basis: "gross" }).toDict().basis).toBe("gross");
  expect("basis" in new SessionParams(fields).toDict()).toBe(false);
});

// No JSON Schema validator is a dependency here, so this reads the schema's
// basis constraint directly; the Python suite runs a full Draft 2020-12
// validation over the same vectors.
test("invitation schema accepts only enumerated bases", () => {
  const paramsSchema = (INVITATION_SCHEMA.properties as Dict).proposed_session_params as Dict;
  const basisSchema = ((paramsSchema.properties as Dict).basis ?? {}) as Dict;
  const allowed = (basisSchema.enum ?? []) as unknown[];
  expect(basisSchema.type).toBe("string");
  for (const basis of VECTORS.valid_bases) {
    expect(allowed.includes(basis)).toBe(true);
  }
  for (const basis of VECTORS.invalid_bases) {
    expect(allowed.includes(basis)).toBe(false);
  }
});
