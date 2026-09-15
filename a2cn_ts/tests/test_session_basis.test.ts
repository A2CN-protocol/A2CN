/**
 * Tests for session_params.basis: carried, enum-checked, fixed at initiation, and
 * restated in every offer's terms.basis.
 *
 * Verdicts come from spec/test-vectors/session-params-basis.json, which the
 * Python suite asserts too. basis is a label: nothing here converts net and
 * gross, and an absent basis stays absent (no default).
 */

import { randomUUID, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { expect, test } from "vitest";

import { A2CNClient } from "../src/a2cn/client.js";
import { generateKeypair, hashObject, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import { SessionParams, TermsObject, type Dict } from "../src/a2cn/messages.js";
import {
  A2CNError,
  SESSION_BASES,
  Session,
  SessionManager,
  SessionState,
} from "../src/a2cn/session.js";
import {
  INITIATOR_DID,
  RESPONDER_DID,
  freshServer,
  makeDidDocument,
  makeSessionInit,
} from "./conftest.js";

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
  offer_cases: Dict[];
};
const INVITATION_SCHEMA = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "schemas", "session-invitation.schema.json"), "utf-8"),
) as Dict;
const MONEY_PARAM_FIXTURES: Record<string, Dict> = Object.fromEntries(
  ["offer_basis_diverges_from_session", "offer_currency_diverges_from_session"].map((name) => [
    name,
    JSON.parse(
      readFileSync(join(REPO_ROOT, "spec", "conformance-fixtures", `${name}.json`), "utf-8"),
    ) as Dict,
  ]),
);
const NOW = "2026-03-24T10:00:00Z";

const { privateKey: INITIATOR_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();
const DID_DOCUMENTS: Record<string, Dict> = {
  [INITIATOR_DID]: makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUBLIC_KEY)),
  [RESPONDER_DID]: makeDidDocument(
    RESPONDER_DID,
    "key-2026-01",
    publicKeyToJwk(RESPONDER_PUBLIC_KEY),
  ),
};

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

function termsWith(basis: unknown): Dict {
  return { total_value: 9_500_000, currency: "USD", basis };
}

/** A signed round-`rnd` offer or counteroffer carrying `terms` verbatim. */
function signedOffer(
  sessionId: string,
  rnd: number,
  senderDid: string,
  privateKey: KeyObject,
  terms: unknown,
  inReplyTo: string | null = null,
): Dict {
  const timestamp = "2026-03-24T10:01:00Z";
  const expiresAt = "2030-01-01T00:00:00Z";
  const messageType = rnd === 1 ? "offer" : "counteroffer";
  const signedTerms = structuredClone(terms);
  const protocolActHash = hashObject({
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: rnd,
    sequence_number: rnd,
    message_type: messageType,
    sender_did: senderDid,
    timestamp,
    expires_at: expiresAt,
    terms: signedTerms,
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
    terms: signedTerms,
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
// SessionAck money parameters are validated before they are compared (Section 6.4.1)
// ---------------------------------------------------------------------------

const ABSENT = Symbol("absent");

/**
 * Every invalid basis and malformed currency as a SessionAck's session_params_accepted.
 *
 * Each case has the shape of an ack_cases entry. A receiver validates
 * session_params_accepted before comparing it with session_params, so each is
 * refused with its own error code, naming the accepted parameter, whatever the
 * SessionInit proposed; never with SESSION_PARAM_CHANGED.
 */
function malformedAcceptedMoneyCases(): [string, Dict][] {
  const cases: [string, Dict][] = [];
  for (const proposedBasis of [...VECTORS.valid_bases, ABSENT]) {
    const proposed: Dict = { currency: "USD" };
    if (proposedBasis !== ABSENT) {
      proposed.basis = proposedBasis;
    }
    const label = proposedBasis === ABSENT ? "no-basis" : String(proposedBasis);
    for (const basis of VECTORS.invalid_bases) {
      cases.push([
        `basis ${JSON.stringify(basis)}, proposed ${label}`,
        {
          proposed,
          accepted: { currency: "USD", basis },
          error: "INVALID_BASIS",
          changed: "session_params_accepted.basis",
        },
      ]);
    }
  }
  for (const currency of [...VECTORS.invalid_currencies, ABSENT]) {
    cases.push([
      currency === ABSENT ? "currency absent" : `currency ${JSON.stringify(currency)}`,
      {
        proposed: { currency: "USD" },
        accepted: currency === ABSENT ? {} : { currency },
        error: "INVALID_REQUEST",
        changed: "session_params_accepted.currency",
      },
    ]);
  }
  return cases;
}

const MALFORMED_ACCEPTED_MONEY = malformedAcceptedMoneyCases();

test.each(MALFORMED_ACCEPTED_MONEY)(
  "session ack money params validated before comparison: %s",
  (_name, c) => {
    const [sessionInit, sessionAck] = initAndAck(c.proposed as Dict, c.accepted as Dict);
    const manager = new SessionManager();
    const err = expectA2CNError(() =>
      manager.createSession("sess-basis", sessionInit, sessionAck, NOW),
    );
    expect(err.code).toBe(c.error);
    expect(err.message).toContain(c.changed as string);
    expect(manager.getSession("sess-basis")).toBeNull();
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

  // Each offer restates the session basis in its signed terms (Section 7.2).
  const offer = signedOffer(
    sessionId,
    1,
    INITIATOR_DID,
    fixture.initiatorKeypair.privateKey,
    termsWith("gross"),
  );
  const counter = signedOffer(
    sessionId,
    2,
    RESPONDER_DID,
    fixture.responderKeypair.privateKey,
    termsWith("gross"),
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
// Offers restate the session basis in terms.basis (Section 7.2)
// ---------------------------------------------------------------------------

/**
 * A live session whose SessionInit and SessionAck carry the given money parameters.
 * The initiator's mandate caps commitments in the session currency, so a
 * conformant offer also passes the mandate check.
 */
function openSession(proposed: Dict, accepted: Dict): [SessionManager, Session] {
  const [sessionInit, sessionAck] = initAndAck(proposed, accepted);
  (sessionInit.initiator_mandate as Dict).max_commitment_currency = proposed.currency;
  const manager = new SessionManager();
  for (const [did, didDocument] of Object.entries(DID_DOCUMENTS)) {
    manager.registerDidDocument(did, didDocument);
  }
  const session = manager.createSession("sess-basis", sessionInit, sessionAck, NOW);
  session.session_timeout_seconds = 86400 * 365 * 100; // NOW is in the past
  return [manager, session];
}

/** A rejected offer is refused before any session state changes. */
function expectOfferLeftNoTrace(session: Session, offer: Dict): void {
  expect(session.state).toBe(SessionState.ACTIVE);
  expect([session.round_number, session.sequence_number]).toEqual([0, 0]);
  expect(session.current_turn).toBe("initiator");
  expect(session.latest_offer_id).toBeNull();
  expect(session._message_log).toEqual([]);
  expect(session._offer_chain).toEqual([]);
  expect((offer.message_id as string) in session._processed_messages).toBe(false);
}

test.each(VECTORS.offer_cases.map((c) => [c.name as string, c]))(
  "offer terms.basis held to the session basis: %s",
  (_name, c) => {
    const [manager, session] = openSession(c.proposed as Dict, c.accepted as Dict);
    const offer = signedOffer("sess-basis", 1, INITIATOR_DID, INITIATOR_KEY, c.terms);
    if (c.valid) {
      const state = manager.processMessage(session, offer);
      expect([state.state, state.round_number]).toEqual([SessionState.NEGOTIATING, 1]);
    } else {
      const err = expectA2CNError(() => manager.processMessage(session, offer));
      expect(err.code).toBe(c.error);
      expect(err.httpStatus).toBe(400);
      expect(err.message).toContain(c.changed as string);
      expectOfferLeftNoTrace(session, offer);
    }
  },
);

const SESSION_BASIS_CHOICES: [string, unknown][] = [
  ...VECTORS.valid_bases.map((basis): [string, unknown] => [basis as string, basis]),
  ["no-basis", undefined],
];
const INVALID_TERMS_BASIS_CASES: [string, string, unknown, unknown][] = VECTORS.invalid_bases.flatMap(
  (basis) =>
    SESSION_BASIS_CHOICES.map(([label, sessionBasis]): [string, string, unknown, unknown] => [
      JSON.stringify(basis),
      label,
      basis,
      sessionBasis,
    ]),
);

test.each(INVALID_TERMS_BASIS_CASES)(
  "unrecognized terms.basis rejected: %s in a %s session",
  (_basisLabel, _sessionLabel, basis, sessionBasis) => {
    const money: Dict = { currency: "USD" };
    if (sessionBasis !== undefined) {
      money.basis = sessionBasis;
    }
    const [manager, session] = openSession(money, money);
    const offer = signedOffer("sess-basis", 1, INITIATOR_DID, INITIATOR_KEY, termsWith(basis));
    const err = expectA2CNError(() => manager.processMessage(session, offer));
    expect(err.code).toBe("INVALID_BASIS");
    expect(err.message).toContain("basis");
    expectOfferLeftNoTrace(session, offer);
  },
);

test("counteroffer cannot change the basis", () => {
  const money = { currency: "USD", basis: "gross" };
  const [manager, session] = openSession(money, money);
  const offer = signedOffer("sess-basis", 1, INITIATOR_DID, INITIATOR_KEY, termsWith("gross"));
  manager.processMessage(session, offer);

  const net = signedOffer(
    "sess-basis",
    2,
    RESPONDER_DID,
    RESPONDER_KEY,
    termsWith("net"),
    offer.message_id as string,
  );
  const err = expectA2CNError(() => manager.processMessage(session, net));
  expect(err.code).toBe("SESSION_PARAM_CHANGED");
  expect(err.message).toContain("basis");
  expect([session.round_number, session.sequence_number, session.current_turn]).toEqual([
    1,
    1,
    "responder",
  ]);
  expect(session._offer_chain).toEqual([offer.protocol_act_hash]);

  const gross = signedOffer(
    "sess-basis",
    2,
    RESPONDER_DID,
    RESPONDER_KEY,
    termsWith("gross"),
    offer.message_id as string,
  );
  expect(manager.processMessage(session, gross).round_number).toBe(2);
});

test("session money params are checked before the mandate", () => {
  // A currency the session did not fix is SESSION_PARAM_CHANGED, whatever the mandate says.
  const [manager, session] = openSession({ currency: "EUR" }, { currency: "EUR" });
  expect(session.initiator_mandate.max_commitment_currency).toBe("EUR");
  // Both a mandate-currency mismatch and over the mandate cap: the session check wins.
  const offer = signedOffer("sess-basis", 1, INITIATOR_DID, INITIATOR_KEY, {
    total_value: 99_000_000,
    currency: "USD",
  });
  const err = expectA2CNError(() => manager.processMessage(session, offer));
  expect(err.code).toBe("SESSION_PARAM_CHANGED");
  expect(err.message).toContain("currency");
  expectOfferLeftNoTrace(session, offer);
});

// The reference responder echoes basis unchanged, so over HTTP accepted == proposed.
const HTTP_OFFER_CASES = VECTORS.offer_cases.filter((c) => isDeepStrictEqual(c.accepted, c.proposed));

test.each(HTTP_OFFER_CASES.map((c) => [c.name as string, c]))(
  "offer terms.basis held over HTTP: %s",
  async (_name, c) => {
    const { client, initiatorKeypair } = freshServer();
    const body = makeSessionInit();
    body.session_params = { ...(body.session_params as Dict), ...(c.proposed as Dict) };
    (body.initiator_mandate as Dict).max_commitment_currency = (c.proposed as Dict).currency;
    const r = await client.post("/sessions", { json: body, headers: headers(body.message_id as string) });
    expect(r.statusCode).toBe(201);
    const sessionId = r.json().session_id as string;

    const offer = signedOffer(sessionId, 1, INITIATOR_DID, initiatorKeypair.privateKey, c.terms);
    const posted = await client.post(`/sessions/${sessionId}/messages`, {
      json: offer,
      headers: headers(offer.message_id as string),
    });
    const state = (await client.get(`/sessions/${sessionId}`)).json();
    if (c.valid) {
      expect(posted.statusCode).toBe(200);
      expect([state.state, state.round_number]).toEqual([SessionState.NEGOTIATING, 1]);
    } else {
      expect(posted.statusCode).toBe(400);
      const error = posted.json().error as Dict;
      expect(error.code).toBe(c.error);
      expect(error.message).toContain(c.changed as string);
      expect([state.state, state.round_number, state.sequence_number]).toEqual([
        SessionState.ACTIVE,
        0,
        0,
      ]);
    }
  },
);

test.each(Object.keys(MONEY_PARAM_FIXTURES).sort())("offer money param conformance fixture: %s", (name) => {
  const given = MONEY_PARAM_FIXTURES[name].given as Dict;
  const expected = MONEY_PARAM_FIXTURES[name].expect as Dict;
  const params = given.session_params as Dict;
  const [manager, session] = openSession(params, params);
  expect(session.state).toBe(given.session_state);
  const givenOffer = given.offer as Dict;
  const offer = signedOffer("sess-basis", 1, INITIATOR_DID, INITIATOR_KEY, givenOffer.terms);
  expect(offer.message_type).toBe(givenOffer.message_type);
  expect(expected.accepted).toBe(false);
  const err = expectA2CNError(() => manager.processMessage(session, offer));
  expect(err.code).toBe(expected.error_code);
  expectOfferLeftNoTrace(session, offer);
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
 * `OMITTED` leaves session_params_accepted out of the SessionAck. Each message
 * posted to the session is appended to `posted` and answered 200.
 */
function clientAnsweringWith(accepted: unknown, posted: Dict[] = []): A2CNClient {
  const respond: typeof fetch = async (input, init) => {
    if (String(input).endsWith("/messages")) {
      posted.push(JSON.parse(init?.body as string) as Dict);
      return new Response(JSON.stringify({ state: SessionState.NEGOTIATING }), { status: 200 });
    }
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

test.each(MALFORMED_ACCEPTED_MONEY)(
  "client validates session ack money params before comparison: %s",
  async (_name, c) => {
    const [sessionInit, sessionAck] = initAndAck(c.proposed as Dict, c.accepted as Dict);
    const client = clientAnsweringWith(sessionAck.session_params_accepted);
    const err = await client
      .initiateSession("https://acme.example", RESPONDER_DID, sessionInit.session_params as Dict)
      .catch((exc: unknown) => exc);
    expect(err).toBeInstanceOf(A2CNError);
    expect((err as A2CNError).code).toBe(c.error);
    expect((err as A2CNError).message).toContain(c.changed as string);
    expect(client._sessions).toEqual({});
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
// A2CNClient: the offers it sends and the counteroffers it receives (Section 7.2)
// ---------------------------------------------------------------------------

/** An initiator holding session sess-basis, opened from the case's money parameters. */
async function openedClient(c: Dict, posted: Dict[]): Promise<A2CNClient> {
  const [sessionInit, sessionAck] = initAndAck(c.proposed as Dict, c.accepted as Dict);
  const client = clientAnsweringWith(sessionAck.session_params_accepted, posted);
  await client.initiateSession("https://acme.example", RESPONDER_DID, sessionInit.session_params as Dict);
  return client;
}

/** Terms restating the session currency and, when the session fixed one, its basis. */
function conformantTerms(accepted: Dict): Dict {
  const basis = accepted.basis === undefined ? {} : { basis: accepted.basis };
  return { total_value: 9_500_000, currency: accepted.currency, ...basis };
}

test.each(VECTORS.offer_cases.map((c) => [c.name as string, c]))(
  "client checks received offer money params: %s",
  async (_name, c) => {
    // The initiator receives counteroffers, so it applies the Section 7.2 receiver rules.
    const client = await openedClient(c, []);
    const state = client._sessions["sess-basis"];
    const before = structuredClone(state);
    const counteroffer = signedOffer("sess-basis", 2, RESPONDER_DID, RESPONDER_KEY, c.terms);
    if (c.valid) {
      client.processIncoming("sess-basis", counteroffer);
      expect(state.latest_offer).toEqual(counteroffer);
      expect(state.offer_chain).toEqual([counteroffer.protocol_act_hash]);
    } else {
      const err = expectA2CNError(() => client.processIncoming("sess-basis", counteroffer));
      expect(err.code).toBe(c.error);
      expect(err.message).toContain(c.changed as string);
      expect(state).toEqual(before);
    }
  },
);

test.each(VECTORS.offer_cases.map((c) => [c.name as string, c]))(
  "client checks offer money params before sending: %s",
  async (_name, c) => {
    // A refused offer is never posted and leaves the round and sequence where they were.
    const posted: Dict[] = [];
    const client = await openedClient(c, posted);
    const state = client._sessions["sess-basis"];
    const send = (terms: unknown) =>
      client.sendOffer("https://acme.example", RESPONDER_DID, "sess-basis", terms as Dict);
    if (c.valid) {
      await send(c.terms);
    } else {
      const err = await send(c.terms).catch((exc: unknown) => exc);
      expect(err).toBeInstanceOf(A2CNError);
      expect((err as A2CNError).code).toBe(c.error);
      expect((err as A2CNError).message).toContain(c.changed as string);
      expect(posted).toEqual([]);
      expect([state.round_number, state.sequence_number]).toEqual([0, 0]);
      await send(conformantTerms(c.accepted as Dict));
    }
    expect(posted.map((offer) => [offer.round_number, offer.sequence_number])).toEqual([[1, 1]]);
  },
);

test.each(VECTORS.offer_cases.map((c) => [c.name as string, c]))(
  "client checks offer money params before accepting: %s",
  async (_name, c) => {
    // The client signs only terms the session allows, whatever reached it unchecked.
    const posted: Dict[] = [];
    const client = await openedClient(c, posted);
    const state = client._sessions["sess-basis"];
    const before = structuredClone(state);
    const offer = signedOffer("sess-basis", 2, RESPONDER_DID, RESPONDER_KEY, c.terms);
    const accept = () =>
      client.sendAcceptance("https://acme.example", RESPONDER_DID, "sess-basis", offer);
    if (c.valid) {
      await accept();
      expect(posted.map((message) => message.accepted_offer_id)).toEqual([offer.message_id]);
      expect(state.sequence_number).toBe(before.sequence_number + 1);
    } else {
      const err = await accept().catch((exc: unknown) => exc);
      expect(err).toBeInstanceOf(A2CNError);
      expect((err as A2CNError).code).toBe(c.error);
      expect((err as A2CNError).message).toContain(c.changed as string);
      expect(posted).toEqual([]);
      expect(state).toEqual(before);
    }
  },
);

test("client refuses to accept a mislabelled offer it recorded", async () => {
  // A message_type other than offer or counteroffer skips the receive check, not this one.
  const posted: Dict[] = [];
  const usd = { currency: "USD" };
  const client = await openedClient({ proposed: usd, accepted: usd }, posted);
  const state = client._sessions["sess-basis"];
  const mislabelled = signedOffer("sess-basis", 2, RESPONDER_DID, RESPONDER_KEY, {
    total_value: 9_500_000,
    currency: "EUR",
  });
  mislabelled.message_type = "Counteroffer";
  client.processIncoming("sess-basis", mislabelled);
  const sequenceNumber = state.sequence_number;

  const err = await client
    .sendAcceptance("https://acme.example", RESPONDER_DID, "sess-basis", mislabelled)
    .catch((exc: unknown) => exc);
  expect(err).toBeInstanceOf(A2CNError);
  expect((err as A2CNError).code).toBe("SESSION_PARAM_CHANGED");
  expect((err as A2CNError).message).toContain("currency");
  expect(posted).toEqual([]);
  expect(state.sequence_number).toBe(sequenceNumber);
});

// ---------------------------------------------------------------------------
// SessionParams, TermsObject, and the SessionInvitation schema
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

test("terms object carries basis only when set", () => {
  expect(
    new TermsObject({ total_value: 9_500_000, currency: "USD", basis: "gross" }).toDict(),
  ).toStrictEqual({ total_value: 9_500_000, currency: "USD", basis: "gross" });
  expect("basis" in new TermsObject({ total_value: 9_500_000, currency: "USD" }).toDict()).toBe(
    false,
  );
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
