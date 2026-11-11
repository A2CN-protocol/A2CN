/**
 * An act that cannot be canonicalized is refused, never an internal error.
 *
 * A string holding a lone surrogate has no UTF-8 encoding, so RFC 8785 cannot
 * canonicalize the act that holds it, and no signature can be checked against
 * it. The session manager refuses such an act as INVALID_SIGNATURE (400), and
 * so does the server; the Python suite checks the same.
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { hashObject, signJws } from "../src/a2cn/crypto.js";
import { A2CNError } from "../src/a2cn/errors.js";
import type { Dict } from "../src/a2cn/messages.js";
import { SessionManager } from "../src/a2cn/session.js";
import { INITIATOR_DID, freshServer, makeSessionInit } from "./conftest.js";
import { REPO_ROOT } from "./support/paths.js";

const BASIS = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-basis.json"), "utf-8"),
) as Dict;
const LONE = "\ud800";

test("the session manager refuses an offer that cannot be canonicalized", () => {
  const manager = new SessionManager();
  for (const [did, document] of Object.entries(BASIS.did_documents as Record<string, Dict>)) {
    manager.registerDidDocument(did, document);
  }
  const sessionAck = BASIS.session_ack as Dict;
  const session = manager.createSession(
    BASIS.session_id as string,
    BASIS.session_init as Dict,
    sessionAck,
    sessionAck.session_created_at as string,
    { legacyReplay: true },
  );
  session.session_timeout_seconds = 86400 * 365 * 100;
  const offer = structuredClone((BASIS.messages as Dict[])[0]);
  (offer.terms as Dict).note = LONE;
  let caught: unknown = null;
  try {
    manager.processMessage(session, offer);
  } catch (exc) {
    caught = exc;
  }
  expect(caught).toBeInstanceOf(A2CNError);
  expect((caught as A2CNError).code).toBe("INVALID_SIGNATURE");
  expect((caught as A2CNError).httpStatus).toBe(400);
});

test("the server refuses an offer that cannot be canonicalized", async () => {
  const { client, initiatorKeypair } = freshServer();
  const body = makeSessionInit();
  const created = await client.post("/sessions", {
    json: body,
    headers: { "Idempotency-Key": body.message_id as string },
  });
  const sessionId = created.json().session_id as string;
  const signedTerms = { total_value: 9_500_000, currency: "USD" };
  const act = {
    protocol_version: "0.3",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    message_type: "offer",
    sender_did: INITIATOR_DID,
    timestamp: "2026-03-24T10:01:00Z",
    expires_at: "2030-01-01T00:00:00Z",
    terms: signedTerms,
  };
  const actHash = hashObject(act);
  const vm = `${INITIATOR_DID}#key-1`;
  const offer = {
    message_type: "offer",
    message_id: randomUUID(),
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "test-agent",
    sender_verification_method: vm,
    timestamp: act.timestamp,
    expires_at: act.expires_at,
    terms: { ...signedTerms, note: LONE },
    protocol_act_hash: actHash,
    protocol_act_signature: signJws(actHash, initiatorKeypair.privateKey, vm),
  };
  const r = await client.post(`/sessions/${sessionId}/messages`, {
    json: offer,
    headers: { "Idempotency-Key": offer.message_id },
  });
  expect(r.statusCode).toBe(400);
  expect((r.json().error as Dict).code).toBe("INVALID_SIGNATURE");
});
