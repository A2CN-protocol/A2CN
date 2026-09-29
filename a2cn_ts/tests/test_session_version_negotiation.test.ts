/**
 * The wire version a session is negotiated at (Section 12.1.7).
 *
 * A SessionInit proposes a version and the SessionAck that answers it must
 * state the same one; the session runs at it. Before this, the session manager
 * took the ack's version when it had one and the init's otherwise, and accepted
 * any string, so an ack of "9.9" produced a session that signed and verified
 * under "9.9". The initiator's client did not look at the ack's version at all,
 * and signed its offers under whatever the responder stated. Both now refuse
 * any pair that does not agree on a version this implementation recognises, and
 * fill nothing in.
 *
 * A new session establishes only at the current version (Section 11.2.1). "0.2"
 * is recognised for verifying records alone, so a pair agreeing on it is refused
 * too, unless the session manager is told it is replaying a recorded session.
 *
 * session-version-negotiation.json pins the cases. The Python suite runs them
 * too.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { A2CNClient } from "../src/a2cn/client.js";
import { generateKeypair } from "../src/a2cn/crypto.js";
import {
  ESTABLISHMENT_WIRE_VERSIONS,
  PROTOCOL_ACT_VERSION,
  SUPPORTED_WIRE_VERSIONS,
  type Dict,
} from "../src/a2cn/messages.js";
import { A2CNError, SessionManager, checkSessionVersions } from "../src/a2cn/session.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "session-version-negotiation.json"), "utf-8"),
) as Dict;
const CASES = VECTOR.cases as Dict[];
// A live establishment: the client never replays, so it never passes the option.
const LIVE_CASES = CASES.filter((c) => c.legacy_replay !== true);
const CLIENT_CASES = LIVE_CASES.filter((c) => c.init_protocol_version === PROTOCOL_ACT_VERSION);

const INITIATOR_DID = "did:web:techcorp.example";
const RESPONDER_DID = "did:web:acme-corp.com";
const PARAMS: Dict = {
  deal_type: "saas_renewal",
  currency: "USD",
  subject: "Test",
  max_rounds: 4,
  session_timeout_seconds: 3600,
  round_timeout_seconds: 900,
};

function hasOwn(obj: Dict, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function withVersion(message: Dict, testCase: Dict, key: string): Dict {
  const copy: Dict = { ...message };
  if (hasOwn(testCase, key)) {
    copy.protocol_version = testCase[key];
  }
  return copy;
}

function initFor(testCase: Dict): Dict {
  return withVersion(
    {
      message_type: "session_init",
      message_id: "neg-init-1",
      session_params: PARAMS,
      initiator: { did: INITIATOR_DID },
      initiator_mandate: { mandate_type: "declared" },
    },
    testCase,
    "init_protocol_version",
  );
}

function ackFor(testCase: Dict, inReplyTo = "neg-init-1"): Dict {
  return withVersion(
    {
      message_type: "session_ack",
      message_id: "neg-ack-1",
      session_id: "sess-neg",
      in_reply_to: inReplyTo,
      session_params_accepted: PARAMS,
      responder: { did: RESPONDER_DID },
      responder_mandate: { mandate_type: "declared" },
      session_created_at: "2026-03-24T10:00:00Z",
      current_turn: "initiator",
    },
    testCase,
    "ack_protocol_version",
  );
}

test("the vector names the versions this implementation recognises", () => {
  expect([...SUPPORTED_WIRE_VERSIONS]).toEqual(VECTOR.supported_wire_versions);
  expect([...ESTABLISHMENT_WIRE_VERSIONS]).toEqual(VECTOR.establishment_wire_versions);
  expect([...ESTABLISHMENT_WIRE_VERSIONS]).toEqual([PROTOCOL_ACT_VERSION]);
  expect(new Set(CASES.map((c) => c.accepted))).toEqual(new Set([true, false]));
  const replay = CASES.filter((c) => c.legacy_replay === true);
  expect(new Set(replay.map((c) => c.accepted))).toEqual(new Set([true, false]));
});

for (const testCase of CASES) {
  test(`the session manager negotiates one version: ${testCase.name}`, () => {
    const manager = new SessionManager();
    const init = initFor(testCase);
    const ack = ackFor(testCase);
    const legacyReplay = testCase.legacy_replay === true;

    if (testCase.accepted) {
      const session = manager.createSession("sess-neg", init, ack, "2026-03-24T10:00:00Z", {
        legacyReplay,
      });
      expect(session.protocol_version).toBe(testCase.runs_at);
      expect(session.toStateDict().protocol_version).toBe(testCase.runs_at);
      return;
    }

    let caught: unknown = null;
    try {
      manager.createSession("sess-neg", init, ack, "2026-03-24T10:00:00Z", { legacyReplay });
    } catch (exc) {
      caught = exc;
    }
    expect(caught).toBeInstanceOf(A2CNError);
    const err = caught as A2CNError;
    expect([err.code, err.message]).toEqual([testCase.error_code, testCase.error_message]);
    expect(manager.getSession("sess-neg")).toBeFalsy();
  });
}

function clientAnswering(testCase: Dict, posted: Dict[]): A2CNClient {
  const respond: typeof fetch = async (input, init) => {
    const body = JSON.parse(init?.body as string) as Dict;
    posted.push(body);
    if (String(input).endsWith("/messages")) {
      return new Response(JSON.stringify({ state: "NEGOTIATING" }), { status: 200 });
    }
    return new Response(JSON.stringify(ackFor(testCase, body.message_id as string)), {
      status: 201,
    });
  };
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

for (const testCase of CLIENT_CASES) {
  test(`the client refuses an ack that changes its version: ${testCase.name}`, async () => {
    const posted: Dict[] = [];
    const client = clientAnswering(testCase, posted);

    if (testCase.accepted) {
      const ack = await client.initiateSession("https://acme.example", RESPONDER_DID, PARAMS);
      expect(ack.protocol_version).toBe(testCase.runs_at);
      expect("sess-neg" in client._sessions).toBe(true);
      return;
    }

    const err = await client
      .initiateSession("https://acme.example", RESPONDER_DID, PARAMS)
      .catch((exc: unknown) => exc);
    expect(err).toBeInstanceOf(A2CNError);
    expect([(err as A2CNError).code, (err as A2CNError).message]).toEqual([
      testCase.error_code,
      testCase.error_message,
    ]);
    // Refused before anything is stored or signed: only the SessionInit went out.
    expect(client._sessions).toEqual({});
    expect(posted.map((m) => m.message_type)).toEqual(["session_init"]);
    expect(posted[0].protocol_version).toBe(PROTOCOL_ACT_VERSION);
  });
}

test("the client cases cover both verdicts", () => {
  expect(new Set(CLIENT_CASES.map((c) => c.accepted))).toEqual(new Set([true, false]));
});

for (const testCase of LIVE_CASES) {
  test(`the client's check refuses every pair a live session refuses: ${testCase.name}`, () => {
    // The client runs this check, with no replay option, on the SessionAck it
    // receives; it holds for a pair the client itself would never propose, such
    // as one agreeing on "0.2".
    const init = initFor(testCase);
    const ack = ackFor(testCase);
    if (testCase.accepted) {
      expect(checkSessionVersions(init, ack)).toBe(testCase.runs_at);
      return;
    }
    let caught: unknown = null;
    try {
      checkSessionVersions(init, ack);
    } catch (exc) {
      caught = exc;
    }
    expect(caught).toBeInstanceOf(A2CNError);
    const err = caught as A2CNError;
    expect([err.code, err.message]).toEqual([testCase.error_code, testCase.error_message]);
  });
}
