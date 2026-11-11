/**
 * invitation_expires_at and invitation_id are read the same way in both languages.
 *
 * An invitation's expiry is an RFC 3339 timestamp with an explicit UTC offset
 * or `Z` (the schema's `date-time`). Anything else — missing, empty, not a
 * string, no offset, a basic-format or date-only value, an out-of-range field —
 * counts as expired, failing closed, at every expiry check: an identical
 * re-send, accept, decline and the expiry sweep. Nothing about the value can
 * produce a 500.
 *
 * POST /invitations requires invitation_id to be a non-empty string, before
 * any DID is resolved or signature checked (INVALID_REQUEST, 400).
 *
 * The Python suite runs the same cases in tests/test_invitation_expiry_and_id.py.
 */

import { randomUUID } from "node:crypto";
import { afterEach, expect, test, vi } from "vitest";

import { generateKeypair, publicKeyToJwk, signInvitation } from "../src/a2cn/crypto.js";
import { InvitationStore } from "../src/a2cn/invitation.js";
import type { Dict } from "../src/a2cn/messages.js";
import { freshServer, makeDidDocument, type ServerFixture, type TestResponse } from "./conftest.js";

const ALICE = "did:web:alice.example";
const MALLORY = "did:web:mallory.example";
const KEYS: Record<string, ReturnType<typeof generateKeypair>> = {
  [ALICE]: generateKeypair(),
  [MALLORY]: generateKeypair(),
};
const MISSING = Symbol("missing");
type Value = unknown;

// [invitation_expires_at, counts as expired]. The clock is real, so "future"
// values are far ahead and "past" ones far behind.
const EXPIRY_CASES: Array<[Value, boolean]> = [
  ["2099-01-01T00:00:00Z", false],
  ["2099-01-01T00:00:00.5Z", false],
  ["2099-01-01T00:00:00+05:30", false],
  ["2099-01-01T00:00:00-08:00", false],
  ["2099-01-01t00:00:00z", false],
  ["2020-01-01T00:00:00Z", true],
  ["2020-01-01T00:00:00.1234567Z", true],
  // Not RFC 3339 with an explicit offset: expired, whatever instant it names.
  ["2099-01-01T00:00:00", true],
  ["2020-01-01T00:00:00", true],
  ["2099-01-01", true],
  ["2020-01-01", true],
  ["20200101T000000Z", true],
  ["20990101T000000Z", true],
  ["2099-01-01 00:00:00Z", true],
  ["2099-01-01T24:00:00Z", true],
  ["2099-01-01T00:60:00Z", true],
  ["2099-01-01T00:00:60Z", true],
  ["2099-02-30T00:00:00Z", true],
  ["2099-13-01T00:00:00Z", true],
  ["2099-01-01T00:00:00+24:00", true],
  ["2099-01-01T00:00:00+0530", true],
  ["0000-01-01T00:00:00Z", true],
  ["٢٠٩٩-01-01T00:00:00Z", true],
  ["2099-01-01T00:00:00Z ", true],
  ["", true],
  [MISSING, true],
  [null, true],
  [20990101, true],
  [["2099-01-01T00:00:00Z"], true],
];

function label(value: Value): string {
  return value === MISSING ? "missing" : JSON.stringify(value);
}

function invitation(inviter: string, invitationId: Value, expires: Value = "2099-01-01T00:00:00Z"): Dict {
  const host = inviter.split(":").at(-1);
  const body: Dict = {
    message_type: "session_invitation",
    invitation_id: invitationId,
    a2cn_version: "0.3",
    inviter_did: inviter,
    inviter_endpoint: `https://${host}/a2cn`,
    inviter_discovery_url: `https://${host}/.well-known/a2cn-agent`,
    proposed_deal_type: "saas_renewal",
    proposed_session_params: { currency: "USD", max_rounds: 4 },
    proposed_terms_summary: { total_value: 9_500_000, currency: "USD" },
    inviter_mandate_summary: { mandate_type: "declared" },
    invitation_expires_at: expires,
    accept_endpoint: `https://${host}/a2cn/invitations/x/accept`,
    decline_endpoint: `https://${host}/a2cn/invitations/x/decline`,
    inviter_verification_method: `${inviter}#key-1`,
    invitation_signature: "",
  };
  if (expires === MISSING) {
    delete body.invitation_expires_at;
  }
  if (invitationId === MISSING) {
    delete body.invitation_id;
  }
  body.invitation_signature = signInvitation(body, KEYS[inviter].privateKey);
  return body;
}

function server(): ServerFixture {
  const fixture = freshServer();
  for (const [did, { publicKey }] of Object.entries(KEYS)) {
    fixture.ctx.registerDidDocument(did, makeDidDocument(did, "key-1", publicKeyToJwk(publicKey)));
  }
  return fixture;
}

function code(res: TestResponse): string {
  return ((res.json().error as Dict | undefined)?.code as string | undefined) ?? "ok";
}

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// invitation_expires_at
// ---------------------------------------------------------------------------

test.each(EXPIRY_CASES.map(([value, expired]) => [label(value), value, expired] as const))(
  "expiry %s is read the same at every check",
  async (_label, expires, expired) => {
    const fixture = server();
    for (const step of ["resend", "accept", "decline"]) {
      const invitationId = randomUUID();
      const body = invitation(ALICE, invitationId, expires);
      const first = await fixture.rawClient.post("/invitations", { json: body });
      expect(first.statusCode, `${step}: ${first.body}`).toBe(201);
      const res =
        step === "resend"
          ? await fixture.rawClient.post("/invitations", { json: body })
          : await fixture.client.post(`/invitations/${invitationId}/${step}`, { json: {} });
      const ok: [number, string] = [step === "resend" ? 201 : 200, "ok"];
      expect([res.statusCode, code(res)], `${step}: ${res.body}`).toEqual(
        expired ? [410, "INVITATION_EXPIRED"] : ok,
      );
      const status = (await fixture.rawClient.get(`/invitations/${invitationId}`)).json().status;
      if (step === "resend") {
        expect(status).toBe("pending");
      } else if (expired) {
        expect(status).toBe("expired");
      }
    }
  },
);

test.each(EXPIRY_CASES.map(([value, expired]) => [label(value), value, expired] as const))(
  "the expiry sweep reads %s the same",
  (_label, expires, expired) => {
    const store = new InvitationStore();
    store.storeInbound(invitation(ALICE, randomUUID(), expires));
    expect(store.expirePending()).toBe(expired ? 1 : 0);
  },
);

// [invitation_expires_at, clock, counts as expired]: the instant an expiry
// names, offset included, read to the millisecond; it has passed once the clock
// is strictly later.
const CLOCKED_CASES: Array<[string, string, boolean]> = [
  ["2030-01-01T00:00:00+05:00", "2030-01-01T02:00:00.000Z", true],
  ["2030-01-01T00:00:00-05:00", "2030-01-01T02:00:00.000Z", false],
  ["2030-01-01T00:00:00Z", "2029-12-31T23:59:59.999Z", false],
  ["2030-01-01T00:00:00Z", "2030-01-01T00:00:00.000Z", false],
  ["2030-01-01T00:00:00Z", "2030-01-01T00:00:00.001Z", true],
  ["2030-01-01T00:00:00.500Z", "2030-01-01T00:00:00.500Z", false],
  ["2030-01-01T00:00:00.500Z", "2030-01-01T00:00:00.501Z", true],
  ["2030-01-01T00:00:00.5009Z", "2030-01-01T00:00:00.501Z", true],
];

test.each(CLOCKED_CASES)(
  "expiry %s at clock %s is read with its offset to the millisecond",
  (expires, clock, expired) => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(clock));
    const store = new InvitationStore();
    store.storeInbound(invitation(ALICE, randomUUID(), expires));
    expect(store.expirePending()).toBe(expired ? 1 : 0);
  },
);

test("an identical re-send of an answered invitation past its expiry is already answered", async () => {
  const fixture = server();
  const invitationId = randomUUID();
  const body = invitation(ALICE, invitationId, "2030-01-01T00:00:00Z");
  expect((await fixture.rawClient.post("/invitations", { json: body })).statusCode).toBe(201);
  expect((await fixture.client.post(`/invitations/${invitationId}/accept`, { json: {} })).statusCode).toBe(200);

  // Later, after the invitation's expiry has passed.
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2031-01-01T00:00:00Z"));
  const res = await fixture.rawClient.post("/invitations", { json: body });

  expect([res.statusCode, code(res)]).toEqual([409, "INVITATION_ALREADY_ANSWERED"]);
  const again = await fixture.client.post(`/invitations/${invitationId}/decline`, { json: {} });
  expect([again.statusCode, code(again)]).toEqual([409, "INVITATION_ALREADY_ANSWERED"]);
  expect((await fixture.rawClient.get(`/invitations/${invitationId}`)).json().status).toBe("accepted");
});

// ---------------------------------------------------------------------------
// invitation_id
// ---------------------------------------------------------------------------

const BAD_IDS: Value[] = [MISSING, null, "", 5, 5.0, 0, true, false, ["x"], { id: "x" }];

test.each(BAD_IDS.map((value) => [label(value), value] as const))(
  "invitation_id %s is refused",
  async (_label, invitationId) => {
    const fixture = server();
    const res = await fixture.rawClient.post("/invitations", { json: invitation(ALICE, invitationId) });

    expect([res.statusCode, code(res)]).toEqual([400, "INVALID_REQUEST"]);
    expect(Object.keys(fixture.ctx.invitationStore._invitations)).toEqual([]);
  },
);

test("a numeric id never reaches a string id's entry", async () => {
  const fixture = server();
  expect((await fixture.rawClient.post("/invitations", { json: invitation(ALICE, "5") })).statusCode).toBe(201);
  const res = await fixture.rawClient.post("/invitations", { json: invitation(MALLORY, 5) });

  expect([res.statusCode, code(res)]).toEqual([400, "INVALID_REQUEST"]);
  const stored = (await fixture.rawClient.get("/invitations/5")).json();
  expect((stored.invitation as Dict).inviter_did).toBe(ALICE);
  expect(Object.keys(fixture.ctx.invitationStore._invitations)).toEqual(["5"]);
});
