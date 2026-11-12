/**
 * An inbound invitation never replaces the one already stored under its id.
 *
 * POST /invitations is authenticated by the invitation's own signature, so any
 * did:web holder can deliver one. The id it names may already be stored: an
 * invitation received earlier, or one this server created (Section 11.7):
 *
 * - a different invitation under that id (another inviter, or other content)
 *   is INVITATION_ID_CONFLICT, whatever the stored status;
 * - the identical signed invitation re-sent is answered as the first delivery
 *   was while the stored one is pending, and is INVITATION_ALREADY_ANSWERED or
 *   INVITATION_EXPIRED once it is answered or expired;
 * - re-delivery never changes the stored entry's inviter, content, status or
 *   created_at.
 *
 * The Python suite runs the same cases in tests/test_invitation_repost.py.
 */

import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";

import { generateKeypair, publicKeyToJwk, signInvitation } from "../src/a2cn/crypto.js";
import { InvitationStore } from "../src/a2cn/invitation.js";
import type { Dict } from "../src/a2cn/messages.js";
import { freshServer, makeDidDocument, type ServerFixture, type TestClient } from "./conftest.js";

const ALICE = "did:web:alice.example";
const MALLORY = "did:web:mallory.example";
const KEYS: Record<string, ReturnType<typeof generateKeypair>> = {
  [ALICE]: generateKeypair(),
  [MALLORY]: generateKeypair(),
};
const STATES = ["pending", "accepted", "declined", "expired"];
const LIVE = "2030-01-01T00:00:00Z";
const PAST = "2020-01-01T00:00:00Z";

function invitation(
  inviter: string,
  invitationId: string,
  { totalValue = 9_500_000, expires = LIVE }: { totalValue?: number; expires?: string } = {},
): Dict {
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
    proposed_terms_summary: { total_value: totalValue, currency: "USD" },
    inviter_mandate_summary: { mandate_type: "declared" },
    invitation_expires_at: expires,
    accept_endpoint: `https://${host}/a2cn/invitations/${invitationId}/accept`,
    decline_endpoint: `https://${host}/a2cn/invitations/${invitationId}/decline`,
    inviter_verification_method: `${inviter}#key-1`,
    invitation_signature: "",
  };
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

async function stored(client: TestClient, invitationId: string): Promise<Dict> {
  const res = await client.get(`/invitations/${invitationId}`);
  expect(res.statusCode).toBe(200);
  return res.json();
}

/** Alice's invitation, stored and then left pending, accepted, declined or expired. */
async function first(fixture: ServerFixture, state: string): Promise<[string, Dict]> {
  const invitationId = randomUUID();
  const original = invitation(ALICE, invitationId, { expires: state === "expired" ? PAST : LIVE });
  expect((await fixture.rawClient.post("/invitations", { json: original })).statusCode).toBe(201);
  if (state === "accepted" || state === "declined") {
    const action = state === "accepted" ? "accept" : "decline";
    expect((await fixture.client.post(`/invitations/${invitationId}/${action}`, { json: {} })).statusCode).toBe(200);
  }
  return [invitationId, original];
}

/** An expired invitation nobody has tried to answer still reads as pending. */
function storedStatus(state: string): string {
  return state === "expired" ? "pending" : state;
}

test.each(STATES)("another inviter over a %s invitation is a conflict", async (state) => {
  const fixture = server();
  const [invitationId, original] = await first(fixture, state);
  const before = await stored(fixture.rawClient, invitationId);

  const res = await fixture.rawClient.post("/invitations", {
    json: invitation(MALLORY, invitationId, { expires: original.invitation_expires_at as string }),
  });

  expect(res.statusCode).toBe(409);
  expect((res.json().error as Dict).code).toBe("INVITATION_ID_CONFLICT");
  const after = await stored(fixture.rawClient, invitationId);
  expect(after).toEqual(before);
  expect(after.invitation).toEqual(original);
  expect(after.status).toBe(storedStatus(state));
});

test.each(STATES)("the same inviter with different content over a %s invitation is a conflict", async (state) => {
  const fixture = server();
  const [invitationId, original] = await first(fixture, state);
  const before = await stored(fixture.rawClient, invitationId);

  const res = await fixture.rawClient.post("/invitations", {
    json: invitation(ALICE, invitationId, {
      totalValue: 1,
      expires: original.invitation_expires_at as string,
    }),
  });

  expect(res.statusCode).toBe(409);
  expect((res.json().error as Dict).code).toBe("INVITATION_ID_CONFLICT");
  const after = await stored(fixture.rawClient, invitationId);
  expect(after).toEqual(before);
  expect(((after.invitation as Dict).proposed_terms_summary as Dict).total_value).toBe(9_500_000);
});

test("an identical retransmission of a pending invitation is answered as before", async () => {
  const fixture = server();
  const [invitationId, original] = await first(fixture, "pending");
  const before = await stored(fixture.rawClient, invitationId);

  const res = await fixture.rawClient.post("/invitations", { json: structuredClone(original) });

  expect(res.statusCode).toBe(201);
  expect(res.json()).toEqual({ invitation_id: invitationId, status: "pending" });
  expect(await stored(fixture.rawClient, invitationId)).toEqual(before);
  const accepted = await fixture.client.post(`/invitations/${invitationId}/accept`, { json: {} });
  expect(accepted.statusCode).toBe(200);
  expect((await stored(fixture.rawClient, invitationId)).status).toBe("accepted");
});

test.each([
  ["accepted", "INVITATION_ALREADY_ANSWERED", 409],
  ["declined", "INVITATION_ALREADY_ANSWERED", 409],
  ["expired", "INVITATION_EXPIRED", 410],
])("an identical retransmission never reopens a %s invitation", async (state, code, status) => {
  const fixture = server();
  const [invitationId, original] = await first(fixture, state);
  const before = await stored(fixture.rawClient, invitationId);

  const res = await fixture.rawClient.post("/invitations", { json: structuredClone(original) });

  expect(res.statusCode).toBe(status);
  expect((res.json().error as Dict).code).toBe(code);
  expect(await stored(fixture.rawClient, invitationId)).toEqual(before);
  const again = await fixture.client.post(
    `/invitations/${invitationId}/${state === "accepted" ? "decline" : "accept"}`,
    { json: {} },
  );
  expect(again.statusCode).toBe(status);
  expect((again.json().error as Dict).code).toBe(code);
});

test("an inbound invitation cannot take an outbound invitation's id", async () => {
  const fixture = server();
  const created = await fixture.client.post("/invitations/create", {
    json: { proposed_deal_type: "saas_renewal", proposed_terms_summary: { total_value: 1 } },
  });
  expect(created.statusCode).toBe(201);
  const invitationId = created.json().invitation_id as string;
  const before = await stored(fixture.rawClient, invitationId);

  const res = await fixture.rawClient.post("/invitations", { json: invitation(MALLORY, invitationId) });

  expect(res.statusCode).toBe(409);
  expect((res.json().error as Dict).code).toBe("INVITATION_ID_CONFLICT");
  expect(await stored(fixture.rawClient, invitationId)).toEqual(before);
});

test("storeInbound refuses a conflicting id", () => {
  const store = new InvitationStore();
  const invitationId = randomUUID();
  const original = invitation(ALICE, invitationId);
  store.storeInbound(original);
  const entry = store.getInvitation(invitationId);
  const snapshot = { ...entry };
  expect(() => store.storeInbound(invitation(MALLORY, invitationId))).toThrow(/^INVITATION_ID_CONFLICT$/);
  store.storeInbound(structuredClone(original));
  expect(store.getInvitation(invitationId)).toBe(entry);
  expect(entry).toEqual(snapshot);
});
