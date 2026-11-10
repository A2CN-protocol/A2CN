/**
 * Section 4.2: a DID document is used only for the DID its id names.
 *
 * Two spellings of one did:web DID can reach one document: the host's case, a
 * trailing dot, a percent-encoded dot or port, a `:.well-known` path, a Unicode
 * host and its punycode. Without this rule a party whose one document lists two
 * keys could sign a TransactionRecord's offer under one spelling and its
 * acceptance under the other, and the record verified: two DIDs, two keys, one
 * party. No DID is normalized. Wherever a verifier obtains a document (the
 * did:web resolver, a mapping or resolver the caller supplies, the server's
 * registered documents), a document whose id is not exactly the DID asked for
 * is no document for it, and its key is unavailable. The Python suite reads the
 * same vector.
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { createJwt, generateKeypair, publicKeyToJwk, signInvitation } from "../src/a2cn/crypto.js";
import {
  DidDocumentIdMismatch,
  didDocumentIsFor,
  didWebToUrl,
  requireDidDocumentFor,
  resolveDidWeb,
  type FetchLike,
} from "../src/a2cn/did.js";
import { EVIDENCE_REASON_KEY_NOT_FOUND, assessSessionEvidenceRecord } from "../src/a2cn/evidence.js";
import type { Dict } from "../src/a2cn/messages.js";
import { REASON_KEY_NOT_FOUND, verifyTransactionRecordReason } from "../src/a2cn/record.js";
import { SessionManager } from "../src/a2cn/session.js";
import { A2CNError } from "../src/a2cn/errors.js";
import {
  INITIATOR_DID,
  SERVER_DID,
  fakeFetch,
  freshServer,
  makeDidDocument,
  makeSessionInit,
} from "./conftest.js";
import { REPO_ROOT } from "./support/paths.js";

function readVector(name: string): Dict {
  return JSON.parse(readFileSync(join(REPO_ROOT, "spec", "test-vectors", name), "utf-8")) as Dict;
}

const PARTIES = readVector("transaction-record-parties.json");
const BASIS = readVector("transaction-record-basis.json");
const HISTORY = readVector("transaction-record-offer-history.json");
const SPELLINGS = PARTIES.spelling_cases as Dict[];
const PARTY_DIDS = PARTIES.did_documents as Record<string, Dict>;
const CONTROL = (PARTIES.cases as Dict[]).find((c) => c.name === "multi_round_control") as Dict;
const ACME = "did:web:acme-corp.com";

function relabelled(document: Dict, did: string): Dict {
  return { ...structuredClone(document), id: did };
}

test("a document is for the DID its id names and no other", () => {
  const document = PARTY_DIDS[INITIATOR_DID];
  expect(didDocumentIsFor(document, INITIATOR_DID)).toBe(true);
  for (const other of [
    "did:web:TechCorp.example",
    `${INITIATOR_DID}.`,
    `${INITIATOR_DID} `,
    `${INITIATOR_DID}#key-1`,
  ]) {
    expect(didDocumentIsFor(document, other)).toBe(false);
  }
  const { id: _id, ...withoutId } = document;
  expect(didDocumentIsFor(withoutId, INITIATOR_DID)).toBe(false);
  for (const notADocument of [null, undefined, [], "did", 7, { id: 7 }, { id: null }]) {
    expect(didDocumentIsFor(notADocument, INITIATOR_DID)).toBe(false);
  }
  expect(requireDidDocumentFor(document, INITIATOR_DID)).toBe(document);
  expect(() => requireDidDocumentFor(document, "did:web:TechCorp.example")).toThrow(
    DidDocumentIdMismatch,
  );
});

for (const c of SPELLINGS) {
  const canonical = c.canonical_did as string;
  const spelled = c.spelled_did as string;
  const documents = c.did_documents as Record<string, Dict>;

  test(`one party under two spellings is never verified: ${c.name}`, () => {
    // Both spellings reach one document; only the one its id names has it.
    const reason = verifyTransactionRecordReason(
      c.record as Dict,
      documents,
      c.offer_hashes as string[],
    );
    expect(reason).toBe(c.expected_reason);
    expect(reason).toBe(REASON_KEY_NOT_FOUND);
  });

  test(`the spelling case is real: ${c.name}`, () => {
    // One document, two keys; relabelled to name the spelling it verifies, so the
    // id binding is the only thing that refuses the record.
    expect(documents[canonical]).toEqual(documents[spelled]);
    expect(documents[canonical].id).toBe(canonical);
    expect(canonical).not.toBe(spelled);
    const fixed = { [canonical]: documents[canonical], [spelled]: relabelled(documents[canonical], spelled) };
    expect(verifyTransactionRecordReason(c.record as Dict, fixed, c.offer_hashes as string[])).toBe(
      null,
    );
  });

  test(`the resolver refuses a document naming another spelling: ${c.name}`, async () => {
    const document = documents[canonical];
    const fetchFn = fakeFetch({
      [didWebToUrl(canonical)]: { status: 200, json: document },
      [didWebToUrl(spelled)]: { status: 200, json: document },
    }) as unknown as FetchLike;
    expect(await resolveDidWeb(canonical, fetchFn)).toEqual(document);
    await expect(resolveDidWeb(spelled, fetchFn)).rejects.toBeInstanceOf(DidDocumentIdMismatch);
  });
}

for (const supply of ["mapping", "callable"]) {
  test(`the record verifier refuses a document naming another DID: ${supply}`, () => {
    const record = CONTROL.record as Dict;
    const hashes = CONTROL.offer_hashes as string[];
    const documents: Record<string, Dict> = {
      ...PARTY_DIDS,
      [ACME]: relabelled(PARTY_DIDS[ACME], "did:web:elsewhere.example"),
    };
    const resolver = supply === "mapping" ? documents : (did: string) => documents[did];
    expect(verifyTransactionRecordReason(record, PARTY_DIDS, hashes)).toBe(null);
    expect(verifyTransactionRecordReason(record, resolver, hashes)).toBe(REASON_KEY_NOT_FOUND);
  });
}

test("the evidence verifier refuses a document naming another DID", () => {
  const record = HISTORY.evidence_record as Dict;
  const documents = (HISTORY.did_documents as Dict).current as Record<string, Dict>;
  expect(assessSessionEvidenceRecord(record, documents).reason).toBe(null);
  for (const did of Object.keys(documents)) {
    const swapped = { ...documents, [did]: relabelled(documents[did], did.toUpperCase()) };
    expect(assessSessionEvidenceRecord(record, swapped).reason).toBe(EVIDENCE_REASON_KEY_NOT_FOUND);
  }
});

test("a session does not use a registered document naming another DID", () => {
  const manager = new SessionManager();
  for (const [did, document] of Object.entries(BASIS.did_documents as Record<string, Dict>)) {
    manager.registerDidDocument(did, did === ACME ? relabelled(document, "did:web:elsewhere.example") : document);
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
  const [offer, counteroffer] = structuredClone((BASIS.messages as Dict[]).slice(0, 2));
  manager.processMessage(session, offer);
  let caught: unknown = null;
  try {
    manager.processMessage(session, counteroffer);
  } catch (exc) {
    caught = exc;
  }
  expect(caught).toBeInstanceOf(A2CNError);
  expect((caught as A2CNError).code).toBe("INVALID_SIGNATURE");
});

test("the server refuses to register a document naming another DID", () => {
  const { ctx } = freshServer();
  expect(() => ctx.registerDidDocument("did:web:TechCorp.example", PARTY_DIDS[INITIATOR_DID])).toThrow(
    DidDocumentIdMismatch,
  );
  expect(ctx.didDocOverride["did:web:TechCorp.example"]).toBe(undefined);
});

test("the server does not use an override naming another DID", async () => {
  // A document put in the override table directly is checked when it is read.
  const { ctx, rawClient, initiatorKeypair, initiatorDidDoc } = freshServer();
  const body = makeSessionInit();
  async function post() {
    const token = await createJwt(INITIATOR_DID, SERVER_DID, initiatorKeypair.privateKey, {
      kid: `${INITIATOR_DID}#key-1`,
      expSeconds: 3600,
    });
    return rawClient.post("/sessions", {
      json: body,
      headers: { "Idempotency-Key": body.message_id as string, Authorization: `Bearer ${token}` },
    });
  }
  ctx.didDocOverride[INITIATOR_DID] = relabelled(initiatorDidDoc, "did:web:TechCorp.example");
  const refused = await post();
  expect(refused.statusCode).toBe(401);
  expect((refused.json().error as Dict).code).toBe("INVALID_JWT");

  ctx.registerDidDocument(INITIATOR_DID, initiatorDidDoc);
  expect((await post()).statusCode).toBe(201);
});

test("an inviter document naming another DID is no document", async () => {
  const { ctx, rawClient } = freshServer();
  const { privateKey: inviterPriv, publicKey: inviterPub } = generateKeypair();
  const inviterDid = "did:web:buyer.example";
  const vmId = `${inviterDid}#key-1`;
  const document = makeDidDocument(inviterDid, "key-1", publicKeyToJwk(inviterPub));
  ctx.didDocOverride[inviterDid] = { ...document, id: "did:web:Buyer.example" };
  const invitation: Dict = {
    message_type: "session_invitation",
    invitation_id: randomUUID(),
    a2cn_version: "0.3",
    inviter_did: inviterDid,
    inviter_endpoint: "https://buyer.example/a2cn",
    inviter_discovery_url: "https://buyer.example/.well-known/a2cn-agent",
    proposed_deal_type: "saas_renewal",
    proposed_session_params: {
      currency: "USD",
      max_rounds: 4,
      session_timeout_seconds: 3600,
      round_timeout_seconds: 900,
    },
    proposed_terms_summary: { total_value: 9_500_000, currency: "USD" },
    inviter_mandate_summary: { mandate_type: "declared" },
    invitation_expires_at: "2030-01-01T00:00:00Z",
    accept_endpoint: "https://buyer.example/a2cn/invitations/test/accept",
    decline_endpoint: "https://buyer.example/a2cn/invitations/test/decline",
    inviter_verification_method: vmId,
    invitation_signature: "",
  };
  invitation.invitation_signature = signInvitation(invitation, inviterPriv);

  const r = await rawClient.post("/invitations", { json: invitation });

  expect(r.statusCode).toBe(403);
  expect((r.json().error as Dict).code).toBe("INVITATION_SIGNATURE_INVALID");
});
