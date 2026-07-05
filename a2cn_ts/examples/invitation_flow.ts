/**
 * A2CN v0.2.0 Demo — Component 8: Session Invitation Flow
 *
 * Scenario:
 *   Buyer:    AcmeBuyer   (inviter)    — proposes a goods_procurement session
 *   Supplier: TechSupply  (invitee)    — receives, verifies, and accepts
 *   After acceptance both parties proceed to a short negotiation (2 rounds)
 *   that reaches COMPLETED.
 *
 * Demonstrates:
 *   - InvitationStore.createInvitation() with ES256 signing
 *   - verifyInvitationSignature() on the received invitation
 *   - POST /invitations  (supplier receives inbound invitation)
 *   - POST /invitations/{id}/accept  (supplier accepts)
 *   - GET  /invitations/{id}         (buyer polls status)
 *   - Session negotiation starting from invitation context
 *   - Terminal webhook payload structure (logged in-process)
 *
 * Run with:
 *   cd a2cn_ts
 *   npx tsx examples/invitation_flow.ts
 *
 * The demo starts a configured supplier server on localhost:8001. If another
 * process is already listening on that port, stop it before running the demo.
 */

import { randomUUID, type KeyObject } from "node:crypto";

import { A2CNClient } from "../src/a2cn/client.js";
import {
  createJwt,
  generateKeypair,
  hashObject,
  publicKeyToJwk,
  signJws,
  verifyInvitationSignature,
} from "../src/a2cn/crypto.js";
import { InvitationStore } from "../src/a2cn/invitation.js";
import { InvitationStatus, WebhookPayload, SessionInvitation } from "../src/a2cn/messages.js";
import type { Dict } from "../src/a2cn/messages.js";
import { generateTransactionRecord } from "../src/a2cn/record.js";
import { createServerContext } from "../src/a2cn/server.js";
import { now as sessionNow } from "../src/a2cn/session.js";

// ---------------------------------------------------------------------------
// Pretty-print helper
// ---------------------------------------------------------------------------

function log(label: string, obj: unknown): void {
  const width = 72;
  console.log();
  console.log("─".repeat(width));
  console.log(`  ${label}`);
  console.log("─".repeat(width));
  console.log(JSON.stringify(obj, null, 2));
  console.log("─".repeat(width));
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SUPPLIER_PORT = 8001;
const SUPPLIER_ENDPOINT = `http://localhost:${SUPPLIER_PORT}`;

const BUYER_DID = "did:web:acmebuyer.example";
const SUPPLIER_DID = "did:web:techsupply.example";

function nowFixed(offsetSeconds = 0): string {
  return new Date(Date.now() + offsetSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** All-fields serialization, mirror of Python's dataclasses.asdict. */
function asDict(invitation: SessionInvitation): Dict {
  return { ...invitation } as unknown as Dict;
}

async function waitForServer(url: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await fetch(url);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(`Server at ${url} did not start within ${timeoutMs / 1000}s`);
}

function demoAuthFetch(
  issuerDid: string,
  audienceDid: () => string,
  privateKey: KeyObject,
  kid: string,
): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    const token = await createJwt(issuerDid, audienceDid(), privateKey, {
      kid,
      expSeconds: 300,
    });
    const headers = {
      ...((init?.headers as Record<string, string>) ?? {}),
      Authorization: `Bearer ${token}`,
    };
    return fetch(url, { ...init, headers });
  }) as typeof fetch;
}

// ---------------------------------------------------------------------------
// Main demo
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // -----------------------------------------------------------------------
  // 1. Generate keypairs for both parties
  // -----------------------------------------------------------------------
  const { privateKey: buyerPriv, publicKey: buyerPub } = generateKeypair();
  const { privateKey: supplierPriv, publicKey: supplierPub } = generateKeypair();
  const serverCtx = createServerContext();
  serverCtx.SERVER_DID = "did:web:localhost";

  const supplierAgentInfo = {
    organization_name: "TechSupply Inc",
    did: SUPPLIER_DID,
    verification_method: `${SUPPLIER_DID}#key-1`,
    agent_id: "supply-agent-ts-001",
    endpoint: SUPPLIER_ENDPOINT,
  };

  const supplierMandate = {
    mandate_type: "declared",
    agent_id: "supply-agent-ts-001",
    principal_organization: "TechSupply Inc",
    principal_did: SUPPLIER_DID,
    authorized_deal_types: ["goods_procurement"],
    max_commitment_value: 5_000_000,
    max_commitment_currency: "USD",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-12-31T00:00:00Z",
  };

  serverCtx.configureResponder({
    agent_info: supplierAgentInfo,
    mandate: supplierMandate,
    deal_types: ["goods_procurement"],
    max_rounds_by_deal_type: { goods_procurement: 5 },
    private_key: supplierPriv,
  });

  const buyerDidDoc = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: BUYER_DID,
    verificationMethod: [
      {
        id: `${BUYER_DID}#key-1`,
        type: "JsonWebKey2020",
        controller: BUYER_DID,
        publicKeyJwk: publicKeyToJwk(buyerPub),
      },
    ],
    authentication: [`${BUYER_DID}#key-1`],
    assertionMethod: [`${BUYER_DID}#key-1`],
  };
  const supplierDidDoc = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: SUPPLIER_DID,
    verificationMethod: [
      {
        id: `${SUPPLIER_DID}#key-1`,
        type: "JsonWebKey2020",
        controller: SUPPLIER_DID,
        publicKeyJwk: publicKeyToJwk(supplierPub),
      },
    ],
    authentication: [`${SUPPLIER_DID}#key-1`],
    assertionMethod: [`${SUPPLIER_DID}#key-1`],
  };
  serverCtx.registerDidDocument(BUYER_DID, buyerDidDoc);
  serverCtx.registerDidDocument(SUPPLIER_DID, supplierDidDoc);

  // -----------------------------------------------------------------------
  // 2. Start the supplier's A2CN server
  // -----------------------------------------------------------------------
  await serverCtx.app.listen({ host: "127.0.0.1", port: SUPPLIER_PORT });
  await waitForServer(`${SUPPLIER_ENDPOINT}/.well-known/a2cn-agent`);
  console.log("✓ Supplier server started");

  // -----------------------------------------------------------------------
  // 3. Buyer creates and signs a SessionInvitation
  // -----------------------------------------------------------------------
  const buyerStore = new InvitationStore();
  const invitation = buyerStore.createInvitation({
    inviterDid: BUYER_DID,
    inviterEndpoint: "https://acmebuyer.example/a2cn",
    inviterDiscoveryUrl: "https://acmebuyer.example/.well-known/a2cn-agent",
    inviterVerificationMethod: `${BUYER_DID}#key-1`,
    privateKey: buyerPriv,
    proposedDealType: "goods_procurement",
    proposedSessionParams: {
      currency: "USD",
      max_rounds: 4,
      session_timeout_seconds: 86400,
      round_timeout_seconds: 3600,
    },
    proposedTermsSummary: {
      description: "Hydraulic fluid drums — 50 x 200L",
      estimated_value: 1_800_000,
      currency: "USD",
    },
    inviterMandateSummary: {
      mandate_type: "declared",
      max_commitment_value: 2_500_000,
      authorized_deal_types: ["goods_procurement"],
    },
    expiresHours: 24,
    baseUrl: SUPPLIER_ENDPOINT,
  });

  const invDict = asDict(invitation);
  log(
    `BUYER creates SessionInvitation  invitation_id=${invitation.invitation_id.slice(0, 8)}...`,
    invDict,
  );
  console.log(`✓ Invitation created — id: ${invitation.invitation_id}`);
  console.log(`  signature: ${invitation.invitation_signature.slice(0, 32)}...`);

  // -----------------------------------------------------------------------
  // 4. Supplier verifies the invitation signature before storing
  // -----------------------------------------------------------------------
  const sigValid = verifyInvitationSignature(invDict, buyerPub);
  if (!sigValid) {
    throw new Error("Invitation signature verification FAILED");
  }
  console.log("✓ Invitation signature verified (ES256 + JCS)");

  // -----------------------------------------------------------------------
  // 5. Supplier receives invitation via POST /invitations
  // -----------------------------------------------------------------------
  const http = demoAuthFetch(BUYER_DID, () => serverCtx.SERVER_DID, buyerPriv, `${BUYER_DID}#key-1`);
  const supplierHttp = demoAuthFetch(
    SUPPLIER_DID,
    () => serverCtx.SERVER_DID,
    supplierPriv,
    `${SUPPLIER_DID}#key-1`,
  );

  let r = await http(`${SUPPLIER_ENDPOINT}/invitations`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(invDict),
  });
  if (![200, 201].includes(r.status)) {
    throw new Error(`POST /invitations failed: ${r.status} ${await r.text()}`);
  }
  const receiveResp = await r.json();
  log("RESPONSE  POST /invitations  (supplier receives inbound invitation)", receiveResp);
  console.log("✓ Supplier stored inbound invitation");

  // -----------------------------------------------------------------------
  // 6. Supplier polls GET /invitations/{id} — should be PENDING
  // -----------------------------------------------------------------------
  r = await http(`${SUPPLIER_ENDPOINT}/invitations/${invitation.invitation_id}`);
  if (r.status !== 200) {
    throw new Error(`GET /invitations/{id} failed: ${r.status}`);
  }
  const statusResp = (await r.json()) as Dict;
  if (statusResp.status !== InvitationStatus.PENDING) {
    throw new Error(`Expected PENDING, got ${statusResp.status}`);
  }
  console.log(`✓ GET /invitations/{id} → status: ${statusResp.status}`);

  // -----------------------------------------------------------------------
  // 7. Supplier accepts via POST /invitations/{id}/accept
  // -----------------------------------------------------------------------
  const acceptPayload = {
    acceptor_did: SUPPLIER_DID,
    acceptor_a2cn_endpoint: SUPPLIER_ENDPOINT,
    acceptor_discovery_url: "https://techsupply.example/.well-known/a2cn-agent",
    acceptor_verification_method: `${SUPPLIER_DID}#key-1`,
    acceptor_public_key_jwk: publicKeyToJwk(supplierPub),
  };
  r = await supplierHttp(`${SUPPLIER_ENDPOINT}/invitations/${invitation.invitation_id}/accept`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(acceptPayload),
  });
  if (r.status !== 200) {
    throw new Error(`POST /accept failed: ${r.status} ${await r.text()}`);
  }
  const acceptance = (await r.json()) as Dict;
  log("RESPONSE  POST /invitations/{id}/accept  (InvitationAcceptance)", acceptance);
  console.log(`✓ Acceptance issued — signed: ${"acceptance_signature" in acceptance}`);

  // -----------------------------------------------------------------------
  // 8. Buyer updates stored invitation to ACCEPTED
  // -----------------------------------------------------------------------
  buyerStore.storeInbound(invDict); // store a copy for tracking
  const entry = buyerStore.getInvitation(invitation.invitation_id)!;
  // In production the buyer would receive acceptance via webhook/callback;
  // here we directly mark it accepted to mirror server state.
  entry.status = InvitationStatus.ACCEPTED;
  console.log("✓ Buyer records invitation as ACCEPTED");

  // -----------------------------------------------------------------------
  // 9. Both parties proceed to open a negotiation session
  //    The buyer initiates using the proposed session params from the invitation.
  // -----------------------------------------------------------------------
  const buyerAgentInfo = {
    organization_name: "AcmeBuyer Corp",
    did: BUYER_DID,
    verification_method: `${BUYER_DID}#key-1`,
    agent_id: "procurement-agent-ab-001",
    endpoint: "https://acmebuyer.example/api/a2cn",
  };
  const buyerMandate = {
    mandate_type: "declared",
    agent_id: "procurement-agent-ab-001",
    principal_organization: "AcmeBuyer Corp",
    principal_did: BUYER_DID,
    authorized_deal_types: ["goods_procurement"],
    max_commitment_value: 2_500_000,
    max_commitment_currency: "USD",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-12-31T00:00:00Z",
  };

  const client = new A2CNClient({
    agentInfo: buyerAgentInfo,
    privateKey: buyerPriv,
    mandate: buyerMandate,
    fetchFn: fetch,
    authTokenFactory: () =>
      createJwt(BUYER_DID, serverCtx.SERVER_DID, buyerPriv, {
        kid: `${BUYER_DID}#key-1`,
        expSeconds: 300,
      }),
  });

  const sessionParams = {
    deal_type: "goods_procurement",
    currency: "USD",
    subject: "Hydraulic fluid drums — Q3 2026",
    subject_reference: `INV-${invitation.invitation_id.slice(0, 8).toUpperCase()}`,
    estimated_value: 1_800_000,
    max_rounds: 4,
    session_timeout_seconds: 86400,
    round_timeout_seconds: 3600,
    // Link back to the invitation that started this session
    invitation_id: invitation.invitation_id,
  };

  const ack = await client.initiateSession(SUPPLIER_ENDPOINT, SUPPLIER_DID, sessionParams);
  const sessionId = ack.session_id as string;
  log(
    "REQUEST  POST /sessions  →  SessionInit (Buyer → Supplier)",
    client._sessions[sessionId].session_init,
  );
  log("RESPONSE 201  ←  SessionAck (Supplier → Buyer)", ack);
  console.log(`✓ Session opened — session_id: ${sessionId}`);

  // Tell client about responder (for offer addressing)
  (client._sessions[sessionId].session_ack as Dict).responder = supplierAgentInfo;

  // -----------------------------------------------------------------------
  // 10. Round 1 — Buyer offers $18,000 (1,800,000 cents)
  // -----------------------------------------------------------------------
  const termsR1 = {
    total_value: 1_800_000,
    currency: "USD",
    line_items: [
      {
        id: "li-1",
        description: "Hydraulic fluid 200L drums",
        quantity: 50,
        unit_of_measure: "EA",
        unit_price: 36_000,
        total: 1_800_000,
      },
    ],
    delivery_days: 14,
    payment_terms: { net_days: 30 },
  };
  await client.sendOffer(SUPPLIER_ENDPOINT, SUPPLIER_DID, sessionId, termsR1);
  log(
    "REQUEST  POST /sessions/{id}/messages  →  Offer round 1  (Buyer → Supplier)  $18,000",
    client._sessions[sessionId].latest_offer,
  );

  // -----------------------------------------------------------------------
  // Supplier counters — Round 2: $20,000 net-60
  // -----------------------------------------------------------------------
  const sessionObj = serverCtx.manager.getSession(sessionId)!;
  const r1Offer = client._sessions[sessionId].latest_offer as Dict;

  function supplierCounter(
    sessId: string,
    seq: number,
    rnd: number,
    terms: Dict,
    inReplyTo: string,
  ): Dict {
    const ts = sessionNow();
    const exp = nowFixed(900);
    const msgId = randomUUID();
    const act = {
      protocol_version: "0.2",
      session_id: sessId,
      round_number: rnd,
      sequence_number: seq,
      message_type: "counteroffer",
      sender_did: SUPPLIER_DID,
      timestamp: ts,
      expires_at: exp,
      terms,
    };
    const pah = hashObject(act);
    const pas = signJws(pah, supplierPriv, `${SUPPLIER_DID}#key-1`);
    return {
      message_type: "counteroffer",
      message_id: msgId,
      session_id: sessId,
      in_reply_to: inReplyTo,
      round_number: rnd,
      sequence_number: seq,
      sender_did: SUPPLIER_DID,
      sender_agent_id: "supply-agent-ts-001",
      sender_verification_method: `${SUPPLIER_DID}#key-1`,
      timestamp: ts,
      expires_at: exp,
      terms,
      protocol_act_hash: pah,
      protocol_act_signature: pas,
    };
  }

  const termsR2 = {
    total_value: 2_000_000,
    currency: "USD",
    line_items: [
      {
        id: "li-1",
        description: "Hydraulic fluid 200L drums",
        quantity: 50,
        unit_of_measure: "EA",
        unit_price: 40_000,
        total: 2_000_000,
      },
    ],
    delivery_days: 10,
    payment_terms: { net_days: 60 },
  };
  const coR2 = supplierCounter(sessionId, 2, 2, termsR2, r1Offer.message_id as string);
  serverCtx.manager.processMessage(sessionObj, coR2);
  client.processIncoming(sessionId, coR2);
  log(
    "REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 2  (Supplier → Buyer)  $20,000",
    coR2,
  );
  console.log("✓ Round 1: Buyer offers $18,000 — Supplier counters $20,000");

  // -----------------------------------------------------------------------
  // Round 3 — Buyer counters $19,000 (moving round — > 0.5% delta)
  // -----------------------------------------------------------------------
  const termsR3 = {
    total_value: 1_900_000,
    currency: "USD",
    line_items: [
      {
        id: "li-1",
        description: "Hydraulic fluid 200L drums",
        quantity: 50,
        unit_of_measure: "EA",
        unit_price: 38_000,
        total: 1_900_000,
      },
    ],
    delivery_days: 14,
    payment_terms: { net_days: 30 },
  };
  await client.sendOffer(
    SUPPLIER_ENDPOINT,
    SUPPLIER_DID,
    sessionId,
    termsR3,
    coR2.message_id as string,
  );
  log(
    "REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 3  (Buyer → Supplier)  $19,000",
    client._sessions[sessionId].latest_offer,
  );

  // -----------------------------------------------------------------------
  // Supplier accepts $19,000 — session completes
  // -----------------------------------------------------------------------
  const r3Offer = client._sessions[sessionId].latest_offer as Dict;

  // Supplier acceptance message
  const ts = sessionNow();
  const msgId = randomUUID();
  // Acceptance uses current round (3), not a new round; sequence advances
  const act = {
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: 3,
    sequence_number: 4,
    accepted_offer_id: r3Offer.message_id,
    accepted_protocol_act_hash: r3Offer.protocol_act_hash,
    message_type: "acceptance",
    sender_did: SUPPLIER_DID,
    timestamp: ts,
    expires_at: nowFixed(900),
    terms: termsR3,
  };
  const pah = hashObject(act);
  const pas = signJws(pah, supplierPriv, `${SUPPLIER_DID}#key-1`);
  const supplierAcceptance = {
    message_type: "acceptance",
    message_id: msgId,
    session_id: sessionId,
    in_reply_to: r3Offer.message_id,
    accepted_offer_id: r3Offer.message_id,
    accepted_protocol_act_hash: r3Offer.protocol_act_hash,
    round_number: 3,
    sequence_number: 4,
    sender_did: SUPPLIER_DID,
    sender_agent_id: "supply-agent-ts-001",
    sender_verification_method: `${SUPPLIER_DID}#key-1`,
    timestamp: ts,
    expires_at: nowFixed(900),
    terms: termsR3,
    protocol_act_hash: pah,
    protocol_act_signature: pas,
  };
  serverCtx.manager.processMessage(sessionObj, supplierAcceptance);
  client.processIncoming(sessionId, supplierAcceptance);
  log(
    "REQUEST  POST /sessions/{id}/messages  →  Acceptance round 4  (Supplier → Buyer)  $19,000",
    supplierAcceptance,
  );
  console.log("✓ Round 3: Buyer offers $19,000 — Supplier accepts");

  // -----------------------------------------------------------------------
  // 11. Verify terminal state and transaction record
  // -----------------------------------------------------------------------
  const serverRecord = generateTransactionRecord(sessionObj);
  const clientRecord = client.buildClientSideRecord(sessionId);

  log("TRANSACTION RECORD  (generated independently by Supplier / server side)", serverRecord);

  if (serverRecord.record_hash !== clientRecord.record_hash) {
    throw new Error(
      `Hash mismatch!\n  server: ${serverRecord.record_hash}\n` +
        `  client: ${clientRecord.record_hash}`,
    );
  }

  console.log(
    `✓ Session COMPLETED — record_hash: ${(serverRecord.record_hash as string).slice(0, 32)}...`,
  );
  console.log("✓ Buyer record_hash == Supplier record_hash");

  // -----------------------------------------------------------------------
  // 12. Show what a terminal WebhookPayload looks like
  // -----------------------------------------------------------------------
  const webhook = new WebhookPayload({
    event_type: "session.completed",
    session_id: sessionId,
    occurred_at: sessionNow(),
    session_state: "COMPLETED",
    terminal: true,
    a2cn_version: "0.2",
    record_hash: serverRecord.record_hash as string,
  });
  log("WEBHOOK PAYLOAD  (would be POST'd to webhook_url on terminal transition)", {
    ...webhook,
  });
  console.log("✓ WebhookPayload constructed (delivery skipped — no webhook_url configured)");
  console.log();
  console.log("✓ A2CN v0.2.0 invitation flow complete");

  await serverCtx.app.close();
}

main().catch((exc) => {
  console.error(exc);
  process.exit(1);
});
