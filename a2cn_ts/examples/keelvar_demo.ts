/**
 * A2CN Keelvar Adapter Demo — Path B Supplier-Side Integration
 *
 * Scenario:
 *   Buyer:    AcmeBuyer Corp  (Keelvar platform user, sends sourcing events)
 *   Supplier: TechSupply Inc  (A2CN agent, responds via Keelvar webhook)
 *
 * Path B — Zero Keelvar platform changes required:
 *   1. Keelvar fires SOURCING_EVENTS_FEED_UPDATED webhook to supplier's endpoint
 *   2. Supplier's A2CN agent parses the webhook → A2CN goods_procurement terms
 *   3. Agent accepts the implicit invitation and initiates an A2CN session
 *   4. 3-round negotiation: Buyer at $20,150 → Supplier at $23,000 → Buyer accepts $21,500
 *   5. Agreed terms translated back to a Keelvar bid response payload
 *   6. (Production) Supplier POSTs bid response to Keelvar API
 *
 * Run with:
 *   cd a2cn_ts
 *   npx tsx examples/keelvar_demo.ts
 *
 * No external dependencies — Keelvar API calls are simulated in-process.
 * The supplier's A2CN server runs on localhost:8003.
 */

import { createHmac, randomUUID } from "node:crypto";

import { KeelvarEventParser } from "../src/adapters/keelvar_adapter.js";
import { A2CNClient } from "../src/a2cn/client.js";
import { createJwt, generateKeypair, hashObject, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import type { Dict } from "../src/a2cn/messages.js";
import { generateTransactionRecord } from "../src/a2cn/record.js";
import { createServerContext } from "../src/a2cn/server.js";
import { now as sessionNow } from "../src/a2cn/session.js";

// ---------------------------------------------------------------------------
// Helpers
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

const SUPPLIER_PORT = 8003;
const SUPPLIER_ENDPOINT = `http://localhost:${SUPPLIER_PORT}`;

const BUYER_DID = "did:web:acmebuyer.example";
const SUPPLIER_DID = "did:web:techsupply.example";

function nowFixed(offsetSeconds = 0): string {
  return new Date(Date.now() + offsetSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// ---------------------------------------------------------------------------
// Simulated Keelvar webhook payload (3 line items, mixed units)
// ---------------------------------------------------------------------------

const KEELVAR_WEBHOOK: Dict = {
  event_id: "evt-keelvar-q3-2026-001",
  event_name: "Q3 2026 Industrial Supplies RFQ",
  buyer_org: "AcmeBuyer Corp",
  deadline: "2026-05-01T17:00:00Z",
  currency: "USD",
  line_items: [
    {
      description: "Hydraulic fluid 200L drums",
      quantity: 50,
      unit_of_measure: "EA",
      unit_price: 360.0, // buyer's benchmark price in USD
      lot_id: "LOT-HF-001",
    },
    {
      description: "Sealing compound industrial grade",
      quantity: 20,
      unit_of_measure: "KG",
      unit_price: 85.0,
      lot_id: "LOT-SC-002",
    },
    {
      description: "Safety gloves cut-resistant (box/100)",
      quantity: 10,
      unit_of_measure: "BX",
      unit_price: 45.0,
      lot_id: "LOT-SG-003",
    },
  ],
};

// ---------------------------------------------------------------------------
// Main demo
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // -----------------------------------------------------------------------
  // 1. Configure TechSupply (supplier) as the A2CN responder
  // -----------------------------------------------------------------------
  const serverCtx = createServerContext();
  const { privateKey: supplierPriv } = generateKeypair();
  const { privateKey: buyerPriv, publicKey: buyerPub } = generateKeypair();

  serverCtx.configureResponder({
    agent_info: {
      organization_name: "TechSupply Inc",
      did: SUPPLIER_DID,
      verification_method: `${SUPPLIER_DID}#key-1`,
      agent_id: "supply-agent-ts-001",
      endpoint: SUPPLIER_ENDPOINT,
    },
    mandate: {
      mandate_type: "declared",
      agent_id: "supply-agent-ts-001",
      principal_organization: "TechSupply Inc",
      principal_did: SUPPLIER_DID,
      authorized_deal_types: ["goods_procurement"],
      max_commitment_value: 5_000_000,
      max_commitment_currency: "USD",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2026-12-31T00:00:00Z",
    },
    deal_types: ["goods_procurement"],
    max_rounds_by_deal_type: { goods_procurement: 5 },
    private_key: supplierPriv,
  });

  // Register buyer's DID doc so the supplier server can verify JWT signatures
  const buyerPubJwk = publicKeyToJwk(buyerPub);
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
        publicKeyJwk: buyerPubJwk,
      },
    ],
    authentication: [`${BUYER_DID}#key-1`],
    assertionMethod: [`${BUYER_DID}#key-1`],
  };
  // SERVER_DID is the JWT audience; set it to SUPPLIER_DID for this demo
  serverCtx.SERVER_DID = SUPPLIER_DID;
  serverCtx.registerDidDocument(BUYER_DID, buyerDidDoc);

  await serverCtx.app.listen({ host: "127.0.0.1", port: SUPPLIER_PORT });
  console.log("✓ Supplier A2CN server started");

  // -----------------------------------------------------------------------
  // 2. Simulate receiving Keelvar SOURCING_EVENTS_FEED_UPDATED webhook
  // -----------------------------------------------------------------------
  console.log();
  console.log("=".repeat(64));
  console.log("  Step 1 — Keelvar webhook received");
  console.log("=".repeat(64));

  // In production: verify HMAC signature first
  const signingKey = "demo-keelvar-signing-key";
  const bodyBytes = Buffer.from(JSON.stringify(KEELVAR_WEBHOOK), "utf-8");
  const sig = createHmac("sha256", signingKey).update(bodyBytes).digest("hex");
  const sigValid = KeelvarEventParser.verifyWebhookSignature(bodyBytes, sig, signingKey);
  console.log(`✓ Webhook signature verified (HMAC_SHA256): ${sigValid}`);

  const parsed = KeelvarEventParser.parseSourcingEventWebhook(KEELVAR_WEBHOOK);
  log(
    "Keelvar SOURCING_EVENTS_FEED_UPDATED  →  parsed summary",
    Object.fromEntries(Object.entries(parsed).filter(([k]) => k !== "raw_payload")),
  );
  console.log(`✓ Keelvar event_id: ${parsed.event_id}`);
  console.log(`  Buyer: ${parsed.buyer_org}, deadline: ${parsed.deadline}`);
  console.log(`  Line items: ${(parsed.line_items as Dict[]).length}`);

  // -----------------------------------------------------------------------
  // 3. Translate webhook to A2CN goods_procurement terms
  // -----------------------------------------------------------------------
  console.log();
  console.log("=".repeat(64));
  console.log("  Step 2 — Translate Keelvar event to A2CN terms");
  console.log("=".repeat(64));

  const initialTerms = KeelvarEventParser.sourcingEventToGoodsProcurementTerms(
    KEELVAR_WEBHOOK,
    14,
  );
  log("Keelvar line items  →  A2CN goods_procurement terms", initialTerms);
  const buyerBenchmark = initialTerms.total_value as number;
  console.log(
    `✓ Buyer benchmark (from Keelvar prices): ` +
      `$${(buyerBenchmark / 100).toLocaleString("en-US", { minimumFractionDigits: 2 })} ${initialTerms.currency}`,
  );
  console.log("  Supplier will open above benchmark and negotiate down");

  // -----------------------------------------------------------------------
  // 4. Supplier initiates A2CN session using buyer benchmark + markup
  //    (in production: buyer sends SessionInvitation first; here we
  //     demonstrate the supplier initiating with benchmark context)
  // -----------------------------------------------------------------------
  console.log();
  console.log("=".repeat(64));
  console.log("  Step 3 — A2CN negotiation");
  console.log("=".repeat(64));

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
    max_commitment_value: 3_000_000,
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
      createJwt(BUYER_DID, SUPPLIER_DID, buyerPriv, { kid: `${BUYER_DID}#key-1`, expSeconds: 300 }),
  });

  const sessionParams = {
    deal_type: "goods_procurement",
    currency: "USD",
    subject: `Q3 2026 Industrial Supplies — ${parsed.event_id}`,
    subject_reference: parsed.event_id,
    estimated_value: buyerBenchmark,
    max_rounds: 5,
    session_timeout_seconds: 86400,
    round_timeout_seconds: 3600,
  };

  const ack = await client.initiateSession(SUPPLIER_ENDPOINT, SUPPLIER_DID, sessionParams);
  const sessionId = ack.session_id as string;
  console.log(`✓ A2CN session opened — id: ${sessionId}`);

  (client._sessions[sessionId].session_ack as Dict).responder = {
    organization_name: "TechSupply Inc",
    did: SUPPLIER_DID,
    verification_method: `${SUPPLIER_DID}#key-1`,
    agent_id: "supply-agent-ts-001",
    endpoint: SUPPLIER_ENDPOINT,
  };

  // -------------------------------------------------------------------
  // Round 1 — Buyer opens at benchmark ($20,150 = buyerBenchmark)
  // -------------------------------------------------------------------
  const termsR1 = { ...initialTerms }; // start from Keelvar benchmark
  await client.sendOffer(SUPPLIER_ENDPOINT, SUPPLIER_DID, sessionId, termsR1);
  log(
    `Round 1 → Buyer offers $${Math.round(buyerBenchmark / 100).toLocaleString("en-US")} (Keelvar benchmark)`,
    client._sessions[sessionId].latest_offer,
  );

  // -------------------------------------------------------------------
  // Supplier counters — Round 2: markup ~14% above benchmark
  // -------------------------------------------------------------------
  const sessionObj = serverCtx.manager.getSession(sessionId)!;
  const r1Offer = client._sessions[sessionId].latest_offer as Dict;

  const supplierCounterValue = 2_300_000; // $23,000

  // Scale supplier's line item prices proportionally
  const scale = supplierCounterValue / Math.max(buyerBenchmark, 1);
  const supplierLineItems = (initialTerms.line_items as Dict[]).map((li) => {
    const newUnit = Math.trunc((li.unit_price as number) * scale);
    return { ...li, unit_price: newUnit, total: (li.quantity as number) * newUnit };
  });

  const termsR2 = {
    total_value: supplierCounterValue,
    currency: "USD",
    line_items: supplierLineItems,
    delivery_days: 10,
    payment_terms: { net_days: 45 },
  };

  let ts = sessionNow();
  const exp = nowFixed(900);
  const msgIdR2 = randomUUID();
  const actR2 = {
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: 2,
    sequence_number: 2,
    message_type: "counteroffer",
    sender_did: SUPPLIER_DID,
    timestamp: ts,
    expires_at: exp,
    terms: termsR2,
  };
  const pahR2 = hashObject(actR2);
  const pasR2 = signJws(pahR2, supplierPriv, `${SUPPLIER_DID}#key-1`);
  const coR2 = {
    message_type: "counteroffer",
    message_id: msgIdR2,
    session_id: sessionId,
    in_reply_to: r1Offer.message_id,
    round_number: 2,
    sequence_number: 2,
    sender_did: SUPPLIER_DID,
    sender_agent_id: "supply-agent-ts-001",
    sender_verification_method: `${SUPPLIER_DID}#key-1`,
    timestamp: ts,
    expires_at: exp,
    terms: termsR2,
    protocol_act_hash: pahR2,
    protocol_act_signature: pasR2,
  };
  serverCtx.manager.processMessage(sessionObj, coR2);
  client.processIncoming(sessionId, coR2);
  log("Round 2 → Supplier counters $23,000 (net-45, delivery 10 days)", coR2);
  console.log(
    `✓ Round 1: Buyer $${Math.round(buyerBenchmark / 100).toLocaleString("en-US")} ` +
      `→ Supplier $${Math.round(supplierCounterValue / 100).toLocaleString("en-US")}`,
  );

  // -------------------------------------------------------------------
  // Round 3 — Buyer counters at $21,500 (midpoint, buyer accepts)
  // -------------------------------------------------------------------
  const finalValue = 2_150_000; // $21,500

  const scale2 = finalValue / Math.max(buyerBenchmark, 1);
  const buyerR3LineItems = (initialTerms.line_items as Dict[]).map((li) => {
    const newUnit = Math.trunc((li.unit_price as number) * scale2);
    return { ...li, unit_price: newUnit, total: (li.quantity as number) * newUnit };
  });

  const termsR3 = {
    total_value: finalValue,
    currency: "USD",
    line_items: buyerR3LineItems,
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
    "Round 3 → Buyer counters $21,500 (net-30, delivery 14 days)",
    client._sessions[sessionId].latest_offer,
  );

  // -------------------------------------------------------------------
  // Supplier accepts $21,500 — session completes
  // -------------------------------------------------------------------
  const r3Offer = client._sessions[sessionId].latest_offer as Dict;
  ts = sessionNow();
  const msgIdAcc = randomUUID();
  // Signed payload is the 5-field acceptance object (Section 7.4), not a
  // full protocol act — Acceptance messages carry no terms/expires_at.
  const acceptancePayload = {
    session_id: sessionId,
    round_number: 3,
    sequence_number: 4,
    accepted_offer_id: r3Offer.message_id,
    accepted_protocol_act_hash: r3Offer.protocol_act_hash,
  };
  const acceptanceSignature = signJws(
    hashObject(acceptancePayload),
    supplierPriv,
    `${SUPPLIER_DID}#key-1`,
  );
  const supplierAcceptance = {
    message_type: "acceptance",
    message_id: msgIdAcc,
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
    acceptance_signature: acceptanceSignature,
  };
  serverCtx.manager.processMessage(sessionObj, supplierAcceptance);
  client.processIncoming(sessionId, supplierAcceptance);
  log("Round 4 → Supplier accepts $21,500 — session COMPLETED", supplierAcceptance);
  console.log(
    `✓ Round 2: Buyer $${Math.round(finalValue / 100).toLocaleString("en-US")} ` +
      `→ Supplier accepts — DEAL at $${Math.round(finalValue / 100).toLocaleString("en-US")}`,
  );

  // -----------------------------------------------------------------------
  // 5. Verify transaction record hashes match
  // -----------------------------------------------------------------------
  const serverRecord = generateTransactionRecord(sessionObj);
  const clientRecord = client.buildClientSideRecord(sessionId);
  if (serverRecord.record_hash !== clientRecord.record_hash) {
    throw new Error(
      `MISMATCH!\n  server: ${serverRecord.record_hash}\n  client: ${clientRecord.record_hash}`,
    );
  }
  console.log(`✓ record_hash: ${(serverRecord.record_hash as string).slice(0, 32)}...`);
  console.log("✓ Buyer record_hash == Supplier record_hash");

  // -----------------------------------------------------------------------
  // 6. Translate agreed terms back to Keelvar bid response
  // -----------------------------------------------------------------------
  console.log();
  console.log("=".repeat(64));
  console.log("  Step 4 — Translate agreed terms to Keelvar bid response");
  console.log("=".repeat(64));

  const agreedTerms = termsR3;
  const bidResponse = KeelvarEventParser.termsToKeelvarBidResponse(
    agreedTerms,
    parsed.event_id as string,
    "sup-techsupply-001",
  );
  log("A2CN agreed_terms  →  Keelvar bid response payload", bidResponse);

  console.log(`✓ Bid response prepared for Keelvar event ${parsed.event_id}`);
  console.log(
    `  Total price: $${(bidResponse.total_price as number).toLocaleString("en-US", { minimumFractionDigits: 2 })} ${bidResponse.currency}`,
  );
  console.log(`  Payment:     ${bidResponse.payment_terms}`);
  console.log(`  Delivery:    ${bidResponse.delivery_days} days`);
  console.log(`  Line items:  ${(bidResponse.line_items as Dict[]).length}`);
  console.log();
  console.log("  [Production] POST bid response to Keelvar API:");
  console.log("  POST https://my.keelvar.app/api/sourcing-events/bid-responses");
  console.log("  Authorization: Bearer {KEELVAR_API_KEY}");
  console.log();
  console.log("✓ Keelvar Path B integration demo complete");

  await serverCtx.app.close();
}

main().catch((exc) => {
  console.error(exc);
  process.exit(1);
});
