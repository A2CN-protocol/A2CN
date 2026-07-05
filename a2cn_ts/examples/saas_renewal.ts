/**
 * A2CN v0.1 / v0.2 Demo — Appendix B SaaS Renewal Walkthrough
 *
 * Scenario (from Appendix B):
 *   Buyer:  TechCorp Inc  (initiator)       starting position: $95,000
 *   Seller: Acme Corp     (responder)       starting position: $115,000
 *   Round 1: TechCorp offers $95K    → Acme counters $115K
 *   Round 2: TechCorp offers $103K   → Acme counters $105K (net-45)
 *   Round 4: TechCorp accepts $105K
 *   Outcome: $105,000 / year, net-45 payment terms
 *
 * CLI flags (v0.2.0):
 *   --deal-type TYPE           Override deal_type in session_params (default: saas_renewal)
 *   --impasse-threshold N      Set impasse detection threshold (default: 3)
 *
 * Run with:
 *   cd a2cn_ts
 *   npx tsx examples/saas_renewal.ts
 *   npx tsx examples/saas_renewal.ts --deal-type saas_renewal --impasse-threshold 2
 */

import { randomUUID } from "node:crypto";

import { A2CNClient } from "../src/a2cn/client.js";
import { createJwt, generateKeypair, hashObject, publicKeyToJwk, signJws } from "../src/a2cn/crypto.js";
import type { Dict } from "../src/a2cn/messages.js";
import { generateTransactionRecord } from "../src/a2cn/record.js";
import { createServerContext } from "../src/a2cn/server.js";
import { now as sessionNow } from "../src/a2cn/session.js";

// ---------------------------------------------------------------------------
// Verbose logging helper
// ---------------------------------------------------------------------------

/** Print a labelled, indented JSON block to stdout. */
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
// Helpers
// ---------------------------------------------------------------------------

const SELLER_PORT = 8000;
const SELLER_ENDPOINT = `http://localhost:${SELLER_PORT}`;

const TECHCORP_DID = "did:web:techcorp.example";
const ACME_DID = "did:web:acme-corp.com";

function nowFixed(offsetSeconds = 0): string {
  return new Date(Date.now() + offsetSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// ---------------------------------------------------------------------------
// Main demo
// ---------------------------------------------------------------------------

async function main(dealType = "saas_renewal", impasseThreshold = 3): Promise<void> {
  // -----------------------------------------------------------------------
  // 1. Configure and start the responder (Acme / seller side)
  // -----------------------------------------------------------------------
  if (dealType !== "saas_renewal") {
    console.log(`  [demo] Using deal_type='${dealType}', impasse_threshold=${impasseThreshold}`);
  }
  if (impasseThreshold !== 3) {
    console.log(`  [demo] impasse_threshold=${impasseThreshold}`);
  }

  const serverCtx = createServerContext();
  const { privateKey: acmePriv, publicKey: acmePub } = generateKeypair();
  const { privateKey: techcorpPriv, publicKey: techcorpPub } = generateKeypair();
  serverCtx.SERVER_DID = "did:web:localhost";

  const acmeAgentInfo = {
    organization_name: "Acme Corp",
    did: ACME_DID,
    verification_method: `${ACME_DID}#key-2026-01`,
    agent_id: "sales-agent-acme-007",
    endpoint: SELLER_ENDPOINT,
  };

  const acmeMandate = {
    mandate_type: "declared",
    agent_id: "sales-agent-acme-007",
    principal_organization: "Acme Corp",
    principal_did: ACME_DID,
    authorized_deal_types: ["saas_renewal"],
    max_commitment_value: 20_000_000,
    max_commitment_currency: "USD",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-12-31T00:00:00Z",
  };

  serverCtx.configureResponder({
    agent_info: acmeAgentInfo,
    mandate: acmeMandate,
    deal_types: ["saas_renewal", "services_contract", dealType],
    max_rounds_by_deal_type: { [dealType]: 5 },
    private_key: acmePriv,
  });

  const techcorpDidDoc = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: TECHCORP_DID,
    verificationMethod: [
      {
        id: `${TECHCORP_DID}#key-1`,
        type: "JsonWebKey2020",
        controller: TECHCORP_DID,
        publicKeyJwk: publicKeyToJwk(techcorpPub),
      },
    ],
    authentication: [`${TECHCORP_DID}#key-1`],
    assertionMethod: [`${TECHCORP_DID}#key-1`],
  };
  const acmeDidDoc = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: ACME_DID,
    verificationMethod: [
      {
        id: `${ACME_DID}#key-2026-01`,
        type: "JsonWebKey2020",
        controller: ACME_DID,
        publicKeyJwk: publicKeyToJwk(acmePub),
      },
    ],
    authentication: [`${ACME_DID}#key-2026-01`],
    assertionMethod: [`${ACME_DID}#key-2026-01`],
  };
  serverCtx.registerDidDocument(TECHCORP_DID, techcorpDidDoc);
  serverCtx.registerDidDocument(ACME_DID, acmeDidDoc);

  // Start server
  await serverCtx.app.listen({ host: "127.0.0.1", port: SELLER_PORT });

  // -----------------------------------------------------------------------
  // 2. Initiator (TechCorp / buyer side) fetches discovery
  // -----------------------------------------------------------------------
  const techcorpAgentInfo = {
    organization_name: "TechCorp Inc",
    did: TECHCORP_DID,
    verification_method: `${TECHCORP_DID}#key-1`,
    agent_id: "procurement-agent-tc-001",
    endpoint: "https://techcorp.example/api/a2cn",
  };

  const techcorpMandate = {
    mandate_type: "declared",
    agent_id: "procurement-agent-tc-001",
    principal_organization: "TechCorp Inc",
    principal_did: TECHCORP_DID,
    authorized_deal_types: ["saas_renewal"],
    max_commitment_value: 15_000_000,
    max_commitment_currency: "USD",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-12-31T00:00:00Z",
  };

  const client = new A2CNClient({
    agentInfo: techcorpAgentInfo,
    privateKey: techcorpPriv,
    mandate: techcorpMandate,
    fetchFn: fetch,
    authTokenFactory: () =>
      createJwt(TECHCORP_DID, serverCtx.SERVER_DID, techcorpPriv, {
        kid: `${TECHCORP_DID}#key-1`,
        expSeconds: 300,
      }),
  });

  console.log("✓ Discovery document fetched from seller");

  // -----------------------------------------------------------------------
  // 3. Session initiation
  // -----------------------------------------------------------------------
  const sessionParams = {
    deal_type: dealType,
    currency: "USD",
    subject: "Acme Analytics Platform — annual renewal FY2027",
    subject_reference: "CONTRACT-2024-ACME-001",
    estimated_value: 12_000_000,
    max_rounds: 4,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
    impasse_threshold: impasseThreshold,
  };

  const ack = await client.initiateSession(SELLER_ENDPOINT, ACME_DID, sessionParams);
  const sessionId = ack.session_id as string;

  log(
    "REQUEST  POST /sessions  →  SessionInit (TechCorp → Acme)",
    client._sessions[sessionId].session_init,
  );
  log("RESPONSE 201  ←  SessionAck (Acme → TechCorp)", ack);

  console.log(`✓ Session initiated — session_id: ${sessionId}`);

  // Tell client about responder party (for offer addressing)
  (client._sessions[sessionId].session_ack as Dict).responder = acmeAgentInfo;

  // -----------------------------------------------------------------------
  // 4. Round 1: TechCorp offers $95,000
  // -----------------------------------------------------------------------
  const termsR1 = {
    total_value: 9_500_000,
    currency: "USD",
    line_items: [
      {
        id: "li-1",
        description: "Acme Analytics Platform — 12 months",
        quantity: 1,
        unit: "year",
        unit_price: 9_500_000,
        total: 9_500_000,
      },
    ],
    payment_terms: { net_days: 30 },
    contract_duration: {
      start_date: "2026-07-01",
      end_date: "2027-06-30",
      auto_renewal: false,
      cancellation_notice_days: 60,
    },
  };

  await client.sendOffer(SELLER_ENDPOINT, ACME_DID, sessionId, termsR1);
  log(
    "REQUEST  POST /sessions/{id}/messages  →  Offer round 1  seq 1  (TechCorp → Acme)  $95,000",
    client._sessions[sessionId].latest_offer,
  );

  // -----------------------------------------------------------------------
  // Acme (responder) counters — Round 2: $115,000 net-60
  // The responder logic runs in-process here; in production each party
  // would be a separate service. We call processMessage directly on
  // the manager to simulate Acme's agent decision.
  // -----------------------------------------------------------------------
  const sessionObj = serverCtx.manager.getSession(sessionId)!;

  function acmeCounteroffer(
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
      sender_did: ACME_DID,
      timestamp: ts,
      expires_at: exp,
      terms,
    };
    const pah = hashObject(act);
    const pas = signJws(pah, acmePriv, `${ACME_DID}#key-2026-01`);
    return {
      message_type: "counteroffer",
      message_id: msgId,
      session_id: sessId,
      in_reply_to: inReplyTo,
      round_number: rnd,
      sequence_number: seq,
      sender_did: ACME_DID,
      sender_agent_id: "sales-agent-acme-007",
      sender_verification_method: `${ACME_DID}#key-2026-01`,
      timestamp: ts,
      expires_at: exp,
      terms,
      protocol_act_hash: pah,
      protocol_act_signature: pas,
    };
  }

  // Round 2: Acme counters $115K, net-60
  const r1Offer = client._sessions[sessionId].latest_offer as Dict;
  const termsR2 = {
    total_value: 11_500_000,
    currency: "USD",
    line_items: [
      {
        id: "li-1",
        description: "Acme Analytics Platform — 12 months",
        quantity: 1,
        unit: "year",
        unit_price: 11_500_000,
        total: 11_500_000,
      },
    ],
    payment_terms: { net_days: 60 },
    contract_duration: {
      start_date: "2026-07-01",
      end_date: "2027-06-30",
      auto_renewal: false,
      cancellation_notice_days: 60,
    },
  };
  const coR2 = acmeCounteroffer(sessionId, 2, 2, termsR2, r1Offer.message_id as string);
  serverCtx.manager.processMessage(sessionObj, coR2);

  log(
    "REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 2  seq 2  (Acme → TechCorp)  $115,000",
    coR2,
  );

  // Update client state to track Acme's counteroffer
  client.processIncoming(sessionId, coR2);

  console.log("✓ Round 1: TechCorp offers $95,000 — Acme counters $115,000");

  // -----------------------------------------------------------------------
  // Round 3: TechCorp counters $103,000 net-30
  // -----------------------------------------------------------------------
  const termsR3 = {
    total_value: 10_300_000,
    currency: "USD",
    line_items: [
      {
        id: "li-1",
        description: "Acme Analytics Platform — 12 months",
        quantity: 1,
        unit: "year",
        unit_price: 10_300_000,
        total: 10_300_000,
      },
    ],
    payment_terms: { net_days: 30 },
    contract_duration: {
      start_date: "2026-07-01",
      end_date: "2027-06-30",
      auto_renewal: false,
      cancellation_notice_days: 60,
    },
  };
  await client.sendOffer(SELLER_ENDPOINT, ACME_DID, sessionId, termsR3, coR2.message_id as string);
  log(
    "REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 3  seq 3  (TechCorp → Acme)  $103,000",
    client._sessions[sessionId].latest_offer,
  );

  // Round 4: Acme counters $105,000 net-45 (within tolerance — TechCorp will accept)
  const r3Offer = client._sessions[sessionId].latest_offer as Dict;
  const termsR4 = {
    total_value: 10_500_000,
    currency: "USD",
    line_items: [
      {
        id: "li-1",
        description: "Acme Analytics Platform — 12 months",
        quantity: 1,
        unit: "year",
        unit_price: 10_500_000,
        total: 10_500_000,
      },
    ],
    payment_terms: { net_days: 45 },
    contract_duration: {
      start_date: "2026-07-01",
      end_date: "2027-06-30",
      auto_renewal: false,
      cancellation_notice_days: 60,
    },
  };
  const coR4 = acmeCounteroffer(sessionId, 4, 4, termsR4, r3Offer.message_id as string);
  serverCtx.manager.processMessage(sessionObj, coR4);

  log(
    "REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 4  seq 4  (Acme → TechCorp)  $105,000",
    coR4,
  );

  // Update client state
  client.processIncoming(sessionId, coR4);

  console.log("✓ Round 2: TechCorp offers $103,000 — Acme counters $105,000 net-45");

  // -----------------------------------------------------------------------
  // TechCorp accepts Acme's $105K offer
  // -----------------------------------------------------------------------
  await client.sendAcceptance(SELLER_ENDPOINT, ACME_DID, sessionId, coR4);
  const messageLog = client._sessions[sessionId].message_log;
  log(
    "REQUEST  POST /sessions/{id}/messages  →  Acceptance  seq 5  (TechCorp → Acme)",
    messageLog[messageLog.length - 1],
  );
  console.log("✓ Round 4: TechCorp accepts $105,000");

  // -----------------------------------------------------------------------
  // Both sides generate transaction records independently
  // -----------------------------------------------------------------------
  // Server side
  const serverRecord = generateTransactionRecord(sessionObj);

  // Client side
  const clientRecord = client.buildClientSideRecord(sessionId);

  log("TRANSACTION RECORD  (generated independently by Acme / seller side)", serverRecord);
  console.log(
    `✓ Transaction record generated — record_hash: ${(serverRecord.record_hash as string).slice(0, 32)}...`,
  );

  if (serverRecord.record_hash !== clientRecord.record_hash) {
    throw new Error(
      `MISMATCH!\n  server: ${serverRecord.record_hash}\n  client: ${clientRecord.record_hash}`,
    );
  }
  console.log("✓ Buyer record_hash == Seller record_hash");
  console.log("✓ A2CN bilateral session complete");

  await serverCtx.app.close();
}

const argv = process.argv.slice(2);
const getArg = (name: string): string | null => {
  const idx = argv.indexOf(name);
  return idx >= 0 && idx + 1 < argv.length ? argv[idx + 1] : null;
};
const dealType = getArg("--deal-type") ?? "saas_renewal";
const impasseArg = getArg("--impasse-threshold");
const impasseThreshold = impasseArg !== null ? parseInt(impasseArg, 10) : 3;

main(dealType, impasseThreshold).catch((exc) => {
  console.error(exc);
  process.exit(1);
});
