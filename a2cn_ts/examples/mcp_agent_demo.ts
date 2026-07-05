/**
 * A2CN MCP Agent Demo — SaaS Renewal Negotiation via MCP Tools
 *
 * Demonstrates how an LLM agent uses the A2CN MCP server tools to negotiate
 * commercial terms autonomously.  The buyer (TechCorp) interacts exclusively
 * through the six MCP tools exposed by mcp_server.  The seller (Acme) is
 * simulated in-process using MockLLM, mirroring the pattern in saas_renewal.
 *
 * Architecture (per spec Section 13.9):
 *     Buyer MockLLM
 *         → decides: what to offer, whether to accept or reject
 *     MCP tool layer (mcp_server)
 *         → handles: session state, DID auth, message signing, sequence tracking
 *     A2CN Fastify server (seller / responder side)
 *         → processes all messages, enforces protocol rules, generates records
 *
 * Expected output:
 *     ✓ Discovered Acme: A2CN v0.2, conformance 2, deal types: ['saas_renewal']
 *     ✓ Session initiated — id: xxxxxxxx...
 *     ✓ Exchange 1: Buyer $95,000 → Seller $109,000
 *       [Buyer LLM] Counter: $99,000 / net-30
 *     ✓ Exchange 2: Buyer $99,000 → Seller $106,000
 *       [Buyer LLM] Accepting $106,000 / net-30
 *     ✓ Exchange 2: Buyer accepts — deal at $106,000 / net-30
 *     ✓ Transaction record_hash: ...
 *     ✓ A2CN MCP agent demo complete
 *
 * Run with:
 *     cd a2cn_ts
 *     npx tsx examples/mcp_agent_demo.ts
 */

// ---------------------------------------------------------------------------
// Agent identity — configure via environment variables before mcp_server loads.
// The MCP context reads these at creation time to build the ephemeral DID document.
// ---------------------------------------------------------------------------

process.env.A2CN_AGENT_DID = process.env.A2CN_AGENT_DID ?? "did:web:mcp-buyer.demo";
process.env.A2CN_AGENT_ID = process.env.A2CN_AGENT_ID ?? "mcp-buyer-001";
process.env.A2CN_AGENT_ORG = process.env.A2CN_AGENT_ORG ?? "TechCorp Inc";

import { generateKeypair } from "../src/a2cn/crypto.js";
import type { Dict } from "../src/a2cn/messages.js";
import { createServerContext } from "../src/a2cn/server.js";
import { createMcpContext } from "../src/mcp_server.js";
import {
  MockLLM,
  NegotiationSkill,
  getValidatedDecision,
  buildTermsFromDecision,
  buildSellerCounteroffer,
  type LlmHistoryEntry,
} from "./llm_agent.js";

// ---------------------------------------------------------------------------
// Demo constants
// ---------------------------------------------------------------------------

const SELLER_DID = "did:web:acme-corp.com";
const SELLER_PORT = 8002;
const SELLER_ENDPOINT = `http://localhost:${SELLER_PORT}`;

// ---------------------------------------------------------------------------
// Patch DID-to-URL resolution for local demo
//
// In production:  did:web:acme-corp.com  →  https://acme-corp.com
// In this demo:   did:web:acme-corp.com  →  http://localhost:8002
//
// The MCP tools resolve the seller DID to https://acme-corp.com; this fetch
// wrapper rewrites those URLs to the local server without modifying mcp_server.
// ---------------------------------------------------------------------------

const demoFetch: typeof fetch = (async (url: string | URL | Request, init?: RequestInit) => {
  const rewritten = String(url).replace("https://acme-corp.com", SELLER_ENDPOINT);
  return fetch(rewritten, init);
}) as typeof fetch;

// ---------------------------------------------------------------------------
// Main demo
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const mcpCtx = createMcpContext({ fetchFn: demoFetch });
  const BUYER_DID = mcpCtx.agentDid; // resolved from env var above

  // -----------------------------------------------------------------------
  // 1. Configure Acme (seller) as the A2CN responder
  // -----------------------------------------------------------------------
  const serverCtx = createServerContext();
  const { privateKey: acmePriv } = generateKeypair();

  serverCtx.configureResponder({
    agent_info: {
      organization_name: "Acme Corp",
      did: SELLER_DID,
      verification_method: `${SELLER_DID}#key-1`,
      agent_id: "sales-agent-acme-007",
      endpoint: SELLER_ENDPOINT,
    },
    mandate: {
      mandate_type: "declared",
      agent_id: "sales-agent-acme-007",
      principal_organization: "Acme Corp",
      principal_did: SELLER_DID,
      authorized_deal_types: ["saas_renewal"],
      max_commitment_value: 20_000_000,
      max_commitment_currency: "USD",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2026-12-31T00:00:00Z",
    },
    deal_types: ["saas_renewal"],
    max_rounds_by_deal_type: { saas_renewal: 8 },
    private_key: acmePriv,
  });

  // The server's own DID is used as the JWT audience claim.
  // Setting it equal to SELLER_DID means discovery returns the same value,
  // so the MCP tool's JWT audience resolves correctly.
  serverCtx.SERVER_DID = SELLER_DID;

  // Register the MCP buyer's ephemeral DID document with the seller server
  // so it can verify Bearer JWT signatures on incoming requests.
  serverCtx.registerDidDocument(BUYER_DID, mcpCtx.agentDidDocument);

  // Tell the MCP server the JWT audience directly, skipping a second
  // discovery round-trip inside a2cn_initiate_session.
  process.env.A2CN_COUNTERPARTY_SERVER_DID = SELLER_DID;

  // -----------------------------------------------------------------------
  // 2. Start the Acme (seller) server
  // -----------------------------------------------------------------------
  await serverCtx.app.listen({ host: "127.0.0.1", port: SELLER_PORT });

  console.log();
  console.log("=".repeat(62));
  console.log("  A2CN MCP Agent Demo — SaaS Renewal Negotiation");
  console.log("=".repeat(62));
  console.log(`  Buyer  (MCP agent): ${BUYER_DID}`);
  console.log(`  Seller (Acme Corp): ${SELLER_DID}`);
  console.log(`  Transport:          HTTP → ${SELLER_ENDPOINT}`);
  console.log();

  // -----------------------------------------------------------------------
  // 3. Discover the seller via MCP tool (Tool 1: a2cn_discover)
  // -----------------------------------------------------------------------
  const disc = await mcpCtx.a2cnDiscover(SELLER_DID);
  if (disc.a2cn_capable) {
    console.log(
      `✓ Discovered Acme: A2CN v${disc.a2cn_version}, ` +
        `conformance ${disc.conformance_level}, ` +
        `deal types: ${JSON.stringify(disc.deal_types)}`,
    );
  } else {
    // Graceful degradation — demo continues even if discovery HTTP fails
    console.log(`  [discovery skipped — demo mode]: ${String(disc.message ?? "").slice(0, 70)}`);
  }

  // -----------------------------------------------------------------------
  // 4. Initiate session and send opening offer (Tool 2: a2cn_initiate_session)
  // -----------------------------------------------------------------------
  const buyerOpeningCents = 9_500_000; // $95,000
  const buyerOpeningNet = 30;

  console.log(
    `\n[Buyer LLM] Opening offer: $${Math.trunc(buyerOpeningCents / 100).toLocaleString("en-US")} / net-${buyerOpeningNet}`,
  );

  const initResult = await mcpCtx.a2cnInitiateSession({
    counterparty_did: SELLER_DID,
    deal_type: "saas_renewal",
    my_did: BUYER_DID,
    initial_offer_total_value_cents: buyerOpeningCents,
    currency: "USD",
    max_rounds: 6,
    payment_terms_net_days: buyerOpeningNet,
    subject: "Acme Analytics Platform — FY2027 renewal",
  });

  if ("error" in initResult) {
    console.log(`✗ Session init failed: ${JSON.stringify(initResult)}`);
    await serverCtx.app.close();
    return;
  }

  const sessionId = initResult.session_id as string;
  console.log(`✓ Session initiated — id: ${sessionId.slice(0, 16)}...`);

  // -----------------------------------------------------------------------
  // 5. Negotiation loop
  //
  // Buyer decisions come from MockLLM via MCP tools.
  // Seller decisions come from MockLLM processed directly via the server's
  // session manager (simulating the seller's in-process agent).
  // -----------------------------------------------------------------------
  const buyerSkill: NegotiationSkill = {
    role: "buyer",
    deal_type: "saas_renewal",
    floor_value_cents: 10_600_000, // max willing to pay: $106,000
    target_value_cents: buyerOpeningCents,
    max_net_days: 45,
    min_net_days: 0,
    walk_away_rounds: 3,
    rationale_template: "aggressive buyer pushing for lowest total cost",
  };
  const sellerSkill: NegotiationSkill = {
    role: "seller",
    deal_type: "saas_renewal",
    floor_value_cents: 10_500_000, // min willing to accept: $105,000
    target_value_cents: 11_500_000,
    max_net_days: 60,
    min_net_days: 30,
    walk_away_rounds: 3,
    rationale_template: "seller protecting margin while staying competitive",
  };

  const buyerLlm = new MockLLM();
  const sellerLlm = new MockLLM();

  const buyerHistory: LlmHistoryEntry[] = [
    { value: buyerOpeningCents, net_days: buyerOpeningNet, rationale: "", round: 1 },
  ];
  const sellerHistory: LlmHistoryEntry[] = [];

  const sessionObj = serverCtx.manager.getSession(sessionId)!;
  const clientState = mcpCtx.sessions[sessionId].client._sessions[sessionId];

  let exchange = 1;

  for (;;) {
    // -------------------------------------------------------------------
    // Seller's turn (simulated in-process, not via HTTP)
    // -------------------------------------------------------------------
    const buyerLastOffer = clientState.latest_offer as Dict;
    const sellerOfferTerms = (buyerLastOffer.terms as Dict) ?? {};

    const sellerDecision = getValidatedDecision(
      sellerLlm,
      sellerSkill,
      sellerOfferTerms,
      sellerHistory,
    );

    if (sellerDecision === null || sellerDecision.action === "withdraw") {
      console.log(`\n✓ Exchange ${exchange}: Seller withdrew — no deal.`);
      break;
    }

    if (sellerDecision.action === "reject") {
      console.log(`\n✓ Exchange ${exchange}: Seller rejected — no deal.`);
      break;
    }

    if (sellerDecision.action === "accept") {
      // Seller accepts buyer's current offer (unusual path — buyer opened aggressively)
      const val = (sellerOfferTerms.total_value as number) ?? 0;
      console.log(
        `\n✓ Exchange ${exchange}: Seller accepts buyer's $${Math.trunc(val / 100).toLocaleString("en-US")} — deal!`,
      );
      mcpCtx.sessions[sessionId].status = "COMPLETED";
      break;
    }

    // Seller sends counteroffer — build and inject into both the server
    // session manager and the MCP client state
    const sellerTerms = buildTermsFromDecision(sellerDecision, sellerSkill, sellerOfferTerms);

    // next_seq: clientState.sequence_number was last incremented by
    // the buyer's most recent sendOffer; seller's reply is always +1
    const nextSeq = clientState.sequence_number + 1;

    const sellerCo = buildSellerCounteroffer(
      sessionId,
      nextSeq, // round == seq (saas_renewal convention)
      nextSeq,
      sellerTerms,
      buyerLastOffer.message_id as string,
      SELLER_DID,
      acmePriv,
    );
    // Update server-side session manager (seller "received" the message)
    serverCtx.manager.processMessage(sessionObj, sellerCo);
    // Update MCP client state so a2cn_accept / a2cn_send_offer see the offer
    mcpCtx.injectCounterpartyOffer(sessionId, sellerCo);

    const sellerVal = sellerTerms.total_value as number;
    const sellerNet = ((sellerTerms.payment_terms as Dict) ?? {}).net_days as number;
    const buyerVal = (sellerOfferTerms.total_value as number) ?? 0;

    console.log(
      `\n✓ Exchange ${exchange}: ` +
        `Buyer $${Math.trunc(buyerVal / 100).toLocaleString("en-US")} → ` +
        `Seller $${Math.trunc(sellerVal / 100).toLocaleString("en-US")} / net-${sellerNet}`,
    );
    sellerHistory.push({ value: sellerVal, net_days: sellerNet, rationale: "", round: nextSeq });

    // -------------------------------------------------------------------
    // Buyer's turn (via MCP tools + MockLLM)
    // -------------------------------------------------------------------
    const buyerDecision = getValidatedDecision(buyerLlm, buyerSkill, sellerTerms, buyerHistory);

    if (buyerDecision === null || buyerDecision.action === "withdraw") {
      console.log("  [Buyer LLM] Withdrawing — no deal.");
      await mcpCtx.a2cnReject(sessionId);
      break;
    }

    if (buyerDecision.action === "reject") {
      console.log("  [Buyer LLM] Rejecting — no deal.");
      await mcpCtx.a2cnReject(sessionId);
      break;
    }

    if (buyerDecision.action === "accept") {
      console.log(
        `  [Buyer LLM] Accepting $${Math.trunc(sellerVal / 100).toLocaleString("en-US")} / net-${sellerNet}`,
      );

      // Tool 4: a2cn_accept
      const acceptResult = await mcpCtx.a2cnAccept(sessionId);
      if ("error" in acceptResult) {
        console.log(`✗ Accept failed: ${JSON.stringify(acceptResult)}`);
      } else {
        const recHash = (acceptResult.record_hash as string) ?? "";
        console.log(
          `\n✓ Exchange ${exchange}: Buyer accepts — ` +
            `deal at $${Math.trunc(sellerVal / 100).toLocaleString("en-US")} / net-${sellerNet}`,
        );
        console.log(`✓ Transaction record_hash: ${recHash.slice(0, 32)}...`);
      }
      break;
    }

    // Buyer sends counteroffer via MCP tool (Tool 3: a2cn_send_offer)
    const newVal = buyerDecision.total_value_cents as number;
    const newNet = buyerDecision.net_days as number;
    console.log(
      `  [Buyer LLM] Counter: $${Math.trunc(newVal / 100).toLocaleString("en-US")} / net-${newNet}`,
    );

    // Tool 3: a2cn_send_offer
    const coResult = await mcpCtx.a2cnSendOffer({
      session_id: sessionId,
      total_value_cents: newVal,
      payment_terms_net_days: newNet,
    });
    if ("error" in coResult) {
      console.log(`✗ Send offer failed: ${JSON.stringify(coResult)}`);
      break;
    }

    buyerHistory.push({ value: newVal, net_days: newNet, rationale: "", round: exchange + 1 });
    exchange += 1;
  }

  // -----------------------------------------------------------------------
  // 6. Final session status (Tool 6: a2cn_get_session_status)
  // -----------------------------------------------------------------------
  const final = await mcpCtx.a2cnGetSessionStatus(sessionId);
  console.log();
  console.log(`✓ Final session state: ${final.status}`);
  if (final.transaction_record) {
    const tr = final.transaction_record as Dict;
    console.log(`✓ Record ID:   ${tr.record_id ?? ""}`);
    console.log(`  Record hash: ${String(tr.record_hash ?? "").slice(0, 32)}...`);
  }
  console.log("✓ A2CN MCP agent demo complete");

  await serverCtx.app.close();
}

main().catch((exc) => {
  console.error(exc);
  process.exit(1);
});
