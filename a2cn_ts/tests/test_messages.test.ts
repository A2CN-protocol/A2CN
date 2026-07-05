/** Tests for a2cn/messages — wire format serialization. */

import { expect, test } from "vitest";

import {
  SessionParams,
  AgentInfo,
  DeclaredMandate,
  TermsObject,
  Offer,
  Acceptance,
} from "../src/a2cn/messages.js";

function makeSessionParams(): SessionParams {
  return new SessionParams({
    deal_type: "saas_renewal",
    currency: "USD",
    subject: "Test",
    max_rounds: 4,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
    subject_reference: "REF-001",
    estimated_value: 12_000_000,
  });
}

function makeAgentInfo(did = "did:web:example.com"): AgentInfo {
  return new AgentInfo({
    organization_name: "Test Org",
    did,
    verification_method: `${did}#key-1`,
    agent_id: "agent-001",
    endpoint: "https://example.com/api/a2cn",
  });
}

function makeMandate(): DeclaredMandate {
  return new DeclaredMandate({
    mandate_type: "declared",
    agent_id: "agent-001",
    principal_organization: "Test Org",
    principal_did: "did:web:example.com",
    authorized_deal_types: ["saas_renewal"],
    max_commitment_value: 15_000_000,
    max_commitment_currency: "USD",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-12-31T00:00:00Z",
  });
}

function makeTerms(): TermsObject {
  return new TermsObject({
    total_value: 9_500_000,
    currency: "USD",
    payment_terms: { net_days: 30 },
  });
}

// ---------------------------------------------------------------------------
// Field names match wire format exactly
// ---------------------------------------------------------------------------

test("session params field names", () => {
  const sp = makeSessionParams();
  const d = sp.toDict();
  expect("deal_type" in d).toBe(true);
  expect("session_timeout_seconds" in d).toBe(true);
  expect("round_timeout_seconds" in d).toBe(true);
  expect("subject_reference" in d).toBe(true);
});

test("agent info field names", () => {
  const ai = makeAgentInfo();
  const d = ai.toDict();
  expect("organization_name" in d).toBe(true);
  expect("verification_method" in d).toBe(true);
  expect("agent_id" in d).toBe(true);
});

test("declared mandate field names", () => {
  const m = makeMandate();
  const d = m.toDict();
  expect(d.mandate_type).toBe("declared");
  expect("authorized_deal_types" in d).toBe(true);
  expect("max_commitment_value" in d).toBe(true);
  expect("valid_until" in d).toBe(true);
});

test("offer field names", () => {
  const offer = new Offer({
    message_type: "offer",
    message_id: "msg-1",
    session_id: "sess-1",
    round_number: 1,
    sequence_number: 1,
    sender_did: "did:web:buyer.example",
    sender_agent_id: "agent-001",
    sender_verification_method: "did:web:buyer.example#key-1",
    timestamp: "2026-03-24T10:00:00Z",
    expires_at: "2026-03-24T10:15:00Z",
    terms: makeTerms(),
    protocol_act_hash: "sha256-abc",
    protocol_act_signature: "eyJ...",
  });
  const d = offer.toDict();
  expect(d.message_type).toBe("offer");
  expect("sender_did" in d).toBe(true);
  expect("sender_agent_id" in d).toBe(true);
  expect("sender_verification_method" in d).toBe(true);
  expect("protocol_act_hash" in d).toBe(true);
  expect("protocol_act_signature" in d).toBe(true);
  // in_reply_to absent in round 1
  expect("in_reply_to" in d).toBe(false);
});

test("offer round2 has in reply to", () => {
  const offer = new Offer({
    message_type: "counteroffer",
    message_id: "msg-2",
    session_id: "sess-1",
    round_number: 2,
    sequence_number: 2,
    sender_did: "did:web:seller.example",
    sender_agent_id: "agent-002",
    sender_verification_method: "did:web:seller.example#key-1",
    timestamp: "2026-03-24T10:02:00Z",
    expires_at: "2026-03-24T10:17:00Z",
    terms: makeTerms(),
    protocol_act_hash: "sha256-def",
    protocol_act_signature: "eyJ...",
    in_reply_to: "msg-1",
  });
  const d = offer.toDict();
  expect(d.message_type).toBe("counteroffer");
  expect(d.in_reply_to).toBe("msg-1");
});

test("offer protocol act object fields", () => {
  const offer = new Offer({
    message_type: "offer",
    message_id: "msg-1",
    session_id: "sess-1",
    round_number: 1,
    sequence_number: 1,
    sender_did: "did:web:buyer.example",
    sender_agent_id: "agent-001",
    sender_verification_method: "did:web:buyer.example#key-1",
    timestamp: "2026-03-24T10:00:00Z",
    expires_at: "2026-03-24T10:15:00Z",
    terms: makeTerms(),
    protocol_act_hash: "sha256-abc",
    protocol_act_signature: "eyJ...",
  });
  const act = offer.protocolActObject();
  expect(new Set(Object.keys(act))).toEqual(
    new Set([
      "protocol_version",
      "session_id",
      "round_number",
      "sequence_number",
      "message_type",
      "sender_did",
      "timestamp",
      "expires_at",
      "terms",
    ]),
  );
});

test("acceptance field names", () => {
  const acc = new Acceptance({
    message_type: "acceptance",
    message_id: "msg-3",
    session_id: "sess-1",
    in_reply_to: "msg-2",
    round_number: 2,
    sequence_number: 3,
    accepted_offer_id: "msg-2",
    accepted_protocol_act_hash: "sha256-def",
    sender_did: "did:web:buyer.example",
    sender_agent_id: "agent-001",
    sender_verification_method: "did:web:buyer.example#key-1",
    timestamp: "2026-03-24T10:05:00Z",
    acceptance_signature: "eyJ...",
  });
  const d = acc.toDict();
  expect("accepted_offer_id" in d).toBe(true);
  expect("accepted_protocol_act_hash" in d).toBe(true);
  expect("acceptance_signature" in d).toBe(true);
});

test("acceptance payload", () => {
  const acc = new Acceptance({
    message_type: "acceptance",
    message_id: "msg-3",
    session_id: "sess-1",
    in_reply_to: "msg-2",
    round_number: 2,
    sequence_number: 3,
    accepted_offer_id: "msg-2",
    accepted_protocol_act_hash: "sha256-def",
    sender_did: "did:web:buyer.example",
    sender_agent_id: "agent-001",
    sender_verification_method: "did:web:buyer.example#key-1",
    timestamp: "2026-03-24T10:05:00Z",
    acceptance_signature: "eyJ...",
  });
  const payload = acc.acceptancePayload();
  expect(new Set(Object.keys(payload))).toEqual(
    new Set([
      "session_id",
      "round_number",
      "sequence_number",
      "accepted_offer_id",
      "accepted_protocol_act_hash",
    ]),
  );
});

test("none fields omitted", () => {
  const sp = new SessionParams({
    deal_type: "saas_renewal",
    currency: "USD",
    subject: "Test",
    max_rounds: 4,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
    // subject_reference and estimated_value left unset
  });
  const d = sp.toDict();
  expect("subject_reference" in d).toBe(false);
  expect("estimated_value" in d).toBe(false);
});
