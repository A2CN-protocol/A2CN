/**
 * Section 9A.6, step 13: the line items of the acts an evidence record records.
 *
 * Every record version is refused a money hazard: a bare `unit_price` or
 * `total`, or a pinned amount that is present but not an integer. An older
 * `record_version` label therefore cannot get one past the check. From `"0.5"`
 * the whole of Section 7.2's line-item rule applies, through the same shared
 * check as the offer path and TransactionRecord verification. The cases are in
 * `session-evidence-record-line-items.json`, and the Python suite reads the
 * same bytes.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { privateKeyFromJwk } from "../src/a2cn/crypto.js";
import {
  LINE_ITEM_RULE_FULL_FROM,
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
} from "../src/a2cn/evidence.js";
import { termsLineItemViolation } from "../src/a2cn/line_items.js";
import type { Dict } from "../src/a2cn/messages.js";
import { Session } from "../src/a2cn/session.js";
import { SPEC_DIR } from "./support/paths.js";

function readVector(name: string): Dict {
  return JSON.parse(readFileSync(join(SPEC_DIR, "test-vectors", name), "utf-8")) as Dict;
}

const VECTOR = readVector("session-evidence-record-line-items.json");
const PARITY = readVector("session-evidence-record-parity.json");
const CASES = VECTOR.cases as Dict[];
const DIDS = VECTOR.did_documents as Record<string, Dict>;

for (const c of CASES) {
  test(`the record reaches the stated verdict: ${c.name}`, () => {
    expect((c.record as Dict).record_version).toBe(c.record_version);
    expect(verifySessionEvidenceRecord(c.record as Dict, DIDS)).toBe(c.verifies);
  });

  test(`the verdict is the shared check's: ${c.name}`, () => {
    // Before 0.5 the shared check runs for the money hazards only; from 0.5 in full.
    const acts = (c.record as Dict).acts as Dict[];
    const terms = (acts[1].act as Dict).terms;
    const hazardsOnly = c.record_version !== LINE_ITEM_RULE_FULL_FROM;
    expect(termsLineItemViolation(terms, { hazardsOnly }) === null).toBe(c.verifies);
  });
}

test("both sides of the version split are covered", () => {
  // A pre-0.5 record missing total_minor verifies; a 0.5 one does not.
  const verdicts = Object.fromEntries(CASES.map((c) => [c.name, c.verifies]));
  expect(verdicts.pre_0_5_missing_total_minor).toBe(true);
  expect(verdicts.missing_total_minor).toBe(false);
  expect(verdicts.pre_0_5_bare_names).toBe(false);
});

function generate(lineItems: unknown): Dict {
  const source = PARITY.session as Dict;
  const producer = PARITY.producer as Dict;
  const session = new Session({
    session_id: source.session_id as string,
    state: source.state as string,
    current_turn: "none",
    terminal_reason: source.terminal_reason as string,
    terminal_message_id: source.terminal_message_id as null,
    session_created_at: source.session_created_at as string,
    state_updated_at: source.state_updated_at as string,
    session_params: source.session_params as Dict,
    initiator_mandate: source.initiator_mandate as Dict,
    responder_mandate: source.responder_mandate as Dict,
    _session_init: source.session_init as Dict,
    _session_ack: source.session_ack as Dict,
    _message_log: source.message_log as Dict[],
  });
  const observed = structuredClone(PARITY.observed_acts) as Dict[];
  const withTerms = observed
    .map((item) => item.act as Dict)
    .filter((act) => typeof act.terms === "object" && act.terms !== null);
  expect(withTerms.length).toBeGreaterThan(0);
  (withTerms[0].terms as Dict).line_items = lineItems;
  return generateSessionEvidenceRecord(session, {
    producerPrivateKey: privateKeyFromJwk(PARITY.producer_private_jwk as Dict),
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs: observed,
  });
}

test("the generator seals a record whose line items hold", () => {
  const record = generate([{ quantity: 1, unit_price_minor: 9000, total_minor: 9000 }]);
  expect(record.record_version).toBe(LINE_ITEM_RULE_FULL_FROM);
  expect(verifySessionEvidenceRecord(record, PARITY.did_documents as Record<string, Dict>)).toBe(
    true,
  );
});

for (const [name, lineItems] of [
  ["bare_names", [{ quantity: 1, unit_price: 90.0, total: 90.0 }]],
  ["missing_total_minor", [{ quantity: 1, unit_price_minor: 9000 }]],
] as const) {
  test(`the generator refuses to seal what the verifier would reject: ${name}`, () => {
    expect(() => generate(lineItems)).toThrow("line_items");
  });
}
