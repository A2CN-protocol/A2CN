/** Static checks for shared conformance fixture catalog. */

import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { basename, dirname, join } from "node:path";
import { expect, test } from "vitest";

const FIXTURE_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "spec",
  "conformance-fixtures",
);

const EXPECTED_FIXTURES = new Set([
  "expired_mandate_on_offer_reference",
  "hitl_threshold_crossing",
  "counterparty_outside_allowed_list",
  "payment_terms_drift_mid_negotiation",
  "partial_acceptance_unresolved_constraint",
  "reputation_score_cannot_expand_authority",
]);

function fixtureJsonFiles(): string[] {
  return readdirSync(FIXTURE_DIR).filter((name) => name.endsWith(".json"));
}

test("conformance fixture catalog complete", () => {
  const fixtureIds = new Set(fixtureJsonFiles().map((name) => basename(name, ".json")));

  expect(fixtureIds).toEqual(EXPECTED_FIXTURES);
});

test("conformance fixtures have required shape", () => {
  for (const name of fixtureJsonFiles()) {
    const fixture = JSON.parse(readFileSync(join(FIXTURE_DIR, name), "utf-8"));

    expect(fixture.id).toBe(basename(name, ".json"));
    expect(["active", "known_gap"]).toContain(fixture.status);
    expect(fixture.summary).toBeTruthy();
    expect(typeof fixture.given).toBe("object");
    expect(typeof fixture.expect).toBe("object");
    expect("accepted" in fixture.expect).toBe(true);
  }
});
