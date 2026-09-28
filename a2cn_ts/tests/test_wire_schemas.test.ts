/**
 * The wire message schemas: one file per wire version, never rewritten (Section 17).
 *
 * A message schema's $id carries the wire version it describes. When the wire
 * version moved to "0.3", each message schema already published for "0.2"
 * stayed exactly as published, and the "0.3" schema was published beside it as
 * <name>-0.3.schema.json. The published files are pinned by digest, so a later
 * edit to one of them fails here rather than silently changing what a "0.2"
 * message is checked against. Acceptance, rejection and withdrawal were first
 * published at "0.3", so each has one unversioned file.
 *
 * The Python suite runs the same checks.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { PROTOCOL_ACT_VERSION, type Dict } from "../src/a2cn/messages.js";

const SCHEMAS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "spec", "schemas");

// sha256 of each message schema file as it was published for wire version "0.2".
const PUBLISHED_0_2_SHA256: Record<string, string> = {
  offer: "c1be4ae82e61ea25bc3127fdbc6ef37e44da191840df06661bf459ea3d801f8a",
  "session-invitation": "1564d8c59c48fef91435a576f9ea6fd939ba69370e6314265a50d91421eed87c",
  delivery_notice: "26259aa0b6d286a52760b9c91a5a85c384f763993e00aec368cdb638dbc9d6d6",
  delivery_acknowledged: "b4aceb0522b14ef43949dc7e1707babfbee65cae4547d0680f20d199c50a8f02",
  dispute_notice: "a723cb94d5f55f3d2bcafc03a9a76b8c548b4d678f324c9af3a5db3c9a563c73",
  dispute_resolved: "1a7d7692a7e8c33be17af257fa648f9f3f588c0a51f2f8b44a293293d5425776",
  "invitation-acceptance": "ba5e4682c27c4d227aa9f54530d7aae3c1cb9b252d1043085a06682b064d062d",
  "invitation-decline": "183f9ffa91bab0740ba2bf129ed548187835f79bb011914e4e81713e0f853ee8",
  "terms/saas_renewal": "c0e1584eae9714a9c183f8dded44b0d5ad6f296870e452d2f2912ca740ff5f27",
  "terms/goods_procurement": "21512ae3bfe5969f54b7f0eb2571bad2e09d7061ba39bfc2bfb1534c661c78b8",
};
const FIRST_PUBLISHED_AT_0_3 = ["acceptance", "rejection", "withdrawal"];

function path(name: string): string {
  return join(SCHEMAS, `${name}.schema.json`);
}

function load(name: string): Dict {
  return JSON.parse(readFileSync(path(name), "utf-8")) as Dict;
}

for (const name of Object.keys(PUBLISHED_0_2_SHA256).sort()) {
  test(`a published 0.2 message schema is unchanged: ${name}`, () => {
    const digest = createHash("sha256").update(readFileSync(path(name))).digest("hex");

    expect(digest).toBe(PUBLISHED_0_2_SHA256[name]);
    expect((load(name).$id as string).endsWith("/0.2")).toBe(true);
  });

  test(`the 0.3 schema differs from its 0.2 file only in the version: ${name}`, () => {
    const current = load(`${name}-0.3`);
    const published = structuredClone(load(name));

    const expectedId = (published.$id as string).slice(0, -"0.2".length) + PROTOCOL_ACT_VERSION;
    expect(current.$id).toBe(expectedId);
    published.$id = current.$id;
    if (name === "session-invitation") {
      const properties = current.properties as Dict;
      expect((properties.a2cn_version as Dict).const).toBe(PROTOCOL_ACT_VERSION);
      ((published.properties as Dict).a2cn_version as Dict).const = PROTOCOL_ACT_VERSION;
    }
    expect(current).toEqual(published);
  });
}

for (const name of FIRST_PUBLISHED_AT_0_3) {
  test(`a schema first published at 0.3 states the wire version: ${name}`, () => {
    expect(load(name).$id).toBe(`https://a2cn.dev/schemas/${name}/${PROTOCOL_ACT_VERSION}`);
    expect(existsSync(path(`${name}-0.3`))).toBe(false);
  });
}
