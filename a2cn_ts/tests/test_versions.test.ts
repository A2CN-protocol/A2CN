/**
 * The versions matrix, the package version, and the README table agree.
 *
 * PROTOCOL_VERSIONS must be read from the modules that own each constant, and
 * the top-level README's "Versions implemented" table must state the same
 * values. Either drifting fails here rather than in a release.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS,
  SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
} from "../src/a2cn/evidence.js";
import { PROTOCOL_ACT_VERSION } from "../src/a2cn/messages.js";
import {
  ACCEPTED_TRANSACTION_RECORD_VERSIONS,
  KNOWN_TRANSACTION_RECORD_VERSIONS,
} from "../src/a2cn/record.js";
import { PROTOCOL_VERSIONS } from "../src/a2cn/versions.js";

const TS_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = join(TS_ROOT, "..");

// README row label -> the matrix value that row states.
const README_ROWS: Record<string, readonly string[]> = {
  "Wire protocol": [PROTOCOL_VERSIONS.wire],
  "TransactionRecord — emits": [PROTOCOL_VERSIONS.transaction_record.emits],
  "TransactionRecord — verifies": PROTOCOL_VERSIONS.transaction_record.accepts,
  "TransactionRecord — known shapes": PROTOCOL_VERSIONS.transaction_record.recognizes,
  "SessionEvidenceRecord — emits": [PROTOCOL_VERSIONS.session_evidence_record.emits],
  "SessionEvidenceRecord — verifies": PROTOCOL_VERSIONS.session_evidence_record.recognizes,
};

function readmeTable(): Map<string, string[]> {
  const text = readFileSync(join(REPO_ROOT, "README.md"), "utf-8");
  const block = /<!-- versions-table:start -->([\s\S]*?)<!-- versions-table:end -->/.exec(text);
  expect(block, "README.md has no versions table between its markers").not.toBeNull();
  const rows = new Map<string, string[]>();
  for (const line of block![1].trim().split("\n").slice(2)) {
    const [label, value] = line.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
    rows.set(label, [...value.matchAll(/`([^`]+)`/g)].map((m) => m[1]));
  }
  return rows;
}

function pyprojectVersion(): string {
  const text = readFileSync(join(REPO_ROOT, "reference-implementation", "python", "pyproject.toml"), "utf-8");
  return /^\[project\][\s\S]*?^version\s*=\s*"([^"]+)"/m.exec(text)![1];
}

describe("versions matrix", () => {
  it("is derived from the module constants", () => {
    expect(PROTOCOL_VERSIONS).toEqual({
      wire: PROTOCOL_ACT_VERSION,
      transaction_record: {
        emits: ACCEPTED_TRANSACTION_RECORD_VERSIONS[ACCEPTED_TRANSACTION_RECORD_VERSIONS.length - 1],
        accepts: [...ACCEPTED_TRANSACTION_RECORD_VERSIONS],
        recognizes: [...KNOWN_TRANSACTION_RECORD_VERSIONS],
      },
      session_evidence_record: {
        emits: SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
        recognizes: [...RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS],
      },
    });
  });

  it("retypes no version in versions.ts", () => {
    // A literal in versions.ts would be a second source that can fall out of
    // step with the module that owns the constant.
    const source = readFileSync(join(TS_ROOT, "src", "a2cn", "versions.ts"), "utf-8");
    expect(source.match(/["']\d+\.\d+(?:\.\d+)?["']/g)).toBeNull();
  });

  it("is stated by the README table", () => {
    const rows = readmeTable();
    for (const [label, expected] of Object.entries(README_ROWS)) {
      expect(rows.get(label), label).toEqual([...expected]);
    }
  });

  it("README table states the package and spec versions", () => {
    const rows = readmeTable();
    const pkg = JSON.parse(readFileSync(join(TS_ROOT, "package.json"), "utf-8"));
    expect(rows.get("TypeScript package `a2cn`")).toEqual([pkg.version]);
    expect(rows.get("Python package `a2cn`")).toEqual([pyprojectVersion()]);
    const spec = rows.get("Specification document");
    expect(spec).toHaveLength(1);
    expect(existsSync(join(REPO_ROOT, "spec", `a2cn-spec-v${spec![0]}.md`))).toBe(true);
  });

  it("README table has no unchecked row", () => {
    const checked = new Set([
      ...Object.keys(README_ROWS),
      "Python package `a2cn`",
      "TypeScript package `a2cn`",
      "Specification document",
    ]);
    expect(new Set(readmeTable().keys())).toEqual(checked);
  });
});
