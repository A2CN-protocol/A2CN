/**
 * Where the tests find the repository root and the shared spec/ directory.
 *
 * The TypeScript package lives at reference-implementation/typescript/, and
 * every test that reads a shared vector, schema or fixture resolves it from
 * here, so the package's depth below the repository root is stated once.
 */

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// tests/support -> tests -> typescript (the package root)
export const TS_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// typescript -> reference-implementation -> the repository root
export const REPO_ROOT = join(TS_ROOT, "..", "..");
export const SPEC_DIR = join(REPO_ROOT, "spec");

if (!existsSync(SPEC_DIR)) {
  // Fail loudly rather than let every vector test report a missing file.
  throw new Error(`tests/support/paths.ts: no spec/ directory at ${REPO_ROOT}`);
}
