// Smoke-test a packed a2cn tarball in a fresh project outside the repository.
//
//     node scripts/smoke_pack.mjs a2cn-X.Y.Z.tgz [--workdir DIR]
//
// The tarball must hold only package.json, README.md, LICENSE and the built
// dist/index and dist/a2cn/* (.js and .d.ts), as the wheel smoke test checks
// what the wheel installs. It is then installed into an empty npm project, with TypeScript and
// @types/node beside it. The usage example in README.md is copied out
// verbatim, type-checked against the package's declarations, compiled and run,
// and must print the wire version and then `true`. The package must resolve
// from the project's node_modules; its internals must not be importable past
// the `exports` map; the optional MCP peer dependencies must not be installed;
// and its version must be package.json's. Exits non-zero, naming the failed
// check, on the first failure.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const TS_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = resolve(TS_ROOT, "..", "..");

function fail(message) {
  console.error(`smoke: FAILED: ${message}`);
  process.exit(1);
}

function check(condition, message) {
  if (!condition) fail(message);
}

function inside(child, parent) {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function run(command, args, cwd) {
  try {
    return execFileSync(command, args, { cwd, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    fail(`${command} ${args.join(" ")} exited ${error.status}:\n${error.stdout ?? ""}${error.stderr ?? ""}`);
  }
}

const argv = process.argv.slice(2);
const workdirFlag = argv.indexOf("--workdir");
let base = tmpdir();
if (workdirFlag !== -1) {
  base = resolve(argv[workdirFlag + 1]);
  argv.splice(workdirFlag, 2);
  mkdirSync(base, { recursive: true });
}
if (argv.length !== 1) {
  console.error("usage: node scripts/smoke_pack.mjs a2cn-X.Y.Z.tgz [--workdir DIR]");
  process.exit(2);
}
const tarball = resolve(argv[0]);
const project = realpathSync(mkdtempSync(join(base, "a2cn-pack-smoke-")));
if (inside(project, REPO_ROOT)) {
  console.error(`smoke: the work directory ${project} is inside the repository`);
  process.exit(2);
}

// The tarball holds the manifest, the README, the licence and the build of
// src/index.ts and src/a2cn, and nothing else.
const ALLOWED = [
  /^package\.json$/,
  /^README\.md$/,
  /^LICENSE$/,
  /^dist\/index\.(js|d\.ts)$/,
  /^dist\/a2cn\/[A-Za-z0-9_]+\.(js|d\.ts)$/,
];
const entries = run("tar", ["-tzf", tarball], base)
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line && !line.endsWith("/"));
check(entries.length > 0, `${tarball} lists no files`);
const unexpected = entries
  .map((entry) => entry.replace(/^package\//, ""))
  .filter((path) => !ALLOWED.some((pattern) => pattern.test(path)));
check(unexpected.length === 0, `the tarball holds unexpected files: ${unexpected.join(", ")}`);
check(entries.includes("package/dist/index.js"), "the tarball has no dist/index.js");

const expectedVersion = JSON.parse(readFileSync(join(TS_ROOT, "package.json"), "utf-8")).version;
const readme = readFileSync(join(TS_ROOT, "README.md"), "utf-8");
const example = readme.split("\n## Use\n")[1]?.match(/```ts\n([\s\S]*?)```/)?.[1];
check(example !== undefined, "README.md has no ```ts example under \"## Use\"");

writeFileSync(join(project, "package.json"), JSON.stringify({ name: "a2cn-smoke", private: true, type: "module" }));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
run(npm, ["install", "--no-audit", "--no-fund", "--loglevel=error", tarball, "typescript@5", "@types/node@22"], project);

// Where "a2cn" resolves, its version, the exports boundary and the optional peers.
const probe = `
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const url = import.meta.resolve("a2cn");
const pkgUrl = import.meta.resolve("a2cn/package.json");
let deep = "not importable";
try { await import("a2cn/dist/a2cn/client.js"); deep = "importable"; } catch {}
const peers = {};
for (const name of ["@modelcontextprotocol/sdk", "zod"]) {
  try { createRequire(import.meta.url).resolve(name + "/package.json"); peers[name] = true; } catch { peers[name] = false; }
}
console.log(JSON.stringify({ url, version: JSON.parse(readFileSync(new URL(pkgUrl), "utf-8")).version, deep, peers }));
`;
writeFileSync(join(project, "probe.mjs"), probe);
const facts = JSON.parse(run(process.execPath, ["probe.mjs"], project));
const resolved = realpathSync(fileURLToPath(facts.url));
check(inside(resolved, join(project, "node_modules", "a2cn")), `"a2cn" resolved to ${resolved}, outside the project`);
check(facts.version === expectedVersion, `the installed version is ${facts.version}, package.json says ${expectedVersion}`);
check(facts.deep === "not importable", "a2cn/dist/a2cn/client.js is importable past the exports map");
for (const [name, present] of Object.entries(facts.peers)) {
  check(!present, `the optional peer dependency ${name} was installed`);
}

// The README example: type-checked against the shipped declarations, then run.
writeFileSync(join(project, "example.ts"), example);
writeFileSync(
  join(project, "tsconfig.json"),
  JSON.stringify({
    compilerOptions: {
      target: "ES2022",
      module: "NodeNext",
      moduleResolution: "NodeNext",
      strict: true,
      types: ["node"],
      outDir: "out",
    },
    files: ["example.ts"],
  }),
);
run(process.execPath, [join(project, "node_modules", "typescript", "bin", "tsc"), "-p", "tsconfig.json"], project);
const lines = run(process.execPath, [join("out", "example.js")], project).trim().split("\n");
check(lines.length === 2, `the README example printed ${JSON.stringify(lines)}`);
check(/^\d+\.\d+$/.test(lines[0]), `the README example printed the wire version ${JSON.stringify(lines[0])}`);
check(lines[1] === "true", `the README example's signature did not verify: ${JSON.stringify(lines[1])}`);

console.log(`smoke: ${tarball.split(/[\\/]/).pop()} passed (${resolved})`);
