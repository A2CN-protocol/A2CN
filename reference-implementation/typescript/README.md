# @a2cn/a2cn (TypeScript)

The TypeScript reference implementation of [A2CN](https://a2cn.io), the open
protocol for agent-to-agent B2B commercial negotiation: signed offers,
counteroffers and acceptances between two parties' agents, and a transaction
record that both sides can verify on their own. It is a port of the
[Python reference implementation](https://github.com/A2CN-protocol/A2CN/tree/main/reference-implementation/python),
held to it by shared test vectors.

- Specification: [spec/](https://github.com/A2CN-protocol/A2CN/tree/main/spec)
- Source: [reference-implementation/typescript](https://github.com/A2CN-protocol/A2CN/tree/main/reference-implementation/typescript)
- Changelog: [CHANGELOG.md](https://github.com/A2CN-protocol/A2CN/blob/main/CHANGELOG.md)
- Security policy: [SECURITY.md](https://github.com/A2CN-protocol/A2CN/blob/main/SECURITY.md)

**Status:** pre-1.0, and the specification is a draft. A minor (0.x) release
may change the API, the wire protocol or a record format; the
[CHANGELOG](https://github.com/A2CN-protocol/A2CN/blob/main/CHANGELOG.md) says
what changed. Security fixes go to the latest 0.3.x release, as the
[security policy](https://github.com/A2CN-protocol/A2CN/blob/main/SECURITY.md)
describes.

## Install

```bash
npm install @a2cn/a2cn
```

The package is ESM only and needs Node.js 20.18.1 or later. Running this
repository's test suite needs Node.js 22.12 or later.

## Use

Everything is exported from the package root, with its types:

```ts
import { PROTOCOL_VERSIONS, generateKeypair, hashObject, signJws, verifyJws } from "@a2cn/a2cn";

console.log(PROTOCOL_VERSIONS.wire);

// Sign the JCS-canonical SHA-256 hash of a value, then verify the signature.
const { privateKey, publicKey } = generateKeypair(); // ES256
const digest = hashObject({ total_minor: 10500000, currency: "USD" });
const token = signJws(digest, privateKey);
console.log(verifyJws(token, publicKey) === digest); // true
```

The exports include the negotiation session state machine, the HTTP client
(`A2CNClient`) and server, transaction and evidence records with their
verifiers (`verifyTransactionRecordReason`, `assessSessionEvidenceRecord`), and
did:web resolution.

The `a2cn-verify` command-line verifier is in the Python package only, for now.

## From source

The MCP server (`src/mcp_server.ts`), the platform adapters and the UBL export
are not part of the package; they run from a source checkout. The MCP server
needs `@modelcontextprotocol/sdk` and `zod`, which are optional peer
dependencies of the package and development dependencies of the checkout.

```bash
git clone https://github.com/A2CN-protocol/A2CN.git
cd A2CN/reference-implementation/typescript
npm ci
npm test
npx tsx src/mcp_server.ts
```

## Questions, bugs and security

- **Questions and ideas** go in
  [GitHub Discussions](https://github.com/A2CN-protocol/A2CN/discussions).
- **Bugs** go in [GitHub Issues](https://github.com/A2CN-protocol/A2CN/issues).
  Include the package version (from `npm ls @a2cn/a2cn`), your Node.js version, and how
  you installed the package (from npm or from a source checkout).
- **Security vulnerabilities** never go in a public issue. Report them
  privately, as [SECURITY.md](https://github.com/A2CN-protocol/A2CN/blob/main/SECURITY.md)
  describes.

## License

Apache-2.0. See [LICENSE](https://github.com/A2CN-protocol/A2CN/blob/main/LICENSE).
