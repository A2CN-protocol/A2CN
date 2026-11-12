# a2cn

The Python reference implementation of [A2CN](https://a2cn.io), the open
protocol for agent-to-agent B2B commercial negotiation: signed offers,
counteroffers and acceptances between two parties' agents, and a transaction
record that both sides can verify on their own.

- Specification: [spec/](https://github.com/A2CN-protocol/A2CN/tree/main/spec)
- Source: [reference-implementation/python](https://github.com/A2CN-protocol/A2CN/tree/main/reference-implementation/python)
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
pip install a2cn
```

Requires Python 3.11 or later.

```python
import a2cn

print(a2cn.__version__, a2cn.PROTOCOL_VERSIONS)
```

The library lives in the `a2cn` package's modules: `a2cn.client` and
`a2cn.server` for the HTTP client and server, `a2cn.record` and
`a2cn.evidence` for the transaction and evidence records, `a2cn.crypto` for
signing and verification, and `a2cn.did` for DID resolution. The
[repository README](https://github.com/A2CN-protocol/A2CN/blob/main/reference-implementation/python/README.md)
walks through the demos and the architecture.

## Verify a record

Installing the package installs `a2cn-verify`. Put a deal's TransactionRecord
and its session's evidence record in one folder, and point the verifier at it:

```bash
a2cn-verify deal/                 # or: python -m a2cn.verify deal/
a2cn-verify deal/ --offline       # fetch nothing; use DID documents saved in the folder
```

It verifies each record with the library's own checks and fetches the parties'
DID documents from their sites (a did:web DID is its own address). For every
record it prints `VERIFIED`, `REFUSED:` with the reason, or `COULD NOT FINISH`
with what is missing. Exit status: 0 everything verified, 1 something was
refused, 3 nothing was refused but something could not finish, 2 bad usage.
`a2cn-verify --help` lists every option.

## MCP server

The MCP server (`mcp_server.py`) is not part of this package. Run it from a
source checkout with the `mcp` extra:

```bash
git clone https://github.com/A2CN-protocol/A2CN.git
cd A2CN/reference-implementation/python
pip install -e '.[mcp]'
python mcp_server.py
```

## Questions, bugs and security

- **Questions and ideas** go in
  [GitHub Discussions](https://github.com/A2CN-protocol/A2CN/discussions).
- **Bugs** go in [GitHub Issues](https://github.com/A2CN-protocol/A2CN/issues).
  Include the package version (`a2cn.__version__`), your Python version, and how
  you installed the package (from PyPI or from a source checkout).
- **Security vulnerabilities** never go in a public issue. Report them
  privately, as [SECURITY.md](https://github.com/A2CN-protocol/A2CN/blob/main/SECURITY.md)
  describes.

## License

Apache-2.0. See [LICENSE](https://github.com/A2CN-protocol/A2CN/blob/main/LICENSE).
