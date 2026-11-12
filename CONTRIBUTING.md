# Contributing to A2CN

We welcome contributions to the specification, reference implementation, and SDK.

## Where to raise things

- **Questions, ideas, and spec feedback** → GitHub Discussions.
- **Bugs and concrete spec/implementation defects** → GitHub Issues.
- **Security vulnerabilities** → see [SECURITY.md](SECURITY.md). Please do **not** open
  a public issue or discussion for a vulnerability.

## Ways to contribute

- Review and comment on the specification
- Implement the protocol in additional languages
- Build integrations with agent frameworks (LangChain, CrewAI, Google ADK)
- Report issues with the spec or implementation
- Share examples of the cross-platform agent negotiation problem

## Process

1. Open an issue to discuss significant changes before implementing
2. Fork the repository and create a branch
3. Submit a pull request with a clear description
4. CI runs on every pull request. Its gate is the two test suites (Python and TypeScript), `tsc --noEmit` and the dependency audits; there is no linter or formatter, by choice.

All contributors must agree to the Apache 2.0 license terms.
