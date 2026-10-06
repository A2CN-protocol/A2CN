# Security Policy

## Supported Versions

A2CN is pre-1.0 and the protocol specification is a **draft** — not a "stable" or certified
standard. Security fixes are applied to the current release line of the reference packages and to
`main`; older releases are not maintained.

| Component | Supported |
|---|---|
| `a2cn` packages (Python + TypeScript), current `0.3.x` line + `main` | :white_check_mark: |
| Releases before the current `0.3.x` line | :x: |

The per-artifact protocol versions a release implements — the wire act protocol, TransactionRecord,
SessionEvidenceRecord, and the specification document — are listed in the version matrix in the
[README](README.md#versions-implemented) and are single-sourced from `a2cn.PROTOCOL_VERSIONS`. (The specification
document is `0.2.0`, draft; the wire protocol is `0.3` as of release `0.3.0` and is not compatible
with `0.2`.)

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Report privately through either channel:

1. **GitHub private vulnerability reporting (preferred).** Open the repository's
   **Security** tab and choose **Report a vulnerability**. This keeps the report
   private to the maintainers and lets us collaborate on a fix and advisory.
2. **Email.** Send details to **security@a2cn.io**.

Please include, where you can:

- the affected component — the spec section, or the `reference-implementation` /
  SDK package with its version or commit;
- a description of the issue and its security impact; and
- steps to reproduce or a proof of concept.

## What to Expect

A2CN is a community project maintained on a best-effort basis.

- **Acknowledgement** of your report within **3 business days**.
- An **initial assessment** within **10 business days**.
- We will keep you updated as we investigate, tell you when a fix ships, and — with
  your permission — credit you for the report.

## Coordinated Disclosure

We follow coordinated disclosure. Please give us a reasonable window to investigate
and release a fix (we aim for **90 days, or until a fix ships, whichever is sooner**)
before disclosing publicly. We are happy to agree timing with you.

## Scope

See the [threat model](spec/THREAT_MODEL.md) for what A2CN is and is not designed to defend against.

**In scope:** the A2CN specification, the reference implementation, and the SDKs in
this repository.

**Out of scope:** third-party integrations or adapters not maintained here; the demo
and website infrastructure; and reports without a demonstrated security impact (for
example theoretical weaknesses, or missing hardening headers on static pages).
Questions about the *design* of the protocol are not vulnerabilities — please raise
those as a normal issue or discussion.

## Safe Harbor

We support good-faith security research. If you make a good-faith effort to follow
this policy, we will consider your research authorized, work with you to resolve the
issue quickly, and will not pursue or support legal action against you. Please avoid
privacy violations, data destruction, and any disruption of services during your
research.
