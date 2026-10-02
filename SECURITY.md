# Security Policy

## Supported Versions

A2CN is pre-1.0 and evolving. Security fixes are applied to the latest released
version and the `main` branch only; earlier tags are not maintained.

| Version | Supported |
|---|---|
| `main` / latest release | :white_check_mark: |
| Older tags (< latest) | :x: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Report privately through either channel:

1. **GitHub private vulnerability reporting (preferred).** Open the repository's
   **Security** tab and choose **Report a vulnerability**. This keeps the report
   private to the maintainers and lets us collaborate on a fix and advisory.
2. **Email.** Send details to **security@a2cn.io**. If you would like to encrypt
   your report, say so in a first (non-sensitive) message and we will share a key.

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
