# A2CN Threat Model

A2CN is a protocol for agent-to-agent negotiation built on signed acts, declared/verified
authority (mandates), deterministic records, and standalone verification. This document states
what the protocol is designed to defend against, what it does **not** establish on its own, and
the assumptions a verifier relies on. It complements the Security Considerations in the
specification (`a2cn-spec-v0.2.0.md` §13) and the reporting process in
[`SECURITY.md`](../SECURITY.md).

A2CN is **pre-1.0 and the specification is a draft** — it is not a "stable" or certified
standard, and it has **not** undergone an external security audit.

## What A2CN is designed to defend against

- **Forged protocol identities and signatures.** Each protocol act is signed over a canonical
  object (RFC 8785 JCS + SHA-256, ES256 or EdDSA JWS) and verified by rebuild against the key the
  signer's DID resolves to (§7.3.1, §7.3.1.1). A relabelled or mutated act fails the rebuild.
- **Unauthorized or malformed authority claims (within the protocol model).** Each party
  states its authority in a mandate that is checked at session initiation (§5), and the
  `max_commitment_value` ceiling is enforced on every offer, counteroffer and acceptance that
  carries a total value (§13.5). See *Current limitations* for what the reference
  implementations do not yet check.
- **Record tampering.** TransactionRecords and SessionEvidenceRecords are canonical and
  recomputable from their own fields; agreed terms are bound to the signed final offer, so any
  change to the record breaks the hash and the signatures over it (§9.5, §9A.6).
- **Ambiguous money amounts.** Line-item money is stated as integer minor units under pinned keys
  (§7.2), and record verification refuses bare `unit_price` / `total` keys and fractional amounts
  at every record version (§9.5, §9A.6), so a verified record cannot be read at 100× or 1/100 of
  its intended value.
- **Replay and stale messages.** Pre-session anti-replay and per-session sequence numbering, plus
  per-offer expiry, bound what a captured message can do (§6.2, §13.1).
- **Resource exhaustion through DID resolution.** Resolving a did:web document follows no
  redirects, refuses compressed documents and documents over 64 KiB, and must finish within five
  seconds, so an attacker-hosted DID document cannot exhaust a server's memory or time (§14.1).
- **Mandate-cap bypass (within implemented checks).** The commitment ceiling is enforced before an
  act binds (§13.5), and an act that crosses the mandate's human-approval threshold is held in
  `AWAITING_HUMAN_APPROVAL` rather than sent (§8.2–§8.4). The hold is released only by an
  ApprovalReceipt signed by an approver the mandate authorizes, who is never the paused party; the
  receipt must name the paused party, reference the session and the mandate, be unexpired, and not
  have released a pause before (§14.1).
- **Session-state and message-order violations.** The session state machine refuses acts that are
  out of order or of the wrong type for the current state (§8, §13).
- **False attribution of unsigned observations as signed counterparty acts.** A
  SessionEvidenceRecord marks every act as either a verified signature or an unsigned observation,
  and a producer-sealed evidence package never presents an unsigned observation as a
  counterparty's signed act; an external-channel completion carries an external commitment
  reference rather than a reconstructed bilateral record, and it cannot attest an in-band
  acceptance of terms the responder signed, however the acceptance refers to them (§9A, §9A.12).

## What A2CN does not establish by itself

- the semantic truth of negotiated representations;
- legal enforceability, or every off-chain condition of authority;
- the correctness of any party's proprietary pricing or negotiation strategy;
- endpoint, host, or network security outside the protocol;
- the integrity of DID or external identity infrastructure it depends on;
- the security of a counterparty that does not participate in A2CN signing;
- regulatory compliance merely because an A2CN artifact exists.

## Current limitations

The reference implementations do not yet perform every check the specification defines:

- A mandate's validity, such as its `valid_until`, is checked only when a session is
  established. It is not re-checked on later acts or at commit.
- Only declared mandates (§5.3) are supported. DID verifiable-credential mandates (§5.4, §5.5)
  are not verified, so the reference servers refuse them with `MANDATE_INVALID` and advertise
  conformance level 1 (declared mandates only).

The conformance fixtures in `spec/conformance-fixtures/` mark scenarios like these `known_gap`.

## Trust assumptions

Verification of A2CN artifacts assumes:

- functioning key / DID resolution for the signatures being verified (§4.2, §7.3.1.1);
- secure private-key custody by each participant;
- a correct canonicalization and hash implementation (RFC 8785 JCS + SHA-256, including correct
  Unicode member-name ordering);
- application-layer policy for any condition that lies outside the protocol;
- a clear distinction, by the consumer, between a producer-sealed evidence package and
  independently signed counterparty acts (§9A).

## Security history

Release `0.3.1` fixed four vulnerabilities in the reference implementations, one of them reported
privately by an external researcher. Each is published as a security advisory:
[GHSA-cmmg-mjjm-9gxx](https://github.com/A2CN-protocol/A2CN/security/advisories/GHSA-cmmg-mjjm-9gxx),
[GHSA-wv53-524j-vfvp](https://github.com/A2CN-protocol/A2CN/security/advisories/GHSA-wv53-524j-vfvp),
[GHSA-rv7j-fccv-8hmx](https://github.com/A2CN-protocol/A2CN/security/advisories/GHSA-rv7j-fccv-8hmx) and
[GHSA-mxw6-x285-g972](https://github.com/A2CN-protocol/A2CN/security/advisories/GHSA-mxw6-x285-g972).
Internal review during development found and fixed other issues before release. A2CN has **not** had an external security audit or certification, and the
protocol and specification remain a draft (pre-1.0). Please report suspected vulnerabilities as
described in [`SECURITY.md`](../SECURITY.md).
