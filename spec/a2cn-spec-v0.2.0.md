# A2CN Protocol Specification

**Version:** 0.2.0  
**Status:** Draft — Not for production use  
**Date:** 2026-03-26  
**Previous version:** 0.1.3  
**License:** Apache 2.0  
**Repository:** https://github.com/a2cn/a2cn  
**Schemas:** https://github.com/a2cn/a2cn/tree/main/spec/schemas

---

## Abstract

The Agent-to-Agent Commercial Negotiation Protocol (A2CN) defines a minimal open
standard for bilateral commercial negotiation between autonomous AI agents representing
different organizations with competing interests. A2CN covers the specific protocol
layer — offer exchange, mandate verification, session lifecycle, and transaction
records — that no existing agent protocol addresses.

A2CN is designed to be complementary to MCP (agent-to-tool), A2A (agent
communication), and AP2 (payment execution). It occupies the layer between "agents
are talking" and "payment is authorized."

---

## Status of This Document

This is a **draft specification** published to solicit feedback from implementers,
procurement platform developers, and the agent framework community. It is not
suitable for production use.

**Version note:** The specification document version (0.1.3) tracks editorial
revisions. The wire protocol version (`protocol_version` and `a2cn_version` fields)
remains `"0.1"` for all 0.1.x specification revisions. A change to `"0.2"` will
indicate a wire-incompatible protocol change.

Normative JSON Schemas for all message types are published alongside this specification
at `spec/schemas/` in the repository. The schemas are **normative** as of v0.1.2.

Feedback should be submitted as GitHub issues at
https://github.com/a2cn/a2cn/issues.

The `/.well-known/a2cn-agent` well-known URI is intended for registration with IANA
per RFC 8615. Registration will be submitted concurrent with the v0.2 release.

---

## Table of Contents

1. Introduction
2. Terminology and Conventions
3. Protocol Overview
4. Component 1: Discovery
5. Component 2: Mandate Declaration and Verification
6. Component 3: Session Initiation
7. Component 4: Offer Exchange
8. Component 5: Session State Machine
9. Component 6: Transaction Record
10. Component 7: Audit Log
11. Component 8: Session Invitation *(new in v0.2)*
12. Transport Binding
13. Error Handling
14. Security Considerations
15. Open Questions
16. Relationship to Other Protocols
17. Conformance
18. Normative JSON Schemas
19. Changelog

---

## 1. Introduction

### 1.1 Background

Autonomous AI agents are being deployed by enterprises to negotiate, procure, and
commit to commercial terms at scale. Buyer-side platforms — Pactum, Fairmarkit,
Zip, Arkestro — are in production use across Global 2000 companies. Seller-side
infrastructure is emerging rapidly: Salesforce Revenue Cloud's Agentforce for
Revenue generates quotes from natural language; Microsoft Dynamics 365's ERP MCP
Server (GA February 2026) exposes pricing and order logic to any MCP-compatible
agent; Luminance's Autonomous Negotiation handles contract language bilaterally.
Every major enterprise software vendor — SAP, Salesforce, Oracle, Coupa — has
shipped APIs and agent capabilities that participate in commercial workflows.

The buyer-side platforms have reached a specific architectural limit. Platforms such
as Fairmarkit and Pactum conduct negotiations by sending email invitations to human
supplier representatives. When a supplier deploys their own autonomous agent, this
interface breaks: agents do not receive emails or navigate supplier web portals. The
seller-side platforms, conversely, generate quotes and offers but have no mechanism
to transmit those offers to buyer agents as machine-readable, signed, negotiable
messages.

These agents are built on different platforms, by different vendors, using different
internal schemas. When a buyer agent deployed by one organization encounters a seller
agent deployed by a different organization on a different platform, no shared protocol
governs their interaction. The result is one of:

- Fallback to email and human-facing chat interfaces designed for human counterparties
- Ad-hoc bilateral integration between specific platform pairs
- No transaction at all

This is the cross-platform agent-to-agent commercial negotiation gap that A2CN fills.

**The invitation problem:** A further gap exists in the current discovery model. The
pull-based `/.well-known/a2cn-agent` mechanism requires both parties to have
independently deployed A2CN endpoints before they can negotiate. This creates a
cold-start problem for adoption. A2CN v0.2 introduces the Session Invitation
component (Component 8) to address this: a buyer agent can send a structured,
signed invitation to a supplier through any delivery channel, enabling the supplier
to activate A2CN capability in response to a specific negotiation request.

### 1.2 The Problem in Detail

Existing protocols do not address this gap:

| Protocol | Layer | Covers B2B Negotiation? |
|----------|-------|------------------------|
| MCP | Agent-to-tool | No — tool access only |
| A2A | Agent communication | No — capability negotiation only |
| UCP | Consumer retail checkout | No — B2C only, confirmed absent from roadmap |
| ACP (OpenAI/Stripe/PayPal) | Consumer checkout | No — B2C only |
| AP2 | Payment execution | No — downstream of agreement |
| Dynamics 365 ERP MCP Server | Seller-side ERP access | No — internal tool access, no bilateral protocol |
| Revenue Cloud Pricing API | Seller-side quote generation | No — generates quotes, no negotiation exchange |

The specific problems A2CN solves:

1. **No shared offer schema** — platforms define their own representations; agents
   cannot parse each other's offers without custom bilateral integration
2. **No counterparty authorization declaration** — no standard mechanism for an
   agent to declare its scope of authority
3. **No neutral transaction record** — each party stores their own version; no
   jointly-produced authoritative record
4. **No cross-organizational audit trail** — auditability for AI-mediated commercial
   decisions is increasingly required; no current protocol provides this across
   organizations
5. **Agent conversation pathologies** — without a session state machine, agents
   exhibit echoing or loop indefinitely
6. **Liability ambiguity** — when disputes arise from agent-mediated transactions,
   the evidentiary record needed for resolution does not exist
7. **No discovery mechanism** — agents cannot determine whether a counterparty has
   an agent-capable endpoint
8. **No adoption pathway for undeployed counterparties** — the pull-based discovery
   model requires both parties to independently deploy A2CN endpoints before they
   meet, creating a cold-start barrier to network growth (addressed by Component 8)

### 1.3 Design Philosophy

A2CN is designed around four principles:

**Minimalism.** The protocol defines exactly what is needed for two compliant agents
to negotiate safely and no more. Negotiation strategy, pricing logic, and
decision-making remain inside each party's system. A2CN governs the exchange
between agents, not the reasoning behind it.

**Neutrality.** A2CN has no opinion about which party's agent negotiates more
effectively. The protocol is equally useful to buyer and seller. No commercial
entity controls the specification.

**Composability.** A2CN is designed to run alongside MCP, A2A, and AP2, not to
replace them. An A2CN negotiation session can be established via A2A, use MCP for
internal data access during negotiation, and hand off to AP2 for payment execution
after agreement.

**Auditability by design.** Every A2CN session produces a structured audit log
of the negotiation, without additional instrumentation.

### 1.4 Scope

**In scope for v0.2 (new additions over v0.1):**
- Session Invitation component (Component 8) — push-based invitation enabling
  adoption by parties without pre-deployed A2CN endpoints
- Deal-type-specific terms schemas for `goods_procurement` and `saas_renewal`
  (OQ-004, now resolved)
- Deal type registry (OQ-001, now resolved)
- Configurable impasse threshold (OQ-005, now resolved)
- Platform integration guidance: Salesforce Revenue Cloud, Microsoft Dynamics 365,
  Fairmarkit, and A2A extension pattern (Section 15)
- MESO (Multiple Equivalent Simultaneous Offers) terms extension
- Webhook callbacks promoted from RECOMMENDED to REQUIRED at Level 2

**In scope for v0.1 (carried forward):**
- Discovery of A2CN-capable endpoints
- Session initiation and lifecycle management
- Offer and counteroffer exchange with explicit turn-taking
- Acceptance, rejection, and withdrawal
- Mandate declaration
- Transaction record generation
- Audit log (compliance trace) generation
- Error handling and session termination
- Idempotency rules for retried requests

**Out of scope (carried forward from v0.1):**
- Negotiation strategy or pricing logic
- Multi-party negotiations (more than two parties)
- Partial acceptance of individual offer terms (all-or-nothing per round)
- Real-time streaming negotiations
- Blockchain or on-chain settlement
- Payment execution (handled by AP2 or ACP downstream)
- Dispute resolution procedures
- Evaluation phase (post-delivery quality assessment)

---

## 2. Terminology and Conventions

### 2.1 Key Terms

**Initiator:** The agent that opens a negotiation session. Either party may be the
initiator. The initiating agent sends the first offer.

**Responder:** The agent that receives the session initiation request.

**Turn holder:** The party currently authorized to send the next offer or
counteroffer. Only the turn holder MAY send an offer in a given round.

**Session:** A bounded negotiation interaction between exactly two agents, governed
by A2CN, covering a single commercial transaction or set of related terms.

**Offer:** A structured message proposing specific commercial terms. In round 1,
sent only by the initiator. In subsequent rounds, sent only by the party that
received the most recent offer or counteroffer (i.e., the current turn holder).

**Counteroffer:** An offer made in response to a prior offer. Sending a counteroffer
implicitly rejects the prior offer and proposes new terms. A counteroffer MUST NOT
be sent simultaneously with a Rejection message for the same offer.

**Acceptance:** A message indicating unconditional agreement to the terms of the
most recently received offer. Acceptance triggers transaction record generation.
An acceptance is only valid from the current turn holder. Acceptance represents
protocol-level agreement on the negotiated terms; legal enforceability is governed
by applicable law and is external to this protocol.

**Rejection:** A message declining the most recently received offer without
proposing new terms. A rejection returns the turn to the rejecting party. The
rejecting party may then send a new offer (becoming a counteroffer in subsequent
rounds), or both parties may reach an impasse.

**Withdrawal:** A message terminating the session without agreement. Either party
may withdraw at any time after session establishment.

**Mandate:** A declaration of the scope within which an agent is operating on
behalf of its principal. In v0.1, a mandate is a protocol-level operating scope
declaration. A Declared Mandate (Tier 1) is self-asserted and not cryptographically
verified by the protocol. A DID VC Mandate (Tier 2) includes a Verifiable Credential
issued by the principal organization.

**Principal:** The organization on whose behalf an agent acts.

**DID:** Decentralized Identifier, as defined by W3C DID Core 1.0.

**DID Document:** The document associated with a DID that contains verification
methods (public keys) and service endpoints. All signing keys used in A2CN MUST be
retrieved from DID documents, not from discovery documents.

**Verification Method:** A public key or other cryptographic material associated
with a DID, expressed in a DID document. A2CN uses verification methods to verify
offer signatures, JWT authentication, and VC proofs.

**Transaction Record:** An immutable, content-addressed document recording the
agreed terms, signed by both parties, produced upon acceptance.

**Audit Log (Compliance Trace):** A structured log of the negotiation session,
produced at session termination for all outcomes.

**Deal Type:** A categorization of the commercial interaction. Declared in the
discovery document.

**Round:** One offer-response cycle. A round begins when the turn holder sends an
offer or counteroffer. The round ends when the other party responds.

**Canonical JSON:** The deterministic JSON serialization produced by the RFC 8785
JSON Canonicalization Scheme (JCS). All signed JSON objects in A2CN MUST be
serialized using JCS before hashing or signing.

**Protocol Act:** A complete A2CN message including its envelope fields (session_id,
round_number, sender_did, timestamp, expires_at) and payload (terms). The signed
scope of an offer covers the full protocol act, not only the terms.

### 2.2 Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described
in RFC 2119.

Where SHOULD is used, the full implications of not following the recommendation
are described inline. An implementer that chooses an alternative approach MUST
ensure interoperability with compliant implementations.

### 2.3 Data Formats

- All messages MUST be encoded as JSON (RFC 8259)
- All signed JSON objects MUST be canonicalized using RFC 8785 JCS before hashing
- All timestamps MUST be in ISO 8601 format with UTC timezone: `YYYY-MM-DDTHH:MM:SSZ`
- All monetary amounts MUST be represented as integers in the smallest currency unit
  (e.g., cents for USD) to avoid floating point errors
- All currency codes MUST be ISO 4217 three-letter codes
- All identifiers that require uniqueness SHOULD be UUID v4 (RFC 4122). Implementations
  MAY use other globally unique identifier formats (e.g., UUID v7, ULID) provided they
  are unique within their scope. Receiving implementations MUST treat identifiers as
  opaque strings and MUST NOT assume UUID format.
- All DIDs MUST conform to W3C DID Core 1.0
- Decimal values (percentages, hours) MUST be represented as integers in the smallest
  meaningful unit: uptime as hundredths of a percent (e.g., 9999 = 99.99%),
  response time as integer minutes, discount percent as hundredths of a percent
- The media type for A2CN messages is `application/a2cn+json`

---

## 3. Protocol Overview

### 3.1 High-Level Flow

```
Initiator Agent                                    Responder Agent
     |                                                  |
     |  1. GET /.well-known/a2cn-agent                 |
     |------------------------------------------------->|
     |  2. Discovery document                           |
     |<-------------------------------------------------|
     |                                                  |
     |  3. Resolve responder DID document               |
     |     (fetch signing keys)                         |
     |                                                  |
     |  4. POST /a2cn/sessions (SessionInit)            |
     |------------------------------------------------->|
     |  5. SessionAck (session_id, responder mandate)   |
     |<-------------------------------------------------|
     |                                                  |
     |  [Turn: Initiator]                               |
     |  6. POST /a2cn/sessions/{id}/messages (Offer)   |
     |------------------------------------------------->|
     |                                                  |
     |  [Turn: Responder]                               |
     |  7. POST /a2cn/sessions/{id}/messages            |
     |     (Counteroffer)                               |
     |<-------------------------------------------------|
     |                                                  |
     |        [rounds continue, turn alternates...]     |
     |                                                  |
     |  [Turn: Initiator]                               |
     |  N. POST /a2cn/sessions/{id}/messages            |
     |     (Acceptance)                                 |
     |------------------------------------------------->|
     |                                                  |
     |  N+1. Both parties independently generate       |
     |        TransactionRecord and AuditLog            |
```

### 3.2 Turn-Taking Rule

**This is the most critical behavioral rule in the protocol.**

- In round 1, ONLY the initiator MAY send an Offer
- After round 1, ONLY the party that received the most recent Offer or Counteroffer
  MAY respond (with Counteroffer, Acceptance, Rejection, or Withdrawal)
- Either party MAY send a Withdrawal at any time regardless of turn
- A party MUST NOT send an Offer or Counteroffer when it is not their turn
- If a party receives an Offer or Counteroffer when it is not that party's turn,
  the receiver MUST reject it with error code `NOT_YOUR_TURN`

Turn ownership is tracked in the session object via the `current_turn` field and
MUST be maintained server-side by each party's A2CN implementation.

### 3.3 One Response Per Open Offer

Each offer or counteroffer requires exactly one response from the turn holder.
The response MUST be one of: Counteroffer, Acceptance, Rejection, or Withdrawal.

A Rejection and a Counteroffer MUST NOT be sent as a compound response to the
same offer. If a party wishes to decline current terms and propose new terms,
they MUST send a Counteroffer (which implicitly rejects the prior offer).

---

## 4. Component 1: Discovery

### 4.1 Purpose

Discovery allows any A2CN-capable agent to determine whether a counterparty
organization has an A2CN endpoint, what deal types they support, and how to
initiate a session.

### 4.2 Trust Model for Discovery

**Critical:** The discovery document is NOT the trust anchor for cryptographic
operations. The discovery document references the organization's DID. All signing
keys used to verify offers, JWTs, and Verifiable Credentials MUST be retrieved
by resolving the organization's DID document.

The discovery document's `verification_method` field contains a reference (a
`kid`) to a specific verification method in the DID document. Implementations
MUST:

1. Fetch the discovery document to learn the counterparty's DID and endpoint
2. Resolve the counterparty's DID document
3. Locate the verification method referenced by `verification_method`
4. Use that verification method's key material for all cryptographic verification

If the DID document cannot be resolved, the agent MUST NOT proceed with session
initiation. If the verification method referenced in the discovery document is
not present in the DID document, the agent MUST NOT proceed and MUST surface
this as a configuration error.

This design eliminates the dual trust-root problem: there is one canonical source
of cryptographic key material (the DID document), and the discovery document
merely points to it.

**Verification method precedence:** The discovery document declares a default
`verification_method` for the organization. However, the `verification_method`
field in a SessionInit or SessionAck message overrides the discovery document
for the duration of that specific session. Once a session is established, both
parties MUST use the verification method declared in the SessionInit (for the
initiator) and SessionAck (for the responder) for all signature verification
within that session, regardless of any subsequent changes to the discovery
document. This ensures consistent key material throughout a session's lifecycle.

### 4.3 The Discovery Document

An organization that supports A2CN MUST publish a discovery document at:

```
https://{domain}/.well-known/a2cn-agent
```

The discovery document MUST be served over HTTPS. HTTP without TLS MUST NOT
be used.

The discovery document MUST be served with `Content-Type: application/a2cn+json`.

Responses SHOULD include standard HTTP cache headers (`Cache-Control`, `ETag`).
When cache headers are absent, agents SHOULD revalidate the discovery document
before initiating a new session if the locally cached copy is older than 1 hour.
When a cached discovery document's DID or `verification_method` changes, any
sessions established under the previous document remain valid; the change affects
only new sessions.

#### 4.3.1 Discovery Document Schema

The normative JSON Schema is published at `spec/schemas/discovery.schema.json`.

```json
{
  "a2cn_version": "0.1",
  "conformance_level": "integer",
  "organization": {
    "name": "string",
    "did": "string",
    "legal_jurisdiction": "string"
  },
  "endpoint": "string",
  "deal_types": ["string"],
  "mandate_methods": ["string"],
  "verification_method": "string",
  "max_rounds_by_deal_type": {
    "<deal_type>": "integer"
  },
  "value_thresholds": {
    "high_value_minimum": "integer",
    "high_value_currency": "string"
  },
  "contact": "string",
  "updated_at": "string"
}
```

#### 4.3.2 Field Definitions

**`conformance_level`** (integer, REQUIRED)  
The conformance level supported by this endpoint. MUST be `1`, `2`, or `3` as
defined in Section 16.2.

**`a2cn_version`** (string, REQUIRED)  
The version of A2CN supported. MUST be `"0.1"` for this version.

**`organization.name`** (string, REQUIRED)  
Human-readable name of the organization.

**`organization.did`** (string, REQUIRED)  
The W3C DID of the organization. `did:web` is RECOMMENDED for organizations
without existing DID infrastructure, as it requires only DNS control.  
Example: `"did:web:acme-corp.com"`

**`organization.legal_jurisdiction`** (string, OPTIONAL)  
ISO 3166-1 alpha-2 country code of the organization's primary legal jurisdiction.

**`endpoint`** (string, REQUIRED)  
The HTTPS base URL of the A2CN API for this organization.

**`deal_types`** (array of strings, REQUIRED)  
Deal types this endpoint supports. At least one MUST be declared.

Built-in deal types:
- `"saas_renewal"` — SaaS or software license renewal
- `"services_contract"` — Professional services or consulting
- `"goods_procurement"` — Physical goods purchase or supply
- `"freight_rate"` — Freight, logistics, or shipping rates
- `"payment_terms"` — Payment terms on an existing relationship

Organizations MAY define custom deal types using reverse domain notation:
`"com.acme.custom_type"`. Custom deal types SHOULD be publicly documented.

> **OPEN QUESTION OQ-001:** Should A2CN maintain a public registry of deal types?
> Proposed resolution: community-maintained registry in v0.2. For v0.1, convention
> and documentation suffice.

**`mandate_methods`** (array of strings, REQUIRED)  
Mandate tiers accepted. Valid values:
- `"declared"` — Tier 1 self-declared mandate (see Section 5)
- `"did_vc"` — Tier 2 DID Verifiable Credential mandate (see Section 5)

**`verification_method`** (string, REQUIRED)  
A reference to the verification method in the organization's DID document to
be used for verifying A2CN signatures. MUST be a DID URL of the form
`{did}#{key-id}`.  
Example: `"did:web:acme-corp.com#key-1"`

Receiving agents MUST resolve this DID document and locate this verification
method before attempting any signature verification.

**`max_rounds_by_deal_type`** (object, OPTIONAL)  
Maximum rounds per deal type. Absent deal types default to 10. Values MUST be
positive integers between 1 and 50.

**`value_thresholds`** (object, CONDITIONAL)  
Required if `"did_vc"` is listed in `mandate_methods`. Defines the transaction
value above which Tier 2 mandate verification is required.

- `high_value_minimum` (integer, REQUIRED) — In smallest currency unit
- `high_value_currency` (string, REQUIRED) — ISO 4217 code

**`contact`** (string, OPTIONAL)  
Email or URL for A2CN integration support.

**`updated_at`** (string, REQUIRED)  
ISO 8601 timestamp of last update to this document.

#### 4.3.3 Complete Example

```json
{
  "a2cn_version": "0.1",
  "conformance_level": 2,
  "organization": {
    "name": "Acme Corp",
    "did": "did:web:acme-corp.com",
    "legal_jurisdiction": "US"
  },
  "endpoint": "https://acme-corp.com/api/a2cn",
  "deal_types": ["saas_renewal", "services_contract", "goods_procurement"],
  "mandate_methods": ["declared", "did_vc"],
  "verification_method": "did:web:acme-corp.com#key-2026-01",
  "max_rounds_by_deal_type": {
    "saas_renewal": 5,
    "services_contract": 10,
    "goods_procurement": 15
  },
  "value_thresholds": {
    "high_value_minimum": 5000000,
    "high_value_currency": "USD"
  },
  "contact": "a2cn@acme-corp.com",
  "updated_at": "2026-03-24T00:00:00Z"
}
```

### 4.4 Discovery Failure Handling

If a discovery document cannot be fetched, parsed, or validated, the agent MUST NOT
attempt session initiation. If the DID referenced in the discovery document cannot
be resolved, the agent MUST NOT attempt session initiation and SHOULD surface this
as a `DID_RESOLUTION_FAILURE` condition.

---

## 5. Component 2: Mandate Declaration and Verification

### 5.1 What a Mandate Is — and Is Not

A mandate in A2CN v0.1 is a **protocol-level operating scope declaration**. It
describes the scope within which an agent is operating: what deal types it covers,
up to what value, and for how long.

**Tier 1 (Declared Mandate) is self-assertion, not cryptographic authorization.**
When an agent presents a Declared Mandate, the counterparty receives a statement
that the agent claims to be operating within a defined scope. The protocol cannot
verify this claim cryptographically. The declaring party accepts reputational and
legal liability for any commitment that exceeds their stated scope. Implementations
SHOULD log all mandate declarations for audit purposes.

**Tier 2 (DID VC Mandate) includes a Verifiable Credential** issued by the
principal organization's DID, which can be cryptographically verified. It provides
stronger evidence that the agent has delegated authority, but the legal enforceability
of that delegation remains subject to the applicable jurisdiction.

Neither tier is a guarantee of legal binding. Contract formation from A2CN sessions
is governed by applicable law, not by the protocol.

### 5.2 Two-Tier Mandate System

**Tier 1: Declared Mandate**  
Used when total estimated transaction value is below the counterparty's
`value_thresholds.high_value_minimum`. The agent self-declares its scope in the
session initiation message.

**Tier 2: DID VC Mandate**  
Used when estimated value meets or exceeds the counterparty's `high_value_minimum`,
or when either party's discovery document declares `"did_vc"` as the only supported
mandate method.

> **OPEN QUESTION OQ-002:** The value threshold is set by the counterparty's
> discovery document. Should A2CN define a protocol-level maximum threshold
> implementations cannot exceed? This prevents a counterparty from setting a
> $0 threshold to block unsophisticated agents. Proposed: $10,000 USD equivalent.

### 5.3 Declared Mandate Object

Schema: `spec/schemas/declared-mandate.schema.json`

```json
{
  "mandate_type": "declared",
  "agent_id": "string",
  "principal_organization": "string",
  "principal_did": "string",
  "authorized_deal_types": ["string"],
  "max_commitment_value": "integer",
  "max_commitment_currency": "string",
  "valid_from": "string",
  "valid_until": "string",
  "scope_description": "string"
}
```

**`mandate_type`** — MUST be `"declared"`

**`agent_id`** — Unique identifier for this agent instance. SHOULD be stable
across sessions but MAY change between deployments.

**`principal_did`** — W3C DID of the principal organization. SHOULD match the DID
in the sender's discovery document. Counterparties SHOULD record this for audit
purposes but the protocol does not cryptographically verify it in Tier 1.

**`max_commitment_value`** — Maximum total value this agent is declaring it will
commit to, in smallest currency unit of `max_commitment_currency`.

**`valid_until`** — MUST be in the future at session initiation time. SHOULD cover
at least the expected session duration.

### 5.4 DID VC Mandate Object

Schema: `spec/schemas/did-vc-mandate.schema.json`

The Verifiable Credential MUST:
- Be issued by the principal organization's DID
- Use the `JsonWebSignature2020` proof type with `ES256` algorithm by default
- Contain credential type `A2CNNegotiationMandate`
- Not be expired at session initiation time

Other proof types MAY be supported by mutual agreement between parties. Implementations
that support additional proof suites MUST document them publicly and MUST negotiate
support via the `mandate_methods` discovery field extension. The default suite
(`JsonWebSignature2020` + `ES256`) MUST always be supported by Level 2 and Level 3
implementations.

```json
{
  "mandate_type": "did_vc",
  "credential": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://a2cn.dev/contexts/v0.1"
    ],
    "type": ["VerifiableCredential", "A2CNNegotiationMandate"],
    "id": "string",
    "issuer": "string",
    "issuanceDate": "string",
    "expirationDate": "string",
    "credentialSubject": {
      "id": "string",
      "agent_id": "string",
      "principal_organization": "string",
      "authorized_deal_types": ["string"],
      "max_commitment_value": "integer",
      "max_commitment_currency": "string",
      "authorized_counterparties": ["string"]
    },
    "proof": {
      "type": "JsonWebSignature2020",
      "created": "string",
      "verificationMethod": "string",
      "proofPurpose": "assertionMethod",
      "jws": "string"
    }
  }
}
```

**`credentialSubject.authorized_counterparties`** (array, OPTIONAL)  
If present and non-empty, this mandate is only valid for negotiations with the
listed DIDs. Receiving agents MUST verify that their own DID appears in this set.
An absent or empty array means the mandate is valid for any counterparty.

### 5.5 Mandate Verification Procedure

**For Tier 1 (Declared):**
1. Verify `valid_until` is in the future
2. Verify the session deal type is in `authorized_deal_types`
3. Record the mandate declaration in the session record
4. No cryptographic verification is performed or implied

**For Tier 2 (DID VC):**
1. Resolve the issuer DID using a conformant DID resolver
   - Implementations MUST support native resolution of `did:web` DIDs
   - Implementations SHOULD support resolution of other DID methods via a
     universal resolver
2. Verify the VC proof signature against the issuer's verification method
3. Verify `expirationDate` is in the future
4. Verify the session deal type is in `credentialSubject.authorized_deal_types`
5. If `authorized_counterparties` is present and non-empty, verify the
   receiver's DID appears in the set
6. Record the verified credential in the session record

**DID document session-duration binding:** Once a verification method has been
successfully resolved from a DID document and used to verify a signature within
a session, that verification method MUST be treated as valid for the entire
duration of that session. Implementations MUST NOT re-resolve the DID document
mid-session and apply newly discovered key material to the current session. This
prevents mid-session key rotation from causing asymmetric verification failures
where one party re-resolves to a new key while the other continues using the
original. New sessions always use freshly resolved DID documents.

If verification fails, the receiver MUST reject the session with `MANDATE_INVALID`.

> **OPEN QUESTION OQ-003:** DID resolution introduces network dependency. Should
> A2CN specify a fallback when the DID resolver is temporarily unavailable?
> Proposed: implementations MAY cache resolved DID documents for up to 24 hours
> for use when live resolution fails, subject to the session still being within
> the cached document's validity period.

---

## 6. Component 3: Session Initiation

### 6.1 Idempotency

Session initiation is subject to network failures and retries. Idempotency rules:

- If a responder receives a `POST /sessions` with a `message_id` it has already
  processed, it MUST return the same `SessionAck` (with the same `session_id`)
  that it returned for the original request. It MUST NOT create a second session.
- Idempotency is keyed on `message_id`. The responder MUST maintain a log of
  processed `message_id` values for at least twice the `session_timeout_seconds`
  duration.
- If a responder receives a retried `POST /sessions` for a `message_id` that
  was previously rejected, it MUST return the same `SessionReject`.
- Similarly, retried `POST /sessions/{id}/messages` with the same `message_id`
  MUST return the same response as the original. The session state MUST NOT
  advance twice for the same message.

### 6.2 Pre-Session Anti-Replay

Session initiation messages arrive before a shared session context exists. To
prevent pre-session replay attacks, the responder MUST maintain a short-term
store of recently seen `(sender_did, message_id, purpose)` tuples for a window
of at least 600 seconds. Any SessionInit with a `(sender_did, message_id, "a2cn_session_init")`
tuple already in this store MUST be handled per the idempotency rules above,
not treated as a new session request.

### 6.3 Initiation Request

Either party may initiate. The initiating agent sends:

```
POST {endpoint}/sessions
Content-Type: application/a2cn+json
Authorization: Bearer {signed_jwt}
```

The JWT in the Authorization header MUST be signed with the private key corresponding
to the verification method referenced in the initiator's discovery document.
The receiving agent MUST resolve the initiator's DID document and verify the JWT
against the referenced verification method before processing the request.

**Key selection rule:** When verifying a JWT, the verification method used MUST
satisfy all three of the following:
1. It MUST be the verification method declared by the sender in their discovery
   document (or in the `initiator.verification_method` / `responder.verification_method`
   field of their SessionInit/SessionAck for subsequent messages)
2. It MUST be present as a valid, non-revoked verification method in the sender's
   DID document
3. The JWT's `kid` header parameter, if present, MUST match the key identifier
   portion of that verification method DID URL

If the JWT `kid` does not match the declared verification method, the receiver
MUST reject the request with HTTP 401. If the DID document does not contain the
declared verification method, the receiver MUST reject with `DID_NOT_FOUND`.

JWT payload:
```json
{
  "iss": "{initiator_did}",
  "aud": "{responder_did}",
  "iat": "{unix_timestamp}",
  "exp": "{unix_timestamp_plus_300_seconds}",
  "jti": "{unique_jwt_id}",
  "purpose": "a2cn_session_init"
}
```

`jti` (JWT ID) is REQUIRED on session-init JWTs and MUST be included in the
pre-session anti-replay store.

For all subsequent in-session requests, JWT `exp` MUST be `iat + 60` seconds.
The 300-second window is permitted only for session initiation to allow for
slower pre-flight DID resolution. Receivers SHOULD accept timestamps within 30
seconds of the receiver's clock to accommodate clock skew.

#### 6.3.1 SessionInit Message

Schema: `spec/schemas/session-init.schema.json`

```json
{
  "message_type": "session_init",
  "message_id": "string",
  "protocol_version": "0.1",
  "session_params": {
    "deal_type": "string",
    "currency": "string",
    "subject": "string",
    "subject_reference": "string",
    "estimated_value": "integer",
    "max_rounds": "integer",
    "session_timeout_seconds": "integer",
    "round_timeout_seconds": "integer"
  },
  "initiator": {
    "organization_name": "string",
    "did": "string",
    "verification_method": "string",
    "agent_id": "string",
    "endpoint": "string"
  },
  "initiator_mandate": {},
  "metadata": {}
}
```

**`session_params.currency`** (string, REQUIRED)  
ISO 4217 currency code. The session currency is fixed at initiation. All offers
and the transaction record MUST use this currency. Currency changes across rounds
are not permitted.

**`session_params.deal_type`** (string, REQUIRED)  
MUST be a deal type declared in the responder's discovery document.

**`session_params.subject`** (string, REQUIRED)  
Human-readable description of what is being negotiated.

**`session_params.subject_reference`** (string, OPTIONAL)  
External reference such as a contract number, PO number, or RFP identifier.

**`session_params.estimated_value`** (integer, CONDITIONAL)  
Required if the responder's discovery document declares `value_thresholds`.
Estimated total value in smallest unit of `session_params.currency`.

**`session_params.max_rounds`** (integer, REQUIRED)  
Maximum negotiation rounds requested. MUST NOT exceed the responder's discovery
document limit for this deal type. Default limit if unspecified in discovery: 10.

**`session_params.session_timeout_seconds`** (integer, REQUIRED)  
Maximum session duration. MUST be between 60 and 86400.

**`session_params.round_timeout_seconds`** (integer, REQUIRED)  
Maximum time for a response per round. MUST be between 30 and 3600.

**`initiator.verification_method`** (string, REQUIRED)  
DID URL of the verification method the initiator will use for signing. The
responder MUST resolve this to verify subsequent messages.

**`initiator_mandate`** (object, REQUIRED)  
Declared Mandate or DID VC Mandate per Section 5.

**`metadata`** (object, OPTIONAL)  
Key-value pairs using reverse domain notation. `"a2cn.*"` keys are reserved.

### 6.4 Session Acknowledgment

The responder MUST respond within 30 seconds with either SessionAck or SessionReject.

#### 6.4.1 SessionAck Message

Schema: `spec/schemas/session-ack.schema.json`

```json
{
  "message_type": "session_ack",
  "message_id": "string",
  "session_id": "string",
  "in_reply_to": "string",
  "protocol_version": "0.1",
  "session_params_accepted": {
    "deal_type": "string",
    "currency": "string",
    "max_rounds": "integer",
    "session_timeout_seconds": "integer",
    "round_timeout_seconds": "integer"
  },
  "responder": {
    "organization_name": "string",
    "did": "string",
    "verification_method": "string",
    "agent_id": "string",
    "endpoint": "string"
  },
  "responder_mandate": {},
  "session_created_at": "string",
  "current_turn": "initiator"
}
```

**`session_id`** (string, REQUIRED)  
UUID generated by the responder. Used in all subsequent session messages.

**`session_params_accepted.max_rounds`**  
The responder MAY reduce `max_rounds` to a lower value. The responder MUST NOT
increase it above the initiator's request. The responder MUST NOT change
`deal_type`, `currency`, `session_timeout_seconds`, or `round_timeout_seconds`.
These four parameters are fixed at session initiation. If the initiator considers
the responder's reduced `max_rounds` unacceptable, it MUST send a Withdrawal to
close the session.

**`current_turn`** (string, REQUIRED)  
MUST be `"initiator"` in the SessionAck. Tracks whose turn it is to send the
next offer. Valid values: `"initiator"` | `"responder"`.

#### 6.4.2 SessionReject Message

Schema: `spec/schemas/session-reject.schema.json`

```json
{
  "message_type": "session_reject",
  "message_id": "string",
  "in_reply_to": "string",
  "error_code": "string",
  "error_message": "string",
  "retry_after_seconds": "integer"
}
```

---

## 7. Component 4: Offer Exchange

All session messages after initiation are sent to:

```
POST {endpoint}/sessions/{session_id}/messages
Content-Type: application/a2cn+json
Authorization: Bearer {signed_jwt}
```

### 7.1 Offer Object

Schema: `spec/schemas/offer.schema.json`

```json
{
  "message_type": "offer",
  "message_id": "string",
  "session_id": "string",
  "in_reply_to": "string",
  "round_number": "integer",
  "sequence_number": "integer",
  "sender_did": "string",
  "sender_agent_id": "string",
  "sender_verification_method": "string",
  "timestamp": "string",
  "expires_at": "string",
  "terms": {
    "total_value": "integer",
    "currency": "string",
    "line_items": [],
    "payment_terms": {},
    "delivery_terms": {},
    "contract_duration": {},
    "sla": {},
    "custom_terms": {}
  },
  "protocol_act_hash": "string",
  "protocol_act_signature": "string"
}
```

**`message_type`** (string, REQUIRED)  
MUST be `"offer"` for round 1. MUST be `"counteroffer"` for rounds 2 and beyond.
If a message arrives with type `"offer"` in round 2 or later, the receiver MUST
reject it with `WRONG_MESSAGE_TYPE`.

**`in_reply_to`** (string, REQUIRED after round 1)  
The `message_id` of the most recent offer or counteroffer received from the other
party, regardless of any intervening Rejection messages. When a party sends a
Rejection and then sends a new offer (now holding the turn), `in_reply_to` in
that new offer MUST reference the offer or counteroffer that was rejected — not
the Rejection message itself. MUST be absent in round 1.

**`round_number`** (integer, REQUIRED)  
The round this message belongs to. MUST equal the current session round number.
The receiver MUST reject messages with unexpected round numbers with `SESSION_WRONG_STATE`.

**`sequence_number`** (integer, REQUIRED)  
A monotonically increasing per-session counter, starting at 1 for the first offer.
Each new message in the session MUST increment by exactly 1.

**Strict ordering model:** A2CN uses strict in-order message delivery. Receivers
MUST process messages in sequence_number order. The receiver MUST reject any message
where `sequence_number != last_processed_sequence_number + 1` with error code
`SEQUENCE_ERROR`. Buffering of out-of-order messages is NOT permitted. There is
no reordering window.

**Sender retry obligation:** To prevent deadlock under the strict ordering model,
a sender MUST continue retrying the current message (same `message_id`, same
`sequence_number`, all fields identical) until it receives an HTTP 2xx
acknowledgment from the receiver. A sender MUST NOT send the next logical message
(with `sequence_number + 1`) until the current message has been acknowledged.
This ensures that message loss does not create gaps that would cause the receiver
to reject subsequent messages.

**Retransmissions:** A message is a retransmission if and only if it has the same
`message_id` as a previously sent message. Retransmissions MUST NOT change any
field, including `sequence_number`. A sender MUST NOT send a different payload
with the same `message_id` — doing so is a protocol violation and receivers MUST
reject it with `SEQUENCE_ERROR`. A sender MUST retry with the identical message
(same `message_id`, same `sequence_number`, same all fields) if it did not receive
HTTP 2xx acknowledgment. A sender MUST NOT generate a new `message_id` for a
retry of the same logical message.

If a receiver receives a retransmission (same `message_id` already processed),
it MUST return the same response as the original per the idempotency rules in
Section 6.1, without incrementing any session counters.

**`sender_verification_method`** (string, REQUIRED)  
DID URL of the verification method used to sign this message. MUST match the
`verification_method` declared by the sender in their discovery document or
SessionInit/SessionAck.

**`expires_at`** (string, REQUIRED)  
The offer is invalid after this time. MUST be after `timestamp`. MUST NOT exceed
`timestamp` plus the session's `round_timeout_seconds`. Receivers MUST NOT accept
an offer whose `expires_at` is in the past.

### 7.2 Terms Object

**`terms.total_value`** (integer, REQUIRED)  
Total monetary value in smallest unit of `terms.currency`.

**`terms.currency`** (string, REQUIRED)  
MUST match the session's negotiated `currency`. Currency MUST NOT change across
rounds.

**`terms.line_items`** (array, OPTIONAL)  
Each item:
```json
{
  "id": "string",
  "description": "string",
  "quantity": "integer",
  "unit": "string",
  "unit_price": "integer",
  "total": "integer"
}
```
`quantity` is a non-negative integer. For fractional quantities (e.g., commodities
measured in tenths), implementers SHOULD use the appropriate smallest unit
(e.g., tenths, hundredths) and document the unit string accordingly.

**`terms.payment_terms`** (object, OPTIONAL)
```json
{
  "net_days": "integer",
  "early_payment_discount_bps": "integer",
  "early_payment_discount_days": "integer",
  "payment_method": "string"
}
```
`early_payment_discount_bps` — discount in basis points (hundredths of a percent).
Example: 200 = 2.00% discount.

`payment_method` values: `"wire"`, `"ach"`, `"check"`, `"card"`, `"crypto"`,
`"other"`

**`terms.delivery_terms`** (object, OPTIONAL)
```json
{
  "delivery_date": "string",
  "delivery_window_days": "integer",
  "incoterm": "string",
  "delivery_location": "string"
}
```

**`terms.contract_duration`** (object, OPTIONAL)
```json
{
  "start_date": "string",
  "end_date": "string",
  "auto_renewal": "boolean",
  "cancellation_notice_days": "integer"
}
```

**`terms.sla`** (object, OPTIONAL)
```json
{
  "uptime_bps": "integer",
  "response_time_minutes": "integer",
  "resolution_time_minutes": "integer",
  "penalty_per_incident": "integer"
}
```
`uptime_bps` — uptime in basis points. Example: 9999 = 99.99%.

SLA penalties (`penalty_per_incident`) are denominated in the session's negotiated
currency (the `currency` field in `session_params`). The `penalty_currency` field
present in v0.1-draft has been removed; all monetary amounts in a session use the
single session currency.

**`terms.custom_terms`** (object, OPTIONAL)  
Key-value pairs using reverse domain notation. Free-text string values in this
field MUST be treated as untrusted input. See Section 13.7 on prompt injection.

> **OPEN QUESTION OQ-004:** Should A2CN define deal-type-specific terms extensions
> (e.g., a `saas_renewal` extension with license-count and seat-tier fields)?
> Proposed: v0.2 introduces deal-type extensions via the same mechanism as
> discovery extensions.

### 7.3 Protocol Act Signing

#### 7.3.1 What Is Signed

The signed scope covers the full protocol act — not only the terms. This prevents
cross-session and cross-round replay of valid offer signatures.

The **protocol act object** used for signing is:

```json
{
  "protocol_version": "0.1",
  "session_id": "string",
  "round_number": "integer",
  "sequence_number": "integer",
  "message_type": "string",
  "sender_did": "string",
  "timestamp": "string",
  "expires_at": "string",
  "terms": {}
}
```

#### 7.3.2 Signing Procedure

```
1. Construct the protocol act object with the fields above
2. Serialize using RFC 8785 JSON Canonicalization Scheme (JCS)
3. Compute: protocol_act_hash = base64url(SHA-256(jcs_bytes))
4. Sign: protocol_act_signature = JWS(protocol_act_hash, sender_private_key, "ES256")
```

`protocol_act_hash` and `protocol_act_signature` are included in the offer message.

Receivers MUST verify the signature before processing the offer:
1. Resolve sender's DID document
2. Locate the verification method referenced by `sender_verification_method`
3. Reconstruct the protocol act object from the offer fields
4. Compute JCS and SHA-256
5. Verify the JWS signature against the retrieved public key

An offer with an invalid signature MUST be rejected with `INVALID_SIGNATURE`.

#### 7.3.3 Key Rotation

The discovery document references a single `verification_method`. If a key must
be rotated, the organization SHOULD update their DID document to add the new
verification method (retaining the old one as `revoked`), then update their
discovery document's `verification_method` field. Sessions established under the
old key remain valid until they reach a terminal state. New sessions use the new
key.

### 7.4 Acceptance Message

Schema: `spec/schemas/acceptance.schema.json`

```json
{
  "message_type": "acceptance",
  "message_id": "string",
  "session_id": "string",
  "in_reply_to": "string",
  "round_number": "integer",
  "sequence_number": "integer",
  "accepted_offer_id": "string",
  "accepted_protocol_act_hash": "string",
  "sender_did": "string",
  "sender_agent_id": "string",
  "sender_verification_method": "string",
  "timestamp": "string",
  "acceptance_signature": "string"
}
```

**`accepted_protocol_act_hash`** — MUST match the `protocol_act_hash` of the
accepted offer. This binds the acceptance to the specific protocol act.

**`acceptance_signature`** — JWS over the JCS-canonicalized form of:
```json
{
  "session_id": "...",
  "round_number": "...",
  "sequence_number": "...",
  "accepted_offer_id": "...",
  "accepted_protocol_act_hash": "..."
}
```
using the accepting party's private key. Including `round_number` and
`sequence_number` in the signed payload closes the narrow edge case where an
acceptance could be replayed within the same session against a different offer
at the same round position. Both signatures (the offer's `protocol_act_signature`
and the acceptance's `acceptance_signature`) together form the dual-signature
basis of the transaction record.

Receivers MUST reject acceptances of expired offers (`expires_at` in the past).

### 7.5 Rejection Message

Schema: `spec/schemas/rejection.schema.json`

```json
{
  "message_type": "rejection",
  "message_id": "string",
  "session_id": "string",
  "in_reply_to": "string",
  "round_number": "integer",
  "sequence_number": "integer",
  "rejected_offer_id": "string",
  "sender_did": "string",
  "sender_agent_id": "string",
  "timestamp": "string",
  "reason_code": "string",
  "reason_description": "string"
}
```

A Rejection returns the turn to the rejecting party. After sending a Rejection,
the rejecting party becomes the new turn holder and MAY send a new Offer or
Counteroffer (incrementing the round), or MAY send a Withdrawal.

**`reason_code`** values:
- `"PRICE_TOO_HIGH"` | `"PRICE_TOO_LOW"` | `"TERMS_UNACCEPTABLE"`
- `"OUTSIDE_MANDATE"` | `"NO_REASON_GIVEN"`

A Rejection does NOT terminate the session unless `round_number` equals
`max_rounds`. After a max-rounds Rejection, the session transitions to
`REJECTED_FINAL`.

**Turn after rejection:** Following a Rejection, `current_turn` is set to the
rejecting party. The rejecting party has the option to make a new offer.

**Round counting after rejection:** When the rejecting party subsequently sends a
new offer (having held the turn after rejection), that new offer MUST use
`message_type: "counteroffer"` (since it occurs after round 1) and MUST increment
`round_number` by 1. The Rejection itself does not increment `round_number`; the
following counteroffer does. Example: Party A sends round 3 counteroffer → Party B
rejects (round stays 3, turn → B) → Party B sends round 4 counteroffer.

**Timeout after rejection:** When a Rejection is sent, the `round_timeout_seconds`
clock begins immediately from the timestamp of the Rejection message for the
rejecting party as the new turn holder. If the turn holder does not send a new
offer, counteroffer, or withdrawal within `round_timeout_seconds`, the session
transitions to `TIMED_OUT`.

### 7.6 Withdrawal Message

Schema: `spec/schemas/withdrawal.schema.json`

```json
{
  "message_type": "withdrawal",
  "message_id": "string",
  "session_id": "string",
  "in_reply_to": "string",
  "sequence_number": "integer",
  "sender_did": "string",
  "sender_agent_id": "string",
  "timestamp": "string",
  "reason_code": "string",
  "reason_description": "string"
}
```

A withdrawal terminates the session immediately with state `WITHDRAWN`. Either
party may withdraw regardless of current turn ownership.

`in_reply_to` — the `message_id` of the most recent message received, if any.
OPTIONAL if withdrawing before any offers are exchanged.

**`reason_code`** values:
- `"OUTSIDE_MANDATE"` | `"COUNTERPARTY_UNREACHABLE"` | `"STRATEGY_DECISION"`
- `"COMPLIANCE_FAILURE"` | `"NO_REASON_GIVEN"`

---

## 8. Component 5: Session State Machine

### 8.1 Session Object

Each party maintains a session object. This is also the canonical response body
for `GET /sessions/{session_id}`.

```json
{
  "session_id": "string",
  "protocol_version": "0.1",
  "state": "string",
  "current_turn": "string",
  "round_number": "integer",
  "max_rounds": "integer",
  "sequence_number": "integer",
  "latest_offer_id": "string",
  "latest_offer_hash": "string",
  "terminal_reason": "string",
  "terminal_message_id": "string",
  "session_created_at": "string",
  "state_updated_at": "string",
  "session_params": {}
}
```

`current_turn` — `"initiator"` | `"responder"` | `"none"` (in terminal states)  
`state_updated_at` — updated on every state transition  
`terminal_reason` — set when entering a terminal state, null otherwise  
`terminal_message_id` — the message_id that caused the terminal transition

Two parties may temporarily disagree on session state due to network delays.
Each party MUST treat their locally maintained state as authoritative for
outbound decisions.

**State disagreement resolution:** When parties detect conflicting state via
polling, the following deterministic rule applies:

1. The party with the higher `sequence_number` in their last received message
   is considered authoritative for that transition
2. If `sequence_number` is equal, the message with the later `timestamp` is
   authoritative
3. If both `sequence_number` and `timestamp` are equal (clock collision), the
   message whose `sender_did` is lexicographically greater (UTF-8 byte order)
   is authoritative

This rule is deterministic: both parties applying it independently will reach
the same conclusion. In practice, the most likely scenario requiring this rule
is simultaneous withdrawal — both parties sending a Withdrawal at the same
sequence position. The turn-taking rules prevent most other simultaneous-message
scenarios.

### 8.2 States

| State | Terminal? | Description |
|-------|-----------|-------------|
| `PENDING` | No | SessionInit sent, awaiting ack |
| `ACTIVE` | No | Session established, awaiting first offer from initiator |
| `NEGOTIATING` | No | Offer sent; awaiting response from turn holder |
| `COMPLETED` | Yes | Agreement reached, transaction record generated |
| `REJECTED_FINAL` | Yes | Max rounds reached with no agreement |
| `WITHDRAWN` | Yes | One party withdrew |
| `TIMED_OUT` | Yes | Session or round timeout expired |
| `ERROR` | Yes | Unrecoverable protocol error |

Note: `ACTIVE` is now used only for the pre-first-offer state, eliminating the
ambiguity where it previously meant both "ready for first offer" and
"counteroffer received." After any offer is sent or received, the state is
`NEGOTIATING`.

### 8.3 State Transitions

```
                ┌─────────────────────────────────┐
                │           PENDING               │
                │    (session_init sent)           │
                └──────────┬──────────────────────┘
                           │
          ┌────────────────┴──────────────┐
          │ session_ack                   │ session_reject or
          ▼                               │ timeout (30s)
  ┌───────────────┐                       ▼
  │    ACTIVE     │                 ┌──────────┐
  │ (turn=init,   │                 │  ERROR   │
  │ awaiting 1st  │                 └──────────┘
  │ offer)        │
  └──────┬────────┘
         │ initiator sends offer
         ▼
  ┌─────────────────────────────────────────────────────┐
  │                  NEGOTIATING                         │
  │  (current_turn = party awaiting response)           │
  └──────┬──────────────────────────────────────────────┘
         │
    ┌────┴────────────────────────────────┐
    │                                     │
    │ acceptance received                 │ counteroffer received
    ▼                                     ▼
┌──────────┐                    [NEGOTIATING, turn flips,
│COMPLETED │                     round_number increments]
└──────────┘                             │
                                         │ rejection received
                                         ▼
                           [NEGOTIATING, turn = rejecting party,
                            rejecting party may now send new offer]
                                         │
                                         │ if round_number = max_rounds
                                         │ AND rejection received
                                         ▼
                                  ┌─────────────┐
                                  │REJECTED_FINAL│
                                  └─────────────┘

From NEGOTIATING or ACTIVE:
  withdrawal → WITHDRAWN
  timeout → TIMED_OUT
  protocol error → ERROR
```

### 8.4 Transition Rules

**From PENDING:**
- → ACTIVE: valid SessionAck received; `current_turn = "initiator"`
- → ERROR: SessionReject received, or 30 seconds elapsed without response

**From ACTIVE:**
- → NEGOTIATING: initiator sends Offer; `current_turn = "responder"`; `round_number = 1`
- → WITHDRAWN: Withdrawal received or sent
- → TIMED_OUT: session_timeout_seconds elapsed

**From NEGOTIATING:**
- → COMPLETED: valid Acceptance received
- → NEGOTIATING: valid Counteroffer received; `current_turn` flips; `round_number` increments
- → NEGOTIATING: valid Rejection received when round_number < max_rounds; `current_turn` = rejecting party; round_number does NOT increment
- → REJECTED_FINAL: Rejection received when round_number = max_rounds
- → WITHDRAWN: Withdrawal sent or received
- → TIMED_OUT: round_timeout_seconds elapsed, or session_timeout_seconds elapsed
- → ERROR: protocol violation received (wrong turn, wrong sequence, invalid signature)

**Terminal states** (COMPLETED, REJECTED_FINAL, WITHDRAWN, TIMED_OUT, ERROR):
- No further state transitions are valid
- Implementations MUST return `SESSION_WRONG_STATE` for any incoming message
  for a session in a terminal state
- The audit log MUST be generated immediately upon entering any terminal state

### 8.5 Round and Sequence Counting

- `round_number` starts at 1 with the first Offer
- `round_number` increments when a Counteroffer is sent
- `round_number` does NOT increment on Rejection, Acceptance, or Withdrawal
- `sequence_number` starts at 1 and increments for every message (offers,
  counteroffers, acceptances, rejections, withdrawals)
- Retransmissions of the same message (same `message_id`) MUST NOT increment
  `sequence_number`

### 8.6 Timeout Handling

**Round timeout:** When `round_timeout_seconds` elapses after an offer is sent
without response, the sending agent SHOULD notify the counterparty:

```json
{
  "message_type": "timeout_notification",
  "message_id": "string",
  "session_id": "string",
  "timeout_type": "round",
  "sender_did": "string",
  "timestamp": "string"
}
```

Then transition locally to `TIMED_OUT`.

**Timeout after rejection:** When a party holds the turn after sending a Rejection,
the round timeout clock begins from the timestamp of the Rejection. If that party
does not send a new offer, counteroffer, or withdrawal within `round_timeout_seconds`,
the session transitions to `TIMED_OUT`.

**Grace window:** A locally triggered timeout is not final if a message with a
higher `sequence_number` is received within 30 seconds of the timeout trigger.
If such a message is received within the grace window, the timeout is cancelled and
the session continues. This prevents premature termination due to minor clock
differences or network latency.

> **Note:** The grace window assumes messages arrive in order, which is consistent
> with the strict ordering model (Section 7.1). In a bilateral protocol with only
> two message sources and a mandatory retry-until-acknowledged rule, out-of-order
> arrival within a grace window is not possible in a correctly functioning
> implementation. The grace window exists solely to handle clock skew and network
> jitter between the timeout trigger and a message that was in-flight at timeout
> time.

**Race condition on timeout:** A party that receives an HTTP 2xx acknowledgment
for a message it sent is deemed to have responded before the timeout, regardless
of clock differences. If a party sends a response and receives HTTP 2xx, but the
counterparty has already declared timeout, the party that received HTTP 2xx SHOULD
send a `timeout_notification` with `timeout_type: "dispute"` and include the
`sequence_number` of the acknowledged message, signaling to the counterparty that
a valid response was delivered.

**Session timeout:** If `session_timeout_seconds` elapses from `session_created_at`
without reaching a terminal state, any party that detects this SHOULD send a
session `timeout_notification` and transition locally to `TIMED_OUT`.

### 8.7 Impasse Detection

A soft impasse is detected when three consecutive full rounds produce no change in
`total_value` from either party. Implementations SHOULD surface soft impasse to
their principal for human review.

Impasse detection considers `total_value` only in v0.1. Multi-term impasse
detection is deferred to v0.2.

> **OPEN QUESTION OQ-005:** Should the impasse threshold (3 rounds, total_value
> only) be configurable per session? Proposed: add an optional `impasse_detection`
> object to session_params in v0.2.

---

## 9. Component 6: Transaction Record

### 9.1 Purpose

The transaction record is the authoritative document of agreed terms. It is
immutable, content-addressed, and signed by both parties. It provides the
evidentiary basis for contract formation documentation and dispute resolution.

### 9.2 Deterministic Generation

Both parties generate the transaction record independently upon seeing a valid
Acceptance. For both records to be identical, all fields MUST be deterministically
derivable from the protocol messages alone. No field MAY depend on local clock
reads or local state that could differ between parties.

### 9.3 Transaction Record Structure

Schema: `spec/schemas/transaction-record.schema.json`

```json
{
  "record_type": "a2cn_transaction_record",
  "record_version": "0.1",
  "record_id": "string",
  "session_id": "string",
  "generated_at": "string",
  "parties": {
    "initiator": {
      "organization_name": "string",
      "did": "string",
      "agent_id": "string",
      "verification_method": "string",
      "mandate_type": "string"
    },
    "responder": {
      "organization_name": "string",
      "did": "string",
      "agent_id": "string",
      "verification_method": "string",
      "mandate_type": "string"
    }
  },
  "deal_type": "string",
  "currency": "string",
  "subject": "string",
  "subject_reference": "string",
  "agreed_terms": {},
  "negotiation_summary": {
    "total_rounds": "integer",
    "total_messages": "integer",
    "session_created_at": "string",
    "first_offer_at": "string",
    "accepted_at": "string",
    "initiating_party_did": "string",
    "accepting_party_did": "string"
  },
  "final_offer": {
    "message_id": "string",
    "sender_did": "string",
    "protocol_act_hash": "string",
    "protocol_act_signature": "string"
  },
  "final_acceptance": {
    "message_id": "string",
    "sender_did": "string",
    "accepted_protocol_act_hash": "string",
    "acceptance_signature": "string"
  },
  "offer_chain_hash": "string",
  "record_hash": "string"
}
```

**`parties`** (object, REQUIRED)  
Contains initiator and responder sub-objects. Fields `organization_name` and
`agent_id` are **informational only** — they are not cryptographically bound and
MUST be derived from the corresponding fields in the SessionInit (for initiator)
and SessionAck (for responder) messages. Both parties deriving these from the same
protocol messages ensures identical values. Fields `did` and `verification_method`
are the authoritative identity references for cryptographic purposes.

**`record_id`** — UUID v5 computed from the session_id, using the A2CN-specific
namespace UUID defined in Appendix A: `f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c`.
Using a unique namespace ensures A2CN record IDs cannot collide with other UUID v5
generators.

> Note: The v0.1-draft and v0.1.1 incorrectly used an invalid namespace string
> `a2cn-0001-0000-0000-a2cn-spec-0001`. This was corrected in v0.1.2 (Appendix A)
> and the Section 9.4 inline reference is corrected here in v0.1.3.
> Implementations MUST use the A2CN namespace UUID from Appendix A.

**`generated_at`** — Set to the `timestamp` field of the Acceptance message. Both
parties derive this from the same protocol message, ensuring identical values.

**`negotiation_summary.accepted_at`** — The `timestamp` field of the Acceptance message.

**`final_offer`** — Contains fields from the accepted Offer message, regardless of
which party sent it. This replaces the v0.1-draft's party-role-specific
`initiator_offer_signature` field, which was incorrect when the responder made
the final accepted offer.

**`final_acceptance`** — Contains fields from the Acceptance message.

**`offer_chain_hash`** — SHA-256 of the JCS-serialized array of all
`protocol_act_hash` values in chronological order:
```
offer_chain_hash = SHA-256(JCS([hash_1, hash_2, ..., hash_n]))
```
Using JCS-serialized array eliminates the ambiguity of bare concatenation.

**`record_hash`** — SHA-256 of the JCS-serialized transaction record with
`record_hash` set to the empty string `""`.

### 9.5 Record Verification

Any party verifying a transaction record MUST:
1. Compute `record_hash` independently and compare
2. Verify `final_offer.protocol_act_signature` against the offering party's key
3. Verify `final_acceptance.acceptance_signature` against the accepting party's key
4. Verify `final_acceptance.accepted_protocol_act_hash` matches
   `final_offer.protocol_act_hash`
5. Recompute `offer_chain_hash` from the session message history and compare

> **OPEN QUESTION OQ-006:** Should the transaction record be submitted to a
> neutral third-party registry for authoritative storage in v0.1? Proposed:
> bilateral storage is correct for v0.1. The Meeting Place concept will provide
> optional neutral hosting in v0.2.

---

## 10. Component 7: Audit Log

### 10.1 Purpose

The audit log provides a structured record of the negotiation session. It is
generated upon entering any terminal state, for all outcomes including failures,
withdrawals, and timeouts. It supports implementation-level audit logging and
evidence collection relevant to compliance programs.

Note: Producing an A2CN audit log does not constitute legal compliance with any
specific regulation. Organizations should consult their compliance and legal
teams regarding applicable requirements.

### 10.2 Null Field Handling

Some audit log fields are not applicable to all session outcomes:
- `record_id` is null for non-COMPLETED sessions
- `first_offer_at` is null for sessions terminated before any offer was sent
- `negotiation_log` may be empty for sessions rejected at initiation

Implementations MUST explicitly include null fields rather than omitting them,
to allow audit consumers to distinguish "not applicable" from "missing data."

### 10.3 Audit Log Structure

Schema: `spec/schemas/audit-log.schema.json`

```json
{
  "log_type": "a2cn_audit_log",
  "log_version": "0.1",
  "log_id": "string",
  "session_id": "string",
  "record_id": "string | null",
  "generated_at": "string",
  "session_outcome": "string",
  "parties": {
    "initiator": {
      "organization_name": "string",
      "did": "string",
      "agent_id": "string",
      "mandate_type": "string"
    },
    "responder": {
      "organization_name": "string | null",
      "did": "string | null",
      "agent_id": "string | null",
      "mandate_type": "string | null"
    }
  },
  "session_timeline": {
    "session_init_at": "string",
    "session_ack_at": "string | null",
    "first_offer_at": "string | null",
    "terminal_state_at": "string",
    "total_duration_seconds": "integer"
  },
  "negotiation_log": [
    {
      "sequence_number": "integer",
      "message_type": "string",
      "message_id": "string",
      "sender_did": "string",
      "timestamp": "string",
      "round_number": "integer | null",
      "total_value_offered": "integer | null",
      "protocol_act_hash": "string | null"
    }
  ],
  "protocol_violations": [
    {
      "timestamp": "string",
      "violation_type": "string",
      "message_id": "string | null",
      "description": "string"
    }
  ],
  "audit_metadata": {
    "ai_system_involved": "boolean",
    "human_oversight_present": "boolean",
    "autonomous_decision": "boolean"
  }
}
```

**`audit_metadata.ai_system_involved`** (boolean, REQUIRED)  
SHOULD be set to `true` when an AI agent was involved in the negotiation.
Implementations where a human is using A2CN tooling directly without an AI
agent MAY set this to `false`.

**`audit_metadata.human_oversight_present`** (boolean, REQUIRED)  
An assertion by the implementation. Indicates whether a human was present and
able to intervene during the negotiation.

**`audit_metadata.autonomous_decision`** (boolean, REQUIRED)  
`true` if the agent made offers or accepted terms without per-round human approval.

**Important:** All `audit_metadata` fields are self-declared by the implementing
agent and are not cryptographically verifiable by the protocol. Recipients of audit
logs MUST treat these fields as attestations by the declaring party, not as
protocol-verified facts.

Note: The negotiation log records message types, hashes, and values — not full
terms content. Full terms are only in the transaction record for completed sessions.
This minimizes data retention obligations while preserving auditability.

---

## 11. Component 8: Session Invitation *(new in v0.2)*

### 11.1 Overview

The pull-based discovery model (Component 1) requires both parties to have
independently deployed `/.well-known/a2cn-agent` endpoints before a session
can be initiated. This creates a cold-start barrier: two organizations can
only negotiate via A2CN if both have already adopted the protocol.

Component 8 introduces a complementary push-based pattern. An inviting party
(typically the buyer) sends a `SessionInvitation` message to a counterparty
through any delivery channel — direct HTTP, email, the Meeting Place invitation
service, or an existing procurement platform webhook. The receiving party
evaluates the invitation, optionally activates or provisions an A2CN endpoint,
and responds with their endpoint details. The inviting party then proceeds with
a standard `SessionInit` (Component 3).

**The invitation does not replace the session initiation flow.** It is a
pre-session handshake that enables adoption by parties without pre-deployed
endpoints. Once both endpoints are known, the standard A2CN session protocol
applies unchanged.

### 11.2 SessionInvitation Message

A `SessionInvitation` is a signed JSON document transmitted to a counterparty
before session initiation. It MUST be signed using the inviting party's DID key
so the recipient can verify its authenticity.

```json
{
  "message_type": "session_invitation",
  "invitation_id": "uuid-v4",
  "a2cn_version": "0.2",
  "inviter_did": "did:web:buyer.example",
  "inviter_endpoint": "https://buyer.example/api/a2cn",
  "inviter_discovery_url": "https://buyer.example/.well-known/a2cn-agent",
  "proposed_deal_type": "goods_procurement",
  "proposed_session_params": {
    "currency": "USD",
    "max_rounds": 5,
    "session_timeout_seconds": 86400,
    "round_timeout_seconds": 3600
  },
  "proposed_terms_summary": {
    "description": "Industrial hydraulic fluid — 200L drums, quantity 50",
    "estimated_value": 18000,
    "currency": "USD"
  },
  "inviter_mandate_summary": {
    "mandate_type": "declared",
    "max_commitment_value": 25000,
    "authorized_deal_types": ["goods_procurement"]
  },
  "invitation_expires_at": "2026-04-03T17:00:00Z",
  "accept_endpoint": "https://buyer.example/api/a2cn/invitations/{invitation_id}/accept",
  "decline_endpoint": "https://buyer.example/api/a2cn/invitations/{invitation_id}/decline",
  "inviter_verification_method": "did:web:buyer.example#key-2026-01",
  "invitation_signature": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### 11.2.1 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `message_type` | string | MUST be `"session_invitation"` |
| `invitation_id` | string | UUID v4 — unique identifier for this invitation |
| `a2cn_version` | string | MUST be `"0.2"` or later |
| `inviter_did` | string | DID of the inviting party |
| `inviter_endpoint` | string | HTTPS URL where the inviter's A2CN responder can be reached |
| `inviter_discovery_url` | string | URL of inviter's `/.well-known/a2cn-agent` document |
| `proposed_deal_type` | string | Deal type string from inviter's discovery document |
| `proposed_session_params` | object | Proposed session parameters (non-binding; may be negotiated in SessionInit) |
| `proposed_terms_summary` | object | Human-readable summary of what is being negotiated |
| `inviter_mandate_summary` | object | Summary of the inviter's mandate authority |
| `invitation_expires_at` | string | ISO 8601 UTC timestamp after which invitation is void |
| `accept_endpoint` | string | HTTPS URL to POST acceptance to |
| `decline_endpoint` | string | HTTPS URL to POST decline to |
| `inviter_verification_method` | string | Verification method ID used to sign the invitation |
| `invitation_signature` | string | Base64url-encoded ES256 signature over the canonical invitation object |

#### 11.2.2 Invitation Signature

The invitation MUST be signed before transmission. Signing procedure:

1. Construct the invitation object with all required fields EXCEPT `invitation_signature`
2. Serialize to canonical JSON using RFC 8785 JCS
3. Compute SHA-256 hash of the canonical bytes
4. Sign the hash with ES256 using the key identified by `inviter_verification_method`
5. Base64url-encode the signature and set as `invitation_signature`

Recipients MUST:
1. Resolve the inviter's DID document to obtain the public key at `inviter_verification_method`
2. Verify the signature against the canonical invitation object (excluding `invitation_signature`)
3. Reject invitations with invalid signatures with HTTP 400

Recipients MUST NOT act on invitations that fail signature verification.

#### 11.2.3 Invitation Lifecycle

```
                    ┌────────────┐
                    │  PENDING   │ ← invitation delivered
                    └──────┬─────┘
             ┌─────────────┼─────────────┐
             │             │             │
        ┌────▼─────┐  ┌────▼─────┐  ┌───▼──────┐
        │ ACCEPTED │  │ DECLINED │  │ EXPIRED  │
        └──────────┘  └──────────┘  └──────────┘
              │
              ▼
        Standard SessionInit
        proceeds (Component 3)
```

Invitations MUST expire at `invitation_expires_at`. Expired invitations MUST
NOT be processed. Implementations SHOULD delete invitation state 30 days after
expiry.

### 11.3 Invitation Acceptance

The invited party responds to an invitation by POSTing an acceptance to the
`accept_endpoint`. The acceptance tells the inviting party where to send the
`SessionInit`.

```json
{
  "message_type": "invitation_acceptance",
  "invitation_id": "uuid-v4 (echoed from invitation)",
  "acceptor_did": "did:web:seller.example",
  "acceptor_a2cn_endpoint": "https://seller.example/api/a2cn",
  "acceptor_discovery_url": "https://seller.example/.well-known/a2cn-agent",
  "accepted_at": "2026-04-02T09:14:22Z",
  "acceptor_verification_method": "did:web:seller.example#key-2026-01",
  "acceptance_signature": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

The acceptance MUST be signed using the same procedure as the invitation
signature (Section 11.2.2), using the acceptor's DID key.

Upon receiving a valid acceptance, the inviting party MUST:
1. Verify the `invitation_id` matches a pending invitation
2. Verify the acceptance signature against the acceptor's DID document
3. Verify `accepted_at` is before `invitation_expires_at`
4. Proceed with a standard `SessionInit` (Section 6) directed at `acceptor_a2cn_endpoint`

The inviting party's `SessionInit` MUST reference `invitation_id` in the optional
`invitation_id` field so the acceptor can correlate the session with the invitation.

### 11.4 Invitation Decline

The invited party MAY decline an invitation by POSTing to the `decline_endpoint`:

```json
{
  "message_type": "invitation_decline",
  "invitation_id": "uuid-v4 (echoed from invitation)",
  "reason_code": "DEAL_TYPE_NOT_SUPPORTED | MANDATE_INSUFFICIENT | CAPACITY | OTHER",
  "reason_message": "Human-readable explanation (optional)",
  "declined_at": "2026-04-02T09:14:22Z"
}
```

Declines are informational. The inviting party SHOULD record the decline for
audit purposes. The inviting party MAY fall back to alternative negotiation
channels (email, supplier portal) after receiving a decline.

### 11.5 Invitation Delivery Channels

The A2CN protocol defines the `SessionInvitation` message format and lifecycle.
It does not mandate a specific delivery mechanism. Implementations MUST support
at least one of the following delivery channels:

**Direct HTTP:** Inviting party POSTs the `SessionInvitation` to a known HTTPS
endpoint at the counterparty's domain. Appropriate when the counterparty has a
known web presence but no A2CN endpoint yet.

**Meeting Place Delivery:** The inviting party submits the `SessionInvitation`
to the Meeting Place's invitation service, which delivers via the counterparty's
preferred channel (email, webhook, or directly if they have a registered endpoint).
The Meeting Place records the invitation and acceptance/decline for audit purposes.
This is the RECOMMENDED delivery channel for counterparties without known A2CN
endpoints.

**Platform Webhook Integration:** Buyer-side procurement platforms (e.g., Fairmarkit,
Zip) MAY deliver `SessionInvitation` documents through existing supplier webhook
infrastructure. When a sourcing event is initiated, the platform delivers both a
traditional supplier invitation AND a machine-readable `SessionInvitation` to the
same supplier endpoint. Suppliers that have an A2CN-capable webhook handler can
accept via A2CN; others receive only the traditional invitation.

**Example: Fairmarkit Integration Pattern**

When Fairmarkit initiates a sourcing event, for each invited supplier it:

1. Checks `/.well-known/a2cn-agent` at the supplier's domain
2. If the endpoint exists: initiates standard A2CN `SessionInit` directly
3. If the endpoint does not exist: delivers `SessionInvitation` via:
   - The `BID_CREATED` webhook (if the supplier has configured a webhook URL in Fairmarkit)
   - The Fairmarkit email invitation (with the `SessionInvitation` JSON as an attachment)
   - The Meeting Place invitation service (if configured)

The supplier's A2CN agent, upon receiving the `SessionInvitation`, responds to
the `accept_endpoint`. Fairmarkit's buyer agent then sends a `SessionInit` to the
supplier's newly-activated endpoint. The resulting A2CN transaction record is
submitted back to Fairmarkit via `POST /self-service/api/v3/responses/...` as the
award data.

### 11.6 Hosted Endpoint Provisioning (Meeting Place Pattern)

The Meeting Place MAY offer hosted A2CN endpoint provisioning to allow suppliers
to participate in A2CN sessions without deploying their own server infrastructure.
When a supplier accepts an invitation through the Meeting Place's interface:

1. The Meeting Place provisions a session-scoped A2CN endpoint on the supplier's behalf
2. The supplier configures negotiation parameters via a web interface: minimum acceptable
   price, maximum discount percentage, acceptable payment terms, delivery flexibility
3. The Meeting Place's hosted agent conducts the session within these constraints
4. The resulting transaction record notes `"hosted_endpoint": true` and `"hosted_by": "meeting-place.a2cn.dev"`
5. Both parties receive the standard dual-signed transaction record

**Mandate for hosted endpoints:** The Meeting Place MUST generate a Tier 1
(Declared) mandate scoped to the parameters the supplier has configured. The
mandate's `max_commitment_value` MUST NOT exceed what the supplier explicitly
authorized. The Meeting Place MUST NOT commit to terms outside the supplier's
configured bounds.

Hosted endpoint sessions are fully interoperable with self-hosted A2CN endpoints.
The buyer agent cannot distinguish a hosted endpoint from a self-hosted one
at the protocol level.

### 11.7 Invitation Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `INVITATION_EXPIRED` | 410 | Invitation `invitation_expires_at` has passed |
| `INVITATION_NOT_FOUND` | 404 | `invitation_id` not recognized |
| `INVITATION_SIGNATURE_INVALID` | 400 | Signature verification failed |
| `INVITATION_ALREADY_ANSWERED` | 409 | Invitation already accepted or declined |
| `INVITATION_VERSION_MISMATCH` | 400 | `a2cn_version` not supported |

---

## 12. Transport Binding

### 11.1 HTTP/REST Binding (Normative)

A2CN v0.1 defines one normative transport: HTTP/REST. All implementations MUST
support this binding.

#### 11.1.1 Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/sessions` | Create session (SessionInit) |
| GET | `/sessions/{id}` | Get session state object |
| POST | `/sessions/{id}/messages` | Send any session message |
| GET | `/sessions/{id}/messages` | Get message history (paginated) |
| GET | `/sessions/{id}/record` | Get transaction record (COMPLETED only) |
| GET | `/sessions/{id}/audit` | Get audit log (any terminal state) |

#### 11.1.2 Pagination

`GET /sessions/{id}/messages` MUST support cursor-based pagination:
- `?after_sequence={n}` returns messages with `sequence_number` > n
- Response MUST include a `next_cursor` field (null if no more messages)
- Page size SHOULD default to 50 and MUST be configurable via `?limit={n}`

#### 11.1.3 Idempotency Keys

All `POST` requests MUST include an `Idempotency-Key` header equal to the
`message_id` of the message being sent. Servers MUST use this header (alongside
the message body's `message_id`) to implement idempotency per Section 6.1.

#### 11.1.4 Authentication

Every request MUST include `Authorization: Bearer {jwt}`.

JWT requirements:
- Algorithm: ES256
- `iss`: Sender's DID
- `aud`: Receiver's DID
- `iat`: Current Unix timestamp
- `exp`: `iat` + 60 seconds (session messages); `iat` + 300 seconds (session init only)
- `jti`: Unique JWT ID (REQUIRED; used for anti-replay)
- `session_id`: Current session ID (REQUIRED for all messages except session init)

Receivers MUST reject JWTs with expired `exp`, mismatched `aud`, failed signature
verification, or `jti` values seen within the last 600 seconds.

Clock skew: Receivers SHOULD accept timestamps within 30 seconds of the receiver's
clock. Receivers MUST NOT accept timestamps more than 30 seconds in the future.

Key verification: The receiver MUST resolve the sender's DID document and verify
the JWT against the verification method referenced in the sender's discovery
document. Receivers MUST NOT verify JWTs using keys embedded in the discovery
document directly.

#### 11.1.5 HTTP Status Codes

| Status | Meaning in A2CN context |
|--------|------------------------|
| 200 | Success |
| 201 | Session or record created |
| 400 | Malformed request, invalid JSON |
| 401 | JWT authentication failure |
| 403 | Authorization failure (mandate invalid, wrong deal type) |
| 404 | Session not found |
| 406 | Unsupported content type requested via Accept header |
| 409 | Session wrong state (terminal or wrong-turn) |
| 422 | Semantically invalid (round exceeded, expired offer, wrong type) |
| 429 | Rate limited |
| 503 | DID resolution failure (temporary) |

#### 11.1.6 Webhook Callbacks (RECOMMENDED)

Implementations SHOULD support webhook callbacks to avoid polling overhead.

SessionInit MAY include a `webhook_url` field in `metadata`:
```json
"metadata": {
  "a2cn.webhook_url": "https://initiator.example.com/a2cn/callbacks"
}
```

If a `webhook_url` is provided, the receiving party SHOULD POST incoming messages
to that URL in addition to making them available via the polling endpoint.

Webhook POST requests MUST include the same `Authorization: Bearer {jwt}` header
as standard A2CN requests. Webhook JWTs MUST have `iss` set to the webhook
sender's DID and `aud` set to the webhook receiver's DID. Webhook receivers MUST
resolve the sender's DID document and verify the JWT against the sender's declared
`verification_method` before processing the callback.

Webhook delivery is best-effort. The polling endpoint remains the authoritative
source. Implementations MUST NOT rely exclusively on webhooks.

#### 11.1.7 Version Negotiation

The `protocol_version` field in SessionInit declares the initiator's version.
If the responder does not support the declared version, it MUST reject with
`PROTOCOL_VERSION_MISMATCH`. The responder MUST NOT silently accept and process
an unsupported version.

Backward compatibility expectations: minor versions within 0.x are not guaranteed
compatible. v1.0 and beyond will define compatibility guarantees.

#### 11.1.8 Content Type

All A2CN requests and responses MUST use `Content-Type: application/a2cn+json`.
Servers MUST return `406 Not Acceptable` if a client requests a different type
via `Accept` header for a content type that is not supported.

---

## 12. Error Handling

### 12.1 Error Response Format

All A2CN errors use a single format regardless of whether they occur during
session initiation or message exchange:

```json
{
  "error": {
    "code": "string",
    "message": "string",
    "detail": "string",
    "timestamp": "string",
    "session_id": "string | null",
    "message_id": "string | null"
  }
}
```

SessionReject messages also use this format via the `error_code` and
`error_message` fields for consistency.

### 12.2 Error Code Reference

| Code | HTTP | Permanent? | Description |
|------|------|------------|-------------|
| `PROTOCOL_VERSION_MISMATCH` | 400 | Yes | Version not supported |
| `DEAL_TYPE_NOT_SUPPORTED` | 403 | Yes | Deal type not in discovery |
| `MANDATE_INVALID` | 403 | Yes | Mandate expired, missing, or VC proof failed |
| `MANDATE_INSUFFICIENT` | 403 | Yes | Mandate scope doesn't cover proposed terms |
| `INVALID_SIGNATURE` | 400 | Yes | Protocol act signature verification failed |
| `WRONG_MESSAGE_TYPE` | 422 | Yes | e.g., "offer" received in round 2+ |
| `NOT_YOUR_TURN` | 409 | Yes | Message sent out of turn |
| `SESSION_NOT_FOUND` | 404 | Yes | Session ID not recognized |
| `SESSION_WRONG_STATE` | 409 | Yes | Message invalid for current session state |
| `ROUND_LIMIT_EXCEEDED` | 422 | Yes | Message would exceed max_rounds |
| `OFFER_EXPIRED` | 422 | Yes | Acceptance of expired offer attempted |
| `OFFER_HASH_MISMATCH` | 400 | Yes | Acceptance hash doesn't match offer hash |
| `SEQUENCE_ERROR` | 422 | Yes | Gap or duplicate in sequence_number |
| `DID_RESOLUTION_FAILURE` | 503 | No | DID temporarily unresolvable |
| `DID_NOT_FOUND` | 403 | Yes | DID does not exist (permanent) |
| `RATE_LIMITED` | 429 | No | Too many requests (retry after header present) |
| `INTERNAL_ERROR` | 500 | No | Implementation error |

Note: `DID_RESOLUTION_FAILURE` (503) is a temporary condition; the client SHOULD
retry with backoff. `DID_NOT_FOUND` (403) is permanent; the client MUST NOT retry.

---

## 13. Security Considerations

### 13.1 Replay Attack Prevention

**In-session:** Each message includes a unique `message_id` and a monotonically
increasing `sequence_number`. Implementations MUST reject messages with
`message_id` values already seen in the session.

**Pre-session:** The `(sender_did, jti, "a2cn_session_init")` tuple is tracked
in the pre-session anti-replay store for 600 seconds (Section 6.2).

**JWT replay:** JWTs include a `jti` that MUST be tracked in a short-lived store.
Any JWT with a previously seen `jti` from the same `iss` MUST be rejected within
a 600-second window.

**Cross-session offer replay:** Prevented by including `session_id` and
`round_number` in the signed protocol act (Section 7.3).

### 13.2 Session Hijacking

Session IDs are sufficiently random to prevent guessing. Combined with JWT
authentication on every request, knowledge of a session ID alone is insufficient
to inject messages.

### 13.3 Transport Security

All A2CN transport MUST use TLS 1.2 or higher. Certificate validation MUST NOT
be disabled. TLS protects against passive eavesdropping. The message-level
signature scheme (protocol act signing) provides non-repudiation even if TLS
is compromised in transit.

### 13.4 Discovery Document Integrity

The discovery document is not cryptographically signed in v0.1. This is a known
limitation. Mitigations:

1. All signing keys are retrieved from DID documents, not from the discovery
   document. An attacker who serves a modified discovery document cannot forge
   valid signatures without also compromising the DID document.
2. For `did:web`, the DID document is at `{domain}/.well-known/did.json`. An
   attacker who controls the domain can compromise both the discovery document
   AND the DID document simultaneously. This is a known limitation of `did:web`.
   **For `did:web` deployments, the security of the entire A2CN protocol chain
   depends on the security of the organization's DNS and web hosting infrastructure.**
   Organizations using `did:web` SHOULD implement:
   - Certificate transparency monitoring for their TLS certificates
   - DNSSEC for their domain
   - Multi-party authorization requirements for changes to `/.well-known/` paths
   - Change alerting for `/.well-known/a2cn-agent` and `/.well-known/did.json`
3. Implementations SHOULD cache discovery documents and alert on key material
   changes between fetches.
4. Signed discovery documents are planned for v0.2. Organizations with high
   security requirements SHOULD use a DID method other than `did:web` that
   provides stronger guarantees (e.g., `did:key` for read-only identities,
   or blockchain-anchored DIDs).

### 13.5 Mandate Scope Enforcement

Implementations SHOULD compare `agreed_terms.total_value` against the mandate's
`max_commitment_value` before generating a transaction record and SHOULD surface
mismatches for human review.

### 13.6 Prompt Injection

A2CN messages contain free-text fields (`subject`, `reason_description`,
`custom_terms` values, `scope_description`). If these fields are passed to
an LLM without sanitization, they may contain injected instructions designed
to manipulate the agent's negotiation behavior.

Mitigations:
- Implementations MUST treat all free-text fields from counterparty messages
  as untrusted external input
- Free-text fields SHOULD be passed to LLMs only after explicit sanitization
  or via structured prompts that isolate the content from the instruction context
- Implementations SHOULD log any unexpected content in free-text fields

### 13.7 Denial of Service

Implementations MUST implement rate limiting. Recommended limits:
- 100 session initiations per organization DID per hour
- 1000 message POSTs per session per hour

`429 Too Many Requests` responses MUST include a `Retry-After` header.

### 13.8 Economic Attack — Echoing

A2CN's structured offer schema is the primary defense against LLM echoing
behavior (documented by Salesforce AI Research). By forcing the exchange into
discrete typed JSON offers with explicit `total_value` integers rather than
natural language, agents cannot drift toward agreement on bad terms via
accommodating language. However, implementations using LLMs to generate offer
content remain vulnerable to echoing in the *reasoning* that produces the offer.
This is an implementation concern, not a protocol concern.

---

## 15. Open Questions

Open questions carry stable IDs across versions. Resolved questions are marked
with their resolution version rather than being renumbered.

| ID | Question | Status | Resolution / Proposed |
|----|----------|--------|-----------------------|
| OQ-001 | Deal type registry vs convention | **RESOLVED v0.2** | Registry published at `a2cn.dev/registry/deal-types`. Core types: `saas_renewal`, `goods_procurement`, `services_engagement`, `logistics_rate`. Community-submitted types via GitHub PR. |
| OQ-002 | Max value threshold protocol cap | Open | $10K USD equivalent cap under consideration; v0.3 |
| OQ-003 | DID resolver fallback when temporarily unavailable | Open | 24h cache allowed |
| OQ-004 | Deal-type-specific terms schemas | **RESOLVED v0.2** | `goods_procurement` and `saas_renewal` schemas defined in Section 18 and `spec/schemas/terms/`. Additional types via extension pattern. |
| OQ-005 | Configurable impasse threshold | **RESOLVED v0.2** | `impasse_threshold` field added to `session_params`. Default 3 consecutive rounds with no movement triggers IMPASSE state. Configurable 1–10. |
| OQ-006 | Neutral transaction record storage | Open | Bilateral for v0.1/v0.2; Meeting Place in v0.3 |
| OQ-007 | Neutral transaction record storage (original) | **RESOLVED v0.1.1** | Bilateral storage correct for v0.1 |
| OQ-008 | Webhooks alongside polling | **RESOLVED v0.1.1** | Promoted to RECOMMENDED; promoted to REQUIRED at Level 2 in v0.2 |
| OQ-009 | Platform DID proxy model | Open | Buyer-side platforms (Pactum, Fairmarkit, Zip) negotiate on behalf of enterprise customers whose DID is not the platform's own DID. Proposed: allow `did:web:platform.ai:customers:{customer-id}` pattern; platform serves the DID document; mandate credential scopes to customer organization. v0.3. |
| OQ-010 | MESO (Multiple Equivalent Simultaneous Offers) | Open | Pactum's negotiation model presents bundled packages where the counterparty chooses between equivalent options (e.g., lower price vs. longer payment terms). Current offer schema is single-option. Proposed: `alternatives` array on Offer model. v0.3. |
| OQ-011 | A2CN as A2A extension | Open | A2A's extension system supports profile extensions (DataPart schemas) and method extensions (new RPC methods). A2CN's offer exchange and session state machine could be implemented as an A2A extension. Proposal to A2A governance pending. |
| OQ-012 | Reverse auction / multi-party invitation | Open | Fairmarkit's reverse auction model involves one buyer inviting multiple competing suppliers. Session Invitation (Component 8) covers bilateral invitation. Multi-party sourcing events where multiple supplier sessions run concurrently are out of scope for v0.2. |
| OQ-013 | DID VC mandate for hosted endpoints | Open | When the Meeting Place hosts an A2CN endpoint on behalf of a supplier, the mandate is Tier 1 (Declared) by design. Whether the Meeting Place can issue a Tier 2 (DID VC) mandate on behalf of a supplier requires further analysis of the trust model. |

Submit feedback via GitHub issues tagged `open-question`.

---

## 16. Relationship to Other Protocols

### 16.1 MCP (Model Context Protocol)

A2CN and MCP are complementary and operate at different layers. During an A2CN
negotiation, each party's agent uses MCP to access its own internal systems —
pricing engines, inventory databases, mandate repositories, ERP data. MCP governs
the agent-to-tool connection. A2CN governs the agent-to-agent exchange.

A2CN SHOULD be implemented as an MCP tool so MCP-compatible agents can initiate
A2CN sessions via standard tool-calling. Any agent framework that supports MCP
(LangChain, CrewAI, Salesforce Agentforce, Microsoft Copilot Studio) can then
invoke A2CN sessions without requiring protocol-specific SDK integration.

**Microsoft Dynamics 365 ERP MCP Server integration pattern:**
The Dynamics 365 ERP MCP server (GA February 2026) exposes pricing, inventory,
and order creation logic through MCP Action tools. An A2CN-compatible seller agent
built on Dynamics 365 uses the following integration pattern:

```
A2CN SessionInit received
  → MCP Action tool: NegotiationResponseCalculator
     input: {buyer_offer_price, quantity, payment_terms}
     output: {seller_response_price, minimum_acceptable, discount_bounds}
  → A2CN Offer generated from output
  → A2CN session continues

A2CN Acceptance received
  → A2CN Transaction Record generated
  → MCP Action tool: CreateOrderFromAgreement
     input: {agreed_terms from transaction_record.agreed_terms}
  → ERP order created
```

The MCP Action tools are custom classes implementing the `ICustomAPI` interface,
registered through the Dynamics 365 ERP MCP server's `api_find_actions` /
`api_invoke_action` mechanism. The A2CN adapter layer calls these tools rather
than implementing pricing logic directly.

### 16.2 A2A (Agent-to-Agent Protocol)

A2A (Google/Linux Foundation, v0.3, 21,700+ GitHub stars) is the emerging
standard for agent-to-agent communication and capability negotiation. A2A and
A2CN are complementary: use A2A for agent discovery and initial communication,
then invoke A2CN as a specialized task type for the commercial negotiation phase.

A2CN should not be confused with A2A's internal "negotiation" — A2A's negotiation
is capability negotiation (what features do you support), not commercial negotiation
(what price will you accept).

**A2A Extension Pattern:** A2A's extension system supports three extension types:
- **Profile extensions:** Require DataParts to follow specific schemas
- **Method extensions:** Add new RPC methods and state machines
- **Data-only extensions:** Add fields to AgentCards

A2CN's offer/counteroffer schema is a profile extension. A2CN's session state
machine is a method extension. A2CN's discovery document fields map to data-only
AgentCard extensions. A formal A2A extension proposal implementing A2CN as an A2A
extension is pending with A2A governance (see OQ-011).

**Precedent:** UCP (Universal Commerce Protocol) and AP2 (payment authorization)
are both implemented as A2A extensions. The pattern is documented and supported.

### 16.3 Salesforce Revenue Cloud / Agentforce for Revenue

Salesforce Revenue Cloud Advanced (API-first, headless architecture) exposes
quote and pricing logic through documented REST endpoints:

```
POST /services/data/v65.0/connect/qoc/sales-transactions
GET  /services/data/v65.0/connect/pricing/...
POST /services/data/v65.0/connect/qoc/sales-transactions (transactionType: Order)
```

An A2CN adapter for Salesforce sellers uses the following integration pattern:

```
A2CN SessionInit received
  → Revenue Cloud Pricing API: calculate initial offer
     POST /connect/pricing/...
     {product_ids, quantity, account_id, requested_discount}
     → returns {calculated_price, approved_discount_range}
  → A2CN Offer generated from calculated_price

A2CN Counteroffer received
  → Revenue Cloud Pricing API: validate proposed terms
     (is counteroffered price within approved_discount_range?)
  → A2CN Accept / CounterOffer / Reject based on result

A2CN Agreement reached
  → A2CN Transaction Record generated (dual-signed)
  → Revenue Cloud Transaction API: create order from agreement
     POST /connect/qoc/sales-transactions
     {transactionType: "Order", agreed_terms from record}
```

Agentforce for Revenue (launched August 2025) generates quotes from natural
language via the Agent Builder platform. These quotes can be wrapped in A2CN
offer messages when the buyer is an agent rather than a human. The quote
generation and A2CN session management are separate concerns — Revenue Cloud
produces the offer terms; A2CN provides the bilateral exchange protocol.

### 16.4 Fairmarkit

Fairmarkit's developer API (developers.fairmarkit.com) exposes documented
webhooks and REST endpoints that enable A2CN integration without requiring
Fairmarkit platform changes.

**Path A — A2CN as buyer outreach channel:**
When Fairmarkit initiates a sourcing event, for each supplier it attempts
discovery at `/.well-known/a2cn-agent`. For A2CN-capable suppliers, the
buyer agent initiates an A2CN session instead of sending an email invitation.
The A2CN transaction record's `agreed_terms` are submitted as the award
via `POST /self-service/api/v3/responses/...`. The ERP writeBack flow is
unchanged.

**Path B — Supplier-side A2CN agent on Fairmarkit events:**
Fairmarkit exposes a `BID_CREATED` webhook that fires when a supplier is
invited to an event. A supplier with an A2CN-capable agent can configure this
webhook to trigger the Session Invitation acceptance flow. The supplier agent
processes the sourcing event data, responds to the inviting party's
`accept_endpoint`, and negotiates via A2CN. The resulting terms are submitted
to Fairmarkit via the existing response API.

**Data model mapping — Fairmarkit → A2CN `goods_procurement` terms:**

| Fairmarkit field | A2CN `goods_procurement` terms field |
|-----------------|--------------------------------------|
| Line item description | `line_items[].description` |
| Quantity | `line_items[].quantity` |
| Unit of measure (UOM) | `line_items[].unit_of_measure` |
| Unit price | `line_items[].unit_price` |
| Delivery days | `delivery_days` |
| MFG part number | `line_items[].manufacturer_part_number` |
| Internal part number | `line_items[].internal_part_number` |
| Benchmark price | Not transmitted (internal buyer reference) |

### 16.5 AP2

AP2 operates downstream of A2CN. After A2CN generates a transaction record,
that record provides the agreed terms for AP2's mandate structure:

```
A2CN session completes
  → Transaction Record generated
  → Transaction Record terms used as AP2 Intent Mandate
  → AP2 handles payment authorization and execution
```

### 16.6 Luminance (Contract Formalization)

Luminance's Autonomous Negotiation (spring 2026 full launch) handles bilateral
contract language negotiation — redlines, clause alternatives, markup acceptance
— operating within Microsoft Word. A2CN handles the commercial term negotiation
phase that precedes contract formalization.

The sequential relationship:

```
A2CN session: agree on price, payment terms, duration, scope
  → A2CN Transaction Record: dual-signed record of agreed commercial terms
    → Luminance session: formalize agreed terms into contract language
      → Signed contract
```

A2CN transaction records SHOULD be passed to the contract formalization phase
as the authoritative statement of agreed commercial terms. This eliminates
re-negotiation of commercial terms during contract drafting — only legal language
is negotiated, not the underlying economics.

### 16.7 UCP

UCP is a consumer retail checkout protocol. Its published roadmap covers B2C
scenarios. B2B commercial negotiation is not on the UCP roadmap. A2CN does not
compete with UCP.

---

## 16. Conformance

### 16.1 Conformant Implementation

A software system is a **conformant A2CN implementation** if it:

1. Implements the HTTP/REST transport binding (Section 11.1)
2. Implements discovery document publishing and consumption (Section 4)
3. Correctly implements all state machine transitions (Section 8)
4. Implements turn-taking enforcement per Section 3.2
5. Implements idempotency per Section 6.1
6. Generates protocol act signatures per Section 7.3 using RFC 8785 JCS
7. Generates transaction records per Section 9
8. Generates audit logs per Section 10
9. Implements all error codes from Section 12
10. Passes the A2CN conformance test suite at `spec/conformance-tests/`
11. Produces messages that validate against the normative JSON Schemas at
    `spec/schemas/`

### 16.2 Conformance Levels

Protocol act signing using RFC 8785 JCS (Section 7.3) is REQUIRED at ALL
conformance levels. It is not a Level 2 feature — it is a universal requirement
for any conformant implementation.

**Level 1 — Core:** Discovery, session initiation, offer exchange with full
protocol act signing, session state machine, turn-taking, idempotency, and
compliance with all MUST requirements in Sections 3–13. Declared mandates only.
DID VC mandate verification is not required at Level 1.

**Level 2 — Full:** All Level 1 requirements, plus DID VC mandate verification
(Section 5.4–5.5), transaction record generation (Section 9), audit log
generation (Section 10), and webhook callbacks (Section 12.1.6). Webhooks are
promoted from RECOMMENDED to REQUIRED at Level 2 in v0.2.

**Level 3 — Extended:** All Level 2 requirements, plus Session Invitation support
(Component 8, Section 11), impasse detection (Section 8.7), MESO terms support
(Section 7.2.3), hosted endpoint provisioning (Section 11.6), and all RECOMMENDED
behaviors throughout the specification.

Implementations MUST declare their conformance level in their discovery document
using the field `"conformance_level": 1 | 2 | 3`. This field is REQUIRED.

**Level interoperability:** Before initiating a session, the initiator SHOULD
inspect the responder's `conformance_level` and `mandate_methods` in their
discovery document. The initiator MUST NOT initiate a session requiring
capabilities above the responder's declared conformance level. In particular,
a Level 1 initiator MUST NOT attempt to present a DID VC mandate to a Level 1
responder that does not declare `"did_vc"` in `mandate_methods`.

---

## 17. Normative JSON Schemas

Normative JSON schemas for all message types are published at
`spec/schemas/` in the repository. As of v0.1.2, these schemas are **normative**.
A conformant implementation MUST produce messages that validate against these
schemas. The following schema files are defined:

| File | Message Type |
|------|-------------|
| `discovery.schema.json` | Discovery document |
| `declared-mandate.schema.json` | Tier 1 mandate |
| `did-vc-mandate.schema.json` | Tier 2 mandate |
| `session-init.schema.json` | SessionInit |
| `session-ack.schema.json` | SessionAck |
| `session-reject.schema.json` | SessionReject |
| `offer.schema.json` | Offer and Counteroffer |
| `acceptance.schema.json` | Acceptance |
| `rejection.schema.json` | Rejection |
| `withdrawal.schema.json` | Withdrawal |
| `timeout-notification.schema.json` | Timeout notification |
| `transaction-record.schema.json` | Transaction record |
| `audit-log.schema.json` | Audit log |
| `session-object.schema.json` | Session state object |
| `error.schema.json` | Error response |

Schemas are **normative** as of v0.1.2. Conformant implementations MUST produce
messages that validate against these schemas.

---

## 19. Changelog

### v0.2.0 (2026-03-26) — Current

**New: Component 8 — Session Invitation**

Introduced push-based session invitation to address the cold-start adoption
barrier in the pull-based discovery model. Key additions:

- `SessionInvitation` message type with signed JSON schema, full field
  specification, and lifecycle (PENDING → ACCEPTED/DECLINED/EXPIRED)
- `InvitationAcceptance` and `InvitationDecline` message types
- Invitation signature procedure using RFC 8785 JCS + ES256
- Three delivery channels defined: Direct HTTP, Meeting Place, Platform Webhook
- Meeting Place hosted endpoint provisioning pattern (supplier participates
  in A2CN sessions without deploying their own server)
- Fairmarkit integration pattern documented as normative example:
  `BID_CREATED` webhook triggers Session Invitation acceptance; A2CN session
  terms submitted as Fairmarkit response via `/self-service/api/v3/responses/...`
- Seven new error codes: `INVITATION_EXPIRED`, `INVITATION_NOT_FOUND`,
  `INVITATION_SIGNATURE_INVALID`, `INVITATION_ALREADY_ANSWERED`,
  `INVITATION_VERSION_MISMATCH`
- `invitation_id` optional field added to `SessionInit` for correlation
- New conformance schema: `session-invitation.schema.json`,
  `invitation-acceptance.schema.json`, `invitation-decline.schema.json`

**Resolved open questions:**

- **OQ-001 RESOLVED:** Deal type registry published at `a2cn.dev/registry/deal-types`.
  Core types: `saas_renewal`, `goods_procurement`, `services_engagement`,
  `logistics_rate`. Community-submitted types via GitHub PR against the registry file.

- **OQ-004 RESOLVED:** Deal-type-specific terms schemas added:
  - `goods_procurement` schema adds: `delivery_days`, `unit_of_measure`,
    `manufacturer_part_number`, `internal_part_number`, `line_items[].quantity`,
    `line_items[].unit_price` as defined fields with types
  - `saas_renewal` schema adds: `subscription_tier`, `seat_count`,
    `support_tier`, `auto_renew_terms`, `uptime_sla_percent` as defined fields
  - Both schemas published at `spec/schemas/terms/`

- **OQ-005 RESOLVED:** `impasse_threshold` field added to `session_params`.
  Optional integer, range 1–10, default 3. When `max_rounds - rounds_remaining`
  consecutive rounds pass with no movement in `total_value` greater than 0.5%,
  the session transitions to IMPASSE. Both parties receive a `timeout_notification`
  with `timeout_type: "impasse"`.

**Promoted: Webhooks REQUIRED at Level 2**

Webhook callbacks (Section 12.1.6) promoted from RECOMMENDED to REQUIRED for
Level 2 conformance. Motivation: enterprise procurement platforms (Pactum,
Fairmarkit, Zip, SAP) use event-driven architectures where polling is
operationally inappropriate. Round responses in enterprise procurement can take
hours; implementations that do not support webhooks cannot interoperate reliably
with enterprise platforms.

**Section 16 expanded: Relationship to Other Protocols**

Sections substantially rewritten and expanded with concrete integration patterns:
- Section 16.1 MCP: Added Microsoft Dynamics 365 ERP MCP Server integration
  pattern with `NegotiationResponseCalculator` and `CreateOrderFromAgreement`
  action tool pattern
- Section 16.2 A2A: Added formal A2A extension mechanism description; filed
  extension proposal with A2A governance (OQ-011)
- Section 16.3 Salesforce Revenue Cloud: Added integration pattern with
  `/connect/pricing/...` and `/connect/qoc/sales-transactions` endpoints
- Section 16.4 Fairmarkit: Added two integration paths (buyer outreach channel;
  supplier-side agent) with Fairmarkit webhook and API references; added
  Fairmarkit → A2CN terms field mapping table
- Section 16.6 Luminance: Documented sequential relationship: A2CN handles
  commercial term negotiation, Luminance handles contract language formalization

**New open questions:**

- OQ-009: Platform DID proxy model — how buyer-side platforms (Pactum, Fairmarkit)
  represent enterprise customer DIDs
- OQ-010: MESO (Multiple Equivalent Simultaneous Offers) terms extension for
  Pactum-style bundle negotiations
- OQ-011: A2CN as A2A extension — formal proposal filed, outcome pending
- OQ-012: Multi-party invitation for reverse auction contexts
- OQ-013: DID VC mandate for Meeting Place hosted endpoints

**Introduction updated:**

Section 1.1 Background updated to reflect current ecosystem state: buyer-side
platforms in production at scale; seller-side infrastructure emerging (Salesforce
Revenue Cloud, Dynamics 365 MCP Server); Luminance as sole production bilateral
contract negotiation system. Invitation problem explicitly described.

Section 1.2 protocol comparison table updated with Dynamics 365 ERP MCP Server
and Revenue Cloud Pricing API.

Section 1.4 Scope updated to enumerate v0.2 additions over v0.1.

### v0.1.3 (2026-03-24)

**Bug fixes — copy-paste errors and internal contradictions:**

- **Fixed Section 9.4 inline namespace UUID.** Section 9.4 still referenced the
  invalid string `a2cn-0001-0000-0000-a2cn-spec-0001` from pre-v0.1.2. Now
  correctly references `f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c` as defined in
  Appendix A. An implementer reading only Section 9 and not Appendix A would
  have used the wrong namespace and generated divergent `record_id` values.

- **Fixed changelog structural anomaly.** Section 18 previously contained the
  v0.1.1 changes listed under a second `v0.1-draft` heading — a copy-paste error
  from the v0.1.2 edit. The duplicate block has been removed. `v0.1-draft` entry
  is now the correct one-liner.

- **Fixed Section 17 internal contradiction.** The final line of Section 17
  previously said "Schemas are labeled informative in v0.1.1 and will become
  normative in v0.2" — contradicting the section header and status document which
  both state schemas are normative as of v0.1.2. Contradicting line removed.

- **Fixed Level 1 / signing paradox (Section 16.2).** Section 16.1 required
  RFC 8785 JCS signing for ALL conformant implementations. Section 16.2 listed
  "RFC 8785 signing" as a Level 2 feature, implying Level 1 implementations
  were exempt. Protocol act signing is a universal requirement at all levels.
  Removed "RFC 8785 signing" from the Level 2 description; clarified that signing
  is required at Level 1. Level 2 now focuses on its distinguishing additions:
  DID VC mandate verification, transaction record, and audit log.

- **Fixed walkthrough mandate asymmetry (Appendix B, Step 1).** TechCorp
  presented a Tier 2 (DID VC) mandate while Acme responded with Tier 1
  (Declared) at a $120,000 deal that exceeded Acme's own $50,000 threshold.
  This appeared to be a protocol violation in the spec's own example. Fixed by
  showing TechCorp's discovery document with `high_value_minimum` of $200,000,
  making the $120,000 deal fall below TechCorp's threshold and Acme's Tier 1
  mandate valid. Added explanation of mandate tier asymmetry: each party's tier
  requirement is determined by the *counterparty's* declared threshold.

**Design gap fixes:**

- **Added verification method precedence rule (Section 4.2).** The
  `verification_method` declared in SessionInit/SessionAck overrides the
  discovery document for the duration of that specific session. Previously
  the spec had two implicit sources of truth (discovery and SessionInit/Ack)
  with no stated priority, allowing implementations to verify against different
  keys.

- **Added DID document session-duration binding (Section 5.5).** Once a
  verification method has been successfully resolved and used to verify a
  signature within a session, it MUST be treated as valid for that session's
  entire duration. Implementations MUST NOT re-resolve mid-session. Prevents
  mid-session key rotation from causing asymmetric verification failures.

- **Added sender retry obligation (Section 7.1).** Under the strict ordering
  model, a sender MUST continue retrying the current message until it receives
  HTTP 2xx before sending the next message (`sequence_number + 1`). Prevents
  deadlock where both sides wait indefinitely after message loss.

- **Made `session_timeout_seconds` and `round_timeout_seconds` immutable
  (Section 6.4.1).** The responder MUST NOT change these parameters in the
  SessionAck, preventing a responder from reducing `round_timeout_seconds` to
  an unreasonably short value. Only `max_rounds` may be reduced; `deal_type`,
  `currency`, `session_timeout_seconds`, and `round_timeout_seconds` are all
  fixed at session initiation.

- **Added Level 1 meets Level 2 guidance (Section 16.2).** Initiator SHOULD
  inspect the responder's `conformance_level` and `mandate_methods` before
  initiating. Initiator MUST NOT initiate a session requiring capabilities above
  the responder's declared level.

- **Expanded acceptance signature payload (Section 7.4).** Added `round_number`
  and `sequence_number` to the acceptance signature payload. Previously only
  `session_id + accepted_offer_id + accepted_protocol_act_hash` were signed,
  leaving a narrow theoretical replay edge case within the same session. The
  full payload now binds the acceptance to its exact session position.

- **Added explicit MUST NOT for retransmission payload changes (Section 7.1).**
  A sender MUST NOT send a different payload with the same `message_id`. This
  was implied but never stated as an explicit prohibition.

- **Added walkthrough protocol_act_hash coverage note (Appendix B, Step 3).**
  Clarifies that abbreviated terms in Steps 4–6 are for readability only; the
  `protocol_act_hash` always covers the complete terms object.

### v0.1.2 (2026-03-24)

**Critical bug fixes:**

- **Fixed invalid namespace UUID (Appendix A).** The v0.1-draft and v0.1.1 used
  `a2cn-0001-0000-0000-a2cn-spec-0001`, which is not a valid UUID (contains
  non-hex characters). UUID v5 generators would produce divergent `record_id`
  values across implementations, defeating deterministic record generation.
  Replaced with a proper UUID v4-generated namespace:
  `f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c`. All implementations MUST update.

- **Clarified rejection-then-offer round counting (Section 7.5).** When the
  rejecting party subsequently sends a new offer (having held the turn after
  rejection), that message MUST use `message_type: "counteroffer"` and MUST
  increment `round_number` by 1. The Rejection does not increment `round_number`;
  the following counteroffer does. Example: A sends round 3 → B rejects (round
  stays 3, turn → B) → B sends round 4 counteroffer.

- **Specified strict ordering model for sequence numbers (Section 7.1).**
  Receivers MUST reject messages where `sequence_number != last + 1`. Buffering
  out-of-order messages is NOT permitted. Retransmissions MUST reuse the identical
  `message_id` AND `sequence_number` — senders MUST NOT generate new `message_id`
  values for retries of unacknowledged messages.

- **Added round timeout after rejection (Section 7.5, 8.6).** The round timeout
  clock begins from the Rejection message timestamp for the rejecting party as new
  turn holder. Previously, the spec started the round clock only "after an offer
  is sent," which left a gap causing indefinite hangs when the rejecting party held
  the turn but sent nothing.

- **Added timeout grace window (Section 8.6).** A local timeout is not final if
  a message with higher `sequence_number` is received within 30 seconds. This
  prevents premature termination due to clock differences or network latency.

- **Added JWT key selection strict rule (Section 6.3).** The verification method
  used MUST satisfy: (1) declared in sender's discovery document or SessionInit/Ack;
  (2) present in sender's DID document; (3) JWT `kid`, if present, matches that
  method. Receivers MUST reject JWT `kid` mismatches with HTTP 401.

**Spec clarity fixes:**

- **Fixed `in_reply_to` after rejection (Section 7.1).** When a party rejects and
  then sends a new counteroffer (holding the turn), `in_reply_to` MUST reference
  the offer or counteroffer that was rejected — not the Rejection message itself.

- **Added deterministic state disagreement resolution (Section 8.1).** Rule:
  highest `sequence_number` wins; if equal, latest `timestamp` wins; if equal,
  lexicographically greater `sender_did` wins. Both parties applying this rule
  independently reach the same conclusion.

- **Added `conformance_level` to discovery document schema (Sections 4.3.1,
  4.3.2, 4.3.3).** The field was declared REQUIRED in conformance Section 16.2
  but was absent from the discovery schema and example. Now added as REQUIRED
  integer field with valid values 1, 2, or 3.

- **Added version string note (Status of This Document).** Document version
  (0.1.2) tracks editorial revisions. Wire protocol version (`protocol_version`,
  `a2cn_version`) remains `"0.1"` for all 0.1.x revisions.

- **Fixed webhook JWT authentication (Section 11.1.6).** Added explicit rule:
  webhook JWTs MUST have `iss` = sender's DID and `aud` = receiver's DID.
  Previously the spec said "include Authorization header" without specifying
  the DID routing.

- **Noted SLA `penalty_currency` removal (Section 7.2).** `penalty_currency`
  was silently removed in v0.1.1 when currency became session-scoped. Now
  explicitly documented: SLA penalties are denominated in the session currency.

- **Fixed `REJECTED_FINAL` terminal notation (Section 8.2).** Changed "No→Yes"
  to "Yes" in the terminal state table.

- **Added 406 to HTTP status code table (Section 11.1.5).**

**Improvements:**

- **Added acceptance binding intent sentence (Terminology, Section 2.1).**
  "Acceptance represents protocol-level agreement; legal enforceability is
  governed by applicable law and is external to this protocol."

- **Marked `organization_name` and `agent_id` as informational (Section 9).**
  These fields in the transaction record are not cryptographically bound and MUST
  be derived from SessionInit/SessionAck. DID and verification_method are the
  authoritative identity references.

- **Added VC proof type extensibility (Section 5.4).** Other proof types MAY be
  supported by mutual agreement. The default suite (`JsonWebSignature2020` + `ES256`)
  MUST always be supported by Level 2 and Level 3 implementations.

- **Added audit log self-declaration note (Section 10.3).** `audit_metadata`
  fields are self-declared by the implementing agent and are not cryptographically
  verifiable by the protocol.

- **Expanded did:web security language (Section 13.4).** Honest statement that
  did:web security depends on DNS/web infrastructure. Added specific SHOULD
  recommendations: certificate transparency monitoring, DNSSEC, multi-party
  authorization for well-known path changes.

- **Schemas promoted to normative (Sections 17, 16.1).** JSON schemas are normative
  as of v0.1.2. Conformant implementations MUST produce schema-valid messages.

- **Open question IDs stabilized (Section 14).** Resolved questions now marked
  [RESOLVED vX.Y] rather than renumbered. OQ-007 and OQ-008 from v0.1 are
  marked resolved. New questions added by v0.1.2 fixes carry OQ-006 forward.

- **Timeout notification extended.** Added `timeout_type: "dispute"` value for
  signaling that a valid message was delivered after the counterparty declared
  timeout.

### v0.1.1 (2026-03-24)

First major revision addressing structural and security gaps identified in the
initial draft review cycle.

**Security:** Adopted RFC 8785 JCS canonicalization for all signed JSON. Expanded
offer signature scope to the full protocol act (session_id, round_number, sequence_number,
message_type, sender_did, timestamp, expires_at, terms). Resolved discovery/DID dual
trust-root by removing `public_key` from the discovery document — all signing keys
now retrieved via DID document resolution. Added JWT `jti` anti-replay with 600-second
store. Added pre-session anti-replay keyed on `(sender_did, jti, purpose)`. Reduced
in-session JWT expiry to 60 seconds. Added 30-second clock skew tolerance.

**State machine:** Added explicit turn-taking rule (Section 3.2). Added `current_turn`
field to session object. Introduced NEGOTIATING state, eliminating ACTIVE state
ambiguity. Adopted one-response-per-offer model — counteroffer implicitly rejects
prior offer. Added `NOT_YOUR_TURN` and `WRONG_MESSAGE_TYPE` error codes. Added
explicit `SESSION_WRONG_STATE` requirement for terminal-state messages.

**Transaction record:** Replaced role-specific signature fields with party-role-agnostic
`final_offer` / `final_acceptance` blocks. Made `generated_at` deterministic (derived
from Acceptance timestamp). Corrected UUID to v5; namespace string was still invalid
at this point (corrected in v0.1.2). Changed `offer_chain_hash` to JCS array hashing.

**Protocol:** Added `currency` as REQUIRED field in `session_params`, fixed for session
duration. Fixed `authorized_counterparties` from exclusion-list to allowlist semantics.
Made `conformance_level` REQUIRED (field missing from schema — corrected in v0.1.2).
Added `sequence_number`, `in_reply_to`, and `sender_verification_method` to all session
messages. Added `SEQUENCE_ERROR` and `DID_NOT_FOUND` error codes with permanent vs
temporary classification.

**Idempotency:** Added Section 6.1 with idempotency semantics for `POST /sessions` and
`POST /sessions/{id}/messages`. Added `Idempotency-Key` header requirement.

**Transport:** Promoted webhook callbacks to RECOMMENDED. Added cursor-based pagination
for message history. Added version negotiation rules. Defined `application/a2cn+json`
media type.

**Audit log:** Renamed "compliance trace" to "audit log". Added null field handling for
non-completed sessions. Changed `ai_system_used` MUST-true to `ai_system_involved`
SHOULD-true with exception for human-driven API use. Softened compliance language.

### v0.1-draft (2026-03-24)

Initial draft for community review. Defined seven protocol components: discovery,
mandate verification, session initiation, offer exchange, session state machine,
transaction record, compliance trace. HTTP/REST normative transport. Two-tier
mandate system. Configurable per-deal-type round limits. Eight open questions.

---

## Appendix A: A2CN Namespace UUID

The A2CN-specific UUID v5 namespace UUID is:

```
f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c
```

This UUID was generated randomly (UUID v4) specifically for use as the A2CN
namespace and is published here as the canonical constant. All A2CN implementations
MUST use this exact UUID (as a 16-byte binary value per RFC 4122 Section 4.3) as
the namespace input when generating UUID v5 `record_id` values.

In code:
```python
import uuid
A2CN_NAMESPACE = uuid.UUID('f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c')
record_id = str(uuid.uuid5(A2CN_NAMESPACE, session_id))
```

This namespace UUID will be formally published and registered as part of the A2CN
specification governance process. The v0.1-draft used an invalid string
(`a2cn-0001-0000-0000-a2cn-spec-0001`), which was not a valid UUID. The v0.1.1
used the same invalid string. This has been corrected in v0.1.2 with a proper
UUID v4-generated namespace.

## Appendix B: SaaS Renewal Walkthrough

This appendix shows a complete A2CN session for a SaaS license renewal negotiation.
All JSON is abbreviated for readability; real implementations would include all
required fields. Signatures and hashes are shown as placeholder strings.

### Scenario

**Buyer:** TechCorp Inc (`did:web:techcorp.example`)  
**Seller:** Acme SaaS (`did:web:acme-corp.com`)  
**Deal:** Annual renewal of Acme's analytics platform  
**Starting position:** Acme wants $120,000/year; TechCorp budget is $95,000  
**Outcome:** Agreement at $105,000/year with net-45 payment terms

---

### Step 1: Discovery

TechCorp's procurement agent fetches the seller's discovery document:

```
GET https://acme-corp.com/.well-known/a2cn-agent
```

Response:
```json
{
  "a2cn_version": "0.1",
  "conformance_level": 2,
  "organization": { "name": "Acme Corp", "did": "did:web:acme-corp.com" },
  "endpoint": "https://acme-corp.com/api/a2cn",
  "deal_types": ["saas_renewal"],
  "mandate_methods": ["declared", "did_vc"],
  "verification_method": "did:web:acme-corp.com#key-2026-01",
  "max_rounds_by_deal_type": { "saas_renewal": 5 },
  "value_thresholds": { "high_value_minimum": 5000000, "high_value_currency": "USD" },
  "updated_at": "2026-03-01T00:00:00Z"
}
```

Acme's discovery document sets `high_value_minimum` at $50,000 (5,000,000 cents).
Since the estimated deal value of $120,000 exceeds this threshold, TechCorp MUST
present a DID VC mandate (Tier 2) when initiating.

Acme's agent also fetches TechCorp's discovery document to determine what mandate
tier it must present in the SessionAck:

```
GET https://techcorp.example/.well-known/a2cn-agent
```

TechCorp's discovery document declares `high_value_minimum` of $200,000
(20,000,000 cents). Since the estimated deal value of $120,000 does not reach
TechCorp's threshold, Acme MAY present a Declared mandate (Tier 1) in the
SessionAck. This asymmetry is valid: each party's mandate tier requirement is
determined by the **counterparty's** declared threshold, not their own.

TechCorp's agent resolves `did:web:acme-corp.com`, fetches the DID document at
`https://acme-corp.com/.well-known/did.json`, and locates the `key-2026-01`
verification method. This key will be used for all signature verification of
messages from Acme throughout the session.

---

### Step 2: Session Initiation

TechCorp's agent sends:

```
POST https://acme-corp.com/api/a2cn/sessions
Authorization: Bearer eyJ...{jwt signed by did:web:techcorp.example#key-1}
Idempotency-Key: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Content-Type: application/a2cn+json
```

```json
{
  "message_type": "session_init",
  "message_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "protocol_version": "0.1",
  "session_params": {
    "deal_type": "saas_renewal",
    "currency": "USD",
    "subject": "Acme Analytics Platform — annual renewal FY2027",
    "subject_reference": "CONTRACT-2024-ACME-001",
    "estimated_value": 12000000,
    "max_rounds": 4,
    "session_timeout_seconds": 3600,
    "round_timeout_seconds": 900
  },
  "initiator": {
    "organization_name": "TechCorp Inc",
    "did": "did:web:techcorp.example",
    "verification_method": "did:web:techcorp.example#key-1",
    "agent_id": "procurement-agent-tc-001",
    "endpoint": "https://techcorp.example/api/a2cn"
  },
  "initiator_mandate": {
    "mandate_type": "did_vc",
    "credential": {
      "type": ["VerifiableCredential", "A2CNNegotiationMandate"],
      "issuer": "did:web:techcorp.example",
      "expirationDate": "2026-06-30T00:00:00Z",
      "credentialSubject": {
        "agent_id": "procurement-agent-tc-001",
        "principal_organization": "TechCorp Inc",
        "authorized_deal_types": ["saas_renewal"],
        "max_commitment_value": 15000000,
        "max_commitment_currency": "USD"
      },
      "proof": { "type": "JsonWebSignature2020", "jws": "eyJ...{vc proof}" }
    }
  }
}
```

Acme's agent verifies the VC, resolves TechCorp's DID, confirms the mandate scope
covers this deal type and estimated value, and responds:

```json
{
  "message_type": "session_ack",
  "message_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "session_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "in_reply_to": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "protocol_version": "0.1",
  "session_params_accepted": {
    "deal_type": "saas_renewal",
    "currency": "USD",
    "max_rounds": 4,
    "session_timeout_seconds": 3600,
    "round_timeout_seconds": 900
  },
  "responder": {
    "organization_name": "Acme Corp",
    "did": "did:web:acme-corp.com",
    "verification_method": "did:web:acme-corp.com#key-2026-01",
    "agent_id": "sales-agent-acme-007",
    "endpoint": "https://acme-corp.com/api/a2cn"
  },
  "responder_mandate": {
    "mandate_type": "declared",
    "agent_id": "sales-agent-acme-007",
    "principal_organization": "Acme Corp",
    "principal_did": "did:web:acme-corp.com",
    "authorized_deal_types": ["saas_renewal"],
    "max_commitment_value": 20000000,
    "max_commitment_currency": "USD",
    "valid_from": "2026-03-24T10:00:00Z",
    "valid_until": "2026-12-31T00:00:00Z"
  },
  "session_created_at": "2026-03-24T10:00:05Z",
  "current_turn": "initiator"
}
```

Session established. `session_id = c3d4e5f6-a7b8-9012-cdef-123456789012`.
Turn: TechCorp (initiator).

---

### Step 3: Round 1 — TechCorp Opens

TechCorp's agent constructs the protocol act for signing:

```json
{
  "protocol_version": "0.1",
  "session_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "round_number": 1,
  "sequence_number": 1,
  "message_type": "offer",
  "sender_did": "did:web:techcorp.example",
  "timestamp": "2026-03-24T10:01:00Z",
  "expires_at": "2026-03-24T10:16:00Z",
  "terms": {
    "total_value": 9500000,
    "currency": "USD",
    "line_items": [
      { "id": "li-1", "description": "Acme Analytics Platform — 12 months",
        "quantity": 1, "unit": "year", "unit_price": 9500000, "total": 9500000 }
    ],
    "payment_terms": { "net_days": 30 },
    "contract_duration": {
      "start_date": "2026-07-01", "end_date": "2027-06-30",
      "auto_renewal": false, "cancellation_notice_days": 60
    }
  }
}
```

> **Note on subsequent steps:** In Steps 4–6 below, terms objects are abbreviated
> with `"...": "..."` for readability. In a real implementation, the `protocol_act_hash`
> always covers the **complete** terms object with all fields — not only the fields
> shown in the abbreviated representation.

Serializes with JCS, computes SHA-256 → `protocol_act_hash: "sha256-abc123..."`,
signs with TechCorp private key → `protocol_act_signature: "eyJ...{jws}"`.

```
POST https://acme-corp.com/api/a2cn/sessions/c3d4.../messages
Idempotency-Key: d4e5f6a7-b8c9-0123-defa-234567890123
```

```json
{
  "message_type": "offer",
  "message_id": "d4e5f6a7-b8c9-0123-defa-234567890123",
  "session_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "round_number": 1,
  "sequence_number": 1,
  "sender_did": "did:web:techcorp.example",
  "sender_agent_id": "procurement-agent-tc-001",
  "sender_verification_method": "did:web:techcorp.example#key-1",
  "timestamp": "2026-03-24T10:01:00Z",
  "expires_at": "2026-03-24T10:16:00Z",
  "terms": { "total_value": 9500000, "currency": "USD", "...": "..." },
  "protocol_act_hash": "sha256-abc123...",
  "protocol_act_signature": "eyJ...{jws}"
}
```

Acme verifies signature. Session state: `NEGOTIATING`, `current_turn: "responder"`,
`round_number: 1`, `sequence_number: 1`.

---

### Step 4: Round 2 — Acme Counters

Acme's agent considers $95,000 too far below list price. It counters at $115,000
with net-60 payment terms (which helps Acme's cash flow to partially offset the
price reduction).

```json
{
  "message_type": "counteroffer",
  "message_id": "e5f6a7b8-c9d0-1234-efab-345678901234",
  "session_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "in_reply_to": "d4e5f6a7-b8c9-0123-defa-234567890123",
  "round_number": 2,
  "sequence_number": 2,
  "sender_did": "did:web:acme-corp.com",
  "sender_agent_id": "sales-agent-acme-007",
  "sender_verification_method": "did:web:acme-corp.com#key-2026-01",
  "timestamp": "2026-03-24T10:03:30Z",
  "expires_at": "2026-03-24T10:18:30Z",
  "terms": {
    "total_value": 11500000,
    "currency": "USD",
    "line_items": [
      { "id": "li-1", "description": "Acme Analytics Platform — 12 months",
        "quantity": 1, "unit": "year", "unit_price": 11500000, "total": 11500000 }
    ],
    "payment_terms": { "net_days": 60 },
    "contract_duration": {
      "start_date": "2026-07-01", "end_date": "2027-06-30",
      "auto_renewal": false, "cancellation_notice_days": 60
    }
  },
  "protocol_act_hash": "sha256-def456...",
  "protocol_act_signature": "eyJ...{jws}"
}
```

Session: `NEGOTIATING`, `current_turn: "initiator"`, `round_number: 2`.

---

### Step 5: Round 3 — TechCorp Counters

TechCorp moves up to $103,000, keeps net-30.

```json
{
  "message_type": "counteroffer",
  "message_id": "f6a7b8c9-d0e1-2345-fabc-456789012345",
  "in_reply_to": "e5f6a7b8-c9d0-1234-efab-345678901234",
  "round_number": 3,
  "sequence_number": 3,
  "terms": { "total_value": 10300000, "currency": "USD",
    "payment_terms": { "net_days": 30 }, "...": "..." },
  "protocol_act_hash": "sha256-ghi789...",
  "protocol_act_signature": "eyJ...{jws}"
}
```

Session: `current_turn: "responder"`, `round_number: 3`.

---

### Step 6: Round 4 — Agreement

Acme splits the difference: $105,000, net-45. This is max round 4 of 4.
Both parties' agents evaluate this as within acceptable range.

```json
{
  "message_type": "counteroffer",
  "message_id": "a7b8c9d0-e1f2-3456-abcd-567890123456",
  "in_reply_to": "f6a7b8c9-d0e1-2345-fabc-456789012345",
  "round_number": 4,
  "sequence_number": 4,
  "terms": { "total_value": 10500000, "currency": "USD",
    "payment_terms": { "net_days": 45 }, "...": "..." },
  "protocol_act_hash": "sha256-jkl012...",
  "protocol_act_signature": "eyJ...{jws}"
}
```

Session: `current_turn: "initiator"`, `round_number: 4` (= `max_rounds`).
TechCorp's agent evaluates: $105,000 with net-45 is within mandate and acceptable.

TechCorp sends acceptance:

```json
{
  "message_type": "acceptance",
  "message_id": "b8c9d0e1-f2a3-4567-bcde-678901234567",
  "session_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "in_reply_to": "a7b8c9d0-e1f2-3456-abcd-567890123456",
  "round_number": 4,
  "sequence_number": 5,
  "accepted_offer_id": "a7b8c9d0-e1f2-3456-abcd-567890123456",
  "accepted_protocol_act_hash": "sha256-jkl012...",
  "sender_did": "did:web:techcorp.example",
  "sender_agent_id": "procurement-agent-tc-001",
  "sender_verification_method": "did:web:techcorp.example#key-1",
  "timestamp": "2026-03-24T10:08:45Z",
  "acceptance_signature": "eyJ...{jws over session_id+offer_id+hash}"
}
```

Session transitions to `COMPLETED`.

---

### Step 7: Transaction Record Generation

Both parties independently generate the transaction record. Key fields:

```json
{
  "record_type": "a2cn_transaction_record",
  "record_version": "0.1",
  "record_id": "{uuid5(A2CN_NAMESPACE, 'c3d4e5f6-a7b8-9012-cdef-123456789012')}",
  "session_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "generated_at": "2026-03-24T10:08:45Z",
  "parties": {
    "initiator": { "organization_name": "TechCorp Inc",
      "did": "did:web:techcorp.example",
      "verification_method": "did:web:techcorp.example#key-1",
      "mandate_type": "did_vc" },
    "responder": { "organization_name": "Acme Corp",
      "did": "did:web:acme-corp.com",
      "verification_method": "did:web:acme-corp.com#key-2026-01",
      "mandate_type": "declared" }
  },
  "deal_type": "saas_renewal",
  "currency": "USD",
  "subject": "Acme Analytics Platform — annual renewal FY2027",
  "subject_reference": "CONTRACT-2024-ACME-001",
  "agreed_terms": {
    "total_value": 10500000, "currency": "USD",
    "payment_terms": { "net_days": 45 },
    "contract_duration": { "start_date": "2026-07-01", "end_date": "2027-06-30",
      "auto_renewal": false, "cancellation_notice_days": 60 }
  },
  "negotiation_summary": {
    "total_rounds": 4, "total_messages": 5,
    "session_created_at": "2026-03-24T10:00:05Z",
    "first_offer_at": "2026-03-24T10:01:00Z",
    "accepted_at": "2026-03-24T10:08:45Z",
    "initiating_party_did": "did:web:techcorp.example",
    "accepting_party_did": "did:web:techcorp.example"
  },
  "final_offer": {
    "message_id": "a7b8c9d0-e1f2-3456-abcd-567890123456",
    "sender_did": "did:web:acme-corp.com",
    "protocol_act_hash": "sha256-jkl012...",
    "protocol_act_signature": "eyJ...{acme jws}"
  },
  "final_acceptance": {
    "message_id": "b8c9d0e1-f2a3-4567-bcde-678901234567",
    "sender_did": "did:web:techcorp.example",
    "accepted_protocol_act_hash": "sha256-jkl012...",
    "acceptance_signature": "eyJ...{techcorp jws}"
  },
  "offer_chain_hash": "sha256(JCS([sha256-abc123, sha256-def456, sha256-ghi789, sha256-jkl012]))",
  "record_hash": "sha256-{hash of record with record_hash=''}"
}
```

**Outcome:** $105,000/year, net-45 payment, contract July 2026 — June 2027.
Both parties hold identical, dual-signed transaction records. The four-round
negotiation took 8 minutes 40 seconds. The agreed value is within both parties'
declared mandates.

## Appendix C: Prior Art and References

- W3C DID Core 1.0: https://www.w3.org/TR/did-core/
- W3C Verifiable Credentials Data Model 1.1: https://www.w3.org/TR/vc-data-model/
- RFC 2119: https://tools.ietf.org/html/rfc2119
- RFC 4122 (UUID): https://tools.ietf.org/html/rfc4122
- RFC 7517 (JSON Web Key): https://tools.ietf.org/html/rfc7517
- RFC 7519 (JWT): https://tools.ietf.org/html/rfc7519
- RFC 8259 (JSON): https://tools.ietf.org/html/rfc8259
- RFC 8615 (Well-Known URIs): https://tools.ietf.org/html/rfc8615
- RFC 8785 (JSON Canonicalization Scheme): https://tools.ietf.org/html/rfc8785
- NegMAS / ANAC: https://negmas.readthedocs.io
- Virtuals Protocol ACP: https://whitepaper.virtuals.io/about-virtuals/agent-commerce-protocol
- Salesforce A2A Semantic Layer: https://www.salesforce.com/blog/agent-to-agent-interaction/
- A2A Protocol Specification: https://github.com/a2aproject/A2A
- MCP Specification: https://modelcontextprotocol.io/specification/2025-11-25
