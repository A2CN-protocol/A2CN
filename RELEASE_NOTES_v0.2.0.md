# A2CN v0.2.0 Release Notes

**Released:** April 2026  
**Spec:** v0.2.0 (3,300+ lines)  
**Tests:** 469 passing
**License:** Apache 2.0

## What's new in v0.2.0

### Session Invitation (Component 8)
Solves the cold-start problem. A buyer agent can now invite a supplier who has no A2CN endpoint yet via a signed SessionInvitation delivered through existing webhook infrastructure (Fairmarkit BID_CREATED, email, or a neutral invitation relay). The invitation is ES256-signed using the inviter's DID key. The supplier verifies authenticity before activating any endpoint.

### Platform adapters
- **Fairmarkit** — FairmakitEventParser translates BID_CREATED webhook payloads into A2CN goods_procurement terms and translates agreed terms back into Fairmarkit's response API format. Path B integration — zero Fairmarkit platform changes required.
- **Salesforce Revenue Cloud** — RevenueCloudAdapter translates Revenue Cloud Pricing API responses into A2CN offer terms and translates agreed terms into Revenue Cloud order payloads.
- **Keelvar** — SOURCING_EVENTS_FEED_UPDATED webhook → A2CN session translation.
- **DealHub** — DealHubEventParser translates quoteReady webhook payloads into A2CN saas_renewal terms and translates agreed terms back into DealHub Actions API calls to mark the quote as externally signed.
- **Nue.io** — NueEventParser translates Nue pricing and subscription data into A2CN saas_renewal terms and translates agreed terms into Nue order creation with externalReference linkage for audit.
- **SAP Ariba** — Event Management and Discovery RFx publication payloads → A2CN goods_procurement terms, with bid and acknowledgement write-back helpers.
- **JAGGAER** — ASO sourcing events and CHES API events → A2CN goods_procurement terms, preserving item and lot IDs for supplier responses.
- **Conga** — CPQ/CLM quote and agreement data → A2CN saas_renewal or goods_procurement terms, with Salesforce-native write-back payloads.
- **Ironclad** — Signed workflow events → A2CN terms, plus workflow metadata and record write-back helpers.
- **Vendr** — Renewal benchmark pricing → A2CN saas_renewal terms and post-agreement audit summaries.
- **DocuSign** — Completed A2CN transaction records → eSignature envelope payloads, with Connect HMAC verification.

### Deal-type-specific terms schemas
- `goods_procurement` — delivery_days, unit_of_measure, manufacturer and internal part numbers
- `saas_renewal` — seat_count, subscription_tier, support_tier, auto_renew_terms, uptime_sla_percent

### Impasse detection
Configurable `impasse_threshold` in session_params. When N consecutive full rounds show no change in total_value from either party, session transitions to IMPASSE. Default N=3, configurable 1-10.

### LLM negotiation skills file
Reference skills file for LLM agents participating in A2CN sessions. Covers warmth-dominance calibration, chain-of-thought reasoning patterns, and Inject+Voss prompt injection defense. Based on Vaccaro et al. (2026) arXiv:2503.06416v3 — 182,812 AI-to-AI negotiations.

### Webhooks at Level 2
Terminal state webhooks (COMPLETED, REJECTED_FINAL, WITHDRAWN, IMPASSE, TIMED_OUT) promoted from RECOMMENDED to REQUIRED for Level 2 conformance. Async delivery with exponential backoff retry.

## Installation

```bash
git clone https://github.com/A2CN-protocol/A2CN.git
cd A2CN/reference-implementation/python
pip install -e .
```

## Run the demos

```bash
# SaaS renewal bilateral negotiation
python examples/saas_renewal.py

# Session Invitation / Fairmarkit integration pattern
uvicorn server:app --port 8002  # Terminal 1
python examples/invitation_flow.py  # Terminal 2

# Keelvar sourcing event end-to-end
python examples/keelvar_demo.py
```

## Run the tests

```bash
pip install -r requirements.txt
pytest tests/ -v
# 469 passed
```

## What's next (v0.3)

- Neutral third-party record custody — optional transaction record custody and compliance export
- Ed25519 as alternate signing suite (coordinated with Concordia Protocol)
- Delegation chain support in mandate verification
- Joint A2A extension proposal with Concordia Protocol
- TypeScript reference implementation
- pip install packaging
