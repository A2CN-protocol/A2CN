# SAP Ariba Sourcing - A2CN Integration Guide

SAP Ariba is a buy-side sourcing and procurement platform. This adapter maps
SAP Ariba Sourcing / Discovery RFx events into A2CN `goods_procurement` terms
and maps agreed A2CN terms back into Ariba-shaped bid or acknowledgement
payloads.

Public docs used:

- Event Management API for SAP Ariba Sourcing
  - `GET /events`
  - `GET /events/{eventId}/items`
- Discovery RFx Publication TO External Marketplace API
  - `GetNextRfxEvent`
  - `GetRfxAttachment`
  - `UpdateRfxEvent`
  - `Acknowledge`

Runtime API use requires SAP Ariba Developer Portal access, an application with
the relevant API package entitlement, environment-specific runtime URLs, OAuth
client credentials, and an application key.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ARIBA_CLIENT_ID` | OAuth client ID from the SAP Ariba Developer Portal |
| `ARIBA_CLIENT_SECRET` | OAuth client secret from the SAP Ariba Developer Portal |
| `ARIBA_TOKEN_URL` | OAuth token URL from the API environment details |
| `ARIBA_API_KEY` | SAP Ariba application key sent as `apiKey` |
| `ARIBA_BASE_URL` | Runtime API URL from the environment details |

---

## Path A - Event Management API

```python
from adapters.ariba_adapter import AribaEventParser

# Event Management API:
# GET /events/{eventId}/items retrieves item details for an event.
event = {
    "eventId": "evt-001",
    "title": "Industrial Supplies RFQ",
    "currency": "USD",
    "items": [
        {"itemId": "10", "title": "Hydraulic fluid", "quantity": 50,
         "unitOfMeasure": "EA", "targetPrice": 360.0, "lotId": "LOT-HF"},
    ],
}

parsed = AribaEventParser.sourcing_event_to_session_inputs(event)
session_params = parsed["session_params"]
initial_terms = parsed["initial_terms"]
```

`initial_terms["total_value"]` is expressed in integer cents and passes A2CN
`goods_procurement` validation.

---

## Path B - Discovery RFx Publication TO External Marketplace

SAP's documented Discovery RFx flow is:

```text
GetNextRfxEvent -> GetRfxAttachment (optional) -> UpdateRfxEvent -> Acknowledge
```

The adapter supports the same RFx shape using tolerant aliases such as `rfxId`,
`rfxTitle`, `lots`, `externalRfxId`, and `lineItems`.

```python
from adapters.ariba_adapter import ariba_acknowledgement_payload

ack = ariba_acknowledgement_payload(
    event_id="rfx-001",
    external_reference="a2cn-session-sess-001",
)
```

Use the acknowledgement payload after accepting the RFx event for A2CN
negotiation. The canonical agreement remains the A2CN transaction record.

---

## Bid Payload

```python
from adapters.ariba_adapter import a2cn_terms_to_ariba_bid

bid = a2cn_terms_to_ariba_bid(
    agreed_terms,
    event_id="evt-001",
    supplier_id="supplier-123",
)
```

The bid payload converts A2CN cents back to decimal Ariba prices and preserves
`internal_part_number` as the Ariba item or lot reference when present.

---

## Auth Helpers

`fetch_ariba_access_token()` implements client-credentials token retrieval using
`ARIBA_CLIENT_ID`, `ARIBA_CLIENT_SECRET`, and `ARIBA_TOKEN_URL`.

`ariba_auth_headers(access_token)` creates headers with:

- `Authorization: Bearer ...`
- `apiKey: ...`
- `Accept: application/json`
- `Content-Type: application/json`

---

## Known Limitations

- SAP Ariba Open APIs are not available by default to all users; administrator
  enablement and API package entitlement are required.
- Runtime URLs and token URLs are environment-specific and must be copied from
  the SAP Ariba Developer Portal environment details.
- Event and RFx field names vary by sourcing flow. The adapter accepts common
  aliases, but production deployments should normalize payloads from the exact
  OpenAPI schema enabled in their tenant.
