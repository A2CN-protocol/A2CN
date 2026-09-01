# JAGGAER ASO - A2CN Integration Guide

JAGGAER ONE is a buy-side source-to-pay platform. This adapter maps JAGGAER
Advanced Sourcing Optimizer (ASO) customer-host / sourcing events into A2CN
`goods_procurement` terms and maps agreed A2CN terms back into
JAGGAER-shaped bid response payloads.

## Validation status

**Built from:** JAGGAER's published Advanced Sourcing Optimizer (ASO) API documentation.

**Verified:** Payload translation in both directions against those published
schemas — 12 tests in `tests/test_jaggaer_adapter.py`.

**Not verified:** This adapter has not been exercised against a live JAGGAER instance. Runtime
access requires the credentials listed under Environment Variables below. Event and
bid payload shapes should be confirmed against a live environment before production
use.

If you have access to a live JAGGAER instance and are willing to validate this
adapter against it, please open an issue — that is the help we most need.

---

Public docs used:

- ASO API documentation
  - Customer Host Entity Service: query ASO events belonging to a customer host
  - Event Entity Service: interact with a specific ASO event
  - Async upload endpoints: entity imports for `rate` and `bid`
- ASO Getting Started
  - `POST /oauth2/token`
  - `GET /chost/{customer-host-id}/user/{user-id}/apiEvents`
  - `Authorization: Bearer ...`
  - `X-API-Key: ...`
- Integration via JAGGAER Public APIs
  - REST services using JSON messaging
  - request/response or event-driven push integration patterns

Runtime API use requires tenant enablement, customer-host configuration,
environment-specific service URLs, OAuth client credentials, an API key, and
JAGGAER Professional Services coordination for the exact tenant schema.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `JAGGAER_CLIENT_ID` | OAuth client ID supplied for ASO API access |
| `JAGGAER_CLIENT_SECRET` | OAuth client secret supplied for ASO API access |
| `JAGGAER_TOKEN_URL` | Authorization Utility Service token URL |
| `JAGGAER_API_KEY` | ASO API key sent as `X-API-Key` |
| `JAGGAER_SCOPE` | Optional OAuth scope, often tenant/customer-host scoped |
| `JAGGAER_CHES_BASE_URL` | Customer Host Entity Service base URL |
| `JAGGAER_EES_BASE_URL` | Event Entity Service base URL |

---

## Path A - Event-Driven Push

JAGGAER public APIs support event-driven push integrations where noted. In this
path, JAGGAER posts a sourcing event notification or event-shaped JSON payload
to middleware. The middleware validates tenant-specific authentication, then
normalizes the payload through the adapter.

```python
from adapters.jaggaer_adapter import JaggaerEventParser

push_event = {
    "event": {
        "eventId": "aso-10003",
        "customerHostId": "275",
        "name": "Industrial Supplies RFQ",
        "currency": "USD",
        "items": [
            {"itemId": "10", "lotId": "LOT-HF", "description": "Hydraulic fluid",
             "quantity": 50, "unitOfMeasure": "EA", "targetPrice": 360.0},
        ],
    }
}

parsed = JaggaerEventParser.sourcing_event_to_session_inputs(push_event)
session_params = parsed["session_params"]
initial_terms = parsed["initial_terms"]
```

`initial_terms["total_value"]` is expressed in integer cents and passes A2CN
`goods_procurement` validation.

---

## Path B - ASO Poll Mode

ASO Customer Host Entity Service documents polling events for a customer host:

```text
GET /chost/{customer-host-id}/user/{user-id}/apiEvents
```

Use `jaggaer_poll_request()` to build the documented request path, then call it
with `jaggaer_auth_headers(access_token)`.

```python
from adapters.jaggaer_adapter import jaggaer_auth_headers, jaggaer_poll_request

request = jaggaer_poll_request(
    customer_host_id="275",
    user_id="user-123",
    base_url="https://ches.example.jaggaer.com",
)
headers = jaggaer_auth_headers("access-token", api_key="api-key")
```

The adapter can parse each returned ASO event with `mode="poll"` so the A2CN
transaction record retains whether the session began from push or polling.

---

## Bid Response Payload

```python
from adapters.jaggaer_adapter import a2cn_terms_to_jaggaer_response

response = a2cn_terms_to_jaggaer_response(
    agreed_terms,
    event_id="aso-10003",
    supplier_id="supplier-123",
)
```

The response payload converts A2CN cents back to decimal JAGGAER prices and
preserves `jaggaer_item_id` and `jaggaer_lot_id` separately. That distinction
matters for ASO bid imports where item IDs and lot IDs are different platform
references.

For live write-back, tenant middleware can submit the response through the
configured JAGGAER bid import or async upload flow. The canonical agreement
remains the A2CN transaction record.

---

## Auth Helpers

`fetch_jaggaer_access_token()` implements client-credentials token retrieval
using:

- `Authorization: Basic` via HTTP client auth
- `grant_type=client_credentials`
- optional `scope`
- `X-API-Key`

`jaggaer_auth_headers(access_token)` creates API call headers with:

- `Authorization: Bearer ...`
- `X-API-Key: ...`
- `Accept: application/json`
- `Content-Type: application/json`

---

## Known Limitations

- JAGGAER public API integrations are tenant-enabled and coordinated through
  JAGGAER Professional Services; exact payload fields may vary.
- The adapter intentionally performs no network I/O except the token helper.
  Tenant middleware should own webhook verification, polling, retries, and
  async bid-upload orchestration.
- ASO supports multiple event categories and bid models. Production deployments
  should normalize their enabled ASO schema into the aliases accepted here before
  starting an A2CN session.
