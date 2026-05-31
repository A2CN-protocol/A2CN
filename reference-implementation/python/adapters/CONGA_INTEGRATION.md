# Conga CPQ/CLM - A2CN Integration Guide

Conga is a sell-side CPQ and CLM platform. This adapter maps Conga CPQ
quote/cart payloads into A2CN `saas_renewal` or `goods_procurement` terms and
maps agreed A2CN terms back into Conga-shaped quote update payloads. It also
provides a small CLM agreement metadata payload for linking the final contract
workflow to an A2CN transaction record.

Public docs used:

- Conga Documentation Portal
  - CPQ REST API Version 5
  - CPQ REST API areas including Quote, Cart Items, Order, and Assets
  - Example cart paths such as `POST /api/cart/v1/carts/{cartId}/items`
  - CLM for REST API Developers
- Conga Developer Portal
  - Advantage Platform REST API Introduction
  - RESTful URLs, JSON messaging, and standard HTTP response codes
- Conga Salesforce pages
  - Conga CPQ and CLM are available as Salesforce-native products

Conga deployments can be Salesforce-native or Advantage Platform-native. The
adapter deliberately accepts tolerant field aliases so the same A2CN mapping can
sit behind either tenant shape.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CONGA_CLIENT_ID` | OAuth client ID for Conga or Salesforce-connected app access |
| `CONGA_CLIENT_SECRET` | OAuth client secret |
| `CONGA_TOKEN_URL` | OAuth token URL for the Conga/Salesforce environment |
| `CONGA_SCOPE` | Optional OAuth scope for Advantage Platform tenants |
| `CONGA_INSTANCE_URL` | Conga or Salesforce instance base URL |
| `CONGA_CPQ_BASE_URL` | Optional CPQ REST base URL override |
| `CONGA_CLM_BASE_URL` | Optional CLM REST base URL override |

---

## Path A - CPQ Quote to A2CN Session

When a Conga quote reaches a negotiation-ready stage, tenant middleware can load
the quote through the Conga CPQ REST APIs and convert it into A2CN terms:

```python
from adapters.conga_adapter import CongaAdapter

quote = {
    "id": "conga-q-001",
    "accountId": "001xx000003DGbY",
    "currency": "USD",
    "lineItems": [
        {"id": "qli-001", "productId": "prod-001",
         "productName": "Enterprise Subscription License",
         "quantity": 100, "unitPrice": 950.0, "totalPrice": 95000.0},
    ],
}

parsed = CongaAdapter.quote_to_session_inputs(quote)
session_params = parsed["session_params"]
initial_terms = parsed["initial_terms"]
```

The adapter classifies subscription-like quotes as `saas_renewal` using product
or charge-type keywords such as `subscription`, `license`, `seat`, and
`renewal`. Otherwise, it emits `goods_procurement` with `delivery_days`.

All monetary values are converted from decimal dollars into integer cents for
A2CN.

---

## Path B - A2CN Agreement to Conga Quote Update

After the A2CN session completes, convert the agreed terms back into a
Conga-shaped update payload:

```python
from adapters.conga_adapter import a2cn_terms_to_conga_quote

payload = a2cn_terms_to_conga_quote(
    agreed_terms,
    quote_id="conga-q-001",
    agreement_id="clm-agreement-001",
)
```

The payload preserves `conga_line_item_id` and `conga_product_id` from the
original quote so middleware can update the correct Conga quote line records.
Prices are converted back from A2CN cents into decimal values.

---

## CLM Agreement Linkage

For formalization in Conga CLM, use `conga_agreement_update_payload()` to link
the Conga agreement to the A2CN transaction record:

```python
from adapters.conga_adapter import conga_agreement_update_payload

metadata = conga_agreement_update_payload(
    agreement_id="clm-agreement-001",
    a2cn_session_id="sess-001",
    record_hash="record-hash",
)
```

The canonical commercial agreement remains the A2CN transaction record, while
Conga owns document generation, contracting workflow, approvals, and CLM
execution.

---

## Revenue Cloud Synergy

Conga’s Salesforce-native deployments share the same broad CRM data model shape
as the existing `RevenueCloudAdapter`: account IDs, opportunity IDs, quote line
items, product IDs, quantity, unit price, total price, and contract dates. That
means existing A2CN Revenue Cloud orchestration can usually reuse:

- Salesforce OAuth / connected-app credential handling
- account and opportunity resolution
- product and pricebook lookup
- downstream quote/order formalization patterns

For Advantage Platform tenants, use the same A2CN terms mapping but configure
the Conga-specific base URLs and token endpoint.

---

## Auth Helpers

`fetch_conga_access_token()` implements OAuth client-credentials token retrieval
using `CONGA_CLIENT_ID`, `CONGA_CLIENT_SECRET`, and `CONGA_TOKEN_URL`, with
optional `CONGA_SCOPE`.

`conga_auth_headers(access_token)` creates headers with:

- `Authorization: Bearer ...`
- `Accept: application/json`
- `Content-Type: application/json`

---

## Known Limitations

- Conga CPQ/CLM field names vary across Salesforce-native and Advantage
  Platform tenants. The adapter accepts common aliases, but production
  deployments should provide a `field_map` for tenant-specific API names.
- This module performs no quote, cart, agreement, or document network writes.
  Tenant middleware should own retries, lifecycle actions, and final API calls.
- The subscription-vs-goods classifier is intentionally conservative and based
  on quote-line metadata. Production deployments can pass an explicit field map
  or pre-classify the quote before starting A2CN.
