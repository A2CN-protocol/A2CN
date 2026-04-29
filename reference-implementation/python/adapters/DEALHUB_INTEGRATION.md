# DealHub CPQ — A2CN Integration Guide

DealHub is a seller-side CPQ platform. This adapter translates DealHub
quoteReady webhook events and API responses into A2CN session terms, and
translates A2CN agreed terms back into DealHub Actions API calls.

---

## Prerequisites

- A DealHub account with API access enabled
- An API Bearer token from **Control Panel → System Settings → API Settings**
- A Headless Simulate Playbook ID (for Path B mandate bound calculation)
- Network access from your A2CN server to your DealHub instance URL

---

## Environment Variables

| Variable               | Description                                               |
|------------------------|-----------------------------------------------------------|
| `DEALHUB_AUTH_TOKEN`   | Bearer token from DealHub API Settings                    |
| `DEALHUB_BASE_URL`     | Your DealHub instance URL (e.g. `https://yourdomain.dealhub.io`) |
| `DEALHUB_PLAYBOOK_ID`  | API Playbook ID for headless quote simulation (Path B)    |

---

## Path A — Webhook-Driven Integration (Primary)

```
1. DealHub fires quoteReady webhook to your endpoint
       ↓
2. DealHubEventParser.quote_ready_webhook_to_session_params(payload)
       → returns A2CN session_params (deal_type, currency, max_rounds, ...)
       ↓
3. DealHubEventParser.fetch_quote_details(payload["dealhub_quote_id"])
       → returns full quote with line items
       ↓
4. DealHubEventParser.quote_to_a2cn_offer_terms(quote_response)
       → returns A2CN offer terms dict (total_value in cents, line_items, ...)
       ↓
5. Initiate or join A2CN session — negotiation proceeds
       ↓
6. On COMPLETED: DealHubEventParser.agreed_terms_to_dealhub_action(
       quote_id, a2cn_session_id, record_hash
   )
       → POST signExternally to DealHub Actions API
       → DealHub quote is marked as won with A2CN audit trail in note field
```

Zero DealHub platform changes required.

---

## Path B — Headless Simulate (Secondary)

Use before initiating a session to set agent mandate bounds from live pricing:

```python
from adapters.dealhub_adapter import DealHubEventParser

bounds = DealHubEventParser.simulate_quote_for_mandate_bounds(
    playbook_id=os.environ["DEALHUB_PLAYBOOK_ID"],
    answers={
        "product_id": "prod-enterprise",
        "quantity": 100,
        "customer_segment": "enterprise",
    },
    floor_discount_pct=0.15,   # 15% max authorised discount
)

mandate = {
    "max_commitment_value": bounds["ceiling_value_cents"],
    "min_acceptable_value": bounds["floor_value_cents"],
    "currency": bounds["currency"],
}
```

---

## Field Map Configuration

DealHub quote response field names vary by instance configuration. The
default field map uses the most common names:

```python
DEFAULT_FIELD_MAP = {
    "total_value_field":  "total_price",
    "currency_field":     "currency",
    "line_items_field":   "line_items",
    "product_name_field": "product_name",
    "quantity_field":     "quantity",
    "unit_price_field":   "unit_price",
}
```

Override individual keys when your instance uses different names:

```python
terms = DealHubEventParser.quote_to_a2cn_offer_terms(
    quote_response,
    field_map={"product_name_field": "name", "unit_price_field": "price"},
)
```

---

## Floor Discount Configuration

`floor_discount_pct` in `simulate_quote_for_mandate_bounds` represents
the maximum discount the seller's agent may offer without human approval.
Configure per product category based on your actual sales policy:

```python
bounds = DealHubEventParser.simulate_quote_for_mandate_bounds(
    playbook_id=playbook_id,
    answers=answers,
    floor_discount_pct=0.10,  # enterprise tier: 10% max
)
```

---

## Known Limitations

- **Field names**: DealHub quote response field names (`total_price`,
  `line_items`, `product_name`, etc.) are based on API conventions and
  must be verified against a live DealHub instance. Use `field_map`
  parameter to correct any mismatches.
- **Simulate API schema**: The headless simulate response schema
  (`total_price`, `line_items`, `currency`) must be verified against
  a live DealHub sandbox. Contact DealHub support for the exact field names.
- **Async HTTP**: The HTTP methods use synchronous `httpx`. Wrap in
  `asyncio.to_thread()` or use `httpx.AsyncClient` if your server is
  fully async.
