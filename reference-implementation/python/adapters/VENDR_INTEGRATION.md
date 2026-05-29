# Vendr MCP and Webhooks - A2CN Integration Guide

Vendr is a buy-side SaaS procurement platform with two useful integration
surfaces for A2CN:

- Vendr MCP server: exposes pricing and benchmark intelligence to agents.
- Vendr webhooks: notify your endpoint about renewal and workflow events.

The cleanest A2CN integration is MCP-to-MCP. An agent asks Vendr's MCP server
for SaaS benchmark context, translates the result into A2CN `saas_renewal`
terms with `vendr_adapter.py`, then calls A2CN's MCP tools to run the bilateral
negotiation and produce the dual-signed transaction record.

No Vendr platform changes are required.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VENDR_API_KEY` | Access key for Vendr MCP/API surfaces, issued by Vendr |
| `VENDR_WEBHOOK_SECRET` | Optional shared secret for HMAC-SHA256 webhook verification |

---

## Path A - Vendr Webhook Starts an A2CN Renewal

```python
from adapters.vendr_adapter import VendrWebhookParser

# Verify against the exact raw request body when Vendr provides a webhook secret.
VendrWebhookParser.verify_webhook_signature(
    body_bytes,
    headers["X-Vendr-Signature"],
    webhook_secret,
)

parsed = VendrWebhookParser.parse_renewal_webhook(payload)
session_params = parsed["session_params"]
initial_terms = parsed["initial_terms"]

# session_params["deal_type"] == "saas_renewal"
# initial_terms["total_value"] is integer cents
```

Vendr webhooks are one-way notifications. The adapter keeps the Vendr event ID
and workflow ID in `session_params` for audit correlation, then A2CN owns the
negotiation state and transaction record.

---

## Path B - MCP-to-MCP Pricing Intelligence

```text
1. Agent calls Vendr MCP server
      -> benchmark/pricing context for vendor, product, seat count, discount band

2. Agent calls vendr_pricing_to_a2cn_terms(pricing)
      -> A2CN saas_renewal terms

3. Agent calls A2CN MCP tools
      -> start_session(...)
      -> send_offer(...)
      -> accept_offer(...)

4. A2CN emits dual-signed transaction record
      -> a2cn_terms_to_vendr_summary(...) creates a local audit summary
```

The bridge is intentionally thin: Vendr remains the pricing-intelligence source,
while A2CN remains the neutral bilateral negotiation and record layer.

---

## Pricing Field Map

The adapter accepts a tolerant benchmark shape so agents can normalize Vendr MCP
responses without deep platform coupling:

```python
pricing = {
    "vendor": "Example SaaS",
    "product": "Enterprise Analytics",
    "list_price": 1200.0,  # dollars per seat per year
    "seat_count": 100,
    "currency": "USD",
    "term_months": 12,
    "observed_discount_band": {"min": 0.15, "max": 0.25},
    "benchmark_range": {"low": 85000.0, "median": 95000.0, "high": 110000.0},
    "source": "vendr_mcp",
}
```

`vendr_pricing_to_a2cn_terms()` applies the observed discount midpoint to the
per-seat list price and converts dollar values to integer cents.

---

## Round-Trip Summary

Vendr's webhook surface does not ingest completed negotiation data, so
`a2cn_terms_to_vendr_summary()` returns a local, Vendr-shaped audit artifact:

```python
summary = a2cn_terms_to_vendr_summary(
    agreed_terms,
    session_id="sess-001",
    record_hash="...",
    workflow_id="wf-001",
)
```

Attach the summary to your internal renewal system, Zip-linked workflow, or
agent memory. The canonical commitment remains the A2CN transaction record.

---

## Known Limitations

- Vendr MCP/API access currently requires an access key from Vendr.
- Webhooks are one-way; they should initiate or correlate A2CN work, not act as
  the write-back channel.
- Field names from MCP responses may vary as Vendr evolves its agent surface.
  Normalize into the documented `pricing` shape before calling the adapter.
