# Ironclad CLM - A2CN Integration Guide

Ironclad is a contract lifecycle management platform with public workflow,
records, and webhook APIs. This adapter connects Ironclad workflow events to
A2CN negotiations and writes the final A2CN terms back to Ironclad workflow
metadata or record properties.

Public docs used:

- `https://developer.ironcladapp.com/llms.txt` - machine-readable docs index.
- `GET /public/api/v1/workflows/{id}` - retrieve workflow attributes.
- `PATCH /public/api/v1/workflows/{id}/attributes` - update workflow metadata.
- `POST /public/api/v1/records` - create a record.
- `GET /public/api/v1/webhooks/verification-key` - retrieve webhook public key.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `IRONCLAD_API_TOKEN` | OAuth bearer token for the Ironclad Public API |
| `IRONCLAD_BASE_URL` | Optional API base, default `https://na1.ironcladapp.com/public/api/v1` |
| `IRONCLAD_AS_USER_EMAIL` | Optional `x-as-user-email` actor for client credentials tokens |

Required scopes depend on the flow:

- `public.workflows.readWorkflows`
- `public.workflows.updateWorkflows`
- `public.records.createRecords`
- `public.webhooks.readWebhooks`

---

## Path B - Workflow to A2CN to Workflow Metadata

```python
from adapters.ironclad_adapter import (
    IroncladWebhookParser,
    a2cn_terms_to_ironclad_workflow,
    update_ironclad_workflow_metadata,
)

parsed = IroncladWebhookParser.workflow_event_to_session_inputs(payload)
session_params = parsed["session_params"]
initial_terms = parsed["initial_terms"]

# Run A2CN offer / counter / accept...

update = a2cn_terms_to_ironclad_workflow(
    agreed_terms,
    workflow_id=parsed["workflow_id"],
    a2cn_session_id=session.id,
    record_hash=transaction_record["record_hash"],
)

await update_ironclad_workflow_metadata(
    update["workflow_id"],
    update["payload"],
)
```

Ironclad's metadata update endpoint requires the workflow to be in the Review
step and expects an `updates` array where each item has an action, path, and
value. Attribute IDs are workflow-template specific, so the adapter exposes a
`field_map` override for production deployments.

---

## Webhook Verification

Ironclad signs webhook deliveries. Verification uses:

1. `X-Ironclad-Webhook-Event-Id`
2. `X-Ironclad-Webhook-Verification`, a JSON object with `nonce`,
   `signAlgorithm`, `signature`, and `encoding`
3. The JSON-stringified request body
4. The PEM public key from `/webhooks/verification-key`

The signed bytes are:

```text
event_id + JSON.stringify(body) + nonce
```

`IroncladWebhookParser.verify_webhook_signature(...)` implements this check
with RSA-SHA256 / PKCS#1 v1.5 verification.

---

## Record Creation Payload

For formalization systems that prefer a record hand-off, use
`a2cn_terms_to_ironclad_record(...)` to build a `POST /records` payload:

```python
payload = a2cn_terms_to_ironclad_record(
    agreed_terms,
    record_type="vendorAgreement",
    name="A2CN Renewal - Acme Analytics",
    a2cn_session_id=session.id,
    record_hash=transaction_record["record_hash"],
)
```

The record payload stores `contractValue`, `counterpartyName`, `a2cnSessionId`,
and `a2cnRecordHash` as metadata properties. The A2CN transaction record remains
the neutral bilateral commitment; Ironclad formalizes and manages the contract.

---

## Known Limitations

- Runtime API access may require Ironclad CSM or ISV Partner enablement.
- Workflow attribute keys vary by workflow template. Configure `field_map`
  before submitting metadata updates.
- Ironclad rejects metadata updates outside the Review step and enforces form
  validation on required or conditional attributes.
