# DocuSign eSignature / Connect - A2CN Integration Guide

DocuSign is a formalization layer for A2CN agreements. A2CN produces the
neutral, dual-signed transaction record; DocuSign executes the signature package
and can notify A2CN middleware when the envelope is completed, declined, or
voided.

## Validation status

**Built from:** DocuSign's published eSignature REST API, Connect and OAuth documentation.

**Verified:** Payload translation in both directions against those published
schemas — 13 tests in `tests/test_docusign_adapter.py`.

**Not verified:** This adapter has not been exercised against a live DocuSign account. Runtime
access requires the credentials listed under Environment Variables below. Envelope
and webhook payload shapes should be confirmed against a live environment before
production use.

If you have access to a live DocuSign instance and are willing to validate this
adapter against it, please open an issue — that is the help we most need.

---

Public docs used:

- DocuSign eSignature REST API
  - `POST /restapi/v2.1/accounts/{accountId}/envelopes`
  - envelope definitions with `status`, `emailSubject`, `documents`, and
    `recipients`
- DocuSign Connect
  - envelope event notifications
  - envelope completed events
  - HMAC signatures for message validation
- DocuSign OAuth
  - JWT bearer grant using integration key, user ID, and RSA private key

This adapter does not replace the A2CN transaction record. It generates a
DocuSign envelope that references the A2CN `session_id`, `record_id`, and
`record_hash` in hidden custom fields and in the generated terms summary.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DOCUSIGN_INTEGRATION_KEY` | OAuth JWT app / integration key |
| `DOCUSIGN_USER_ID` | DocuSign user GUID to impersonate |
| `DOCUSIGN_PRIVATE_KEY` | RSA private key PEM for the JWT grant |
| `DOCUSIGN_SCOPE` | Optional scope, defaults to `signature impersonation` |
| `DOCUSIGN_AUTH_BASE_URI` | Auth host, e.g. `https://account-d.docusign.com` |
| `DOCUSIGN_ACCOUNT_ID` | eSignature account ID |
| `DOCUSIGN_BASE_URI` | eSignature REST base URI |
| `DOCUSIGN_CONNECT_SECRET` | Optional Connect HMAC secret |

---

## Path A - A2CN Record to Envelope

```python
from adapters.docusign_adapter import a2cn_record_to_docusign_envelope

envelope = a2cn_record_to_docusign_envelope(
    transaction_record,
    signer_contacts={
        "did:web:buyer.example": {
            "name": "Buyer Legal",
            "email": "legal@buyer.example",
        },
        "did:web:seller.example": {
            "name": "Seller Legal",
            "email": "legal@seller.example",
        },
    },
    connect_url="https://middleware.example.com/docusign/connect",
)
```

The envelope contains:

- a generated text document summarizing the A2CN agreed terms
- two signers, one for each party DID
- hidden custom fields for `a2cn_session_id`, `a2cn_record_id`, and
  `a2cn_record_hash`
- optional envelope event notification configuration for Connect

Create it with:

```text
POST /restapi/v2.1/accounts/{accountId}/envelopes
```

Use `docusign_envelope_create_request()` to build the request URL and payload
shape for middleware.

---

## Path B - Connect Completion to A2CN Status

```python
from adapters.docusign_adapter import DocuSignConnectParser

update = DocuSignConnectParser.parse_envelope_event(connect_payload)
```

The parser returns:

- `envelope_id`
- `envelope_status`
- `post_commitment_status`
- `a2cn_session_id`
- `a2cn_record_hash`
- `completed`

Middleware can then update its local post-commitment state for the matching
A2CN transaction record. Core protocol state does not need to change.

When a Connect HMAC secret is configured, validate the raw request body before
processing:

```python
valid = DocuSignConnectParser.verify_hmac_signature(
    payload_bytes,
    signature_header,
    secret,
)
```

---

## OAuth

`fetch_docusign_access_token()` implements the JWT bearer grant:

- `iss`: integration key
- `sub`: user ID
- `aud`: DocuSign auth host
- `scope`: `signature impersonation` by default
- grant type: `urn:ietf:params:oauth:grant-type:jwt-bearer`

For developer accounts, use the demo auth host:

```text
https://account-d.docusign.com
```

For production, use:

```text
https://account.docusign.com
```

---

## Navigator / CLM Notes

Navigator and CLM can be used downstream to discover, store, or route executed
contract records. The A2CN adapter keeps that as middleware responsibility:
DocuSign owns envelope execution and CLM workflow, while A2CN owns the neutral
bilateral transaction record and record hash.

---

## Known Limitations

- The adapter generates a deterministic text summary document, not a full legal
  contract template. Production deployments can replace the generated document
  with a CLM template while preserving the A2CN custom fields.
- Party DIDs do not inherently contain signer email addresses. Middleware must
  provide a DID-to-contact mapping.
- This module does not perform envelope creation or Connect acknowledgement
  network calls except for the OAuth token helper.
