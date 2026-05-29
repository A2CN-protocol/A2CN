"""
Ironclad CLM -> A2CN translation layer.

Translates Ironclad workflow/webhook payloads into A2CN terms, and translates
completed A2CN terms back into Ironclad workflow metadata updates.

Ironclad public API references used for this adapter:
  Docs index:        https://developer.ironcladapp.com/llms.txt
  Retrieve workflow: GET   /public/api/v1/workflows/{id}
  Update metadata:   PATCH /public/api/v1/workflows/{id}/attributes
  Create record:     POST  /public/api/v1/records
  Webhooks:          GET   /public/api/v1/webhooks/verification-key

No core protocol changes are required; this module is a platform translation
layer with deterministic helpers and optional HTTP write-back.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


_SAAS_KEYWORDS = frozenset({"renewal", "subscription", "license", "seat", "saas"})


def _money_to_cents(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, dict):
        value = value.get("amount", 0)
    return int(float(value) * 100)


def _int_value(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    return int(float(value))


def _field(attributes: dict, *names: str, default: Any = None) -> Any:
    for name in names:
        if name in attributes:
            return attributes[name]
    return default


def _json_stringify_body(body: dict) -> str:
    """
    Match the compact JSON.stringify(body) form used in Ironclad's example.
    """
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def _deal_type_from_workflow(workflow: dict) -> str:
    haystack = " ".join(
        str(part).lower()
        for part in (
            workflow.get("title", ""),
            workflow.get("template", ""),
            workflow.get("workflowType", ""),
            workflow.get("type", ""),
        )
    )
    return "saas_renewal" if any(key in haystack for key in _SAAS_KEYWORDS) else "goods_procurement"


class IroncladWebhookParser:
    """
    Verifies and translates Ironclad workflow webhook payloads.

    Ironclad signs webhooks with a verification header containing nonce,
    signAlgorithm, signature, and encoding. The signed payload is:
    X-Ironclad-Webhook-Event-Id + JSON.stringify(body) + nonce.
    """

    @staticmethod
    def verify_webhook_signature(
        event_id: str,
        verification_header: str,
        body: dict,
        public_key_pem: str | bytes,
    ) -> bool:
        if not event_id or not verification_header or not public_key_pem:
            return False
        try:
            verification = json.loads(verification_header)
            nonce = verification["nonce"]
            algorithm = str(verification["signAlgorithm"]).upper().replace("-", "")
            signature = verification["signature"]
            encoding = verification.get("encoding", "base64").lower()
            if encoding == "base64":
                signature_bytes = base64.b64decode(signature)
            elif encoding == "hex":
                signature_bytes = bytes.fromhex(signature)
            else:
                return False
            if algorithm not in {"RSASHA256", "SHA256"}:
                return False

            public_key = serialization.load_pem_public_key(
                public_key_pem.encode("utf-8")
                if isinstance(public_key_pem, str)
                else public_key_pem
            )
            signed_data = (
                event_id + _json_stringify_body(body) + str(nonce)
            ).encode("utf-8")
            public_key.verify(
                signature_bytes,
                signed_data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except (KeyError, TypeError, ValueError, InvalidSignature):
            return False

    @staticmethod
    def workflow_event_to_session_inputs(
        payload: dict,
        max_rounds: int = 5,
        default_delivery_days: int = 14,
    ) -> dict:
        """
        Translate an Ironclad workflow event into A2CN session params and terms.

        Accepts either a full workflow object or a webhook wrapper containing
        ``workflow`` / ``data``. Workflow attributes follow the shape returned by
        Ironclad's Retrieve Workflow endpoint.
        """
        workflow = payload.get("workflow") or payload.get("data") or payload
        attributes = workflow.get("attributes", {})
        deal_type = _deal_type_from_workflow(workflow)

        counterparty = _field(
            attributes,
            "counterpartyName",
            "counterparty",
            "vendorName",
            default="",
        )
        currency = _field(attributes, "currency", default=None)
        amount = _field(
            attributes,
            "contractValue",
            "amount",
            "fee",
            "totalValue",
            default=0,
        )
        if isinstance(amount, dict):
            currency = amount.get("currency", currency)
        currency = currency or "USD"
        total_cents = _money_to_cents(amount)
        seat_count = max(_int_value(_field(attributes, "seatCount", "seat_count", default=1), 1), 1)
        term_months = max(_int_value(_field(attributes, "termMonths", "term_months", default=12), 12), 1)
        product = _field(
            attributes,
            "product",
            "productName",
            "subscriptionTier",
            default=workflow.get("title", "Ironclad workflow"),
        )

        terms: dict = {
            "deal_type": deal_type,
            "total_value": total_cents,
            "currency": currency,
            "line_items": [
                {
                    "description": product,
                    "quantity": seat_count if deal_type == "saas_renewal" else 1,
                    "unit_price": int(total_cents / max(seat_count, 1))
                    if deal_type == "saas_renewal"
                    else total_cents,
                    "total": total_cents,
                }
            ],
            "payment_terms": {
                "net_days": _int_value(
                    _field(attributes, "paymentTermsNetDays", "netDays", default=30),
                    30,
                )
            },
            "custom_terms": {
                "ironclad": {
                    "workflow_id": workflow.get("id", payload.get("workflowId", "")),
                    "ironclad_id": workflow.get("ironcladId", ""),
                    "counterparty_name": counterparty,
                }
            },
        }
        if deal_type == "saas_renewal":
            terms["seat_count"] = seat_count
            terms["subscription_tier"] = str(product)
            terms["term_months"] = term_months
        else:
            terms["delivery_days"] = _int_value(
                _field(attributes, "deliveryDays", "delivery_days", default=default_delivery_days),
                default_delivery_days,
            )

        session_params = {
            "deal_type": deal_type,
            "currency": currency,
            "max_rounds": max_rounds,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
            "ironclad_workflow_id": workflow.get("id", payload.get("workflowId", "")),
            "ironclad_id": workflow.get("ironcladId", ""),
            "counterparty_name": counterparty,
        }

        return {
            "event_id": payload.get("eventId", payload.get("event_id", "")),
            "event_type": payload.get("eventType", payload.get("event_type", "")),
            "workflow_id": session_params["ironclad_workflow_id"],
            "session_params": session_params,
            "initial_terms": terms,
            "raw_payload": payload,
        }


def a2cn_terms_to_ironclad_workflow(
    agreed_terms: dict,
    workflow_id: str,
    a2cn_session_id: str,
    record_hash: str,
    field_map: dict | None = None,
) -> dict:
    """
    Build the PATCH /workflows/{id}/attributes payload for agreed A2CN terms.

    Ironclad requires an ``updates`` array with ``set`` or ``remove`` actions.
    Field keys are configurable because workflow attribute IDs are tenant and
    template specific.
    """
    fields = {
        "contract_value": "contractValue",
        "currency": "currency",
        "term_months": "termMonths",
        "counterparty_name": "counterpartyName",
        "a2cn_session_id": "a2cnSessionId",
        "a2cn_record_hash": "a2cnRecordHash",
        "payment_terms_net_days": "paymentTermsNetDays",
    }
    fields.update(field_map or {})
    ironclad_meta = agreed_terms.get("custom_terms", {}).get("ironclad", {})
    updates = [
        {
            "action": "set",
            "path": fields["contract_value"],
            "value": {
                "currency": agreed_terms.get("currency", "USD"),
                "amount": agreed_terms.get("total_value", 0) / 100.0,
            },
        },
        {"action": "set", "path": fields["currency"], "value": agreed_terms.get("currency", "USD")},
        {"action": "set", "path": fields["a2cn_session_id"], "value": a2cn_session_id},
        {"action": "set", "path": fields["a2cn_record_hash"], "value": record_hash},
        {
            "action": "set",
            "path": fields["payment_terms_net_days"],
            "value": agreed_terms.get("payment_terms", {}).get("net_days", 30),
        },
    ]
    if agreed_terms.get("term_months") is not None:
        updates.append({
            "action": "set",
            "path": fields["term_months"],
            "value": agreed_terms["term_months"],
        })
    if ironclad_meta.get("counterparty_name"):
        updates.append({
            "action": "set",
            "path": fields["counterparty_name"],
            "value": ironclad_meta["counterparty_name"],
        })

    return {
        "workflow_id": workflow_id,
        "endpoint": f"/workflows/{workflow_id}/attributes",
        "payload": {
            "updates": updates,
            "comment": (
                f"A2CN negotiation completed. Session {a2cn_session_id}; "
                f"record hash {record_hash}."
            ),
        },
    }


def a2cn_terms_to_ironclad_record(
    agreed_terms: dict,
    record_type: str,
    name: str,
    a2cn_session_id: str,
    record_hash: str,
) -> dict:
    """
    Build the POST /records payload for formalizing an A2CN transaction record.
    """
    ironclad_meta = agreed_terms.get("custom_terms", {}).get("ironclad", {})
    return {
        "type": record_type,
        "name": name,
        "properties": {
            "counterpartyName": {
                "type": "string",
                "value": ironclad_meta.get("counterparty_name", ""),
            },
            "contractValue": {
                "type": "monetary_amount",
                "value": {
                    "currency": agreed_terms.get("currency", "USD"),
                    "amount": agreed_terms.get("total_value", 0) / 100.0,
                },
            },
            "a2cnSessionId": {"type": "string", "value": a2cn_session_id},
            "a2cnRecordHash": {"type": "string", "value": record_hash},
        },
    }


async def update_ironclad_workflow_metadata(
    workflow_id: str,
    update_payload: dict,
    as_user_email: str | None = None,
) -> dict:
    """
    Submit an Ironclad workflow metadata update using IRONCLAD_API_TOKEN.
    """
    token = os.environ.get("IRONCLAD_API_TOKEN")
    base_url = os.environ.get("IRONCLAD_BASE_URL", "https://na1.ironcladapp.com/public/api/v1")
    actor_email = as_user_email or os.environ.get("IRONCLAD_AS_USER_EMAIL")
    if not token:
        raise ValueError("IRONCLAD_API_TOKEN environment variable is required.")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if actor_email:
        headers["x-as-user-email"] = actor_email

    url = f"{base_url.rstrip('/')}/workflows/{workflow_id}/attributes"
    async with httpx.AsyncClient() as client:
        response = await client.patch(url, json=update_payload, headers=headers)
    response.raise_for_status()
    return response.json()
