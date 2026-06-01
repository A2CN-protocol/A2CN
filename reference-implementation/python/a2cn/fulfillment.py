"""
Concordia FulfillmentAttestation composition helpers.

The A2CN session remains the agreement pointer; this module emits the
Concordia-shaped fulfillment artifact that downstream Concordia tooling can
verify.
"""

from __future__ import annotations

import base64
import copy
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a2cn.crypto import canonicalize


FULFILLMENT_ATTESTATION_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:concordia:schema:fulfillment_attestation:v0.5",
    "title": "Concordia Fulfillment Attestation",
    "description": (
        "A standalone signed artifact emitted after settlement, recording whether "
        "an agreement was honored. Distinct from the in-line `fulfillment` block "
        "on a reputation attestation (SPEC.md Section 9.6.4) - this is the A2CN-aligned "
        "shape emitted on a discrete DELIVERY_ACKNOWLEDGED boundary, linking back "
        "to the agreement attestation via `references[]` with `relationship: "
        "\"fulfills\"`. Introduced in v0.5 per A2A Discussion #1737. See "
        "docs/A2CN_FULFILLMENT.md for the integrator walkthrough and SPEC.md "
        "Section 9.6.4 for the relationship with the in-line fulfillment block."
    ),
    "type": "object",
    "required": [
        "attestation_type",
        "id",
        "issued_at",
        "agreement_attestation_id",
        "fulfillment",
        "references",
        "signature",
    ],
    "properties": {
        "attestation_type": {
            "type": "string",
            "const": "FulfillmentAttestation",
        },
        "id": {"type": "string", "minLength": 1},
        "issued_at": {"type": "string", "format": "date-time"},
        "agreement_attestation_id": {"type": "string", "minLength": 1},
        "fulfillment": {
            "type": "object",
            "required": ["status"],
            "additionalProperties": True,
            "properties": {
                "status": {
                    "type": "string",
                    "enum": [
                        "fulfilled_clean",
                        "fulfilled_with_mediation",
                        "failed",
                        "disputed_unresolved",
                    ],
                },
                "settled_at": {"type": "string", "format": "date-time"},
            },
        },
        "references": {
            "type": "array",
            "minItems": 1,
            "contains": {
                "type": "object",
                "required": ["relationship"],
                "properties": {"relationship": {"const": "fulfills"}},
            },
            "items": {
                "type": "object",
                "required": ["id", "type", "relationship"],
                "properties": {
                    "id": {"type": "string"},
                    "type": {"type": "string"},
                    "relationship": {"type": "string"},
                },
                "additionalProperties": True,
            },
        },
        "meta": {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "mediator_invoked": {"type": "boolean"},
                "resolution_outcome": {"type": "string"},
                "resolver_did": {"type": "string"},
                "resolution_timestamp": {"type": "string", "format": "date-time"},
                "fulfillment_evidence": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
        },
        "signature": {
            "type": "object",
            "required": ["alg", "value"],
            "additionalProperties": True,
            "properties": {
                "alg": {"type": "string", "enum": ["Ed25519"]},
                "value": {"type": "string", "minLength": 1},
                "signer_did": {"type": "string"},
            },
        },
    },
    "allOf": [
        {
            "if": {
                "properties": {
                    "fulfillment": {
                        "properties": {
                            "status": {"const": "fulfilled_with_mediation"},
                        },
                        "required": ["status"],
                    },
                },
                "required": ["fulfillment"],
            },
            "then": {
                "properties": {
                    "meta": {
                        "type": "object",
                        "properties": {"mediator_invoked": {"const": True}},
                        "required": ["mediator_invoked"],
                    },
                },
                "required": ["meta"],
            },
        },
    ],
    "additionalProperties": True,
}


def build_fulfillment_attestation(
    session_record: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    signer_did: str | None = None,
    dispute_resolved_message: dict[str, Any] | None = None,
    issued_at: str | None = None,
) -> dict[str, Any]:
    """
    Build and Ed25519-sign a Concordia FulfillmentAttestation.

    `session_record["session_id"]` is used as Concordia's
    agreement_attestation_id pointer for the A2CN composition.
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("FulfillmentAttestation signing requires an Ed25519 private key")

    session_id = session_record.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_record must include a non-empty session_id")

    now = issued_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fulfillment: dict[str, Any] = {
        "status": _fulfillment_status(dispute_resolved_message),
    }

    if dispute_resolved_message is not None:
        settled_at = dispute_resolved_message.get("resolution_timestamp")
    else:
        delivery_ack = session_record.get("delivery_acknowledged") or {}
        settled_at = delivery_ack.get("acknowledgment_timestamp")
    if isinstance(settled_at, str) and settled_at:
        fulfillment["settled_at"] = settled_at

    attestation: dict[str, Any] = {
        "attestation_type": "FulfillmentAttestation",
        "id": f"urn:concordia:fulfillment:{uuid.uuid4()}",
        "issued_at": now,
        "agreement_attestation_id": session_id,
        "fulfillment": fulfillment,
        "references": [
            {"type": "receipt", "id": session_id, "relationship": "fulfills"},
            {
                "type": "chain_session",
                "id": f"urn:a2cn:session:{session_id}",
                "relationship": "references",
            },
        ],
    }

    meta = _meta_from_dispute_resolution(dispute_resolved_message)
    if meta:
        attestation["meta"] = meta

    attestation["signature"] = _sign_attestation(attestation, private_key, signer_did)
    validate_fulfillment_attestation(attestation)
    return attestation


def validate_fulfillment_attestation(attestation: dict[str, Any]) -> None:
    """Validate against the Concordia schema when jsonschema is installed."""
    try:
        import jsonschema
    except ImportError:
        return
    jsonschema.validate(attestation, FULFILLMENT_ATTESTATION_SCHEMA)


def _fulfillment_status(dispute_resolved_message: dict[str, Any] | None) -> str:
    if dispute_resolved_message is None:
        return "fulfilled_clean"

    outcome = dispute_resolved_message.get("resolution_outcome")
    if outcome in {"buyer_prevails", "seller_prevails", "mutual_settlement"}:
        return "fulfilled_with_mediation"
    raise ValueError(f"Unsupported resolution_outcome for fulfillment attestation: {outcome!r}")


def _meta_from_dispute_resolution(
    dispute_resolved_message: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if dispute_resolved_message is None:
        return None

    meta: dict[str, Any] = {"mediator_invoked": True}
    for source_key, target_key in (
        ("resolution_outcome", "resolution_outcome"),
        ("resolver_did", "resolver_did"),
        ("resolution_timestamp", "resolution_timestamp"),
        ("evidence_references", "fulfillment_evidence"),
    ):
        value = dispute_resolved_message.get(source_key)
        if value:
            meta[target_key] = value
    return meta


def _sign_attestation(
    attestation: dict[str, Any],
    private_key: Ed25519PrivateKey,
    signer_did: str | None,
) -> dict[str, Any]:
    unsigned = copy.deepcopy(attestation)
    unsigned.pop("signature", None)
    signature = {
        "alg": "Ed25519",
        "value": _b64url(private_key.sign(canonicalize(unsigned))),
    }
    if signer_did:
        signature["signer_did"] = signer_did
    return signature


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
