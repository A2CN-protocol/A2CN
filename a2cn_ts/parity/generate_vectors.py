"""
Cross-language parity vector generator.

Run from the Python reference implementation environment:

    cd reference-implementation/python
    uv run --extra dev python ../../a2cn_ts/parity/generate_vectors.py

Emits a2cn_ts/parity/vectors.json containing:
  - JCS canonicalization byte vectors (exact canonical JSON strings)
  - hash_object outputs (base64url SHA-256 over JCS)
  - Ed25519 JWS tokens (deterministic — TypeScript must reproduce byte-identical)
  - ES256 JWS + JWT tokens (randomized signatures — TypeScript must verify them)
  - A full deterministic session (fixed keys/ids/timestamps, recorded signatures)
    whose replay through any conformant state machine must yield the same
    record_id, offer_chain_hash, and record_hash.

The TypeScript test parity/vectors.test.ts consumes this file.
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

from a2cn.crypto import (
    canonicalize,
    create_jwt,
    hash_object,
    private_key_from_jwk,
    public_key_to_jwk,
    sign_invitation,
    sign_jws,
)
from a2cn.record import A2CN_NAMESPACE, generate_transaction_record
from a2cn.session import SessionManager

# Fixed demo keys (committed in demos/two_process/demo_shared.*; demo-only).
BUYER_PRIVATE_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "yBqAozmK34lgmawkZJiql8cV8mBdLvmyVH8AHrThJHo",
    "y": "YlgfTYFme_XeFKLxzh0LLOKi-q7x6sqZAyGBVbglaX4",
    "d": "XZJC7OiOPA9RvV6yobPgm1kZdg9htDWgIxXP0wDT6b0",
}
SUPPLIER_PRIVATE_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "6vLBotDYauSe6zbkEWMLxM84MYXIXbsvqRU-yfvdOAM",
    "y": "iENZCpZVUyC63C9Y7fhtZ6z367TNAm1Iebia49zfGzY",
    "d": "Fp0yOmzWBBlaSTbhggddYAZEt97_mGyjSI6BUBywS9k",
}
# Fixed Ed25519 key (parity-vector-only).
ED25519_PRIVATE_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
}

BUYER_DID = "did:web:techcorp.example"
SUPPLIER_DID = "did:web:acme-corp.com"

buyer_priv = private_key_from_jwk(BUYER_PRIVATE_JWK)
supplier_priv = private_key_from_jwk(SUPPLIER_PRIVATE_JWK)
ed_priv = private_key_from_jwk(ED25519_PRIVATE_JWK)

buyer_pub_jwk = public_key_to_jwk(buyer_priv.public_key())
supplier_pub_jwk = public_key_to_jwk(supplier_priv.public_key())
ed_pub_jwk = public_key_to_jwk(ed_priv.public_key())


def make_did_document(did: str, key_id: str, public_key_jwk: dict) -> dict:
    vm_id = f"{did}#{key_id}"
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_key_jwk,
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    }


# ---------------------------------------------------------------------------
# 1. Canonicalization + hash vectors
# ---------------------------------------------------------------------------

CANONICAL_CASES = [
    {"b": 2, "a": 1},
    {"z": {"b": 2, "a": 1}, "a": 0, "list": [3, {"y": 2, "x": 1}, "s"]},
    {"unicode": "héllo wörld ünïcode ☃", "empty_obj": {}, "empty_arr": []},
    {"total_value": 10_500_000, "currency": "USD", "seat_count": 100},
    {"float_half": 1.5, "float_small": 0.25, "big_int": 9007199254740991},
    {"nested": {"deep": {"deeper": {"value": True, "other": False, "none": None}}}},
    ["array", "top", 1, 2, 3, {"k": "v"}],
    {"escape\"key": "va\\lue with \n newline and \t tab", "slash/": "//"},
]

canonicalization = [
    {
        "input": case,
        "canonical": canonicalize(case).decode("utf-8"),
        "hash": hash_object(case),
    }
    for case in CANONICAL_CASES
]

# ---------------------------------------------------------------------------
# 2. Signature vectors
# ---------------------------------------------------------------------------

JWS_PAYLOAD = "parity-vector-protocol-act-hash"

signatures = {
    # Ed25519 JWS is deterministic: TypeScript must produce the IDENTICAL token.
    "ed25519_jws": sign_jws(JWS_PAYLOAD, ed_priv, kid="did:web:parity.example#ed25519-1"),
    "ed25519_public_jwk": ed_pub_jwk,
    # ES256 signatures are randomized: TypeScript must VERIFY these tokens.
    "es256_jws": sign_jws(JWS_PAYLOAD, buyer_priv, kid=f"{BUYER_DID}#key-1"),
    "es256_public_jwk": buyer_pub_jwk,
    "jws_payload": JWS_PAYLOAD,
    # Long-lived JWT for cross-verification (fixed audience/issuer).
    "es256_jwt": create_jwt(
        BUYER_DID,
        SUPPLIER_DID,
        buyer_priv,
        kid=f"{BUYER_DID}#key-1",
        purpose="parity_vector",
        session_id="parity-session",
        exp_seconds=60 * 60 * 24 * 365 * 10,
    ),
    "jwt_issuer": BUYER_DID,
    "jwt_audience": SUPPLIER_DID,
}

# Invitation signature over JCS (Ed25519 → deterministic bytes).
invitation_dict = {
    "message_type": "session_invitation",
    "invitation_id": "11111111-2222-3333-4444-555555555555",
    "a2cn_version": "0.2",
    "inviter_did": "did:web:parity.example",
    "proposed_deal_type": "saas_renewal",
    "invitation_expires_at": "2030-01-01T00:00:00Z",
    "invitation_signature": "",
}
signatures["ed25519_invitation_signature"] = sign_invitation(invitation_dict, ed_priv)
signatures["invitation_dict"] = {
    **{k: v for k, v in invitation_dict.items() if k != "invitation_signature"},
    "invitation_signature": signatures["ed25519_invitation_signature"],
}

# ---------------------------------------------------------------------------
# 3. Deterministic session → transaction record
# ---------------------------------------------------------------------------

SESSION_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012"

session_init = {
    "message_type": "session_init",
    "message_id": "parity-init-1",
    "protocol_version": "0.2",
    "session_params": {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "subject": "Parity Vector Session",
        "subject_reference": "PARITY-REF-001",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    },
    "initiator": {
        "organization_name": "TechCorp Inc",
        "did": BUYER_DID,
        "verification_method": f"{BUYER_DID}#key-1",
        "agent_id": "parity-buyer-agent",
        "endpoint": "https://techcorp.example/api/a2cn",
    },
    "initiator_mandate": {"mandate_type": "declared"},
}

session_ack = {
    "message_type": "session_ack",
    "message_id": "parity-ack-1",
    "session_id": SESSION_ID,
    "in_reply_to": "parity-init-1",
    "protocol_version": "0.2",
    "session_params_accepted": {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    },
    "responder": {
        "organization_name": "Acme Corp",
        "did": SUPPLIER_DID,
        "verification_method": f"{SUPPLIER_DID}#key-1",
        "agent_id": "parity-seller-agent",
        "endpoint": "http://localhost:8000",
    },
    "responder_mandate": {"mandate_type": "declared"},
    "session_created_at": "2026-03-24T10:00:00Z",
    "current_turn": "initiator",
}


def build_offer(msg_type: str, msg_id: str, rnd: int, seq: int, sender_did: str,
                private_key, kid: str, terms: dict, timestamp: str,
                in_reply_to: str | None = None) -> dict:
    protocol_act = {
        "protocol_version": "0.2",
        "session_id": SESSION_ID,
        "round_number": rnd,
        "sequence_number": seq,
        "message_type": msg_type,
        "sender_did": sender_did,
        "timestamp": timestamp,
        "expires_at": "2030-01-01T00:00:00Z",
        "terms": terms,
    }
    pah = hash_object(protocol_act)
    msg = {
        "message_type": msg_type,
        "message_id": msg_id,
        "session_id": SESSION_ID,
        "round_number": rnd,
        "sequence_number": seq,
        "sender_did": sender_did,
        "sender_agent_id": "parity-agent",
        "sender_verification_method": kid,
        "timestamp": timestamp,
        "expires_at": "2030-01-01T00:00:00Z",
        "terms": terms,
        "protocol_act_hash": pah,
        "protocol_act_signature": sign_jws(pah, private_key, kid=kid),
    }
    if in_reply_to:
        msg["in_reply_to"] = in_reply_to
    return msg


offer_1 = build_offer(
    "offer", "parity-offer-1", 1, 1, BUYER_DID, buyer_priv, f"{BUYER_DID}#key-1",
    {"total_value": 9_500_000, "currency": "USD", "seat_count": 100},
    "2026-03-24T10:01:00Z",
)
counter_1 = build_offer(
    "counteroffer", "parity-counter-1", 2, 2, SUPPLIER_DID, supplier_priv,
    f"{SUPPLIER_DID}#key-1",
    {"total_value": 10_500_000, "currency": "USD", "seat_count": 100},
    "2026-03-24T10:02:00Z",
    in_reply_to="parity-offer-1",
)

acceptance_payload = {
    "session_id": SESSION_ID,
    "round_number": 2,
    "sequence_number": 3,
    "accepted_offer_id": "parity-counter-1",
    "accepted_protocol_act_hash": counter_1["protocol_act_hash"],
}
acceptance = {
    "message_type": "acceptance",
    "message_id": "parity-acc-1",
    "session_id": SESSION_ID,
    "in_reply_to": "parity-counter-1",
    "round_number": 2,
    "sequence_number": 3,
    "accepted_offer_id": "parity-counter-1",
    "accepted_protocol_act_hash": counter_1["protocol_act_hash"],
    "sender_did": BUYER_DID,
    "sender_agent_id": "parity-agent",
    "sender_verification_method": f"{BUYER_DID}#key-1",
    "timestamp": "2026-03-24T10:03:00Z",
    "acceptance_signature": sign_jws(
        hash_object(acceptance_payload), buyer_priv, kid=f"{BUYER_DID}#key-1"
    ),
}

# Replay through the Python state machine to derive the expected record.
manager = SessionManager()
manager.register_did_document(
    BUYER_DID, make_did_document(BUYER_DID, "key-1", buyer_pub_jwk)
)
manager.register_did_document(
    SUPPLIER_DID, make_did_document(SUPPLIER_DID, "key-1", supplier_pub_jwk)
)
session = manager.create_session(SESSION_ID, session_init, session_ack, "2026-03-24T10:00:00Z")
session.session_timeout_seconds = 86400 * 365 * 100
manager.process_message(session, offer_1)
manager.process_message(session, counter_1)
manager.process_message(session, acceptance)
assert session.state == "COMPLETED", session.state

record = generate_transaction_record(session)

session_vector = {
    "session_id": SESSION_ID,
    "buyer_did": BUYER_DID,
    "supplier_did": SUPPLIER_DID,
    "buyer_public_jwk": buyer_pub_jwk,
    "supplier_public_jwk": supplier_pub_jwk,
    "session_init": session_init,
    "session_ack": session_ack,
    "messages": [offer_1, counter_1, acceptance],
    "expected": {
        "a2cn_namespace": str(A2CN_NAMESPACE),
        "record_id": record["record_id"],
        "record_hash": record["record_hash"],
        "offer_chain_hash": record["offer_chain_hash"],
        "generated_at": record["generated_at"],
        "full_record": record,
    },
}

# ---------------------------------------------------------------------------
# Write vectors.json
# ---------------------------------------------------------------------------

vectors = {
    "generator": "reference-implementation/python via a2cn_ts/parity/generate_vectors.py",
    "canonicalization": canonicalization,
    "signatures": signatures,
    "session": session_vector,
}

out_path = HERE / "vectors.json"
out_path.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"Wrote {out_path}")
print(f"record_hash: {record['record_hash']}")
print(f"record_id:   {record['record_id']}")
