"""The five act types each have a published schema (Section 17).

Section 7.4, 7.5 and 7.6 have always named `acceptance.schema.json`,
`rejection.schema.json` and `withdrawal.schema.json`, and Section 17 has always
listed them, but the files did not exist. A verifier that gates on act type had
nothing to check an acceptance or a decline against.

A schema constrains what a conformant producer emits and is deliberately
stricter than a verifier (Section 17): verification is decided by the rebuild of
Section 7.3.1, not by a field's length or floor. These tests therefore pin the
producer contract, in both directions — a real message validates, and a
malformed one is actually rejected. A validator that only ever says yes proves
nothing.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.crypto import generate_keypair, sign_jws
from a2cn.messages import PROTOCOL_ACT_VERSION, SIGNED_ACT_SIGNATURE_FIELDS, signed_act_hash

REPO_ROOT = Path(__file__).parents[3]
SCHEMAS = REPO_ROOT / "spec" / "schemas"
VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "transaction-record-basis.json").read_text()
)
# A real captured acceptance, not a hand-built fixture.
ACCEPTANCE = next(m for m in VECTOR["messages"] if m["message_type"] == "acceptance")

SIGNER_PRIVATE_KEY, _SIGNER_PUBLIC_KEY = generate_keypair()
SENDER_DID = "did:web:techcorp.example"
SENDER_VM = f"{SENDER_DID}#key-1"


def _schema(name: str) -> dict:
    return json.loads((SCHEMAS / f"{name}.schema.json").read_text())


def _errors(schema: dict, instance: dict) -> list:
    jsonschema = pytest.importorskip("jsonschema")
    return list(jsonschema.Draft202012Validator(schema).iter_errors(instance))


def _sign(act: dict) -> dict:
    signed = copy.deepcopy(act)
    signed["sender_verification_method"] = SENDER_VM
    signed[SIGNED_ACT_SIGNATURE_FIELDS[act["message_type"]]] = sign_jws(
        signed_act_hash(signed),
        SIGNER_PRIVATE_KEY,
        kid=SENDER_VM,
    )
    return signed


def _rejection() -> dict:
    return {
        "message_type": "rejection",
        "message_id": "rejection-1",
        "session_id": VECTOR["session_id"],
        "in_reply_to": "basis-counter-1",
        "round_number": 2,
        "sequence_number": 4,
        "rejected_offer_id": "basis-counter-1",
        "sender_did": SENDER_DID,
        "sender_agent_id": "basis-agent",
        "timestamp": "2026-03-24T10:04:00Z",
        "reason_code": "PRICE_TOO_HIGH",
        "reason_description": "above mandate",
    }


def _withdrawal() -> dict:
    return {
        "message_type": "withdrawal",
        "message_id": "withdrawal-1",
        "session_id": VECTOR["session_id"],
        "in_reply_to": "basis-counter-1",
        "round_number": 2,
        "sequence_number": 4,
        "sender_did": SENDER_DID,
        "sender_agent_id": "basis-agent",
        "timestamp": "2026-03-24T10:04:00Z",
        "reason_code": "STRATEGY_DECISION",
    }


# ---------------------------------------------------------------------------
# The schemas are themselves valid, and they are the files the spec names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["acceptance", "rejection", "withdrawal"])
def test_schema_is_valid_draft_2020_12(name: str):
    jsonschema = pytest.importorskip("jsonschema")

    jsonschema.Draft202012Validator.check_schema(_schema(name))


@pytest.mark.parametrize("name", ["acceptance", "rejection", "withdrawal"])
def test_schema_id_states_the_wire_version(name: str):
    assert _schema(name)["$id"] == f"https://a2cn.dev/schemas/{name}/{PROTOCOL_ACT_VERSION}"


# ---------------------------------------------------------------------------
# Real messages validate
# ---------------------------------------------------------------------------


def test_a_captured_acceptance_validates():
    assert _errors(_schema("acceptance"), ACCEPTANCE) == []


def test_a_signed_rejection_validates():
    assert _errors(_schema("rejection"), _sign(_rejection())) == []


def test_a_signed_withdrawal_validates():
    assert _errors(_schema("withdrawal"), _sign(_withdrawal())) == []


def test_an_unsigned_decline_validates():
    """Signing a decline is OPTIONAL, so an unsigned one is still conformant."""
    assert _errors(_schema("rejection"), _rejection()) == []
    assert _errors(_schema("withdrawal"), _withdrawal()) == []


# ---------------------------------------------------------------------------
# Malformed messages are actually rejected — the other direction
# ---------------------------------------------------------------------------


def test_a_withdrawal_without_round_number_is_rejected():
    """round_number is REQUIRED so the common header can be rebuilt (Section 7.6)."""
    without_round = _withdrawal()
    del without_round["round_number"]

    assert _errors(_schema("withdrawal"), without_round) != []


@pytest.mark.parametrize(
    ("name", "build"),
    [("rejection", _rejection), ("withdrawal", _withdrawal)],
)
def test_a_signature_without_its_verification_method_is_rejected(name: str, build):
    """A signature nobody can locate a key for is not a conformant message."""
    signed = _sign(build())
    del signed["sender_verification_method"]

    assert _errors(_schema(name), signed) != []


def test_an_unknown_reason_code_is_rejected():
    rejection = _rejection()
    rejection["reason_code"] = "BECAUSE_I_SAID_SO"
    withdrawal = _withdrawal()
    withdrawal["reason_code"] = "PRICE_TOO_HIGH"  # a rejection's code, not a withdrawal's

    assert _errors(_schema("rejection"), rejection) != []
    assert _errors(_schema("withdrawal"), withdrawal) != []


def test_a_malformed_accepted_protocol_act_hash_is_rejected():
    acceptance = copy.deepcopy(ACCEPTANCE)
    acceptance["accepted_protocol_act_hash"] = "too-short"

    assert _errors(_schema("acceptance"), acceptance) != []


def test_a_relabelled_act_does_not_validate_against_another_types_schema():
    """message_type is pinned, so a schema admits exactly one act type."""
    assert _errors(_schema("withdrawal"), _sign(_rejection())) != []
    assert _errors(_schema("rejection"), _sign(_withdrawal())) != []
    assert _errors(_schema("acceptance"), _sign(_rejection())) != []
