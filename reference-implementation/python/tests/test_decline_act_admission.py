"""What a receiver admits on the two decline paths (Sections 7.5, 7.6).

decline-act-admission.json pins two rules, and both suites run every case in it
through the state machine.

A present signature is always checked. The signed-act guard used to ask whether
the signature field was truthy, so an empty string — and, here only, an empty
object or list, or a zero — was read as "unsigned" and skipped the check that a
present signature makes mandatory. The act then entered the message log as one
the evidence record's classifier calls signed but that cannot verify. Only an
absent field is the unsigned act; a present one, null included, is a signature
claim, which is what the published schemas say too.

A withdrawal carries a valid round_number: the round in progress, so 1 before
any offer. It is part of the common header every
signed act covers and withdrawal.schema.json requires it unconditionally, but
the runtime checked round_number on the other act types only, so it accepted a
withdrawal the published schema refuses. Each round_number case is checked
against the schema here as well, so the two cannot drift apart again.

The TypeScript suite runs the same cases.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.crypto import generate_keypair, public_key_to_jwk, sign_jws
from a2cn.messages import (
    PROTOCOL_ACT_VERSION,
    SIGNED_ACT_SIGNATURE_FIELDS,
    Withdrawal,
    signed_act_hash,
)
from a2cn.session import A2CNError, SessionManager, SessionState
from tests.conftest import make_did_document
from tests.test_session import (
    INITIATOR_DID,
    INITIATOR_PUBLIC_KEY,
    RESPONDER_DID,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_PUBLIC_KEY,
    SESSION_ACK,
    SESSION_INIT,
    _make_offer,
)

REPO_ROOT = Path(__file__).parents[3]
VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "decline-act-admission.json").read_text()
)
WITHDRAWAL_SCHEMA = json.loads(
    (REPO_ROOT / "spec" / "schemas" / "withdrawal.schema.json").read_text()
)
SIGNATURE_CASES = VECTOR["signature_presence"]["cases"]
ROUND_CASES = VECTOR["withdrawal_round_number"]["cases"]


def _session_at_negotiating():
    """The vector's session: the initiator's signed round-1 offer, processed."""
    manager = SessionManager()
    manager.register_did_document(
        INITIATOR_DID,
        make_did_document(INITIATOR_DID, "key-1", public_key_to_jwk(INITIATOR_PUBLIC_KEY)),
    )
    manager.register_did_document(
        RESPONDER_DID,
        make_did_document(RESPONDER_DID, "key-2026-01", public_key_to_jwk(RESPONDER_PUBLIC_KEY)),
    )
    session_id = VECTOR["session"]["session_id"]
    session = manager.create_session(session_id, SESSION_INIT, SESSION_ACK, "2026-03-24T10:00:00Z")
    # The fixtures use a historical created_at; a large timeout keeps the session
    # from expiring mid-test.
    session.session_timeout_seconds = 86400 * 365 * 100
    manager.process_message(session, _make_offer(session_id, 1, 1, INITIATOR_DID))
    assert session.state == VECTOR["session"]["state_before"]
    return manager, session


def _assert_verdict(manager, session, act: dict, case: dict) -> None:
    if case["accepted"]:
        manager.process_message(session, act)
        assert session.state == case["state_after"]
        assert act in session._message_log
        return
    state_before = session.state
    with pytest.raises(A2CNError) as excinfo:
        manager.process_message(session, act)
    assert (excinfo.value.code, excinfo.value.message) == (
        case["error_code"],
        case["error_message"],
    )
    assert session.state == state_before
    assert act not in session._message_log


def test_the_vector_matches_this_implementation_and_its_fixtures():
    assert VECTOR["signature_fields"] == {
        act_type: SIGNED_ACT_SIGNATURE_FIELDS[act_type] for act_type in ("rejection", "withdrawal")
    }
    assert VECTOR["session"]["initiator_did"] == INITIATOR_DID
    assert VECTOR["session"]["responder_did"] == RESPONDER_DID
    for act in VECTOR["acts"].values():
        assert act["session_id"] == VECTOR["session"]["session_id"]
        assert act["sender_did"] == RESPONDER_DID
        assert act["sender_verification_method"] == VECTOR["session"]["responder_verification_method"]
    # The round_number cases are only meaningful if they differ from a valid act
    # in round_number alone, so the base withdrawal must be schema-valid.
    base = copy.deepcopy(VECTOR["acts"]["withdrawal"])
    assert _schema_errors(base) == []


# ---------------------------------------------------------------------------
# A present signature is always checked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", SIGNATURE_CASES, ids=[c["name"] for c in SIGNATURE_CASES])
def test_signature_presence(case):
    manager, session = _session_at_negotiating()
    act = copy.deepcopy(VECTOR["acts"][case["act_type"]])
    field = VECTOR["signature_fields"][case["act_type"]]
    if "signature" in case:
        act[field] = case["signature"]
    else:
        act.pop(field, None)

    _assert_verdict(manager, session, act, case)


# ---------------------------------------------------------------------------
# A withdrawal carries a valid round_number, and schema and runtime agree
# ---------------------------------------------------------------------------


def _schema_errors(instance: dict) -> list:
    jsonschema = pytest.importorskip("jsonschema")
    return list(jsonschema.Draft202012Validator(WITHDRAWAL_SCHEMA).iter_errors(instance))


def _withdrawal_for(case: dict, *, signed: bool) -> dict:
    act = copy.deepcopy(VECTOR["acts"]["withdrawal"])
    if "round_number" in case:
        act["round_number"] = case["round_number"]
    else:
        del act["round_number"]
    if not signed:
        del act["sender_verification_method"]
        return act
    vm = act["sender_verification_method"]
    # An act that does not rebuild has no hash to sign, so it is signed over a
    # stand-in payload, exactly as a sender that stripped or mangled the field
    # would have to.
    payload_hash = signed_act_hash(act, version_when_absent=PROTOCOL_ACT_VERSION) or "0" * 43
    act["withdrawal_signature"] = sign_jws(payload_hash, RESPONDER_PRIVATE_KEY, kid=vm)
    return act


@pytest.mark.parametrize("signed", [False, True], ids=["unsigned", "signed"])
@pytest.mark.parametrize("case", ROUND_CASES, ids=[c["name"] for c in ROUND_CASES])
def test_withdrawal_round_number(case, signed):
    manager, session = _session_at_negotiating()
    act = _withdrawal_for(case, signed=signed)

    _assert_verdict(manager, session, act, case)


@pytest.mark.parametrize("signed", [False, True], ids=["unsigned", "signed"])
@pytest.mark.parametrize("case", ROUND_CASES, ids=[c["name"] for c in ROUND_CASES])
def test_withdrawal_round_number_schema_agrees_with_the_runtime(case, signed):
    act = _withdrawal_for(case, signed=signed)

    assert case["schema_valid"] == case["accepted"]
    assert (_schema_errors(act) == []) is case["schema_valid"]


def test_withdrawal_round_number_cases_cover_both_verdicts():
    """A vector whose cases all agree on one verdict would prove nothing."""
    verdicts = {case["accepted"] for case in ROUND_CASES}
    assert verdicts == {True, False}
    assert any("round_number" not in case for case in ROUND_CASES)


# ---------------------------------------------------------------------------
# The library's own Withdrawal type builds what the runtime admits
# ---------------------------------------------------------------------------


def test_the_withdrawal_type_builds_a_withdrawal_the_runtime_accepts():
    """The message class is the other producer of a withdrawal, so it is held to
    the same rule as the wire: its output must carry round_number."""
    manager, session = _session_at_negotiating()
    act = Withdrawal(
        message_type="withdrawal",
        message_id="typed-wd-1",
        session_id=session.session_id,
        round_number=1,
        sequence_number=2,
        sender_did=RESPONDER_DID,
        sender_agent_id="acme-agent",
        timestamp="2026-03-24T10:05:00Z",
        reason_code="STRATEGY_DECISION",
        in_reply_to="offer-1",
    ).to_dict()

    manager.process_message(session, act)

    assert act["round_number"] == 1
    assert session.state == SessionState.WITHDRAWN


def test_the_withdrawal_type_carries_round_1_before_any_offer():
    manager = SessionManager()
    session = manager.create_session(
        VECTOR["session"]["session_id"], SESSION_INIT, SESSION_ACK, "2026-03-24T10:00:00Z"
    )
    session.session_timeout_seconds = 86400 * 365 * 100
    act = Withdrawal(
        message_type="withdrawal",
        message_id="typed-wd-pre-offer",
        session_id=session.session_id,
        round_number=1,
        sequence_number=1,
        sender_did=INITIATOR_DID,
        sender_agent_id="tc-agent",
        timestamp="2026-03-24T10:02:00Z",
        reason_code="NO_REASON_GIVEN",
    ).to_dict()

    manager.process_message(session, act)

    assert act["round_number"] == 1
    assert session.state == SessionState.WITHDRAWN


def test_the_withdrawal_type_requires_round_number():
    with pytest.raises(TypeError):
        Withdrawal(
            message_type="withdrawal",
            message_id="typed-wd-2",
            session_id="sess-001",
            sequence_number=2,
            sender_did=RESPONDER_DID,
            sender_agent_id="acme-agent",
            timestamp="2026-03-24T10:05:00Z",
            reason_code="STRATEGY_DECISION",
        )
