"""The wire version a recorded act is rebuilt under (Section 7.3.1).

A live act does not state its wire version on the wire, so which version its
signature is checked against depends on where the act is read:

  - a live act is rebuilt under its session's negotiated version;
  - a recorded act that states a version is rebuilt under the version it states;
  - a recorded act that states none is rebuilt under the pinned "0.2".

A SessionEvidenceRecord used to store its acts as they came off the wire, with
no version, and a verifier rebuilt them under whatever version it emitted. Moving
the emitted version would then have left every stored record unverifiable. The
generator now states each session act's version, and the version-less reading is
pinned, so a record verifies the same way under every later emit version.

session-evidence-record-wire-version.json pins all three. The TypeScript suite
runs the same cases.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.crypto import (
    canonicalize,
    generate_keypair,
    hash_bytes,
    hash_object,
    private_key_from_jwk,
    public_key_to_jwk,
    sign_jws,
)
from a2cn.evidence import generate_session_evidence_record, verify_session_evidence_record
from a2cn.messages import (
    LEGACY_VERSIONLESS_WIRE_VERSION,
    PROTOCOL_ACT_VERSION,
    SIGNED_ACT_SIGNATURE_FIELDS,
    signed_act_hash,
)
from a2cn.session import A2CNError, Session, SessionManager
from tests.conftest import make_did_document

VECTOR = json.loads(
    (
        Path(__file__).parents[3]
        / "spec"
        / "test-vectors"
        / "session-evidence-record-wire-version.json"
    ).read_text()
)
DID_DOCUMENTS = VECTOR["did_documents"]
PRODUCER = VECTOR["producer"]
PRODUCER_KEY = private_key_from_jwk(VECTOR["producer_private_jwk"])
CURRENT = VECTOR["current"]
LEGACY_RECORD = VECTOR["legacy_record"]
OBSERVED = VECTOR["observed"]


def _current_record() -> dict:
    return _record_for(CURRENT["session"])


def _record_for(source: dict, observed_acts: list | None = None) -> dict:
    session = Session(
        session_id=source["session_id"],
        state=source["state"],
        current_turn="none",
        terminal_reason=source["terminal_reason"],
        terminal_message_id=source["terminal_message_id"],
        session_created_at=source["session_created_at"],
        state_updated_at=source["state_updated_at"],
        session_params=source["session_params"],
        initiator_mandate=source["initiator_mandate"],
        responder_mandate=source["responder_mandate"],
    )
    session._session_init = source["session_init"]
    session._session_ack = source["session_ack"]
    session._message_log = source["message_log"]
    return generate_session_evidence_record(
        session,
        producer_private_key=PRODUCER_KEY,
        producer_did=PRODUCER["did"],
        producer_agent_id=PRODUCER["agent_id"],
        producer_verification_method=PRODUCER["verification_method"],
        observed_acts=observed_acts,
    )


BASES = {
    "current": CURRENT["expected"]["record"],
    "legacy": LEGACY_RECORD,
    "observed": OBSERVED["expected"]["record"],
}


def _edited(case: dict) -> dict:
    base = BASES[case["base"]]
    record = copy.deepcopy(base)
    entry = record["acts"][case["act_index"]]
    if case.get("remove_protocol_version"):
        del entry["act"]["protocol_version"]
    else:
        entry["act"]["protocol_version"] = case["set_protocol_version"]
    entry["act_hash"] = hash_object(entry["act"])
    record["act_chain_hash"] = hash_bytes(canonicalize([e["act_hash"] for e in record["acts"]]))
    record["record_hash"] = ""
    record["producer_signature"] = ""
    record["record_hash"] = hash_object(record)
    record["producer_signature"] = sign_jws(
        record["record_hash"], PRODUCER_KEY, kid=PRODUCER["verification_method"]
    )
    return record


def test_the_emit_version_is_not_the_pinned_legacy_version():
    """Without this, every legacy case below would pass by coincidence."""
    assert PROTOCOL_ACT_VERSION == "0.3"
    assert LEGACY_VERSIONLESS_WIRE_VERSION == "0.2"
    assert CURRENT["session"]["session_ack"]["protocol_version"] == PROTOCOL_ACT_VERSION


# ---------------------------------------------------------------------------
# A new record states each session act's wire version, and verifies
# ---------------------------------------------------------------------------


def test_a_new_record_states_each_acts_wire_version_and_matches_the_vector():
    expected = CURRENT["expected"]
    record = _current_record()

    assert [e["act"]["protocol_version"] for e in record["acts"]] == expected["stated_versions"]
    assert set(expected["stated_versions"]) == {PROTOCOL_ACT_VERSION}
    assert record["record_version"] == expected["record_version"]
    assert [e["act_hash"] for e in record["acts"]] == expected["act_hashes"]
    assert record["act_chain_hash"] == expected["act_chain_hash"]
    assert record["record_hash"] == expected["record_hash"]
    assert record == expected["record"]
    assert verify_session_evidence_record(record, DID_DOCUMENTS)


def test_the_session_log_itself_is_left_as_it_came_off_the_wire():
    """The version is stated in the record, not written back into the session."""
    _current_record()
    assert all("protocol_version" not in m for m in CURRENT["session"]["message_log"])


# ---------------------------------------------------------------------------
# A legacy record, whose acts state no version, still verifies
# ---------------------------------------------------------------------------


def test_a_legacy_record_whose_acts_state_no_version_still_verifies():
    assert all("protocol_version" not in e["act"] for e in LEGACY_RECORD["acts"])
    assert any(e["signature"] for e in LEGACY_RECORD["acts"])
    assert verify_session_evidence_record(LEGACY_RECORD, DID_DOCUMENTS)


# ---------------------------------------------------------------------------
# Each edit to a stated version reaches the vector's hash and verdict
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", VECTOR["edit_cases"], ids=lambda case: case["name"])
def test_an_edited_stated_version(case):
    record = _edited(case)

    assert record["record_hash"] == case["resealed_record_hash"]
    assert verify_session_evidence_record(record, DID_DOCUMENTS) is case["verifies"]


def test_the_edit_cases_cover_both_verdicts():
    assert {case["verifies"] for case in VECTOR["edit_cases"]} == {True, False}


# ---------------------------------------------------------------------------
# A live act is checked under its session's negotiated version
# ---------------------------------------------------------------------------


def _session_at(version: str, session_id: str) -> tuple[SessionManager, object]:
    """The vector's session, negotiated at the given version."""
    source = CURRENT["session"]
    manager = SessionManager()
    for did, document in DID_DOCUMENTS.items():
        manager.register_did_document(did, document)
    init = {**source["session_init"], "protocol_version": version}
    ack = {**source["session_ack"], "protocol_version": version}
    # A session at a superseded version exists only as a replay (Section 11.2.1).
    session = manager.create_session(
        session_id,
        init,
        ack,
        source["session_created_at"],
        legacy_replay=version != PROTOCOL_ACT_VERSION,
    )
    session.session_timeout_seconds = 86400 * 365 * 100
    return manager, session


def _first_offer(signed_under: str) -> dict:
    """A round-1 offer signed under the given version, as it went on the wire.

    The 0.3 offer is the current session's; the 0.2 offer is the one the legacy
    record holds, which states no version, exactly as it was received.
    """
    if signed_under == PROTOCOL_ACT_VERSION:
        offer = copy.deepcopy(CURRENT["session"]["message_log"][0])
    else:
        offer = copy.deepcopy(LEGACY_RECORD["acts"][0]["act"])
    assert offer["message_type"] == "offer"
    assert "protocol_version" not in offer
    return offer


@pytest.mark.parametrize("negotiated", [PROTOCOL_ACT_VERSION, LEGACY_VERSIONLESS_WIRE_VERSION])
def test_a_live_offer_is_checked_under_the_negotiated_version(negotiated):
    for signed_under in (PROTOCOL_ACT_VERSION, LEGACY_VERSIONLESS_WIRE_VERSION):
        offer = _first_offer(signed_under)
        manager, session = _session_at(negotiated, offer["session_id"])
        assert session.protocol_version == negotiated
        if signed_under == negotiated:
            manager.process_message(session, offer)
            assert offer in session._message_log
        else:
            with pytest.raises(A2CNError) as excinfo:
                manager.process_message(session, offer)
            assert excinfo.value.code == "INVALID_SIGNATURE"


def test_a_live_act_stating_another_version_is_refused():
    offer = _first_offer(PROTOCOL_ACT_VERSION)
    manager, session = _session_at(PROTOCOL_ACT_VERSION, offer["session_id"])
    offer["protocol_version"] = LEGACY_VERSIONLESS_WIRE_VERSION

    with pytest.raises(A2CNError) as excinfo:
        manager.process_message(session, offer)

    assert (excinfo.value.code, excinfo.value.message) == (
        "PROTOCOL_VERSION_MISMATCH",
        "protocol_version does not match the session's negotiated version",
    )
    assert offer not in session._message_log


def test_a_live_act_stating_its_own_negotiated_version_is_accepted():
    offer = _first_offer(PROTOCOL_ACT_VERSION)
    manager, session = _session_at(PROTOCOL_ACT_VERSION, offer["session_id"])
    offer["protocol_version"] = PROTOCOL_ACT_VERSION

    manager.process_message(session, offer)

    assert offer in session._message_log


# ---------------------------------------------------------------------------
# A caller that signs a new act without naming a version fails closed
# ---------------------------------------------------------------------------


BUYER_DID = "did:web:techcorp.example"
SELLER_DID = "did:web:acme-corp.com"
BUYER_VM = f"{BUYER_DID}#key-1"
SELLER_VM = f"{SELLER_DID}#key-1"
BUYER_KEY, BUYER_PUBLIC = generate_keypair()
SELLER_KEY, SELLER_PUBLIC = generate_keypair()
FAIL_CLOSED_PARAMS = {
    "deal_type": "saas_renewal",
    "currency": "USD",
    "subject": "Test",
    "max_rounds": 4,
    "session_timeout_seconds": 3600,
    "round_timeout_seconds": 900,
}
TERMS = {"total_value": 9_500_000, "currency": "USD"}
UNNAMED = object()


def _signed(act: dict, key, vm: str, version) -> dict:
    """Sign the act as a caller would, naming a version or (UNNAMED) naming none."""
    act = copy.deepcopy(act)
    act["sender_verification_method"] = vm
    options = {} if version is UNNAMED else {"version_when_absent": version}
    payload_hash = signed_act_hash(act, **options)
    if act["message_type"] in ("offer", "counteroffer"):
        act["protocol_act_hash"] = payload_hash
    act[SIGNED_ACT_SIGNATURE_FIELDS[act["message_type"]]] = sign_jws(payload_hash, key, kid=vm)
    return act


def _fail_closed_session():
    manager = SessionManager()
    manager.register_did_document(
        BUYER_DID, make_did_document(BUYER_DID, "key-1", public_key_to_jwk(BUYER_PUBLIC))
    )
    manager.register_did_document(
        SELLER_DID, make_did_document(SELLER_DID, "key-1", public_key_to_jwk(SELLER_PUBLIC))
    )
    init = {
        "message_type": "session_init",
        "message_id": "fc-init-1",
        "protocol_version": PROTOCOL_ACT_VERSION,
        "session_params": FAIL_CLOSED_PARAMS,
        "initiator": {"did": BUYER_DID, "verification_method": BUYER_VM},
        "initiator_mandate": {"mandate_type": "declared"},
    }
    ack = {
        "message_type": "session_ack",
        "message_id": "fc-ack-1",
        "session_id": "sess-fail-closed",
        "protocol_version": PROTOCOL_ACT_VERSION,
        "session_params_accepted": FAIL_CLOSED_PARAMS,
        "responder": {"did": SELLER_DID, "verification_method": SELLER_VM},
        "responder_mandate": {"mandate_type": "declared"},
    }
    session = manager.create_session("sess-fail-closed", init, ack, "2026-03-24T10:00:00Z")
    session.session_timeout_seconds = 86400 * 365 * 100
    return manager, session


def _offer(message_type: str, seq: int, rnd: int, did: str) -> dict:
    return {
        "message_type": message_type,
        "message_id": f"fc-{message_type}-{seq}",
        "session_id": "sess-fail-closed",
        "round_number": rnd,
        "sequence_number": seq,
        "sender_did": did,
        "sender_agent_id": "agent",
        "timestamp": f"2026-03-24T10:0{seq}:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "terms": TERMS,
    }


def _seller_act(message_type: str, first_offer: dict) -> dict:
    base = {
        "message_type": message_type,
        "message_id": f"fc-{message_type}-2",
        "session_id": "sess-fail-closed",
        "round_number": 1,
        "sequence_number": 2,
        "sender_did": SELLER_DID,
        "sender_agent_id": "agent",
        "timestamp": "2026-03-24T10:02:00Z",
    }
    if message_type == "acceptance":
        base["accepted_offer_id"] = first_offer["message_id"]
        base["accepted_protocol_act_hash"] = first_offer["protocol_act_hash"]
    elif message_type == "rejection":
        base["rejected_offer_id"] = first_offer["message_id"]
        base["reason_code"] = "PRICE_TOO_HIGH"
    else:
        base["reason_code"] = "STRATEGY_DECISION"
    return base


# (act type, error message when signed naming no version, state after the control)
FAIL_CLOSED_CASES = [
    ("offer", "Protocol act hash does not match message fields", "NEGOTIATING"),
    ("counteroffer", "Protocol act hash does not match message fields", "NEGOTIATING"),
    ("acceptance", "acceptance_signature payload does not match message fields", "COMPLETED"),
    ("rejection", "rejection_signature payload does not match message fields", "NEGOTIATING"),
    ("withdrawal", "withdrawal_signature payload does not match message fields", "WITHDRAWN"),
]


def _act_for(message_type: str, manager, session, version) -> dict:
    """The act under test, after whatever the session needs first, signed as asked."""
    if message_type == "offer":
        return _signed(_offer("offer", 1, 1, BUYER_DID), BUYER_KEY, BUYER_VM, version)
    first = _signed(_offer("offer", 1, 1, BUYER_DID), BUYER_KEY, BUYER_VM, PROTOCOL_ACT_VERSION)
    manager.process_message(session, first)
    if message_type == "counteroffer":
        act = _offer("counteroffer", 2, 2, SELLER_DID)
    else:
        act = _seller_act(message_type, first)
    return _signed(act, SELLER_KEY, SELLER_VM, version)


@pytest.mark.parametrize(
    ("message_type", "error_message", "state_after"),
    FAIL_CLOSED_CASES,
    ids=[case[0] for case in FAIL_CLOSED_CASES],
)
def test_an_act_signed_without_naming_a_version_is_refused_by_a_current_session(
    message_type, error_message, state_after
):
    """The default is the pinned legacy version, so it must fail closed, not open.

    A caller that signs a new act and names no version signs it under "0.2". A
    session negotiated at the current version refuses it and never logs it; it is
    never admitted under a version it was not signed under.
    """
    manager, session = _fail_closed_session()
    unnamed = _act_for(message_type, manager, session, UNNAMED)
    state_before = session.state
    log_before = list(session._message_log)

    with pytest.raises(A2CNError) as excinfo:
        manager.process_message(session, unnamed)

    assert (excinfo.value.code, excinfo.value.message) == ("INVALID_SIGNATURE", error_message)
    assert session.state == state_before
    assert session._message_log == log_before


@pytest.mark.parametrize(
    ("message_type", "error_message", "state_after"),
    FAIL_CLOSED_CASES,
    ids=[case[0] for case in FAIL_CLOSED_CASES],
)
def test_the_same_act_signed_at_the_negotiated_version_is_accepted(
    message_type, error_message, state_after
):
    manager, session = _fail_closed_session()
    named = _act_for(message_type, manager, session, PROTOCOL_ACT_VERSION)

    manager.process_message(session, named)

    assert session.state == state_after
    assert named in session._message_log


# ---------------------------------------------------------------------------
# Observed acts state the negotiated version too
# ---------------------------------------------------------------------------


def test_a_signed_observed_act_is_recorded_with_the_negotiated_version_and_verifies():
    expected = OBSERVED["expected"]
    assert all("protocol_version" not in act for act in OBSERVED["observed_acts"])

    record = _record_for(OBSERVED["session"], OBSERVED["observed_acts"])

    assert [e["act"]["protocol_version"] for e in record["acts"]] == expected["stated_versions"]
    assert [e["attribution"] for e in record["acts"]] == expected["attributions"]
    assert "verified_signature" == record["acts"][1]["attribution"]
    assert [e["act_hash"] for e in record["acts"]] == expected["act_hashes"]
    assert record["record_hash"] == expected["record_hash"]
    assert record == expected["record"]
    assert verify_session_evidence_record(record, DID_DOCUMENTS)


def test_an_observed_act_that_states_a_version_keeps_it_and_a_wrong_one_fails():
    """The generator never overwrites a stated version, so a wrong one fails closed."""
    case = OBSERVED["stating_another_version"]
    observed = copy.deepcopy(OBSERVED["observed_acts"])
    observed[0]["protocol_version"] = case["observed_protocol_version"]

    record = _record_for(OBSERVED["session"], observed)

    assert record["acts"][1]["act"]["protocol_version"] == case["observed_protocol_version"]
    assert record["record_hash"] == case["record_hash"]
    assert verify_session_evidence_record(record, DID_DOCUMENTS) is case["verifies"]


def test_a_wrapped_observed_act_is_stated_inside_its_act():
    """An observed item may wrap its act beside metadata; the version goes on the act."""
    wrapped = [{"act": copy.deepcopy(OBSERVED["observed_acts"][0])}]

    record = _record_for(OBSERVED["session"], wrapped)

    assert record["acts"][1]["act"]["protocol_version"] == PROTOCOL_ACT_VERSION
    assert "protocol_version" not in {k for k in record["acts"][1] if k != "act"}
    assert record["record_hash"] == OBSERVED["expected"]["record_hash"]


def test_an_unsigned_observed_act_is_stated_and_stays_an_unsigned_observation():
    act = copy.deepcopy(OBSERVED["observed_acts"][0])
    for name in ("protocol_act_signature", "sender_verification_method"):
        del act[name]

    record = _record_for(OBSERVED["session"], [act])

    entry = record["acts"][1]
    assert entry["act"]["protocol_version"] == PROTOCOL_ACT_VERSION
    assert entry["attribution"] == "unsigned_observation"
    assert entry["signature"] is None
    assert verify_session_evidence_record(record, DID_DOCUMENTS)
