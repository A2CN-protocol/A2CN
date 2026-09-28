"""A decline's signature is required and verified like any other act's.

A rejection or withdrawal a party sends on the wire must be signed, exactly as
its offers and acceptances are (Sections 7.5, 7.6): an unsigned one is refused,
never recorded as an unsigned observation. The unsigned path belongs only to an
act the producer observed from a party that does not sign (Section 9A.3), which
enters a record through the evidence generator, not through the state machine.
The signature check itself came first. The signature slots were added without any
verification call site, so ``_verify_sender_signature`` ran for offers and
acceptances only: a decline carrying a forged signature was accepted with no
check at all, advanced the session, and entered the message log — from where a
receiver's own evidence record counts it an invalid act. A counterparty could
therefore degrade a third party's durable artifact with one junk string,
holding no key material and producing no valid signature.

Every forgery below is a real JWS over the act's own correct hash, signed by a
key the sender does not control. A syntactically broken string would be refused
by a parse failure and would prove nothing about verification; only an actual
signature check refuses these.

Two rules are tested here, one on each side of the line:
  - a party's own decline MUST be signed, and a signature MUST be verified, and
  - an unsigned decline observed from a party that does not sign is still
    recorded, as an unsigned observation.
"""

from __future__ import annotations

import uuid

import pytest

from a2cn.crypto import generate_keypair, public_key_to_jwk, sign_jws
from a2cn.evidence import generate_session_evidence_record, verify_session_evidence_record
from a2cn.messages import PROTOCOL_ACT_VERSION, signed_act_hash
from a2cn.session import A2CNError, SessionManager, SessionState
from tests.conftest import make_did_document
from tests.test_session import (
    INITIATOR_DID,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_PUBLIC_KEY,
    RESPONDER_DID,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_PUBLIC_KEY,
    SESSION_ACK,
    SESSION_INIT,
    _make_offer,
)

# A key no party in the session controls. Signing with it produces a structurally
# valid JWS over the right payload that no registered verification method verifies.
ATTACKER_PRIVATE_KEY, _ATTACKER_PUBLIC_KEY = generate_keypair()

RESPONDER_VM = f"{RESPONDER_DID}#key-2026-01"

DID_DOCUMENTS = {
    INITIATOR_DID: make_did_document(
        INITIATOR_DID, "key-1", public_key_to_jwk(INITIATOR_PUBLIC_KEY)
    ),
    RESPONDER_DID: make_did_document(
        RESPONDER_DID, "key-2026-01", public_key_to_jwk(RESPONDER_PUBLIC_KEY)
    ),
}

SIGNATURE_FIELD = {
    "rejection": "rejection_signature",
    "withdrawal": "withdrawal_signature",
}


def _session_at_negotiating():
    """A real session advanced by a real signed offer, via process_message."""
    manager = SessionManager()
    manager.register_did_document(
        INITIATOR_DID,
        make_did_document(INITIATOR_DID, "key-1", public_key_to_jwk(INITIATOR_PUBLIC_KEY)),
    )
    manager.register_did_document(
        RESPONDER_DID,
        make_did_document(RESPONDER_DID, "key-2026-01", public_key_to_jwk(RESPONDER_PUBLIC_KEY)),
    )
    session = manager.create_session(
        "sess-001", SESSION_INIT, SESSION_ACK, "2026-03-24T10:00:00Z"
    )
    # The fixtures use a historical created_at; a large timeout keeps the session
    # from expiring mid-test.
    session.session_timeout_seconds = 86400 * 365 * 100
    manager.process_message(session, _make_offer("sess-001", 1, 1, INITIATOR_DID))
    return manager, session


def _rejection(session_id: str) -> dict:
    return {
        "message_type": "rejection",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "protocol_version": "0.3",
        "round_number": 1,
        "sequence_number": 2,
        "rejected_offer_id": "offer-1",
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "acme-agent",
        "timestamp": "2026-03-24T10:05:00Z",
        "reason_code": "PRICE_TOO_HIGH",
    }


def _withdrawal(session_id: str, *, with_sequence: bool = True) -> dict:
    act = {
        "message_type": "withdrawal",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "protocol_version": "0.3",
        "round_number": 1,
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "acme-agent",
        "timestamp": "2026-03-24T10:05:00Z",
        "reason_code": "STRATEGY_DECISION",
    }
    if with_sequence:
        act["sequence_number"] = 2
    return act


def _sign_with(act: dict, private_key) -> dict:
    """Sign the act's own rebuilt envelope with the given key."""
    act = dict(act)
    act["sender_verification_method"] = RESPONDER_VM
    payload_hash = signed_act_hash(act)
    assert payload_hash is not None, "fixture must be rebuildable to be signed honestly"
    act[SIGNATURE_FIELD[act["message_type"]]] = sign_jws(
        payload_hash, private_key, kid=RESPONDER_VM
    )
    return act


# ---------------------------------------------------------------------------
# A forged decline signature is refused
# ---------------------------------------------------------------------------


def test_a_forged_rejection_signature_is_refused():
    manager, session = _session_at_negotiating()
    forged = _sign_with(_rejection(session.session_id), ATTACKER_PRIVATE_KEY)

    with pytest.raises(A2CNError) as excinfo:
        manager.process_message(session, forged)

    assert excinfo.value.code == "INVALID_SIGNATURE"
    assert forged not in session._message_log


def test_a_forged_withdrawal_signature_is_refused():
    manager, session = _session_at_negotiating()
    forged = _sign_with(_withdrawal(session.session_id), ATTACKER_PRIVATE_KEY)

    with pytest.raises(A2CNError) as excinfo:
        manager.process_message(session, forged)

    assert excinfo.value.code == "INVALID_SIGNATURE"
    assert session.state != SessionState.WITHDRAWN


def test_a_forged_withdrawal_without_a_sequence_number_is_refused():
    """The loosest dispatch path in the state machine.

    Withdrawal is dispatched ahead of the turn and approval guards, and its
    sequence check runs only when ``sequence_number`` is present. An act that
    omits it therefore reaches the handler by the shortest route available, so
    a verification call placed after any of those guards would miss it.
    """
    manager, session = _session_at_negotiating()
    act = _withdrawal(session.session_id, with_sequence=False)
    act["sender_verification_method"] = RESPONDER_VM
    # This act cannot be rebuilt — it is missing a field its signature must
    # cover — so it is signed over a stand-in payload, exactly as an attacker
    # stripping the field would have to.
    act["withdrawal_signature"] = sign_jws("0" * 43, ATTACKER_PRIVATE_KEY, kid=RESPONDER_VM)

    with pytest.raises(A2CNError) as excinfo:
        manager.process_message(session, act)

    assert excinfo.value.code == "INVALID_SIGNATURE"
    assert session.state != SessionState.WITHDRAWN


def test_a_stripped_rejection_is_refused_by_validation_before_the_signature_check():
    """Which layer refuses a stripped rejection, recorded rather than assumed.

    ``signed_act_hash`` returns None for an act that does not carry the fields
    its signature covers, and treating that as an absent signature would hand an
    attacker the whole check for the price of deleting one field. For a
    *rejection* that case never reaches the signature check at all: round_number
    and timestamp are required on the wire, so message validation refuses the
    act first. That is defence in depth, not the signature check doing its job.

    This test was written expecting INVALID_SIGNATURE and measured
    INVALID_REQUEST, so it is pinned to the layer that actually refuses. It
    passes both before and after the verification fix — it guards the boundary
    rather than proving the fix, and a later change that moves validation after
    verification would surface here. The reachable unrebuildable case is the
    withdrawal above, whose sequence_number is genuinely optional.
    """
    manager, session = _session_at_negotiating()
    act = _rejection(session.session_id)
    del act["round_number"]
    del act["timestamp"]
    assert signed_act_hash(act) is None, "fixture must be unrebuildable for this test to mean anything"
    act["sender_verification_method"] = RESPONDER_VM
    act["rejection_signature"] = sign_jws("0" * 43, ATTACKER_PRIVATE_KEY, kid=RESPONDER_VM)

    with pytest.raises(A2CNError) as excinfo:
        manager.process_message(session, act)

    assert excinfo.value.code == "INVALID_REQUEST"


# ---------------------------------------------------------------------------
# An honestly signed decline still works
# ---------------------------------------------------------------------------


def test_an_honestly_signed_rejection_is_accepted():
    manager, session = _session_at_negotiating()
    signed = _sign_with(_rejection(session.session_id), RESPONDER_PRIVATE_KEY)

    manager.process_message(session, signed)

    assert signed in session._message_log


def test_an_honestly_signed_withdrawal_is_accepted():
    manager, session = _session_at_negotiating()
    signed = _sign_with(_withdrawal(session.session_id), RESPONDER_PRIVATE_KEY)

    manager.process_message(session, signed)

    assert session.state == SessionState.WITHDRAWN


# ---------------------------------------------------------------------------
# A party's own decline must be signed; an observed one need not be
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("message_type", ["rejection", "withdrawal"])
def test_an_unsigned_decline_from_a_party_is_refused(message_type):
    manager, session = _session_at_negotiating()
    build = _rejection if message_type == "rejection" else _withdrawal
    unsigned = build(session.session_id)
    state_before = session.state

    with pytest.raises(A2CNError) as excinfo:
        manager.process_message(session, unsigned)

    assert (excinfo.value.code, excinfo.value.message) == (
        "INVALID_SIGNATURE",
        f"Missing sender_verification_method or {SIGNATURE_FIELD[message_type]}",
    )
    assert session.state == state_before
    assert unsigned not in session._message_log


@pytest.mark.parametrize("message_type", ["rejection", "withdrawal"])
def test_an_unsigned_decline_observed_from_a_non_signing_party_is_still_recorded(message_type):
    """A counterparty that signs nothing, such as a mandate-only one, still has its
    decline recorded, as an unsigned observation, through the evidence generator."""
    manager, session = _session_at_negotiating()
    build = _rejection if message_type == "rejection" else _withdrawal
    observed = build(session.session_id)
    session.state = SessionState.TIMED_OUT
    session.current_turn = "none"
    session.terminal_reason = "session_timeout"
    session.terminal_message_id = None
    session.state_updated_at = "2026-03-24T10:10:00Z"

    record = generate_session_evidence_record(
        session,
        producer_private_key=INITIATOR_PRIVATE_KEY,
        producer_did=INITIATOR_DID,
        producer_agent_id="buyer-agent",
        producer_verification_method=f"{INITIATOR_DID}#key-1",
        observed_acts=[observed],
    )

    entry = next(e for e in record["acts"] if e["act"]["message_type"] == message_type)
    assert entry["attribution"] == "unsigned_observation"
    assert entry["signature"] is None
    assert verify_session_evidence_record(record, DID_DOCUMENTS)


# ---------------------------------------------------------------------------
# Only a party to the session may withdraw from it
# ---------------------------------------------------------------------------

OUTSIDER_DID = "did:web:outsider.example"
OUTSIDER_VM = f"{OUTSIDER_DID}#key-1"
OUTSIDER_PRIVATE_KEY, OUTSIDER_PUBLIC_KEY = generate_keypair()


def test_a_validly_signed_withdrawal_from_a_registered_non_party_is_refused():
    """Its DID resolves and its signature verifies, so only the party check refuses it."""
    manager, session = _session_at_negotiating()
    manager.register_did_document(
        OUTSIDER_DID,
        make_did_document(OUTSIDER_DID, "key-1", public_key_to_jwk(OUTSIDER_PUBLIC_KEY)),
    )
    act = {**_withdrawal(session.session_id), "sender_did": OUTSIDER_DID}
    act["sender_verification_method"] = OUTSIDER_VM
    act["withdrawal_signature"] = sign_jws(
        signed_act_hash(act, version_when_absent=PROTOCOL_ACT_VERSION),
        OUTSIDER_PRIVATE_KEY,
        kid=OUTSIDER_VM,
    )
    state_before = session.state

    with pytest.raises(A2CNError) as excinfo:
        manager.process_message(session, act)

    assert excinfo.value.code == "UNAUTHORIZED_SENDER"
    assert excinfo.value.http_status == 403
    assert OUTSIDER_DID in excinfo.value.message
    assert excinfo.value.message.endswith("is not a party to this session")
    assert session.state == state_before
    assert act not in session._message_log
