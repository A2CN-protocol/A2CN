"""Rejection and withdrawal can be signed in band, and are verified like any act.

Before the envelope these two act types had no signature slot at all: a party
that signed its own withdrawal had nowhere conformant to put the signature, so
an evidence record either called the act unsigned — stating that nobody signed
an act the party did in fact sign — or carried a signature the verifier had no
rule for. The envelope gives each its own slot and its own signed object, so a
decline is provable by the same rebuild every other act uses.

Signing a decline is OPTIONAL on the wire: an unsigned decline is still a
conformant message, and is still recorded as an unsigned observation. What is
not optional is the check. Once an act carries a signature, the rebuild decides,
and nothing about the act's own content can turn the check off.
"""

from __future__ import annotations

import copy
import uuid

from a2cn.crypto import generate_keypair, public_key_to_jwk, sign_jws
from a2cn.evidence import (
    assess_session_evidence_record,
    verify_session_evidence_record,
)
from a2cn.messages import (
    PROTOCOL_ACT_VERSION,
    SIGNED_ACT_SIGNATURE_FIELDS,
    rebuild_signed_act,
    signed_act_hash,
)
from tests.conftest import INITIATOR_DID, RESPONDER_DID, make_did_document
from tests.test_evidence import (
    INITIATOR_PRIVATE_KEY,
    INITIATOR_PUBLIC_KEY,
    INITIATOR_VM,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_PUBLIC_KEY,
    RESPONDER_VM,
    _generate,
    _make_session,
    _mark_timed_out,
)

OTHER_PRIVATE_KEY, OTHER_PUBLIC_KEY = generate_keypair()


def _sign(act: dict, private_key, verification_method: str) -> dict:
    """Sign an act over its own rebuilt envelope, as a conformant sender would."""
    signed = copy.deepcopy(act)
    signed["sender_verification_method"] = verification_method
    signed[SIGNED_ACT_SIGNATURE_FIELDS[act["message_type"]]] = sign_jws(
        signed_act_hash(signed, version_when_absent=PROTOCOL_ACT_VERSION),
        private_key,
        kid=verification_method,
    )
    return signed


def _rejection(session_id: str) -> dict:
    return {
        "message_type": "rejection",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "in_reply_to": "offer-1",
        "round_number": 1,
        "sequence_number": 2,
        "rejected_offer_id": "offer-1",
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "seller-agent",
        "timestamp": "2026-03-24T10:05:00Z",
        "reason_code": "PRICE_TOO_HIGH",
        "reason_description": "above mandate",
    }


def _withdrawal(session_id: str) -> dict:
    return {
        "message_type": "withdrawal",
        "message_id": str(uuid.uuid4()),
        "session_id": session_id,
        "in_reply_to": "offer-1",
        "round_number": 1,
        "sequence_number": 2,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "buyer-agent",
        "timestamp": "2026-03-24T10:05:00Z",
        "reason_code": "STRATEGY_DECISION",
        "reason_description": "walking away",
    }


# ---------------------------------------------------------------------------
# A signed decline verifies, and is attributed to its signer
# ---------------------------------------------------------------------------


def test_a_signed_rejection_is_a_verified_act():
    manager, session, did_documents = _make_session()
    signed = _sign(_rejection(session.session_id), RESPONDER_PRIVATE_KEY, RESPONDER_VM)
    session._message_log = [signed]
    _mark_timed_out(session)

    evidence = _generate(session)

    assert evidence["acts"][0]["attribution"] == "verified_signature"
    assert evidence["acts"][0]["signature_type"] == "rejection_signature"
    assert verify_session_evidence_record(evidence, did_documents)


def test_a_signed_withdrawal_is_a_verified_act():
    manager, session, did_documents = _make_session()
    signed = _sign(_withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM)
    session._message_log = [signed]
    _mark_timed_out(session)

    evidence = _generate(session)

    assert evidence["acts"][0]["attribution"] == "verified_signature"
    assert evidence["acts"][0]["signature_type"] == "withdrawal_signature"
    assert verify_session_evidence_record(evidence, did_documents)


def test_a_signed_withdrawal_no_longer_forces_an_invalid_record():
    """The recorded gap: a party's own signed act, unprovable.

    Before the slot existed, a signed withdrawal could only be carried as an
    unsigned observation or as an act the verifier counted invalid. Neither
    stated the truth, and the most common ending to a session was the one that
    could not verify.
    """
    manager, session, did_documents = _make_session()
    signed = _sign(_withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM)
    session._message_log = [signed]
    _mark_timed_out(session)

    assessment = assess_session_evidence_record(_generate(session), did_documents)

    assert assessment["valid"] is True
    assert assessment["invalid_acts"] == 0
    assert assessment["verified_acts"] == 1


# ---------------------------------------------------------------------------
# An unsigned decline stays conformant, and stays honestly unsigned
# ---------------------------------------------------------------------------


def test_an_unsigned_decline_is_still_an_unsigned_observation():
    manager, session, did_documents = _make_session()
    session._message_log = [_withdrawal(session.session_id)]
    _mark_timed_out(session)

    evidence = _generate(session)

    assert evidence["acts"][0]["attribution"] == "unsigned_observation"
    assert evidence["acts"][0]["signature"] is None
    assert verify_session_evidence_record(evidence, did_documents)


# ---------------------------------------------------------------------------
# What the rebuild refuses
# ---------------------------------------------------------------------------


def test_a_decline_signed_by_the_wrong_key_is_refused():
    manager, session, did_documents = _make_session()
    forged = _sign(_withdrawal(session.session_id), OTHER_PRIVATE_KEY, INITIATOR_VM)
    session._message_log = [forged]
    _mark_timed_out(session)

    evidence = _generate(session)

    assert not verify_session_evidence_record(evidence, did_documents)


def test_a_decline_whose_reason_code_was_altered_after_signing_is_refused():
    """reason_code is inside the signed scope, so restating why is not possible."""
    manager, session, did_documents = _make_session()
    signed = _sign(_withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM)
    signed["reason_code"] = "COMPLIANCE_FAILURE"
    session._message_log = [signed]
    _mark_timed_out(session)

    evidence = _generate(session)

    assert not verify_session_evidence_record(evidence, did_documents)


def test_a_decline_whose_reason_description_changed_still_verifies():
    """It is outside the signed scope, deliberately, and nothing pretends otherwise."""
    manager, session, did_documents = _make_session()
    signed = _sign(_withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM)
    before = signed_act_hash(signed)
    signed["reason_description"] = "something else entirely"

    assert signed_act_hash(signed) == before


def test_a_rejection_relabelled_as_a_withdrawal_is_refused():
    """The signature field names the act type it was made under."""
    manager, session, did_documents = _make_session()
    signed = _sign(_rejection(session.session_id), RESPONDER_PRIVATE_KEY, RESPONDER_VM)
    relabelled = copy.deepcopy(signed)
    relabelled["message_type"] = "withdrawal"

    # The rebuild now demands a withdrawal's scope, and the signature it carries
    # is still in the rejection's slot.
    assert signed_act_hash(relabelled) != signed_act_hash(signed)
    assert "rejection_signature" in relabelled
    assert "withdrawal_signature" not in relabelled


def test_moving_a_decline_signature_into_the_other_slot_is_refused():
    manager, session, did_documents = _make_session()
    signed = _sign(_withdrawal(session.session_id), INITIATOR_PRIVATE_KEY, INITIATOR_VM)
    moved = copy.deepcopy(signed)
    moved["rejection_signature"] = moved.pop("withdrawal_signature")
    moved["message_type"] = "rejection"
    moved["rejected_offer_id"] = "offer-1"
    session._message_log = [moved]
    _mark_timed_out(session)

    evidence = _generate(session)

    assert not verify_session_evidence_record(evidence, did_documents)


def test_a_withdrawal_without_round_number_cannot_be_rebuilt():
    """round_number is REQUIRED on a withdrawal so the common header applies.

    Section 7.6's message did not carry one, so the header could not be rebuilt
    from a withdrawal's own fields; it is now required, and an act that omits it
    is refused rather than rebuilt over a guessed round.
    """
    without_round = _withdrawal("session-1")
    del without_round["round_number"]

    assert rebuild_signed_act(without_round) is None
