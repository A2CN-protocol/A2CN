"""Verify one signed act on its own (Sections 7.3 to 7.6).

A record verifier checks the acts inside a record; this checks a single act an
auditor holds by itself: an offer, counteroffer, acceptance, rejection or
withdrawal. It rebuilds the object the act's signature covers with the same
primitive the records use (``rebuild_signed_act``, Section 7.3.1), requires the
signing method to be under the sender's DID, and verifies the signature against
the key that DID document lists for it. For an offer or counteroffer the act's
stated ``protocol_act_hash`` must also equal the rebuilt hash (Section 7.3.2).

A verified act proves who signed which terms. It says nothing about the session
around it: whether the act was in turn, in time, or ever accepted.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from jwt.exceptions import InvalidSignatureError

from a2cn.crypto import hash_object, verify_jws
from a2cn.did import get_public_key, get_verification_method
from a2cn.messages import SIGNED_ACT_SIGNATURE_FIELDS, SUPPORTED_WIRE_VERSIONS, rebuild_signed_act

DidResolver = Mapping[str, dict] | Callable[[str], dict]

#: The act types this verifies: every act that carries its own signature.
SIGNED_ACT_TYPES = tuple(SIGNED_ACT_SIGNATURE_FIELDS)

# Why an act does not verify. verify_signed_act_reason returns one of these, or
# None when the act verifies.
ACT_REASON_UNSUPPORTED_TYPE = "UNSUPPORTED_ACT_TYPE"
ACT_REASON_VERSION_UNSTATED = "WIRE_VERSION_UNSTATED"
ACT_REASON_NOT_RECOMPUTABLE = "ACT_NOT_RECOMPUTABLE"
ACT_REASON_HASH_MISMATCH = "PROTOCOL_ACT_HASH_MISMATCH"
ACT_REASON_SIGNATURE_MISSING = "SIGNATURE_MISSING"
ACT_REASON_METHOD_NOT_CONTROLLED = "VERIFICATION_METHOD_NOT_CONTROLLED"
ACT_REASON_DID_UNRESOLVED = "DID_DOCUMENT_UNRESOLVED"
ACT_REASON_KEY_UNUSABLE = "VERIFICATION_METHOD_UNUSABLE"
ACT_REASON_SIGNATURE_INVALID = "SIGNATURE_INVALID"


def verify_signed_act_reason(
    act: Any,
    did_resolver: DidResolver,
    *,
    wire_version: str | None = None,
) -> str | None:
    """Why ``act`` does not verify, or None when its signature does.

    ``wire_version`` stands in for a ``protocol_version`` the act does not state.
    An act received inside a session states none and is rebuilt under the
    session's negotiated version (Section 7.3.1); held on its own, nothing says
    which version that was, so the caller must say. An act that states its
    version is always rebuilt under it, and ``wire_version`` is then ignored.
    """
    if not isinstance(act, Mapping) or act.get("message_type") not in SIGNED_ACT_SIGNATURE_FIELDS:
        return ACT_REASON_UNSUPPORTED_TYPE
    if "protocol_version" not in act and wire_version not in SUPPORTED_WIRE_VERSIONS:
        return ACT_REASON_VERSION_UNSTATED

    rebuilt = rebuild_signed_act(act, version_when_absent=wire_version or "")
    if rebuilt is None:
        return ACT_REASON_NOT_RECOMPUTABLE
    expected_hash = hash_object(rebuilt)
    if act["message_type"] in ("offer", "counteroffer") and act.get("protocol_act_hash") != expected_hash:
        return ACT_REASON_HASH_MISMATCH

    signature = act.get(SIGNED_ACT_SIGNATURE_FIELDS[act["message_type"]])
    verification_method = act.get("sender_verification_method")
    sender_did = act.get("sender_did")
    if not (isinstance(signature, str) and signature) or not (
        isinstance(verification_method, str) and verification_method
    ):
        return ACT_REASON_SIGNATURE_MISSING
    if not (
        isinstance(sender_did, str)
        and sender_did
        and (verification_method == sender_did or verification_method.startswith(f"{sender_did}#"))
    ):
        return ACT_REASON_METHOD_NOT_CONTROLLED

    try:
        did_document = (
            did_resolver(sender_did) if callable(did_resolver) else did_resolver[sender_did]
        )
    except Exception:
        return ACT_REASON_DID_UNRESOLVED
    try:
        public_key = get_public_key(get_verification_method(did_document, verification_method))
    except Exception:
        return ACT_REASON_KEY_UNUSABLE
    try:
        signed_payload = verify_jws(signature, public_key)
    except (InvalidSignatureError, ValueError):
        # A signature that does not verify, or bytes that are not a JWS at all.
        return ACT_REASON_SIGNATURE_INVALID
    if signed_payload != expected_hash:
        return ACT_REASON_SIGNATURE_INVALID
    return None


def verify_signed_act(act: Any, did_resolver: DidResolver, *, wire_version: str | None = None) -> bool:
    """Whether ``act``'s signature verifies; ``verify_signed_act_reason`` says why not."""
    return verify_signed_act_reason(act, did_resolver, wire_version=wire_version) is None
