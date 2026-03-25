"""Tests for a2cn.did — using respx to mock HTTPS fetches."""

import pytest
import respx
import httpx

from a2cn.did import resolve_did_web, _did_web_to_url, get_verification_method, get_public_key
from a2cn.crypto import generate_keypair, public_key_to_jwk
from tests.conftest import make_did_document, INITIATOR_DID, RESPONDER_DID


# ---------------------------------------------------------------------------
# _did_web_to_url
# ---------------------------------------------------------------------------

def test_did_web_simple():
    assert _did_web_to_url("did:web:example.com") == "https://example.com/.well-known/did.json"


def test_did_web_with_path():
    assert _did_web_to_url("did:web:example.com:path:to:key") == "https://example.com/path/to/key/did.json"


def test_did_web_not_did_web_raises():
    with pytest.raises(ValueError, match="Not a did:web DID"):
        _did_web_to_url("did:key:z6Mkfoo")


# ---------------------------------------------------------------------------
# resolve_did_web (mock HTTP)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_resolve_did_web_simple():
    priv, pub = generate_keypair()
    did_doc = make_did_document("did:web:example.com", "key-1", public_key_to_jwk(pub))

    respx.get("https://example.com/.well-known/did.json").mock(
        return_value=httpx.Response(200, json=did_doc)
    )

    async with httpx.AsyncClient() as client:
        result = await resolve_did_web("did:web:example.com", client)

    assert result["id"] == "did:web:example.com"
    assert result["verificationMethod"][0]["type"] == "JsonWebKey2020"


@pytest.mark.asyncio
@respx.mock
async def test_resolve_did_web_with_path():
    priv, pub = generate_keypair()
    did_doc = make_did_document("did:web:example.com:users:alice", "key-1", public_key_to_jwk(pub))

    respx.get("https://example.com/users/alice/did.json").mock(
        return_value=httpx.Response(200, json=did_doc)
    )

    async with httpx.AsyncClient() as client:
        result = await resolve_did_web("did:web:example.com:users:alice", client)

    assert result["id"] == "did:web:example.com:users:alice"


@pytest.mark.asyncio
@respx.mock
async def test_resolve_did_web_404_raises():
    respx.get("https://notfound.example/.well-known/did.json").mock(
        return_value=httpx.Response(404)
    )
    with pytest.raises(httpx.HTTPStatusError):
        async with httpx.AsyncClient() as client:
            await resolve_did_web("did:web:notfound.example", client)


# ---------------------------------------------------------------------------
# get_verification_method
# ---------------------------------------------------------------------------

def test_get_verification_method_found():
    priv, pub = generate_keypair()
    did_doc = make_did_document(INITIATOR_DID, "key-1", public_key_to_jwk(pub))
    vm_id = f"{INITIATOR_DID}#key-1"
    vm = get_verification_method(did_doc, vm_id)
    assert vm["id"] == vm_id


def test_get_verification_method_not_found_raises():
    priv, pub = generate_keypair()
    did_doc = make_did_document(INITIATOR_DID, "key-1", public_key_to_jwk(pub))
    with pytest.raises(KeyError, match="not found"):
        get_verification_method(did_doc, f"{INITIATOR_DID}#nonexistent")


# ---------------------------------------------------------------------------
# get_public_key
# ---------------------------------------------------------------------------

def test_get_public_key_roundtrip():
    priv, pub = generate_keypair()
    jwk = public_key_to_jwk(pub)
    vm = {
        "id": f"{INITIATOR_DID}#key-1",
        "type": "JsonWebKey2020",
        "controller": INITIATOR_DID,
        "publicKeyJwk": jwk,
    }
    recovered = get_public_key(vm)
    assert recovered.public_numbers() == pub.public_numbers()


def test_get_public_key_unsupported_type_raises():
    vm = {
        "id": "did:web:example.com#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:web:example.com",
    }
    with pytest.raises(ValueError, match="Unsupported verification method type"):
        get_public_key(vm)


def test_get_public_key_missing_jwk_raises():
    vm = {
        "id": "did:web:example.com#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:web:example.com",
    }
    with pytest.raises(ValueError, match="missing 'publicKeyJwk'"):
        get_public_key(vm)
