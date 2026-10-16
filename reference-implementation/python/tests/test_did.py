"""Tests for a2cn.did — using respx to mock HTTPS fetches."""

import json
from pathlib import Path

import pytest
import respx
import httpx

from a2cn.did import resolve_did_web, _did_web_to_url, get_verification_method, get_public_key
from a2cn.crypto import generate_keypair, generate_ed25519_keypair, public_key_to_jwk
from tests.conftest import INITIATOR_DID, RESPONDER_DID, make_did_document


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
# resolve_did_web limits: content encoding, size, decoding, deadline
# ---------------------------------------------------------------------------

LIMITS_DID = "did:web:limits.example"
LIMITS_URL = "https://limits.example/.well-known/did.json"


def _document_of_size(size: int) -> bytes:
    """A valid DID document padded to exactly ``size`` bytes."""
    _, pub = generate_ed25519_keypair()
    text = json.dumps(make_did_document(LIMITS_DID, "key-1", public_key_to_jwk(pub)))
    head = text[:-1] + ', "pad": "'
    pad = size - len(head) - len('"}')
    assert pad >= 0
    body = (head + "a" * pad + '"}').encode("utf-8")
    assert len(body) == size
    return body


async def _resolve(response=None, side_effect=None, timeout=None):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(LIMITS_URL)
        if side_effect is not None:
            route.mock(side_effect=side_effect)
        else:
            route.mock(return_value=response)
        async with httpx.AsyncClient() as client:
            return await resolve_did_web(LIMITS_DID, client, timeout=timeout)


async def test_resolve_did_web_asks_for_an_unencoded_document():
    seen = []

    def answer(request):
        seen.append(request.headers.get("accept-encoding"))
        return httpx.Response(200, content=_document_of_size(2000))

    await _resolve(side_effect=answer)
    assert seen == ["identity"]


def _compressed(encoding: str, body: bytes) -> bytes:
    import gzip
    import zlib
    if encoding == "gzip":
        return gzip.compress(body)
    if encoding == "deflate":
        return zlib.compress(body)
    if encoding == "gzip, gzip":
        return gzip.compress(gzip.compress(body))
    return body  # an encoding the client does not decode; only the header matters


@pytest.mark.parametrize("encoding", ["gzip", "x-gzip", "deflate", "br", "zstd", "gzip, gzip"])
async def test_resolve_did_web_refuses_a_compressed_document(encoding):
    body = _compressed(encoding, _document_of_size(2000))
    response = httpx.Response(200, content=body, headers={"Content-Encoding": encoding})
    with pytest.raises(ValueError, match="content encoding"):
        await _resolve(response)


async def test_resolve_did_web_accepts_an_explicit_identity_encoding():
    response = httpx.Response(200, content=_document_of_size(2000), headers={"Content-Encoding": "identity"})
    assert (await _resolve(response))["id"] == LIMITS_DID


async def test_resolve_did_web_size_limit_is_inclusive():
    assert (await _resolve(httpx.Response(200, content=_document_of_size(65536))))["id"] == LIMITS_DID
    with pytest.raises(ValueError, match="larger than the resolution limit"):
        await _resolve(httpx.Response(200, content=_document_of_size(65537)))


async def test_resolve_did_web_size_limit_counts_every_chunk():
    body = _document_of_size(70000)

    async def chunks():
        for i in range(0, len(body), 1000):
            yield body[i:i + 1000]

    with pytest.raises(ValueError, match="larger than the resolution limit"):
        await _resolve(httpx.Response(200, content=chunks()))


async def test_resolve_did_web_stops_reading_at_the_size_limit():
    # 1 MiB of whitespace, offered 4 KiB at a time; reading should stop near 64 KiB.
    sent = 0

    async def whitespace():
        nonlocal sent
        for _ in range(256):
            sent += 4096
            yield b" " * 4096

    with pytest.raises(ValueError, match="larger than the resolution limit"):
        await _resolve(httpx.Response(200, content=whitespace()))
    assert sent <= 65536 + 4096


async def test_resolve_did_web_deadline_covers_the_body():
    import asyncio
    body = _document_of_size(2000)

    async def stalls():
        yield body[:1000]
        await asyncio.sleep(1.0)
        yield body[1000:]

    with pytest.raises(TimeoutError):
        await _resolve(httpx.Response(200, content=stalls()), timeout=0.2)


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
async def test_resolve_did_web_refuses_non_json_number_literals(literal):
    body = _document_of_size(2000)[:-1] + b', "x": ' + literal.encode() + b"}"
    with pytest.raises(ValueError, match="non-JSON literal"):
        await _resolve(httpx.Response(200, content=body))


async def test_resolve_did_web_refuses_invalid_utf8():
    body = _document_of_size(2000)[:-2] + b'\xff"}'
    with pytest.raises(UnicodeDecodeError):
        await _resolve(httpx.Response(200, content=body))


# ---------------------------------------------------------------------------
# get_verification_method
# ---------------------------------------------------------------------------

def test_get_verification_method_found():
    priv, pub = generate_keypair()
    did_doc = make_did_document(INITIATOR_DID, "key-1", public_key_to_jwk(pub))
    vm_id = f"{INITIATOR_DID}#key-1"
    vm = get_verification_method(did_doc, vm_id)
    assert vm["id"] == vm_id


def test_public_did_authorizes_transport_key_for_assertion():
    repository_root = Path(__file__).resolve().parents[3]
    did_document = json.loads(
        (repository_root / ".well-known" / "did.json").read_text()
    )
    transport_method = "did:web:a2cn.io#a2cn-buyer-agent-transport-av1"

    assert transport_method in did_document["assertionMethod"]
    assert get_verification_method(
        did_document,
        transport_method,
        allowed_relationships=("assertionMethod",),
    )["id"] == transport_method


def test_get_verification_method_rejects_key_agreement_only_key():
    priv, pub = generate_keypair()
    vm_id = f"{INITIATOR_DID}#agreement-key"
    did_doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": INITIATOR_DID,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": INITIATOR_DID,
                "publicKeyJwk": public_key_to_jwk(pub),
            }
        ],
        "keyAgreement": [vm_id],
    }

    with pytest.raises(KeyError, match="not found"):
        get_verification_method(did_doc, vm_id)


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
        "type": "RsaVerificationKey2018",
        "controller": "did:web:example.com",
    }
    with pytest.raises(ValueError, match="Unsupported verification method type"):
        get_public_key(vm)


def test_get_public_key_ed25519_roundtrip():
    _, pub = generate_ed25519_keypair()
    jwk = public_key_to_jwk(pub)
    vm = {
        "id": f"{INITIATOR_DID}#ed25519-1",
        "type": "JsonWebKey2020",
        "controller": INITIATOR_DID,
        "publicKeyJwk": jwk,
    }
    recovered = get_public_key(vm)
    assert public_key_to_jwk(recovered) == jwk


def test_get_public_key_missing_jwk_raises():
    vm = {
        "id": "did:web:example.com#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:web:example.com",
    }
    with pytest.raises(ValueError, match="missing 'publicKeyJwk'"):
        get_public_key(vm)
