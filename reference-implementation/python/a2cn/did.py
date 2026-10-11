"""
A2CN DID Resolution — did:web only.

Section 4.2: All signing keys MUST be retrieved from DID documents.

did:web:example.com           → https://example.com/.well-known/did.json
did:web:example.com:path:to   → https://example.com/path/to/did.json
"""

import asyncio
import json

import httpx

from a2cn.crypto import SigningPublicKey, public_key_from_jwk

# Resolution limits, identical in both reference implementations: the whole
# fetch, body included, must finish within the timeout; no redirect is
# followed; and a document larger than the cap is refused before it is read in
# full.
DID_RESOLUTION_TIMEOUT_SECONDS = 5.0
DID_DOCUMENT_MAX_BYTES = 65536


async def resolve_did_web(
    did: str, client: httpx.AsyncClient | None = None, timeout: float | None = None
) -> dict:
    """
    Resolve a did:web DID to its DID document.

    The document must be UTF-8 JSON (an optional UTF-8 byte-order mark is
    allowed), without NaN or Infinity literals, no larger than
    ``DID_DOCUMENT_MAX_BYTES``, and fetched within ``timeout`` seconds in total
    (``DID_RESOLUTION_TIMEOUT_SECONDS`` by default) with no redirect followed.

    Raises:
        ValueError: if the DID is not a did:web DID, or the document is too
            large or not valid UTF-8 JSON
        httpx.HTTPError: if the DID document cannot be fetched
        TimeoutError: if the fetch does not finish in time
    """
    url = _did_web_to_url(did)
    deadline = DID_RESOLUTION_TIMEOUT_SECONDS if timeout is None else timeout
    async with asyncio.timeout(deadline):
        if client is not None:
            return await _fetch_did_document(client, url)
        async with httpx.AsyncClient() as c:
            return await _fetch_did_document(c, url)


async def _fetch_did_document(client: httpx.AsyncClient, url: str):
    async with client.stream("GET", url, follow_redirects=False) as response:
        response.raise_for_status()
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > DID_DOCUMENT_MAX_BYTES:
                raise ValueError("DID document is larger than the resolution limit")
    return parse_did_document(bytes(body))


def parse_did_document(body: bytes):
    """Parse a fetched DID document: strict UTF-8 JSON, no NaN or Infinity."""

    def refuse(literal: str):
        raise ValueError(f"DID document contains the non-JSON literal {literal}")

    return json.loads(body.decode("utf-8-sig"), parse_constant=refuse)


def _did_web_to_url(did: str) -> str:
    """Convert a did:web DID to the corresponding HTTPS URL."""
    if not did.startswith("did:web:"):
        raise ValueError(f"Not a did:web DID: {did!r}")

    # Strip prefix
    remainder = did[len("did:web:"):]

    # If there are colons after the domain, they become path segments
    parts = remainder.split(":")
    domain = parts[0]
    path_parts = parts[1:]

    if path_parts:
        path = "/".join(path_parts)
        return f"https://{domain}/{path}/did.json"
    else:
        return f"https://{domain}/.well-known/did.json"


def get_verification_method(
    did_document: dict,
    method_id: str,
    *,
    allowed_relationships: tuple[str, ...] = ("assertionMethod", "authentication"),
) -> dict:
    """
    Extract a signing verification method from a DID document by its DID URL.

    The method MUST be authorized for one of the allowed verification
    relationships. By default this permits assertion signatures and JWT
    authentication signatures, while excluding keyAgreement-only keys.

    Raises:
        KeyError: if the method is not found
    """
    verification_methods = {
        method.get("id"): method
        for method in did_document.get("verificationMethod", [])
        if isinstance(method, dict) and method.get("id")
    }

    for key in allowed_relationships:
        for method in did_document.get(key, []):
            # Methods can be embedded objects or string references.
            if isinstance(method, dict) and method.get("id") == method_id:
                return method
            if isinstance(method, str) and method == method_id:
                if method_id in verification_methods:
                    return verification_methods[method_id]
                break

    raise KeyError(f"Verification method {method_id!r} not found in DID document")


def get_public_key(verification_method: dict) -> SigningPublicKey:
    """
    Return a cryptography public key object from a supported verification method.

    Raises:
        ValueError: if the verification method type is not supported or the key cannot be parsed
    """
    vm_type = verification_method.get("type")
    if vm_type not in (
        "JsonWebKey2020",
        "EcdsaSecp256r1VerificationKey2019",
    ):
        raise ValueError(
            f"Unsupported verification method type: {vm_type!r}. "
            "Only JsonWebKey2020 and EcdsaSecp256r1VerificationKey2019 are supported."
        )

    jwk = verification_method.get("publicKeyJwk")
    if not jwk:
        raise ValueError("Verification method missing 'publicKeyJwk' field")

    supported_jwk = (
        (jwk.get("kty") == "EC" and jwk.get("crv") == "P-256")
        or (jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519")
    )
    if not supported_jwk:
        raise ValueError(
            f"Unsupported key type/curve: kty={jwk.get('kty')!r}, crv={jwk.get('crv')!r}. "
            "Only EC P-256 and OKP Ed25519 keys are supported."
        )

    return public_key_from_jwk(jwk)
