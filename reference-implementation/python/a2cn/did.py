"""
A2CN DID Resolution — did:web only.

Section 4.2: All signing keys MUST be retrieved from DID documents.

did:web:example.com           → https://example.com/.well-known/did.json
did:web:example.com:path:to   → https://example.com/path/to/did.json
"""

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from a2cn.crypto import public_key_from_jwk


async def resolve_did_web(did: str, client: httpx.AsyncClient | None = None) -> dict:
    """
    Resolve a did:web DID to its DID document.

    Raises:
        ValueError: if the DID is not a did:web DID or cannot be parsed
        httpx.HTTPError: if the DID document cannot be fetched
    """
    url = _did_web_to_url(did)
    if client is not None:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()
    async with httpx.AsyncClient() as c:
        response = await c.get(url)
        response.raise_for_status()
        return response.json()


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


def get_verification_method(did_document: dict, method_id: str) -> dict:
    """
    Extract a specific verification method from a DID document by its DID URL.

    Searches verificationMethod, authentication, assertionMethod arrays.

    Raises:
        KeyError: if the method is not found
    """
    search_keys = [
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ]

    for key in search_keys:
        for method in did_document.get(key, []):
            # Methods can be embedded objects or string references
            if isinstance(method, dict):
                if method.get("id") == method_id:
                    return method
            elif isinstance(method, str) and method == method_id:
                # It's a reference — look up in verificationMethod
                for vm in did_document.get("verificationMethod", []):
                    if isinstance(vm, dict) and vm.get("id") == method_id:
                        return vm

    raise KeyError(f"Verification method {method_id!r} not found in DID document")


def get_public_key(verification_method: dict) -> EllipticCurvePublicKey:
    """
    Return a cryptography public key object from a JsonWebKey2020 verification method.

    Raises:
        ValueError: if the verification method type is not supported or the key cannot be parsed
    """
    vm_type = verification_method.get("type")
    if vm_type not in ("JsonWebKey2020", "EcdsaSecp256r1VerificationKey2019"):
        raise ValueError(
            f"Unsupported verification method type: {vm_type!r}. "
            "Only JsonWebKey2020 is supported."
        )

    jwk = verification_method.get("publicKeyJwk")
    if not jwk:
        raise ValueError("Verification method missing 'publicKeyJwk' field")

    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError(
            f"Unsupported key type/curve: kty={jwk.get('kty')!r}, crv={jwk.get('crv')!r}. "
            "Only EC P-256 keys are supported."
        )

    return public_key_from_jwk(jwk)
