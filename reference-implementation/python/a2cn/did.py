"""
A2CN DID Resolution — did:web only.

Section 4.2: All signing keys MUST be retrieved from DID documents.

did:web:example.com           → https://example.com/.well-known/did.json
did:web:example.com:path:to   → https://example.com/path/to/did.json
"""

import asyncio
import ipaddress
import json
import socket
from urllib.parse import unquote

import httpcore
import httpx

from a2cn.crypto import SigningPublicKey, public_key_from_jwk

# Resolution limits, identical in both reference implementations: the whole
# fetch, body included, must finish within the timeout; no redirect is
# followed; and a document larger than the cap is refused before it is read in
# full.
DID_RESOLUTION_TIMEOUT_SECONDS = 5.0
DID_DOCUMENT_MAX_BYTES = 65536


async def resolve_did_web(
    did: str,
    client: httpx.AsyncClient | None = None,
    timeout: float | None = None,
    *,
    allow_private_hosts: bool = False,
) -> dict:
    """
    Resolve a did:web DID to its DID document.

    The document must be UTF-8 JSON (an optional UTF-8 byte-order mark is
    allowed), without NaN or Infinity literals, sent without a content
    encoding, no larger than ``DID_DOCUMENT_MAX_BYTES``, and fetched within
    ``timeout`` seconds in total (``DID_RESOLUTION_TIMEOUT_SECONDS`` by
    default) with no redirect followed.

    The host must be a name, not an IP address, and every address it resolves
    to must be public unicast (``is_public_unicast``); the resolver connects
    only to the addresses it checked, trying them in order until one connects,
    with no second lookup, and TLS still verifies the host name. It does not use
    a proxy from the environment, because a proxy makes its own lookup. ``allow_private_hosts`` turns both checks off, for local
    development and tests only. A ``client`` you supply makes its own
    connections: the host-name check still applies, the address check does not.

    The document's ``id`` must be exactly ``did`` (``did_document_is_for``):
    a document that names another DID is refused, however close the spelling,
    because it is that other DID's document, not this one's. No DID is
    normalized for the comparison.

    Raises:
        DidWebHostRefused (a ValueError): if the address policy refuses the host
        DidDocumentIdMismatch (a ValueError): if the document's id is not ``did``
        ValueError: if the DID is not a did:web DID, or the document is too
            large, compressed, or not valid UTF-8 JSON
        httpx.HTTPError: if the DID document cannot be fetched
        OSError: if the host name cannot be looked up
        TimeoutError: if the fetch does not finish in time
    """
    url = _did_web_to_url(did)
    if not allow_private_hosts and _is_ip_literal(_did_web_host(did)):
        raise DidWebHostRefused("did:web host is written as an IP address; it must be a name")
    deadline = DID_RESOLUTION_TIMEOUT_SECONDS if timeout is None else timeout
    async with asyncio.timeout(deadline):
        if client is not None:
            document = await _fetch_did_document(client, url)
        elif allow_private_hosts:
            async with httpx.AsyncClient() as c:
                document = await _fetch_did_document(c, url)
        else:
            async with public_address_client() as c:
                document = await _fetch_did_document(c, url)
    return require_did_document_for(document, did)


class DidDocumentIdMismatch(ValueError):
    """A DID document whose ``id`` is not exactly the DID it was obtained for.

    DID Core requires a resolved document's ``id`` to be the DID that was
    resolved. Two spellings of one did:web DID can reach one document (a
    host's case, a trailing dot, an escaped character, a ``:.well-known``
    path, a Unicode host and its punycode), and only one of them is the
    document's ``id``. A verifier that used the document for the other would
    let one party sign as two. The key it lists is unavailable for that DID,
    exactly as when no document can be obtained.
    """


def did_document_is_for(did_document, did) -> bool:
    """Whether ``did_document`` is the DID document of ``did``: its ``id`` is exactly ``did``.

    The comparison is exact string equality, with no normalization, so a
    document is the document of one spelling only. A document that is not a
    JSON object, or has no string ``id``, is no DID's document.
    """
    return (
        isinstance(did_document, dict)
        and isinstance(did, str)
        and isinstance(did_document.get("id"), str)
        and did_document["id"] == did
    )


def require_did_document_for(did_document, did):
    """Return ``did_document`` if it is the document of ``did``; raise DidDocumentIdMismatch if not."""
    if not did_document_is_for(did_document, did):
        named = did_document.get("id") if isinstance(did_document, dict) else None
        raise DidDocumentIdMismatch(
            f"the DID document obtained for {did!r} is the document of {named!r}, not of that DID"
        )
    return did_document


class DidWebHostRefused(ValueError):
    """The address policy refuses this host: an IP address, or a name with an
    address that is not public unicast. The policy covers every request to a
    host a caller names: did:web resolution, and the reference server's
    invitation delivery."""


# Addresses a did:web document is never fetched from. IPv6 outside 2000::/3 is
# refused as well, and an IPv4-mapped or NAT64 address is judged by the IPv4
# address it carries. The TypeScript implementation holds the same table, and
# spec/test-vectors/did-web-address-policy.json tests both.
_REFUSED_IPV4 = tuple(
    ipaddress.IPv4Network(network)
    for network in (
        "0.0.0.0/8",  # this network, unspecified
        "10.0.0.0/8",  # private
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local
        "172.16.0.0/12",  # private
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "192.88.99.0/24",  # 6to4 relay anycast
        "192.168.0.0/16",  # private
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation
        "203.0.113.0/24",  # documentation
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, broadcast
    )
)
_GLOBAL_UNICAST_IPV6 = ipaddress.IPv6Network("2000::/3")
_REFUSED_IPV6 = tuple(
    ipaddress.IPv6Network(network)
    for network in (
        "2001::/23",  # IETF protocol assignments (Teredo, benchmarking, ORCHID)
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4
        "3fff::/20",  # documentation
    )
)
_IPV4_CARRYING_IPV6 = (
    ipaddress.IPv6Network("::ffff:0:0/96"),  # IPv4-mapped
    ipaddress.IPv6Network("64:ff9b::/96"),  # NAT64
)


def is_public_unicast(address: str) -> bool:
    """Whether a did:web document may be fetched from this IP address."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if any(ip in network for network in _IPV4_CARRYING_IPV6):
            return is_public_unicast(str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)))
        return ip in _GLOBAL_UNICAST_IPV6 and not any(ip in network for network in _REFUSED_IPV6)
    return not any(ip in network for network in _REFUSED_IPV4)


def _did_web_host(did: str) -> str:
    """The host a did:web DID names: percent-decoded, without its port."""
    host = unquote(did[len("did:web:"):].split(":")[0])
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")]
    if host.count(":") == 1:
        return host.split(":")[0]
    return host


def _is_ip_literal(host: str) -> bool:
    """A host written as an IP address, including the shortened and numeric
    IPv4 forms a system resolver reads as addresses (``127.1``, ``2130706433``)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


async def _lookup(host: str, port: int) -> list[str]:
    """Every address the system resolver gives for a host."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


async def _public_addresses(host: str, port: int) -> list[str]:
    """One lookup; every address, in order, if every one is public unicast."""
    addresses = await _lookup(host, port)
    if not addresses:
        raise DidWebHostRefused(f"host {host} has no address")
    for address in addresses:
        if not is_public_unicast(address):
            raise DidWebHostRefused(f"host {host} resolves to a non-public address, {address}")
    return addresses


def _network_backend() -> httpcore.AsyncNetworkBackend:
    return httpcore.AnyIOBackend()


class _PublicAddressBackend(httpcore.AsyncNetworkBackend):
    """Connects only to addresses the policy checked, so the connection cannot
    reach an address a second lookup would give. The checked addresses are
    tried in order until one connects, as a direct connection would, so a host
    whose first address is unreachable still resolves; the resolver's deadline
    bounds the whole attempt. httpcore starts TLS with the request's host name,
    so the certificate is still checked against it."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend):
        self._inner = inner

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        failure: Exception | None = None
        for address in await _public_addresses(host, port):
            try:
                return await self._inner.connect_tcp(
                    address, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                failure = exc
        assert failure is not None  # _public_addresses never returns an empty list
        raise failure

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise DidWebHostRefused("the address policy does not connect over a Unix socket")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _PublicAddressTransport(httpx.AsyncHTTPTransport):
    def __init__(self):
        super().__init__()
        # httpx 0.27 takes no network backend, so the pool it built is replaced
        # with one that connects through the address policy.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(), network_backend=_PublicAddressBackend(_network_backend())
        )


def public_address_client(**options) -> httpx.AsyncClient:
    """An HTTP client that connects only through the address policy: each
    connection looks the host up once, refuses it (DidWebHostRefused) unless
    every address is public unicast, and connects only to the checked
    addresses. It uses no proxy from the environment, because a proxy makes its
    own lookup. ``options`` go to httpx.AsyncClient (a timeout, say)."""
    return httpx.AsyncClient(transport=_PublicAddressTransport(), trust_env=False, **options)


def check_url_host(url: str, *, allow_private_hosts: bool = False) -> str:
    """The host an http or https URL names, checked before any lookup.

    Raises:
        DidWebHostRefused (a ValueError): if the host is written as an IP
            address (any form ``_is_ip_literal`` reads as one), unless
            ``allow_private_hosts``
        ValueError: if the URL is not an http or https URL with a host
    """
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError) as exc:
        raise ValueError("not an http or https URL") from exc
    if parsed.scheme not in ("http", "https") or not parsed.host:
        raise ValueError("not an http or https URL")
    if not allow_private_hosts and _is_ip_literal(parsed.host):
        raise DidWebHostRefused(f"host {parsed.host} is written as an IP address; it must be a name")
    return parsed.host


async def _fetch_did_document(client: httpx.AsyncClient, url: str):
    headers = {"Accept-Encoding": "identity"}
    async with client.stream("GET", url, headers=headers, follow_redirects=False) as response:
        response.raise_for_status()
        # The size limit counts bytes as sent, so a compressed body is refused
        # rather than inflated.
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding != "identity":
            raise ValueError("DID document is sent with a content encoding")
        body = bytearray()
        async for chunk in response.aiter_raw():
            body.extend(chunk)
            if len(body) > DID_DOCUMENT_MAX_BYTES:
                raise ValueError("DID document is larger than the resolution limit")
    return parse_did_document(bytes(body))


def parse_did_document(body: bytes):
    """Parse a fetched DID document: strict UTF-8 JSON, no NaN or Infinity."""

    def refuse(literal: str):
        raise ValueError(f"DID document contains the non-JSON literal {literal}")

    return json.loads(body.decode("utf-8-sig"), parse_constant=refuse)


class VerificationMethodNotFoundError(KeyError):
    """The DID document does not list the verification method asked for.

    A KeyError, so existing callers keep working; verifiers catch it to tell a
    key the document does not list (rotated, or never published) from a
    signature that is wrong.
    """


def did_web_document_url(did: str) -> str:
    """The HTTPS URL a did:web DID's document is published at."""
    return _did_web_to_url(did)


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
        VerificationMethodNotFoundError (a KeyError): if the method is not found
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

    raise VerificationMethodNotFoundError(f"Verification method {method_id!r} not found in DID document")


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
