"""Transport security, authentication, and the response-hardening middleware.

TLS 1.3
-------
Zero-Trust §7.1 sets TLS 1.3 as the enforced version. :func:`build_tls_context` builds
a context that will not negotiate anything older -- ``minimum_version`` is set
explicitly rather than relying on a protocol constant, because ``PROTOCOL_TLS_SERVER``
happily negotiates 1.2 and a "TLS 1.3 server" that quietly accepts 1.2 is the exact
downgrade the setting exists to prevent.

Where TLS is terminated matters for what this module can promise. Two deployments:

* **Direct.** The server holds the certificate; :func:`build_tls_context` governs, and
  the guarantee is real end to end.
* **Behind a terminating proxy.** The proxy governs the version, and this process sees
  plaintext HTTP. :class:`RequireTlsMiddleware` then relies on a forwarded header,
  which is only as trustworthy as the proxy setting it -- so it is honoured **only**
  from a configured trusted-proxy list. An unconditional trust of
  ``X-Forwarded-Proto`` would let any client claim TLS by sending a header.

Authentication
--------------
:class:`PrincipalResolver` is the seam to the real identity provider. Zero-Trust §1.1
requires OIDC + FIDO2 hardware MFA for tactical operations and §1.3 requires device
posture attestation before session issuance; both live in that provider, not here.
What this module guarantees is narrower and still essential: **the principal is
server-derived**. Role and zone scoping come from the resolved session, never from the
request body, because a request that could name its own role would make the precedence
matrix decorative.
"""

from __future__ import annotations

import hmac
import ssl
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol

from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from mcp_server.schemas.identity import OperatorIdentity

__all__ = [
    "MAX_REQUEST_BYTES",
    "SECURITY_HEADERS",
    "AuthenticatedPrincipal",
    "BodySizeLimitMiddleware",
    "HostAllowListMiddleware",
    "PrincipalResolver",
    "RequireTlsMiddleware",
    "SecurityHeadersMiddleware",
    "StaticTokenResolver",
    "build_tls_context",
    "harden_uvicorn_config",
]

#: Cap on a request body. The largest legitimate payload is a polygon with a few
#: hundred vertices; anything approaching this is a defect or an attack.
MAX_REQUEST_BYTES: Final[int] = 256 * 1024

#: Zero-Trust §3.2, mandatory on every response.
#:
#: The API serves JSON only and is never framed, so the policy is maximally
#: restrictive: no scripts, no objects, no framing, no ambient browser capabilities.
SECURITY_HEADERS: Final[Mapping[str, str]] = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; require-trusted-types-for 'script'"
    ),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    "Cache-Control": "no-store",
}


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """A resolved session. Every field here is server-derived."""

    identity: OperatorIdentity
    session_id: str
    #: True when the identity provider attested the device posture (Zero-Trust §1.3).
    device_attested: bool = False

    @property
    def operator_id(self) -> str:
        return self.identity.operator_id

    @property
    def role_value(self) -> str:
        return self.identity.role.value


class PrincipalResolver(Protocol):
    """Seam to the identity provider.

    Implementations MUST return ``None`` rather than a partially-populated principal
    on any failure. There is no "anonymous" principal: an unresolvable credential is
    an unauthenticated request.
    """

    def resolve(self, credential: str) -> AuthenticatedPrincipal | None:
        ...


class StaticTokenResolver:
    """Development resolver mapping opaque bearer tokens to principals.

    **Not a production identity provider.** Real deployments resolve an OIDC access
    token, verify it against a JWKS with an allow-listed algorithm, and check device
    posture (Zero-Trust §1.1, §1.3). This exists so the full request path can be
    exercised in tests without standing up an IdP.

    Token comparison is constant-time even here: a development shortcut that teaches
    the codebase to compare secrets with ``==`` is how that pattern reaches production.
    """

    def __init__(self, tokens: Mapping[str, AuthenticatedPrincipal]) -> None:
        self._tokens = dict(tokens)

    def resolve(self, credential: str) -> AuthenticatedPrincipal | None:
        if not credential:
            return None
        encoded = credential.encode("utf-8")
        match: AuthenticatedPrincipal | None = None
        # Scan every entry so the comparison count does not depend on which token was
        # supplied, and compare each in constant time (Zero-Trust §10).
        for token, principal in self._tokens.items():
            if hmac.compare_digest(encoded, token.encode("utf-8")):
                match = principal
        return match


def extract_bearer(headers: Headers) -> str | None:
    """Pull a bearer credential out of the Authorization header.

    Returns ``None`` for anything that is not exactly one ``Bearer <token>`` -- no
    tolerance for alternative schemes or extra whitespace-separated parts, since a
    lenient parser here is a parser differential between this server and whatever
    audits its logs.
    """
    raw = headers.get("authorization")
    if not raw:
        return None
    parts = raw.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None
    return parts[1]


def build_tls_context(
    *,
    certfile: str,
    keyfile: str,
    keyfile_password: str | None = None,
    client_ca_file: str | None = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    """Build a server TLS context that will not negotiate below TLS 1.3.

    ``require_client_cert`` turns this into the mTLS listener Zero-Trust §0.1 requires
    for service-to-service hops. Operator sessions authenticate with OIDC + FIDO2 over
    ordinary TLS; the agent orchestrator and other internal callers use mTLS.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # The load-bearing line. PROTOCOL_TLS_SERVER negotiates 1.2 by default.
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    context.options |= ssl.OP_NO_COMPRESSION  # CRIME
    context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=keyfile_password)

    if client_ca_file:
        context.load_verify_locations(cafile=client_ca_file)
        context.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
    elif require_client_cert:
        raise ValueError("require_client_cert needs a client_ca_file to verify against")

    return context


def harden_uvicorn_config(config: object) -> None:
    """Force TLS 1.3 onto a loaded uvicorn config.

    uvicorn builds its own ``SSLContext`` and does not expose ``minimum_version``, so
    a server started through ``uvicorn.run(ssl_certfile=...)`` would accept TLS 1.2.
    Call this after ``config.load()`` and before serving.

    Raises if TLS is not configured at all -- silently doing nothing would leave a
    caller believing they had hardened a listener that is serving plaintext.
    """
    tls = getattr(config, "ssl", None)
    if tls is None:
        raise ValueError(
            "uvicorn config has no TLS context to harden; either configure "
            "ssl_certfile/ssl_keyfile or terminate TLS at a proxy pinned to 1.3"
        )
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.options |= ssl.OP_NO_COMPRESSION


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply :data:`SECURITY_HEADERS` to every response, including error responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response


class RequireTlsMiddleware(BaseHTTPMiddleware):
    """Refuse plaintext requests.

    When TLS terminates at a proxy this consults a forwarded header, but **only** from
    a peer on ``trusted_proxies``. Trusting the header unconditionally would let any
    client assert TLS by sending ``X-Forwarded-Proto: https``.
    """

    def __init__(
        self,
        app: object,
        *,
        enabled: bool = True,
        trusted_proxies: Iterable[str] = (),
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._enabled = enabled
        self._trusted = frozenset(trusted_proxies)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self._enabled:
            return await call_next(request)

        if request.url.scheme == "https":
            return await call_next(request)

        peer = request.client.host if request.client else ""
        if peer in self._trusted and request.headers.get("x-forwarded-proto") == "https":
            return await call_next(request)

        return JSONResponse(
            status_code=426,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32006,
                    "message": "TLS 1.3 is required for this endpoint",
                },
            },
            headers=dict(SECURITY_HEADERS),
        )


class HostAllowListMiddleware(BaseHTTPMiddleware):
    """Validate the Host header against an explicit allow-list (Zero-Trust §3.3).

    Wildcard or absent Host validation is forbidden by the standard: it is what makes
    DNS rebinding and cache-poisoning work against an otherwise sound service.
    """

    def __init__(self, app: object, *, allowed_hosts: Iterable[str]) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._allowed = frozenset(h.lower() for h in allowed_hosts)
        if not self._allowed:
            raise ValueError("an empty host allow-list would accept nothing; configure hosts")
        if "*" in self._allowed:
            raise ValueError("wildcard Host validation is forbidden (Zero-Trust 3.3)")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        host = (request.headers.get("host") or "").split(":")[0].lower()
        if host not in self._allowed:
            return JSONResponse(
                status_code=421,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Host header is not allow-listed"},
                },
                headers=dict(SECURITY_HEADERS),
            )
        return await call_next(request)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies before they are buffered.

    Checks the declared ``Content-Length`` first so an oversized request is refused
    without reading it. A chunked request with no length is still bounded downstream
    by the read cap in the endpoint.
    """

    def __init__(self, app: object, *, max_bytes: int = MAX_REQUEST_BYTES) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._max = max_bytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                return _too_large("Content-Length is not an integer")
            if length > self._max:
                return _too_large(f"request body exceeds the {self._max}-byte limit")
        return await call_next(request)


def _too_large(message: str) -> JSONResponse:
    return JSONResponse(
        status_code=413,
        content={
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32005, "message": message},
        },
        headers=dict(SECURITY_HEADERS),
    )
