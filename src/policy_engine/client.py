"""Fail-closed client for the deterministic policy engine.

Deployment shape
----------------
OPA runs as a sidecar alongside the MCP server and is queried over loopback. The
policy bundle -- the ``.rego`` files in :mod:`policy_engine.policies` plus the
generated ``data/safety_envelope.json`` -- is signed and delivered to OPA out of band,
so the bounds a request is judged against arrive with the bundle rather than with the
request.

The one rule
------------
**No response, no answer, no allow.** Every failure mode below produces a denial:

============================  =========================================
Unreachable / connection refused   engine unavailable -> deny
Timeout                            engine unavailable -> deny
Non-200 status                     deny
Oversized response body            deny
Malformed or non-JSON body         deny
Missing ``result`` key             deny
``allow`` that is not literally ``True``  deny
Any unexpected exception           deny
============================  =========================================

This is Zero-Trust §0.1 applied to the component that *is* the authorization decision:
if the check cannot complete, the answer is no. :meth:`PolicyEngine.evaluate` therefore
does not raise -- an exception escaping into the dispatch path is exactly the ambiguity
that must not exist.

Why the transport is a seam
---------------------------
:class:`PolicyTransport` keeps HTTP out of the decision logic so the fail-closed
behaviour can be tested exhaustively without a running OPA, and so an embedded
(WASM) evaluator can be substituted later without touching this file.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol

from policy_engine.models import PolicyDecision, PolicyPath

__all__ = [
    "DEFAULT_TIMEOUT_S",
    "MAX_RESPONSE_BYTES",
    "HttpPolicyTransport",
    "PolicyEngine",
    "PolicyTransport",
    "PolicyTransportError",
    "StaticPolicyTransport",
    "TransportResponse",
]

#: Cap on an accepted decision document. A policy decision is small; a large body
#: means a misrouted request or a hostile endpoint, and we refuse to parse it.
MAX_RESPONSE_BYTES: Final[int] = 1 << 20

#: Budget for one evaluation. The gate sits in the dispatch path, so a slow engine
#: must fail rather than hang -- but note that failing means denying, so this timeout
#: trades availability for safety, deliberately.
DEFAULT_TIMEOUT_S: Final[float] = 1.5


class PolicyTransportError(RuntimeError):
    """The policy engine could not be reached or did not answer usably."""


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    body: bytes


class PolicyTransport(Protocol):
    """Seam to the OPA data API.

    Implementations MUST raise :class:`PolicyTransportError` on any failure rather
    than returning a synthesised permissive body. A transport that invented a
    response would be forging an authorization decision.
    """

    def post(self, path: str, document: bytes, *, timeout_s: float) -> TransportResponse:
        ...


class PolicyEngine:
    """The non-bypassable authorization gate, as seen by the MCP server.

    There is deliberately no ``evaluate_or_raise``, no ``allow_on_error`` flag, and no
    caching of affirmative decisions. Each of those would be a way to get a "yes"
    without the policy having said so.
    """

    def __init__(
        self,
        transport: PolicyTransport,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        on_decision: Callable[[str, PolicyDecision], None] | None = None,
    ) -> None:
        self._transport = transport
        self._timeout_s = timeout_s
        # Every decision is recorded, allowed and denied alike: Master Plan §5 makes
        # rejected proposals part of the audit backbone, not noise to discard.
        self._on_decision = on_decision

    def evaluate(self, path: PolicyPath, document: Mapping[str, Any]) -> PolicyDecision:
        """Evaluate one request. Never raises; every failure is a denial."""
        decision = self._evaluate(path, document)
        if self._on_decision is not None:
            try:
                self._on_decision(path.value, decision)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException:  # noqa: S110 - see below
                # Deliberately swallowed and deliberately not logged from here: the
                # audit sink IS the logging path, so reporting its failure through it
                # would recurse. A sink defect must never change the verdict; sink
                # health is monitored where the sink is constructed.
                pass
        return decision

    def _evaluate(self, path: PolicyPath, document: Mapping[str, Any]) -> PolicyDecision:
        try:
            payload = json.dumps({"input": document}, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            # Non-serialisable input means the server built a bad document. Deny:
            # the policy never saw the request, so nothing authorized it.
            return PolicyDecision.deny(
                "policy_input_unserialisable",
                f"could not serialise policy input: {exc}",
            )

        try:
            response = self._transport.post(
                f"/v1/data/{path.value}", payload, timeout_s=self._timeout_s
            )
        except PolicyTransportError as exc:
            return PolicyDecision.deny(
                "policy_engine_unavailable",
                f"policy engine unreachable, failing closed: {exc}",
                engine_unavailable=True,
            )
        except (KeyboardInterrupt, SystemExit):
            # Genuine interpreter shutdown. Propagate: the process is going away, and
            # converting that into a routine denial would hide it from the supervisor.
            raise
        except BaseException as exc:
            # Everything else -- including a pathological transport raising outside the
            # Exception hierarchy -- becomes a denial. An exception escaping into the
            # dispatch path is the ambiguity Zero-Trust Sec.0.1 forbids.
            return PolicyDecision.deny(
                "policy_engine_unavailable",
                f"policy transport raised {type(exc).__name__}, failing closed",
                engine_unavailable=True,
            )

        # mypy reports this as unreachable because the annotation promises the
        # type. That promise is static only: PolicyTransport is a Protocol, which is
        # structural and NOT enforced at runtime, so a client can return anything.
        # Verified by the fail-closed sweep in tests/policy.
        if not isinstance(response, TransportResponse):
            return PolicyDecision.deny(  # type: ignore[unreachable]
                "policy_engine_unavailable",
                "policy transport returned an unrecognised response type",
                engine_unavailable=True,
            )

        if response.status != 200:
            return PolicyDecision.deny(
                "policy_engine_error",
                f"policy engine returned HTTP {response.status}",
                engine_unavailable=response.status >= 500,
            )

        if len(response.body) > MAX_RESPONSE_BYTES:
            return PolicyDecision.deny(
                "policy_malformed",
                f"decision body of {len(response.body)} bytes exceeds the "
                f"{MAX_RESPONSE_BYTES}-byte cap",
            )

        try:
            envelope = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return PolicyDecision.deny(
                "policy_malformed", f"decision body is not valid JSON: {exc}"
            )

        if not isinstance(envelope, Mapping):
            return PolicyDecision.deny("policy_malformed", "decision body is not a JSON object")

        if "result" not in envelope:
            # OPA omits `result` when the queried path is undefined -- typically a
            # policy that failed to load. An undefined gate is not an open gate.
            return PolicyDecision.deny(
                "policy_undefined",
                f"policy path {path.value!r} returned no result; the policy may not be loaded",
            )

        return PolicyDecision.from_opa_result(envelope["result"])


class HttpPolicyTransport:
    """HTTP transport to an OPA sidecar over loopback.

    Uses ``urllib`` rather than a third-party HTTP client to keep the dependency
    surface of the authorization path minimal (Zero-Trust §6.2). Loopback only by
    default: the policy engine is a sidecar, and a remote one would add a network
    partition to the dispatch path.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8181") -> None:
        if not base_url.startswith(("http://127.0.0.1", "http://localhost")):
            raise ValueError(
                f"policy engine must be a loopback sidecar, got {base_url!r}; a remote "
                "policy engine puts a network partition in the dispatch path"
            )
        self._base_url = base_url.rstrip("/")

    def post(self, path: str, document: bytes, *, timeout_s: float) -> TransportResponse:
        import urllib.error
        import urllib.request

        # S310: the scheme is not caller-controlled -- the constructor above rejects
        # any base_url that is not http://127.0.0.1 or http://localhost.
        request = urllib.request.Request(  # noqa: S310
            url=f"{self._base_url}{path}",
            data=document,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            # S310: the scheme is not caller-controlled -- the constructor above
            # rejects any base_url that is not http://127.0.0.1 or http://localhost.
            with urllib.request.urlopen(request, timeout=timeout_s) as response:  # noqa: S310
                return TransportResponse(
                    status=response.status,
                    body=response.read(MAX_RESPONSE_BYTES + 1),
                )
        except urllib.error.HTTPError as exc:
            return TransportResponse(status=exc.code, body=exc.read(MAX_RESPONSE_BYTES + 1))
        except Exception as exc:
            raise PolicyTransportError(f"{type(exc).__name__}: {exc}") from exc


class StaticPolicyTransport:
    """Deterministic transport for testing the fail-closed paths without OPA."""

    def __init__(
        self,
        *,
        status: int = 200,
        body: bytes | None = None,
        result: Any = None,
        raise_error: BaseException | None = None,
    ) -> None:
        self._status = status
        self._raise = raise_error
        if body is not None:
            self._body = body
        elif result is not None:
            self._body = json.dumps({"result": result}).encode("utf-8")
        else:
            self._body = b"{}"
        self.calls: list[tuple[str, bytes]] = []

    def post(self, path: str, document: bytes, *, timeout_s: float) -> TransportResponse:
        self.calls.append((path, document))
        if self._raise is not None:
            raise self._raise
        return TransportResponse(status=self._status, body=self._body)
