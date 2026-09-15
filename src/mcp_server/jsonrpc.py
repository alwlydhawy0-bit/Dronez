"""JSON-RPC 2.0 envelope handling for the MCP tool surface.

Strictness
----------
The envelope is parsed as strictly as the tool payloads inside it. A request whose
``jsonrpc`` field is not exactly ``"2.0"``, whose ``method`` is not a string, or whose
``params`` is not an object is rejected outright rather than best-effort interpreted.
Zero-Trust §0.1 makes ambiguous framing a fail-closed condition, and §3.4 forbids
"best-effort normalize" on anything protocol-shaped.

Errors versus rejections
------------------------
Two different things can go wrong, and conflating them loses information:

* **Protocol and gate failures** become JSON-RPC *errors*: malformed envelope, unknown
  method, authentication failure, rate limiting, a sanitizer block, a tool the caller
  is not scoped to. The request never reached a tool.
* **Domain decisions** become JSON-RPC *results* carrying a structured rejection: a
  policy denial, a negative airspace clearance, a digest mismatch. The tool ran, and
  the answer is no.

A caller can therefore distinguish "I could not ask" from "I asked and was refused",
which matters both operationally and for the audit trail.

Batches
-------
Supported, bounded, and **not** a way around the rate limiter: every call in a batch
consumes budget independently. A batch that exhausts the limit mid-way has its
remaining calls rejected individually, which is the same outcome as sending them
separately -- exactly the property that makes batching uninteresting as an attack.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Final

__all__ = [
    "JSONRPC_VERSION",
    "MAX_BATCH_SIZE",
    "JsonRpcError",
    "JsonRpcErrorCode",
    "JsonRpcRequest",
    "error_response",
    "parse_envelope",
    "success_response",
]

JSONRPC_VERSION: Final[str] = "2.0"

#: Bound on a single batch. Each element still costs a rate-limit token, so this caps
#: the parse and dispatch cost of one request rather than the throughput of a caller.
MAX_BATCH_SIZE: Final[int] = 20

_MAX_METHOD_LEN: Final[int] = 128
_MAX_ID_LEN: Final[int] = 128


class JsonRpcErrorCode(IntEnum):
    """Standard codes plus this server's implementation-defined range.

    JSON-RPC 2.0 reserves -32000 to -32099 for implementation-defined server errors;
    the gate failures below live there.
    """

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    UNAUTHENTICATED = -32001
    FORBIDDEN_SCOPE = -32002
    RATE_LIMITED = -32003
    SANITIZER_BLOCKED = -32004
    PAYLOAD_TOO_LARGE = -32005
    TLS_REQUIRED = -32006
    SERVICE_UNAVAILABLE = -32007


class JsonRpcError(Exception):
    """A protocol or gate failure, carrying its wire representation.

    ``data`` is deliberately narrow: reason codes and short details only. An error
    body is returned to a caller who may be an attacker, so it must not leak internal
    state, key ids, or the contents of another tenant's request.
    """

    def __init__(
        self,
        code: JsonRpcErrorCode,
        message: str,
        *,
        data: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = dict(data) if data else None

    def to_wire(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": int(self.code), "message": self.message[:256]}
        if self.data:
            error["data"] = self.data
        return error


@dataclass(frozen=True, slots=True)
class JsonRpcRequest:
    """One validated call within an envelope."""

    method: str
    params: Mapping[str, Any]
    #: ``None`` means a notification: no response is returned for it.
    request_id: str | int | None
    is_notification: bool
    #: The exact bytes of this call, for the audit record's payload hash.
    raw: bytes


def _invalid(message: str) -> JsonRpcError:
    return JsonRpcError(JsonRpcErrorCode.INVALID_REQUEST, message)


def _parse_one(item: Any) -> JsonRpcRequest:
    """Validate a single call object. Raises :class:`JsonRpcError` on any violation."""
    if not isinstance(item, Mapping):
        raise _invalid("a JSON-RPC call must be an object")

    unknown = set(item) - {"jsonrpc", "method", "params", "id"}
    if unknown:
        # Consistent with the strict-schema rule applied to tool payloads: an
        # undeclared envelope field is a rejection, not something to ignore.
        raise _invalid(f"undeclared envelope field(s): {sorted(unknown)}")

    if item.get("jsonrpc") != JSONRPC_VERSION:
        raise _invalid(f"jsonrpc must be exactly {JSONRPC_VERSION!r}")

    method = item.get("method")
    if not isinstance(method, str) or not method:
        raise _invalid("method must be a non-empty string")
    if len(method) > _MAX_METHOD_LEN:
        raise _invalid("method name is too long")

    params = item.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, Mapping):
        # Positional params are legal JSON-RPC but deliberately unsupported: the tool
        # schemas are keyword-only, and accepting positional arguments would mean
        # mapping them by position, which silently reorders on any schema change.
        raise JsonRpcError(
            JsonRpcErrorCode.INVALID_PARAMS,
            "params must be an object; positional parameters are not supported",
        )

    has_id = "id" in item
    request_id = item.get("id")
    if has_id and request_id is not None:
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            raise _invalid("id must be a string, a number, or null")
        if isinstance(request_id, str) and len(request_id) > _MAX_ID_LEN:
            raise _invalid("id is too long")

    return JsonRpcRequest(
        method=method,
        params=params,
        request_id=request_id if has_id else None,
        # A call with no `id` member at all is a notification. An explicit `"id": null`
        # is a request whose response carries a null id -- the spec distinguishes them.
        is_notification=not has_id,
        raw=json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )


def parse_envelope(body: bytes) -> tuple[list[JsonRpcRequest], bool]:
    """Parse a request body into calls.

    Returns ``(calls, is_batch)``. Raises :class:`JsonRpcError` for envelope-level
    failures; per-call failures inside a batch are raised by the caller's dispatch
    loop so one bad call does not sink the whole batch.
    """
    try:
        payload = json.loads(body.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise JsonRpcError(JsonRpcErrorCode.PARSE_ERROR, f"body is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise JsonRpcError(JsonRpcErrorCode.PARSE_ERROR, f"body is not valid JSON: {exc}") from exc

    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes)):
        if not payload:
            raise _invalid("a batch must contain at least one call")
        if len(payload) > MAX_BATCH_SIZE:
            raise _invalid(f"a batch may contain at most {MAX_BATCH_SIZE} calls")
        return [_parse_one(item) for item in payload], True

    return [_parse_one(payload)], False


def success_response(request_id: str | int | None, result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def error_response(request_id: str | int | None, error: JsonRpcError) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error.to_wire()}
