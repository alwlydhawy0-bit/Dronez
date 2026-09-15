"""FastAPI application exposing the MCP tool surface over JSON-RPC 2.0.

Request path, in order
----------------------
Each step can only narrow what proceeds, and each records an audit entry:

1. **Middleware** -- host allow-list, TLS requirement, body size cap, security headers.
2. **Authenticate** -- resolve a server-side principal. No principal, no request.
3. **Parse the JSON-RPC envelope** -- strictly.
4. **Per call:**
   a. **Rate limit.** Before any expensive work, and charged on the attempt.
   b. **Capability scope.** Is this principal allowed to invoke this tool at all?
   c. **Schema.** ``parse_json`` on the exact params bytes.
   d. **Sanitize inbound free text.**
   e. **Handle.**
   f. **Sanitize the result** when the caller is an agent, because the result is about
      to re-enter a model's context (Zero-Trust §4.2).
   g. **Audit**, whatever happened.

Why authentication precedes rate limiting
-----------------------------------------
The limiter is per session, and a session only exists once a credential resolves. The
cost of that ordering is that unauthenticated requests are not session-rate-limited
here -- that is the edge proxy's job (Zero-Trust §1.1 anti-automation), and is called
out rather than left implicit.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from mcp_server.audit import CommandRecord, Outcome
from mcp_server.context import FREE_TEXT_FIELDS, ServerContext
from mcp_server.guardrails.sanitizer import ContentChannel
from mcp_server.jsonrpc import (
    JsonRpcError,
    JsonRpcErrorCode,
    JsonRpcRequest,
    error_response,
    parse_envelope,
    success_response,
)
from mcp_server.schemas.identity import Role
from mcp_server.schemas.tools import AGENT_PROPOSABLE_TOOLS, ToolName
from mcp_server.security import (
    MAX_REQUEST_BYTES,
    SECURITY_HEADERS,
    AuthenticatedPrincipal,
    BodySizeLimitMiddleware,
    HostAllowListMiddleware,
    RequireTlsMiddleware,
    SecurityHeadersMiddleware,
    extract_bearer,
)
from mcp_server.tools.base import CallContext

__all__ = ["RPC_PATH", "create_app"]

RPC_PATH = "/rpc"


def create_app(
    ctx: ServerContext,
    *,
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1"),
    require_tls: bool = True,
    trusted_proxies: tuple[str, ...] = (),
    start_feed_refresh: bool = True,
) -> FastAPI:
    """Build the application.

    ``require_tls`` defaults to ``True``. Turning it off is a development affordance
    and is logged as such in the status endpoint, so a server accidentally running
    plaintext says so rather than looking healthy.
    """
    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        # The background refresh keeps the NFZ cache warm; the clearance path still
        # refreshes on demand, so a failure here degrades latency, never correctness.
        if start_feed_refresh:
            ctx.feed.start_background_refresh()
        try:
            yield
        finally:
            ctx.feed.stop_background_refresh()

    app = FastAPI(
        title="Tactical Drone Recon MCP Server",
        version="1.0.0",
        lifespan=lifespan,
        # The interactive docs are disabled: they are an unauthenticated surface that
        # enumerates the tool catalogue, which is exactly the reconnaissance an
        # attacker wants (Zero-Trust §2.2, excessive exposure).
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Middleware executes in reverse registration order, so this registers the
    # outermost last: headers wrap everything, then host, then TLS, then size.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)
    app.add_middleware(
        RequireTlsMiddleware, enabled=require_tls, trusted_proxies=trusted_proxies
    )
    app.add_middleware(HostAllowListMiddleware, allowed_hosts=allowed_hosts)
    app.add_middleware(SecurityHeadersMiddleware)

    app.state.ctx = ctx
    app.state.require_tls = require_tls

    @app.get("/healthz")
    def healthz() -> Response:
        """Liveness only. Deliberately says nothing about authorization state."""
        return JSONResponse({"status": "ok"}, headers=dict(SECURITY_HEADERS))

    @app.get("/status")
    def status(request: Request) -> Response:
        """Operational state. Authenticated: feed health is not public information."""
        principal = _authenticate(ctx, request)
        if principal is None:
            return _unauthenticated_response()
        return JSONResponse(
            {
                "feed": ctx.feed.status,
                "staged_plans": len(ctx.store),
                "tools": sorted(t.value for t in ctx.handlers),
                "require_tls": request.app.state.require_tls,
                "signature_algorithms": sorted(
                    a.value for a in ctx.verifier.available_algorithms
                ),
            },
            headers=dict(SECURITY_HEADERS),
        )

    @app.post(RPC_PATH)
    async def rpc(request: Request) -> Response:
        body = await request.body()
        if len(body) > MAX_REQUEST_BYTES:
            # Backstop for a chunked request that declared no Content-Length.
            return _error_response(
                None,
                JsonRpcError(
                    JsonRpcErrorCode.PAYLOAD_TOO_LARGE,
                    f"request body exceeds the {MAX_REQUEST_BYTES}-byte limit",
                ),
                status_code=413,
            )

        principal = _authenticate(ctx, request)
        if principal is None:
            ctx.audit.record(
                tool="-", outcome=Outcome.REJECTED_AUTH, payload=body,
                detail="no resolvable credential",
            )
            return _unauthenticated_response()

        try:
            calls, is_batch = parse_envelope(body)
        except JsonRpcError as exc:
            ctx.audit.record(
                tool="-", outcome=Outcome.REJECTED_SCHEMA, payload=body,
                operator_id=principal.operator_id, role=principal.role_value,
                session_id=principal.session_id, detail=exc.message,
            )
            return _error_response(None, exc)

        responses: list[dict[str, Any]] = []
        for call in calls:
            result = _dispatch_call(ctx, principal, call)
            if call.is_notification:
                # A notification gets no response even when it failed. The audit
                # record is the only trace, which is why step (g) is unconditional.
                continue
            responses.append(result)

        if not responses:
            return Response(status_code=204, headers=dict(SECURITY_HEADERS))
        payload: Any = responses if is_batch else responses[0]
        return JSONResponse(payload, headers=dict(SECURITY_HEADERS))

    return app


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

def _dispatch_call(
    ctx: ServerContext, principal: AuthenticatedPrincipal, call: JsonRpcRequest
) -> dict[str, Any]:
    """Run one call through the gates. Never raises."""
    def record(
        outcome: Outcome,
        *,
        tool: str = call.method,
        detail: str = "",
        decision: dict[str, Any] | None = None,
        reason_codes: tuple[str, ...] = (),
    ) -> CommandRecord:
        """Record this attempt. Principal and payload are fixed for the whole call."""
        return ctx.audit.record(
            tool=tool,
            outcome=outcome,
            payload=call.raw,
            operator_id=principal.operator_id,
            role=principal.role_value,
            session_id=principal.session_id,
            detail=detail,
            decision=decision,
            reason_codes=reason_codes,
        )

    # (a) Rate limit first: the work below is what an attacker wants to force.
    limit = ctx.proposal_limiter.acquire(principal.session_id)
    if not limit.allowed:
        record(Outcome.REJECTED_RATE_LIMIT, detail=limit.rejection_detail)
        return error_response(
            call.request_id,
            JsonRpcError(
                JsonRpcErrorCode.RATE_LIMITED,
                "rate limit exceeded for this session",
                data={"retry_after_s": round(limit.retry_after_s, 3)},
            ),
        )

    # (b) Is this a tool, and may this principal invoke it?
    try:
        tool = ToolName(call.method)
    except ValueError:
        record(Outcome.REJECTED_SCHEMA, detail="unknown method")
        return error_response(
            call.request_id,
            JsonRpcError(JsonRpcErrorCode.METHOD_NOT_FOUND, f"unknown method {call.method!r}"),
        )

    handler = ctx.handlers.get(tool)
    if handler is None:
        record(Outcome.REJECTED_SCHEMA, detail="tool is specified but not implemented")
        return error_response(
            call.request_id,
            JsonRpcError(
                JsonRpcErrorCode.METHOD_NOT_FOUND,
                f"tool {tool.value!r} is not implemented by this server",
            ),
        )

    if principal.identity.role is Role.AI_AGENT and tool not in AGENT_PROPOSABLE_TOOLS:
        record(Outcome.REJECTED_SCOPE, detail=f"agent sessions may not invoke {tool.value}")
        return error_response(
            call.request_id,
            JsonRpcError(
                JsonRpcErrorCode.FORBIDDEN_SCOPE,
                f"this session is not scoped to invoke {tool.value!r}",
            ),
        )

    # (c) Schema, from the raw params bytes.
    try:
        params_bytes = json.dumps(call.params).encode("utf-8")
        request_model = handler.request_model.parse_json(params_bytes)
    except ValidationError as exc:
        record(Outcome.REJECTED_SCHEMA, detail=f"{exc.error_count()} schema violation(s)")
        return error_response(
            call.request_id,
            JsonRpcError(
                JsonRpcErrorCode.INVALID_PARAMS,
                "params failed strict schema validation",
                # Field locations and error types only -- never the submitted values,
                # which may carry another tenant's data or an attacker's payload.
                data={"errors": _safe_validation_errors(exc)},
            ),
        )
    except (TypeError, ValueError) as exc:
        record(Outcome.REJECTED_SCHEMA, detail=str(exc)[:256])
        return error_response(
            call.request_id,
            JsonRpcError(JsonRpcErrorCode.INVALID_PARAMS, "params could not be validated"),
        )

    # (d) Screen inbound free text.
    blocked = _screen_inbound(ctx, tool, request_model)
    if blocked is not None:
        record(Outcome.REJECTED_SANITIZER, detail=blocked)
        return error_response(
            call.request_id,
            JsonRpcError(
                JsonRpcErrorCode.SANITIZER_BLOCKED,
                "content was blocked by the sanitizer",
            ),
        )

    # (e) Handle.
    ctx_call = CallContext(
        principal=principal,
        now=ctx.now(),
        raw_payload=call.raw,
        trace_id=f"trace-{abs(hash(call.raw)) & 0xFFFFFFFF:08x}",
    )
    try:
        outcome = handler.handle(request_model, ctx_call)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        record(Outcome.ERROR, detail=f"handler raised {type(exc).__name__}")
        return error_response(
            call.request_id,
            JsonRpcError(JsonRpcErrorCode.INTERNAL_ERROR, "the tool could not be completed"),
        )

    result = outcome.response.model_dump(mode="json")

    # (f) The result is about to re-enter an agent's context window.
    if principal.identity.role is Role.AI_AGENT:
        verdict = ctx.sanitizer.screen(
            json.dumps(result, sort_keys=True), ContentChannel.TOOL_RESULT
        )
        if not verdict.allowed:
            record(
                Outcome.REJECTED_SANITIZER,
                detail=(
                    "tool result blocked before re-entering agent context: "
                    f"{verdict.detail}"
                ),
            )
            return error_response(
                call.request_id,
                JsonRpcError(
                    JsonRpcErrorCode.SANITIZER_BLOCKED,
                    "the tool result was blocked before returning to an agent session",
                ),
            )

    # (g) Audit, unconditionally.
    entry = record(
        outcome.audit_outcome,
        decision=outcome.decision,
        reason_codes=outcome.reason_codes,
        detail=outcome.detail,
    )
    if isinstance(result, dict) and isinstance(result.get("rejection"), dict):
        result["rejection"]["command_record_id"] = entry.record_id

    return success_response(call.request_id, result)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _authenticate(ctx: ServerContext, request: Request) -> AuthenticatedPrincipal | None:
    credential = extract_bearer(request.headers)
    if credential is None:
        return None
    return ctx.resolver.resolve(credential)


def _screen_inbound(ctx: ServerContext, tool: ToolName, model: object) -> str | None:
    """Screen declared free-text fields. Returns a detail string when blocked."""
    for field_name in FREE_TEXT_FIELDS.get(tool, ()):
        value = getattr(model, field_name, None)
        if not isinstance(value, str) or not value:
            continue
        verdict = ctx.sanitizer.screen(value, ContentChannel.USER_INPUT)
        if not verdict.allowed:
            return f"{field_name}: {verdict.detail}"
    return None


def _safe_validation_errors(exc: ValidationError) -> list[dict[str, str]]:
    """Field locations and error types only -- never the submitted values."""
    return [
        {"loc": ".".join(str(p) for p in err.get("loc", ())), "type": str(err.get("type", ""))}
        for err in exc.errors()[:16]
    ]


def _unauthenticated_response() -> JSONResponse:
    return _error_response(
        None,
        JsonRpcError(JsonRpcErrorCode.UNAUTHENTICATED, "a valid bearer credential is required"),
        status_code=401,
    )


def _error_response(
    request_id: str | int | None, error: JsonRpcError, *, status_code: int = 200
) -> JSONResponse:
    headers = dict(SECURITY_HEADERS)
    if status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(
        error_response(request_id, error), status_code=status_code, headers=headers
    )
