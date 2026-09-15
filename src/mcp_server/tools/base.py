"""Tool handler contract.

A handler receives an already-validated request and a :class:`CallContext`, and
returns a :class:`ToolOutcome` carrying both the response and everything the audit
trail needs. Handlers do not write audit records themselves -- the dispatcher does,
uniformly, so there is no path on which a handler can return without being recorded.

Handlers must not raise. A defect becomes an ``ERROR`` outcome and a structured
rejection, because an exception escaping a handler is an unhandled state in the
dispatch path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from mcp_server.audit import Outcome
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.tools import ToolName
from mcp_server.security import AuthenticatedPrincipal

__all__ = ["CallContext", "ToolHandler", "ToolOutcome"]


@dataclass(frozen=True, slots=True)
class CallContext:
    """Per-call state. Every field is server-derived."""

    principal: AuthenticatedPrincipal
    now: datetime
    #: Exact bytes of this call, for the audit payload hash.
    raw_payload: bytes
    #: Correlation id, safe to pass to external services -- carries no identity.
    trace_id: str


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    """A handler's result plus its audit projection."""

    response: StrictModel
    audit_outcome: Outcome
    reason_codes: tuple[str, ...] = ()
    detail: str = ""
    decision: dict[str, Any] = field(default_factory=dict)


class ToolHandler(Protocol):
    """One MCP tool."""

    name: ToolName
    request_model: type[StrictModel]

    def handle(self, request: Any, ctx: CallContext) -> ToolOutcome:
        ...
