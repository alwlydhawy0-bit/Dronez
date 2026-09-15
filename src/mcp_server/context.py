"""Server composition root.

Every dependency the request path uses is assembled here and nowhere else. Handlers
receive what they need through their constructors, so there is no module-level
singleton a test can forget to replace and no hidden global a request can reach.

The wiring is also where the fail-closed defaults live: a :class:`ServerContext` built
with no arguments has a policy engine pointing at a loopback OPA that may not be
running (every evaluation denies), a dispatcher that refuses (`GatedDispatcher`), and
a principal resolver that knows no tokens (every request is unauthenticated). A
misconfigured server therefore does nothing, rather than doing something unauthorized.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

from mcp_server.audit import AuditSink, AuditTrail, InMemoryAuditSink, SecurityViolation
from mcp_server.dispatch import GatedDispatcher, HardwareDispatcher
from mcp_server.feed import LiveAirspaceFeed
from mcp_server.guardrails.rate_limiter import AgentProposalLimiter, HardwareCommandLimiter
from mcp_server.guardrails.sanitizer import PromptSanitizer
from mcp_server.precedence import PrecedenceArbiter
from mcp_server.repositories import FleetProvider, MissionRegistry
from mcp_server.schemas.tools import ToolName
from mcp_server.security import PrincipalResolver
from mcp_server.signing import KeyRegistry, NonceStore, SignatureVerifier
from mcp_server.store import FlightPlanStore
from mcp_server.tools.base import ToolHandler
from mcp_server.tools.clearance import CheckAirspaceClearanceHandler
from mcp_server.tools.confirm import ConfirmFlightPlanHandler
from mcp_server.tools.deploy import DeployReconWaypointHandler
from mcp_server.tools.stream import StreamSessionRegistry, StreamThermalFeedHandler
from policy_engine import PolicyEngine

__all__ = ["FREE_TEXT_FIELDS", "ServerContext", "build_handlers"]

#: Request fields carrying operator free text, screened by the sanitizer on the way in.
#: Declared explicitly rather than inferred: a heuristic that guessed which strings are
#: prose would eventually guess wrong about an identifier, and silently stop screening
#: a field that matters.
FREE_TEXT_FIELDS: Mapping[ToolName, tuple[str, ...]] = {
    ToolName.CONFIRM_FLIGHT_PLAN: ("note",),
    ToolName.REQUEST_EMERGENCY_STOP: ("reason",),
}


@dataclass(slots=True)
class ServerContext:
    """Everything the request path needs, assembled once."""

    feed: LiveAirspaceFeed
    policy: PolicyEngine
    missions: MissionRegistry
    fleet: FleetProvider
    sanitizer: PromptSanitizer
    resolver: PrincipalResolver

    store: FlightPlanStore = field(default_factory=FlightPlanStore)
    #: Optional override. Left unset, __post_init__ builds one sharing this context's
    #: clock -- a registry with its own clock would expire sessions on a different
    #: timeline from everything else in the request path.
    stream_session_registry: StreamSessionRegistry | None = None
    key_registry: KeyRegistry = field(default_factory=KeyRegistry)
    nonces: NonceStore = field(default_factory=NonceStore)
    dispatcher: HardwareDispatcher = field(default_factory=GatedDispatcher)
    audit_sink: AuditSink = field(default_factory=InMemoryAuditSink)
    #: Fan-out for security violations -- the subset of rejections worth paging on.
    #: Defaults to None, which still records them in the audit trail; production wires
    #: this to the SIEM (Zero-Trust §8.2).
    alert_sink: Callable[[SecurityViolation], None] | None = None

    proposal_limiter: AgentProposalLimiter = field(default_factory=AgentProposalLimiter)
    command_limiter: HardwareCommandLimiter = field(default_factory=HardwareCommandLimiter)

    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    # Populated by __post_init__.
    audit: AuditTrail = field(init=False)
    verifier: SignatureVerifier = field(init=False)
    arbiter: PrecedenceArbiter = field(init=False)
    stream_sessions: StreamSessionRegistry = field(init=False)
    handlers: Mapping[ToolName, ToolHandler] = field(init=False)

    def __post_init__(self) -> None:
        self.audit = AuditTrail(
            self.audit_sink, clock=self.clock, alert_sink=self.alert_sink
        )
        self.stream_sessions = self.stream_session_registry or StreamSessionRegistry(
            clock=self.clock
        )
        self.verifier = SignatureVerifier(self.key_registry, self.nonces, clock=self.clock)
        self.arbiter = PrecedenceArbiter(self.policy, self.audit, clock=self.clock)
        self.handlers = build_handlers(self)

    def now(self) -> datetime:
        return self.clock()


def build_handlers(ctx: ServerContext) -> dict[ToolName, ToolHandler]:
    """Construct the tool handlers this server exposes.

    Only the three tools this milestone implements are registered. A tool whose
    contract exists in ``schemas.tools`` but has no handler here is *not* exposed --
    the JSON-RPC dispatcher reports it as method-not-found, which is the correct
    answer for a tool that is specified but not built. Registering a placeholder
    would be worse: it would advertise a capability the server does not have.
    """
    return {
        ToolName.CHECK_AIRSPACE_CLEARANCE: CheckAirspaceClearanceHandler(ctx.feed),
        ToolName.DEPLOY_RECON_WAYPOINT: DeployReconWaypointHandler(
            feed=ctx.feed,
            policy=ctx.policy,
            missions=ctx.missions,
            fleet=ctx.fleet,
            store=ctx.store,
            arbiter=ctx.arbiter,
        ),
        ToolName.STREAM_THERMAL_FEED: StreamThermalFeedHandler(
            missions=ctx.missions,
            sessions=ctx.stream_sessions,
        ),
        ToolName.CONFIRM_FLIGHT_PLAN: ConfirmFlightPlanHandler(
            store=ctx.store,
            verifier=ctx.verifier,
            dispatcher=ctx.dispatcher,
        ),
    }
