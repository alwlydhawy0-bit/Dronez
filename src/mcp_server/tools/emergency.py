"""``request_emergency_stop`` -- the broadcast kill switch.

Master Plan §5: *"a swarm/zone-wide broadcast kill switch, delivered over a channel
independent of the primary mission command path, callable by any authenticated field
leader physically in the affected zone **without needing command-room mediation**."*

What this handler does not do
-----------------------------
It does not consult the policy engine, and that is deliberate rather than an oversight.
See :mod:`mcp_server.emergency`: fail-closed means denying *authority*, not denying
*safety actions*. A stop makes the fleet strictly less capable, so the conservative
answer when a check cannot complete is to let it through.

What it still requires: a valid hardware-bound signature. An unauthenticated stop would
be a denial-of-service primitive against the entire fleet, and that failure mode is not
benign either.

Order of checks
---------------
Signature, then zone scope, then broadcast. Zone scope comes *after* the signature so an
unsigned caller cannot use the endpoint to enumerate which zones exist.
"""

from __future__ import annotations

from fleet_manager import FleetRegistry
from mcp_server.audit import Outcome
from mcp_server.emergency import (
    EmergencyStop,
    EmergencyStopService,
    StopReason,
    StopScope,
    new_stop_id,
)
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.identity import Role
from mcp_server.schemas.tools import (
    EmergencyStopScope,
    RejectionCode,
    RequestEmergencyStopRequest,
    RequestEmergencyStopResponse,
    ToolName,
    ToolRejection,
)
from mcp_server.signing import SignatureVerifier
from mcp_server.tools.base import CallContext, ToolOutcome

__all__ = ["RequestEmergencyStopHandler"]


def _reject(code: RejectionCode, detail: str, zone_id: str, outcome: Outcome) -> ToolOutcome:
    return ToolOutcome(
        response=RequestEmergencyStopResponse(
            broadcast=False,
            incident_zone_id=zone_id,
            rejection=ToolRejection(code=code, detail=detail[:512]),
        ),
        audit_outcome=outcome,
        reason_codes=(code.value,),
        detail=detail[:512],
    )


class RequestEmergencyStopHandler:
    """Verifies the issuer, then broadcasts out of band."""

    name: ToolName = ToolName.REQUEST_EMERGENCY_STOP
    request_model: type[StrictModel] = RequestEmergencyStopRequest

    def __init__(
        self,
        *,
        service: EmergencyStopService,
        fleet: FleetRegistry,
        verifier: SignatureVerifier,
    ) -> None:
        self._service = service
        self._fleet = fleet
        self._verifier = verifier

    def handle(
        self, request: RequestEmergencyStopRequest, ctx: CallContext
    ) -> ToolOutcome:
        zone_id = request.incident_zone_id
        issuer = request.authorization.issuer

        # 1 -- human tier only. The schema already forbids an agent-issued envelope;
        # this also rejects an agent *session* relaying a human's.
        if ctx.principal.identity.role is Role.AI_AGENT:
            return _reject(
                RejectionCode.PRECEDENCE_VIOLATION,
                "an AI agent session may not issue an emergency stop; a stop is a human "
                "judgement about physical safety",
                zone_id,
                Outcome.REJECTED_SCOPE,
            )

        if ctx.principal.operator_id != issuer.operator_id:
            return _reject(
                RejectionCode.SIGNATURE_INVALID,
                "the authenticated session does not match the authorization's issuer",
                zone_id,
                Outcome.REJECTED_SIGNATURE,
            )

        # 2 -- signature. The one check a stop cannot skip: without it the endpoint is a
        # fleet-wide denial-of-service primitive.
        verdict = self._verifier.verify_emergency_stop(
            request.authorization, incident_zone_id=zone_id
        )
        if not verdict.valid:
            return _reject(
                RejectionCode.SIGNATURE_INVALID,
                verdict.detail,
                zone_id,
                Outcome.REJECTED_SIGNATURE,
            )

        # 3 -- zone scope, after the signature so the endpoint is not a zone enumerator.
        if zone_id not in ctx.principal.identity.authorized_zone_ids:
            return _reject(
                RejectionCode.NOT_AUTHORIZED_FOR_ZONE,
                f"operator is not scoped to incident zone {zone_id!r}",
                zone_id,
                Outcome.REJECTED_SCOPE,
            )

        # 4 -- broadcast. No policy-engine call; see the module docstring.
        targets: tuple[str, ...]
        if request.scope is EmergencyStopScope.SINGLE_DRONE and request.drone_id:
            targets = (request.drone_id,)
            scope = StopScope.SINGLE_DRONE
        else:
            targets = tuple(d.drone_id for d in self._fleet.airborne_in_zone(zone_id))
            scope = StopScope.ZONE

        stop = EmergencyStop(
            stop_id=new_stop_id(),
            scope=scope,
            incident_zone_id=zone_id,
            reason=StopReason.OPERATOR_JUDGEMENT,
            issued_by_operator_id=ctx.principal.operator_id,
            issued_by_role=Role(ctx.principal.role_value),
            issued_utc=ctx.now,
            drone_id=request.drone_id if scope is StopScope.SINGLE_DRONE else None,
        )
        result = self._service.broadcast(
            stop, targets, session_id=ctx.principal.session_id, payload=ctx.raw_payload
        )

        # A stop with nothing airborne to stop is a success, not a failure: the zone is
        # already clear, which is the outcome the operator wanted.
        return ToolOutcome(
            response=RequestEmergencyStopResponse(
                broadcast=True,
                incident_zone_id=zone_id,
                affected_drone_ids=result.delivered,
                broadcast_utc=result.broadcast_utc,
                channel="independent-broadcast",
                rejection=None,
            ),
            audit_outcome=Outcome.ACCEPTED if result.complete else Outcome.ERROR,
            reason_codes=() if result.complete else ("emergency_stop_partial_delivery",),
            detail=(
                f"stop broadcast to {len(result.delivered)}/{len(result.attempted)} "
                f"airborne drones over {result.channel}"
                + (
                    f"; NOT DELIVERED to {list(result.undelivered)}"
                    if result.undelivered
                    else ""
                )
            ),
            decision={"stop": stop.to_dict(), "broadcast": result.to_dict()},
        )
