"""``get_fleet_status`` -- read-only fleet query.

Master Plan §5: *"read-only query of drone availability, battery, and maintenance state,
needed before any dispatch decision can be sanity-checked by a human."*

Read-only, and never a gate
---------------------------
This tool answers questions. It reserves nothing, dispatches nothing, and its answer is
never treated as an authorization by anything downstream -- `deploy_recon_waypoint` takes
its own fleet snapshot at decision time rather than trusting one a caller fetched
earlier. A fleet view is a picture, and a picture goes stale.

Field-level scoping
-------------------
Zero-Trust §2.2 requires field-level authorization on read paths, not only write paths:
*"a user authorized to view a resource is not automatically authorized to view every
field on it."* So the response is scoped to the caller's incident zone, and an agent
session sees availability without the maintenance narrative -- it needs to know whether
it can propose a mission, not why an airframe is in the shop.
"""

from __future__ import annotations

from fleet_manager import FleetRegistry, FleetScheduler
from mcp_server.audit import Outcome
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.identity import Role
from mcp_server.schemas.tools import (
    DroneState as SchemaDroneState,
)
from mcp_server.schemas.tools import (
    DroneStatus,
    GetFleetStatusRequest,
    GetFleetStatusResponse,
    ToolName,
)
from mcp_server.tools.base import CallContext, ToolOutcome

__all__ = ["GetFleetStatusHandler"]


class GetFleetStatusHandler:
    """Projects the fleet registry into the tool's response schema."""

    name: ToolName = ToolName.GET_FLEET_STATUS
    request_model: type[StrictModel] = GetFleetStatusRequest

    def __init__(
        self,
        *,
        registry: FleetRegistry,
        scheduler: FleetScheduler | None = None,
    ) -> None:
        self._registry = registry
        self._scheduler = scheduler

    def handle(self, request: GetFleetStatusRequest, ctx: CallContext) -> ToolOutcome:
        now = ctx.now
        drones = self._registry.all_drones()

        if request.incident_zone_id is not None:
            if request.incident_zone_id not in ctx.principal.identity.authorized_zone_ids:
                return ToolOutcome(
                    response=GetFleetStatusResponse(drones=(), queried_utc=now),
                    audit_outcome=Outcome.REJECTED_SCOPE,
                    reason_codes=("not_authorized_for_zone",),
                    detail="caller is not scoped to the requested incident zone",
                )
            drones = tuple(
                d for d in drones if d.home_zone_id in (None, request.incident_zone_id)
            )

        statuses: list[DroneStatus] = []
        for drone in drones:
            available = drone.is_available(now)
            if not available and not request.include_unavailable:
                continue
            statuses.append(
                DroneStatus(
                    drone_id=drone.drone_id,
                    state=SchemaDroneState(drone.state.value),
                    battery_pct=drone.battery_pct,
                    available=available,
                    airframe_type=drone.airframe_type,
                    maintenance_grounded=drone.maintenance_grounded,
                    link_quality_pct=drone.link_quality_pct,
                    current_mission_id=drone.current_mission_id,
                )
            )

        decision: dict[str, object] = {
            "total": len(statuses),
            "available": sum(1 for s in statuses if s.available),
        }
        # The scheduler view is operational context for a human deciding what to do
        # next. An agent gets availability only: queue depth and preemption candidates
        # are decisions for the command room, and showing them to a proposer invites it
        # to argue about them.
        if self._scheduler is not None and ctx.principal.identity.role is not Role.AI_AGENT:
            decision["scheduler"] = self._scheduler.status()

        return ToolOutcome(
            response=GetFleetStatusResponse(drones=tuple(statuses), queried_utc=now),
            audit_outcome=Outcome.ACCEPTED,
            detail=f"{decision['available']}/{len(statuses)} drones available",
            decision=decision,
        )
