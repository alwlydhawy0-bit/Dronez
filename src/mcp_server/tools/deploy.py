"""``deploy_recon_waypoint`` -- propose a flight plan.

What "deploy" does and does not mean
------------------------------------
Despite the name, a successful call **stages** a plan. Nothing flies. Master Plan §3
puts human confirmation between the proposal and dispatch, and §5 gives that step its
own tool. The name is the one in the tool contract, so it stays; the behaviour is
governed by the plan, not the verb.

The chain, in order
-------------------
1. **Mission → incident zone.** Resolved server-side. A request cannot supply its own
   authorization envelope.
2. **Airspace clearance, called internally.** The handler calls the clearance path
   itself rather than accepting a clearance from the caller. A caller-supplied
   clearance is a caller-supplied authorization, and Master Plan §5 requires a
   *current* affirmative clearance obtained at dispatch time.
3. **Fleet snapshot.** Server-derived availability and endurance.
4. **Policy engine.** The deterministic gate re-derives containment, envelope bounds,
   clearance validity and precedence from raw facts.
5. **Stage.** Only on `allow`, with a digest binding the plan to what was authorized.

Steps 2-4 all deny independently. Step 2 is not an optimisation that can be skipped
when the policy would catch it anyway: the policy validates *a clearance*, and if none
was obtained there is nothing to validate, which is itself a denial.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from dronez.airspace.client import ClearanceDecision
from dronez.authz import Role
from dronez.safety.envelope import ENVELOPE
from mcp_server.audit import Outcome
from mcp_server.feed import LiveAirspaceFeed, SyncStatus
from mcp_server.precedence import PrecedenceArbiter
from mcp_server.repositories import FleetProvider, MissionRegistry
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.tools import (
    DeployReconWaypointRequest,
    DeployReconWaypointResponse,
    RejectionCode,
    ToolName,
    ToolRejection,
)
from mcp_server.store import FlightPlanStore, StagedFlightPlan, compute_plan_digest
from mcp_server.tools.base import CallContext, ToolOutcome
from policy_engine import PolicyEngine, PolicyPath, build_deploy_recon_waypoint_input

__all__ = ["DeployReconWaypointHandler"]

#: Policy denial codes mapped onto the tool's rejection vocabulary. An unmapped code
#: falls through to ENVELOPE_VIOLATION rather than being reported as success.
_POLICY_CODE_MAP = {
    "outside_incident_zone": RejectionCode.OUTSIDE_INCIDENT_ZONE,
    "zone_inactive": RejectionCode.ZONE_INACTIVE,
    "not_authorized_for_zone": RejectionCode.NOT_AUTHORIZED_FOR_ZONE,
    "envelope_violation": RejectionCode.ENVELOPE_VIOLATION,
    "zone_altitude_violation": RejectionCode.ENVELOPE_VIOLATION,
    "altitude_band_inverted": RejectionCode.ENVELOPE_VIOLATION,
    "clearance_invalid": RejectionCode.CLEARANCE_MISSING,
    "airspace_conflict": RejectionCode.AIRSPACE_DENIED,
    "pattern_not_allowed": RejectionCode.SCHEMA_INVALID,
    "prohibited_capability": RejectionCode.SCHEMA_INVALID,
    "precedence_violation": RejectionCode.PRECEDENCE_VIOLATION,
    "unknown_role": RejectionCode.NOT_AUTHORIZED_FOR_ZONE,
    "fleet_unavailable": RejectionCode.FLEET_UNAVAILABLE,
    "insufficient_battery_range": RejectionCode.INSUFFICIENT_BATTERY_RANGE,
    "malformed_input": RejectionCode.SCHEMA_INVALID,
    "policy_engine_unavailable": RejectionCode.POLICY_ENGINE_UNAVAILABLE,
    "policy_undefined": RejectionCode.POLICY_ENGINE_UNAVAILABLE,
    "policy_malformed": RejectionCode.POLICY_ENGINE_UNAVAILABLE,
    "policy_engine_error": RejectionCode.POLICY_ENGINE_UNAVAILABLE,
    "policy_incoherent": RejectionCode.POLICY_ENGINE_UNAVAILABLE,
}


def _reject(
    code: RejectionCode,
    detail: str,
    outcome: Outcome,
    *,
    offending: tuple[str, ...] = (),
    reason_codes: tuple[str, ...] = (),
    decision: dict[str, Any] | None = None,
) -> ToolOutcome:
    return ToolOutcome(
        response=DeployReconWaypointResponse(
            accepted=False,
            rejection=ToolRejection(code=code, detail=detail[:512], offending_ids=offending),
        ),
        audit_outcome=outcome,
        reason_codes=reason_codes or (code.value,),
        detail=detail[:512],
        decision=decision or {},
    )


class DeployReconWaypointHandler:
    """Validates, authorizes, and stages a reconnaissance flight plan."""

    name: ToolName = ToolName.DEPLOY_RECON_WAYPOINT
    request_model: type[StrictModel] = DeployReconWaypointRequest

    def __init__(
        self,
        *,
        feed: LiveAirspaceFeed,
        policy: PolicyEngine,
        missions: MissionRegistry,
        fleet: FleetProvider,
        store: FlightPlanStore,
        arbiter: PrecedenceArbiter | None = None,
        plan_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._feed = feed
        self._policy = policy
        self._missions = missions
        self._fleet = fleet
        self._store = store
        self._arbiter = arbiter
        self._plan_id = plan_id_factory or (lambda: f"FP-{uuid.uuid4().hex[:16]}")

    def handle(
        self, request: DeployReconWaypointRequest, ctx: CallContext
    ) -> ToolOutcome:
        # 0 -- precedence, before anything else.
        #
        # A Tier-3 agent naming a command to supersede is a security event, not a
        # scheduling conflict (Master Plan Sec.5). It is checked first so the violation
        # is recorded even when the request would have failed later for some mundane
        # reason -- an attacker should not be able to hide a probe behind a bad polygon.
        if request.supersedes_command_id and ctx.principal.identity.role is Role.AI_AGENT:
            if self._arbiter is not None:
                self._arbiter.report_supersession_attempt(
                    principal=ctx.principal,
                    superseded_command_id=request.supersedes_command_id,
                    tool=self.name.value,
                    payload=ctx.raw_payload,
                )
            return _reject(
                RejectionCode.PRECEDENCE_VIOLATION,
                "a Tier 3 agent proposal may not supersede a command; an agent holds no "
                "override authority over any tier. This attempt has been recorded as a "
                "security event.",
                Outcome.SECURITY_VIOLATION,
                offending=(request.supersedes_command_id,),
                reason_codes=("agent_supersession_attempt",),
            )

        # 1 -- resolve the authorization envelope, server-side.
        binding = self._missions.binding_for(request.mission_id)
        if binding is None:
            return _reject(
                RejectionCode.ZONE_INACTIVE,
                f"mission {request.mission_id!r} is not bound to an active incident zone",
                Outcome.REJECTED_POLICY,
            )
        zone = binding.incident_zone

        # Scope check before doing expensive work. The policy re-checks this; doing it
        # here too means an unscoped caller cannot use the tool to probe feed state.
        if not zone.is_active_at(ctx.now):
            return _reject(
                RejectionCode.ZONE_INACTIVE,
                "the incident zone is not active at this instant",
                Outcome.REJECTED_POLICY,
            )
        if ctx.principal.operator_id not in zone.authorized_operator_ids:
            return _reject(
                RejectionCode.NOT_AUTHORIZED_FOR_ZONE,
                f"operator is not scoped to incident zone {zone.incident_zone_id!r}",
                Outcome.REJECTED_SCOPE,
            )

        # 2 -- airspace clearance, obtained here and now. Never supplied by the caller.
        clearance, sync = self._feed.check_clearance(
            request.polygon.to_core(),
            request.altitude_min_m_agl,
            request.altitude_max_m_agl,
        )
        if not clearance.cleared:
            detail = clearance.detail
            if sync.status is SyncStatus.FAILED:
                detail = f"{detail} (feed refresh failed: {sync.detail})"
            return _reject(
                RejectionCode.AIRSPACE_DENIED
                if clearance.blocking_zone_ids
                else RejectionCode.CLEARANCE_STALE,
                detail,
                Outcome.REJECTED_CLEARANCE,
                offending=clearance.blocking_zone_ids,
                reason_codes=(clearance.reason.value,),
                decision={
                    "clearance": clearance.to_audit_record(),
                    "sync_status": sync.status.value,
                },
            )

        # 3 -- fleet facts, server-derived.
        required_endurance = request.duration_s * ENVELOPE.battery_range_reserve_factor
        fleet = self._fleet.snapshot(
            incident_zone_id=zone.incident_zone_id,
            required_endurance_s=required_endurance,
        )

        # 4 -- the deterministic gate.
        document = build_deploy_recon_waypoint_input(
            request=request,
            principal=ctx.principal.identity,
            incident_zone=zone,
            clearance=clearance,
            fleet=fleet,
            now=ctx.now,
            cleared_polygon=request.polygon,
            cleared_altitude_min_m_agl=request.altitude_min_m_agl,
            cleared_altitude_max_m_agl=request.altitude_max_m_agl,
            # Defence in depth: step 0 already refused a Tier-3 supersession, and the
            # Rego refuses it independently. A regression in either still denies.
            supersedes_command_id=request.supersedes_command_id,
        )
        decision = self._policy.evaluate(PolicyPath.DEPLOY_RECON_WAYPOINT, document)

        if not decision.allowed:
            first = decision.codes[0] if decision.codes else "policy_denied"
            code = _POLICY_CODE_MAP.get(first, RejectionCode.ENVELOPE_VIOLATION)
            detail = "; ".join(r.detail for r in decision.reasons)[:512]
            return _reject(
                code,
                detail or "the policy engine denied this proposal",
                Outcome.REJECTED_POLICY,
                reason_codes=decision.codes,
                decision=decision.audit_record(),
            )

        # 5 -- stage. The plan is authorized; it is not dispatched.
        return self._stage(request, ctx, zone.incident_zone_id, fleet, clearance, decision)

    def _stage(
        self,
        request: DeployReconWaypointRequest,
        ctx: CallContext,
        incident_zone_id: str,
        fleet: object,
        clearance: ClearanceDecision,
        decision: object,
    ) -> ToolOutcome:
        flight_plan_id = self._plan_id()
        assigned = getattr(fleet, "candidate_drone_id", None)
        digest = compute_plan_digest(
            flight_plan_id=flight_plan_id,
            request=request,
            incident_zone_id=incident_zone_id,
            assigned_drone_id=assigned,
            clearance_expires_utc=clearance.expires_utc,
        )
        plan = StagedFlightPlan(
            flight_plan_id=flight_plan_id,
            digest=digest,
            request=request,
            incident_zone_id=incident_zone_id,
            assigned_drone_id=assigned,
            proposed_by_operator_id=ctx.principal.operator_id,
            proposed_by_role=ctx.principal.role_value,
            staged_utc=ctx.now,
            # The plan dies with its clearance. A staged plan that outlived the
            # clearance it was authorized against would be a stale authorization.
            expires_utc=clearance.expires_utc,
            policy_version=getattr(decision, "policy_version", ""),
        )

        if not self._store.stage(plan):
            return _reject(
                RejectionCode.INTERNAL_ERROR,
                "could not stage the flight plan; the staging store is full",
                Outcome.ERROR,
            )

        return ToolOutcome(
            response=DeployReconWaypointResponse(
                accepted=True,
                flight_plan_id=flight_plan_id,
                flight_plan_digest=digest,
                assigned_drone_id=assigned,
                clearance_expires_utc=clearance.expires_utc,
                requires_confirmation=True,
            ),
            audit_outcome=Outcome.STAGED,
            reason_codes=(),
            detail="plan staged awaiting human confirmation",
            decision={
                "flight_plan_id": flight_plan_id,
                "digest": digest,
                "assigned_drone_id": assigned,
                "policy_version": getattr(decision, "policy_version", ""),
                "clearance": clearance.to_audit_record(),
            },
        )
