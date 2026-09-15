"""Input and output schemas for every MCP tool.

This module is the **complete tool catalogue**. Zero-Trust §4.2 (*Least-Privilege
Tool Scoping*) requires that the tool definitions exposed to a model be the minimum
needed for the task rather than the full catalogue, and §11.1 makes *"a
tool-permission scope broader than the minimum documented for the feature"* a
release-blocking finding. Keeping every tool in one registry is what makes that
auditable: :data:`TOOL_REGISTRY` is the set a scope is checked against.

Two rules govern everything here.

**Bounds come from the safety envelope, never from a literal.** Every altitude and
velocity limit is derived from :data:`dronez.safety.envelope.ENVELOPE`, so changing
a constant moves the schema with it and cannot leave a stale literal behind. The
envelope digest test then forces that change through project memory.

**Rejections are structured, never partial.** Master Plan §5: *"Any validation
failure returns a structured rejection (never a partial/best-effort flight plan)."*
There is no response type in this module that can represent "mostly approved".
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from dronez.safety.envelope import ENVELOPE
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.geo import GeoPolygon
from mcp_server.schemas.identity import SignedCommandEnvelope

__all__ = [
    "TOOL_REGISTRY",
    "TOOL_SCHEMA_VERSIONS",
    "CheckAirspaceClearanceRequest",
    "CheckAirspaceClearanceResponse",
    "ConfirmDecision",
    "ConfirmFlightPlanRequest",
    "ConfirmFlightPlanResponse",
    "DeployReconWaypointRequest",
    "DeployReconWaypointResponse",
    "DetectionMode",
    "DroneState",
    "DroneStatus",
    "EmergencyStopScope",
    "ExecuteSafeReturnRequest",
    "ExecuteSafeReturnResponse",
    "GetFleetStatusRequest",
    "GetFleetStatusResponse",
    "PatternType",
    "RejectionCode",
    "RequestEmergencyStopRequest",
    "RequestEmergencyStopResponse",
    "SafeReturnTrigger",
    "StreamQuality",
    "StreamThermalFeedRequest",
    "StreamThermalFeedResponse",
    "ToolName",
    "ToolRejection",
]

# --------------------------------------------------------------------------- #
# Shared identifier and measurement types
# --------------------------------------------------------------------------- #

_ID = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
MissionId = Annotated[str, _ID]
DroneId = Annotated[str, _ID]
FlightPlanId = Annotated[str, _ID]
IncidentZoneId = Annotated[str, _ID]

#: Altitude in metres above ground level, bounded by the platform envelope at the
#: type level. A request outside these bounds cannot be constructed, so the policy
#: engine never sees one -- defence in depth, not a substitute for the policy check.
AltitudeAgl = Annotated[
    float,
    Field(ge=ENVELOPE.altitude_min_agl_m, le=ENVELOPE.altitude_max_agl_m),
]
GroundSpeed = Annotated[float, Field(gt=0.0, le=ENVELOPE.ground_speed_max_mps)]

#: SHA-256 hex digest. Used to bind a human confirmation to the exact plan reviewed.
Sha256Hex = Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]


class ToolName(StrEnum):
    """Every tool this server exposes. There are no others."""

    DEPLOY_RECON_WAYPOINT = "deploy_recon_waypoint"
    STREAM_THERMAL_FEED = "stream_thermal_feed"
    EXECUTE_SAFE_RETURN = "execute_safe_return"
    CHECK_AIRSPACE_CLEARANCE = "check_airspace_clearance"
    CONFIRM_FLIGHT_PLAN = "confirm_flight_plan"
    GET_FLEET_STATUS = "get_fleet_status"
    REQUEST_EMERGENCY_STOP = "request_emergency_stop"


class RejectionCode(StrEnum):
    """Machine-readable rejection reasons, logged on every rejected call."""

    SCHEMA_INVALID = "schema_invalid"
    RATE_LIMITED = "rate_limited"
    SANITIZER_BLOCKED = "sanitizer_blocked"
    SANITIZER_UNAVAILABLE = "sanitizer_unavailable"
    SIGNATURE_MISSING = "signature_missing"
    SIGNATURE_INVALID = "signature_invalid"
    SIGNATURE_EXPIRED = "signature_expired"
    NONCE_REPLAYED = "nonce_replayed"
    NOT_AUTHORIZED_FOR_ZONE = "not_authorized_for_zone"
    PRECEDENCE_VIOLATION = "precedence_violation"
    ZONE_INACTIVE = "zone_inactive"
    OUTSIDE_INCIDENT_ZONE = "outside_incident_zone"
    ENVELOPE_VIOLATION = "envelope_violation"
    AIRSPACE_DENIED = "airspace_denied"
    CLEARANCE_STALE = "clearance_stale"
    CLEARANCE_MISSING = "clearance_missing"
    FLEET_UNAVAILABLE = "fleet_unavailable"
    INSUFFICIENT_BATTERY_RANGE = "insufficient_battery_range"
    PLAN_DIGEST_MISMATCH = "plan_digest_mismatch"
    CONFIRMATION_REQUIRED = "confirmation_required"
    POLICY_ENGINE_UNAVAILABLE = "policy_engine_unavailable"
    #: The plan was fully authorized but the hardware dispatch seam refused it. Distinct
    #: from an internal error: nothing went wrong, the gate is deliberately shut.
    DISPATCH_GATE_CLOSED = "dispatch_gate_closed"
    INTERNAL_ERROR = "internal_error"


class ToolRejection(StrictModel):
    """The only shape a failed tool call may return.

    Note what is absent: there is no field for a partial result, a "best effort"
    plan, or a suggested relaxation. A caller that wants a different answer must
    submit a different request.
    """

    code: RejectionCode
    detail: Annotated[str, Field(max_length=512)]
    #: Correlates with the append-only ``Command`` record for this attempt.
    command_record_id: Annotated[str | None, Field(max_length=64)] = None
    #: Populated where the rejection names specific offending entities, e.g. the
    #: blocking airspace zone IDs.
    offending_ids: Annotated[tuple[str, ...], Field(max_length=64)] = ()


# --------------------------------------------------------------------------- #
# 1. deploy_recon_waypoint
# --------------------------------------------------------------------------- #

class PatternType(StrEnum):
    """Permitted flight patterns.

    Closed by design. Master Plan §5: *"no freeform arbitrary path from raw agent
    output."* An agent can choose among reviewed patterns; it cannot describe a
    novel trajectory.
    """

    PERIMETER_SWEEP = "perimeter_sweep"
    GRID = "grid"
    ORBIT = "orbit"


class DeployReconWaypointRequest(StrictModel):
    """Propose a reconnaissance flight plan inside an authorized incident zone.

    Being able to construct this object means the request is *well-formed*. It does
    not mean the plan is authorized: containment against the ``IncidentZone``, live
    airspace clearance, fleet availability and battery-range sufficiency are all
    decided by the policy engine, which this schema deliberately does not duplicate.
    """

    mission_id: MissionId
    polygon: GeoPolygon
    altitude_min_m_agl: AltitudeAgl
    altitude_max_m_agl: AltitudeAgl
    velocity_max_mps: GroundSpeed
    pattern_type: PatternType
    #: Requested time-box. Bounded by the mission duration limit; the incident zone's
    #: own window narrows it further at the policy layer.
    duration_s: Annotated[float, Field(gt=0.0, le=ENVELOPE.mission_duration_max_s)]
    #: Optional preferred airframe. A preference only -- the scheduler may override it,
    #: and naming a drone never bypasses the availability check.
    preferred_drone_id: DroneId | None = None
    #: Identifier of a command this proposal replaces, when the caller holds override
    #: authority over it.
    #:
    #: Declared deliberately rather than left as an undeclared field. If a Tier-3 agent
    #: could not *express* a supersession, its attempt would be rejected as a generic
    #: schema error and the signal would be lost. Making it expressible is what lets
    #: the precedence gate classify it as a security violation (Master Plan §5).
    supersedes_command_id: Annotated[str | None, Field(max_length=64)] = None

    @model_validator(mode="after")
    def _altitude_band_is_ordered(self) -> Self:
        if self.altitude_min_m_agl >= self.altitude_max_m_agl:
            raise ValueError("altitude_min_m_agl must be strictly below altitude_max_m_agl")
        return self


class DeployReconWaypointResponse(StrictModel):
    """Result of a proposal.

    ``accepted=True`` means the plan passed the policy gate and is **staged awaiting
    human confirmation** -- it does not mean anything is flying. Dispatch happens only
    after :class:`ConfirmFlightPlanRequest`.
    """

    accepted: bool
    flight_plan_id: FlightPlanId | None = None
    #: Digest of the canonical staged plan. The operator confirms *this* digest, which
    #: is what stops a plan being altered between review and dispatch.
    flight_plan_digest: Sha256Hex | None = None
    assigned_drone_id: DroneId | None = None
    clearance_expires_utc: datetime | None = None
    requires_confirmation: bool = True
    rejection: ToolRejection | None = None

    @model_validator(mode="after")
    def _outcome_is_unambiguous(self) -> Self:
        if self.accepted:
            if self.rejection is not None:
                raise ValueError("an accepted proposal must not carry a rejection")
            if not (self.flight_plan_id and self.flight_plan_digest):
                raise ValueError(
                    "an accepted proposal must carry a flight_plan_id and its digest"
                )
            if not self.requires_confirmation:
                raise ValueError(
                    "a staged plan always requires explicit human confirmation "
                    "(Master Plan Sec.5 confirm_flight_plan)"
                )
        else:
            if self.rejection is None:
                raise ValueError("a rejected proposal must carry a structured rejection")
            if self.flight_plan_id or self.flight_plan_digest or self.assigned_drone_id:
                raise ValueError(
                    "a rejected proposal must not carry a partial plan; rejections are "
                    "structured and total, never best-effort"
                )
        return self


# --------------------------------------------------------------------------- #
# 2. stream_thermal_feed
# --------------------------------------------------------------------------- #

class StreamQuality(StrEnum):
    """Bandwidth-adaptive tier."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ADAPTIVE = "adaptive"


class DetectionMode(StrEnum):
    PASSIVE_STREAM = "passive_stream"
    ACTIVE_OBJECT_DETECTION = "active_object_detection"


class StreamThermalFeedRequest(StrictModel):
    mission_id: MissionId
    drone_id: DroneId
    stream_quality: StreamQuality
    detection_mode: DetectionMode


class StreamThermalFeedResponse(StrictModel):
    """Signaling result for a thermal/optical stream.

    Master Plan §5 makes the transport non-negotiable: the WebRTC pipeline is
    encrypted end-to-end with DTLS 1.3 / SRTP, and *"the stream is rejected at the
    signaling layer if a client cannot negotiate it."* The literal types below
    encode that -- a response asserting a weaker transport cannot be constructed.
    """

    accepted: bool
    session_id: Annotated[str | None, Field(max_length=128)] = None
    #: Time-boxed to the mission window and revoked on mission close or zone expiry.
    expires_utc: datetime | None = None
    transport: Literal["dtls1.3-srtp"] | None = None
    #: Per-frame hashing happens on the edge hardware *before* transmission, so
    #: evidentiary integrity does not depend on trusting the network path.
    frame_hash_algorithm: Literal["sha256-edge"] | None = None
    rejection: ToolRejection | None = None

    @model_validator(mode="after")
    def _accepted_streams_are_encrypted(self) -> Self:
        if self.accepted:
            if self.rejection is not None:
                raise ValueError("an accepted stream must not carry a rejection")
            if self.transport != "dtls1.3-srtp" or self.frame_hash_algorithm != "sha256-edge":
                raise ValueError(
                    "an accepted stream must declare DTLS 1.3/SRTP transport and "
                    "edge-side frame hashing; both are mandatory"
                )
            if self.session_id is None or self.expires_utc is None:
                raise ValueError("an accepted stream must be identified and time-boxed")
        elif self.rejection is None:
            raise ValueError("a rejected stream must carry a structured rejection")
        return self


# --------------------------------------------------------------------------- #
# 3. execute_safe_return
# --------------------------------------------------------------------------- #

class SafeReturnTrigger(StrEnum):
    """Why an RTL is being requested.

    ``DEGRADED_VISUAL_INERTIAL_LANDING`` is deliberately **absent**. Master Plan §5:
    it *"is not a trigger_reason of this tool -- it is a lower-level firmware path
    that preempts execute_safe_return entirely."* Adding it here would imply the
    server can request it, which would invert the control relationship.
    """

    LOW_BATTERY = "low_battery"
    SIGNAL_LOSS = "signal_loss"
    JAMMING_DETECTED = "jamming_detected"
    GEOFENCE_BREACH = "geofence_breach"
    MANUAL_OVERRIDE = "manual_override"
    EMERGENCY_STOP_BROADCAST = "emergency_stop_broadcast"


class ExecuteSafeReturnRequest(StrictModel):
    """Request an RTL.

    This tool is unusual and the asymmetry is the point: for the autonomous triggers
    the flight controller executes RTL **on its own, without waiting for this call**.
    The server-invoked path exists for operator-initiated returns and for logging. It
    is never the sole path by which RTL can occur, and the server must never attempt
    to countermand a firmware-initiated one (Zero-Trust §4.1).
    """

    drone_id: DroneId
    trigger_reason: SafeReturnTrigger
    mission_id: MissionId | None = None


class ExecuteSafeReturnResponse(StrictModel):
    acknowledged: bool
    drone_id: DroneId
    #: True when the airframe had already begun RTL autonomously. This is a normal,
    #: expected outcome -- not an error -- and the server records it rather than
    #: attempting to re-issue or override the command.
    already_autonomous: bool = False
    rejection: ToolRejection | None = None

    @model_validator(mode="after")
    def _outcome_is_unambiguous(self) -> Self:
        if self.acknowledged and self.rejection is not None:
            raise ValueError("an acknowledged return must not carry a rejection")
        if not self.acknowledged and self.rejection is None:
            raise ValueError("an unacknowledged return must carry a structured rejection")
        return self


# --------------------------------------------------------------------------- #
# 4. check_airspace_clearance
# --------------------------------------------------------------------------- #

class CheckAirspaceClearanceRequest(StrictModel):
    """The mandatory pre-dispatch airspace gate (Master Plan §5)."""

    mission_id: MissionId
    polygon: GeoPolygon
    altitude_min_m_agl: AltitudeAgl
    altitude_max_m_agl: AltitudeAgl

    @model_validator(mode="after")
    def _altitude_band_is_ordered(self) -> Self:
        if self.altitude_min_m_agl >= self.altitude_max_m_agl:
            raise ValueError("altitude_min_m_agl must be strictly below altitude_max_m_agl")
        return self


class CheckAirspaceClearanceResponse(StrictModel):
    """Binding clearance decision.

    Mirrors :class:`dronez.airspace.client.ClearanceDecision` at the MCP boundary.
    ``cleared=True`` requires an explicit ``expires_utc``: a clearance without an
    expiry could be minted early and replayed at dispatch, which is exactly the gap
    the validity window exists to close.
    """

    cleared: bool
    reason: Annotated[str, Field(max_length=64)]
    detail: Annotated[str, Field(max_length=512)]
    evaluated_utc: datetime
    expires_utc: datetime | None = None
    blocking_zone_ids: Annotated[tuple[str, ...], Field(max_length=256)] = ()
    advisory_zone_ids: Annotated[tuple[str, ...], Field(max_length=256)] = ()
    feed_authority: Annotated[str | None, Field(max_length=64)] = None
    feed_sequence: int | None = None
    feed_age_s: float | None = None

    @model_validator(mode="after")
    def _clearance_is_time_boxed_and_conflict_free(self) -> Self:
        if self.cleared:
            if self.expires_utc is None:
                raise ValueError("an affirmative clearance must carry an expiry")
            if self.expires_utc <= self.evaluated_utc:
                raise ValueError("clearance expiry must be after evaluation time")
            if self.blocking_zone_ids:
                raise ValueError(
                    "a clearance cannot be affirmative while naming blocking zones"
                )
        return self


# --------------------------------------------------------------------------- #
# 5. confirm_flight_plan
# --------------------------------------------------------------------------- #

class ConfirmDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ConfirmFlightPlanRequest(StrictModel):
    """The explicit human authorization step.

    Master Plan §5 calls this out specifically: without a dedicated tool,
    *"confirmation risks being implemented as an implicit UI-only step with no
    server-side enforcement."*

    Two properties make it real rather than ceremonial:

    * **It requires a signed envelope.** :class:`SignedCommandEnvelope` cannot be
      constructed by an AI agent, so a Tier-3 identity structurally cannot confirm
      its own proposal.
    * **It binds to a digest.** The operator approves ``flight_plan_digest``, not
      just an ID. If the staged plan changed after it was rendered for review, the
      digest no longer matches and the confirmation is refused -- closing the TOCTOU
      window between "operator read the map overlay" and "server dispatched a plan".
    """

    flight_plan_id: FlightPlanId
    flight_plan_digest: Sha256Hex
    decision: ConfirmDecision
    authorization: SignedCommandEnvelope
    #: Operator's note, retained in the audit record. Never interpreted as an instruction.
    note: Annotated[str, Field(max_length=512)] = ""


class ConfirmFlightPlanResponse(StrictModel):
    flight_plan_id: FlightPlanId
    decision: ConfirmDecision
    dispatched: bool
    confirmed_by_operator_id: Annotated[str | None, Field(max_length=64)] = None
    confirmed_utc: datetime | None = None
    rejection: ToolRejection | None = None

    @model_validator(mode="after")
    def _only_approvals_dispatch(self) -> Self:
        if self.dispatched:
            if self.decision is not ConfirmDecision.APPROVE:
                raise ValueError("a plan may only be dispatched on an APPROVE decision")
            if self.rejection is not None:
                raise ValueError("a dispatched plan must not carry a rejection")
            if not (self.confirmed_by_operator_id and self.confirmed_utc):
                raise ValueError(
                    "a dispatched plan must record which operator confirmed it and when"
                )
        return self


# --------------------------------------------------------------------------- #
# 6. get_fleet_status
# --------------------------------------------------------------------------- #

class DroneState(StrEnum):
    """Mission state machine (Master Plan §4).

    ``DEGRADED_VISUAL_INERTIAL_LANDING`` appears here as an *observable* sub-state of
    ``FAILSAFE`` -- the command room must be able to see it. That is distinct from it
    being requestable, which it is not: see :class:`SafeReturnTrigger`.
    """

    IDLE = "idle"
    PRE_FLIGHT_CHECK = "pre_flight_check"
    ARMED = "armed"
    IN_TRANSIT = "in_transit"
    ON_STATION = "on_station"
    RTL_TRIGGERED = "rtl_triggered"
    LANDING = "landing"
    POST_FLIGHT = "post_flight"
    MAINTENANCE = "maintenance"
    FAILSAFE = "failsafe"
    LOST_LINK = "lost_link"
    DEGRADED_VISUAL_INERTIAL_LANDING = "degraded_visual_inertial_landing"


class GetFleetStatusRequest(StrictModel):
    """Read-only fleet query. Never a dispatch gate."""

    incident_zone_id: IncidentZoneId | None = None
    include_unavailable: bool = True


class DroneStatus(StrictModel):
    drone_id: DroneId
    state: DroneState
    battery_pct: Annotated[float, Field(ge=0.0, le=100.0)]
    #: False whenever maintenance, battery, or state rules out dispatch. Computed
    #: server-side from the fields below -- never accepted from a caller.
    available: bool
    airframe_type: Annotated[str, Field(max_length=64)]
    maintenance_grounded: bool = False
    link_quality_pct: Annotated[float | None, Field(ge=0.0, le=100.0)] = None
    current_mission_id: MissionId | None = None

    @model_validator(mode="after")
    def _availability_is_consistent(self) -> Self:
        if self.available:
            if self.maintenance_grounded:
                raise ValueError("a maintenance-grounded drone cannot be reported available")
            if self.battery_pct < ENVELOPE.battery_rtl_trigger_pct:
                raise ValueError(
                    f"a drone below the {ENVELOPE.battery_rtl_trigger_pct}% RTL trigger "
                    "cannot be reported available for dispatch"
                )
            if self.state not in (DroneState.IDLE, DroneState.POST_FLIGHT):
                raise ValueError(
                    f"a drone in state {self.state.value!r} is not available for dispatch"
                )
        return self


class GetFleetStatusResponse(StrictModel):
    drones: Annotated[tuple[DroneStatus, ...], Field(max_length=512)]
    queried_utc: datetime

    @property
    def available_drones(self) -> tuple[DroneStatus, ...]:
        return tuple(d for d in self.drones if d.available)


# --------------------------------------------------------------------------- #
# 7. request_emergency_stop
# --------------------------------------------------------------------------- #

class EmergencyStopScope(StrEnum):
    ZONE = "zone"
    SINGLE_DRONE = "single_drone"


class RequestEmergencyStopRequest(StrictModel):
    """Zone-wide broadcast kill switch.

    Master Plan §5: callable by any authenticated field leader physically in the
    affected zone **without command-room mediation**, and delivered over a channel
    independent of the primary mission command path.

    The independent channel is why this is modelled separately from
    :class:`ExecuteSafeReturnRequest` rather than as another trigger reason: if the
    primary path is what failed, a stop that travels down it is worth nothing.
    """

    scope: EmergencyStopScope
    incident_zone_id: IncidentZoneId
    drone_id: DroneId | None = None
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    authorization: SignedCommandEnvelope

    @model_validator(mode="after")
    def _scope_matches_target(self) -> Self:
        if self.scope is EmergencyStopScope.SINGLE_DRONE and self.drone_id is None:
            raise ValueError("a single-drone emergency stop must name the drone")
        if self.scope is EmergencyStopScope.ZONE and self.drone_id is not None:
            raise ValueError("a zone-wide emergency stop must not name a single drone")
        return self


class RequestEmergencyStopResponse(StrictModel):
    broadcast: bool
    incident_zone_id: IncidentZoneId
    affected_drone_ids: Annotated[tuple[str, ...], Field(max_length=512)] = ()
    broadcast_utc: datetime | None = None
    #: Confirms delivery went out of band. An emergency stop that only traversed the
    #: primary command path has not met its contract.
    channel: Literal["independent-broadcast"] | None = None
    rejection: ToolRejection | None = None

    @model_validator(mode="after")
    def _broadcast_uses_the_independent_channel(self) -> Self:
        if self.broadcast:
            if self.rejection is not None:
                raise ValueError("a completed broadcast must not carry a rejection")
            if self.channel != "independent-broadcast":
                raise ValueError(
                    "an emergency stop must be delivered over the independent channel"
                )
            if self.broadcast_utc is None:
                raise ValueError("a completed broadcast must record when it went out")
        elif self.rejection is None:
            raise ValueError("a failed broadcast must carry a structured rejection")
        return self


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

#: Name -> (request model, response model). The complete exposed surface.
TOOL_REGISTRY: dict[ToolName, tuple[type[StrictModel], type[StrictModel]]] = {
    ToolName.DEPLOY_RECON_WAYPOINT: (DeployReconWaypointRequest, DeployReconWaypointResponse),
    ToolName.STREAM_THERMAL_FEED: (StreamThermalFeedRequest, StreamThermalFeedResponse),
    ToolName.EXECUTE_SAFE_RETURN: (ExecuteSafeReturnRequest, ExecuteSafeReturnResponse),
    ToolName.CHECK_AIRSPACE_CLEARANCE: (
        CheckAirspaceClearanceRequest,
        CheckAirspaceClearanceResponse,
    ),
    ToolName.CONFIRM_FLIGHT_PLAN: (ConfirmFlightPlanRequest, ConfirmFlightPlanResponse),
    ToolName.GET_FLEET_STATUS: (GetFleetStatusRequest, GetFleetStatusResponse),
    ToolName.REQUEST_EMERGENCY_STOP: (
        RequestEmergencyStopRequest,
        RequestEmergencyStopResponse,
    ),
}

#: Per-tool contract versions, mirrored in ``CLAUDE.md`` §5.
TOOL_SCHEMA_VERSIONS: dict[ToolName, str] = {
    ToolName.DEPLOY_RECON_WAYPOINT: "deploy_recon_waypoint/1.0.0",
    ToolName.STREAM_THERMAL_FEED: "stream_thermal_feed/1.0.0",
    ToolName.EXECUTE_SAFE_RETURN: "execute_safe_return/1.0.0",
    ToolName.CHECK_AIRSPACE_CLEARANCE: "check_airspace_clearance/1.0.0",
    ToolName.CONFIRM_FLIGHT_PLAN: "confirm_flight_plan/1.0.0",
    ToolName.GET_FLEET_STATUS: "get_fleet_status/1.0.0",
    ToolName.REQUEST_EMERGENCY_STOP: "request_emergency_stop/1.0.0",
}

#: Tools an AI agent session may ever be scoped to propose. Read-only queries and
#: proposals only. The agent can never confirm a plan (that is the human gate) and
#: can never broadcast an emergency stop (that is a physically-present field leader's
#: authority). Zero-Trust §4.2 least-privilege tool scoping.
AGENT_PROPOSABLE_TOOLS: frozenset[ToolName] = frozenset({
    ToolName.DEPLOY_RECON_WAYPOINT,
    ToolName.CHECK_AIRSPACE_CLEARANCE,
    ToolName.GET_FLEET_STATUS,
    ToolName.STREAM_THERMAL_FEED,
})
