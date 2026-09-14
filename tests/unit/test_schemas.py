"""Strict-schema conformance for the MCP tool boundary.

Each test pins a rejection that must survive refactoring. A schema that accepts more
than it did yesterday is a security regression (Zero-Trust §3.1).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from dronez.safety.envelope import ENVELOPE, PROHIBITED_CAPABILITIES
from mcp_server.schemas import (
    AGENT_PROPOSABLE_TOOLS,
    TOOL_REGISTRY,
    TOOL_SCHEMA_VERSIONS,
    GeoPolygon,
    IncidentPriority,
    IncidentZone,
    IncidentZoneStatus,
    OperatorIdentity,
    Role,
    ToolName,
    can_override,
)
from mcp_server.schemas.identity import (
    CommandSignature,
    SignatureAlgorithm,
    SignedCommandEnvelope,
)
from mcp_server.schemas.tools import (
    CheckAirspaceClearanceResponse,
    ConfirmDecision,
    ConfirmFlightPlanResponse,
    DeployReconWaypointRequest,
    DeployReconWaypointResponse,
    DroneState,
    DroneStatus,
    EmergencyStopScope,
    PatternType,
    RejectionCode,
    RequestEmergencyStopResponse,
    StreamThermalFeedResponse,
    ToolRejection,
)

T0 = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)


def square(lon: float, lat: float, half: float) -> GeoPolygon:
    return GeoPolygon.from_rings([[
        [lon - half, lat - half], [lon + half, lat - half],
        [lon + half, lat + half], [lon - half, lat + half],
        [lon - half, lat - half],
    ]])


@pytest.fixture
def command_room() -> OperatorIdentity:
    return OperatorIdentity(
        operator_id="op-cr-001",
        role=Role.COMMAND_ROOM,
        fido2_credential_id="cred-cr-1",
        authorized_zone_ids=frozenset({"IZ-1"}),
    )


@pytest.fixture
def valid_deploy_request() -> DeployReconWaypointRequest:
    return DeployReconWaypointRequest(
        mission_id="M-001",
        polygon=square(46.5, 24.5, 0.01),
        altitude_min_m_agl=30.0,
        altitude_max_m_agl=100.0,
        velocity_max_mps=10.0,
        pattern_type=PatternType.GRID,
        duration_s=900.0,
    )


# --------------------------------------------------------------------------- #
# Closed-world validation
# --------------------------------------------------------------------------- #

def test_undeclared_field_is_rejected(valid_deploy_request: DeployReconWaypointRequest) -> None:
    """Mass-assignment block. An agent cannot append a field and hope it is honoured."""
    payload = valid_deploy_request.model_dump(mode="json")
    payload["skip_confirmation"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DeployReconWaypointRequest.parse_json(json.dumps(payload))


def test_string_is_not_coerced_to_a_number(
    valid_deploy_request: DeployReconWaypointRequest,
) -> None:
    payload = valid_deploy_request.model_dump(mode="json")
    payload["altitude_max_m_agl"] = "100"
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(json.dumps(payload))


def test_nan_altitude_is_rejected(valid_deploy_request: DeployReconWaypointRequest) -> None:
    """NaN defeats every comparison-based bound check: NaN > 120 is False."""
    payload = valid_deploy_request.model_dump(mode="json")
    payload["altitude_max_m_agl"] = float("nan")
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(json.dumps(payload))


def test_validated_request_is_immutable(
    valid_deploy_request: DeployReconWaypointRequest,
) -> None:
    """The object the gate approved must be the object that gets used."""
    with pytest.raises(ValidationError):
        valid_deploy_request.altitude_max_m_agl = 500.0  # type: ignore[misc]


@pytest.mark.parametrize(
    "field, value",
    [
        ("altitude_max_m_agl", ENVELOPE.altitude_max_agl_m + 0.1),
        ("altitude_min_m_agl", ENVELOPE.altitude_min_agl_m - 0.1),
        ("velocity_max_mps", ENVELOPE.ground_speed_max_mps + 0.1),
        ("velocity_max_mps", 0.0),
        ("duration_s", ENVELOPE.mission_duration_max_s + 1),
    ],
)
def test_envelope_bounds_are_enforced_at_the_type_level(
    valid_deploy_request: DeployReconWaypointRequest, field: str, value: float
) -> None:
    payload = valid_deploy_request.model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(json.dumps(payload))


def test_inverted_altitude_band_is_rejected(
    valid_deploy_request: DeployReconWaypointRequest,
) -> None:
    payload = valid_deploy_request.model_dump(mode="json")
    payload["altitude_min_m_agl"], payload["altitude_max_m_agl"] = 100.0, 30.0
    with pytest.raises(ValidationError, match="strictly below"):
        DeployReconWaypointRequest.parse_json(json.dumps(payload))


def test_freeform_pattern_is_rejected(
    valid_deploy_request: DeployReconWaypointRequest,
) -> None:
    """No freeform arbitrary path from raw agent output (Master Plan §5)."""
    payload = valid_deploy_request.model_dump(mode="json")
    payload["pattern_type"] = "freeform"
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(json.dumps(payload))


# --------------------------------------------------------------------------- #
# Structured rejections, never partial results
# --------------------------------------------------------------------------- #

def test_rejected_proposal_cannot_carry_a_partial_plan() -> None:
    with pytest.raises(ValidationError, match="must not carry a partial plan"):
        DeployReconWaypointResponse(
            accepted=False,
            flight_plan_id="FP-1",
            rejection=ToolRejection(code=RejectionCode.ENVELOPE_VIOLATION, detail="x"),
        )


def test_rejected_proposal_must_name_a_reason() -> None:
    with pytest.raises(ValidationError, match="structured rejection"):
        DeployReconWaypointResponse(accepted=False)


def test_accepted_proposal_always_requires_confirmation() -> None:
    with pytest.raises(ValidationError, match="requires explicit human confirmation"):
        DeployReconWaypointResponse(
            accepted=True,
            flight_plan_id="FP-1",
            flight_plan_digest="a" * 64,
            requires_confirmation=False,
        )


def test_accepted_proposal_is_staged_not_dispatched() -> None:
    response = DeployReconWaypointResponse(
        accepted=True, flight_plan_id="FP-1", flight_plan_digest="b" * 64
    )
    assert response.requires_confirmation is True


# --------------------------------------------------------------------------- #
# Transport and integrity guarantees encoded in types
# --------------------------------------------------------------------------- #

def test_accepted_stream_must_declare_dtls_and_edge_hashing() -> None:
    with pytest.raises(ValidationError):
        StreamThermalFeedResponse(
            accepted=True,
            session_id="s-1",
            expires_utc=T0,
            transport="plain-rtp",  # type: ignore[arg-type]
            frame_hash_algorithm="sha256-edge",
        )


def test_accepted_stream_without_edge_hashing_is_rejected() -> None:
    with pytest.raises(ValidationError, match="edge-side frame hashing"):
        StreamThermalFeedResponse(
            accepted=True, session_id="s-1", expires_utc=T0, transport="dtls1.3-srtp"
        )


def test_emergency_stop_must_use_the_independent_channel() -> None:
    with pytest.raises(ValidationError, match="independent channel"):
        RequestEmergencyStopResponse(
            broadcast=True, incident_zone_id="IZ-1", broadcast_utc=T0
        )


def test_affirmative_clearance_requires_an_expiry() -> None:
    with pytest.raises(ValidationError, match="must carry an expiry"):
        CheckAirspaceClearanceResponse(
            cleared=True, reason="cleared", detail="", evaluated_utc=T0
        )


def test_clearance_cannot_be_affirmative_while_naming_blocking_zones() -> None:
    with pytest.raises(ValidationError, match="cannot be affirmative"):
        CheckAirspaceClearanceResponse(
            cleared=True,
            reason="cleared",
            detail="",
            evaluated_utc=T0,
            expires_utc=T0 + timedelta(seconds=120),
            blocking_zone_ids=("NFZ-1",),
        )


def test_only_an_approval_can_dispatch() -> None:
    with pytest.raises(ValidationError, match="only be dispatched on an APPROVE"):
        ConfirmFlightPlanResponse(
            flight_plan_id="FP-1",
            decision=ConfirmDecision.REJECT,
            dispatched=True,
            confirmed_by_operator_id="op-cr-001",
            confirmed_utc=T0,
        )


# --------------------------------------------------------------------------- #
# Identity, signing, precedence
# --------------------------------------------------------------------------- #

def test_human_tiers_require_hardware_mfa() -> None:
    with pytest.raises(ValidationError, match="requires a FIDO2 credential"):
        OperatorIdentity(operator_id="op-cr-002", role=Role.COMMAND_ROOM)


def test_agent_identity_cannot_hold_a_hardware_credential() -> None:
    with pytest.raises(ValidationError, match="must not carry a FIDO2 credential"):
        OperatorIdentity(
            operator_id="agent-1", role=Role.AI_AGENT, fido2_credential_id="cred-x"
        )


def _signature(credential: str = "cred-cr-1") -> CommandSignature:
    return CommandSignature(
        algorithm=SignatureAlgorithm.ES256,
        key_id="key-1",
        fido2_credential_id=credential,
        value="v" * 32,
        signed_at=T0,
        expires_at=T0 + timedelta(seconds=120),
        nonce="n" * 16,
    )


def test_agent_cannot_construct_a_signed_envelope() -> None:
    """Tier 3 proposes; a human tier disposes. Enforced by the type, not by discipline."""
    agent = OperatorIdentity(operator_id="agent-1", role=Role.AI_AGENT)
    with pytest.raises(ValidationError, match="cannot carry a command signature"):
        SignedCommandEnvelope(issuer=agent, signature=_signature(), mission_id="M-001")


def test_signature_must_bind_to_the_issuers_credential(
    command_room: OperatorIdentity,
) -> None:
    with pytest.raises(ValidationError, match="not bound to the issuing operator"):
        SignedCommandEnvelope(
            issuer=command_room,
            signature=_signature(credential="cred-someone-else"),
            mission_id="M-001",
        )


def test_signature_lifetime_is_capped(command_room: OperatorIdentity) -> None:
    with pytest.raises(ValidationError, match="lifetime exceeds"):
        CommandSignature(
            algorithm=SignatureAlgorithm.ES256,
            key_id="key-1",
            fido2_credential_id="cred-cr-1",
            value="v" * 32,
            signed_at=T0,
            expires_at=T0 + timedelta(hours=8),
            nonce="n" * 16,
        )


def test_signature_algorithm_none_cannot_be_expressed() -> None:
    assert "none" not in {a.value for a in SignatureAlgorithm}
    with pytest.raises(ValidationError):
        CommandSignature(
            algorithm="none",  # type: ignore[arg-type]
            key_id="key-1",
            fido2_credential_id="cred-1",
            value="v" * 32,
            signed_at=T0,
            expires_at=T0 + timedelta(seconds=60),
            nonce="n" * 16,
        )


@pytest.mark.parametrize("target", list(Role))
def test_agent_can_never_override_anything(target: Role) -> None:
    """Including another agent proposal -- otherwise a rejection could be laundered."""
    assert can_override(Role.AI_AGENT, target) is False


def test_precedence_matrix_matches_the_master_plan() -> None:
    assert can_override(Role.COMMAND_ROOM, Role.FIELD_LEADER)
    assert can_override(Role.COMMAND_ROOM, Role.AI_AGENT)
    assert can_override(Role.FIELD_LEADER, Role.AI_AGENT)
    assert not can_override(Role.FIELD_LEADER, Role.COMMAND_ROOM)
    # Authority is by tier, never by recency: a peer cannot override a peer.
    assert not can_override(Role.COMMAND_ROOM, Role.COMMAND_ROOM)


# --------------------------------------------------------------------------- #
# IncidentZone -- the root authorization envelope (TM-01)
# --------------------------------------------------------------------------- #

def _zone(command_room: OperatorIdentity, **overrides: object) -> IncidentZone:
    base: dict[str, object] = {
        "incident_zone_id": "IZ-1",
        "boundary": square(46.5, 24.5, 0.5),
        "priority": IncidentPriority.P1_CRITICAL,
        "status": IncidentZoneStatus.ACTIVE,
        "authorized_from": T0,
        "authorized_until": T0 + timedelta(hours=2),
        "altitude_ceiling_m_agl": 100.0,
        "altitude_floor_m_agl": 20.0,
        "declared_by": command_room,
        "authorized_operator_ids": frozenset({"op-cr-001"}),
    }
    return IncidentZone(**{**base, **overrides})  # type: ignore[arg-type]


def test_zone_cannot_widen_the_platform_envelope(command_room: OperatorIdentity) -> None:
    with pytest.raises(ValidationError):
        _zone(command_room, altitude_ceiling_m_agl=ENVELOPE.altitude_max_agl_m + 1)


def test_zone_window_is_capped(command_room: OperatorIdentity) -> None:
    with pytest.raises(ValidationError, match="exceeds the"):
        _zone(
            command_room,
            authorized_until=T0 + timedelta(seconds=ENVELOPE.incident_zone_max_duration_s + 60),
        )


def test_only_the_command_room_may_declare_a_zone(command_room: OperatorIdentity) -> None:
    field_leader = OperatorIdentity(
        operator_id="op-fl-001", role=Role.FIELD_LEADER, fido2_credential_id="cred-fl-1"
    )
    with pytest.raises(ValidationError, match="only be declared by the command room"):
        _zone(
            command_room,
            declared_by=field_leader,
            authorized_operator_ids=frozenset({"op-fl-001"}),
        )


def test_zone_activity_checks_time_not_just_status(command_room: OperatorIdentity) -> None:
    """A stored status can lag reality, so time is checked independently."""
    zone = _zone(command_room)
    assert zone.is_active_at(T0 + timedelta(hours=1))
    assert not zone.is_active_at(T0 - timedelta(minutes=1))
    assert not zone.is_active_at(T0 + timedelta(hours=3))
    assert not _zone(command_room, status=IncidentZoneStatus.REVOKED).is_active_at(
        T0 + timedelta(hours=1)
    )


def test_zone_policy_projection_excludes_free_text(command_room: OperatorIdentity) -> None:
    """A decision engine that never receives a value cannot leak it in a decision log."""
    projection = _zone(command_room, reference="SENSITIVE-CASE-REF").to_policy_input()
    assert "reference" not in projection
    assert "declared_by" not in projection


# --------------------------------------------------------------------------- #
# Tool catalogue
# --------------------------------------------------------------------------- #

def test_registry_covers_every_tool_exactly_once() -> None:
    assert set(TOOL_REGISTRY) == set(ToolName)
    assert set(TOOL_SCHEMA_VERSIONS) == set(ToolName)


def test_no_tool_name_references_a_prohibited_capability() -> None:
    """Reconnaissance only, at any phase (Master Plan §3)."""
    for tool in ToolName:
        for capability in PROHIBITED_CAPABILITIES:
            assert capability not in tool.value, f"{tool.value} references {capability}"


def test_agent_cannot_be_scoped_to_human_only_tools() -> None:
    """Confirmation and emergency stop are human authority, not agent capability."""
    for tool in (
        ToolName.CONFIRM_FLIGHT_PLAN,
        ToolName.REQUEST_EMERGENCY_STOP,
        ToolName.EXECUTE_SAFE_RETURN,
    ):
        assert tool not in AGENT_PROPOSABLE_TOOLS


def test_degraded_landing_is_observable_but_not_requestable() -> None:
    """It preempts execute_safe_return; it is not one of its triggers (Master Plan §5)."""
    from mcp_server.schemas.tools import SafeReturnTrigger

    assert DroneState.DEGRADED_VISUAL_INERTIAL_LANDING.value in {s.value for s in DroneState}
    assert "degraded" not in {t.value for t in SafeReturnTrigger}


def test_unavailable_drone_cannot_be_reported_available() -> None:
    with pytest.raises(ValidationError, match="RTL trigger"):
        DroneStatus(
            drone_id="D-1",
            state=DroneState.IDLE,
            battery_pct=ENVELOPE.battery_rtl_trigger_pct - 1,
            available=True,
            airframe_type="quad",
        )


def test_in_flight_drone_cannot_be_reported_available() -> None:
    with pytest.raises(ValidationError, match="not available for dispatch"):
        DroneStatus(
            drone_id="D-1",
            state=DroneState.ON_STATION,
            battery_pct=90.0,
            available=True,
            airframe_type="quad",
        )


def test_emergency_stop_scope_must_match_its_target() -> None:
    from mcp_server.schemas.tools import RequestEmergencyStopRequest

    envelope = SignedCommandEnvelope(
        issuer=OperatorIdentity(
            operator_id="op-fl-001", role=Role.FIELD_LEADER, fido2_credential_id="cred-fl-1"
        ),
        signature=_signature(credential="cred-fl-1"),
        mission_id="M-001",
    )
    with pytest.raises(ValidationError, match="must name the drone"):
        RequestEmergencyStopRequest(
            scope=EmergencyStopScope.SINGLE_DRONE,
            incident_zone_id="IZ-1",
            reason="lost visual",
            authorization=envelope,
        )


# --------------------------------------------------------------------------- #
# The ingress path: strict JSON mode
# --------------------------------------------------------------------------- #

VALID_DEPLOY_JSON = json.dumps({
    "mission_id": "M-001",
    "polygon": {
        "type": "Polygon",
        "coordinates": [[
            [46.49, 24.49], [46.51, 24.49], [46.51, 24.51], [46.49, 24.51], [46.49, 24.49],
        ]],
    },
    "altitude_min_m_agl": 30.0,
    "altitude_max_m_agl": 100.0,
    "velocity_max_mps": 10.0,
    "pattern_type": "grid",
    "duration_s": 900.0,
})


def test_wire_json_is_accepted() -> None:
    """A real MCP request arrives as JSON; strict JSON mode must accept its encodings."""
    request = DeployReconWaypointRequest.parse_json(VALID_DEPLOY_JSON)
    assert request.pattern_type is PatternType.GRID
    assert request.polygon.coordinates[0][0] == (46.49, 24.49)


@pytest.mark.parametrize(
    "find, replace, label",
    [
        ('"altitude_max_m_agl": 100.0', '"altitude_max_m_agl": NaN', "NaN altitude"),
        ('"altitude_max_m_agl": 100.0', '"altitude_max_m_agl": Infinity', "Inf altitude"),
        ("46.51", "NaN", "NaN coordinate"),
    ],
)
def test_non_finite_numbers_are_rejected_on_the_wire(
    find: str, replace: str, label: str
) -> None:
    """NaN defeats every comparison-based bound check, so it must never parse."""
    mutated = VALID_DEPLOY_JSON.replace(find, replace)
    assert mutated != VALID_DEPLOY_JSON, f"{label}: mutation did not apply"
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(mutated)


def test_lossy_coercion_is_still_rejected_in_json_mode() -> None:
    """JSON mode relaxes encodings, never type safety."""
    mutated = VALID_DEPLOY_JSON.replace('"velocity_max_mps": 10.0', '"velocity_max_mps": "10"')
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(mutated)


def test_trailing_data_after_the_document_is_rejected() -> None:
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(VALID_DEPLOY_JSON + "{}")
