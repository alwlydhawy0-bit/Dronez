"""Wire-level contract tests for all seven MCP tool schemas.

`tests/unit/test_schemas.py` tests the schemas as Python objects. This suite tests
them as a **wire contract**: what a caller may send, what is refused, and what a
rejection is allowed to contain. Every case goes through `parse_json` on JSON text,
because that is the ingress path a request actually takes (CLAUDE.md §5).

The governing property, swept generically across all seven tools: **an undeclared
field is a rejection, a malformed value is a rejection, and no rejection response may
carry a partial result.** Zero-Trust §3.1 makes the first mass-assignment defence;
CLAUDE.md §10.4 makes the last non-negotiable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError
from tests.contract.conftest import DIGEST, REMOVE, SQUARE, wire

from dronez.safety.envelope import ENVELOPE
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.tools import (
    AGENT_PROPOSABLE_TOOLS,
    TOOL_REGISTRY,
    TOOL_SCHEMA_VERSIONS,
    CheckAirspaceClearanceResponse,
    ConfirmDecision,
    ConfirmFlightPlanResponse,
    DeployReconWaypointRequest,
    DeployReconWaypointResponse,
    DroneState,
    ExecuteSafeReturnResponse,
    PatternType,
    RejectionCode,
    RequestEmergencyStopResponse,
    SafeReturnTrigger,
    StreamThermalFeedResponse,
    ToolName,
    ToolRejection,
)

TOOLS = [name.value for name in ToolName]

#: Response models built directly in Python get real datetimes, not ISO strings.
#: Strict mode does not coerce a string into a datetime in Python mode -- the same
#: asymmetry the ingress rule exists for (CLAUDE.md §5).
T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
BEFORE_T0 = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)
AFTER_T0 = datetime(2026, 1, 15, 10, 2, tzinfo=UTC)


def request_model(tool: str) -> type[StrictModel]:
    return TOOL_REGISTRY[ToolName(tool)][0]


def response_model(tool: str) -> type[StrictModel]:
    return TOOL_REGISTRY[ToolName(tool)][1]


# --------------------------------------------------------------------------- #
# The registry itself is part of the contract
# --------------------------------------------------------------------------- #

def test_every_tool_name_has_a_registry_entry() -> None:
    assert set(TOOL_REGISTRY) == set(ToolName)


def test_every_tool_name_has_a_schema_version() -> None:
    assert set(TOOL_SCHEMA_VERSIONS) == set(ToolName)


@pytest.mark.parametrize("tool", TOOLS)
def test_schema_version_is_namespaced_semver(tool: str) -> None:
    """``<name>/<major>.<minor>.<patch>``, so a receiver can refuse a major it does
    not implement rather than best-effort parsing it (CLAUDE.md §5)."""
    version = TOOL_SCHEMA_VERSIONS[ToolName(tool)]
    name, _, semver = version.partition("/")
    assert name == tool, f"{version} does not name its own tool"
    parts = semver.split(".")
    assert len(parts) == 3 and all(p.isdigit() for p in parts), version


@pytest.mark.parametrize("tool", TOOLS)
def test_request_and_response_models_are_distinct(tool: str) -> None:
    assert request_model(tool) is not response_model(tool)


def test_the_agent_tool_surface_is_a_strict_subset() -> None:
    """Least privilege (Zero-Trust §0.1): the agent gets fewer tools than a human."""
    assert AGENT_PROPOSABLE_TOOLS < set(ToolName)


def test_no_high_consequence_tool_is_agent_proposable() -> None:
    """Confirmation, emergency stop and RTL all authorize or command physical action.

    An agent able to invoke any of them would hold authority the precedence matrix
    says Tier 3 does not have.
    """
    forbidden = {
        ToolName.CONFIRM_FLIGHT_PLAN,
        ToolName.REQUEST_EMERGENCY_STOP,
        ToolName.EXECUTE_SAFE_RETURN,
    }
    assert not (AGENT_PROPOSABLE_TOOLS & forbidden)


# --------------------------------------------------------------------------- #
# Generic ingress contract, swept over all seven tools
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("tool", TOOLS)
def test_a_valid_request_parses(tool: str) -> None:
    assert request_model(tool).parse_json(wire(tool)) is not None


@pytest.mark.parametrize("tool", TOOLS)
def test_an_undeclared_field_is_rejected(tool: str) -> None:
    """Zero-Trust §3.1: undeclared fields are an immediate rejection, which is what
    blocks mass assignment."""
    with pytest.raises(ValidationError, match=r"[Ee]xtra"):
        request_model(tool).parse_json(wire(tool, unexpected_field="x"))


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "smuggled",
    ["role", "operator_id", "authorized_zone_ids", "principal", "tier", "is_admin"],
)
def test_an_authorization_field_cannot_be_smuggled_in(tool: str, smuggled: str) -> None:
    """The principal is server-derived. A caller supplying its own role or zone list
    would be supplying its own authorization."""
    with pytest.raises(ValidationError):
        request_model(tool).parse_json(wire(tool, **{smuggled: "command_room"}))


@pytest.mark.parametrize("tool", TOOLS)
def test_requests_are_immutable(tool: str) -> None:
    """A validated request cannot be edited between the gate and the handler."""
    parsed = request_model(tool).parse_json(wire(tool))
    field = next(iter(type(parsed).model_fields))
    with pytest.raises(ValidationError):
        setattr(parsed, field, "mutated")


@pytest.mark.parametrize("tool", TOOLS)
def test_requests_round_trip_through_json(tool: str) -> None:
    """Serialize, re-parse, get the same object -- so a staged request and the digest
    taken over it cannot disagree."""
    model = request_model(tool)
    first = model.parse_json(wire(tool))
    assert model.parse_json(first.model_dump_json()) == first


@pytest.mark.parametrize("tool", TOOLS)
def test_a_truncated_body_is_rejected(tool: str) -> None:
    with pytest.raises(ValidationError):
        request_model(tool).parse_json(wire(tool)[:-4])


@pytest.mark.parametrize("tool", TOOLS)
def test_a_json_array_is_not_a_request(tool: str) -> None:
    with pytest.raises(ValidationError):
        request_model(tool).parse_json("[]")


@pytest.mark.parametrize("tool", TOOLS)
def test_a_json_null_is_not_a_request(tool: str) -> None:
    with pytest.raises(ValidationError):
        request_model(tool).parse_json("null")


@pytest.mark.parametrize("tool", TOOLS)
def test_every_required_field_is_actually_required(tool: str) -> None:
    model = request_model(tool)
    required = [name for name, f in model.model_fields.items() if f.is_required()]
    if not required:
        # `get_fleet_status` is entirely optional by design -- an empty body is a
        # valid whole-fleet query. Asserted explicitly below rather than skipped
        # silently, so this branch cannot quietly swallow a schema regression.
        assert tool == "get_fleet_status", f"{tool} unexpectedly has no required fields"
        model.parse_json("{}")
        return
    for name in required:
        with pytest.raises(ValidationError):
            model.parse_json(wire(tool, **{name: REMOVE}))


# --------------------------------------------------------------------------- #
# Numeric hostility: NaN, Infinity, and type confusion
# --------------------------------------------------------------------------- #

NUMERIC_FIELDS = [
    ("deploy_recon_waypoint", "altitude_max_m_agl", "100.0"),
    ("deploy_recon_waypoint", "velocity_max_mps", "10.0"),
    ("deploy_recon_waypoint", "duration_s", "900.0"),
    ("check_airspace_clearance", "altitude_max_m_agl", "100.0"),
]


@pytest.mark.parametrize(("tool", "field", "literal"), NUMERIC_FIELDS)
@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numbers_are_rejected(
    tool: str, field: str, literal: str, bad: str
) -> None:
    """``allow_inf_nan=False`` on StrictModel. NaN defeats every comparison it appears
    in -- ``nan <= ceiling`` is false, so a bound check silently passes nothing.

    Built by substitution on the serialized body because ``json.dumps`` emits these as
    bare literals. The assertion guards that the substitution actually applied: a
    mutation that silently no-ops would make this test pass for the wrong reason.
    """
    body = wire(tool)
    mutated = body.replace(f'"{field}": {literal}', f'"{field}": {bad}')
    assert mutated != body, f"the {bad} substitution did not apply to {field}"

    with pytest.raises(ValidationError):
        request_model(tool).parse_json(mutated)


@pytest.mark.parametrize(("tool", "field", "_literal"), NUMERIC_FIELDS)
def test_a_numeric_string_is_not_a_number(tool: str, field: str, _literal: str) -> None:
    """Strict mode does not coerce. A string that happens to look numeric must not
    slip past a bound check."""
    with pytest.raises(ValidationError):
        request_model(tool).parse_json(wire(tool, **{field: "100"}))


@pytest.mark.parametrize("tool", TOOLS)
def test_an_unknown_enum_value_is_rejected(tool: str) -> None:
    """A new behaviour cannot be introduced by naming it in a request."""
    model = request_model(tool)
    enum_fields = [
        name
        for name, f in model.model_fields.items()
        if isinstance(f.annotation, type)
        and issubclass(f.annotation, str)
        and hasattr(f.annotation, "__members__")
    ]
    if not enum_fields:
        pytest.skip(f"{tool} declares no enum fields")
    for name in enum_fields:
        with pytest.raises(ValidationError):
            model.parse_json(wire(tool, **{name: "admin_override"}))


# --------------------------------------------------------------------------- #
# Bounds come from the envelope, not from literals
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("tool", ["deploy_recon_waypoint", "check_airspace_clearance"])
def test_altitude_ceiling_is_the_envelope_ceiling(tool: str) -> None:
    ceiling = ENVELOPE.altitude_max_agl_m
    request_model(tool).parse_json(wire(tool, altitude_max_m_agl=ceiling))
    with pytest.raises(ValidationError):
        request_model(tool).parse_json(wire(tool, altitude_max_m_agl=ceiling + 0.1))


@pytest.mark.parametrize("tool", ["deploy_recon_waypoint", "check_airspace_clearance"])
def test_altitude_floor_is_the_envelope_floor(tool: str) -> None:
    floor = ENVELOPE.altitude_min_agl_m
    request_model(tool).parse_json(
        wire(tool, altitude_min_m_agl=floor, altitude_max_m_agl=floor + 10.0)
    )
    with pytest.raises(ValidationError):
        request_model(tool).parse_json(wire(tool, altitude_min_m_agl=floor - 0.1))


def test_velocity_ceiling_is_the_envelope_ceiling() -> None:
    top = ENVELOPE.ground_speed_max_mps
    DeployReconWaypointRequest.parse_json(
        wire("deploy_recon_waypoint", velocity_max_mps=top)
    )
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(
            wire("deploy_recon_waypoint", velocity_max_mps=top + 0.1)
        )


def test_zero_velocity_is_rejected() -> None:
    """A recon pattern flown at 0 m/s is a hover with a flight plan attached."""
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(
            wire("deploy_recon_waypoint", velocity_max_mps=0.0)
        )


def test_negative_velocity_is_rejected() -> None:
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(
            wire("deploy_recon_waypoint", velocity_max_mps=-5.0)
        )


def test_duration_ceiling_is_the_mission_time_box() -> None:
    top = ENVELOPE.mission_duration_max_s
    DeployReconWaypointRequest.parse_json(wire("deploy_recon_waypoint", duration_s=top))
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(
            wire("deploy_recon_waypoint", duration_s=top + 1)
        )


@pytest.mark.parametrize("tool", ["deploy_recon_waypoint", "check_airspace_clearance"])
def test_an_inverted_altitude_band_is_rejected(tool: str) -> None:
    with pytest.raises(ValidationError, match="strictly below"):
        request_model(tool).parse_json(
            wire(tool, altitude_min_m_agl=100.0, altitude_max_m_agl=30.0)
        )


@pytest.mark.parametrize("tool", ["deploy_recon_waypoint", "check_airspace_clearance"])
def test_a_zero_thickness_altitude_band_is_rejected(tool: str) -> None:
    with pytest.raises(ValidationError, match="strictly below"):
        request_model(tool).parse_json(
            wire(tool, altitude_min_m_agl=50.0, altitude_max_m_agl=50.0)
        )


# --------------------------------------------------------------------------- #
# Geometry
# --------------------------------------------------------------------------- #

BAD_POLYGONS: dict[str, Any] = {
    "unclosed ring": [[[46.4, 24.4], [46.6, 24.4], [46.6, 24.6], [46.4, 24.6]]],
    "too few positions": [[[46.4, 24.4], [46.6, 24.4], [46.4, 24.4]]],
    "degenerate line": [[[46.4, 24.4], [46.6, 24.4], [46.4, 24.4], [46.4, 24.4]]],
    "longitude out of range": [
        [[181.0, 24.4], [46.6, 24.4], [46.6, 24.6], [181.0, 24.4]]
    ],
    "latitude out of range": [[[46.4, 91.0], [46.6, 24.4], [46.6, 24.6], [46.4, 91.0]]],
    "empty rings": [],
    "three-element position": [
        [[46.4, 24.4, 100.0], [46.6, 24.4], [46.6, 24.6], [46.4, 24.4, 100.0]]
    ],
}


@pytest.mark.parametrize("tool", ["deploy_recon_waypoint", "check_airspace_clearance"])
@pytest.mark.parametrize("label", list(BAD_POLYGONS))
def test_malformed_polygons_are_rejected(tool: str, label: str) -> None:
    with pytest.raises(ValidationError):
        request_model(tool).parse_json(
            wire(tool, polygon={"type": "Polygon", "coordinates": BAD_POLYGONS[label]})
        )


@pytest.mark.parametrize("tool", ["deploy_recon_waypoint", "check_airspace_clearance"])
def test_a_non_polygon_geometry_type_is_rejected(tool: str) -> None:
    with pytest.raises(ValidationError):
        request_model(tool).parse_json(
            wire(tool, polygon={"type": "MultiPolygon", "coordinates": SQUARE})
        )


@pytest.mark.parametrize("tool", ["deploy_recon_waypoint", "check_airspace_clearance"])
def test_an_oversized_ring_is_rejected(tool: str) -> None:
    """Bounded so containment checking cannot be made arbitrarily expensive."""
    ring = [[46.4 + i * 1e-6, 24.4] for i in range(600)]
    ring.append(ring[0])
    with pytest.raises(ValidationError):
        request_model(tool).parse_json(
            wire(tool, polygon={"type": "Polygon", "coordinates": [ring]})
        )


# --------------------------------------------------------------------------- #
# Identifiers
# --------------------------------------------------------------------------- #

HOSTILE_IDS = [
    "../../etc/passwd",
    "M-001; DROP TABLE missions",
    "M 001",
    "<script>alert(1)</script>",
    "M" + chr(0) + "001",
    "M" + chr(10) + "001",
    "-leading-dash",
    "",
    "ab",
    "M" * 65,
]


@pytest.mark.parametrize("bad", HOSTILE_IDS, ids=lambda s: repr(s)[:32])
def test_hostile_mission_ids_are_rejected(bad: str) -> None:
    """Identifiers reach logs, policy input and (later) query parameters. The pattern
    is an allow-list, so a path traversal or an injection payload is not an
    identifier."""
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(
            wire("deploy_recon_waypoint", mission_id=bad)
        )


@pytest.mark.parametrize(
    "bad", ["A" * 64, "g" * 64, DIGEST[:63], DIGEST + "a", "0X" + "a" * 62, ""]
)
def test_a_malformed_plan_digest_is_rejected(bad: str) -> None:
    """The digest binds a human's approval to the exact plan reviewed. A digest that
    is not a digest cannot bind anything."""
    with pytest.raises(ValidationError):
        request_model("confirm_flight_plan").parse_json(
            wire("confirm_flight_plan", flight_plan_digest=bad)
        )


# --------------------------------------------------------------------------- #
# Reconnaissance-only: the scope boundary, at the schema level
# --------------------------------------------------------------------------- #

def test_the_pattern_set_is_closed() -> None:
    """Master Plan §5: no freeform arbitrary path from raw agent output. An agent
    chooses among reviewed patterns; it cannot describe a novel trajectory."""
    assert {p.value for p in PatternType} == {"perimeter_sweep", "grid", "orbit"}


@pytest.mark.parametrize(
    "offensive",
    ["payload_release", "engage", "strike", "pursue", "intercept", "deploy_payload"],
)
def test_no_offensive_pattern_can_be_requested(offensive: str) -> None:
    """CLAUDE.md §1.1, non-negotiable by any milestone: reconnaissance only."""
    with pytest.raises(ValidationError):
        DeployReconWaypointRequest.parse_json(
            wire("deploy_recon_waypoint", pattern_type=offensive)
        )


def test_degraded_landing_is_not_a_requestable_return_trigger() -> None:
    """It *preempts* RTL rather than being one of its reasons. Listing it here would
    imply the server can request it, inverting the control relationship
    (docs/07-degraded-landing-firmware-spec.md §5)."""
    assert "degraded_visual_inertial_landing" not in {t.value for t in SafeReturnTrigger}


def test_degraded_landing_is_an_observable_drone_state() -> None:
    """Observable is not requestable -- but it must be observable, or the command room
    is blind during the event it most needs to understand."""
    assert "degraded_visual_inertial_landing" in {s.value for s in DroneState}


def test_failsafe_is_observable_but_not_a_return_trigger() -> None:
    assert "failsafe" in {s.value for s in DroneState}
    assert "failsafe" not in {t.value for t in SafeReturnTrigger}


# --------------------------------------------------------------------------- #
# Responses: a rejection is structured and total, never best-effort
# --------------------------------------------------------------------------- #

def test_a_rejected_deploy_cannot_carry_a_flight_plan() -> None:
    with pytest.raises(ValidationError, match="best-effort"):
        DeployReconWaypointResponse(
            accepted=False,
            flight_plan_id="FP-001",
            rejection=ToolRejection(code=RejectionCode.AIRSPACE_DENIED, detail="nfz"),
        )


def test_a_rejected_deploy_cannot_carry_a_digest() -> None:
    with pytest.raises(ValidationError, match="best-effort"):
        DeployReconWaypointResponse(
            accepted=False,
            flight_plan_digest=DIGEST,
            rejection=ToolRejection(code=RejectionCode.AIRSPACE_DENIED, detail="nfz"),
        )


def test_a_rejected_deploy_cannot_carry_an_assigned_drone() -> None:
    with pytest.raises(ValidationError, match="best-effort"):
        DeployReconWaypointResponse(
            accepted=False,
            assigned_drone_id="D-1",
            rejection=ToolRejection(code=RejectionCode.FLEET_UNAVAILABLE, detail="none"),
        )


@pytest.mark.parametrize("tool", TOOLS)
def test_no_response_model_declares_a_partial_result_field(tool: str) -> None:
    """There is no field for a best-effort plan or a suggested relaxation anywhere in
    the contract. A caller that wants a different answer submits a different
    request."""
    banned = {"partial", "best_effort", "suggested", "fallback", "relaxed", "approximate"}
    fields = set(response_model(tool).model_fields)
    assert not (fields & banned), f"{tool} exposes {fields & banned}"


def test_an_accepted_deploy_must_carry_a_digest() -> None:
    with pytest.raises(ValidationError, match="digest"):
        DeployReconWaypointResponse(accepted=True, flight_plan_id="FP-001")


def test_an_accepted_deploy_always_requires_confirmation() -> None:
    """A staged plan that could skip confirmation would make the human gate
    optional."""
    with pytest.raises(ValidationError, match="confirmation"):
        DeployReconWaypointResponse(
            accepted=True,
            flight_plan_id="FP-001",
            flight_plan_digest=DIGEST,
            requires_confirmation=False,
        )


def test_an_accepted_deploy_cannot_also_be_a_rejection() -> None:
    with pytest.raises(ValidationError, match="must not carry a rejection"):
        DeployReconWaypointResponse(
            accepted=True,
            flight_plan_id="FP-001",
            flight_plan_digest=DIGEST,
            rejection=ToolRejection(code=RejectionCode.INTERNAL_ERROR, detail="x"),
        )


def test_a_rejected_deploy_must_say_why() -> None:
    with pytest.raises(ValidationError, match="structured rejection"):
        DeployReconWaypointResponse(accepted=False)


# --- stream: the transport is not negotiable -------------------------------

def test_an_accepted_stream_cannot_declare_a_weaker_transport() -> None:
    """Master Plan §5: the stream is rejected at the signaling layer if a client
    cannot negotiate DTLS/SRTP. A response asserting anything weaker cannot be
    built."""
    with pytest.raises(ValidationError):
        StreamThermalFeedResponse(
            accepted=True,
            session_id="s-1",
            expires_utc=T0,
            transport="rtp-plain",  # type: ignore[arg-type]
            frame_hash_algorithm="sha256-edge",
        )


def test_an_accepted_stream_cannot_omit_edge_hashing() -> None:
    """Hashing at the console attests only that nobody altered a frame after it
    arrived -- which an attacker on the RF link can make true of frames they
    substituted."""
    with pytest.raises(ValidationError, match="edge-side frame hashing"):
        StreamThermalFeedResponse(
            accepted=True,
            session_id="s-1",
            expires_utc=T0,
            transport="dtls1.3-srtp",
        )


def test_an_accepted_stream_must_be_time_boxed() -> None:
    with pytest.raises(ValidationError, match="time-boxed"):
        StreamThermalFeedResponse(
            accepted=True,
            session_id="s-1",
            transport="dtls1.3-srtp",
            frame_hash_algorithm="sha256-edge",
        )


# --- clearance: affirmative decisions are time-boxed and conflict-free ------

def test_an_affirmative_clearance_must_carry_an_expiry() -> None:
    """Without one it could be minted early and replayed at dispatch."""
    with pytest.raises(ValidationError, match="expiry"):
        CheckAirspaceClearanceResponse(
            cleared=True,
            reason="CLEAR",
            detail="",
            evaluated_utc=T0,
        )


def test_a_clearance_expiring_before_it_was_evaluated_is_rejected() -> None:
    with pytest.raises(ValidationError, match="after evaluation"):
        CheckAirspaceClearanceResponse(
            cleared=True,
            reason="CLEAR",
            detail="",
            evaluated_utc=T0,
            expires_utc=BEFORE_T0,
        )


def test_a_clearance_cannot_be_affirmative_and_name_a_blocking_zone() -> None:
    with pytest.raises(ValidationError, match="blocking zones"):
        CheckAirspaceClearanceResponse(
            cleared=True,
            reason="CLEAR",
            detail="",
            evaluated_utc=T0,
            expires_utc=AFTER_T0,
            blocking_zone_ids=("NFZ-1",),
        )


def test_a_denial_may_name_blocking_zones() -> None:
    decision = CheckAirspaceClearanceResponse(
        cleared=False,
        reason="ZONE_CONFLICT",
        detail="",
        evaluated_utc=T0,
        blocking_zone_ids=("NFZ-1", "NFZ-2"),
    )
    assert decision.blocking_zone_ids == ("NFZ-1", "NFZ-2")


# --- confirm: only approvals dispatch --------------------------------------

def test_a_rejection_decision_cannot_dispatch() -> None:
    with pytest.raises(ValidationError, match="only be dispatched on an APPROVE"):
        ConfirmFlightPlanResponse(
            flight_plan_id="FP-001",
            decision=ConfirmDecision.REJECT,
            dispatched=True,
            confirmed_by_operator_id="op-cr-001",
            confirmed_utc=T0,
        )


def test_a_dispatched_plan_must_name_the_confirming_operator() -> None:
    """Non-repudiation: 'who authorized this flight?' must be answerable
    afterwards."""
    with pytest.raises(ValidationError, match="which operator confirmed"):
        ConfirmFlightPlanResponse(
            flight_plan_id="FP-001",
            decision=ConfirmDecision.APPROVE,
            dispatched=True,
        )


@pytest.mark.parametrize("tool", ["confirm_flight_plan", "request_emergency_stop"])
def test_an_agent_identity_cannot_hold_a_hardware_credential(tool: str) -> None:
    """The first of two layers. Relabelling a human envelope as an agent is caught on
    the *identity*: a credential lives in a hardware authenticator a person holds, so
    an agent claiming one is claiming something it cannot physically have."""
    body = json.loads(wire(tool))
    body["authorization"]["issuer"]["role"] = "ai_agent"
    with pytest.raises(ValidationError, match="must not carry a FIDO2 credential"):
        request_model(tool).parse_json(json.dumps(body))


@pytest.mark.parametrize("tool", ["confirm_flight_plan", "request_emergency_stop"])
def test_an_agent_cannot_carry_a_command_signature(tool: str) -> None:
    """The second layer, reached by stripping the credential to get past the first.

    Tier 3 proposes and a human disposes, so an agent structurally cannot confirm its
    own proposal or stop the fleet -- and the rule does not depend on the identity
    check above having fired.
    """
    body = json.loads(wire(tool))
    body["authorization"]["issuer"]["role"] = "ai_agent"
    del body["authorization"]["issuer"]["fido2_credential_id"]
    with pytest.raises(ValidationError, match="cannot carry a command signature"):
        request_model(tool).parse_json(json.dumps(body))


def test_a_signature_bound_to_a_different_credential_is_rejected() -> None:
    body = json.loads(wire("confirm_flight_plan"))
    body["authorization"]["signature"]["fido2_credential_id"] = "cred-someone-else"
    with pytest.raises(ValidationError, match="not bound to"):
        request_model("confirm_flight_plan").parse_json(json.dumps(body))


# --- emergency stop: scope and target must agree ---------------------------

def test_a_single_drone_stop_must_name_the_drone() -> None:
    with pytest.raises(ValidationError, match="must name the drone"):
        request_model("request_emergency_stop").parse_json(
            wire("request_emergency_stop", scope="single_drone")
        )


def test_a_zone_stop_must_not_name_a_drone() -> None:
    """Otherwise the scope field and the target field disagree, and which one the
    server obeys becomes an implementation detail."""
    with pytest.raises(ValidationError, match="must not name a single drone"):
        request_model("request_emergency_stop").parse_json(
            wire("request_emergency_stop", scope="zone", drone_id="D-1")
        )


def test_a_broadcast_stop_must_use_the_independent_channel() -> None:
    with pytest.raises(ValidationError, match="independent channel"):
        RequestEmergencyStopResponse(
            broadcast=True,
            incident_zone_id="IZ-1",
            broadcast_utc=T0,
            channel=None,
        )


# --- execute_safe_return ---------------------------------------------------

def test_an_acknowledged_return_cannot_carry_a_rejection() -> None:
    with pytest.raises(ValidationError, match="must not carry a rejection"):
        ExecuteSafeReturnResponse(
            acknowledged=True,
            drone_id="D-1",
            rejection=ToolRejection(code=RejectionCode.INTERNAL_ERROR, detail="x"),
        )


def test_an_already_autonomous_return_is_a_normal_outcome() -> None:
    """The firmware beat the server to it. That is expected, and the server records it
    rather than trying to re-issue or override (Zero-Trust §4.1)."""
    response = ExecuteSafeReturnResponse(
        acknowledged=True, drone_id="D-1", already_autonomous=True
    )
    assert response.already_autonomous
    assert response.rejection is None


# --------------------------------------------------------------------------- #
# Rejection codes
# --------------------------------------------------------------------------- #

def test_rejection_detail_is_bounded() -> None:
    """Error bodies reach a caller who may be an attacker, and reach logs."""
    with pytest.raises(ValidationError):
        ToolRejection(code=RejectionCode.INTERNAL_ERROR, detail="x" * 513)


def test_rejection_codes_are_unique() -> None:
    values = [c.value for c in RejectionCode]
    assert len(values) == len(set(values))


def test_the_dispatch_gate_has_its_own_rejection_code() -> None:
    """A refusal by the closed Milestone-0 gate is not an internal error: nothing went
    wrong, the gate is deliberately shut. Conflating them would make a deliberate
    refusal look like a defect in the logs."""
    assert RejectionCode.DISPATCH_GATE_CLOSED != RejectionCode.INTERNAL_ERROR


#: How each tool says no. Two tools do not carry a `rejection` field, and that is
#: deliberate rather than a gap:
#:
#: * `check_airspace_clearance` -- the denial IS the response. `cleared=False` with a
#:   machine-readable `reason` is a complete, structured answer; a separate rejection
#:   channel would create two ways to say no and a question about which one binds.
#: * `get_fleet_status` -- a read-only query with no authorization to refuse. Scope
#:   filtering returns fewer drones, which is an answer, not a failure.
NEGATIVE_OUTCOME_FIELD = {
    "deploy_recon_waypoint": "rejection",
    "stream_thermal_feed": "rejection",
    "execute_safe_return": "rejection",
    "check_airspace_clearance": "cleared",
    "confirm_flight_plan": "rejection",
    "get_fleet_status": "drones",
    "request_emergency_stop": "rejection",
}


@pytest.mark.parametrize("tool", TOOLS)
def test_every_response_can_express_a_negative_outcome(tool: str) -> None:
    """A tool that cannot say no is a tool that fails open."""
    field = NEGATIVE_OUTCOME_FIELD[tool]
    assert field in response_model(tool).model_fields, (
        f"{tool} has no way to express a negative outcome"
    )


def test_a_clearance_denial_is_the_response_not_a_side_channel() -> None:
    """`cleared=False` carries a reason code and a detail, which is a complete
    structured denial. That is why this response has no `rejection` field."""
    fields = set(response_model("check_airspace_clearance").model_fields)
    assert {"cleared", "reason", "detail"} <= fields
    assert "rejection" not in fields
