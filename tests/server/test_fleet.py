"""``get_fleet_status`` over the real HTTP surface.

Two things are under test that a direct handler call would miss: that the response is
scoped to what the caller is allowed to see (Zero-Trust §2.2 -- field-level
authorization applies to read paths too), and that an answer from this tool never
becomes an authorization for anything.
"""

from __future__ import annotations

from typing import Any

from tests.server.conftest import (
    AGENT_TOKEN,
    FL_TOKEN,
    MISSION_ID,
    T0,
    ZONE_ID,
    Harness,
)

from dronez.safety.states import DroneState as FleetDroneState
from fleet_manager import DroneRecord


def fleet_status(harness: Harness, token: str, **params: Any) -> dict[str, Any]:
    body = harness.rpc("get_fleet_status", params, token=token).json()
    assert "error" not in body, body
    return body["result"]  # type: ignore[no-any-return]


def by_id(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {d["drone_id"]: d for d in result["drones"]}


# --------------------------------------------------------------------------- #
# The basic answer
# --------------------------------------------------------------------------- #

def test_the_fleet_is_reported(harness: Harness) -> None:
    result = fleet_status(harness, FL_TOKEN)
    assert by_id(result).keys() >= {"D-1", "D-2", "D-3"}
    assert result["queried_utc"]


def test_availability_is_computed_not_echoed(harness: Harness) -> None:
    """D-1 is idle and charged; D-2 is on station; D-3 is grounded."""
    drones = by_id(fleet_status(harness, FL_TOKEN))
    assert drones["D-1"]["available"] is True
    assert drones["D-2"]["available"] is False
    assert drones["D-3"]["available"] is False


def test_unavailable_drones_can_be_excluded(harness: Harness) -> None:
    result = fleet_status(harness, FL_TOKEN, include_unavailable=False)
    assert all(d["available"] for d in result["drones"])
    assert [d["drone_id"] for d in result["drones"]] == ["D-1"]


def test_a_grounded_drone_is_never_reported_available(harness: Harness) -> None:
    """The response schema refuses to encode it, so a projection bug is a 500, not a
    quietly dispatchable airframe."""
    drones = by_id(fleet_status(harness, FL_TOKEN))
    assert drones["D-3"]["maintenance_grounded"] is True
    assert drones["D-3"]["available"] is False


# --------------------------------------------------------------------------- #
# Zone scoping (Zero-Trust §2.2)
# --------------------------------------------------------------------------- #

def test_a_zone_query_excludes_other_zones(harness: Harness) -> None:
    result = fleet_status(harness, FL_TOKEN, incident_zone_id=ZONE_ID)
    assert "D-9" not in by_id(result), "an airframe in another zone must not be listed"


def test_a_zone_the_caller_is_not_scoped_to_returns_nothing(harness: Harness) -> None:
    result = fleet_status(harness, FL_TOKEN, incident_zone_id="IZ-OTHER")
    assert result["drones"] == []


def test_an_out_of_scope_zone_query_is_audited_as_a_scope_rejection(
    harness: Harness,
) -> None:
    fleet_status(harness, FL_TOKEN, incident_zone_id="IZ-OTHER")
    record = harness.ctx.audit_sink.records()[-1]  # type: ignore[attr-defined]
    assert record.outcome.value == "rejected_scope"
    assert "not_authorized_for_zone" in record.reason_codes


# --------------------------------------------------------------------------- #
# The agent sees less
# --------------------------------------------------------------------------- #

def test_an_agent_may_query_the_fleet(harness: Harness) -> None:
    """It needs to know whether a mission is proposable at all."""
    result = fleet_status(harness, AGENT_TOKEN)
    assert result["drones"]


def test_an_agent_is_not_shown_the_scheduler(harness: Harness) -> None:
    """Queue depth and preemption candidates are command-room decisions. Showing them
    to a proposer invites it to argue about them."""
    fleet_status(harness, AGENT_TOKEN)
    agent_record = harness.ctx.audit_sink.records()[-1]  # type: ignore[attr-defined]
    assert "scheduler" not in agent_record.decision

    fleet_status(harness, FL_TOKEN)
    human_record = harness.ctx.audit_sink.records()[-1]  # type: ignore[attr-defined]
    assert "scheduler" in human_record.decision


# --------------------------------------------------------------------------- #
# A fleet view is a picture, and a picture goes stale
# --------------------------------------------------------------------------- #

def test_a_fleet_answer_reflects_telemetry_age(harness: Harness) -> None:
    """Master Plan §4: a stale record's battery and position are guesses."""
    assert by_id(fleet_status(harness, FL_TOKEN))["D-1"]["available"] is True

    harness.clock.advance(120)
    assert by_id(fleet_status(harness, FL_TOKEN))["D-1"]["available"] is False


def test_the_query_reserves_nothing(harness: Harness) -> None:
    """Read-only means read-only: two identical queries see the same fleet."""
    first = by_id(fleet_status(harness, FL_TOKEN))
    second = by_id(fleet_status(harness, FL_TOKEN))
    assert first["D-1"]["available"] == second["D-1"]["available"]
    assert harness.ctx.scheduler.assignments() == ()


def test_a_degraded_landing_is_visible_to_the_command_room(harness: Harness) -> None:
    """DVIL spec §5.2: observable, never commandable. Blinding the operators during
    the exact event they most need to understand is its own safety failure."""
    harness.ctx.drones.upsert(
        DroneRecord(
            drone_id="D-2", airframe_type="quad-micro",
            state=FleetDroneState.FAILSAFE, battery_pct=60.0, endurance_s=1400.0,
            last_seen_utc=harness.clock(), home_zone_id=ZONE_ID,
            current_mission_id=MISSION_ID,
        )
    )
    harness.ctx.drones.upsert(
        DroneRecord(
            drone_id="D-2", airframe_type="quad-micro",
            state=FleetDroneState.DEGRADED_VISUAL_INERTIAL_LANDING,
            battery_pct=58.0, endurance_s=1300.0,
            last_seen_utc=harness.clock(), home_zone_id=ZONE_ID,
            current_mission_id=MISSION_ID,
        )
    )
    drones = by_id(fleet_status(harness, FL_TOKEN))
    assert drones["D-2"]["state"] == "degraded_visual_inertial_landing"
    assert drones["D-2"]["available"] is False


def test_no_tool_input_can_set_a_degraded_landing_state(harness: Harness) -> None:
    """There is no vocabulary for it. The request schema forbids undeclared fields, so
    an attempt to smuggle one in is a schema rejection, not a state change."""
    body = harness.rpc(
        "get_fleet_status", {"state": "degraded_visual_inertial_landing"}, token=FL_TOKEN
    ).json()
    assert body["error"]["code"] == -32602


def test_unknown_fields_are_rejected(harness: Harness) -> None:
    body = harness.rpc("get_fleet_status", {"zone": ZONE_ID}, token=FL_TOKEN).json()
    assert body["error"]["code"] == -32602


def test_the_response_carries_no_operator_identity(harness: Harness) -> None:
    """Zero-Trust §2.2: responses are built from allow-listed DTOs, not from whatever
    the server happens to know."""
    import json

    blob = json.dumps(fleet_status(harness, FL_TOKEN))
    assert "op-cr-001" not in blob
    assert "cred-" not in blob
    assert str(T0.year) in blob  # the timestamp is there; the identity is not
