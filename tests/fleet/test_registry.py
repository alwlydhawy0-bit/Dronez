"""The fleet registry: what the command room is looking at.

Two properties matter here. First, **availability is computed, never asserted** -- a
drone is dispatchable because its state, battery, grounding and telemetry age all say
so, not because a field says `available: true`. Second, **an impossible reported state
is not believed**: a telemetry stream is an untrusted input like any other
(CLAUDE.md §10.4), and a stream that claims a physically impossible transition is
evidence of corruption or an attacker, not of the transition.
"""

from __future__ import annotations

from tests.fleet.conftest import ZONE, Clock, record

from dronez.safety.envelope import ENVELOPE
from dronez.safety.states import DroneState
from fleet_manager import STALE_TELEMETRY_S, FleetRegistry

# --------------------------------------------------------------------------- #
# Availability is computed from facts, and the reason is preserved
# --------------------------------------------------------------------------- #

def test_a_healthy_idle_drone_is_available(registry: FleetRegistry, clock: Clock) -> None:
    registry.upsert(record("D-1"))
    assert registry.get("D-1") is not None
    assert registry.available() == registry.all_drones()


def test_maintenance_grounds_a_drone_independent_of_mission_demand(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Master Plan §4: grounding is independent of demand. A busy incident does not
    make an airframe airworthy."""
    registry.upsert(record("D-1", grounded=True))
    drone = registry.get("D-1")
    assert drone is not None
    assert not drone.is_available(clock())
    assert "maintenance" in str(drone.unavailable_reason(clock()))


def test_a_drone_below_the_rtl_trigger_is_not_dispatchable(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Dispatching an airframe already below its own RTL threshold sends it out to
    immediately turn around."""
    registry.upsert(record("D-1", battery_pct=ENVELOPE.battery_rtl_trigger_pct - 0.1))
    drone = registry.get("D-1")
    assert drone is not None
    assert not drone.is_available(clock())
    assert "RTL trigger" in str(drone.unavailable_reason(clock()))


def test_stale_telemetry_makes_a_drone_unavailable(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Believing a stale record means dispatching to an airframe whose battery,
    position and state are all guesses."""
    registry.upsert(record("D-1"))
    clock.advance(STALE_TELEMETRY_S + 1)
    drone = registry.get("D-1")
    assert drone is not None
    assert not drone.is_available(clock())
    assert "stale" in str(drone.unavailable_reason(clock()))


def test_an_airborne_drone_is_not_available_for_a_new_mission(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1", state=DroneState.ON_STATION))
    assert registry.available() == ()


def test_the_unavailability_reason_distinguishes_the_three_situations(
    registry: FleetRegistry, clock: Clock
) -> None:
    """An operator looking at an empty fleet list needs to know whether everything is
    flying, everything is flat, or the telemetry link is down."""
    registry.upsert(record("D-flying", state=DroneState.IN_TRANSIT))
    registry.upsert(record("D-flat", battery_pct=5.0))
    registry.upsert(record("D-grounded", grounded=True))
    reasons = {
        d.drone_id: str(d.unavailable_reason(clock())) for d in registry.all_drones()
    }
    assert "in state in_transit" in reasons["D-flying"]
    assert "RTL trigger" in reasons["D-flat"]
    assert "maintenance" in reasons["D-grounded"]


# --------------------------------------------------------------------------- #
# Endurance and the reserve factor
# --------------------------------------------------------------------------- #

def test_endurance_must_cover_the_mission_plus_the_reserve(
    registry: FleetRegistry,
) -> None:
    """`battery_range_reserve_factor` is a pre-dispatch sufficiency check: a mission
    that needs every drop of the battery is a mission with no margin."""
    duration = 1000.0
    required = duration * ENVELOPE.battery_range_reserve_factor
    assert registry is not None

    exact = record("D-exact", endurance_s=required)
    short = record("D-short", endurance_s=required - 1.0)
    assert exact.can_sustain(duration)
    assert not short.can_sustain(duration)


def test_available_filters_on_endurance(registry: FleetRegistry) -> None:
    registry.upsert(record("D-long", endurance_s=5000.0))
    registry.upsert(record("D-short", endurance_s=100.0))
    ids = [d.drone_id for d in registry.available(mission_duration_s=1800.0)]
    assert ids == ["D-long"]


def test_available_is_ordered_fullest_first(registry: FleetRegistry) -> None:
    registry.upsert(record("D-low", battery_pct=55.0))
    registry.upsert(record("D-high", battery_pct=98.0))
    registry.upsert(record("D-mid", battery_pct=77.0))
    assert [d.drone_id for d in registry.available()] == ["D-high", "D-mid", "D-low"]


# --------------------------------------------------------------------------- #
# Zone scoping
# --------------------------------------------------------------------------- #

def test_available_is_scoped_to_the_zone(registry: FleetRegistry) -> None:
    registry.upsert(record("D-here", zone=ZONE))
    registry.upsert(record("D-elsewhere", zone="IZ-OTHER"))
    registry.upsert(record("D-unassigned", zone=None))
    ids = {d.drone_id for d in registry.available(zone_id=ZONE)}
    assert ids == {"D-here", "D-unassigned"}


def test_airborne_in_zone_is_the_emergency_stop_target_set(
    registry: FleetRegistry,
) -> None:
    """A stop targets what is flying *in that zone* -- not the whole fleet, and not
    airframes sitting on the ground."""
    registry.upsert(record("D-flying-here", state=DroneState.ON_STATION, zone=ZONE))
    registry.upsert(record("D-idle-here", state=DroneState.IDLE, zone=ZONE))
    registry.upsert(record("D-flying-there", state=DroneState.IN_TRANSIT, zone="IZ-OTHER"))
    assert [d.drone_id for d in registry.airborne_in_zone(ZONE)] == ["D-flying-here"]


def test_a_drone_in_degraded_landing_is_an_emergency_stop_target(
    registry: FleetRegistry,
) -> None:
    """It is airborne until it is not. Excluding it would hide a drone that is coming
    down from the people who most need to know where it is."""
    registry.upsert(
        record("D-dvil", state=DroneState.DEGRADED_VISUAL_INERTIAL_LANDING, zone=ZONE)
    )
    assert [d.drone_id for d in registry.airborne_in_zone(ZONE)] == ["D-dvil"]


# --------------------------------------------------------------------------- #
# Telemetry is untrusted input
# --------------------------------------------------------------------------- #

def test_an_impossible_reported_transition_is_rejected_and_counted(
    registry: FleetRegistry,
) -> None:
    registry.upsert(record("D-1", state=DroneState.IDLE))
    registry.upsert(record("D-1", state=DroneState.ON_STATION))  # IDLE -> ON_STATION

    drone = registry.get("D-1")
    assert drone is not None
    assert drone.state is DroneState.IDLE, "the impossible state must not be believed"
    assert registry.rejected_transitions == 1


def test_rejecting_a_transition_leaves_the_stale_record_which_then_fails_freshness(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Holding a stale record is the safe failure: it stops dispatch on its own.

    Believing the impossible one would not.
    """
    registry.upsert(record("D-1", state=DroneState.IDLE))
    clock.advance(STALE_TELEMETRY_S + 1)
    registry.upsert(record("D-1", state=DroneState.ON_STATION, last_seen=clock()))

    drone = registry.get("D-1")
    assert drone is not None
    assert not drone.is_available(clock())


def test_a_legitimate_firmware_transition_is_accepted(registry: FleetRegistry) -> None:
    """The registry must record a fail-safe, not argue with it."""
    registry.upsert(record("D-1", state=DroneState.ON_STATION))
    registry.upsert(record("D-1", state=DroneState.FAILSAFE))
    registry.upsert(record("D-1", state=DroneState.DEGRADED_VISUAL_INERTIAL_LANDING))

    drone = registry.get("D-1")
    assert drone is not None
    assert drone.state is DroneState.DEGRADED_VISUAL_INERTIAL_LANDING
    assert registry.rejected_transitions == 0


def test_a_drone_in_degraded_landing_is_never_dispatchable(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(
        record("D-1", state=DroneState.DEGRADED_VISUAL_INERTIAL_LANDING, battery_pct=99.0)
    )
    assert registry.available() == ()


# --------------------------------------------------------------------------- #
# Mutation and projection
# --------------------------------------------------------------------------- #

def test_mark_maintenance_toggles_grounding(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    assert registry.mark_maintenance("D-1", grounded=True)
    drone = registry.get("D-1")
    assert drone is not None and not drone.is_available(clock())

    assert registry.mark_maintenance("D-1", grounded=False)
    drone = registry.get("D-1")
    assert drone is not None and drone.is_available(clock())


def test_mark_maintenance_on_an_unknown_drone_reports_failure(
    registry: FleetRegistry,
) -> None:
    assert not registry.mark_maintenance("D-nope", grounded=True)


def test_snapshot_counts_match_the_records(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    registry.upsert(record("D-2", state=DroneState.ON_STATION))
    registry.upsert(record("D-3", grounded=True))

    snap = registry.snapshot()
    assert snap["total"] == 3
    assert snap["available"] == 1
    assert snap["airborne"] == 1
    assert snap["grounded"] == 1


def test_snapshot_is_zone_scoped(registry: FleetRegistry) -> None:
    registry.upsert(record("D-here", zone=ZONE))
    registry.upsert(record("D-elsewhere", zone="IZ-OTHER"))
    assert registry.snapshot(zone_id=ZONE)["total"] == 1


def test_a_record_rejects_naive_timestamps() -> None:
    """An offset-naive timestamp makes the staleness check meaningless."""
    import datetime as _dt

    import pytest

    with pytest.raises(ValueError, match="UTC offset"):
        record("D-1", last_seen=_dt.datetime(2026, 3, 1, 8, 0))
