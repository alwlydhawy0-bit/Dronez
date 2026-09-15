"""Invariants of the drone mission state machine.

The property under test is not "the transition table is correct" -- it is that **the
ground has no vocabulary for a fail-safe**. Zero-Trust §4.1: *"The MCP server MUST
NEVER attempt to override hardware emergency return commands."* A server that could
command `FAILSAFE -> IN_TRANSIT` could override one.

These run over the full state cross-product rather than a handful of examples, because
a hole in an allow-list is exactly the kind of defect an example-based test misses.
"""

from __future__ import annotations

import itertools

import pytest

from dronez.safety.states import (
    AIRBORNE_STATES,
    FAILSAFE_STATES,
    FIRMWARE_TRANSITIONS,
    GROUND_COMMANDABLE,
    DroneState,
    TransitionAuthority,
    check_transition,
    is_airborne,
    may_ground_command,
)

ALL_PAIRS = list(itertools.product(DroneState, DroneState))


# --------------------------------------------------------------------------- #
# The load-bearing invariant
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("source", "target"), ALL_PAIRS)
def test_ground_can_never_command_entry_into_a_failsafe_state(
    source: DroneState, target: DroneState
) -> None:
    if target not in FAILSAFE_STATES or source is target:
        return
    check = check_transition(source, target, by_ground=True)
    assert not check.permitted
    assert check.authority is TransitionAuthority.FIRMWARE_ONLY


@pytest.mark.parametrize(("source", "target"), ALL_PAIRS)
def test_ground_can_never_command_exit_from_a_failsafe_state(
    source: DroneState, target: DroneState
) -> None:
    if source not in FAILSAFE_STATES or source is target:
        return
    check = check_transition(source, target, by_ground=True)
    assert not check.permitted
    assert check.authority is TransitionAuthority.FIRMWARE_ONLY


def test_no_ground_commandable_pair_touches_a_failsafe_state() -> None:
    """Stated directly against the table, not only through the function.

    Two ways to reach the same conclusion: if a future edit adds a pair to the
    allow-list, this fails even if someone also changed ``check_transition``.
    """
    for source, target in GROUND_COMMANDABLE:
        assert source not in FAILSAFE_STATES, (source, target)
        assert target not in FAILSAFE_STATES, (source, target)


def test_degraded_landing_is_unreachable_from_the_ground_in_every_direction() -> None:
    dvil = DroneState.DEGRADED_VISUAL_INERTIAL_LANDING
    for other in DroneState:
        if other is dvil:
            continue
        assert not may_ground_command(other, dvil)
        assert not may_ground_command(dvil, other)


def test_degraded_landing_is_entered_only_from_failsafe() -> None:
    """DVIL is a *sub-state* of FAILSAFE, not a peer of it (Master Plan §4).

    An airframe reaches it by having already failed safe, which is what makes
    "concurrent GNSS denial and vision loss" an escalation rather than a first move.
    """
    dvil = DroneState.DEGRADED_VISUAL_INERTIAL_LANDING
    entries = {source for source, target in FIRMWARE_TRANSITIONS if target is dvil}
    assert entries == {DroneState.FAILSAFE}


def test_degraded_landing_ends_on_the_ground() -> None:
    """Its only exit is touchdown. There is no sensor-recovery exit.

    ``docs/07-degraded-landing-firmware-spec.md`` §4.3: a recovered GNSS fix does not
    resume navigation, because an adversary who can deny GNSS can also restore a
    spoofed one, and a re-navigating aircraft would then fly wherever they chose.
    """
    dvil = DroneState.DEGRADED_VISUAL_INERTIAL_LANDING
    exits = {target for source, target in FIRMWARE_TRANSITIONS if source is dvil}
    assert exits == {DroneState.POST_FLIGHT}


# --------------------------------------------------------------------------- #
# Ordinary mission flow still works
# --------------------------------------------------------------------------- #

def test_the_nominal_mission_flow_is_ground_commandable() -> None:
    """Master Plan §4's happy path, end to end."""
    flow = [
        DroneState.IDLE,
        DroneState.PRE_FLIGHT_CHECK,
        DroneState.ARMED,
        DroneState.IN_TRANSIT,
        DroneState.ON_STATION,
        DroneState.RTL_TRIGGERED,
        DroneState.LANDING,
        DroneState.POST_FLIGHT,
        DroneState.IDLE,
    ]
    for source, target in itertools.pairwise(flow):
        check = check_transition(source, target, by_ground=True)
        assert check.permitted, f"{source} -> {target}: {check.detail}"
        assert check.authority is TransitionAuthority.GROUND


def test_a_no_op_transition_is_permitted() -> None:
    check = check_transition(DroneState.ON_STATION, DroneState.ON_STATION, by_ground=True)
    assert check.permitted


def test_an_arbitrary_leap_is_not_ground_commandable() -> None:
    check = check_transition(DroneState.IDLE, DroneState.ON_STATION, by_ground=True)
    assert not check.permitted
    assert check.authority is None


def test_denials_carry_a_reason() -> None:
    """CLAUDE.md §10.4: fail closed, *loudly*."""
    for source, target in ALL_PAIRS:
        check = check_transition(source, target, by_ground=True)
        if not check.permitted:
            assert check.detail.strip()


# --------------------------------------------------------------------------- #
# Observing a reported transition
# --------------------------------------------------------------------------- #

def test_failsafe_is_reachable_as_an_interrupt_from_every_state() -> None:
    """Master Plan §4: FAILSAFE is an interrupt from *any* state.

    Except from inside itself. ``DEGRADED_VISUAL_INERTIAL_LANDING`` is a sub-state of
    FAILSAFE, so "escalating" to FAILSAFE from it is not a transition -- it is a
    report the airframe cannot have generated.
    """
    for source in DroneState:
        if source in FAILSAFE_STATES:
            continue
        check = check_transition(source, DroneState.FAILSAFE, by_ground=False)
        assert check.permitted, source
        assert check.authority is TransitionAuthority.FIRMWARE_ONLY


def test_lost_link_forces_failsafe() -> None:
    """Loss of link is a handled trigger, never an unhandled state."""
    check = check_transition(DroneState.LOST_LINK, DroneState.FAILSAFE, by_ground=False)
    assert check.permitted


def test_an_impossible_reported_transition_is_not_believed() -> None:
    """A telemetry stream claiming this is corrupt, not informative."""
    check = check_transition(
        DroneState.DEGRADED_VISUAL_INERTIAL_LANDING,
        DroneState.ARMED,
        by_ground=False,
    )
    assert not check.permitted
    assert "corrupt" in check.detail


def test_observing_never_widens_what_the_ground_may_command() -> None:
    """``by_ground=False`` accepts more; it must never make the ground path accept more."""
    for source, target in ALL_PAIRS:
        if check_transition(source, target, by_ground=True).permitted:
            assert check_transition(source, target, by_ground=False).permitted


# --------------------------------------------------------------------------- #
# Airborne classification -- what makes a scheduling mistake consequential
# --------------------------------------------------------------------------- #

def test_every_failsafe_state_is_classified_airborne() -> None:
    """A drone in a fail-safe is a physical object in motion until it is not.

    Classifying one as on-the-ground would let the scheduler hand it out.
    """
    assert FAILSAFE_STATES <= AIRBORNE_STATES


def test_ground_states_are_not_airborne() -> None:
    for state in (
        DroneState.IDLE,
        DroneState.PRE_FLIGHT_CHECK,
        DroneState.ARMED,
        DroneState.POST_FLIGHT,
        DroneState.MAINTENANCE,
    ):
        assert not is_airborne(state)
