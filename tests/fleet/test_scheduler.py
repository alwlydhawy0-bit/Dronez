"""Priority-queue arbitration for contested fleet resources.

The scheduler decides *who waits*, which is a resource question, not a safety one --
so a bug here delays a mission rather than flying an unsafe one. That is why it sits
outside the policy gate: every assignment it makes is still re-validated by
`deploy_recon_waypoint`, which takes its own fleet snapshot at decision time.

What it must get right is the part an operator acts on: a deterministic order under
contention, an honest wait estimate, and a clear distinction between "wait" and
"call someone else".
"""

from __future__ import annotations

from tests.fleet.conftest import ZONE, Clock, fleet_request, record

from dronez.safety.states import DroneState
from fleet_manager import (
    ArbitrationOutcome,
    FleetRegistry,
    FleetScheduler,
    RequestPriority,
)
from mcp_server.schemas.identity import Role


def scheduler(registry: FleetRegistry, clock: Clock) -> FleetScheduler:
    return FleetScheduler(registry, clock=clock)


# --------------------------------------------------------------------------- #
# The uncontested case
# --------------------------------------------------------------------------- #

def test_a_request_against_a_free_fleet_is_assigned(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    decision = scheduler(registry, clock).request(fleet_request("R-1"))

    assert decision.outcome is ArbitrationOutcome.ASSIGNED
    assert decision.assignment is not None
    assert decision.assignment.drone_id == "D-1"


def test_the_fullest_airframe_is_assigned_first(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-low", battery_pct=45.0))
    registry.upsert(record("D-high", battery_pct=97.0))
    decision = scheduler(registry, clock).request(fleet_request("R-1"))
    assert decision.assignment is not None
    assert decision.assignment.drone_id == "D-high"


def test_an_assigned_drone_is_not_assigned_twice(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-1"))
    second = sched.request(fleet_request("R-2"))
    assert second.outcome is ArbitrationOutcome.QUEUED


# --------------------------------------------------------------------------- #
# Contention: who wins, and does the loser know why
# --------------------------------------------------------------------------- #

def test_a_contested_request_is_queued_with_a_position_and_an_estimate(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-1", duration_s=900.0))
    queued = sched.request(fleet_request("R-2"))

    assert queued.outcome is ArbitrationOutcome.QUEUED
    assert queued.queued is not None
    assert queued.queued.position == 0
    assert queued.queued.estimated_wait_s is not None
    assert queued.queued.blocked_by_drone_id == "D-1"


def test_priority_beats_arrival_order(registry: FleetRegistry, clock: Clock) -> None:
    """A P1 arriving second still goes ahead of a P3 that arrived first."""
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-holder"))

    sched.request(fleet_request("R-routine", priority=RequestPriority.P3_ROUTINE))
    clock.advance(10)
    sched.request(fleet_request("R-critical", priority=RequestPriority.P1_CRITICAL))

    order = [q.request.request_id for q in sched.queued_requests()]
    assert order == ["R-critical", "R-routine"]


def test_role_tier_breaks_a_priority_tie(registry: FleetRegistry, clock: Clock) -> None:
    """Master Plan §5: Command Room outranks a Field Leader. At equal incident
    priority, the higher tier is served first."""
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-holder"))

    sched.request(fleet_request("R-field", role=Role.FIELD_LEADER))
    clock.advance(10)
    sched.request(fleet_request("R-room", role=Role.COMMAND_ROOM))

    order = [q.request.request_id for q in sched.queued_requests()]
    assert order == ["R-room", "R-field"]


def test_arrival_order_breaks_a_full_tie(registry: FleetRegistry, clock: Clock) -> None:
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-holder"))

    sched.request(fleet_request("R-first", at=clock()))
    clock.advance(30)
    sched.request(fleet_request("R-second", at=clock()))

    order = [q.request.request_id for q in sched.queued_requests()]
    assert order == ["R-first", "R-second"]


def test_requests_in_the_same_tick_keep_a_stable_order(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Two requests at the same instant must still order deterministically, or the
    queue is non-reproducible under load -- and an operator cannot be told their
    position."""
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-holder"))
    for i in range(5):
        sched.request(fleet_request(f"R-{i}", at=clock()))

    order = [q.request.request_id for q in sched.queued_requests()]
    assert order == [f"R-{i}" for i in range(5)]


# --------------------------------------------------------------------------- #
# "Wait" versus "call someone else"
# --------------------------------------------------------------------------- #

def test_a_request_no_airframe_could_ever_serve_is_unserviceable_not_queued(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Queueing this would tell an operator to wait for something that will never
    happen, during an incident."""
    registry.upsert(record("D-1", endurance_s=120.0))
    decision = scheduler(registry, clock).request(fleet_request("R-1", duration_s=1800.0))

    assert decision.outcome is ArbitrationOutcome.UNSERVICEABLE
    assert "endurance" in decision.detail


def test_a_fully_grounded_fleet_is_unserviceable(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1", grounded=True))
    decision = scheduler(registry, clock).request(fleet_request("R-1"))
    assert decision.outcome is ArbitrationOutcome.UNSERVICEABLE


def test_a_wrong_zone_fleet_is_unserviceable(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1", zone="IZ-OTHER"))
    decision = scheduler(registry, clock).request(fleet_request("R-1", zone=ZONE))
    assert decision.outcome is ArbitrationOutcome.UNSERVICEABLE


def test_a_busy_but_capable_fleet_queues_rather_than_refusing(
    registry: FleetRegistry, clock: Clock
) -> None:
    """The distinction that matters: this one *will* be served."""
    registry.upsert(record("D-1", endurance_s=5000.0))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-1"))
    assert sched.request(fleet_request("R-2")).outcome is ArbitrationOutcome.QUEUED


def test_a_queue_estimate_accounts_for_the_requests_ahead(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-holder"))
    sched.request(fleet_request("R-a"))
    sched.request(fleet_request("R-b"))

    waits = [q.estimated_wait_s for q in sched.queued_requests()]
    assert waits[0] is not None and waits[1] is not None
    assert waits[1] > waits[0], "being further back must estimate a longer wait"


# --------------------------------------------------------------------------- #
# Release and promotion
# --------------------------------------------------------------------------- #

def test_releasing_a_drone_promotes_the_front_of_the_queue(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-1"))
    sched.request(fleet_request("R-2", priority=RequestPriority.P3_ROUTINE))
    sched.request(fleet_request("R-3", priority=RequestPriority.P1_CRITICAL))

    promoted = sched.release("D-1")
    assert promoted is not None
    assert promoted.outcome is ArbitrationOutcome.ASSIGNED
    assert promoted.request_id == "R-3", "the P1 is promoted, not the earlier P3"


def test_releasing_with_an_empty_queue_promotes_nothing(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-1"))
    assert sched.release("D-1") is None
    assert sched.assignments() == ()


def test_an_expired_reservation_frees_the_airframe(
    registry: FleetRegistry, clock: Clock
) -> None:
    """A reservation that outlived its mission would hold an airframe hostage to a
    request nobody is acting on."""
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-1", duration_s=600.0))

    clock.advance(601)
    registry.upsert(record("D-1", last_seen=clock()))
    assert sched.request(fleet_request("R-2")).outcome is ArbitrationOutcome.ASSIGNED


def test_a_full_queue_refuses_rather_than_growing_without_bound(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    sched = FleetScheduler(registry, clock=clock, max_queue=2)
    sched.request(fleet_request("R-holder"))
    sched.request(fleet_request("R-1"))
    sched.request(fleet_request("R-2"))

    overflow = sched.request(fleet_request("R-3"))
    assert overflow.outcome is ArbitrationOutcome.UNSERVICEABLE
    assert "queue is full" in overflow.detail


# --------------------------------------------------------------------------- #
# Preemption is advisory, and only advisory
# --------------------------------------------------------------------------- #

def test_preemption_is_surfaced_when_a_higher_priority_request_is_blocked(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-routine", priority=RequestPriority.P3_ROUTINE))
    sched.request(fleet_request("R-critical", priority=RequestPriority.P1_CRITICAL))

    candidates = sched.preemption_candidates()
    assert len(candidates) == 1
    assert candidates[0].drone_id == "D-1"
    assert candidates[0].current_priority is RequestPriority.P3_ROUTINE
    assert "human decision" in candidates[0].detail


def test_surfacing_a_preemption_candidate_recalls_nothing(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Choosing between two live incidents is a human judgement, so the scheduler
    assembles the context and stops there."""
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-routine", priority=RequestPriority.P3_ROUTINE))
    sched.request(fleet_request("R-critical", priority=RequestPriority.P1_CRITICAL))

    before = sched.assignments()
    sched.preemption_candidates()
    assert sched.assignments() == before
    assert [a.request_id for a in sched.assignments()] == ["R-routine"]


def test_no_preemption_candidate_against_an_equal_or_higher_holder(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Recalling a P1 to serve another P1 buys nothing and costs a mission."""
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-a", priority=RequestPriority.P1_CRITICAL))
    sched.request(fleet_request("R-b", priority=RequestPriority.P1_CRITICAL))
    assert sched.preemption_candidates() == ()


def test_no_preemption_candidates_with_an_empty_queue(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-1"))
    assert sched.preemption_candidates() == ()


# --------------------------------------------------------------------------- #
# The scheduler never overrides the registry's safety facts
# --------------------------------------------------------------------------- #

def test_an_airborne_drone_is_never_assigned(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Queued, not refused: a flying airframe lands, so this request *will* be served.

    Being airborne is transient, which is why it queues rather than reporting
    unserviceable -- that verdict is reserved for the permanent-ish properties
    (grounding, zone, endurance). What must never happen is an assignment.
    """
    registry.upsert(record("D-1", state=DroneState.ON_STATION))
    decision = scheduler(registry, clock).request(fleet_request("R-1"))
    assert decision.outcome is ArbitrationOutcome.QUEUED
    assert decision.assignment is None


def test_a_drone_that_fails_safe_mid_reservation_is_not_reassigned(
    registry: FleetRegistry, clock: Clock
) -> None:
    """Once the reservation expires the scheduler would happily reuse the airframe.

    It does not, because availability is the registry's call and the registry reads
    the state: a drone in FAILSAFE is not dispatchable however the scheduler feels.
    The request waits instead -- which is right, since the airframe will land.
    """
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-1", duration_s=300.0))

    registry.upsert(record("D-1", state=DroneState.FAILSAFE))
    clock.advance(301)
    registry.upsert(record("D-1", state=DroneState.FAILSAFE, last_seen=clock()))

    decision = sched.request(fleet_request("R-2"))
    assert decision.outcome is ArbitrationOutcome.QUEUED
    assert decision.assignment is None
    assert sched.assignments() == ()


def test_a_drone_in_degraded_landing_is_not_reassigned(
    registry: FleetRegistry, clock: Clock
) -> None:
    """The case the DVIL spec §6 calls out: mark it unavailable immediately, with no
    grace period. A drone coming down under ultrasonic guidance is not a fleet asset."""
    registry.upsert(record("D-1", state=DroneState.ON_STATION))
    registry.upsert(record("D-1", state=DroneState.FAILSAFE))
    registry.upsert(record("D-1", state=DroneState.DEGRADED_VISUAL_INERTIAL_LANDING))

    decision = scheduler(registry, clock).request(fleet_request("R-1"))
    assert decision.assignment is None


def test_status_projects_the_whole_picture(
    registry: FleetRegistry, clock: Clock
) -> None:
    registry.upsert(record("D-1"))
    sched = scheduler(registry, clock)
    sched.request(fleet_request("R-1", priority=RequestPriority.P3_ROUTINE))
    sched.request(fleet_request("R-2", priority=RequestPriority.P1_CRITICAL))

    status = sched.status()
    assert status["queue_depth"] == 1
    assert len(status["assignments"]) == 1  # type: ignore[arg-type]
    assert len(status["preemption_candidates"]) == 1  # type: ignore[arg-type]
