"""Multi-drone scheduling and contested-resource arbitration.

Master Plan §3, failure journeys: *"Contested fleet (two commanders, one available
drone): priority-queue policy (declared incident severity, requester role) arbitrates;
the losing request is queued with an explicit wait-time estimate, never silently
dropped."*

"Never silently dropped" is the requirement that shapes this module. A scheduler that
returns "no drone available" has told an operator almost nothing: they cannot tell
whether to wait thirty seconds or call another agency. So a losing request is admitted
to a queue, keeps its place, and comes back with an estimate.

Arbitration order
-----------------
1. **Declared incident severity.** A P1 outranks a P2 outranks a P3.
2. **Requester tier.** Command Room outranks Field Leader outranks AI Agent.
3. **Request time.** Ties go to whoever asked first.

Severity comes before role deliberately. A field leader standing at a P1 incident
outranks a command-room operator running a P3 sweep, because the airframe should go
where the emergency is rather than to whoever has the grander title.

Preemption is surfaced, never taken
-----------------------------------
When a P1 request is blocked by a P3 mission already in the air, this module
:meth:`~FleetScheduler.preemption_candidates` *identifies* the recall that would free an
airframe -- and stops there. Recalling an airborne drone ends a mission somebody is
relying on, and choosing between two live incidents is a human judgement, not a
scheduler's. It is surfaced so the command room can make it in one step rather than
reconstructing the situation from a fleet list.

This is the same "propose, don't dispose" line the whole system is built on, applied to
a resource decision instead of a flight decision.
"""

from __future__ import annotations

import itertools
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final

from dronez.authz import Role
from fleet_manager.registry import DroneRecord, FleetRegistry

__all__ = [
    "DEFAULT_TURNAROUND_S",
    "ArbitrationOutcome",
    "Assignment",
    "FleetRequest",
    "FleetScheduler",
    "PreemptionCandidate",
    "QueuedRequest",
    "RequestPriority",
    "SchedulingDecision",
]

#: Battery swap, pre-flight checks and handling between sorties. Used to estimate when a
#: busy airframe becomes available again. Deliberately generous: an estimate that runs
#: long is an operator waiting slightly less than told, which is the harmless direction.
DEFAULT_TURNAROUND_S: Final[float] = 420.0


class RequestPriority(StrEnum):
    """Declared incident severity, mirroring ``IncidentPriority``."""

    P1_CRITICAL = "p1_critical"
    P2_URGENT = "p2_urgent"
    P3_ROUTINE = "p3_routine"

    @property
    def rank(self) -> int:
        """Lower is more urgent, so it sorts directly."""
        return {"p1_critical": 0, "p2_urgent": 1, "p3_routine": 2}[self.value]


@dataclass(frozen=True, slots=True)
class FleetRequest:
    """A claim on a drone."""

    request_id: str
    mission_id: str
    incident_zone_id: str
    priority: RequestPriority
    requester_operator_id: str
    requester_role: Role
    duration_s: float
    requested_utc: datetime

    def sort_key(self, tiebreak: int) -> tuple[int, int, float, int]:
        """Arbitration key. Every component ascending, so lower wins.

        ``tiebreak`` is a monotonic admission counter rather than a timestamp
        comparison: two requests arriving in the same clock tick must still have a
        stable, reproducible order, or the queue is non-deterministic under load.
        """
        return (
            self.priority.rank,
            int(self.requester_role.tier),
            self.requested_utc.timestamp(),
            tiebreak,
        )


@dataclass(frozen=True, slots=True)
class Assignment:
    """A drone reserved for a mission."""

    request_id: str
    drone_id: str
    mission_id: str
    incident_zone_id: str
    assigned_utc: datetime
    #: Reservation expiry. A reservation that outlived its mission would hold an
    #: airframe hostage to a request nobody is acting on.
    expires_utc: datetime

    def is_active_at(self, when: datetime) -> bool:
        return when < self.expires_utc

    def to_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "drone_id": self.drone_id,
            "mission_id": self.mission_id,
            "incident_zone_id": self.incident_zone_id,
            "assigned_utc": self.assigned_utc.isoformat(),
            "expires_utc": self.expires_utc.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class QueuedRequest:
    """A request waiting for an airframe, with an estimate.

    ``estimated_wait_s`` is ``None`` when nothing in the fleet could ever serve the
    request -- every airframe is grounded, or none has the endurance. That is different
    from "a long wait", and an operator needs to be able to tell the difference: one
    means wait, the other means call someone else.
    """

    request: FleetRequest
    position: int
    estimated_wait_s: float | None
    blocked_by_drone_id: str | None
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request.request_id,
            "mission_id": self.request.mission_id,
            "priority": self.request.priority.value,
            "position": self.position,
            "estimated_wait_s": self.estimated_wait_s,
            "blocked_by_drone_id": self.blocked_by_drone_id,
            "detail": self.detail,
        }


class ArbitrationOutcome(StrEnum):
    ASSIGNED = "assigned"
    QUEUED = "queued"
    #: No airframe in the fleet could ever serve this request as specified.
    UNSERVICEABLE = "unserviceable"


@dataclass(frozen=True, slots=True)
class SchedulingDecision:
    """What happened to a fleet request."""

    outcome: ArbitrationOutcome
    request_id: str
    assignment: Assignment | None = None
    queued: QueuedRequest | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "request_id": self.request_id,
            "assignment": self.assignment.to_dict() if self.assignment else None,
            "queued": self.queued.to_dict() if self.queued else None,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class PreemptionCandidate:
    """A recall that would free an airframe for a higher-priority request.

    Advisory only. See the module docstring: choosing between two live incidents is a
    human judgement.
    """

    drone_id: str
    current_mission_id: str | None
    current_priority: RequestPriority | None
    blocking_request_id: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "drone_id": self.drone_id,
            "current_mission_id": self.current_mission_id,
            "current_priority": self.current_priority.value if self.current_priority else None,
            "blocking_request_id": self.blocking_request_id,
            "detail": self.detail,
        }


class FleetScheduler:
    """Assigns drones, arbitrates contention, and keeps the losers informed."""

    def __init__(
        self,
        registry: FleetRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
        turnaround_s: float = DEFAULT_TURNAROUND_S,
        max_queue: int = 256,
    ) -> None:
        self._registry = registry
        self._clock = clock or (lambda: datetime.now(UTC))
        self._turnaround = turnaround_s
        self._max_queue = max_queue
        self._lock = threading.Lock()
        self._assignments: dict[str, Assignment] = {}
        self._queue: list[tuple[tuple[int, int, float, int], FleetRequest]] = []
        self._admission = itertools.count()
        self._mission_priority: dict[str, RequestPriority] = {}

    # -- requesting ------------------------------------------------------

    def request(self, request: FleetRequest) -> SchedulingDecision:
        """Assign a drone, or queue the request with an estimate."""
        with self._lock:
            self._expire_locked()
            self._mission_priority[request.mission_id] = request.priority

            candidate = self._pick_locked(request)
            if candidate is not None:
                return self._assign_locked(request, candidate)

            if not self._any_airframe_could_serve(request):
                return SchedulingDecision(
                    outcome=ArbitrationOutcome.UNSERVICEABLE,
                    request_id=request.request_id,
                    detail=(
                        "no airframe in the fleet can serve this request as specified; "
                        "every candidate is grounded or lacks the endurance for "
                        f"{request.duration_s:.0f}s plus reserve"
                    ),
                )

            if len(self._queue) >= self._max_queue:
                return SchedulingDecision(
                    outcome=ArbitrationOutcome.UNSERVICEABLE,
                    request_id=request.request_id,
                    detail="the fleet request queue is full",
                )

            key = request.sort_key(next(self._admission))
            self._queue.append((key, request))
            self._queue.sort(key=lambda item: item[0])
            queued = self._describe_queued_locked(request)
            return SchedulingDecision(
                outcome=ArbitrationOutcome.QUEUED,
                request_id=request.request_id,
                queued=queued,
                detail=queued.detail,
            )

    def release(self, drone_id: str) -> SchedulingDecision | None:
        """Release a reservation and promote the highest-priority waiting request."""
        with self._lock:
            for request_id, assignment in list(self._assignments.items()):
                if assignment.drone_id == drone_id:
                    del self._assignments[request_id]
                    self._mission_priority.pop(assignment.mission_id, None)
                    break
            return self._promote_locked()

    def _promote_locked(self) -> SchedulingDecision | None:
        """Give a freed airframe to the front of the queue, if anyone can use it."""
        for index, (_key, queued_request) in enumerate(self._queue):
            candidate = self._pick_locked(queued_request)
            if candidate is not None:
                self._queue.pop(index)
                return self._assign_locked(queued_request, candidate)
        return None

    # -- arbitration internals -------------------------------------------

    def _pick_locked(self, request: FleetRequest) -> DroneRecord | None:
        reserved = {a.drone_id for a in self._assignments.values()}
        for drone in self._registry.available(
            mission_duration_s=request.duration_s, zone_id=request.incident_zone_id
        ):
            if drone.drone_id not in reserved:
                return drone
        return None

    def _assign_locked(
        self, request: FleetRequest, drone: DroneRecord
    ) -> SchedulingDecision:
        now = self._clock()
        assignment = Assignment(
            request_id=request.request_id,
            drone_id=drone.drone_id,
            mission_id=request.mission_id,
            incident_zone_id=request.incident_zone_id,
            assigned_utc=now,
            expires_utc=now + timedelta(seconds=request.duration_s),
        )
        self._assignments[request.request_id] = assignment
        return SchedulingDecision(
            outcome=ArbitrationOutcome.ASSIGNED,
            request_id=request.request_id,
            assignment=assignment,
            detail=f"assigned {drone.drone_id} ({drone.battery_pct:.0f}% battery)",
        )

    def _any_airframe_could_serve(self, request: FleetRequest) -> bool:
        """Whether *any* airframe could serve this if it were free.

        Distinguishes "wait" from "call someone else". Ignores current state and
        reservations, and considers only the permanent-ish properties: grounding, zone
        positioning, and endurance.
        """
        for drone in self._registry.all_drones():
            if drone.maintenance_grounded:
                continue
            if drone.home_zone_id not in (None, request.incident_zone_id):
                continue
            if drone.can_sustain(request.duration_s):
                return True
        return False

    def _describe_queued_locked(self, request: FleetRequest) -> QueuedRequest:
        position = next(
            (i for i, (_k, r) in enumerate(self._queue) if r.request_id == request.request_id),
            len(self._queue) - 1,
        )
        blocker, free_at = self._earliest_release_locked(request)
        if free_at is None:
            return QueuedRequest(
                request=request,
                position=position,
                estimated_wait_s=None,
                blocked_by_drone_id=None,
                detail=(
                    "queued at position "
                    f"{position + 1}; no airframe is currently reserved, so the wait "
                    "depends on a drone returning to service"
                ),
            )

        now = self._clock()
        # Requests ahead in the queue each consume one release cycle before this one.
        wait = max(0.0, (free_at - now).total_seconds()) + position * (
            self._turnaround + 60.0
        )
        return QueuedRequest(
            request=request,
            position=position,
            estimated_wait_s=wait,
            blocked_by_drone_id=blocker,
            detail=(
                f"queued at position {position + 1}; estimated wait {wait / 60:.0f} min, "
                f"behind {blocker}"
            ),
        )

    def _earliest_release_locked(
        self, request: FleetRequest
    ) -> tuple[str | None, datetime | None]:
        relevant = [
            a
            for a in self._assignments.values()
            if a.incident_zone_id == request.incident_zone_id
        ] or list(self._assignments.values())
        if not relevant:
            return None, None
        soonest = min(relevant, key=lambda a: a.expires_utc)
        return soonest.drone_id, soonest.expires_utc + timedelta(seconds=self._turnaround)

    def _expire_locked(self) -> None:
        now = self._clock()
        for request_id, assignment in list(self._assignments.items()):
            if not assignment.is_active_at(now):
                del self._assignments[request_id]
                self._mission_priority.pop(assignment.mission_id, None)

    # -- preemption (advisory) -------------------------------------------

    def preemption_candidates(self) -> tuple[PreemptionCandidate, ...]:
        """Recalls that would unblock a higher-priority queued request.

        **Advisory.** Nothing here recalls anything; it hands the command room the
        decision with the context already assembled.
        """
        with self._lock:
            self._expire_locked()
            if not self._queue:
                return ()

            candidates: list[PreemptionCandidate] = []
            for _key, waiting in self._queue:
                for assignment in self._assignments.values():
                    if assignment.incident_zone_id != waiting.incident_zone_id:
                        continue
                    holder_priority = self._mission_priority.get(assignment.mission_id)
                    if holder_priority is None:
                        continue
                    if holder_priority.rank <= waiting.priority.rank:
                        continue
                    candidates.append(
                        PreemptionCandidate(
                            drone_id=assignment.drone_id,
                            current_mission_id=assignment.mission_id,
                            current_priority=holder_priority,
                            blocking_request_id=waiting.request_id,
                            detail=(
                                f"recalling {assignment.drone_id} would end a "
                                f"{holder_priority.value} mission to serve a "
                                f"{waiting.priority.value} request; this is a human "
                                "decision between two live incidents"
                            ),
                        )
                    )
            return tuple(candidates)

    # -- inspection ------------------------------------------------------

    def queued_requests(self) -> tuple[QueuedRequest, ...]:
        with self._lock:
            self._expire_locked()
            return tuple(self._describe_queued_locked(r) for _k, r in self._queue)

    def assignments(self) -> tuple[Assignment, ...]:
        with self._lock:
            self._expire_locked()
            return tuple(self._assignments.values())

    def status(self) -> dict[str, object]:
        return {
            "assignments": [a.to_dict() for a in self.assignments()],
            "queue_depth": len(self.queued_requests()),
            "queue": [q.to_dict() for q in self.queued_requests()],
            "preemption_candidates": [c.to_dict() for c in self.preemption_candidates()],
        }
