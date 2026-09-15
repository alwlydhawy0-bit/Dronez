"""Lookup seams for mission, zone and fleet state.

These are the facts the policy engine decides on, so every one of them is
**server-derived**. Nothing here reads a value out of a request body: a caller that
could supply its own incident zone or its own fleet availability would be supplying
its own authorization.

In-memory implementations are provided for Milestone 1. The production sources are
PostgreSQL + PostGIS for zones and missions, and the fleet registry for drone state
(Master Plan §4).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

from mcp_server.schemas.incident_zone import IncidentZone
from mcp_server.schemas.tools import DroneStatus
from policy_engine.models import FleetSnapshot

__all__ = [
    "FleetProvider",
    "InMemoryFleetProvider",
    "InMemoryMissionRegistry",
    "MissionBinding",
    "MissionRegistry",
]


@dataclass(frozen=True, slots=True)
class MissionBinding:
    """A mission and the incident zone that authorizes it.

    Master Plan §4: a `Mission` *"links an `IncidentZone`, requesting operator,
    assigned drone(s), and lifecycle state."* The link is the load-bearing part -- it
    is what makes "is this polygon inside the authorized boundary?" a question with a
    single answer.
    """

    mission_id: str
    incident_zone: IncidentZone


class MissionRegistry(Protocol):
    """Resolves a mission id to its authorizing incident zone."""

    def binding_for(self, mission_id: str) -> MissionBinding | None:
        ...


class FleetProvider(Protocol):
    """Supplies fleet facts for a dispatch decision."""

    def snapshot(self, *, incident_zone_id: str, required_endurance_s: float) -> FleetSnapshot:
        ...

    def statuses(self, *, incident_zone_id: str | None = None) -> tuple[DroneStatus, ...]:
        ...


class InMemoryMissionRegistry:
    """Development registry. Thread-safe."""

    def __init__(self, bindings: tuple[MissionBinding, ...] = ()) -> None:
        self._lock = threading.Lock()
        self._bindings = {b.mission_id: b for b in bindings}

    def register(self, binding: MissionBinding) -> None:
        with self._lock:
            self._bindings[binding.mission_id] = binding

    def binding_for(self, mission_id: str) -> MissionBinding | None:
        with self._lock:
            return self._bindings.get(mission_id)


class InMemoryFleetProvider:
    """Development fleet view backed by a list of :class:`DroneStatus`.

    Candidate selection is deliberately simple and deliberately conservative: the
    highest-battery available airframe whose endurance covers the mission plus the
    reserve factor. The policy engine re-checks endurance and battery independently,
    so a defect here produces a denial rather than an unsafe dispatch.
    """

    def __init__(
        self,
        drones: tuple[DroneStatus, ...] = (),
        *,
        endurance_s_by_drone: dict[str, float] | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._drones = list(drones)
        self._endurance = dict(endurance_s_by_drone or {})

    def set_drones(
        self,
        drones: tuple[DroneStatus, ...],
        *,
        endurance_s_by_drone: dict[str, float] | None = None,
    ) -> None:
        with self._lock:
            self._drones = list(drones)
            if endurance_s_by_drone is not None:
                self._endurance = dict(endurance_s_by_drone)

    def statuses(self, *, incident_zone_id: str | None = None) -> tuple[DroneStatus, ...]:
        with self._lock:
            return tuple(self._drones)

    def snapshot(self, *, incident_zone_id: str, required_endurance_s: float) -> FleetSnapshot:
        with self._lock:
            available = [d for d in self._drones if d.available]
            available.sort(key=lambda d: d.battery_pct, reverse=True)
            candidate = next(
                (
                    d
                    for d in available
                    if self._endurance.get(d.drone_id, 0.0) >= required_endurance_s
                ),
                None,
            )
            return FleetSnapshot(
                available_drone_ids=tuple(d.drone_id for d in available),
                candidate_drone_id=candidate.drone_id if candidate else None,
                candidate_battery_pct=candidate.battery_pct if candidate else None,
                candidate_endurance_s=(
                    self._endurance.get(candidate.drone_id) if candidate else None
                ),
            )
