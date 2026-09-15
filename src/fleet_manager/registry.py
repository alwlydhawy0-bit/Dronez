"""Fleet registry -- the source of truth for what each airframe is doing.

Master Plan §4 lists the `Drone` entity's source of truth as the fleet registry:
*"Identity, airframe type, current state, battery, maintenance status."* §5 makes
`get_fleet_status` *"read-only ... needed before any dispatch decision can be sanity-
checked by a human."*

Read-only is load-bearing
-------------------------
Nothing in this module dispatches, reserves or commands. It records what is true and
answers questions about it. The scheduler in :mod:`fleet_manager.scheduler` makes
decisions; keeping the two apart means a bug in scheduling cannot corrupt the picture
the command room is looking at while it decides.

Availability is computed, never asserted
----------------------------------------
:meth:`DroneRecord.is_available` derives availability from state, battery and
maintenance rather than storing a flag. A stored flag drifts: something sets it, then
the battery drains, and the flag still says yes. The safety envelope's RTL trigger is
the battery floor, so a drone that cannot be dispatched *and immediately recalled* is
not available.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Final

from dronez.safety.envelope import ENVELOPE
from dronez.safety.states import DroneState, check_transition, is_airborne

__all__ = [
    "STALE_TELEMETRY_S",
    "DroneRecord",
    "FleetRegistry",
    "UnavailableReason",
]

#: A drone whose telemetry is older than this is not dispatchable, whatever it last
#: said. Believing a stale record means dispatching to an airframe whose battery,
#: position and state are all guesses.
STALE_TELEMETRY_S: Final[float] = 30.0


class UnavailableReason(str):
    """Human-readable availability reason. A plain string subclass so it logs cleanly."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class DroneRecord:
    """One airframe, as the registry currently understands it."""

    drone_id: str
    airframe_type: str
    state: DroneState
    battery_pct: float
    #: Flight time the current charge supports, seconds.
    endurance_s: float
    last_seen_utc: datetime
    maintenance_grounded: bool = False
    link_quality_pct: float | None = None
    current_mission_id: str | None = None
    #: Incident zone the airframe is physically positioned for.
    home_zone_id: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.battery_pct <= 100.0:
            raise ValueError("battery_pct must be a percentage")
        if self.endurance_s < 0:
            raise ValueError("endurance_s must be non-negative")
        if self.last_seen_utc.tzinfo is None:
            raise ValueError("last_seen_utc must carry an explicit UTC offset")

    @property
    def is_airborne(self) -> bool:
        return is_airborne(self.state)

    def unavailable_reason(self, now: datetime) -> UnavailableReason | None:
        """Why this drone cannot be dispatched, or ``None`` if it can.

        Returning the reason rather than a boolean is deliberate: an operator looking at
        an empty fleet list needs to know whether everything is flying, everything is
        flat, or the telemetry link is down -- three very different situations.
        """
        if self.maintenance_grounded:
            return UnavailableReason("grounded for maintenance")
        if (now - self.last_seen_utc).total_seconds() > STALE_TELEMETRY_S:
            age = (now - self.last_seen_utc).total_seconds()
            return UnavailableReason(
                f"telemetry is {age:.0f}s stale; its battery and position are guesses"
            )
        if self.state not in (DroneState.IDLE, DroneState.POST_FLIGHT):
            return UnavailableReason(f"in state {self.state.value}")
        if self.battery_pct < ENVELOPE.battery_rtl_trigger_pct:
            return UnavailableReason(
                f"battery {self.battery_pct:.0f}% is below the "
                f"{ENVELOPE.battery_rtl_trigger_pct:.0f}% RTL trigger"
            )
        return None

    def is_available(self, now: datetime) -> bool:
        return self.unavailable_reason(now) is None

    def can_sustain(self, mission_duration_s: float) -> bool:
        """Whether this drone's endurance covers a mission plus the energy reserve."""
        required = mission_duration_s * ENVELOPE.battery_range_reserve_factor
        return self.endurance_s >= required

    def to_dict(self, now: datetime) -> dict[str, object]:
        reason = self.unavailable_reason(now)
        return {
            "drone_id": self.drone_id,
            "airframe_type": self.airframe_type,
            "state": self.state.value,
            "battery_pct": self.battery_pct,
            "endurance_s": self.endurance_s,
            "available": reason is None,
            "unavailable_reason": str(reason) if reason else None,
            "maintenance_grounded": self.maintenance_grounded,
            "link_quality_pct": self.link_quality_pct,
            "current_mission_id": self.current_mission_id,
            "home_zone_id": self.home_zone_id,
            "last_seen_utc": self.last_seen_utc.isoformat(),
        }


class FleetRegistry:
    """Thread-safe record of the fleet. Read-only with respect to dispatch."""

    def __init__(
        self,
        drones: tuple[DroneRecord, ...] = (),
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._drones: dict[str, DroneRecord] = {d.drone_id: d for d in drones}
        self.rejected_transitions = 0

    def upsert(self, record: DroneRecord) -> None:
        """Record a drone's current state, validating the transition.

        A reported transition the airframe cannot physically make is rejected and
        counted. The record is *not* updated: believing an impossible state is worse
        than holding a stale one, because the stale one at least fails the freshness
        check and stops dispatch.
        """
        with self._lock:
            existing = self._drones.get(record.drone_id)
            if existing is not None and existing.state is not record.state:
                check = check_transition(existing.state, record.state, by_ground=False)
                if not check.permitted:
                    self.rejected_transitions += 1
                    return
            self._drones[record.drone_id] = record

    def get(self, drone_id: str) -> DroneRecord | None:
        with self._lock:
            return self._drones.get(drone_id)

    def all_drones(self) -> tuple[DroneRecord, ...]:
        with self._lock:
            return tuple(sorted(self._drones.values(), key=lambda d: d.drone_id))

    def available(
        self, *, mission_duration_s: float | None = None, zone_id: str | None = None
    ) -> tuple[DroneRecord, ...]:
        """Dispatchable drones, best first.

        Ordered by battery descending: picking the fullest airframe leaves the most
        margin for a mission that overruns, and spreads wear across the fleet less
        unevenly than always picking the same one.
        """
        now = self._clock()
        candidates = [d for d in self.all_drones() if d.is_available(now)]
        if mission_duration_s is not None:
            candidates = [d for d in candidates if d.can_sustain(mission_duration_s)]
        if zone_id is not None:
            candidates = [d for d in candidates if d.home_zone_id in (None, zone_id)]
        return tuple(sorted(candidates, key=lambda d: d.battery_pct, reverse=True))

    def airborne_in_zone(self, zone_id: str) -> tuple[DroneRecord, ...]:
        """Airborne drones positioned for a zone -- the emergency-stop target set."""
        return tuple(
            d for d in self.all_drones() if d.is_airborne and d.home_zone_id == zone_id
        )

    def mark_maintenance(self, drone_id: str, *, grounded: bool) -> bool:
        """Ground or release an airframe.

        Master Plan §4: a `MaintenanceRecord` *"grounds a drone from availability
        independent of mission demand."* Independent is the point -- a busy incident
        does not make an airframe airworthy.
        """
        with self._lock:
            record = self._drones.get(drone_id)
            if record is None:
                return False
            self._drones[drone_id] = replace(record, maintenance_grounded=grounded)
            return True

    def snapshot(self, *, zone_id: str | None = None) -> dict[str, object]:
        now = self._clock()
        drones = self.all_drones()
        if zone_id is not None:
            drones = tuple(d for d in drones if d.home_zone_id in (None, zone_id))
        return {
            "queried_utc": now.isoformat(),
            "total": len(drones),
            "available": sum(1 for d in drones if d.is_available(now)),
            "airborne": sum(1 for d in drones if d.is_airborne),
            "grounded": sum(1 for d in drones if d.maintenance_grounded),
            "drones": [d.to_dict(now) for d in drones],
        }

    def __len__(self) -> int:
        with self._lock:
            return len(self._drones)
