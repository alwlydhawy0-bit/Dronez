"""Shared fixtures for the fleet registry and scheduler."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dronez.safety.states import DroneState
from fleet_manager import DroneRecord, FleetRegistry, FleetRequest, RequestPriority
from mcp_server.schemas.identity import Role

T0 = datetime(2026, 3, 1, 8, 0, tzinfo=UTC)
ZONE = "IZ-1"


class Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def record(
    drone_id: str,
    *,
    state: DroneState = DroneState.IDLE,
    battery_pct: float = 90.0,
    endurance_s: float = 2400.0,
    last_seen: datetime | None = None,
    grounded: bool = False,
    zone: str | None = ZONE,
    mission_id: str | None = None,
) -> DroneRecord:
    return DroneRecord(
        drone_id=drone_id,
        airframe_type="quad-micro",
        state=state,
        battery_pct=battery_pct,
        endurance_s=endurance_s,
        last_seen_utc=last_seen or T0,
        maintenance_grounded=grounded,
        home_zone_id=zone,
        current_mission_id=mission_id,
    )


def fleet_request(
    request_id: str,
    *,
    priority: RequestPriority = RequestPriority.P2_URGENT,
    role: Role = Role.COMMAND_ROOM,
    duration_s: float = 900.0,
    at: datetime | None = None,
    mission_id: str | None = None,
    zone: str = ZONE,
) -> FleetRequest:
    return FleetRequest(
        request_id=request_id,
        mission_id=mission_id or f"M-{request_id}",
        incident_zone_id=zone,
        priority=priority,
        requester_operator_id="op-1",
        requester_role=role,
        duration_s=duration_s,
        requested_utc=at or T0,
    )


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def registry(clock: Clock) -> FleetRegistry:
    return FleetRegistry(clock=clock)
