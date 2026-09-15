"""Fleet management: the registry of what each airframe is doing, and who gets it next.

Stdlib only. The registry records; the scheduler decides. Keeping them apart means a
scheduling bug cannot corrupt the picture the command room is looking at while deciding.
"""

from fleet_manager.registry import STALE_TELEMETRY_S, DroneRecord, FleetRegistry
from fleet_manager.scheduler import (
    ArbitrationOutcome,
    Assignment,
    FleetRequest,
    FleetScheduler,
    PreemptionCandidate,
    QueuedRequest,
    RequestPriority,
    SchedulingDecision,
)

__all__ = [
    "STALE_TELEMETRY_S",
    "ArbitrationOutcome",
    "Assignment",
    "DroneRecord",
    "FleetRegistry",
    "FleetRequest",
    "FleetScheduler",
    "PreemptionCandidate",
    "QueuedRequest",
    "RequestPriority",
    "SchedulingDecision",
]
