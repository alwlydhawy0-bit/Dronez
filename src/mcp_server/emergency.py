"""The emergency-stop broadcast channel.

Master Plan §3: *"a field leader or command operator can issue a broadcast
emergency-stop that forces every drone in the affected zone to immediate RTL, delivered
over a channel **independent of the primary command path**."* §5: *"callable by any
authenticated field leader physically in the affected zone without needing command-room
mediation."*

Why independence is the whole design
------------------------------------
An emergency stop is needed precisely when something has gone wrong -- and one of the
things that may have gone wrong is the primary command path. A stop that travels down
the same path as the commands it is trying to cancel is worth nothing in the case it
exists for.

So :class:`EmergencyBroadcastChannel` is a separate seam with separate transport and
separate credentials. :func:`assert_channel_independence` refuses a configuration where
the stop channel and the dispatcher share an object, because a shared object means a
shared failure.

The inverted fail-safe rule
---------------------------
Everywhere else in this system, an incomplete security check means **deny**. Here it
does not, and the distinction matters enough to state plainly:

> **Fail-closed means denying *authority*, not denying *safety actions*.**

An emergency stop makes the fleet strictly *less* capable: drones land or return. The
failure modes are asymmetric:

* A spurious stop grounds the fleet. Disruptive, recoverable, visible.
* A blocked stop leaves drones flying when a human has decided they should not be.

So the policy engine is **not** consulted. If OPA is down, the stop still goes. What is
still required is a valid hardware-bound signature -- without it, an unauthenticated
stop would be a denial-of-service primitive against the whole fleet, and that failure
mode is not benign either. Signature yes, policy engine no.

Proximity is recorded, not gated
--------------------------------
§5 describes a field leader *physically in* the affected zone. Device position is
self-reported and spoofable, so making it a hard gate would add no real security while
creating a way for a legitimate stop to be refused. It is recorded for the audit trail
and for review; zone authorization is what actually gates the action.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from dronez.authz import Role
from mcp_server.audit import AuditTrail, Outcome

__all__ = [
    "BroadcastResult",
    "ChannelIndependenceError",
    "DeliveryReceipt",
    "EmergencyBroadcastChannel",
    "EmergencyStop",
    "EmergencyStopService",
    "StopReason",
    "StopScope",
    "assert_channel_independence",
]


class StopScope(StrEnum):
    ZONE = "zone"
    SINGLE_DRONE = "single_drone"


class StopReason(StrEnum):
    """Why the stop was issued. Recorded; never used to gate the action."""

    PERSONNEL_AT_RISK = "personnel_at_risk"
    MANNED_AIRCRAFT = "manned_aircraft"
    LOSS_OF_CONTROL = "loss_of_control"
    AIRSPACE_VIOLATION = "airspace_violation"
    OPERATOR_JUDGEMENT = "operator_judgement"
    DRILL = "drill"


@dataclass(frozen=True, slots=True)
class EmergencyStop:
    """A broadcast stop command."""

    stop_id: str
    scope: StopScope
    incident_zone_id: str
    reason: StopReason
    issued_by_operator_id: str
    issued_by_role: Role
    issued_utc: datetime
    drone_id: str | None = None
    #: Self-reported device position at issue time. Recorded, not gated. See module docs.
    proximity_attestation: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.scope is StopScope.SINGLE_DRONE and not self.drone_id:
            raise ValueError("a single-drone stop must name the drone")
        if self.scope is StopScope.ZONE and self.drone_id:
            raise ValueError("a zone-wide stop must not name a single drone")
        if self.issued_by_role is Role.AI_AGENT:
            raise ValueError(
                "an AI agent may not issue an emergency stop; a stop is a human "
                "judgement about physical safety (Master Plan Sec.5)"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "stop_id": self.stop_id,
            "scope": self.scope.value,
            "incident_zone_id": self.incident_zone_id,
            "reason": self.reason.value,
            "issued_by_operator_id": self.issued_by_operator_id,
            "issued_by_role": self.issued_by_role.value,
            "issued_utc": self.issued_utc.isoformat(),
            "drone_id": self.drone_id,
            "proximity_attested": bool(self.proximity_attestation),
        }


@dataclass(frozen=True, slots=True)
class DeliveryReceipt:
    """Per-drone delivery outcome."""

    drone_id: str
    delivered: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class BroadcastResult:
    """Outcome of one broadcast.

    ``delivered`` and ``undelivered`` are reported separately and both are populated.
    A partial broadcast that reported only successes would let an operator believe the
    zone was clear while a drone that never received the stop kept flying -- which is
    the one thing they must not be able to believe wrongly.
    """

    stop_id: str
    attempted: tuple[str, ...]
    receipts: tuple[DeliveryReceipt, ...]
    broadcast_utc: datetime
    channel: str

    @property
    def delivered(self) -> tuple[str, ...]:
        return tuple(r.drone_id for r in self.receipts if r.delivered)

    @property
    def undelivered(self) -> tuple[str, ...]:
        return tuple(r.drone_id for r in self.receipts if not r.delivered)

    @property
    def complete(self) -> bool:
        return bool(self.attempted) and not self.undelivered

    def to_dict(self) -> dict[str, Any]:
        return {
            "stop_id": self.stop_id,
            "channel": self.channel,
            "broadcast_utc": self.broadcast_utc.isoformat(),
            "attempted": list(self.attempted),
            "delivered": list(self.delivered),
            "undelivered": list(self.undelivered),
            "complete": self.complete,
        }


class EmergencyBroadcastChannel(Protocol):
    """Out-of-band path to every airframe in a zone.

    Implementations MUST NOT route through the primary command path, the policy engine,
    or the MCP dispatch queue. In deployment this is a dedicated low-bitrate RF channel
    -- a stop is a handful of bytes and needs to survive conditions under which video and
    telemetry do not.

    ``channel_name`` is used by :func:`assert_channel_independence` and appears in the
    audit record, so a deployment that quietly reverted to the primary path is visible
    in the log rather than only in a diagram.
    """

    @property
    def channel_name(self) -> str:
        ...

    def broadcast(
        self, stop: EmergencyStop, drone_ids: tuple[str, ...]
    ) -> tuple[DeliveryReceipt, ...]:
        ...


class ChannelIndependenceError(RuntimeError):
    """The stop channel is not independent of the primary command path."""


def assert_channel_independence(
    channel: EmergencyBroadcastChannel, dispatcher: object
) -> None:
    """Refuse a configuration where the stop shares the path it must survive.

    A structural check, not a proof: it catches the same-object and same-transport
    cases, which is what a refactor is most likely to introduce. Genuine RF independence
    is a deployment property that has to be verified physically, and is recorded as a
    Milestone-4 HIL gate rather than claimed here.
    """
    if channel is dispatcher:
        raise ChannelIndependenceError(
            "the emergency-stop channel and the dispatcher are the same object; a stop "
            "that travels down the path it is cancelling is worth nothing in the case "
            "it exists for"
        )
    channel_transport = getattr(channel, "_transport", None)
    dispatcher_transport = getattr(dispatcher, "_transport", None)
    if channel_transport is not None and channel_transport is dispatcher_transport:
        raise ChannelIndependenceError(
            "the emergency-stop channel shares a transport with the dispatcher; a "
            "shared transport is a shared failure"
        )


class EmergencyStopService:
    """Issues stops. Deliberately short, and deliberately not gated on the policy engine."""

    def __init__(
        self,
        channel: EmergencyBroadcastChannel,
        audit: AuditTrail,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._channel = channel
        self._audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))
        self.stops_issued = 0

    def broadcast(
        self,
        stop: EmergencyStop,
        drone_ids: tuple[str, ...],
        *,
        session_id: str | None = None,
        payload: bytes = b"",
    ) -> BroadcastResult:
        """Send the stop and record it. Never raises.

        A transport failure produces a result with everything undelivered rather than an
        exception, because the caller must be told *which* drones were not reached --
        and an exception carries no such list.
        """
        now = self._clock()
        try:
            receipts = self._channel.broadcast(stop, drone_ids)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as exc:
            receipts = tuple(
                DeliveryReceipt(
                    drone_id=drone_id,
                    delivered=False,
                    detail=f"broadcast channel raised {type(exc).__name__}",
                )
                for drone_id in drone_ids
            )

        result = BroadcastResult(
            stop_id=stop.stop_id,
            attempted=drone_ids,
            receipts=receipts,
            broadcast_utc=now,
            channel=self._channel.channel_name,
        )
        self.stops_issued += 1

        # A stop is always a P1-visible event, whether or not it was complete. An
        # incomplete one is more urgent, not less.
        self._audit.record(
            tool="request_emergency_stop",
            outcome=Outcome.ACCEPTED if result.complete else Outcome.ERROR,
            payload=payload,
            operator_id=stop.issued_by_operator_id,
            role=stop.issued_by_role.value,
            session_id=session_id,
            decision={"stop": stop.to_dict(), "broadcast": result.to_dict()},
            reason_codes=() if result.complete else ("emergency_stop_partial_delivery",),
            detail=(
                f"emergency stop {stop.stop_id} broadcast over {result.channel}: "
                f"{len(result.delivered)}/{len(result.attempted)} delivered"
            ),
        )
        return result


class InMemoryBroadcastChannel:
    """Development channel. Records what would have gone out.

    **Not the real path.** The deployed channel is a dedicated RF link; this exists so
    the stop path can be exercised without one, and it names itself distinctly so a
    deployment running on it is obvious in the audit log.
    """

    channel_name = "in-memory-development-channel"

    def __init__(self, *, unreachable: frozenset[str] = frozenset()) -> None:
        self._unreachable = unreachable
        self.broadcasts: list[tuple[EmergencyStop, tuple[str, ...]]] = []

    def broadcast(
        self, stop: EmergencyStop, drone_ids: tuple[str, ...]
    ) -> tuple[DeliveryReceipt, ...]:
        self.broadcasts.append((stop, drone_ids))
        return tuple(
            DeliveryReceipt(
                drone_id=drone_id,
                delivered=drone_id not in self._unreachable,
                detail="" if drone_id not in self._unreachable else "no response",
            )
            for drone_id in drone_ids
        )


def new_stop_id() -> str:
    return f"stop-{uuid.uuid4().hex[:16]}"
