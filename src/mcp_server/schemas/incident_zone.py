"""``IncidentZone`` -- the root authorization envelope.

Closes threat-model item ``TM-01``.

Master Plan §3 makes this the first step of the happy path: *"Command room operator
declares an Incident Zone (boundary polygon, priority, authorized duration) -- this
is the source-of-truth authorization envelope for everything downstream."* §4 lists
its source of truth as the command-room authorization action.

Everything else in the system is checked **against** this object. A flight plan is
legitimate only if its polygon lies inside this boundary, its altitude band lies
inside this ceiling, and the mission runs inside this time window. That makes the
three invariants below the most consequential validation in the codebase:

1. **A zone can only narrow, never widen.** ``altitude_ceiling_m_agl`` is clamped to
   the hard safety envelope, so declaring a zone cannot buy altitude the airframe is
   not allowed to fly. Master Plan §5 requires envelope checks to be *"independent of
   any per-mission override"* -- this is where that independence is established.
2. **A zone is always time-boxed.** ``incident_zone_max_duration_s`` caps the window,
   which is what makes standing surveillance structurally impossible rather than
   merely discouraged (Master Plan §3, out of scope).
3. **Only the command room may declare one.** A field leader can request recon inside
   an existing zone; they cannot mint a new authorization envelope.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, model_validator

from dronez.safety.envelope import ENVELOPE
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.geo import GeoPolygon
from mcp_server.schemas.identity import OperatorIdentity, Role

__all__ = ["IncidentPriority", "IncidentZone", "IncidentZoneStatus"]

IncidentZoneId = Annotated[
    str, Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
]


class IncidentPriority(StrEnum):
    """Declared severity. Arbitrates a contested fleet (Master Plan §3)."""

    P1_CRITICAL = "p1_critical"
    P2_URGENT = "p2_urgent"
    P3_ROUTINE = "p3_routine"


class IncidentZoneStatus(StrEnum):
    """Lifecycle. Only ``ACTIVE`` authorizes anything.

    ``REVOKED`` is deliberately terminal and distinct from ``EXPIRED``: a zone pulled
    by a human is not the same event as one that timed out, and conflating them
    would lose that distinction in the audit trail.
    """

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CLOSED = "closed"


class IncidentZone(StrictModel):
    """The authorization envelope every downstream request is validated against."""

    incident_zone_id: IncidentZoneId
    boundary: GeoPolygon
    priority: IncidentPriority
    status: IncidentZoneStatus

    authorized_from: datetime
    authorized_until: datetime

    #: Mission ceiling for this zone. May be **lower** than the platform envelope,
    #: never higher -- see invariant 1 in the module docstring.
    altitude_ceiling_m_agl: Annotated[float, Field(gt=0.0, le=ENVELOPE.altitude_max_agl_m)]
    altitude_floor_m_agl: Annotated[float, Field(ge=ENVELOPE.altitude_min_agl_m)]

    declared_by: OperatorIdentity
    #: Operators scoped to this zone. Authorization is per-zone, never fleet-wide.
    authorized_operator_ids: Annotated[frozenset[str], Field(max_length=256)]

    #: Free-text incident reference for the case-management system. Operator-supplied
    #: and therefore untrusted for display purposes; never interpreted as an instruction.
    reference: Annotated[str, Field(max_length=256)] = ""

    @model_validator(mode="after")
    def _enforce_root_envelope_invariants(self) -> Self:
        if self.authorized_from.tzinfo is None or self.authorized_until.tzinfo is None:
            raise ValueError("authorization window timestamps must carry an explicit UTC offset")

        if self.authorized_until <= self.authorized_from:
            raise ValueError("authorized_until must be after authorized_from")

        window_s = (self.authorized_until - self.authorized_from).total_seconds()
        if window_s > ENVELOPE.incident_zone_max_duration_s:
            raise ValueError(
                f"authorization window of {window_s:.0f}s exceeds the "
                f"{ENVELOPE.incident_zone_max_duration_s:.0f}s maximum; a longer watch "
                "requires a renewed human authorization, not a longer zone"
            )

        if self.altitude_floor_m_agl >= self.altitude_ceiling_m_agl:
            raise ValueError("altitude_floor_m_agl must be strictly below altitude_ceiling_m_agl")

        # Redundant with the Field bound above, and deliberately so: this is the
        # invariant that stops a per-mission override from buying altitude, and it
        # should fail loudly at the object boundary rather than rely on one annotation.
        if self.altitude_ceiling_m_agl > ENVELOPE.altitude_max_agl_m:
            raise ValueError(
                f"zone ceiling {self.altitude_ceiling_m_agl} m AGL exceeds the platform "
                f"envelope ceiling {ENVELOPE.altitude_max_agl_m} m AGL; a zone may narrow "
                "the envelope, never widen it"
            )

        if self.declared_by.role is not Role.COMMAND_ROOM:
            raise ValueError(
                f"an IncidentZone may only be declared by the command room, not by "
                f"{self.declared_by.role.value!r}"
            )

        if self.declared_by.operator_id not in self.authorized_operator_ids:
            raise ValueError("the declaring operator must be among the authorized operators")

        return self

    def is_active_at(self, when: datetime) -> bool:
        """Whether this zone authorizes anything at ``when``.

        Status and window are checked together. A zone marked ``ACTIVE`` whose window
        has passed does not authorize anything -- the stored status can lag reality,
        so time is checked independently rather than trusted through the flag.
        """
        if self.status is not IncidentZoneStatus.ACTIVE:
            return False
        return self.authorized_from <= when < self.authorized_until

    def remaining_seconds(self, when: datetime | None = None) -> float:
        when = when or datetime.now(UTC)
        return max(0.0, (self.authorized_until - when).total_seconds())

    def to_policy_input(self) -> dict[str, object]:
        """Projection handed to the Rego policies.

        Only the fields the policy actually decides on. Operator free text and PII
        stay out of the policy input: a decision engine that does not receive a value
        cannot leak it in a decision log.
        """
        return {
            "incident_zone_id": self.incident_zone_id,
            "status": self.status.value,
            "priority": self.priority.value,
            "boundary": self.boundary.as_rings(),
            "authorized_from": self.authorized_from.isoformat(),
            "authorized_until": self.authorized_until.isoformat(),
            "altitude_floor_m_agl": self.altitude_floor_m_agl,
            "altitude_ceiling_m_agl": self.altitude_ceiling_m_agl,
            "authorized_operator_ids": sorted(self.authorized_operator_ids),
        }
