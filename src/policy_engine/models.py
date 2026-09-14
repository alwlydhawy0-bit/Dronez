"""Typed inputs and decisions for the deterministic policy gate.

This module builds the JSON document handed to OPA and parses what comes back. It
holds **no authorization logic** -- that lives entirely in the Rego. Duplicating even
one rule here would create a second implementation of the gate, and two
implementations of an authorization decision drift. When they drift, the one that is
wrong is the one nobody is looking at.

What this module *is* responsible for is making sure the policy sees the truth: the
projection below is the only thing the gate gets to reason about, so anything omitted
here is invisible to the decision.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from dronez.airspace.client import ClearanceDecision
from mcp_server.schemas.geo import GeoPolygon
from mcp_server.schemas.identity import OperatorIdentity
from mcp_server.schemas.incident_zone import IncidentZone
from mcp_server.schemas.tools import DeployReconWaypointRequest

__all__ = [
    "DenyReason",
    "FleetSnapshot",
    "PolicyDecision",
    "PolicyPath",
    "build_deploy_recon_waypoint_input",
]


class PolicyPath(StrEnum):
    """Rego decision paths this server queries. One per gated tool."""

    DEPLOY_RECON_WAYPOINT = "dronez/authz/deploy_recon_waypoint/decision"


@dataclass(frozen=True, slots=True)
class DenyReason:
    """One policy violation. Codes are stable and safe to alert on."""

    code: str
    detail: str

    @classmethod
    def parse(cls, raw: Any) -> DenyReason:
        if isinstance(raw, Mapping):
            code = raw.get("code")
            detail = raw.get("detail")
            if isinstance(code, str) and isinstance(detail, str):
                return cls(code=code[:64], detail=detail[:512])
        # An unparseable reason still denies; it just cannot be described precisely.
        return cls(code="unparseable_reason", detail=str(raw)[:512])


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Outcome of one policy evaluation.

    ``allowed`` is true only when the policy said so explicitly. Every constructor
    path other than :meth:`from_opa_result` on a well-formed affirmative response
    produces a denial.
    """

    allowed: bool
    reasons: tuple[DenyReason, ...] = ()
    policy_version: str = ""
    #: True when the denial came from the engine being unusable rather than from a
    #: rule firing. Operationally different: one is a bad request, the other is an
    #: outage that needs paging.
    engine_unavailable: bool = False

    @classmethod
    def deny(cls, code: str, detail: str, *, engine_unavailable: bool = False) -> PolicyDecision:
        return cls(
            allowed=False,
            reasons=(DenyReason(code=code, detail=detail),),
            engine_unavailable=engine_unavailable,
        )

    @classmethod
    def from_opa_result(cls, result: Any) -> PolicyDecision:
        """Parse an OPA ``result`` document, failing closed on anything unexpected."""
        if not isinstance(result, Mapping):
            return cls.deny(
                "policy_malformed",
                f"policy returned {type(result).__name__}, expected an object",
            )

        raw_allow = result.get("allow")
        # Identity check against True, not truthiness. The string "false", the integer
        # 1 and a non-empty list are all truthy, and none of them is a policy saying yes.
        allowed = raw_allow is True

        raw_deny = result.get("deny", [])
        reasons: tuple[DenyReason, ...] = ()
        if isinstance(raw_deny, Sequence) and not isinstance(raw_deny, (str, bytes)):
            reasons = tuple(DenyReason.parse(item) for item in raw_deny[:64])

        version = result.get("policy_version")
        policy_version = version if isinstance(version, str) else ""

        if allowed and reasons:
            # A policy that both allows and lists violations is incoherent. Deny and
            # surface it: this indicates a defect in the Rego, not a bad request.
            incoherent = DenyReason(
                "policy_incoherent",
                f"policy returned allow=true alongside {len(reasons)} denial(s)",
            )
            return cls(
                allowed=False,
                reasons=(incoherent, *reasons),
                policy_version=policy_version,
            )

        if not allowed and not reasons:
            return cls(
                allowed=False,
                reasons=(DenyReason(
                    "policy_denied",
                    "policy denied the request without naming a reason",
                ),),
                policy_version=policy_version,
            )

        return cls(allowed=allowed, reasons=reasons, policy_version=policy_version)

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(r.code for r in self.reasons)

    def audit_record(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "policy_version": self.policy_version,
            "engine_unavailable": self.engine_unavailable,
            "deny": [{"code": r.code, "detail": r.detail} for r in self.reasons],
        }


@dataclass(frozen=True, slots=True)
class FleetSnapshot:
    """Fleet facts the policy decides on. Server-derived, never caller-supplied."""

    available_drone_ids: tuple[str, ...] = ()
    candidate_drone_id: str | None = None
    candidate_battery_pct: float | None = None
    candidate_endurance_s: float | None = None

    def to_policy_input(self) -> dict[str, Any]:
        candidate: dict[str, Any] = {}
        if self.candidate_drone_id is not None:
            candidate["drone_id"] = self.candidate_drone_id
        if self.candidate_battery_pct is not None:
            candidate["battery_pct"] = self.candidate_battery_pct
        if self.candidate_endurance_s is not None:
            candidate["endurance_s"] = self.candidate_endurance_s
        return {
            "available_drone_ids": list(self.available_drone_ids),
            "candidate": candidate,
        }


def _clearance_to_policy_input(
    clearance: ClearanceDecision | None,
    cleared_polygon: GeoPolygon | None,
    cleared_altitude_min_m_agl: float | None,
    cleared_altitude_max_m_agl: float | None,
) -> dict[str, Any] | None:
    """Project a clearance for the policy.

    The cleared *volume* travels with the decision. Without it the policy could only
    check that some clearance exists, not that it covers this request -- and a
    clearance for a different area would sail through.
    """
    if clearance is None:
        return None
    projection: dict[str, Any] = {
        "cleared": clearance.cleared,
        "reason": clearance.reason.value,
        "evaluated_utc": clearance.evaluated_utc.isoformat(),
        "expires_utc": clearance.expires_utc.isoformat(),
        "blocking_zone_ids": list(clearance.blocking_zone_ids),
        "advisory_zone_ids": list(clearance.advisory_zone_ids),
        "feed_age_s": clearance.feed_age_s,
        "feed_sequence": clearance.feed_sequence,
    }
    if cleared_polygon is not None:
        projection["polygon"] = cleared_polygon.as_rings()
    if cleared_altitude_min_m_agl is not None:
        projection["altitude_min_m_agl"] = cleared_altitude_min_m_agl
    if cleared_altitude_max_m_agl is not None:
        projection["altitude_max_m_agl"] = cleared_altitude_max_m_agl
    return projection


def build_deploy_recon_waypoint_input(
    *,
    request: DeployReconWaypointRequest,
    principal: OperatorIdentity,
    incident_zone: IncidentZone,
    clearance: ClearanceDecision | None,
    fleet: FleetSnapshot,
    now: datetime,
    cleared_polygon: GeoPolygon | None = None,
    cleared_altitude_min_m_agl: float | None = None,
    cleared_altitude_max_m_agl: float | None = None,
    supersedes_command_id: str | None = None,
) -> dict[str, Any]:
    """Assemble the OPA input document for a flight-plan proposal.

    Note what is **not** here: no operator free text, no agent rationale, no mission
    description, no urgency flag. Zero-Trust §4.2 -- natural-language claims of
    authority are not a credential, and the cleanest way to guarantee the gate
    ignores them is to never put them in front of it.
    """
    request_projection: dict[str, Any] = {
        "mission_id": request.mission_id,
        "polygon": request.polygon.as_rings(),
        "altitude_min_m_agl": request.altitude_min_m_agl,
        "altitude_max_m_agl": request.altitude_max_m_agl,
        "velocity_max_mps": request.velocity_max_mps,
        "pattern_type": request.pattern_type.value,
        "duration_s": request.duration_s,
    }
    if supersedes_command_id:
        # Carried so the policy can reject a Tier-3 supersession attempt and log it as
        # a security event. Present only when the caller actually asserted it.
        request_projection["supersedes_command_id"] = supersedes_command_id

    document: dict[str, Any] = {
        "now": now.isoformat(),
        "request": request_projection,
        "principal": {
            "operator_id": principal.operator_id,
            "role": principal.role.value,
        },
        "incident_zone": incident_zone.to_policy_input(),
        "fleet": fleet.to_policy_input(),
    }

    clearance_projection = _clearance_to_policy_input(
        clearance, cleared_polygon, cleared_altitude_min_m_agl, cleared_altitude_max_m_agl
    )
    if clearance_projection is not None:
        document["clearance"] = clearance_projection

    return document
