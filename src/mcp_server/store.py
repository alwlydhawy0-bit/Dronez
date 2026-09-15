"""Staging store for authorized-but-unconfirmed flight plans.

A plan that clears the policy gate is **staged**, not dispatched. It sits here until
a human confirms it, and the properties of this store are what make that confirmation
meaningful rather than ceremonial:

* **Digest-addressed.** The digest is computed from the canonical plan, and
  confirmation must present the same digest. If anything about the staged plan changed
  between the operator reading the map overlay and the confirmation arriving, the
  digest no longer matches -- closing the TOCTOU window that would otherwise let a
  reviewed plan be swapped for a different one.
* **Single-use.** A staged plan is consumed atomically. Two confirmations of the same
  plan cannot both succeed, so a captured confirmation cannot dispatch a second
  sortie.
* **Time-boxed to its clearance.** A plan expires when the airspace clearance it was
  authorized against expires. Master Plan §5 requires an affirmative, *current*
  clearance before dispatch; letting a staged plan outlive its clearance would
  reintroduce exactly the stale-authorization problem the validity window closes.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from mcp_server.schemas.tools import DeployReconWaypointRequest

__all__ = [
    "MAX_STAGED_PLANS",
    "ConsumeFailure",
    "ConsumeResult",
    "FlightPlanStore",
    "StagedFlightPlan",
    "compute_plan_digest",
]

#: Bound on concurrently staged plans. Staging is gated by authentication and the
#: policy engine, so this bounds a defect rather than normal operation.
MAX_STAGED_PLANS: Final[int] = 4096


def compute_plan_digest(
    *,
    flight_plan_id: str,
    request: DeployReconWaypointRequest,
    incident_zone_id: str,
    assigned_drone_id: str | None,
    clearance_expires_utc: datetime,
) -> str:
    """SHA-256 over the canonical staged plan.

    Everything that changes what would actually fly is inside the digest: the
    geometry, the envelope, the assigned airframe, and the clearance window it was
    authorized against. A digest that covered only the identifier would let the plan
    behind that identifier change without detection.
    """
    canonical = {
        "v": 1,
        "flight_plan_id": flight_plan_id,
        "mission_id": request.mission_id,
        "incident_zone_id": incident_zone_id,
        "polygon": request.polygon.as_rings(),
        "altitude_min_m_agl": request.altitude_min_m_agl,
        "altitude_max_m_agl": request.altitude_max_m_agl,
        "velocity_max_mps": request.velocity_max_mps,
        "pattern_type": request.pattern_type.value,
        "duration_s": request.duration_s,
        "assigned_drone_id": assigned_drone_id,
        "clearance_expires_utc": clearance_expires_utc.astimezone(UTC).isoformat(),
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True, slots=True)
class StagedFlightPlan:
    """An authorized plan awaiting human confirmation. Nothing is flying."""

    flight_plan_id: str
    digest: str
    request: DeployReconWaypointRequest
    incident_zone_id: str
    assigned_drone_id: str | None
    proposed_by_operator_id: str
    proposed_by_role: str
    staged_utc: datetime
    #: Expiry of the airspace clearance this plan was authorized against.
    expires_utc: datetime
    policy_version: str

    def is_valid_at(self, when: datetime) -> bool:
        return when < self.expires_utc

    def audit_projection(self) -> dict[str, Any]:
        return {
            "flight_plan_id": self.flight_plan_id,
            "digest": self.digest,
            "mission_id": self.request.mission_id,
            "incident_zone_id": self.incident_zone_id,
            "assigned_drone_id": self.assigned_drone_id,
            "proposed_by": self.proposed_by_operator_id,
            "proposed_by_role": self.proposed_by_role,
            "staged_utc": self.staged_utc.isoformat(),
            "expires_utc": self.expires_utc.isoformat(),
            "policy_version": self.policy_version,
        }


class ConsumeFailure(StrEnum):
    """Why a staged plan could not be consumed. Each is an auditable event."""

    NOT_FOUND = "flight_plan_not_found"
    DIGEST_MISMATCH = "plan_digest_mismatch"
    EXPIRED = "flight_plan_expired"
    ALREADY_CONSUMED = "flight_plan_already_consumed"
    WRONG_ZONE = "flight_plan_zone_mismatch"


@dataclass(frozen=True, slots=True)
class ConsumeResult:
    """Outcome of a consume attempt. ``plan`` is populated only on success."""

    plan: StagedFlightPlan | None
    failure: ConsumeFailure | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.plan is not None and self.failure is None


class FlightPlanStore:
    """Thread-safe, bounded store of staged plans.

    In-memory at Milestone 1. A multi-instance deployment needs this backed by the
    shared datastore, because a plan staged on one instance must be confirmable on
    another and single-use consumption must hold across all of them -- a per-instance
    store would let the same plan be confirmed once per instance.
    """

    def __init__(
        self,
        *,
        max_plans: int = MAX_STAGED_PLANS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._max = max_plans
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._plans: dict[str, StagedFlightPlan] = {}
        #: Consumed ids are remembered so a second confirmation gets ALREADY_CONSUMED
        #: rather than the indistinguishable NOT_FOUND. The difference matters: one is
        #: a duplicate submission, the other may be an attacker probing for a plan id.
        self._consumed: dict[str, datetime] = {}
        #: Expired ids are tracked SEPARATELY from consumed ones. Collapsing them would
        #: report a plan that timed out as one that was already confirmed, which sends
        #: an operator looking for a confirmation that never happened.
        self._expired: dict[str, datetime] = {}

    def stage(self, plan: StagedFlightPlan) -> bool:
        """Stage a plan. Returns ``False`` if the store is full or the id is in use."""
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            if plan.flight_plan_id in self._plans or plan.flight_plan_id in self._consumed:
                return False
            if len(self._plans) >= self._max:
                return False
            self._plans[plan.flight_plan_id] = plan
            return True

    def peek(self, flight_plan_id: str) -> StagedFlightPlan | None:
        """Read without consuming. For status display only -- never for dispatch."""
        with self._lock:
            return self._plans.get(flight_plan_id)

    def consume(
        self,
        flight_plan_id: str,
        digest: str,
        *,
        expected_zone_id: str | None = None,
    ) -> ConsumeResult:
        """Atomically validate and remove a staged plan.

        Check-and-remove happen under one lock, so two concurrent confirmations cannot
        both succeed. That is the property that stops a captured confirmation from
        dispatching twice.
        """
        now = self._clock()
        with self._lock:
            plan = self._plans.get(flight_plan_id)
            if plan is None:
                # Look the requested id up BEFORE pruning: pruning first would sweep an
                # expired plan into the consumed set and report it as already confirmed.
                if flight_plan_id in self._consumed:
                    return ConsumeResult(
                        None,
                        ConsumeFailure.ALREADY_CONSUMED,
                        "this flight plan has already been confirmed",
                    )
                if flight_plan_id in self._expired:
                    return ConsumeResult(
                        None,
                        ConsumeFailure.EXPIRED,
                        "the airspace clearance this plan was authorized against has "
                        "expired; re-propose to obtain a current clearance",
                    )
                return ConsumeResult(
                    None, ConsumeFailure.NOT_FOUND, "no such staged flight plan"
                )

            # Constant-time comparison: the digest is a secret-adjacent value an
            # attacker would otherwise be able to discover byte by byte through timing.
            if not _constant_time_equal(plan.digest, digest):
                return ConsumeResult(
                    None,
                    ConsumeFailure.DIGEST_MISMATCH,
                    "the confirmed digest does not match the staged plan; the plan may "
                    "have changed since it was reviewed",
                )

            if not plan.is_valid_at(now):
                del self._plans[flight_plan_id]
                self._expired[flight_plan_id] = now
                return ConsumeResult(
                    None,
                    ConsumeFailure.EXPIRED,
                    "the airspace clearance this plan was authorized against has expired; "
                    "re-propose to obtain a current clearance",
                )

            if expected_zone_id is not None and plan.incident_zone_id != expected_zone_id:
                return ConsumeResult(
                    None,
                    ConsumeFailure.WRONG_ZONE,
                    "the confirming operator is scoped to a different incident zone",
                )

            del self._plans[flight_plan_id]
            self._consumed[flight_plan_id] = now
            self._prune_locked(now)
            return ConsumeResult(plan)

    def _prune_locked(self, now: datetime) -> None:
        for pid in [p for p, plan in self._plans.items() if not plan.is_valid_at(now)]:
            del self._plans[pid]
            self._expired[pid] = now

        # Terminal ids are retained only as long as a plan could plausibly still be
        # re-submitted; past that they are indistinguishable from never having existed.
        cutoff = now.timestamp() - 3600.0
        for table in (self._consumed, self._expired):
            for pid in [p for p, at in table.items() if at.timestamp() <= cutoff]:
                del table[pid]

    def __len__(self) -> int:
        with self._lock:
            return len(self._plans)


def _constant_time_equal(a: str, b: str) -> bool:
    import hmac as _hmac

    return _hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
