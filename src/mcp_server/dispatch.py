"""The hardware dispatch seam.

**Nothing in this repository dispatches to hardware.** This module is the single,
explicit place where that would happen, and the default implementation refuses.

Why it exists as a refusing seam rather than not at all
-------------------------------------------------------
The confirmation path has to *end* somewhere, and the end needs to be visible. A
codebase where dispatch is simply absent invites the next contributor to add a
MAVLink publish call wherever it happens to be convenient -- inside the confirm
handler, or worse, inside the policy layer. A named seam that fails closed makes the
boundary reviewable: there is exactly one place to look, one place to change, and a
test asserting it currently refuses.

The gate
--------
Master Plan §6, Milestone 0: *"No flight-capable code is written before this milestone
closes."* Three Milestone-0 criteria remain open (``CLAUDE.md`` §2), including the
accountable-owner sign-off on the safety envelope and the live sovereign NFZ endpoint.

Implementing :class:`HardwareDispatcher` for real is Milestone 1's final step and must
not happen before those close. When it does, it must also satisfy:

* MAVLink2 message signing on every command link (Zero-Trust §4.3).
* mTLS to the companion computer, with firmware attestation checked before the
  platform is admitted to a mission (§4.3).
* The 2 commands/second per-agent dispatch limit (§4.1) -- a separate limiter
  instance from the proposal limit.
* **No override of a firmware-initiated fail-safe, ever** (§4.1). The dispatcher
  requests actions inside the envelope; it is never the last line of defence for one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from mcp_server.store import StagedFlightPlan

__all__ = [
    "MILESTONE_0_GATE_DETAIL",
    "DispatchOutcome",
    "DispatchResult",
    "GatedDispatcher",
    "HardwareDispatcher",
]

MILESTONE_0_GATE_DETAIL = (
    "hardware dispatch is not implemented: the Milestone-0 gate is open "
    "(safety-envelope sign-off, live sovereign NFZ endpoint, and GACA licensing "
    "remain outstanding). The plan was fully authorized and has been recorded, "
    "but nothing has been sent to an airframe."
)


class DispatchOutcome(StrEnum):
    DISPATCHED = "dispatched"
    REFUSED_GATE = "refused_milestone_gate"
    REFUSED_TRANSPORT = "refused_transport"
    REFUSED_ATTESTATION = "refused_attestation"


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """Outcome of a dispatch attempt. ``dispatched`` is true only on a real send."""

    dispatched: bool
    outcome: DispatchOutcome
    detail: str
    drone_id: str | None = None
    dispatched_utc: datetime | None = None


class HardwareDispatcher(Protocol):
    """Seam to the airframe.

    Implementations must never raise into the request path; a transport failure is a
    refusal, recorded as such.
    """

    def dispatch(self, plan: StagedFlightPlan) -> DispatchResult:
        ...


class GatedDispatcher:
    """The default. Refuses every dispatch, and says exactly why.

    This is not a stub that "will be filled in later" in the casual sense -- it is the
    enforcement point for the Milestone-0 gate. The accompanying test asserts that a
    fully authorized, human-confirmed plan still does not reach hardware.
    """

    def dispatch(self, plan: StagedFlightPlan) -> DispatchResult:
        return DispatchResult(
            dispatched=False,
            outcome=DispatchOutcome.REFUSED_GATE,
            detail=MILESTONE_0_GATE_DETAIL,
            drone_id=plan.assigned_drone_id,
        )
