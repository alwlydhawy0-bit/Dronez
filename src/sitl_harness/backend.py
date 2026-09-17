"""The backend seam: where a scenario meets something that can run it.

Three implementations are contemplated, and only the first exists here:

======================  ========================  ==============================
Backend                 Evidence class            Status
======================  ========================  ==============================
``SimulatedFirmware``   ``MODEL_ONLY``            Implemented (``model.py``)
``Px4SitlBackend``      ``SOFTWARE_IN_THE_LOOP``  **Not implemented** -- below
``HilRigBackend``       ``HARDWARE_IN_THE_LOOP``  **Not implemented** -- no rig
======================  ========================  ==============================

Why the other two raise instead of existing
-------------------------------------------
Driving PX4 means publishing MAVLink, and CLAUDE.md §2.1 forbids a MAVLink publisher
in this repository until the Milestone-0 gate closes. That is not an inconvenience to
work around: the seam is the honest place to stop, and a stub that pretended to run
SITL would produce green output attesting to nothing.

So :class:`Px4SitlBackend` and :class:`HilRigBackend` raise
:class:`BackendUnavailable` with the reason. ``scripts/run_hil.py --require-hardware``
turns that into a non-zero exit, which is what CI gates on -- a suite that silently
falls back to the model is a suite that reports success for work nobody did.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from dronez.safety.states import DroneState
from sitl_harness.scenarios import EvidenceClass, Fault, Scenario

__all__ = [
    "BackendUnavailable",
    "HilRigBackend",
    "Observation",
    "Px4SitlBackend",
    "SitlBackend",
]


class BackendUnavailable(RuntimeError):
    """This backend cannot run here, and says why."""


@dataclass(frozen=True, slots=True)
class Observation:
    """What the harness saw, stated as external observations only.

    Nothing here is an internal call or a private variable: every field is something
    a rig could measure from outside the airframe. That is what lets the same oracle
    judge a model, SITL, and real hardware without being rewritten for each.
    """

    #: Ordered states entered, including the initial one.
    state_trace: tuple[DroneState, ...]
    #: Mean descent rate while in the terminal descent, m/s.
    descent_rate_mps: float | None = None
    #: Whether any lateral translation was commanded (avoidance is not).
    commanded_lateral_translation: bool = False
    #: Smallest obstacle clearance observed, metres.
    min_obstacle_clearance_m: float | None = None
    disarmed: bool = False
    #: Flags raised in telemetry during the run.
    telemetry_flags: frozenset[str] = frozenset()
    #: Inbound commands the airframe did not act on.
    ignored_commands: frozenset[Fault] = frozenset()
    #: Free-text notes for the report.
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def final_state(self) -> DroneState:
        return self.state_trace[-1]


@runtime_checkable
class SitlBackend(Protocol):
    """Runs one scenario and reports what happened."""

    @property
    def name(self) -> str: ...

    @property
    def evidence_class(self) -> EvidenceClass: ...

    def run(self, scenario: Scenario) -> Observation: ...


_NO_PUBLISHER = (
    "Driving {target} requires publishing MAVLink, and CLAUDE.md §2.1 forbids a "
    "MAVLink/ROS2 publisher in this repository until the Milestone-0 gate closes. "
    "This backend is a declared seam, not an omission: run the scenarios against "
    "{target} from the {where}, where the publisher legitimately lives, and feed the "
    "observations back through `sitl_harness.runner`."
)


class Px4SitlBackend:
    """PX4/Gazebo software-in-the-loop. **Not implemented.**"""

    name = "px4-gazebo-sitl"
    evidence_class = EvidenceClass.SOFTWARE_IN_THE_LOOP

    def run(self, scenario: Scenario) -> Observation:
        raise BackendUnavailable(
            _NO_PUBLISHER.format(target="PX4/Gazebo SITL", where="SITL test rig repo")
        )


class HilRigBackend:
    """The hardware rig. **Not implemented, and no rig exists** (`TM-12`)."""

    name = "hil-rig"
    evidence_class = EvidenceClass.HARDWARE_IN_THE_LOOP

    def run(self, scenario: Scenario) -> Observation:
        raise BackendUnavailable(
            "No hardware-in-the-loop rig exists (TM-12), and no airframe has been "
            "selected (TM-27, CLAUDE.md §4.1). This is the backend whose results would "
            "close both items; until it runs, the degraded-landing constants remain "
            "engineering defaults and HIL-D-05 -- the single most important test in the "
            "programme -- is unexecuted."
        )
