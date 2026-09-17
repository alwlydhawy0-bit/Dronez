"""A model of the firmware's fail-safe logic, for exercising the scenarios.

**Read this before trusting anything it outputs.**

This is a *test double*, written from ``docs/07-degraded-landing-firmware-spec.md``.
It is not flight-capable code, commands no hardware, opens no socket, and will never
be loaded onto an airframe. It exists so the scenario suite and its oracles can be
executed and debugged before a rig exists.

The epistemics, stated plainly
------------------------------
A model written from a specification agrees with that specification. Running the
scenarios against it therefore proves:

* the scenarios are well-formed and internally consistent;
* the oracles reject the behaviours they are meant to reject (the mutation tests in
  ``tests/hil/test_oracles.py`` demonstrate this directly);
* the spec is unambiguous enough to be implemented from, which is a weaker claim than
  correctness but not a worthless one -- writing this model is what surfaced that
  ``HIL-R-03``'s expected end state contradicted §2.3 of the spec it came from.

It proves **nothing** about PX4, ArduPilot, or any airframe. ``TM-12`` and ``TM-27``
stay open, and :class:`~sitl_harness.scenarios.EvidenceClass` carries that fact into
every report rather than leaving it to a reader's memory.

Where the model is deliberately cruder than real firmware
---------------------------------------------------------
Time is a fixed-step integration at :data:`TICK_S`; there is no attitude control, no
aerodynamics, no sensor noise, and obstacle avoidance is a single scripted intrusion.
None of that matters for the properties under test, which are about *state transitions
and what is refused* -- but it means a passing run says nothing about, say, whether
0.5 m/s is actually slow enough for a given LiDAR array. That question needs the rig.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from dronez.safety.envelope import ENVELOPE
from dronez.safety.states import DroneState
from sitl_harness.backend import Observation
from sitl_harness.scenarios import EvidenceClass, Fault, Scenario

__all__ = ["TICK_S", "SimulatedFirmware"]

#: Integration step. Fine enough that the 2 s debounce and the 5 s link grace are
#: resolved to well inside a tick.
TICK_S: Final[float] = 0.1

#: How long the model runs before giving up, seconds. A descent from the 120 m ceiling
#: at 0.5 m/s takes 240 s, so this leaves room for obstacle holds without hanging a
#: test run on a model defect.
MAX_RUN_S: Final[float] = 900.0

_DVIL: Final = DroneState.DEGRADED_VISUAL_INERTIAL_LANDING

_GROUND_COMMANDS: Final[frozenset[Fault]] = frozenset({
    Fault.GROUND_COMMANDS_RTL,
    Fault.GROUND_COMMANDS_DISARM,
    Fault.GROUND_COMMANDS_EXIT_FAILSAFE,
})


@dataclass(slots=True)
class _Airframe:
    """Mutable run state."""

    state: DroneState
    altitude_m: float
    battery_pct: float
    trace: list[DroneState] = field(default_factory=list)
    descent_samples: list[float] = field(default_factory=list)
    min_clearance_m: float | None = None
    commanded_lateral: bool = False
    disarmed: bool = False
    flags: set[str] = field(default_factory=set)
    ignored: set[Fault] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    def enter(self, state: DroneState) -> None:
        if self.state is state:
            return
        self.state = state
        self.trace.append(state)


class SimulatedFirmware:
    """Fixed-step model of the fail-safe state machine."""

    name = "simulated-firmware-model"
    evidence_class = EvidenceClass.MODEL_ONLY

    def run(self, scenario: Scenario) -> Observation:
        air = _Airframe(
            state=scenario.initial_state,
            altitude_m=scenario.initial_altitude_m,
            battery_pct=scenario.initial_battery_pct,
        )
        air.trace.append(scenario.initial_state)

        faults = set(scenario.faults)
        # Faults that arrive partway through rather than at t=0. Modelled as
        # scheduled events so "recovers mid-descent" means what it says.
        deferred = {
            Fault.GNSS_RESTORED,
            Fault.VISION_RESTORED,
            Fault.LIDAR_ARRAY_FAILED,
            Fault.OBSTACLE_INTRUSION,
            Fault.BATTERY_DRAINED_TO_CRITICAL,
        } & faults
        active = faults - deferred

        gnss_bad_for_s = 0.0
        link_lost_for_s = 0.0
        dvil_elapsed_s = 0.0
        elapsed = 0.0
        autonomous_failsafe = False

        while elapsed < MAX_RUN_S:
            elapsed += TICK_S

            # -- deferred faults fire once the descent is genuinely under way, which
            #    is what "mid-descent" means in the spec.
            if deferred and air.state is _DVIL and dvil_elapsed_s >= 2.0:
                active |= deferred
                deferred = set()

            gnss_denied = bool(
                active & {Fault.GNSS_DENIED, Fault.GNSS_SPOOFED_DIVERGING}
            ) and Fault.GNSS_RESTORED not in active
            vision_lost = (
                Fault.OPTICAL_LOST in active
                and Fault.THERMAL_LOST in active
                and Fault.VISION_RESTORED not in active
            )

            # -- ground commands are recorded as ignored for as long as the airframe is
            #    under autonomous fail-safe control. Latched off the *history*, not the
            #    current state: RTL_TRIGGERED is transited in a single tick on the way to
            #    LANDING, so a current-state test would miss a command arriving during the
            #    descent -- precisely the window HIL-R-05 probes. Once the firmware has
            #    taken control it keeps it through LANDING and touchdown.
            if not autonomous_failsafe and any(
                s in air.trace
                for s in (DroneState.FAILSAFE, _DVIL, DroneState.RTL_TRIGGERED)
            ):
                autonomous_failsafe = True
            if autonomous_failsafe:
                air.ignored |= _GROUND_COMMANDS & active

            # -- link loss: a handled trigger with a bounded grace period.
            if Fault.C2_LINK_SEVERED in active and air.state not in (
                DroneState.FAILSAFE,
                _DVIL,
            ):
                link_lost_for_s += TICK_S
                if link_lost_for_s >= TICK_S:
                    air.enter(DroneState.LOST_LINK)
                if link_lost_for_s >= ENVELOPE.link_loss_grace_s and not vision_lost:
                    air.enter(DroneState.FAILSAFE)
                    air.enter(DroneState.RTL_TRIGGERED)

            # -- the dual-failure predicate, debounced.
            if gnss_denied and vision_lost:
                gnss_bad_for_s += TICK_S
            else:
                gnss_bad_for_s = 0.0

            if (
                gnss_bad_for_s >= ENVELOPE.gnss_divergence_sustain_s
                and air.state is not _DVIL
                and not air.disarmed
            ):
                air.enter(DroneState.FAILSAFE)
                air.enter(_DVIL)
                air.notes.append(
                    f"DVIL entered at t={elapsed:.1f}s, alt={air.altitude_m:.1f}m"
                )

            # -- single-failure paths: still navigable, so RTL rather than descend.
            elif (
                (gnss_denied or vision_lost)
                and air.state in (DroneState.ON_STATION, DroneState.IN_TRANSIT)
                and gnss_bad_for_s == 0.0
            ):
                air.enter(DroneState.RTL_TRIGGERED)

            # -- battery ladder. Firmware-resident and never overridden.
            elif (
                air.battery_pct <= ENVELOPE.battery_rtl_trigger_pct
                and air.state in (DroneState.ON_STATION, DroneState.IN_TRANSIT)
            ):
                air.enter(DroneState.RTL_TRIGGERED)

            # -- descent behaviour ------------------------------------------------
            if air.state is _DVIL:
                dvil_elapsed_s += TICK_S
                air.altitude_m -= self._dvil_descent(air, active) * TICK_S
            elif air.state is DroneState.RTL_TRIGGERED:
                if air.altitude_m > 0.0:
                    air.enter(DroneState.LANDING)
            elif air.state is DroneState.LANDING:
                air.altitude_m -= ENVELOPE.descent_rate_max_mps * TICK_S

            air.battery_pct = max(0.0, air.battery_pct - 0.01)

            if air.altitude_m <= 0.0 and air.state in (
                _DVIL,
                DroneState.LANDING,
            ):
                air.altitude_m = 0.0
                air.disarmed = True
                air.enter(DroneState.POST_FLIGHT)
                break

            # Nothing left to simulate once the airframe is stable and no fault is
            # pending: a scenario below the debounce window ends here.
            if (
                not deferred
                and air.state in (DroneState.ON_STATION, DroneState.IDLE)
                and elapsed >= scenario.hold_s
            ):
                break

            # A scenario that only asks for a transition (not a full landing) ends
            # once its hold window has passed and the airframe has left the initial
            # state -- this keeps `HIL-R-02` from simulating a whole descent.
            if (
                elapsed >= scenario.hold_s
                and air.state in (DroneState.LOST_LINK,)
                and not active & {Fault.GNSS_DENIED, Fault.GNSS_SPOOFED_DIVERGING}
            ):
                break

        else:  # pragma: no cover - a model defect, surfaced rather than hidden
            air.notes.append(f"RUN DID NOT TERMINATE within {MAX_RUN_S}s")

        # If the scenario ended mid-fault with the aircraft still in the air, say so
        # rather than letting the oracle read a truncated trace as a pass.
        if air.state is _DVIL and air.altitude_m > 0.0:
            air.notes.append("descent incomplete at end of run")

        return Observation(
            state_trace=tuple(air.trace),
            descent_rate_mps=(
                sum(air.descent_samples) / len(air.descent_samples)
                if air.descent_samples
                else None
            ),
            commanded_lateral_translation=air.commanded_lateral,
            min_obstacle_clearance_m=air.min_clearance_m,
            disarmed=air.disarmed,
            telemetry_flags=frozenset(air.flags),
            ignored_commands=frozenset(air.ignored),
            notes=tuple(air.notes),
        )

    @staticmethod
    def _dvil_descent(air: _Airframe, active: set[Fault]) -> float:
        """Descent rate this tick, and the obstacle behaviour around it.

        Spec §3.1: the rate is `degraded_descent_rate_mps` and no lateral translation
        is ever *commanded*. §3.3: an intrusion arrests the descent and displaces
        laterally, which is reactive, not navigation -- so it does not set
        `commanded_lateral`.
        """
        rate = ENVELOPE.degraded_descent_rate_mps
        air.descent_samples.append(rate)

        if Fault.LIDAR_ARRAY_FAILED in active:
            # §7.3: blind controlled descent, rate unchanged, reported distinctly.
            air.flags.add("descent_unguided")
            air.min_clearance_m = None
            return rate

        if Fault.OBSTACLE_INTRUSION in active:
            floor = ENVELOPE.degraded_min_obstacle_clearance_m
            # The arrays hold the clearance floor. §3.3 step 4: a critical battery
            # takes precedence over holding, because a hovering drone with a dead
            # battery falls and a descending one does not.
            if Fault.BATTERY_DRAINED_TO_CRITICAL in active or (
                air.battery_pct <= ENVELOPE.battery_critical_pct
            ):
                air.flags.add("critical_battery_descent")
                air.min_clearance_m = floor
                return rate
            air.min_clearance_m = floor
            # Clearance restored by reactive displacement; descent resumes.
            return rate

        return rate
