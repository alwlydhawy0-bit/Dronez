"""HIL / SITL scenario definitions for the fail-safe paths.

What this module is
-------------------
The **executable form** of the acceptance criteria in
``docs/07-degraded-landing-firmware-spec.md`` §8, plus the fail-safe RTL cases. Each
:class:`Scenario` states a starting condition, a sequence of faults to inject, and the
oracle that decides whether the airframe behaved. Nothing here talks to hardware.

What this module is emphatically **not**
----------------------------------------
It is not evidence that any firmware is correct. A scenario suite is a set of
*questions*; only a real airframe on a real rig can answer them. Running these against
:class:`~sitl_harness.model.SimulatedFirmware` checks that the questions are
well-formed and that the oracles catch the failures they are meant to catch --
**it cannot close `TM-12` or `TM-27`**, because a model written from a specification
will agree with that specification. That is a tautology, not a test result.
:func:`sitl_harness.runner.SuiteResult.evidence_class` exists to keep that distinction
in the output rather than in a footnote.

Scenario IDs match the spec so a HIL report can be diffed against it directly:
``HIL-D-*`` are the degraded-landing cases, ``HIL-R-*`` the RTL ones.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from dronez.safety.states import DroneState

__all__ = [
    "SCENARIOS",
    "EvidenceClass",
    "Expectation",
    "Fault",
    "Scenario",
    "scenario_by_id",
]


class Fault(StrEnum):
    """A condition the rig injects.

    Deliberately about *sensors and links*, never about commands: the whole point of
    the degraded-landing path is that it is driven by what the airframe can perceive,
    not by what anyone tells it.

    The three ``GROUND_COMMANDS_*`` values are the exception, and they exist to prove
    a negative -- that a ground command during a fail-safe changes nothing.
    """

    GNSS_DENIED = "gnss_denied"
    #: A healthy-looking fix that diverges from inertial dead-reckoning: the signature
    #: of capture, not of loss. This is the case `gnss_ins_divergence_max_m` exists for.
    GNSS_SPOOFED_DIVERGING = "gnss_spoofed_diverging"
    #: The spoofer stops, handing back a plausible fix mid-descent (spec §4.3).
    GNSS_RESTORED = "gnss_restored"
    OPTICAL_LOST = "optical_lost"
    THERMAL_LOST = "thermal_lost"
    VISION_RESTORED = "vision_restored"
    LIDAR_ARRAY_FAILED = "lidar_array_failed"
    OBSTACLE_INTRUSION = "obstacle_intrusion"
    C2_LINK_SEVERED = "c2_link_severed"
    MCP_SERVER_POWERED_OFF = "mcp_server_powered_off"
    COMPANION_COMPUTER_HALTED = "companion_computer_halted"
    BATTERY_DRAINED_TO_CRITICAL = "battery_drained_to_critical"
    GROUND_COMMANDS_RTL = "ground_commands_rtl"
    GROUND_COMMANDS_DISARM = "ground_commands_disarm"
    GROUND_COMMANDS_EXIT_FAILSAFE = "ground_commands_exit_failsafe"


class EvidenceClass(StrEnum):
    """What a passing run of this scenario actually proves.

    The distinction that keeps a green suite from being mistaken for a safety
    argument.
    """

    #: Ran against a model of the firmware. Proves the scenario and its oracle are
    #: well-formed. Proves nothing about any airframe.
    MODEL_ONLY = "model_only"
    #: Ran against PX4/Gazebo SITL. Proves the autopilot logic behaves, with simulated
    #: sensors and no real airframe dynamics.
    SOFTWARE_IN_THE_LOOP = "software_in_the_loop"
    #: Ran on the rig, with the real flight controller and real sensor hardware. The
    #: only class that closes TM-12 and TM-27.
    HARDWARE_IN_THE_LOOP = "hardware_in_the_loop"


@dataclass(frozen=True, slots=True)
class Expectation:
    """The oracle. Every field is optional; those set are all required to hold.

    Stated as *observations of the airframe*, never as internal calls, so the same
    expectation can be evaluated against a model, SITL, or a rig instrumented only
    from the outside.
    """

    #: State the airframe must be in when the scenario ends.
    final_state: DroneState | None = None
    #: States it must pass through, in order (not necessarily contiguously).
    passes_through: tuple[DroneState, ...] = ()
    #: States it must NEVER enter. The most important field here: most of these
    #: scenarios are about something that must *not* happen.
    never_enters: tuple[DroneState, ...] = ()
    #: Descent rate, m/s, within `rate_tolerance`.
    descent_rate_mps: float | None = None
    rate_tolerance: float = 0.1
    #: Whether any lateral translation was *commanded* (avoidance displacement is
    #: not commanded translation -- see spec §3.3).
    commanded_lateral_translation: bool | None = None
    #: Minimum obstacle clearance maintained throughout, metres.
    min_obstacle_clearance_m: float | None = None
    #: Whether the airframe must end disarmed.
    disarmed: bool | None = None
    #: Telemetry flags that must be raised, e.g. an unguided-descent indication.
    telemetry_flags: tuple[str, ...] = ()
    #: Inbound commands that must have been ignored.
    ignored_commands: tuple[Fault, ...] = ()


@dataclass(frozen=True, slots=True)
class Scenario:
    """One acceptance case."""

    scenario_id: str
    title: str
    #: The spec section this case comes from, so a failure points at the rule.
    spec_ref: str
    initial_state: DroneState
    faults: tuple[Fault, ...]
    expect: Expectation
    #: Why this case exists -- the failure it is designed to catch.
    rationale: str = ""
    #: Altitude AGL at the start, metres.
    initial_altitude_m: float = 60.0
    initial_battery_pct: float = 80.0
    #: Seconds the fault condition is held before the oracle is evaluated. Below the
    #: debounce window this must NOT trigger; above it, it must.
    hold_s: float = 5.0
    tags: tuple[str, ...] = field(default_factory=tuple)


DVIL: Final = DroneState.DEGRADED_VISUAL_INERTIAL_LANDING


# --------------------------------------------------------------------------- #
# HIL-D-*  degraded visual-inertial landing (spec §8)
# --------------------------------------------------------------------------- #

_DEGRADED_LANDING: tuple[Scenario, ...] = (
    Scenario(
        scenario_id="HIL-D-01",
        title="GNSS denied, vision intact",
        spec_ref="§1.1, §2.2",
        initial_state=DroneState.ON_STATION,
        faults=(Fault.GNSS_DENIED,),
        expect=Expectation(
            passes_through=(DroneState.RTL_TRIGGERED,),
            never_enters=(DVIL,),
        ),
        rationale=(
            "The aircraft still knows where it is relative to what it can see, so "
            "visual-inertial RTL is available. Entering DVIL here would ground a "
            "recoverable mission."
        ),
        tags=("single-failure",),
    ),
    Scenario(
        scenario_id="HIL-D-02",
        title="Vision lost, GNSS intact",
        spec_ref="§1.1",
        initial_state=DroneState.ON_STATION,
        faults=(Fault.OPTICAL_LOST, Fault.THERMAL_LOST),
        expect=Expectation(
            passes_through=(DroneState.RTL_TRIGGERED,),
            never_enters=(DVIL,),
        ),
        rationale="The aircraft still knows where it is absolutely. Standard RTL.",
        tags=("single-failure",),
    ),
    Scenario(
        scenario_id="HIL-D-03",
        title="Optical lost, thermal intact, GNSS denied",
        spec_ref="§2.2",
        initial_state=DroneState.ON_STATION,
        faults=(Fault.GNSS_DENIED, Fault.OPTICAL_LOST),
        expect=Expectation(
            passes_through=(DroneState.RTL_TRIGGERED,),
            never_enters=(DVIL,),
        ),
        rationale=(
            "Predicate B requires BOTH optical and thermal to be unusable. A "
            "smoke-obscured camera with a working thermal array is not a concurrent "
            "failure, and treating it as one would trigger DVIL on every fire."
        ),
        tags=("single-failure", "predicate-b"),
    ),
    Scenario(
        scenario_id="HIL-D-04",
        title="Concurrent denial, clear airspace below",
        spec_ref="§3.1",
        initial_state=DroneState.ON_STATION,
        faults=(Fault.GNSS_DENIED, Fault.OPTICAL_LOST, Fault.THERMAL_LOST),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DroneState.FAILSAFE, DVIL),
            descent_rate_mps=0.5,
            commanded_lateral_translation=False,
            disarmed=True,
        ),
        rationale="The nominal degraded landing. Everything else is a variation on it.",
        tags=("dual-failure", "baseline"),
    ),
    Scenario(
        scenario_id="HIL-D-05",
        title="Concurrent denial with the MCP server powered off",
        spec_ref="§5",
        initial_state=DroneState.ON_STATION,
        faults=(
            Fault.MCP_SERVER_POWERED_OFF,
            Fault.GNSS_DENIED,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DroneState.FAILSAFE, DVIL),
            descent_rate_mps=0.5,
            disarmed=True,
        ),
        rationale=(
            "TM-12: the single most important test in the programme. The Master Plan's "
            "central claim is that a server outage degrades capability, never safety. "
            "This is that claim, stated as a measurement."
        ),
        tags=("dual-failure", "independence", "TM-12"),
    ),
    Scenario(
        scenario_id="HIL-D-06",
        title="Concurrent denial with the C2 link severed",
        spec_ref="§5",
        initial_state=DroneState.ON_STATION,
        faults=(
            Fault.C2_LINK_SEVERED,
            Fault.GNSS_DENIED,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            descent_rate_mps=0.5,
            disarmed=True,
        ),
        rationale="DVIL is usually entered with the link up; it must not need it.",
        tags=("dual-failure", "independence"),
    ),
    Scenario(
        scenario_id="HIL-D-07",
        title="Concurrent denial with the companion computer halted",
        spec_ref="§5",
        initial_state=DroneState.ON_STATION,
        faults=(
            Fault.COMPANION_COMPUTER_HALTED,
            Fault.GNSS_DENIED,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            descent_rate_mps=0.5,
            disarmed=True,
        ),
        rationale=(
            "DVIL is flight-controller-resident. A compromised or crashed Jetson -- "
            "the component most exposed to the network -- must not reach it."
        ),
        tags=("dual-failure", "independence"),
    ),
    Scenario(
        scenario_id="HIL-D-08",
        title="Obstacle intrudes to 1.0 m mid-descent",
        spec_ref="§3.3",
        initial_state=DroneState.ON_STATION,
        faults=(
            Fault.GNSS_DENIED,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
            Fault.OBSTACLE_INTRUSION,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            min_obstacle_clearance_m=1.5,
            commanded_lateral_translation=False,
            disarmed=True,
        ),
        rationale=(
            "Avoidance displacement is reactive, never planned. It is the only lateral "
            "motion in this state, and it must not be confused with navigation."
        ),
        tags=("dual-failure", "avoidance"),
    ),
    Scenario(
        scenario_id="HIL-D-09",
        title="GNSS 'recovers' mid-descent",
        spec_ref="§4.3",
        initial_state=DroneState.ON_STATION,
        faults=(
            Fault.GNSS_SPOOFED_DIVERGING,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
            Fault.GNSS_RESTORED,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            never_enters=(DroneState.IN_TRANSIT, DroneState.ON_STATION),
            descent_rate_mps=0.5,
            disarmed=True,
        ),
        rationale=(
            "The adversarial case the no-exit rule exists for. An attacker who can deny "
            "GNSS can also restore a spoofed fix; resuming navigation would fly the "
            "aircraft wherever they chose, with its inertial reference already too "
            "degraded to cross-check them."
        ),
        tags=("dual-failure", "adversarial", "no-exit"),
    ),
    Scenario(
        scenario_id="HIL-D-10",
        title="Vision recovers mid-descent",
        spec_ref="§4.3",
        initial_state=DroneState.ON_STATION,
        faults=(
            Fault.GNSS_DENIED,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
            Fault.VISION_RESTORED,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            never_enters=(DroneState.IN_TRANSIT, DroneState.ON_STATION),
            descent_rate_mps=0.5,
            disarmed=True,
        ),
        rationale=(
            "Recovered sensors are used for *seeing*, never for *going somewhere else*."
        ),
        tags=("dual-failure", "no-exit"),
    ),
    Scenario(
        scenario_id="HIL-D-11",
        title="Ultrasonic/LiDAR arrays fail mid-DVIL",
        spec_ref="§7.3",
        initial_state=DroneState.ON_STATION,
        faults=(
            Fault.GNSS_DENIED,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
            Fault.LIDAR_ARRAY_FAILED,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            descent_rate_mps=0.5,
            telemetry_flags=("descent_unguided",),
            disarmed=True,
        ),
        rationale=(
            "A blind controlled descent is the least-bad option -- the aircraft cannot "
            "hold altitude indefinitely. But the command room must be told, because the "
            "ground-safety implication for a security team differs sharply from a "
            "guided descent."
        ),
        tags=("dual-failure", "degraded-guidance"),
    ),
    Scenario(
        scenario_id="HIL-D-12",
        title="Battery reaches critical while holding on an obstacle",
        spec_ref="§3.3 step 4",
        initial_state=DroneState.ON_STATION,
        initial_battery_pct=12.0,
        faults=(
            Fault.GNSS_DENIED,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
            Fault.OBSTACLE_INTRUSION,
            Fault.BATTERY_DRAINED_TO_CRITICAL,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            disarmed=True,
        ),
        rationale=(
            "The hardest trade in the spec, made deliberately: a drone hovering at 1.5 m "
            "clearance with a dead battery falls. One descending under control at "
            "0.5 m/s does not."
        ),
        tags=("dual-failure", "battery"),
    ),
    Scenario(
        scenario_id="HIL-D-13",
        title="Ground commands RTL / disarm during DVIL",
        spec_ref="§5, Zero-Trust §4.1",
        initial_state=DroneState.ON_STATION,
        faults=(
            Fault.GNSS_DENIED,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
            Fault.GROUND_COMMANDS_RTL,
            Fault.GROUND_COMMANDS_DISARM,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            descent_rate_mps=0.5,
            disarmed=True,
            ignored_commands=(Fault.GROUND_COMMANDS_RTL, Fault.GROUND_COMMANDS_DISARM),
        ),
        rationale=(
            "A mid-air disarm is the worst thing the ground could do here. The server "
            "MUST NEVER override a hardware emergency return."
        ),
        tags=("dual-failure", "ground-override"),
    ),
    Scenario(
        scenario_id="HIL-D-14",
        title="Forged, correctly-signed 'exit DVIL' command injected",
        spec_ref="§5.1",
        initial_state=DroneState.ON_STATION,
        faults=(
            Fault.GNSS_DENIED,
            Fault.OPTICAL_LOST,
            Fault.THERMAL_LOST,
            Fault.GROUND_COMMANDS_EXIT_FAILSAFE,
        ),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            disarmed=True,
            ignored_commands=(Fault.GROUND_COMMANDS_EXIT_FAILSAFE,),
        ),
        rationale=(
            "Not a formality: the MAVLink parser is native-code attack surface reachable "
            "in this state. There is no such command in the protocol surface, and a "
            "well-formed signed frame asking for one must still do nothing."
        ),
        tags=("dual-failure", "adversarial", "ground-override"),
    ),
    Scenario(
        scenario_id="HIL-D-15",
        title="Transient 1 s dual dropout, below the debounce window",
        spec_ref="§2.3",
        initial_state=DroneState.ON_STATION,
        hold_s=1.0,
        faults=(Fault.GNSS_DENIED, Fault.OPTICAL_LOST, Fault.THERMAL_LOST),
        expect=Expectation(
            final_state=DroneState.ON_STATION,
            never_enters=(DVIL, DroneState.FAILSAFE),
        ),
        rationale=(
            "`gnss_divergence_sustain_s` exists so a multipath glitch beside a building "
            "is not read as an attack. A state this consequential must not be one "
            "dropped frame away."
        ),
        tags=("debounce",),
    ),
    Scenario(
        scenario_id="HIL-D-16",
        title="GNSS spoof walking position away at 2 m/s, vision denied",
        spec_ref="§2.1",
        initial_state=DroneState.ON_STATION,
        faults=(Fault.GNSS_SPOOFED_DIVERGING, Fault.OPTICAL_LOST, Fault.THERMAL_LOST),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            never_enters=(DroneState.IN_TRANSIT,),
            disarmed=True,
        ),
        rationale=(
            "The anti-spoofing case. The fix is internally healthy -- good satellite "
            "count, good HDOP, high confidence -- and diverging from inertial truth. "
            "A high-confidence fix is not a trustworthy fix."
        ),
        tags=("dual-failure", "adversarial", "spoofing"),
    ),
    Scenario(
        scenario_id="HIL-D-17",
        title="Dual failure during multi-drone operation",
        spec_ref="§8",
        initial_state=DroneState.ON_STATION,
        faults=(Fault.GNSS_DENIED, Fault.OPTICAL_LOST, Fault.THERMAL_LOST),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            disarmed=True,
        ),
        rationale=(
            "Each affected airframe enters DVIL independently; the unaffected ones "
            "maintain `swarm_min_separation_m` from their own onboard deconfliction, "
            "not from a server round-trip."
        ),
        tags=("dual-failure", "swarm"),
    ),
    Scenario(
        scenario_id="HIL-D-18",
        title="Dual failure at the 120 m ceiling",
        spec_ref="§8",
        initial_state=DroneState.ON_STATION,
        initial_altitude_m=120.0,
        faults=(Fault.GNSS_DENIED, Fault.OPTICAL_LOST, Fault.THERMAL_LOST),
        expect=Expectation(
            final_state=DroneState.POST_FLIGHT,
            passes_through=(DVIL,),
            descent_rate_mps=0.5,
            disarmed=True,
        ),
        rationale=(
            "Sizes the battery reserve: 120 m at 0.5 m/s is four minutes of descent "
            "before any obstacle hold is counted."
        ),
        tags=("dual-failure", "endurance"),
    ),
)


# --------------------------------------------------------------------------- #
# HIL-R-*  fail-safe RTL (Master Plan §4, CLAUDE.md §5.4)
# --------------------------------------------------------------------------- #

_SAFE_RETURN: tuple[Scenario, ...] = (
    Scenario(
        scenario_id="HIL-R-01",
        title="Battery falls to the RTL trigger",
        spec_ref="envelope: battery_rtl_trigger_pct",
        initial_state=DroneState.ON_STATION,
        initial_battery_pct=29.0,
        faults=(),
        expect=Expectation(
            passes_through=(DroneState.RTL_TRIGGERED,),
            final_state=DroneState.POST_FLIGHT,
            never_enters=(DVIL,),
            disarmed=True,
        ),
        rationale=(
            "Autonomous, firmware-resident, and Zero-Trust §4.1 forbids the server "
            "overriding it."
        ),
        tags=("rtl", "battery"),
    ),
    Scenario(
        scenario_id="HIL-R-02",
        title="Link loss forces FAILSAFE after the grace period",
        spec_ref="envelope: link_loss_grace_s",
        initial_state=DroneState.ON_STATION,
        faults=(Fault.C2_LINK_SEVERED,),
        hold_s=6.0,
        expect=Expectation(
            passes_through=(DroneState.LOST_LINK, DroneState.FAILSAFE),
            never_enters=(DVIL,),
        ),
        rationale=(
            "Loss of link is a handled trigger, never an unhandled state. A link-lost "
            "aircraft that can still navigate should RTL, not descend where it is."
        ),
        tags=("rtl", "link"),
    ),
    Scenario(
        scenario_id="HIL-R-03",
        title="Link loss below the grace period does not fail safe",
        spec_ref="envelope: link_loss_grace_s",
        initial_state=DroneState.ON_STATION,
        faults=(Fault.C2_LINK_SEVERED,),
        hold_s=2.0,
        expect=Expectation(
            final_state=DroneState.LOST_LINK,
            never_enters=(DroneState.FAILSAFE, DVIL),
        ),
        rationale=(
            "A brief RF dropout must not end a mission. LOST_LINK itself is correct "
            "and immediate -- it is a distinct degraded state, not a failure -- and "
            "what must not happen below `link_loss_grace_s` is the FAILSAFE it "
            "escalates to."
        ),
        tags=("rtl", "link", "debounce"),
    ),
    Scenario(
        scenario_id="HIL-R-04",
        title="RTL completes with the MCP server powered off",
        spec_ref="Master Plan §4",
        initial_state=DroneState.ON_STATION,
        initial_battery_pct=29.0,
        faults=(Fault.MCP_SERVER_POWERED_OFF,),
        expect=Expectation(
            passes_through=(DroneState.RTL_TRIGGERED, DroneState.LANDING),
            final_state=DroneState.POST_FLIGHT,
            disarmed=True,
        ),
        rationale="The other half of TM-12: the ordinary fail-safe path, server absent.",
        tags=("rtl", "independence", "TM-12"),
    ),
    Scenario(
        scenario_id="HIL-R-05",
        title="Ground cannot countermand a firmware-initiated RTL",
        spec_ref="Zero-Trust §4.1",
        initial_state=DroneState.ON_STATION,
        initial_battery_pct=29.0,
        faults=(Fault.GROUND_COMMANDS_EXIT_FAILSAFE,),
        expect=Expectation(
            passes_through=(DroneState.RTL_TRIGGERED,),
            final_state=DroneState.POST_FLIGHT,
            ignored_commands=(Fault.GROUND_COMMANDS_EXIT_FAILSAFE,),
            disarmed=True,
        ),
        rationale=(
            "`GROUND_COMMANDABLE` has no pair leaving a fail-safe state, so the server "
            "cannot express this. The rig proves the airframe refuses it even when a "
            "frame arrives anyway."
        ),
        tags=("rtl", "ground-override"),
    ),
)


SCENARIOS: Final[tuple[Scenario, ...]] = _DEGRADED_LANDING + _SAFE_RETURN


def scenario_by_id(scenario_id: str) -> Scenario:
    for scenario in SCENARIOS:
        if scenario.scenario_id == scenario_id:
            return scenario
    raise KeyError(f"no scenario {scenario_id!r}")


def scenarios_tagged(tag: str) -> tuple[Scenario, ...]:
    return tuple(s for s in SCENARIOS if tag in s.tags)


def _check_ids_are_unique(scenarios: Sequence[Scenario]) -> None:
    ids = [s.scenario_id for s in scenarios]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise ValueError(f"duplicate scenario ids: {sorted(duplicates)}")


_check_ids_are_unique(SCENARIOS)
