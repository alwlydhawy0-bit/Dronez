"""The drone mission state machine, and who is allowed to move it.

Master Plan §4:

    IDLE -> PRE-FLIGHT-CHECK -> ARMED -> IN-TRANSIT -> ON-STATION (RECON ACTIVE)
         -> RTL-TRIGGERED -> LANDING -> POST-FLIGHT/MAINTENANCE

with **FAILSAFE** reachable as an interrupt from any state, and **LOST-LINK** a distinct
degraded state that itself forces a FAILSAFE transition after a bounded grace period.

The question this module answers
--------------------------------
Not "which transitions are physically possible" -- the firmware knows that -- but
**which transitions the ground may command**. Those are different sets, and the gap
between them is the safety architecture:

* The server may *request* a drone move within the normal mission flow.
* The server may **never** command a transition into ``FAILSAFE`` or any of its
  sub-states, and may **never** command a transition *out* of one. Zero-Trust §4.1:
  *"The MCP server MUST NEVER attempt to override hardware emergency return commands."*
* ``DEGRADED_VISUAL_INERTIAL_LANDING`` is firmware-resident and has no ground-commandable
  entry at all.

:data:`GROUND_COMMANDABLE` is the allow-list, and
``test_failsafe_is_never_ground_commandable`` asserts the gap holds. A transition absent
from that table is not something the server asks for politely and is refused -- it is
something the server has no vocabulary to express.

Observable versus commandable
-----------------------------
Every state here is *observable*: the command room must be able to see that a drone has
entered degraded landing, or the operators are flying blind during the exact event they
most need to understand. Being observable is not being requestable, and conflating the
two is how a safety state becomes an attack surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

__all__ = [
    "AIRBORNE_STATES",
    "FAILSAFE_STATES",
    "GROUND_COMMANDABLE",
    "TERMINAL_STATES",
    "DroneState",
    "TransitionAuthority",
    "TransitionCheck",
    "check_transition",
    "is_airborne",
    "may_ground_command",
]


class DroneState(StrEnum):
    """Mission state. Mirrors ``mcp_server.schemas.tools.DroneState``.

    Defined here as well because the fleet scheduler and the state rules are stdlib
    domain logic that must not depend on the web schema layer -- and a drift test keeps
    the two in step.
    """

    IDLE = "idle"
    PRE_FLIGHT_CHECK = "pre_flight_check"
    ARMED = "armed"
    IN_TRANSIT = "in_transit"
    ON_STATION = "on_station"
    RTL_TRIGGERED = "rtl_triggered"
    LANDING = "landing"
    POST_FLIGHT = "post_flight"
    MAINTENANCE = "maintenance"
    FAILSAFE = "failsafe"
    LOST_LINK = "lost_link"
    DEGRADED_VISUAL_INERTIAL_LANDING = "degraded_visual_inertial_landing"


class TransitionAuthority(StrEnum):
    """Who may cause a transition.

    ``FIRMWARE_ONLY`` is the important one: it marks transitions the flight controller
    makes on local sensor data, with no dependency on the link, the MCP server, the
    policy engine, or any agent. They are listed here so that ground software can
    *recognise* them, never so that it can trigger them.
    """

    #: The server may request it, subject to the policy gate.
    GROUND = "ground"
    #: The firmware makes this decision alone.
    FIRMWARE_ONLY = "firmware_only"
    #: Either may cause it (e.g. an operator-initiated RTL, or a low-battery one).
    EITHER = "either"


#: ``FAILSAFE`` and everything beneath it.
FAILSAFE_STATES: Final[frozenset[DroneState]] = frozenset({
    DroneState.FAILSAFE,
    DroneState.DEGRADED_VISUAL_INERTIAL_LANDING,
})

#: States from which no further mission work happens without human action.
TERMINAL_STATES: Final[frozenset[DroneState]] = frozenset({
    DroneState.POST_FLIGHT,
    DroneState.MAINTENANCE,
})

#: States in which the airframe is off the ground. A drone in any of these is a physical
#: object in motion, which is what makes a scheduling mistake about it consequential.
AIRBORNE_STATES: Final[frozenset[DroneState]] = frozenset({
    DroneState.IN_TRANSIT,
    DroneState.ON_STATION,
    DroneState.RTL_TRIGGERED,
    DroneState.LANDING,
    DroneState.LOST_LINK,
    DroneState.FAILSAFE,
    DroneState.DEGRADED_VISUAL_INERTIAL_LANDING,
})

#: Transitions the ground may command. **This is an allow-list.**
#:
#: Note what is absent: nothing enters ``FAILSAFE``, nothing enters
#: ``DEGRADED_VISUAL_INERTIAL_LANDING``, and nothing leaves either. A server that could
#: command a drone out of FAILSAFE could override a fail-safe, which Zero-Trust §4.1
#: forbids in as many words.
GROUND_COMMANDABLE: Final[frozenset[tuple[DroneState, DroneState]]] = frozenset({
    (DroneState.IDLE, DroneState.PRE_FLIGHT_CHECK),
    (DroneState.PRE_FLIGHT_CHECK, DroneState.ARMED),
    (DroneState.PRE_FLIGHT_CHECK, DroneState.IDLE),
    (DroneState.ARMED, DroneState.IN_TRANSIT),
    (DroneState.ARMED, DroneState.IDLE),
    (DroneState.IN_TRANSIT, DroneState.ON_STATION),
    (DroneState.IN_TRANSIT, DroneState.RTL_TRIGGERED),
    (DroneState.ON_STATION, DroneState.IN_TRANSIT),
    (DroneState.ON_STATION, DroneState.RTL_TRIGGERED),
    (DroneState.RTL_TRIGGERED, DroneState.LANDING),
    (DroneState.LANDING, DroneState.POST_FLIGHT),
    (DroneState.POST_FLIGHT, DroneState.IDLE),
    (DroneState.POST_FLIGHT, DroneState.MAINTENANCE),
    (DroneState.MAINTENANCE, DroneState.IDLE),
})

#: Transitions the firmware makes alone, recorded so ground software can recognise them.
#:
#: ``LOST_LINK -> FAILSAFE`` is the bounded grace period from Master Plan §4: loss of
#: link is a handled trigger, never an unhandled state.
#:
#: ``FAILSAFE -> DEGRADED_VISUAL_INERTIAL_LANDING`` is the concurrent GNSS-denial and
#: vision-loss path. It **preempts** RTL rather than being one of its trigger reasons,
#: because a standard RTL still assumes the aircraft can navigate back to a launch point.
#: ``DEGRADED_VISUAL_INERTIAL_LANDING`` is absent as a *source* of a FAILSAFE
#: transition: it is already a sub-state of FAILSAFE, so there is no escalation left
#: (``docs/07-degraded-landing-firmware-spec.md`` §4.2).
FIRMWARE_TRANSITIONS: Final[frozenset[tuple[DroneState, DroneState]]] = frozenset(
    {(source, DroneState.FAILSAFE) for source in DroneState if source not in FAILSAFE_STATES}
    | {
        (source, DroneState.LOST_LINK)
        for source in AIRBORNE_STATES
        if source not in FAILSAFE_STATES
    }
    | {
        (DroneState.FAILSAFE, DroneState.DEGRADED_VISUAL_INERTIAL_LANDING),
        (DroneState.LOST_LINK, DroneState.FAILSAFE),
        (DroneState.FAILSAFE, DroneState.LANDING),
        (DroneState.FAILSAFE, DroneState.RTL_TRIGGERED),
        (DroneState.DEGRADED_VISUAL_INERTIAL_LANDING, DroneState.POST_FLIGHT),
    }
)


@dataclass(frozen=True, slots=True)
class TransitionCheck:
    """Whether a transition is permitted, and by whom."""

    permitted: bool
    authority: TransitionAuthority | None
    detail: str


def is_airborne(state: DroneState) -> bool:
    return state in AIRBORNE_STATES


def may_ground_command(source: DroneState, target: DroneState) -> bool:
    """Whether the server may request this transition."""
    return (source, target) in GROUND_COMMANDABLE


def check_transition(
    source: DroneState, target: DroneState, *, by_ground: bool
) -> TransitionCheck:
    """Classify a proposed transition.

    ``by_ground=True`` asks whether the server may command it. ``by_ground=False`` asks
    whether the firmware could plausibly have caused it -- used when validating a
    reported state change, so a telemetry stream claiming an impossible transition is
    treated as corrupt rather than believed.
    """
    if source is target:
        return TransitionCheck(True, TransitionAuthority.EITHER, "no-op")

    ground_ok = (source, target) in GROUND_COMMANDABLE
    firmware_ok = (source, target) in FIRMWARE_TRANSITIONS

    if by_ground:
        if target in FAILSAFE_STATES:
            return TransitionCheck(
                False,
                TransitionAuthority.FIRMWARE_ONLY,
                f"{target.value} is firmware-resident; the ground has no vocabulary to "
                "command entry into a fail-safe state (Zero-Trust 4.1)",
            )
        if source in FAILSAFE_STATES:
            return TransitionCheck(
                False,
                TransitionAuthority.FIRMWARE_ONLY,
                f"a drone in {source.value} is under firmware control; the MCP server "
                "must never attempt to override a hardware emergency return",
            )
        if not ground_ok:
            return TransitionCheck(
                False,
                None,
                f"{source.value} -> {target.value} is not a ground-commandable transition",
            )
        return TransitionCheck(True, TransitionAuthority.GROUND, "permitted")

    if firmware_ok or ground_ok:
        authority = (
            TransitionAuthority.EITHER
            if firmware_ok and ground_ok
            else (TransitionAuthority.FIRMWARE_ONLY if firmware_ok else TransitionAuthority.GROUND)
        )
        return TransitionCheck(True, authority, "observed transition is plausible")

    return TransitionCheck(
        False,
        None,
        f"{source.value} -> {target.value} is not a transition this airframe can make; "
        "treat the reporting stream as corrupt rather than the state as real",
    )
