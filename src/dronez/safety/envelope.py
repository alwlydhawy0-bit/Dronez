"""Safety-envelope constants for the tactical recon platform.

This module is the **single source of truth** for every hard safety bound in the
system. It is deliberately dependency-free (stdlib only) so that it can be
imported by the MCP server, the policy engine, the HIL test harness, and the
firmware-parameter generator without dragging in a web framework.

Milestone-0 contract
--------------------
Master Plan, Milestone 0 requires: *"policy-engine schema and safety-envelope
constants defined and reviewed by a named accountable owner"*. The values below
are the **proposed** Milestone-0 defaults. They are NOT yet signed off; see
``SIGN_OFF`` at the bottom of this module and the sign-off block in ``CLAUDE.md``.
No flight-capable code may consume these values until that block records a named
owner and a review date.

Enforcement locus (read this before changing anything)
------------------------------------------------------
Per Master Plan §2 (kinetic-failure mitigation) and Zero-Trust Standard §4.1
(*Fail-Safe Override Priority*), the MCP server is **never** the last line of
defence for a safety bound. Every constant therefore carries an explicit
:class:`EnforcementLocus` recording where the bound is *actually* enforced:

* ``FIRMWARE``  - enforced in PX4/ArduPilot flight-controller firmware. Survives
  loss of link, loss of the companion computer, and total MCP server outage.
  The server may *request* behaviour inside this bound; it can never widen it.
* ``COMPANION`` - enforced on the onboard companion computer (Jetson-class).
  Survives loss of link to the MCP server, but not loss of the airframe's own
  compute.
* ``SERVER``    - enforced by the deterministic, non-LLM policy engine before
  dispatch. This is an *admission* control only: it prevents a bad plan from
  being sent, it does not stop a drone already in flight.

A ``SERVER``-only locus on a kinetic bound is a design defect. The
``test_no_kinetic_bound_is_server_only`` regression test enforces this.

Drift control
-------------
:func:`envelope_digest` produces a stable SHA-256 over the canonical
serialisation of every constant. That digest is recorded in ``CLAUDE.md``. If
someone changes a bound without updating the project memory, the digest test
fails. This is the mechanism that stops a future engineering or agent session
from silently re-relaxing a safety decision that was made deliberately.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "ENFORCEMENT",
    "ENVELOPE",
    "PROHIBITED_CAPABILITIES",
    "SIGN_OFF",
    "Bound",
    "EnforcementLocus",
    "EnvelopeConsistencyError",
    "SafetyEnvelope",
    "envelope_digest",
    "validate_envelope",
]

SCHEMA_VERSION: Final[str] = "safety-envelope/1.0.0"


class EnforcementLocus(StrEnum):
    """Where a safety bound is actually enforced. See module docstring."""

    FIRMWARE = "firmware"
    COMPANION = "companion"
    SERVER = "server"


@dataclass(frozen=True, slots=True)
class Bound:
    """Provenance metadata for one safety constant."""

    locus: EnforcementLocus
    kinetic: bool
    rationale: str
    source: str


@dataclass(frozen=True, slots=True)
class SafetyEnvelope:
    """Immutable hard bounds. Values are SI units unless the name says otherwise.

    Nothing in this system may accept a per-mission override that widens any of
    these values. Master Plan §5 (``deploy_recon_waypoint`` validation) requires
    altitude/velocity to be checked against a hard-coded envelope *independent of
    any per-mission override*.
    """

    # --- Vertical envelope -------------------------------------------------
    altitude_max_agl_m: float = 120.0
    altitude_min_agl_m: float = 15.0
    climb_rate_max_mps: float = 5.0
    descent_rate_max_mps: float = 3.0

    # --- Horizontal envelope ----------------------------------------------
    ground_speed_max_mps: float = 15.0
    mission_radius_max_m: float = 2000.0
    geofence_soft_buffer_m: float = 25.0

    # --- Energy reserve ----------------------------------------------------
    battery_rtl_trigger_pct: float = 30.0
    battery_land_now_pct: float = 15.0
    battery_critical_pct: float = 10.0
    battery_range_reserve_factor: float = 1.30

    # --- Link / time-box ---------------------------------------------------
    link_loss_grace_s: float = 5.0
    mission_duration_max_s: float = 1800.0
    incident_zone_max_duration_s: float = 21600.0

    # --- Navigation integrity (GPS spoofing cross-validation) --------------
    gnss_ins_divergence_max_m: float = 12.0
    gnss_divergence_sustain_s: float = 2.0
    gnss_min_satellites: int = 8
    gnss_max_hdop: float = 1.8

    # --- Dual-failure degraded landing -------------------------------------
    degraded_descent_rate_mps: float = 0.5
    degraded_min_obstacle_clearance_m: float = 1.5

    # --- Swarm deconfliction (Milestone 4) ---------------------------------
    swarm_min_separation_m: float = 15.0

    # --- Rate limits -------------------------------------------------------
    agent_proposals_per_second: float = 2.0
    hardware_commands_per_second: float = 2.0

    # --- Airspace data freshness -------------------------------------------
    nfz_max_staleness_s: float = 300.0
    nfz_clearance_validity_s: float = 120.0


ENVELOPE: Final[SafetyEnvelope] = SafetyEnvelope()


#: Provenance for every field of :class:`SafetyEnvelope`. Keys MUST be exhaustive;
#: :func:`validate_envelope` fails closed if a constant has no recorded locus.
ENFORCEMENT: Final[Mapping[str, Bound]] = {
    "altitude_max_agl_m": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale=(
            "120 m AGL is the standard VLOS ceiling in GACA/ICAO-aligned rules. "
            "Enforced as a PX4/ArduPilot fence ceiling so it holds with the MCP "
            "server disconnected."
        ),
        source="GACA VLOS ceiling; Master Plan Sec.5 deploy_recon_waypoint validation",
    ),
    "altitude_min_agl_m": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale=(
            "Floor that keeps the airframe clear of street furniture, cabling and "
            "bystanders inside an urban incident zone."
        ),
        source="Master Plan Sec.2 kinetic-failure mitigation",
    ),
    "climb_rate_max_mps": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale="Bounds energy drawn during ascent and keeps the fence ceiling recoverable.",
        source="Airframe performance envelope (pending fleet-specific review)",
    ),
    "descent_rate_max_mps": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale="Above this a multirotor risks vortex-ring state on a vertical descent.",
        source="Airframe performance envelope (pending fleet-specific review)",
    ),
    "ground_speed_max_mps": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale=(
            "Caps kinetic energy at impact and keeps the obstacle-avoidance sensor "
            "horizon longer than the stopping distance."
        ),
        source="Master Plan Sec.5 velocity_max validation",
    ),
    "mission_radius_max_m": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale="Fence radius from launch; also the practical VLOS/licensing bound.",
        source="Master Plan Sec.3 out-of-scope BVLOS",
    ),
    "geofence_soft_buffer_m": Bound(
        EnforcementLocus.SERVER,
        kinetic=False,
        rationale=(
            "Admission-control margin only. The policy engine shrinks an accepted "
            "polygon by this buffer so that normal navigation error never reaches "
            "the firmware hard fence. The hard fence is the real control."
        ),
        source="Master Plan Sec.4 policy gate",
    ),
    "battery_rtl_trigger_pct": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale=(
            "Autonomous RTL trigger. Zero-Trust Sec.4.1 forbids the MCP server "
            "overriding it."
        ),
        source="Zero-Trust Standard Sec.4.1 Fail-Safe Override Priority",
    ),
    "battery_land_now_pct": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale="Abandon RTL, land in place: returning is no longer energetically safe.",
        source="Zero-Trust Standard Sec.4.1",
    ),
    "battery_critical_pct": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale="Immediate controlled descent regardless of position over ground.",
        source="Zero-Trust Standard Sec.4.1",
    ),
    "battery_range_reserve_factor": Bound(
        EnforcementLocus.SERVER,
        kinetic=False,
        rationale=(
            "Pre-dispatch sufficiency check: required energy x 1.30 must be available "
            "before a plan is admitted. Prevents dispatching a doomed mission; does "
            "not replace the firmware triggers above."
        ),
        source="Master Plan Sec.5 battery-range sufficiency check",
    ),
    "link_loss_grace_s": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale=(
            "LOST-LINK is a distinct state that forces FAILSAFE after this bounded "
            "grace period. Loss of link is a handled trigger, never an unhandled state."
        ),
        source="Master Plan Sec.4 state machine; Zero-Trust Sec.4.1",
    ),
    "mission_duration_max_s": Bound(
        EnforcementLocus.COMPANION,
        kinetic=False,
        rationale=(
            "Hard mission time-box. Held on the companion computer so expiry triggers "
            "RTL even if the server cannot be reached to close the mission."
        ),
        source="Master Plan Sec.3 happy path step 7",
    ),
    "incident_zone_max_duration_s": Bound(
        EnforcementLocus.SERVER,
        kinetic=False,
        rationale=(
            "Caps the root authorisation envelope at 6 h so that 'watch this area "
            "indefinitely' is structurally impossible without a renewed human "
            "authorisation."
        ),
        source="Master Plan Sec.3 out-of-scope standing surveillance",
    ),
    "gnss_ins_divergence_max_m": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale=(
            "GNSS is cross-validated against inertial dead-reckoning. Divergence past "
            "this threshold means the position fix is not trustworthy for geofencing."
        ),
        source="Zero-Trust Standard Sec.4.3 GPS Spoofing/Jamming Detection",
    ),
    "gnss_divergence_sustain_s": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale=(
            "Divergence must persist this long to fail safe, so a single glitch is "
            "not a trigger."
        ),
        source="Zero-Trust Standard Sec.4.3",
    ),
    "gnss_min_satellites": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale="Below this count the fix is not admissible as geofence ground truth.",
        source="Zero-Trust Standard Sec.4.3",
    ),
    "gnss_max_hdop": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale="Horizontal dilution of precision ceiling for an admissible fix.",
        source="Zero-Trust Standard Sec.4.3",
    ),
    "degraded_descent_rate_mps": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale=(
            "DEGRADED_VISUAL_INERTIAL_LANDING descent rate. Slow enough that the "
            "ultrasonic/LiDAR arrays remain the binding constraint on the descent."
        ),
        source="Master Plan Sec.4 DEGRADED_VISUAL_INERTIAL_LANDING",
    ),
    "degraded_min_obstacle_clearance_m": Bound(
        EnforcementLocus.FIRMWARE,
        kinetic=True,
        rationale=(
            "Lateral/vertical clearance the avoidance arrays must maintain during "
            "that descent."
        ),
        source="Master Plan Sec.4 DEGRADED_VISUAL_INERTIAL_LANDING",
    ),
    "swarm_min_separation_m": Bound(
        EnforcementLocus.COMPANION,
        kinetic=True,
        rationale=(
            "Multi-drone minimum separation. Enforced onboard so deconfliction does "
            "not depend on a server round-trip. Milestone 4."
        ),
        source="Master Plan Sec.6 Milestone 4",
    ),
    "agent_proposals_per_second": Bound(
        EnforcementLocus.SERVER,
        kinetic=False,
        rationale=(
            "Hard cap on agent tool proposals, counted whether or not the policy "
            "engine ultimately approves them. Bounds a runaway or adversarially "
            "driven agent loop. Distinct from the hardware dispatch limit."
        ),
        source="Master Plan Sec.5 Agent Rate Limit",
    ),
    "hardware_commands_per_second": Bound(
        EnforcementLocus.SERVER,
        kinetic=False,
        rationale=(
            "Per-agent dispatch rate to ROS2/MAVLink nodes, to prevent buffer "
            "overflow and control instability."
        ),
        source="Zero-Trust Standard Sec.4.1 Command Rate Limiting & Anti-Flooding",
    ),
    "nfz_max_staleness_s": Bound(
        EnforcementLocus.SERVER,
        kinetic=False,
        rationale=(
            "Bounded freshness window for sovereign NFZ / GACA data. Past this age "
            "the cache is not authoritative and check_airspace_clearance fails closed."
        ),
        source="Master Plan Sec.4 AirspaceZone; Zero-Trust Sec.0.1 Default Deny",
    ),
    "nfz_clearance_validity_s": Bound(
        EnforcementLocus.SERVER,
        kinetic=False,
        rationale=(
            "How long an affirmative clearance decision may be carried before "
            "dispatch. Stops a clearance being minted early and replayed later."
        ),
        source="Master Plan Sec.5 check_airspace_clearance",
    ),
}


#: Capabilities that are structurally out of scope. Master Plan §3 states that no
#: tool in this system shall accept, validate, or dispatch a payload-release or
#: offensive-action command, at any phase. This list is asserted against the tool
#: catalogue by a release-gate test; it is not advisory.
PROHIBITED_CAPABILITIES: Final[tuple[str, ...]] = (
    "payload_release",
    "weapon_arm",
    "weapon_release",
    "kinetic_effect",
    "interdiction",
    "target_engagement",
    "autonomous_pursuit",
    "standing_surveillance",
)


#: Milestone-0 accountable-owner sign-off. ``owner`` and ``reviewed_utc`` MUST be
#: populated before any flight-capable code consumes ``ENVELOPE``. The
#: corresponding gate test asserts this, so leaving it unset fails the build
#: rather than silently shipping unreviewed bounds.
SIGN_OFF: Final[Mapping[str, Any]] = {
    "status": "PENDING_REVIEW",
    "owner": None,
    "role": "Accountable Safety Owner (named individual, not a team)",
    "reviewed_utc": None,
    "milestone": 0,
}


class EnvelopeConsistencyError(ValueError):
    """Raised when the envelope is internally inconsistent. Always fail closed."""


def _canonical() -> dict[str, Any]:
    """Deterministic serialisation used for the drift digest."""
    return {
        "schema_version": SCHEMA_VERSION,
        "constants": {f.name: getattr(ENVELOPE, f.name) for f in fields(ENVELOPE)},
        "enforcement": {
            name: {"locus": b.locus.value, "kinetic": b.kinetic}
            for name, b in sorted(ENFORCEMENT.items())
        },
        "prohibited_capabilities": list(PROHIBITED_CAPABILITIES),
    }


def envelope_digest() -> str:
    """SHA-256 over the canonical envelope. Recorded in ``CLAUDE.md`` for drift control."""
    blob = json.dumps(_canonical(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def validate_envelope(env: SafetyEnvelope = ENVELOPE) -> None:
    """Assert the envelope is internally coherent. Raises on any inconsistency.

    Called at import time so an incoherent envelope fails closed at process start
    rather than at dispatch time.
    """
    declared = {f.name for f in fields(env)}
    missing = declared - set(ENFORCEMENT)
    if missing:
        raise EnvelopeConsistencyError(
            f"safety constants with no recorded enforcement locus: {sorted(missing)}"
        )
    orphaned = set(ENFORCEMENT) - declared
    if orphaned:
        raise EnvelopeConsistencyError(
            f"enforcement entries for non-existent constants: {sorted(orphaned)}"
        )

    if not env.altitude_min_agl_m < env.altitude_max_agl_m:
        raise EnvelopeConsistencyError("altitude floor must be below the ceiling")
    if not (
        env.battery_critical_pct
        < env.battery_land_now_pct
        < env.battery_rtl_trigger_pct
    ):
        raise EnvelopeConsistencyError(
            "battery thresholds must satisfy critical < land_now < rtl_trigger"
        )
    if env.battery_range_reserve_factor <= 1.0:
        raise EnvelopeConsistencyError("range reserve factor must exceed 1.0")
    if env.degraded_descent_rate_mps >= env.descent_rate_max_mps:
        raise EnvelopeConsistencyError(
            "degraded-landing descent must be slower than the normal descent limit"
        )
    if env.nfz_clearance_validity_s > env.nfz_max_staleness_s:
        raise EnvelopeConsistencyError(
            "a clearance may not outlive the freshness window of the data it was derived from"
        )
    for name in ("agent_proposals_per_second", "hardware_commands_per_second"):
        if getattr(env, name) <= 0:
            raise EnvelopeConsistencyError(f"{name} must be positive")
    for name, bound in ENFORCEMENT.items():
        if bound.kinetic and bound.locus is EnforcementLocus.SERVER:
            raise EnvelopeConsistencyError(
                f"{name!r} is a kinetic bound enforced only at the server; kinetic "
                "bounds must be enforced onboard (firmware or companion)"
            )


validate_envelope()
