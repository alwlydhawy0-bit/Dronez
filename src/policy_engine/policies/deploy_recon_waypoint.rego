# THE deterministic authorization gate for a proposed reconnaissance flight plan.
#
# Zero-Trust Sec.4.2: "Every proposed tool call is re-validated against the safety
# envelope, geofence, financial limit, or ABAC rule by NON-LLM CODE before dispatch.
# A model claiming special authorization, an 'admin override', a 'debug mode', or a
# 'previous instruction' in its own output text has zero effect on this gate --
# natural-language claims of authority are not a credential."
#
# This file is that gate. Three structural properties make it one:
#
#   1. DEFAULT DENY. `allow` is false unless every check passes. A rule that fails to
#      evaluate -- because input was missing, malformed, or an unknown enum arrived --
#      cannot produce an allow.
#   2. NO FREE TEXT IS READ. There is no rule anywhere in this package that inspects a
#      natural-language field. Urgency, justification and operator notes are absent
#      from the decision by construction, not by discipline.
#   3. BOUNDS COME FROM `data`, NOT `input`. The safety envelope arrives with the policy
#      bundle (generated from the Python module by scripts/gen_policy_data.py). The
#      caller cannot widen the limits it is being judged against.
#
# Decision shape: {"allow": bool, "deny": [ {code, detail}, ... ], "policy_version": str}
# A denial always enumerates every reason, not just the first, so an operator sees the
# whole picture and a rejected-proposal pattern is analysable.

package dronez.authz.deploy_recon_waypoint

import rego.v1

import data.dronez.authz.clearance
import data.dronez.authz.precedence
import data.dronez.geometry
import data.dronez.safety_envelope.constants as envelope

policy_version := "deploy_recon_waypoint/1.0.0"

default allow := false

# Allow requires BOTH no violations AND positively-established completeness. Checking
# only `count(deny) == 0` would allow an empty input, where no deny rule fires because
# nothing is there to violate.
allow if {
	input_complete
	count(deny) == 0
}

decision := {
	"allow": allow,
	"deny": [d | some d in deny],
	"policy_version": policy_version,
}

# --------------------------------------------------------------------------- #
# Input completeness
# --------------------------------------------------------------------------- #

input_complete if {
	is_object(input.request)
	is_object(input.principal)
	is_object(input.incident_zone)
	is_string(input.now)

	input.request.polygon
	is_number(input.request.altitude_min_m_agl)
	is_number(input.request.altitude_max_m_agl)
	is_number(input.request.velocity_max_mps)
	is_string(input.request.pattern_type)
	is_string(input.principal.role)
	is_string(input.principal.operator_id)
}

deny contains {
	"code": "malformed_input",
	"detail": "policy input is incomplete; required request, principal, incident_zone or now fields are missing",
} if {
	not input_complete
}

# --------------------------------------------------------------------------- #
# Recon-only: pattern allow-list
# --------------------------------------------------------------------------- #

allowed_patterns := {"perimeter_sweep", "grid", "orbit"}

deny contains {
	"code": "pattern_not_allowed",
	"detail": sprintf("pattern_type %q is not on the allow-list; no freeform path is accepted from agent output", [input.request.pattern_type]),
} if {
	input_complete
	not allowed_patterns[input.request.pattern_type]
}

# A prohibited capability may not appear anywhere in the request, at any phase.
deny contains {
	"code": "prohibited_capability",
	"detail": sprintf("request references prohibited capability %q; this is a reconnaissance-only platform", [capability]),
} if {
	some capability in data.dronez.safety_envelope.prohibited_capabilities
	some key, _ in input.request
	contains(lower(key), capability)
}

# --------------------------------------------------------------------------- #
# Role and precedence
# --------------------------------------------------------------------------- #

deny contains {
	"code": "unknown_role",
	"detail": sprintf("role %q has no precedence tier", [input.principal.role]),
} if {
	input_complete
	not precedence.known_role(input.principal.role)
}

deny contains {
	"code": "precedence_violation",
	"detail": "a Tier 3 agent proposal may not reference or supersede a human-issued command; logged as a security event",
} if {
	precedence.agent_supersession_attempt(input.principal, input.request)
}

# --------------------------------------------------------------------------- #
# Incident zone: the root authorization envelope
# --------------------------------------------------------------------------- #

zone := input.incident_zone

zone_active if {
	zone.status == "active"
	from_ns := time.parse_rfc3339_ns(zone.authorized_from)
	until_ns := time.parse_rfc3339_ns(zone.authorized_until)
	now_ns := time.parse_rfc3339_ns(input.now)

	now_ns >= from_ns
	now_ns < until_ns
}

deny contains {
	"code": "zone_inactive",
	"detail": "the incident zone is not active at this instant; its status or authorization window does not permit dispatch",
} if {
	input_complete
	not zone_active
}

deny contains {
	"code": "not_authorized_for_zone",
	"detail": sprintf("operator %q is not scoped to incident zone %q", [input.principal.operator_id, zone.incident_zone_id]),
} if {
	input_complete
	not operator_scoped
}

operator_scoped if {
	some authorized in zone.authorized_operator_ids
	authorized == input.principal.operator_id
}

# --------------------------------------------------------------------------- #
# Polygon-in-polygon containment
# --------------------------------------------------------------------------- #

contained if {
	geometry.polygon_contains(zone.boundary, input.request.polygon)
}

deny contains {
	"code": "outside_incident_zone",
	"detail": "the proposed polygon is not wholly contained within the incident zone boundary",
} if {
	input_complete
	not contained
}

# --------------------------------------------------------------------------- #
# Altitude and velocity bounding
# --------------------------------------------------------------------------- #

deny contains {
	"code": "altitude_band_inverted",
	"detail": "altitude_min_m_agl must be strictly below altitude_max_m_agl",
} if {
	input_complete
	input.request.altitude_min_m_agl >= input.request.altitude_max_m_agl
}

# Platform envelope. Hard bounds from `data`, never from the request.
deny contains {
	"code": "envelope_violation",
	"detail": sprintf("requested ceiling %v m AGL exceeds the platform envelope ceiling %v m AGL", [input.request.altitude_max_m_agl, envelope.altitude_max_agl_m]),
} if {
	input_complete
	input.request.altitude_max_m_agl > envelope.altitude_max_agl_m
}

deny contains {
	"code": "envelope_violation",
	"detail": sprintf("requested floor %v m AGL is below the platform envelope floor %v m AGL", [input.request.altitude_min_m_agl, envelope.altitude_min_agl_m]),
} if {
	input_complete
	input.request.altitude_min_m_agl < envelope.altitude_min_agl_m
}

deny contains {
	"code": "envelope_violation",
	"detail": sprintf("requested velocity %v m/s exceeds the platform maximum %v m/s", [input.request.velocity_max_mps, envelope.ground_speed_max_mps]),
} if {
	input_complete
	input.request.velocity_max_mps > envelope.ground_speed_max_mps
}

deny contains {
	"code": "envelope_violation",
	"detail": "requested velocity must be positive",
} if {
	input_complete
	input.request.velocity_max_mps <= 0
}

deny contains {
	"code": "envelope_violation",
	"detail": sprintf("requested duration %v s exceeds the mission maximum %v s", [input.request.duration_s, envelope.mission_duration_max_s]),
} if {
	input_complete
	is_number(input.request.duration_s)
	input.request.duration_s > envelope.mission_duration_max_s
}

# Zone ceiling. A zone may narrow the envelope; a request may not exceed the narrowed
# bound. This is what stops a per-mission value from buying altitude.
deny contains {
	"code": "zone_altitude_violation",
	"detail": sprintf("requested ceiling %v m AGL exceeds the incident zone ceiling %v m AGL", [input.request.altitude_max_m_agl, zone.altitude_ceiling_m_agl]),
} if {
	input_complete
	is_number(zone.altitude_ceiling_m_agl)
	input.request.altitude_max_m_agl > zone.altitude_ceiling_m_agl
}

deny contains {
	"code": "zone_altitude_violation",
	"detail": sprintf("requested floor %v m AGL is below the incident zone floor %v m AGL", [input.request.altitude_min_m_agl, zone.altitude_floor_m_agl]),
} if {
	input_complete
	is_number(zone.altitude_floor_m_agl)
	input.request.altitude_min_m_agl < zone.altitude_floor_m_agl
}

# --------------------------------------------------------------------------- #
# Sovereign airspace clearance
# --------------------------------------------------------------------------- #

deny contains {
	"code": "clearance_invalid",
	"detail": "no valid sovereign airspace clearance covers this volume; a stale, unreachable, negative or mismatched clearance fails the dispatch closed",
} if {
	input_complete
	not clearance.valid
}

# Named separately from the catch-all above so an operator sees WHICH restriction
# blocked them rather than a generic clearance failure.
deny contains {
	"code": "airspace_conflict",
	"detail": sprintf("proposed volume intersects blocking sovereign restriction %q", [zone_id]),
} if {
	input_complete
	some zone_id in object.get(input.clearance, "blocking_zone_ids", [])
}

# --------------------------------------------------------------------------- #
# Fleet availability and battery-range sufficiency
# --------------------------------------------------------------------------- #

deny contains {
	"code": "fleet_unavailable",
	"detail": "no drone is available for dispatch",
} if {
	input_complete
	count(object.get(input.fleet, "available_drone_ids", [])) == 0
}

# Required energy is scaled by the reserve factor before comparison, so a mission that
# would arrive home exactly empty is refused.
deny contains {
	"code": "insufficient_battery_range",
	"detail": sprintf("candidate drone endurance %v s does not cover %v s of mission plus the %vx reserve", [endurance, input.request.duration_s, envelope.battery_range_reserve_factor]),
} if {
	input_complete
	endurance := input.fleet.candidate.endurance_s
	is_number(endurance)
	is_number(input.request.duration_s)
	endurance < input.request.duration_s * envelope.battery_range_reserve_factor
}

deny contains {
	"code": "insufficient_battery_range",
	"detail": sprintf("candidate drone battery %v%% is at or below the %v%% RTL trigger", [battery, envelope.battery_rtl_trigger_pct]),
} if {
	input_complete
	battery := input.fleet.candidate.battery_pct
	is_number(battery)
	battery <= envelope.battery_rtl_trigger_pct
}

# --------------------------------------------------------------------------- #
# Human confirmation
# --------------------------------------------------------------------------- #

# An allowed plan is STAGED, never dispatched. Master Plan Sec.3: every agent-proposed
# plan requires explicit operator confirmation unless it exactly matches a pre-approved
# template. Expressed as an output obligation rather than a deny, because the plan is
# legitimately allowed to exist -- it just may not fly yet.
requires_human_confirmation if {
	input.principal.role == "ai_agent"
}

requires_human_confirmation if {
	not input.request.matches_approved_template
}
