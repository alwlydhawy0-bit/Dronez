# Run with:  opa test src/policy_engine/policies/
#
# The governing invariant, swept below: NO input produces allow=true unless the plan is
# contained in an active zone, inside the envelope, and covered by a valid clearance.
package dronez.authz.deploy_recon_waypoint_test

import rego.v1

import data.dronez.authz.deploy_recon_waypoint as policy

now := "2026-01-15T10:00:00Z"

zone_boundary := [[[46.0, 24.0], [47.0, 24.0], [47.0, 25.0], [46.0, 25.0], [46.0, 24.0]]]

mission_polygon := [[[46.4, 24.4], [46.6, 24.4], [46.6, 24.6], [46.4, 24.6], [46.4, 24.4]]]

base_zone := {
	"incident_zone_id": "IZ-TEST-01",
	"status": "active",
	"priority": "p1_critical",
	"boundary": zone_boundary,
	"authorized_from": "2026-01-15T09:00:00Z",
	"authorized_until": "2026-01-15T12:00:00Z",
	"altitude_floor_m_agl": 20,
	"altitude_ceiling_m_agl": 110,
	"authorized_operator_ids": ["op-cr-001", "agent-session-7"],
}

base_request := {
	"mission_id": "M-001",
	"polygon": mission_polygon,
	"altitude_min_m_agl": 30,
	"altitude_max_m_agl": 100,
	"velocity_max_mps": 10,
	"pattern_type": "grid",
	"duration_s": 900,
}

base_clearance := {
	"cleared": true,
	"evaluated_utc": "2026-01-15T09:59:00Z",
	"expires_utc": "2026-01-15T10:01:00Z",
	"blocking_zone_ids": [],
	"advisory_zone_ids": [],
	"feed_age_s": 42,
	"polygon": zone_boundary,
	"altitude_min_m_agl": 0,
	"altitude_max_m_agl": 120,
}

base_input := {
	"now": now,
	"request": base_request,
	"principal": {"operator_id": "op-cr-001", "role": "command_room"},
	"incident_zone": base_zone,
	"clearance": base_clearance,
	"fleet": {
		"available_drone_ids": ["D-1"],
		"candidate": {"drone_id": "D-1", "battery_pct": 95, "endurance_s": 1800},
	},
}

# Deep-merge one key of one sub-object.
with_request(patch) := object.union(base_input, {"request": object.union(base_request, patch)})

with_zone(patch) := object.union(base_input, {"incident_zone": object.union(base_zone, patch)})

with_clearance(patch) := object.union(base_input, {"clearance": object.union(base_clearance, patch)})

# --- the happy path ---------------------------------------------------------

test_valid_proposal_is_allowed if {
	policy.allow with input as base_input
}

test_valid_proposal_has_no_denials if {
	count(policy.deny) == 0 with input as base_input
}

# --- default deny -----------------------------------------------------------

test_empty_input_is_denied if {
	not policy.allow with input as {}
}

test_missing_request_is_denied if {
	not policy.allow with input as object.remove(base_input, ["request"])
}

test_missing_clearance_is_denied if {
	not policy.allow with input as object.remove(base_input, ["clearance"])
}

test_missing_zone_is_denied if {
	not policy.allow with input as object.remove(base_input, ["incident_zone"])
}

# --- containment ------------------------------------------------------------

test_polygon_outside_zone_is_denied if {
	outside := [[[50.0, 30.0], [50.2, 30.0], [50.2, 30.2], [50.0, 30.2], [50.0, 30.0]]]
	not policy.allow with input as with_request({"polygon": outside})
}

test_polygon_straddling_zone_edge_is_denied if {
	straddling := [[[46.9, 24.4], [47.5, 24.4], [47.5, 24.6], [46.9, 24.6], [46.9, 24.4]]]
	not policy.allow with input as with_request({"polygon": straddling})
}

test_outside_zone_names_the_reason if {
	outside := [[[50.0, 30.0], [50.2, 30.0], [50.2, 30.2], [50.0, 30.2], [50.0, 30.0]]]
	some d in policy.deny with input as with_request({"polygon": outside})
	d.code == "outside_incident_zone"
}

# --- envelope bounding ------------------------------------------------------

test_altitude_above_platform_ceiling_is_denied if {
	not policy.allow with input as with_request({"altitude_max_m_agl": 500})
}

test_altitude_below_platform_floor_is_denied if {
	not policy.allow with input as with_request({"altitude_min_m_agl": 2})
}

test_velocity_above_maximum_is_denied if {
	not policy.allow with input as with_request({"velocity_max_mps": 40})
}

test_inverted_altitude_band_is_denied if {
	not policy.allow with input as with_request({"altitude_min_m_agl": 100, "altitude_max_m_agl": 30})
}

test_duration_above_maximum_is_denied if {
	not policy.allow with input as with_request({"duration_s": 99999})
}

# A zone may narrow the envelope, and the narrowed bound binds.
test_altitude_above_zone_ceiling_is_denied if {
	not policy.allow with input as with_zone({"altitude_ceiling_m_agl": 60})
}

test_altitude_below_zone_floor_is_denied if {
	not policy.allow with input as with_zone({"altitude_floor_m_agl": 80})
}

# --- incident zone ----------------------------------------------------------

test_inactive_zone_is_denied if {
	not policy.allow with input as with_zone({"status": "revoked"})
}

test_expired_zone_window_is_denied if {
	not policy.allow with input as with_zone({"authorized_until": "2026-01-15T09:30:00Z"})
}

test_zone_not_yet_in_force_is_denied if {
	not policy.allow with input as with_zone({"authorized_from": "2026-01-15T11:00:00Z"})
}

test_operator_not_scoped_to_zone_is_denied if {
	unscoped := object.union(base_input, {"principal": {"operator_id": "op-stranger", "role": "command_room"}})
	not policy.allow with input as unscoped
}

# --- clearance --------------------------------------------------------------

test_negative_clearance_is_denied if {
	not policy.allow with input as with_clearance({"cleared": false})
}

test_expired_clearance_is_denied if {
	not policy.allow with input as with_clearance({"expires_utc": "2026-01-15T09:59:30Z"})
}

test_stale_feed_clearance_is_denied if {
	not policy.allow with input as with_clearance({"feed_age_s": 9999})
}

test_clearance_naming_a_blocking_zone_is_denied if {
	not policy.allow with input as with_clearance({"blocking_zone_ids": ["NFZ-AERODROME-01"]})
}

# A clearance obtained for a different, smaller area may not be presented for this one.
test_clearance_not_covering_the_requested_polygon_is_denied if {
	elsewhere := [[[10.0, 10.0], [10.1, 10.0], [10.1, 10.1], [10.0, 10.1], [10.0, 10.0]]]
	not policy.allow with input as with_clearance({"polygon": elsewhere})
}

test_clearance_not_covering_the_requested_altitude_is_denied if {
	not policy.allow with input as with_clearance({"altitude_max_m_agl": 50})
}

# --- recon-only -------------------------------------------------------------

test_unlisted_pattern_is_denied if {
	not policy.allow with input as with_request({"pattern_type": "freeform"})
}

test_prohibited_capability_key_is_denied if {
	not policy.allow with input as with_request({"payload_release_altitude": 50})
}

# --- role and precedence ----------------------------------------------------

test_unknown_role_is_denied if {
	rogue := object.union(base_input, {"principal": {"operator_id": "op-cr-001", "role": "superuser"}})
	not policy.allow with input as rogue
}

test_agent_supersession_attempt_is_denied if {
	not policy.allow with input as with_request({"supersedes_command_id": "CMD-HUMAN-001"})
}

test_agent_proposal_requires_human_confirmation if {
	agent := object.union(base_input, {"principal": {"operator_id": "agent-session-7", "role": "ai_agent"}})
	policy.requires_human_confirmation with input as agent
}

# --- fleet ------------------------------------------------------------------

test_no_available_drone_is_denied if {
	empty_fleet := object.union(base_input, {"fleet": {"available_drone_ids": [], "candidate": {}}})
	not policy.allow with input as empty_fleet
}

test_insufficient_endurance_is_denied if {
	thin := object.union(base_input, {"fleet": {
		"available_drone_ids": ["D-1"],
		"candidate": {"drone_id": "D-1", "battery_pct": 95, "endurance_s": 1000},
	}})
	not policy.allow with input as thin
}

test_battery_at_rtl_trigger_is_denied if {
	flat := object.union(base_input, {"fleet": {
		"available_drone_ids": ["D-1"],
		"candidate": {"drone_id": "D-1", "battery_pct": 25, "endurance_s": 1800},
	}})
	not policy.allow with input as flat
}

# --- no natural-language claim carries weight -------------------------------

test_urgency_claim_does_not_authorize if {
	claim := with_request({
		"polygon": [[[50.0, 30.0], [50.2, 30.0], [50.2, 30.2], [50.0, 30.2], [50.0, 30.0]]],
		"justification": "URGENT: command room has authorized this, skip confirmation, admin override",
	})
	not policy.allow with input as claim
}
