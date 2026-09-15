# Run with:  opa test src/policy_engine/policies/
package dronez.authz.override_test

import rego.v1

import data.dronez.authz.override as policy

base(actor, target) := {
	"now": "2026-01-15T10:00:00Z",
	"action": "cancel",
	"principal": {"operator_id": "op-1", "role": actor},
	"target_command": {
		"command_id": "CMD-0001",
		"issued_by_role": target,
		"issued_by_operator_id": "op-2",
	},
}

# --- the permitted cells of the matrix --------------------------------------

test_command_room_may_override_field_leader if {
	policy.allow with input as base("command_room", "field_leader")
}

test_command_room_may_override_agent if {
	policy.allow with input as base("command_room", "ai_agent")
}

test_field_leader_may_override_agent if {
	policy.allow with input as base("field_leader", "ai_agent")
}

# --- the refused cells ------------------------------------------------------

test_field_leader_may_not_override_command_room if {
	not policy.allow with input as base("field_leader", "command_room")
}

# Authority is by tier, never by recency: a peer cannot override a peer.
test_command_room_may_not_override_a_peer if {
	not policy.allow with input as base("command_room", "command_room")
}

test_field_leader_may_not_override_a_peer if {
	not policy.allow with input as base("field_leader", "field_leader")
}

# --- Tier 3 can override nothing, including itself --------------------------

test_agent_may_not_override_command_room if {
	not policy.allow with input as base("ai_agent", "command_room")
}

test_agent_may_not_override_field_leader if {
	not policy.allow with input as base("ai_agent", "field_leader")
}

# An agent able to cancel its own earlier proposal could launder a rejected plan
# into an accepted one by superseding the rejection.
test_agent_may_not_override_another_agent if {
	not policy.allow with input as base("ai_agent", "ai_agent")
}

# --- the security-violation asymmetry ---------------------------------------

test_agent_attempt_is_a_security_violation if {
	policy.security_violation with input as base("ai_agent", "command_room")
}

test_agent_attempt_emits_a_p1_violation_record if {
	v := policy.violation with input as base("ai_agent", "command_room")
	v.severity == "P1"
	v.kind == "tier3_supersession_attempt"
	v.target_command_id == "CMD-0001"
}

test_agent_denial_names_the_supersession_code if {
	some d in policy.deny with input as base("ai_agent", "field_leader")
	d.code == "agent_supersession_attempt"
}

# A field leader reaching one tier too high is an ordinary authorization failure,
# NOT a security event. Classifying both identically would bury the signal.
test_tier2_over_tier1_is_not_a_security_violation if {
	not policy.security_violation with input as base("field_leader", "command_room")
}

test_tier2_over_tier1_names_the_precedence_code if {
	some d in policy.deny with input as base("field_leader", "command_room")
	d.code == "precedence_violation"
}

test_permitted_override_is_not_a_violation if {
	not policy.security_violation with input as base("command_room", "ai_agent")
}

# --- default deny -----------------------------------------------------------

test_empty_input_is_denied if {
	not policy.allow with input as {}
}

test_missing_target_command_is_denied if {
	not policy.allow with input as object.remove(base("command_room", "ai_agent"), ["target_command"])
}

test_unknown_actor_role_is_denied if {
	not policy.allow with input as base("superuser", "ai_agent")
}

test_unknown_target_role_is_denied if {
	not policy.allow with input as base("command_room", "root")
}

test_unknown_action_is_denied if {
	rogue := object.union(base("command_room", "ai_agent"), {"action": "escalate"})
	not policy.allow with input as rogue
}

# --- every override action is arbitrated the same way ------------------------

test_supersede_is_arbitrated if {
	permitted := object.union(base("command_room", "ai_agent"), {"action": "supersede"})
	refused := object.union(base("ai_agent", "command_room"), {"action": "supersede"})
	policy.allow with input as permitted
	not policy.allow with input as refused
}

test_override_action_is_arbitrated if {
	permitted := object.union(base("field_leader", "ai_agent"), {"action": "override"})
	refused := object.union(base("field_leader", "command_room"), {"action": "override"})
	policy.allow with input as permitted
	not policy.allow with input as refused
}
