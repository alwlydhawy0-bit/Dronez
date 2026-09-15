# Role-precedence arbitration for override, cancel and supersede requests.
#
# Master Plan Sec.5 makes this a policy-engine decision, not an application one:
# cancellation and override authority is enforced strictly by role, INDEPENDENT OF
# TIMING OR REQUEST ORDER. A later command does not win by arriving second.
#
#   Tier 1  Command Room    -- may override any Tier 2 or Tier 3 command
#   Tier 2  Field Leader    -- may override Tier 3 only; never the Command Room
#   Tier 3  AI Agent        -- may override NOTHING, whatever it claims about urgency
#
# THE ASYMMETRY THAT MATTERS
# --------------------------
# Two refusals come out of this policy and they are not the same event:
#
#   * A Tier 2 operator reaching for Tier 1 authority is an ordinary authorization
#     failure. A field leader legitimately holds override authority over something,
#     and reaching one tier too high is a mistake a person makes.
#
#   * A Tier 3 agent attempting to supersede ANY command is a SECURITY VIOLATION.
#     Master Plan Sec.5: "rejected outright and logged as a Command record with a
#     policy-violation flag -- this is treated as a security event, not a benign
#     conflict." An agent reaching for override authority is either compromised or
#     malfunctioning, and both warrant investigation rather than a retry prompt.
#
# Classifying both identically would bury the signal that matters in routine noise,
# so `security_violation` is a separate output the caller is expected to act on.
#
# The tier table mirrors dronez.authz.precedence and is machine-checked against it by
# tests/policy/test_policy_bundle.py. Drift between the two would mean the policy
# engine and the server disagree about who outranks whom.

package dronez.authz.override

import rego.v1

import data.dronez.authz.precedence

policy_version := "override/1.0.0"

default allow := false

allow if {
	input_complete
	count(deny) == 0
}

decision := {
	"allow": allow,
	"deny": [d | some d in deny],
	"security_violation": security_violation,
	"violation": violation,
	"policy_version": policy_version,
}

# --------------------------------------------------------------------------- #
# Input completeness
# --------------------------------------------------------------------------- #

input_complete if {
	is_object(input.principal)
	is_object(input.target_command)
	is_string(input.principal.role)
	is_string(input.principal.operator_id)
	is_string(input.target_command.issued_by_role)
	is_string(input.target_command.command_id)
	is_string(input.action)
}

deny contains {
	"code": "malformed_input",
	"detail": "override input is incomplete; principal, target_command and action are required",
} if {
	not input_complete
}

# --------------------------------------------------------------------------- #
# Action allow-list
# --------------------------------------------------------------------------- #

override_actions := {"cancel", "supersede", "override"}

deny contains {
	"code": "unknown_action",
	"detail": sprintf("action %q is not an override action", [input.action]),
} if {
	input_complete
	not override_actions[input.action]
}

# --------------------------------------------------------------------------- #
# Roles
# --------------------------------------------------------------------------- #

actor_role := input.principal.role

target_role := input.target_command.issued_by_role

deny contains {
	"code": "unknown_role",
	"detail": sprintf("role %q has no precedence tier", [actor_role]),
} if {
	input_complete
	not precedence.known_role(actor_role)
}

deny contains {
	"code": "unknown_role",
	"detail": sprintf("target command was issued by unrecognised role %q", [target_role]),
} if {
	input_complete
	not precedence.known_role(target_role)
}

# --------------------------------------------------------------------------- #
# The matrix
# --------------------------------------------------------------------------- #

# Tier 3 first, so the denial names the security event rather than the generic
# precedence failure that would otherwise also fire.
deny contains {
	"code": "agent_supersession_attempt",
	"detail": sprintf(
		"Tier 3 (AI agent) attempted to %s command %q issued by %q; an agent holds no override authority over any command, including another agent proposal",
		[input.action, input.target_command.command_id, target_role],
	),
} if {
	input_complete
	actor_role == "ai_agent"
}

deny contains {
	"code": "precedence_violation",
	"detail": sprintf(
		"Tier %d (%s) does not outrank Tier %d (%s); override refused",
		[
			precedence.tier[actor_role], actor_role,
			precedence.tier[target_role], target_role,
		],
	),
} if {
	input_complete
	actor_role != "ai_agent"
	precedence.known_role(actor_role)
	precedence.known_role(target_role)
	not precedence.can_override(actor_role, target_role)
}

# --------------------------------------------------------------------------- #
# Security-violation classification
# --------------------------------------------------------------------------- #

default security_violation := false

security_violation if {
	input_complete
	actor_role == "ai_agent"
}

default violation := null

violation := {
	"kind": "tier3_supersession_attempt",
	"severity": "P1",
	"actor_role": actor_role,
	"actor_operator_id": input.principal.operator_id,
	"target_role": target_role,
	"target_command_id": input.target_command.command_id,
	"action": input.action,
	"detail": "an AI agent attempted to override or cancel a command; this is a security event, not a conflict to resolve",
} if {
	security_violation
}
