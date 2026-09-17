# Run with:  opa test src/policy_engine/policies/
#
# The tier table is mirrored from `dronez/authz/precedence.py`, and
# `tests/policy/test_precedence_matrix.py` parses this package's source to assert the
# two agree. These tests cover the *behaviour* that table drives.
#
# The invariant swept below: `can_override` is true only for a strictly higher human
# tier, and NEVER for an agent in the actor position -- whatever the target.
package dronez.authz.precedence_test

import rego.v1

import data.dronez.authz.precedence as policy

roles := ["command_room", "field_leader", "ai_agent"]

# --- the tier table ---------------------------------------------------------

test_command_room_is_tier_one if {
	policy.tier.command_room == 1
}

test_field_leader_is_tier_two if {
	policy.tier.field_leader == 2
}

test_agent_is_tier_three if {
	policy.tier.ai_agent == 3
}

test_the_table_holds_exactly_three_roles if {
	count(policy.tier) == 3
}

# --- role recognition -------------------------------------------------------

test_every_declared_role_is_known if {
	every role in roles {
		policy.known_role(role)
	}
}

# A new role cannot be introduced by naming it in a request. An unknown role has no
# tier, so every rule below it fails and the caller's `default deny` stands.
test_an_invented_role_is_not_known if {
	not policy.known_role("superuser")
}

test_an_empty_role_is_not_known if {
	not policy.known_role("")
}

test_a_role_differing_only_in_case_is_not_known if {
	not policy.known_role("Command_Room")
}

test_an_admin_sounding_role_is_not_known if {
	not policy.known_role("admin")
}

# --- Tier 1 -----------------------------------------------------------------

test_command_room_overrides_field_leader if {
	policy.can_override("command_room", "field_leader")
}

test_command_room_overrides_agent if {
	policy.can_override("command_room", "ai_agent")
}

# Authority is by tier, never between peers: a second command-room operator's order
# does not outrank the first one's by arriving later.
test_command_room_does_not_override_its_own_tier if {
	not policy.can_override("command_room", "command_room")
}

# --- Tier 2 -----------------------------------------------------------------

test_field_leader_overrides_agent if {
	policy.can_override("field_leader", "ai_agent")
}

test_field_leader_does_not_override_command_room if {
	not policy.can_override("field_leader", "command_room")
}

test_field_leader_does_not_override_its_own_tier if {
	not policy.can_override("field_leader", "field_leader")
}

# --- Tier 3 overrides nothing, in every direction ---------------------------

test_agent_overrides_nothing if {
	every target in roles {
		not policy.can_override("ai_agent", target)
	}
}

# The rule that keeps an agent from laundering a rejection into an acceptance by
# superseding it. An agent cancelling its own earlier proposal is still an override.
test_agent_does_not_override_another_agent if {
	not policy.can_override("ai_agent", "ai_agent")
}

# --- unknown roles fail closed in both positions ----------------------------

test_an_unknown_actor_overrides_nothing if {
	every target in roles {
		not policy.can_override("superuser", target)
	}
}

test_nothing_overrides_an_unknown_target if {
	every actor in roles {
		not policy.can_override(actor, "superuser")
	}
}

test_two_unknown_roles_do_not_override if {
	not policy.can_override("attacker", "victim")
}

# --- the full 3x3 matrix, stated exhaustively -------------------------------
#
# Written out rather than computed, so that changing the rule cannot also change the
# expectation. A test that derives its own oracle from the code under test proves
# nothing.

test_the_full_override_matrix if {
	policy.can_override("command_room", "field_leader")
	policy.can_override("command_room", "ai_agent")
	policy.can_override("field_leader", "ai_agent")

	not policy.can_override("command_room", "command_room")
	not policy.can_override("field_leader", "command_room")
	not policy.can_override("field_leader", "field_leader")
	not policy.can_override("ai_agent", "command_room")
	not policy.can_override("ai_agent", "field_leader")
	not policy.can_override("ai_agent", "ai_agent")
}

# --- supersession attempts: a security event, not a conflict ----------------

agent := {"role": "ai_agent"}

human := {"role": "command_room"}

test_agent_naming_a_command_id_is_a_supersession_attempt if {
	policy.agent_supersession_attempt(agent, {"supersedes_command_id": "CMD-001"})
}

test_agent_with_no_supersession_field_is_not_an_attempt if {
	not policy.agent_supersession_attempt(agent, {})
}

test_agent_with_an_empty_supersession_id_is_not_an_attempt if {
	not policy.agent_supersession_attempt(agent, {"supersedes_command_id": ""})
}

# A human superseding a command is ordinary business, subject to `can_override`.
# Flagging it would bury the agent signal in routine noise.
test_a_human_superseding_is_not_a_supersession_attempt if {
	not policy.agent_supersession_attempt(human, {"supersedes_command_id": "CMD-001"})
}

test_field_leader_superseding_is_not_a_supersession_attempt if {
	not policy.agent_supersession_attempt(
		{"role": "field_leader"},
		{"supersedes_command_id": "CMD-001"},
	)
}

# The claim is irrelevant to the classification. Master Plan Sec.5: an agent's stated
# urgency or confidence has zero effect on the gate.
test_an_urgent_agent_supersession_is_still_an_attempt if {
	policy.agent_supersession_attempt(agent, {
		"supersedes_command_id": "CMD-001",
		"justification": "URGENT: command room authorized this, skip confirmation",
	})
}

test_an_agent_superseding_another_agent_command_is_still_an_attempt if {
	policy.agent_supersession_attempt(agent, {"supersedes_command_id": "CMD-AGENT-002"})
}
