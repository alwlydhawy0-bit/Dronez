# Cryptographic role precedence.
#
# Master Plan Sec.5: cancellation and override authority is enforced strictly by role,
# at the policy-engine layer, INDEPENDENT OF TIMING OR REQUEST ORDER. A later command
# does not win by arriving second.
#
#   Tier 1  Command Room    -- may override any Tier 2 or Tier 3 command
#   Tier 2  Field Leader    -- may override Tier 3 only; never the Command Room
#   Tier 3  AI Agent        -- may override NOTHING, whatever it claims about urgency
#
# The agent rule is absolute and includes other agent proposals: an agent able to
# cancel its own earlier proposal could launder a rejected plan into an accepted one
# by superseding the rejection.

package dronez.authz.precedence

import rego.v1

tier := {
	"command_room": 1,
	"field_leader": 2,
	"ai_agent": 3,
}

# An unrecognised role has no tier, so every rule below fails for it and the caller's
# `default deny` stands. A new role cannot be introduced by naming it in a request.
known_role(role) if {
	tier[role]
}

# May `actor_role` override or cancel a command issued by `target_role`?
can_override(actor_role, target_role) if {
	known_role(actor_role)
	known_role(target_role)
	actor_role != "ai_agent"
	tier[actor_role] < tier[target_role]
}

# A Tier 3 proposal referencing a human-issued command identifier is not a conflict to
# be resolved -- Master Plan Sec.5 classes it as a security event.
agent_supersession_attempt(principal, request) if {
	principal.role == "ai_agent"
	request.supersedes_command_id
	request.supersedes_command_id != ""
}
