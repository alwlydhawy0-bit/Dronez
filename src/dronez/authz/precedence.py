"""The Role Precedence Matrix.

Master Plan §5: cancellation and override authority is enforced strictly by role, at
the policy-engine layer, **independent of timing or request order**. A later command
does not win by arriving second.

======  =====================  ==================================================
Tier    Role                   May override / cancel
======  =====================  ==================================================
1       Command Room           Any Tier 2 or Tier 3 command
2       Tactical Field Leader  Tier 3 only -- never the Command Room
3       AI Agent proposal      **Nothing**, regardless of its own stated confidence
                               or claimed urgency
======  =====================  ==================================================

Why this is stdlib and lives in ``dronez``
------------------------------------------
Three components enforce this matrix: the policy engine (Rego), the MCP server
(Python), and the airframe-side bridge before it signs a frame. They must agree
exactly, so the matrix is defined once, here, in a package none of them owns.

The Rego copy is machine-checked against this module by
``tests/policy/test_policy_bundle.py``. A tier table that drifts between the two would
mean the policy engine and the server disagree about who outranks whom -- and the
disagreement would surface as an authorization bug, not a test failure.

The Tier-3 rule is absolute and includes *other agent proposals*: an agent able to
cancel its own earlier proposal could launder a rejected plan into an accepted one by
superseding the rejection.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Final

__all__ = [
    "PRECEDENCE_MATRIX",
    "ROLE_TIER",
    "Role",
    "SupersessionAttempt",
    "Tier",
    "can_override",
    "classify_supersession",
    "may_issue_field_command",
]


class Tier(IntEnum):
    """Precedence tier. **Lower value means higher authority.**

    ``IntEnum`` so that ``<`` reads as "outranks" -- which is the point of using it
    rather than free-form strings that invite an accidental lexical comparison.
    """

    COMMAND_ROOM = 1
    FIELD_LEADER = 2
    AI_AGENT = 3


class Role(StrEnum):
    """Issuing role. Maps 1:1 onto a :class:`Tier`."""

    COMMAND_ROOM = "command_room"
    FIELD_LEADER = "field_leader"
    AI_AGENT = "ai_agent"

    @property
    def tier(self) -> Tier:
        return ROLE_TIER[self]

    @property
    def is_human(self) -> bool:
        return self is not Role.AI_AGENT


ROLE_TIER: Final[dict[Role, Tier]] = {
    Role.COMMAND_ROOM: Tier.COMMAND_ROOM,
    Role.FIELD_LEADER: Tier.FIELD_LEADER,
    Role.AI_AGENT: Tier.AI_AGENT,
}

#: The matrix as data, for the drift test against the Rego bundle and for rendering in
#: an operator console. ``actor -> roles it may override``.
PRECEDENCE_MATRIX: Final[dict[Role, frozenset[Role]]] = {
    Role.COMMAND_ROOM: frozenset({Role.FIELD_LEADER, Role.AI_AGENT}),
    Role.FIELD_LEADER: frozenset({Role.AI_AGENT}),
    Role.AI_AGENT: frozenset(),
}


def can_override(actor: Role, target: Role) -> bool:
    """Whether ``actor`` may cancel or override a command issued by ``target``.

    Two properties are load-bearing and are asserted by tests:

    * The AI agent can never override anything, including another agent proposal.
    * Authority is strictly by tier, never by recency, and **never between peers**: a
      Command Room operator cannot override another Command Room operator's command
      through this path. Peer disputes are resolved by a human, not by whoever's
      request arrived last.
    """
    if actor is Role.AI_AGENT:
        return False
    return actor.tier < target.tier


def may_issue_field_command(actor: Role) -> bool:
    """Whether ``actor`` may author a command that reaches hardware.

    Only the human tiers. A Tier-3 proposal is a *proposal*; it becomes a field command
    only once a human authorizes it, and the authorization carries that human's
    signature rather than the agent's.
    """
    return actor.is_human


@dataclass(frozen=True, slots=True)
class SupersessionAttempt:
    """Classification of a request that tries to supersede an existing command."""

    permitted: bool
    actor: Role
    target: Role
    #: True when this is a security event rather than a benign authorization failure.
    is_security_violation: bool
    reason: str


def classify_supersession(
    actor: Role, target: Role, *, superseded_command_id: str
) -> SupersessionAttempt:
    """Decide whether a supersession is permitted, and how a refusal should be treated.

    The distinction that matters: a **Tier-3 supersession attempt is a security event,
    not a benign conflict** (Master Plan §5). An agent attempting to cancel a human's
    command is either compromised or malfunctioning, and both warrant investigation
    rather than a retry prompt.

    A Tier-2 operator attempting to override Tier 1 is also refused, but it is an
    ordinary authorization failure: a field leader legitimately holds override
    authority over *something*, and reaching for it one tier too high is a mistake a
    person makes. Classifying both identically would bury the signal that matters in
    routine noise.
    """
    if actor is Role.AI_AGENT:
        return SupersessionAttempt(
            permitted=False,
            actor=actor,
            target=target,
            is_security_violation=True,
            reason=(
                f"Tier 3 (AI agent) attempted to supersede command "
                f"{superseded_command_id!r} issued by Tier {int(target.tier)} "
                f"({target.value}); an agent holds no override authority over any "
                "command, and the attempt is recorded as a security event"
            ),
        )

    if can_override(actor, target):
        return SupersessionAttempt(
            permitted=True,
            actor=actor,
            target=target,
            is_security_violation=False,
            reason=(
                f"Tier {int(actor.tier)} ({actor.value}) outranks Tier "
                f"{int(target.tier)} ({target.value})"
            ),
        )

    return SupersessionAttempt(
        permitted=False,
        actor=actor,
        target=target,
        is_security_violation=False,
        reason=(
            f"Tier {int(actor.tier)} ({actor.value}) does not outrank Tier "
            f"{int(target.tier)} ({target.value}); override refused"
        ),
    )
