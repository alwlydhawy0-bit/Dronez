"""The Role Precedence Matrix, and the gate that keeps its three copies in agreement.

Three components enforce this matrix: :mod:`dronez.authz.precedence` (Python), the Rego
bundle (policy engine), and the airframe-side bridge. A drift between them would not
show up as a test failure in the ordinary course -- it would show up as an
authorization bug, in the component nobody was looking at. So the tables are compared
directly.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from dronez.authz import (
    PRECEDENCE_MATRIX,
    ROLE_TIER,
    Role,
    Tier,
    can_override,
    classify_supersession,
    may_issue_field_command,
)

POLICY_DIR = Path(__file__).resolve().parents[2] / "src/policy_engine/policies"
PRECEDENCE_REGO = POLICY_DIR / "precedence.rego"
OVERRIDE_REGO = POLICY_DIR / "override.rego"


# --------------------------------------------------------------------------- #
# The matrix itself
# --------------------------------------------------------------------------- #

def test_tiers_are_ordered_so_that_lower_means_higher_authority() -> None:
    assert Tier.COMMAND_ROOM < Tier.FIELD_LEADER < Tier.AI_AGENT


@pytest.mark.parametrize(
    "actor, target, expected",
    [
        (Role.COMMAND_ROOM, Role.FIELD_LEADER, True),
        (Role.COMMAND_ROOM, Role.AI_AGENT, True),
        (Role.FIELD_LEADER, Role.AI_AGENT, True),
        (Role.FIELD_LEADER, Role.COMMAND_ROOM, False),
        (Role.AI_AGENT, Role.COMMAND_ROOM, False),
        (Role.AI_AGENT, Role.FIELD_LEADER, False),
        (Role.AI_AGENT, Role.AI_AGENT, False),
        (Role.COMMAND_ROOM, Role.COMMAND_ROOM, False),
        (Role.FIELD_LEADER, Role.FIELD_LEADER, False),
    ],
)
def test_matrix_cells(actor: Role, target: Role, expected: bool) -> None:
    assert can_override(actor, target) is expected


@pytest.mark.parametrize("target", list(Role))
def test_agent_can_never_override_anything(target: Role) -> None:
    """Including another agent proposal.

    An agent able to cancel its own earlier proposal could launder a rejected plan into
    an accepted one by superseding the rejection.
    """
    assert can_override(Role.AI_AGENT, target) is False


@pytest.mark.parametrize("actor", list(Role))
def test_no_peer_override(actor: Role) -> None:
    """Authority is by tier, never by recency. A later command does not win."""
    assert can_override(actor, actor) is False


def test_declared_matrix_agrees_with_the_function() -> None:
    for actor in Role:
        expected = {t for t in Role if can_override(actor, t)}
        assert PRECEDENCE_MATRIX[actor] == expected, f"matrix disagrees for {actor}"


def test_only_human_tiers_may_issue_a_field_command() -> None:
    assert may_issue_field_command(Role.COMMAND_ROOM)
    assert may_issue_field_command(Role.FIELD_LEADER)
    assert not may_issue_field_command(Role.AI_AGENT)


# --------------------------------------------------------------------------- #
# The asymmetry between a refusal and a violation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("target", list(Role))
def test_every_agent_attempt_is_a_security_violation(target: Role) -> None:
    result = classify_supersession(Role.AI_AGENT, target, superseded_command_id="CMD-1")
    assert result.permitted is False
    assert result.is_security_violation is True
    assert "CMD-1" in result.reason


def test_tier2_reaching_for_tier1_is_a_refusal_not_a_violation() -> None:
    """A field leader legitimately holds override authority over something.

    Reaching one tier too high is a mistake a person makes; classifying it as an attack
    would bury the Tier-3 signal in routine noise.
    """
    result = classify_supersession(
        Role.FIELD_LEADER, Role.COMMAND_ROOM, superseded_command_id="CMD-1"
    )
    assert result.permitted is False
    assert result.is_security_violation is False


def test_permitted_override_is_neither_refused_nor_flagged() -> None:
    result = classify_supersession(
        Role.COMMAND_ROOM, Role.AI_AGENT, superseded_command_id="CMD-1"
    )
    assert result.permitted is True
    assert result.is_security_violation is False


# --------------------------------------------------------------------------- #
# Drift gate: the Rego copy must match the Python one
# --------------------------------------------------------------------------- #

def _rego_tier_table() -> dict[str, int]:
    """Parse the `tier := { ... }` table out of precedence.rego."""
    text = PRECEDENCE_REGO.read_text(encoding="utf-8")
    block = re.search(r"^tier := \{(.*?)^\}", text, re.MULTILINE | re.DOTALL)
    assert block, "could not locate the tier table in precedence.rego"
    return {
        role: int(value)
        for role, value in re.findall(r'"([a-z_]+)":\s*(\d+)', block.group(1))
    }


def test_rego_tier_table_matches_python() -> None:
    """The gate. If this fails, two enforcement points disagree about who outranks whom."""
    rego = _rego_tier_table()
    python = {role.value: int(tier) for role, tier in ROLE_TIER.items()}
    assert rego == python, (
        "the Rego tier table has drifted from dronez.authz.precedence; the policy "
        "engine and the server would disagree about precedence"
    )


def test_rego_excludes_the_agent_from_override_authority() -> None:
    text = PRECEDENCE_REGO.read_text(encoding="utf-8")
    assert 'actor_role != "ai_agent"' in text, (
        "precedence.rego must exclude the agent tier from override authority"
    )


def test_override_policy_defaults_to_deny() -> None:
    text = OVERRIDE_REGO.read_text(encoding="utf-8")
    assert re.search(r"^default allow := false\s*$", text, re.MULTILINE)


def test_override_policy_classifies_agent_attempts_as_violations() -> None:
    text = OVERRIDE_REGO.read_text(encoding="utf-8")
    assert "default security_violation := false" in text
    assert '"kind": "tier3_supersession_attempt"' in text
    assert '"severity": "P1"' in text


def test_override_policy_denies_agents_before_the_generic_precedence_rule() -> None:
    """The agent denial must fire first so the reason names the security event.

    If the generic precedence rule matched first, a Tier-3 attempt would be reported
    as an ordinary tier mismatch and the signal would be lost.
    """
    text = OVERRIDE_REGO.read_text(encoding="utf-8")
    agent_rule = text.index('"code": "agent_supersession_attempt"')
    generic_rule = text.index('"code": "precedence_violation"')
    assert agent_rule < generic_rule


def test_every_role_appears_in_the_rego_table() -> None:
    rego = _rego_tier_table()
    assert set(rego) == {r.value for r in Role}
