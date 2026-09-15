"""Role-precedence enforcement over the real HTTP surface.

Master Plan §5: a Tier-3 proposal that attempts to supersede a higher-tier command is
*"rejected outright and logged as a `Command` record with a policy-violation flag --
this is treated as a security event, not a benign conflict."*

Two things must therefore be true, and both are tested: the request is **rejected**,
and the attempt is **recorded and alerted** as a violation rather than as an ordinary
denial.
"""

from __future__ import annotations

import pytest
from tests.server.conftest import (
    AGENT_TOKEN,
    CR_TOKEN,
    FL_TOKEN,
    Harness,
    deploy_params,
)

from dronez.authz import Role
from mcp_server.audit import Outcome, SecurityViolation, ViolationKind, ViolationSeverity
from mcp_server.precedence import OverrideAction, PrecedenceArbiter, TargetCommand
from policy_engine import PolicyEngine, StaticPolicyTransport


def result_of(response):  # type: ignore[no-untyped-def]
    body = response.json()
    assert "result" in body, f"expected a result, got {body}"
    return body["result"]


# --------------------------------------------------------------------------- #
# Tier 3 supersession through an ordinary proposal
# --------------------------------------------------------------------------- #

def test_agent_supersession_attempt_is_rejected(harness: Harness) -> None:
    result = result_of(harness.rpc(
        "deploy_recon_waypoint",
        deploy_params(supersedes_command_id="CMD-HUMAN-0001"),
        token=AGENT_TOKEN,
    ))
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "precedence_violation"
    assert "CMD-HUMAN-0001" in result["rejection"]["offending_ids"]


def test_agent_supersession_attempt_is_logged_as_a_security_violation(
    harness: Harness,
) -> None:
    """One attempt produces two records, and both are wanted.

    The *violation* record carries the P1 alert payload and is what a SIEM rule fires
    on. The *Command* record is the audit backbone entry for the tool call itself,
    which Master Plan §5 requires for every attempt including rejected ones. Neither
    substitutes for the other: an alert with no Command record has no provenance, and
    a Command record with no alert reaches nobody.
    """
    harness.rpc(
        "deploy_recon_waypoint",
        deploy_params(supersedes_command_id="CMD-HUMAN-0001"),
        token=AGENT_TOKEN,
    )
    records = harness.ctx.audit_sink.by_outcome(Outcome.SECURITY_VIOLATION)
    assert len(records) == 2, f"expected a violation and a Command record, got {len(records)}"
    assert all(r.outcome.is_security_signal for r in records)
    assert all(r.role == "ai_agent" for r in records)

    violations = [r for r in records if "tier3_supersession_attempt" in r.reason_codes]
    assert len(violations) == 1, "exactly one record should carry the alert payload"
    violation = violations[0]
    assert violation.decision["alert"] == "security_violation"
    assert violation.decision["severity"] == "P1"
    assert violation.decision["target"] == "CMD-HUMAN-0001"

    tool_records = [r for r in records if "agent_supersession_attempt" in r.reason_codes]
    assert len(tool_records) == 1, "exactly one record should cover the tool call"
    assert tool_records[0].tool == "deploy_recon_waypoint"


def test_violation_is_recorded_before_any_other_validation(harness: Harness) -> None:
    """Checked first, so an attacker cannot hide a probe behind a bad polygon.

    The polygon here is far outside the incident zone -- the request would fail anyway.
    The supersession attempt must still be the recorded outcome.
    """
    result = result_of(harness.rpc(
        "deploy_recon_waypoint",
        deploy_params(
            area=(50.0, 30.0, 0.002),
            supersedes_command_id="CMD-HUMAN-0002",
        ),
        token=AGENT_TOKEN,
    ))
    assert result["rejection"]["code"] == "precedence_violation"
    assert harness.ctx.audit_sink.by_outcome(Outcome.SECURITY_VIOLATION)


def test_violation_reaches_the_alert_sink(harness: Harness) -> None:
    """A violation recorded but never alerted is the failure mode the API prevents."""
    alerts: list[SecurityViolation] = []
    harness.ctx.audit._alert_sink = alerts.append

    harness.rpc(
        "deploy_recon_waypoint",
        deploy_params(supersedes_command_id="CMD-HUMAN-0003"),
        token=AGENT_TOKEN,
    )
    assert len(alerts) == 1
    assert alerts[0].kind is ViolationKind.TIER3_SUPERSESSION
    assert alerts[0].severity is ViolationSeverity.P1
    assert alerts[0].target == "CMD-HUMAN-0003"


def test_a_human_proposal_without_supersession_is_unaffected(harness: Harness) -> None:
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params()))
    assert result["accepted"] is True
    assert not harness.ctx.audit_sink.by_outcome(Outcome.SECURITY_VIOLATION)


def test_supersession_field_is_declared_not_smuggled(harness: Harness) -> None:
    """The field is part of the schema on purpose.

    An attempt that could not be *expressed* would be rejected as a generic schema
    error, and the signal would be lost. Making it expressible is what lets the gate
    classify it.
    """
    from mcp_server.schemas.tools import DeployReconWaypointRequest

    assert "supersedes_command_id" in DeployReconWaypointRequest.model_fields


# --------------------------------------------------------------------------- #
# The arbiter, across the whole matrix
# --------------------------------------------------------------------------- #

def _arbiter(harness: Harness, *, allow: bool) -> PrecedenceArbiter:
    engine = PolicyEngine(
        StaticPolicyTransport(
            result={"allow": allow, "deny": [] if allow else [
                {"code": "precedence_violation", "detail": "refused"}
            ], "policy_version": "override/1.0.0"}
        )
    )
    return PrecedenceArbiter(engine, harness.ctx.audit, clock=harness.clock)


def _principal(harness: Harness, token: str):  # type: ignore[no-untyped-def]
    return harness.ctx.resolver.resolve(token)


@pytest.mark.parametrize("action", sorted(OverrideAction.ALL))
def test_agent_override_is_refused_and_flagged_for_every_action(
    harness: Harness, action: str
) -> None:
    arbiter = _arbiter(harness, allow=False)
    decision = arbiter.arbitrate(
        principal=_principal(harness, AGENT_TOKEN),
        target=TargetCommand("CMD-1", Role.COMMAND_ROOM, "op-cr-001"),
        action=action,
        tool="override",
    )
    assert decision.allowed is False
    assert decision.security_violation is True


def test_field_leader_over_command_room_is_refused_but_not_flagged(
    harness: Harness,
) -> None:
    """An ordinary authorization failure. Flagging it would bury the Tier-3 signal."""
    arbiter = _arbiter(harness, allow=False)
    decision = arbiter.arbitrate(
        principal=_principal(harness, FL_TOKEN),
        target=TargetCommand("CMD-1", Role.COMMAND_ROOM, "op-cr-001"),
        action=OverrideAction.CANCEL,
        tool="override",
    )
    assert decision.allowed is False
    assert decision.security_violation is False
    assert not harness.ctx.audit_sink.by_outcome(Outcome.SECURITY_VIOLATION)


def test_command_room_over_agent_is_permitted(harness: Harness) -> None:
    arbiter = _arbiter(harness, allow=True)
    decision = arbiter.arbitrate(
        principal=_principal(harness, CR_TOKEN),
        target=TargetCommand("CMD-1", Role.AI_AGENT, "agent-session-7"),
        action=OverrideAction.OVERRIDE,
        tool="override",
    )
    assert decision.allowed is True
    assert decision.security_violation is False


def test_unknown_action_is_refused_without_consulting_the_policy(
    harness: Harness,
) -> None:
    transport = StaticPolicyTransport(result={"allow": True, "deny": []})
    arbiter = PrecedenceArbiter(
        PolicyEngine(transport), harness.ctx.audit, clock=harness.clock
    )
    decision = arbiter.arbitrate(
        principal=_principal(harness, CR_TOKEN),
        target=TargetCommand("CMD-1", Role.AI_AGENT, "agent-7"),
        action="escalate",
        tool="override",
    )
    assert decision.allowed is False
    assert "unknown_action" in decision.codes
    assert transport.calls == []


def test_policy_engine_outage_refuses_the_override(harness: Harness) -> None:
    """An outage is a denial, and is reported as an outage rather than an attack."""
    from policy_engine.client import PolicyTransportError

    arbiter = PrecedenceArbiter(
        PolicyEngine(StaticPolicyTransport(raise_error=PolicyTransportError("refused"))),
        harness.ctx.audit,
        clock=harness.clock,
    )
    decision = arbiter.arbitrate(
        principal=_principal(harness, CR_TOKEN),
        target=TargetCommand("CMD-1", Role.AI_AGENT, "agent-7"),
        action=OverrideAction.CANCEL,
        tool="override",
    )
    assert decision.allowed is False
    assert decision.security_violation is False, (
        "a policy-engine outage is not an attack indicator; routing it to the security "
        "rota is how real violations come to be ignored"
    )


def test_agent_attempt_is_flagged_even_when_the_engine_is_down(harness: Harness) -> None:
    """The server classifies the event itself, so the signal survives the outage.

    Deriving the flag from the matrix rather than from the policy response is what
    makes this possible.
    """
    from policy_engine.client import PolicyTransportError

    arbiter = PrecedenceArbiter(
        PolicyEngine(StaticPolicyTransport(raise_error=PolicyTransportError("refused"))),
        harness.ctx.audit,
        clock=harness.clock,
    )
    decision = arbiter.arbitrate(
        principal=_principal(harness, AGENT_TOKEN),
        target=TargetCommand("CMD-1", Role.COMMAND_ROOM, "op-cr-001"),
        action=OverrideAction.CANCEL,
        tool="override",
    )
    assert decision.allowed is False
    assert decision.security_violation is True
    assert harness.ctx.audit_sink.by_outcome(Outcome.SECURITY_VIOLATION)
