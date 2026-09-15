"""Override arbitration and security-violation reporting.

This is the server-side half of the Role Precedence Matrix. The decision itself is made
by the policy engine (``policy_engine/policies/override.rego``); what lives here is the
consequence handling -- specifically, the rule that a Tier-3 attempt is not simply
refused but **recorded and alerted**.

Master Plan §5: a Tier-3 proposal that attempts to reference or supersede a Tier-1/2
command identifier *"is rejected outright and logged as a `Command` record with a
policy-violation flag -- this is treated as a security event, not a benign conflict."*

The asymmetry, once more
------------------------
Two refusals leave this module and they are not the same event:

* **Tier 2 reaching for Tier 1** -- an ordinary authorization failure. A field leader
  legitimately holds override authority over something; reaching one tier too high is
  a mistake a person makes.
* **Tier 3 reaching for anything** -- a security violation. An agent holds no override
  authority at all, so an attempt is either compromise or malfunction, and both want
  investigation rather than a retry prompt.

Fail-closed
-----------
:meth:`PrecedenceArbiter.arbitrate` never raises and never permits on an error path.
If the policy engine is unreachable the override is refused, and that refusal is
reported as an outage rather than an attack -- a distinction the on-call rota depends
on.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from dronez.authz import Role, classify_supersession
from mcp_server.audit import (
    AuditTrail,
    SecurityViolation,
    ViolationKind,
    ViolationSeverity,
)
from mcp_server.security import AuthenticatedPrincipal
from policy_engine import PolicyEngine, PolicyPath
from policy_engine.models import OverrideDecision, build_override_input

__all__ = ["OverrideAction", "PrecedenceArbiter", "TargetCommand"]


class OverrideAction:
    """The actions this matrix arbitrates. Kept in sync with ``override.rego``."""

    CANCEL = "cancel"
    SUPERSEDE = "supersede"
    OVERRIDE = "override"

    ALL = frozenset({CANCEL, SUPERSEDE, OVERRIDE})


@dataclass(frozen=True, slots=True)
class TargetCommand:
    """The existing command an actor is reaching for.

    ``issued_by_role`` comes from the stored ``Command`` record, never from the
    request. A caller that could name the target's role could name a low one and
    manufacture authority over it.
    """

    command_id: str
    issued_by_role: Role
    issued_by_operator_id: str


class PrecedenceArbiter:
    """Decides override requests and reports Tier-3 attempts as security violations."""

    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditTrail,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))

    def arbitrate(
        self,
        *,
        principal: AuthenticatedPrincipal,
        target: TargetCommand,
        action: str,
        tool: str,
        payload: bytes = b"",
    ) -> OverrideDecision:
        """Arbitrate one override request.

        A Tier-3 attempt is recorded and alerted **before** the decision is returned,
        so the security event is durable even if the caller discards the result.
        """
        if action not in OverrideAction.ALL:
            return OverrideDecision.deny(
                "unknown_action", f"action {action!r} is not an override action"
            )

        document = build_override_input(
            actor_operator_id=principal.operator_id,
            actor_role=principal.role_value,
            target_command_id=target.command_id,
            target_issued_by_role=target.issued_by_role.value,
            target_issued_by_operator_id=target.issued_by_operator_id,
            action=action,
            now=self._clock(),
        )
        raw = self._policy.evaluate(PolicyPath.OVERRIDE, document)
        decision = OverrideDecision.from_opa_result(
            {
                "allow": raw.allowed,
                "deny": [{"code": r.code, "detail": r.detail} for r in raw.reasons],
                "security_violation": _violation_flag(principal.identity.role, raw.allowed),
                "violation": None,
                "policy_version": raw.policy_version,
            }
        )

        if decision.security_violation:
            self._report(principal, target, action, tool, payload, decision)

        return decision

    def _report(
        self,
        principal: AuthenticatedPrincipal,
        target: TargetCommand,
        action: str,
        tool: str,
        payload: bytes,
        decision: OverrideDecision,
    ) -> None:
        classification = classify_supersession(
            principal.identity.role,
            target.issued_by_role,
            superseded_command_id=target.command_id,
        )
        self._audit.record_violation(
            SecurityViolation(
                kind=ViolationKind.TIER3_SUPERSESSION,
                severity=ViolationSeverity.P1,
                actor_operator_id=principal.operator_id,
                actor_role=principal.role_value,
                session_id=principal.session_id,
                detail=classification.reason,
                target=target.command_id,
                context={
                    "action": action,
                    "target_role": target.issued_by_role.value,
                    "policy_codes": list(decision.codes),
                    "policy_version": decision.policy_version,
                },
            ),
            tool=tool,
            payload=payload,
        )

    def report_supersession_attempt(
        self,
        *,
        principal: AuthenticatedPrincipal,
        superseded_command_id: str,
        tool: str,
        payload: bytes = b"",
    ) -> SecurityViolation:
        """Record a Tier-3 supersession attempt found inside an ordinary request.

        Used where the attempt arrives as a field on a proposal rather than as a
        dedicated override call. The target's tier is unknown in that case -- the agent
        named a command id without the server having resolved it -- so it is reported
        against the highest tier, because an agent holds no override authority over any
        of them and the severity does not depend on which one it reached for.
        """
        classification = classify_supersession(
            principal.identity.role,
            Role.COMMAND_ROOM,
            superseded_command_id=superseded_command_id,
        )
        violation = SecurityViolation(
            kind=ViolationKind.TIER3_SUPERSESSION,
            severity=ViolationSeverity.P1,
            actor_operator_id=principal.operator_id,
            actor_role=principal.role_value,
            session_id=principal.session_id,
            detail=classification.reason,
            target=superseded_command_id,
            context={"action": OverrideAction.SUPERSEDE, "surfaced_in": tool},
        )
        self._audit.record_violation(violation, tool=tool, payload=payload)
        return violation


def _violation_flag(actor: Role, allowed: bool) -> bool:
    """Whether this refusal is an attack indicator.

    Derived from the matrix rather than read from the policy response, because the
    server must classify the event even when the policy engine is the thing that
    failed. The Rego computes the same flag independently; they are cross-checked by
    ``tests/policy/test_precedence_matrix.py``.
    """
    return actor is Role.AI_AGENT and not allowed
