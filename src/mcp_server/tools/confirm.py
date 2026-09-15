"""``confirm_flight_plan`` -- the server-enforced human authorization gate.

Master Plan §5 explains why this is a tool rather than a UI step: *"without a
dedicated tool for it, 'confirmation' risks being implemented as an implicit UI-only
step with no server-side enforcement."*

Six checks, and each closes a distinct hole
-------------------------------------------
============================================  ==========================================
Check                                          What it stops
============================================  ==========================================
Principal is a human tier                      An agent confirming its own proposal
Principal matches the envelope issuer          Submitting someone else's authorization
Signature verifies over the plan + decision    Replaying an approval onto another plan
Nonce unconsumed                               Replaying the same approval twice
Staged plan matches the digest                 A plan altered after it was reviewed
Plan consumed atomically, once                 One approval dispatching twice
============================================  ==========================================

Dropping any one of them leaves a usable path. The digest check is the subtle one: an
operator confirms a `flight_plan_id`, but what they *reviewed* was a map overlay of a
specific geometry. Binding the confirmation to a digest of that geometry is what makes
the two the same thing.

After all six pass
------------------
The plan reaches :mod:`mcp_server.dispatch`, which **refuses**: the Milestone-0 gate is
open. The authorization is real and recorded; the actuation is not implemented. That
boundary is the point of this milestone.
"""

from __future__ import annotations

from mcp_server.audit import Outcome
from mcp_server.dispatch import HardwareDispatcher
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.identity import Role
from mcp_server.schemas.tools import (
    ConfirmDecision,
    ConfirmFlightPlanRequest,
    ConfirmFlightPlanResponse,
    RejectionCode,
    ToolName,
    ToolRejection,
)
from mcp_server.signing import SignatureVerifier
from mcp_server.store import ConsumeFailure, FlightPlanStore
from mcp_server.tools.base import CallContext, ToolOutcome

__all__ = ["ConfirmFlightPlanHandler"]

_CONSUME_FAILURE_CODES = {
    ConsumeFailure.NOT_FOUND: RejectionCode.PLAN_DIGEST_MISMATCH,
    ConsumeFailure.DIGEST_MISMATCH: RejectionCode.PLAN_DIGEST_MISMATCH,
    ConsumeFailure.EXPIRED: RejectionCode.CLEARANCE_STALE,
    ConsumeFailure.ALREADY_CONSUMED: RejectionCode.PLAN_DIGEST_MISMATCH,
    ConsumeFailure.WRONG_ZONE: RejectionCode.NOT_AUTHORIZED_FOR_ZONE,
}


class ConfirmFlightPlanHandler:
    """Verifies a human authorization and hands the plan to the dispatch seam."""

    name: ToolName = ToolName.CONFIRM_FLIGHT_PLAN
    request_model: type[StrictModel] = ConfirmFlightPlanRequest

    def __init__(
        self,
        *,
        store: FlightPlanStore,
        verifier: SignatureVerifier,
        dispatcher: HardwareDispatcher,
    ) -> None:
        self._store = store
        self._verifier = verifier
        self._dispatcher = dispatcher

    def handle(
        self, request: ConfirmFlightPlanRequest, ctx: CallContext
    ) -> ToolOutcome:
        issuer = request.authorization.issuer

        # 1 -- human tier only. The schema already forbids an agent-issued envelope;
        # this also rejects an agent *session* submitting a human's envelope, which
        # the schema cannot see.
        if ctx.principal.identity.role is Role.AI_AGENT:
            return self._reject(
                request,
                RejectionCode.PRECEDENCE_VIOLATION,
                "an AI agent session may not confirm a flight plan; Tier 3 proposes "
                "and a human tier disposes",
                Outcome.REJECTED_SCOPE,
            )

        # 2 -- the authenticated session must be the operator who signed.
        if ctx.principal.operator_id != issuer.operator_id:
            return self._reject(
                request,
                RejectionCode.SIGNATURE_INVALID,
                "the authenticated session does not match the authorization's issuer",
                Outcome.REJECTED_SIGNATURE,
            )

        # 3 + 4 -- signature over this exact plan and decision, and nonce freshness.
        verdict = self._verifier.verify_confirmation(
            request.authorization,
            flight_plan_id=request.flight_plan_id,
            flight_plan_digest=request.flight_plan_digest,
            decision=request.decision.value,
        )
        if not verdict.valid:
            failure = verdict.failure.value if verdict.failure else "signature_invalid"
            code = (
                RejectionCode.NONCE_REPLAYED
                if verdict.failure and verdict.failure.value.endswith("nonce_replayed")
                else RejectionCode.SIGNATURE_INVALID
            )
            return self._reject(
                request, code, verdict.detail, Outcome.REJECTED_SIGNATURE,
                reason_codes=(failure,),
            )

        # 5 + 6 -- digest match and atomic single-use consumption.
        result = self._store.consume(request.flight_plan_id, request.flight_plan_digest)
        if not result.ok or result.plan is None:
            failure = result.failure or ConsumeFailure.NOT_FOUND
            return self._reject(
                request,
                _CONSUME_FAILURE_CODES.get(failure, RejectionCode.PLAN_DIGEST_MISMATCH),
                result.detail,
                Outcome.REJECTED_POLICY,
                reason_codes=(failure.value,),
            )
        plan = result.plan

        # A rejection is a legitimate, recorded outcome -- not an error. The plan is
        # already consumed, so a rejected plan cannot later be approved: re-propose.
        if request.decision is ConfirmDecision.REJECT:
            return ToolOutcome(
                response=ConfirmFlightPlanResponse(
                    flight_plan_id=request.flight_plan_id,
                    decision=ConfirmDecision.REJECT,
                    dispatched=False,
                    confirmed_by_operator_id=ctx.principal.operator_id,
                    confirmed_utc=ctx.now,
                ),
                audit_outcome=Outcome.ACCEPTED,
                detail="operator rejected the staged plan",
                decision={"plan": plan.audit_projection(), "decision": "reject"},
            )

        # Authorized. Everything above passed. Now the dispatch seam decides whether
        # anything reaches an airframe -- and at Milestone 1 it refuses.
        dispatch = self._dispatcher.dispatch(plan)
        if not dispatch.dispatched:
            return ToolOutcome(
                response=ConfirmFlightPlanResponse(
                    flight_plan_id=request.flight_plan_id,
                    decision=ConfirmDecision.APPROVE,
                    dispatched=False,
                    confirmed_by_operator_id=ctx.principal.operator_id,
                    confirmed_utc=ctx.now,
                    rejection=ToolRejection(
                        code=RejectionCode.DISPATCH_GATE_CLOSED,
                        detail=dispatch.detail[:512],
                    ),
                ),
                audit_outcome=Outcome.REJECTED_DISPATCH_GATE,
                reason_codes=(dispatch.outcome.value,),
                detail=dispatch.detail[:512],
                decision={
                    "plan": plan.audit_projection(),
                    "decision": "approve",
                    "dispatch_outcome": dispatch.outcome.value,
                    "authorization_complete": True,
                },
            )

        return ToolOutcome(
            response=ConfirmFlightPlanResponse(
                flight_plan_id=request.flight_plan_id,
                decision=ConfirmDecision.APPROVE,
                dispatched=True,
                confirmed_by_operator_id=ctx.principal.operator_id,
                confirmed_utc=dispatch.dispatched_utc or ctx.now,
            ),
            audit_outcome=Outcome.DISPATCHED,
            detail=dispatch.detail[:512],
            decision={
                "plan": plan.audit_projection(),
                "decision": "approve",
                "dispatch_outcome": dispatch.outcome.value,
            },
        )

    @staticmethod
    def _reject(
        request: ConfirmFlightPlanRequest,
        code: RejectionCode,
        detail: str,
        outcome: Outcome,
        *,
        reason_codes: tuple[str, ...] = (),
    ) -> ToolOutcome:
        return ToolOutcome(
            response=ConfirmFlightPlanResponse(
                flight_plan_id=request.flight_plan_id,
                decision=request.decision,
                dispatched=False,
                rejection=ToolRejection(code=code, detail=detail[:512]),
            ),
            audit_outcome=outcome,
            reason_codes=reason_codes or (code.value,),
            detail=detail[:512],
        )
