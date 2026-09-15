"""``check_airspace_clearance`` -- the mandatory pre-dispatch airspace gate.

Master Plan §5 defines the contract precisely: this tool *"takes a `mission_id` and
proposed `polygon`/altitude envelope and returns a binding clearance decision by
validating against the live, encrypted-sync feed from local sovereign NFZ databases
and current GACA regulatory rules. `deploy_recon_waypoint` MUST call this and receive
an affirmative clearance before dispatch proceeds; a stale, unreachable, or negative
clearance response fails the dispatch closed, per the Default-Deny mandate."*

Real-time, not cached
---------------------
The handler refreshes the feed before evaluating, so the decision reflects the feed at
the moment of the decision rather than at the last successful background poll. If the
refresh fails and the cache is outside its freshness window, the answer is a denial
with `feed_stale` -- never a fallback to the last known picture.

The denial reason distinguishes *why*: `feed_stale` and `feed_unavailable` are
operational failures that page someone, while `zone_conflict` is the system working
correctly. Collapsing them would hide an outage behind routine denials.
"""

from __future__ import annotations

from dronez.airspace.client import DenialReason
from mcp_server.audit import Outcome
from mcp_server.feed import LiveAirspaceFeed, SyncStatus
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.tools import (
    CheckAirspaceClearanceRequest,
    CheckAirspaceClearanceResponse,
    ToolName,
)
from mcp_server.tools.base import CallContext, ToolOutcome

__all__ = ["CheckAirspaceClearanceHandler"]


class CheckAirspaceClearanceHandler:
    """Evaluates a proposed volume against the live sovereign feed."""

    name: ToolName = ToolName.CHECK_AIRSPACE_CLEARANCE
    request_model: type[StrictModel] = CheckAirspaceClearanceRequest

    def __init__(self, feed: LiveAirspaceFeed) -> None:
        self._feed = feed

    def handle(
        self, request: CheckAirspaceClearanceRequest, ctx: CallContext
    ) -> ToolOutcome:
        decision, sync = self._feed.check_clearance(
            request.polygon.to_core(),
            request.altitude_min_m_agl,
            request.altitude_max_m_agl,
        )

        detail = decision.detail
        if sync.status is SyncStatus.FAILED and not decision.cleared:
            # Surface the transport failure alongside the denial. Without this an
            # operator sees "airspace denied" and starts looking for a restriction
            # that does not exist.
            detail = f"{decision.detail} (feed refresh failed: {sync.detail})"

        response = CheckAirspaceClearanceResponse(
            cleared=decision.cleared,
            reason=decision.reason.value,
            detail=detail[:512],
            evaluated_utc=decision.evaluated_utc,
            expires_utc=decision.expires_utc if decision.cleared else None,
            blocking_zone_ids=decision.blocking_zone_ids,
            advisory_zone_ids=decision.advisory_zone_ids,
            feed_authority=decision.feed_authority,
            feed_sequence=decision.feed_sequence,
            feed_age_s=decision.feed_age_s,
        )

        outcome = Outcome.ACCEPTED if decision.cleared else Outcome.REJECTED_CLEARANCE
        return ToolOutcome(
            response=response,
            audit_outcome=outcome,
            reason_codes=(decision.reason.value,),
            detail=detail[:512],
            decision={
                "cleared": decision.cleared,
                "reason": decision.reason.value,
                "blocking_zone_ids": list(decision.blocking_zone_ids),
                "feed_sequence": decision.feed_sequence,
                "feed_age_s": decision.feed_age_s,
                "sync_status": sync.status.value,
            },
        )


#: Denial reasons that indicate an operational failure rather than restricted
#: airspace. A rising rate of these is an outage, and should alert as one.
OPERATIONAL_DENIALS = frozenset({
    DenialReason.FEED_STALE,
    DenialReason.FEED_UNAVAILABLE,
    DenialReason.FEED_NEVER_SYNCED,
    DenialReason.INTERNAL_ERROR,
})
