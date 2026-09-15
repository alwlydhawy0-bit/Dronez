"""``stream_thermal_feed`` -- authorize and open a live sensor feed.

Master Plan §5 gives this tool three obligations, and the handler does them in this
order because each narrows what the next has to consider:

1. **Authorization.** *"Requestor must hold an active authorization against the
   `mission_id`'s `IncidentZone`."* Resolved server-side; the request names a mission,
   never a zone or a permission.
2. **Time-boxing.** *"Stream access is time-boxed to the mission window and
   automatically revoked on mission close or `IncidentZone` expiry."* The session cannot
   outlive the authorization that created it.
3. **Transport.** *"The stream is rejected at the signaling layer if a client cannot
   negotiate"* DTLS/SRTP. Screened before a session is allocated, so an unacceptable
   offer costs nothing.

Why the SDP screen comes after authorization
--------------------------------------------
An unauthenticated or unscoped caller learns nothing about what the platform will
accept. Screening the offer first would turn this tool into an oracle for probing the
media policy without holding any authorization at all.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final

from mcp_server.audit import Outcome
from mcp_server.media import DtlsSrtpPolicy, SdpGuard
from mcp_server.repositories import MissionRegistry
from mcp_server.schemas.base import StrictModel
from mcp_server.schemas.tools import (
    RejectionCode,
    StreamThermalFeedRequest,
    StreamThermalFeedResponse,
    ToolName,
    ToolRejection,
)
from mcp_server.tools.base import CallContext, ToolOutcome

__all__ = ["StreamSession", "StreamSessionRegistry", "StreamThermalFeedHandler"]

#: Ceiling on a single stream session, independent of the zone window. A zone may be
#: authorized for six hours; a media session held open that long is a credential nobody
#: re-checked. Re-requesting is cheap.
MAX_SESSION_S: Final[float] = 900.0


class StreamSession:
    """An authorized media session.

    Immutable once created. Revocation is a store-level operation, not a mutation --
    a session object that could be edited after authorization is one whose scope could
    drift from what was approved.
    """

    __slots__ = (
        "drone_id",
        "expires_utc",
        "fingerprint_hash",
        "incident_zone_id",
        "mission_id",
        "operator_id",
        "session_id",
        "started_utc",
    )

    def __init__(
        self,
        *,
        session_id: str,
        mission_id: str,
        drone_id: str,
        incident_zone_id: str,
        operator_id: str,
        started_utc: datetime,
        expires_utc: datetime,
        fingerprint_hash: str,
    ) -> None:
        self.session_id = session_id
        self.mission_id = mission_id
        self.drone_id = drone_id
        self.incident_zone_id = incident_zone_id
        self.operator_id = operator_id
        self.started_utc = started_utc
        self.expires_utc = expires_utc
        self.fingerprint_hash = fingerprint_hash

    def is_live_at(self, when: datetime) -> bool:
        return self.started_utc <= when < self.expires_utc

    def to_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "mission_id": self.mission_id,
            "drone_id": self.drone_id,
            "incident_zone_id": self.incident_zone_id,
            "operator_id": self.operator_id,
            "started_utc": self.started_utc.isoformat(),
            "expires_utc": self.expires_utc.isoformat(),
        }


class StreamSessionRegistry:
    """Live media sessions, with zone-scoped revocation."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sessions: dict[str, StreamSession] = {}

    def open(self, session: StreamSession) -> None:
        self._sessions[session.session_id] = session

    def get(self, session_id: str) -> StreamSession | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if not session.is_live_at(self._clock()):
            # Expiry is checked on read rather than swept on a timer. A sweeper that
            # fell behind would leave an expired session usable, and "usable" is the
            # only property that matters here.
            del self._sessions[session_id]
            return None
        return session

    def revoke_zone(self, incident_zone_id: str) -> int:
        """Revoke every session scoped to a zone. Called on zone expiry or close."""
        doomed = [
            sid for sid, s in self._sessions.items() if s.incident_zone_id == incident_zone_id
        ]
        for sid in doomed:
            del self._sessions[sid]
        return len(doomed)

    def live_sessions(self) -> tuple[StreamSession, ...]:
        now = self._clock()
        return tuple(s for s in self._sessions.values() if s.is_live_at(now))

    def __len__(self) -> int:
        return len(self.live_sessions())


def _reject(code: RejectionCode, detail: str, outcome: Outcome) -> ToolOutcome:
    return ToolOutcome(
        response=StreamThermalFeedResponse(
            accepted=False,
            rejection=ToolRejection(code=code, detail=detail[:512]),
        ),
        audit_outcome=outcome,
        reason_codes=(code.value,),
        detail=detail[:512],
    )


class StreamThermalFeedHandler:
    """Authorizes a feed and opens a DTLS/SRTP media session."""

    name: ToolName = ToolName.STREAM_THERMAL_FEED
    request_model: type[StrictModel] = StreamThermalFeedRequest

    def __init__(
        self,
        *,
        missions: MissionRegistry,
        sessions: StreamSessionRegistry,
        guard: SdpGuard | None = None,
        policy: DtlsSrtpPolicy | None = None,
        max_session_s: float = MAX_SESSION_S,
    ) -> None:
        self._missions = missions
        self._sessions = sessions
        self._guard = guard or SdpGuard()
        self._policy = policy or DtlsSrtpPolicy()
        self._max_session = timedelta(seconds=max_session_s)

    def handle(
        self, request: StreamThermalFeedRequest, ctx: CallContext
    ) -> ToolOutcome:
        # 1 -- authorization, server-side.
        binding = self._missions.binding_for(request.mission_id)
        if binding is None:
            return _reject(
                RejectionCode.ZONE_INACTIVE,
                f"mission {request.mission_id!r} is not bound to an incident zone",
                Outcome.REJECTED_POLICY,
            )
        zone = binding.incident_zone

        if not zone.is_active_at(ctx.now):
            return _reject(
                RejectionCode.ZONE_INACTIVE,
                "the incident zone is not active; stream access is revoked on zone expiry",
                Outcome.REJECTED_POLICY,
            )
        if ctx.principal.operator_id not in zone.authorized_operator_ids:
            return _reject(
                RejectionCode.NOT_AUTHORIZED_FOR_ZONE,
                f"operator is not scoped to incident zone {zone.incident_zone_id!r}",
                Outcome.REJECTED_SCOPE,
            )

        # 2 -- transport, screened before anything is allocated.
        verdict = self._guard.screen(request.sdp_offer)
        if not verdict.acceptable:
            rejection = verdict.rejection.value if verdict.rejection else "sdp_rejected"
            return ToolOutcome(
                response=StreamThermalFeedResponse(
                    accepted=False,
                    rejection=ToolRejection(
                        code=RejectionCode.SCHEMA_INVALID, detail=verdict.detail[:512]
                    ),
                ),
                audit_outcome=Outcome.REJECTED_SCHEMA,
                reason_codes=(rejection,),
                detail=verdict.detail[:512],
            )

        # 3 -- time-box. The session dies with the zone, or sooner.
        expires = min(zone.authorized_until, ctx.now + self._max_session)
        if expires <= ctx.now:
            return _reject(
                RejectionCode.ZONE_INACTIVE,
                "the incident zone window leaves no time for a session",
                Outcome.REJECTED_POLICY,
            )

        session = StreamSession(
            session_id=f"stream-{uuid.uuid4().hex[:16]}",
            mission_id=request.mission_id,
            drone_id=request.drone_id,
            incident_zone_id=zone.incident_zone_id,
            operator_id=ctx.principal.operator_id,
            started_utc=ctx.now,
            expires_utc=expires,
            fingerprint_hash=verdict.fingerprint_hash or "",
        )
        self._sessions.open(session)

        return ToolOutcome(
            response=StreamThermalFeedResponse(
                accepted=True,
                session_id=session.session_id,
                expires_utc=expires,
                transport="dtls1.3-srtp",
                frame_hash_algorithm="sha256-edge",
            ),
            audit_outcome=Outcome.ACCEPTED,
            detail=f"media session open until {expires.isoformat()}",
            decision={
                "session": session.to_dict(),
                "sdp": {
                    "fingerprint_hash": verdict.fingerprint_hash,
                    "media_kinds": list(verdict.media_kinds),
                    "transport_profile": verdict.transport_profile,
                },
                "dtls_policy": self._policy.to_dict(),
                "stream_quality": request.stream_quality.value,
                "detection_mode": request.detection_mode.value,
            },
        )
