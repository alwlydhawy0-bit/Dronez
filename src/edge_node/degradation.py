"""Graceful quality degradation under link stress.

Master Plan §5 states the rule and its priority order plainly: *"On link degradation,
the stream drops quality tier before dropping detection-event delivery -- actionable
detection alerts are prioritized over raw video bandwidth. Every detection event is
hashed and archived to the WORM store at capture time, independent of whether the live
viewer was connected."*

The invariant
-------------
**Detection events are never shed.** Every tier below, including the floor, carries
them. That is not an optimisation to be tuned: a recon platform whose value is telling a
security team what is inside a building before they enter it fails completely if the
detection reaches nobody, and succeeds adequately if the video is grainy. The bandwidth
that video would have used is what gets given up.

:data:`SHEDDABLE` is the explicit list of what may be dropped, and
``test_detection_events_are_never_sheddable`` asserts detection is absent from it.

Hysteresis
----------
A controller that stepped tier directly off an instantaneous measurement would oscillate
on a link that is marginal rather than bad -- and every tier change costs a
renegotiation and a visible glitch. So degradation is immediate (a bad link now is a bad
link) while recovery requires the link to hold good for :data:`RECOVERY_DWELL_S`. The
asymmetry is deliberate: dropping quality early is cheap, restoring it prematurely
costs another drop.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Final

__all__ = [
    "RECOVERY_DWELL_S",
    "SHEDDABLE",
    "DegradationController",
    "LinkQuality",
    "PayloadClass",
    "StreamTier",
    "TierDecision",
]

#: How long the link must hold at a better grade before the tier is raised.
RECOVERY_DWELL_S: Final[float] = 10.0


class StreamTier(IntEnum):
    """Delivery tiers, ordered worst to best.

    ``DETECTION_ONLY`` is the floor and it is **not** "nothing". It carries detection
    events and telemetry with no video at all -- the mode in which a jammed or
    near-jammed link still tells the command room that there are four people in the
    north stairwell.
    """

    DETECTION_ONLY = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def carries_video(self) -> bool:
        return self is not StreamTier.DETECTION_ONLY

    @property
    def label(self) -> str:
        return self.name.lower()


class PayloadClass(StrEnum):
    """What is flowing, in priority order. Lower index in :data:`_PRIORITY` wins."""

    #: Object detections. The reason the platform exists.
    DETECTION_EVENT = "detection_event"
    #: Position, battery, link health. Small, and needed to fly safely.
    TELEMETRY = "telemetry"
    #: Periodic full frames, so a late joiner or a recovering link can resync.
    KEYFRAME = "keyframe"
    #: Inter-frame video. The bulk of the bandwidth and the first thing to go.
    VIDEO_DELTA = "video_delta"


_PRIORITY: Final[tuple[PayloadClass, ...]] = (
    PayloadClass.DETECTION_EVENT,
    PayloadClass.TELEMETRY,
    PayloadClass.KEYFRAME,
    PayloadClass.VIDEO_DELTA,
)

#: The only classes that may ever be dropped to save bandwidth.
#:
#: Detection events and telemetry are deliberately absent. Telemetry because flying
#: safely depends on it; detection because delivering it is the mission.
SHEDDABLE: Final[frozenset[PayloadClass]] = frozenset(
    {PayloadClass.VIDEO_DELTA, PayloadClass.KEYFRAME}
)

#: What each tier admits, in priority order.
_TIER_ADMITS: Final[dict[StreamTier, frozenset[PayloadClass]]] = {
    StreamTier.DETECTION_ONLY: frozenset({PayloadClass.DETECTION_EVENT, PayloadClass.TELEMETRY}),
    StreamTier.LOW: frozenset(
        {PayloadClass.DETECTION_EVENT, PayloadClass.TELEMETRY, PayloadClass.KEYFRAME}
    ),
    StreamTier.MEDIUM: frozenset(_PRIORITY),
    StreamTier.HIGH: frozenset(_PRIORITY),
}

#: Approximate bitrate budget per tier, bits per second. Used to decide the tier a link
#: can sustain, not to shape traffic -- shaping is the encoder's job.
_TIER_BITRATE: Final[dict[StreamTier, int]] = {
    StreamTier.DETECTION_ONLY: 32_000,
    StreamTier.LOW: 250_000,
    StreamTier.MEDIUM: 1_200_000,
    StreamTier.HIGH: 4_000_000,
}


@dataclass(frozen=True, slots=True)
class LinkQuality:
    """A measurement of the RF link, as reported by the WebRTC transport.

    Loss and round-trip time are both needed: a link can have low loss and a round-trip
    that makes live video useless, and a link can be fast and lossy enough that video
    arrives as artefacts. Either alone would mis-grade half the failure modes.
    """

    #: Estimated available bandwidth, bits per second.
    available_bitrate_bps: int
    #: Fraction lost, 0.0-1.0.
    packet_loss: float
    round_trip_ms: float
    #: True when the transport reports jamming or a total loss of carrier.
    carrier_lost: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.packet_loss <= 1.0:
            raise ValueError("packet_loss is a fraction between 0 and 1")
        if self.available_bitrate_bps < 0 or self.round_trip_ms < 0:
            raise ValueError("bitrate and round-trip time must be non-negative")

    @property
    def is_usable(self) -> bool:
        """Whether anything can be delivered at all."""
        return not self.carrier_lost and self.available_bitrate_bps > 0

    def sustainable_tier(self) -> StreamTier:
        """The best tier this link could carry, ignoring hysteresis.

        Loss and latency cap the tier independently of raw bandwidth: a fat pipe that
        drops one packet in twenty cannot carry inter-frame video usefully, however many
        bits per second it advertises.
        """
        if not self.is_usable:
            return StreamTier.DETECTION_ONLY

        by_bandwidth = StreamTier.DETECTION_ONLY
        for tier in (StreamTier.HIGH, StreamTier.MEDIUM, StreamTier.LOW):
            if self.available_bitrate_bps >= _TIER_BITRATE[tier]:
                by_bandwidth = tier
                break

        cap = StreamTier.HIGH
        if self.packet_loss > 0.02 or self.round_trip_ms > 400:
            cap = StreamTier.MEDIUM
        if self.packet_loss > 0.08 or self.round_trip_ms > 800:
            cap = StreamTier.LOW
        if self.packet_loss > 0.20 or self.round_trip_ms > 2000:
            cap = StreamTier.DETECTION_ONLY

        return StreamTier(min(int(by_bandwidth), int(cap)))


@dataclass(frozen=True, slots=True)
class TierDecision:
    """The controller's verdict, and why."""

    tier: StreamTier
    previous_tier: StreamTier
    admits: frozenset[PayloadClass]
    reason: str
    changed: bool

    @property
    def degraded(self) -> bool:
        return self.tier < self.previous_tier

    @property
    def recovered(self) -> bool:
        return self.tier > self.previous_tier

    def admits_class(self, payload: PayloadClass) -> bool:
        return payload in self.admits

    def to_dict(self) -> dict[str, object]:
        return {
            "tier": self.tier.label,
            "previous_tier": self.previous_tier.label,
            "admits": sorted(p.value for p in self.admits),
            "reason": self.reason,
            "changed": self.changed,
        }


class DegradationController:
    """Decides what to send as the link changes.

    Thread-safe: link measurements arrive from the transport thread while the encoder
    thread asks what it may send.
    """

    def __init__(
        self,
        *,
        initial_tier: StreamTier = StreamTier.HIGH,
        ceiling: StreamTier = StreamTier.HIGH,
        recovery_dwell_s: float = RECOVERY_DWELL_S,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._ceiling = ceiling
        self._tier = StreamTier(min(int(initial_tier), int(ceiling)))
        self._dwell = timedelta(seconds=recovery_dwell_s)
        self._good_since: datetime | None = None
        self.degradations = 0
        self.recoveries = 0

    @property
    def tier(self) -> StreamTier:
        with self._lock:
            return self._tier

    def observe(self, link: LinkQuality) -> TierDecision:
        """Fold a link measurement into the current tier."""
        now = self._clock()
        sustainable = StreamTier(min(int(link.sustainable_tier()), int(self._ceiling)))

        with self._lock:
            previous = self._tier

            if sustainable < previous:
                # Degrade immediately. A link that cannot carry the current tier is
                # already dropping packets; waiting out a dwell period just means
                # dropping them for longer.
                self._tier = sustainable
                self._good_since = None
                self.degradations += 1
                reason = (
                    f"link supports at most {sustainable.label} "
                    f"({link.available_bitrate_bps} bps, {link.packet_loss:.1%} loss, "
                    f"{link.round_trip_ms:.0f} ms RTT)"
                )
                return self._decision(previous, reason, changed=True)

            if sustainable > previous:
                # Recover only after the link has held. Every tier change costs a
                # renegotiation and a visible glitch, so a flapping link should not
                # produce a flapping stream.
                if self._good_since is None:
                    self._good_since = now
                    return self._decision(
                        previous,
                        f"link improved to {sustainable.label}; holding {previous.label} "
                        f"for {self._dwell.total_seconds():.0f}s before raising",
                        changed=False,
                    )
                if now - self._good_since >= self._dwell:
                    self._tier = sustainable
                    self._good_since = None
                    self.recoveries += 1
                    return self._decision(
                        previous,
                        f"link held at {sustainable.label} for the dwell period",
                        changed=True,
                    )
                remaining = (self._dwell - (now - self._good_since)).total_seconds()
                return self._decision(
                    previous,
                    f"link improving; {remaining:.0f}s of dwell remaining",
                    changed=False,
                )

            self._good_since = None
            return self._decision(previous, "link steady", changed=False)

    def _decision(self, previous: StreamTier, reason: str, *, changed: bool) -> TierDecision:
        return TierDecision(
            tier=self._tier,
            previous_tier=previous,
            admits=_TIER_ADMITS[self._tier],
            reason=reason,
            changed=changed,
        )

    def admits(self, payload: PayloadClass) -> bool:
        """Whether ``payload`` may be sent at the current tier.

        Detection events and telemetry return ``True`` at every tier, including the
        floor. That is the invariant this whole module exists to hold.
        """
        with self._lock:
            return payload in _TIER_ADMITS[self._tier]

    def force_tier(self, tier: StreamTier, *, reason: str) -> TierDecision:
        """Pin the tier -- an operator asking for a specific quality.

        Still bounded by the ceiling: an operator may ask for less than the link can
        carry, never for more than the session was authorized for.
        """
        with self._lock:
            previous = self._tier
            self._tier = StreamTier(min(int(tier), int(self._ceiling)))
            self._good_since = None
            return self._decision(previous, reason, changed=self._tier != previous)
