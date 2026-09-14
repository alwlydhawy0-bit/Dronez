"""Hard rate limiting at the MCP server boundary.

Two distinct limits, deliberately not collapsed into one
--------------------------------------------------------
============================  =====  ==========================================
Limit                         Rate   Counts
============================  =====  ==========================================
Agent tool **proposals**      2/s    every proposal, approved or rejected alike
Hardware **command dispatch** 2/s    commands actually sent to ROS2/MAVLink
============================  =====  ==========================================

Master Plan §5 defines the first: *"hard cap of 2 tool proposals per second per
agent session, enforced at the MCP server boundary independent of whether any
individual proposal is ultimately approved or rejected by the policy engine."*
Zero-Trust §4.1 defines the second, to prevent buffer overflows and drone control
instability.

Counting rejected proposals is the whole point of the first limit. A limiter that
only counted approvals would leave an adversarially-driven agent free to hammer the
policy engine indefinitely, because every one of its probes gets rejected. The
expensive work -- schema validation, sanitizer round-trip, policy evaluation -- happens
*before* the verdict, so it is attempts that must be bounded, not successes.

Implementation notes
--------------------
* **Monotonic clock.** Wall-clock time can jump backwards (NTP correction, operator
  action) and a backwards jump would hand out free capacity. ``time.monotonic``
  cannot go backwards.
* **Sliding window, not token bucket.** "Maximum 2 per second" is enforced literally:
  no instant may have more than 2 acquisitions in the preceding second. A token
  bucket with burst capacity would permit brief bursts above that.
* **Bounded memory.** The session table is capped and pruned, because an unbounded
  per-session structure turns the limiter itself into the resource-exhaustion vector
  it exists to prevent.
* **Thread-safe.** One lock around the whole check-and-record so two concurrent
  proposals cannot both observe the pre-acquisition count.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from dronez.safety.envelope import ENVELOPE

__all__ = [
    "MAX_TRACKED_SESSIONS",
    "AgentProposalLimiter",
    "HardwareCommandLimiter",
    "LimitKind",
    "RateLimitDecision",
    "SlidingWindowRateLimiter",
]

#: Cap on tracked sessions. Session creation is gated by authentication upstream, so
#: this bounds a defect or a credential-stuffing burst rather than normal operation.
MAX_TRACKED_SESSIONS: Final[int] = 4096


class LimitKind(StrEnum):
    """Which limit produced a decision. Kept distinct so alerting can tell them apart."""

    AGENT_PROPOSAL = "agent_proposal"
    HARDWARE_COMMAND = "hardware_command"


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Outcome of one acquisition attempt.

    ``allowed=False`` is a normal, expected control action, not an error. It is
    still recorded: a session that is persistently rate-limited is a security
    signal, the same way a pattern of rejected proposals is.
    """

    allowed: bool
    kind: LimitKind
    session_id: str
    #: Acquisitions observed in the trailing window, including this one if allowed.
    observed_in_window: int
    limit: float
    window_s: float
    #: Seconds until capacity is expected to free up. Zero when allowed.
    retry_after_s: float

    @property
    def rejection_detail(self) -> str:
        return (
            f"{self.kind.value} rate limit exceeded for session: "
            f"{self.observed_in_window} in the trailing {self.window_s:g}s window, "
            f"limit {self.limit:g}/s; retry after {self.retry_after_s:.3f}s"
        )


class SlidingWindowRateLimiter:
    """Per-session sliding-window limiter.

    Not reusable across limit kinds by accident: construct one instance per
    :class:`LimitKind`, or two limits would share a window and silently halve each
    other's capacity.
    """

    def __init__(
        self,
        kind: LimitKind,
        max_per_second: float,
        *,
        window_s: float = 1.0,
        max_sessions: int = MAX_TRACKED_SESSIONS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if max_per_second <= 0:
            raise ValueError("max_per_second must be positive")
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self._kind = kind
        self._max_per_second = max_per_second
        self._window_s = window_s
        self._capacity = int(max_per_second * window_s)
        if self._capacity < 1:
            raise ValueError(
                f"max_per_second={max_per_second} over a {window_s}s window admits no "
                "requests at all; this is a configuration error, not a valid limit"
            )
        self._max_sessions = max_sessions
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        # OrderedDict gives LRU eviction order for free.
        self._windows: OrderedDict[str, deque[float]] = OrderedDict()

    @property
    def kind(self) -> LimitKind:
        return self._kind

    @property
    def limit(self) -> float:
        return self._max_per_second

    def acquire(self, session_id: str) -> RateLimitDecision:
        """Attempt one acquisition. **Records the attempt whether or not it is allowed.**

        Call this *before* doing any expensive work for the request, and call it
        exactly once per attempt -- calling it again after a policy rejection would
        double-count.
        """
        if not session_id:
            # An unattributable request cannot be rate-limited, so it is not admitted.
            # Fail closed rather than share one anonymous bucket that any caller
            # could exhaust for everyone else.
            return RateLimitDecision(
                allowed=False,
                kind=self._kind,
                session_id="",
                observed_in_window=0,
                limit=self._max_per_second,
                window_s=self._window_s,
                retry_after_s=0.0,
            )

        now = self._clock()
        cutoff = now - self._window_s

        with self._lock:
            window = self._windows.get(session_id)
            if window is None:
                self._prune_locked(now)
                window = deque()
                self._windows[session_id] = window
            self._windows.move_to_end(session_id)

            while window and window[0] <= cutoff:
                window.popleft()

            if len(window) >= self._capacity:
                # Oldest entry in the window determines when capacity frees up.
                retry_after = max(0.0, window[0] + self._window_s - now)
                return RateLimitDecision(
                    allowed=False,
                    kind=self._kind,
                    session_id=session_id,
                    observed_in_window=len(window),
                    limit=self._max_per_second,
                    window_s=self._window_s,
                    retry_after_s=retry_after,
                )

            window.append(now)
            return RateLimitDecision(
                allowed=True,
                kind=self._kind,
                session_id=session_id,
                observed_in_window=len(window),
                limit=self._max_per_second,
                window_s=self._window_s,
                retry_after_s=0.0,
            )

    def _prune_locked(self, now: float) -> None:
        """Drop fully-expired sessions, then LRU-evict if still over capacity."""
        cutoff = now - self._window_s
        expired = [sid for sid, w in self._windows.items() if not w or w[-1] <= cutoff]
        for sid in expired:
            del self._windows[sid]

        while len(self._windows) >= self._max_sessions:
            # Evicting the least-recently-used session loses its window, which at
            # worst grants that one session a fresh allowance. That is strictly
            # preferable to refusing new sessions, which would let an attacker who
            # filled the table lock everyone else out.
            self._windows.popitem(last=False)

    def tracked_sessions(self) -> int:
        with self._lock:
            return len(self._windows)

    def reset(self, session_id: str | None = None) -> None:
        """Clear state. Test and session-teardown use only -- never a request path.

        There is deliberately no way for a request to reach this: a caller that could
        reset its own window would have no limit at all.
        """
        with self._lock:
            if session_id is None:
                self._windows.clear()
            else:
                self._windows.pop(session_id, None)


class AgentProposalLimiter(SlidingWindowRateLimiter):
    """The 2 proposals/second/session cap from Master Plan §5.

    Rate comes from the safety envelope so it cannot drift from project memory.
    """

    def __init__(
        self,
        *,
        max_sessions: int = MAX_TRACKED_SESSIONS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        super().__init__(
            LimitKind.AGENT_PROPOSAL,
            ENVELOPE.agent_proposals_per_second,
            max_sessions=max_sessions,
            clock=clock,
        )


class HardwareCommandLimiter(SlidingWindowRateLimiter):
    """The 2 commands/second/agent dispatch cap from Zero-Trust §4.1.

    Separate instance, separate window. Sharing one limiter with
    :class:`AgentProposalLimiter` would mean a burst of read-only proposals could
    starve an outbound safety-relevant command.
    """

    def __init__(
        self,
        *,
        max_sessions: int = MAX_TRACKED_SESSIONS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        super().__init__(
            LimitKind.HARDWARE_COMMAND,
            ENVELOPE.hardware_commands_per_second,
            max_sessions=max_sessions,
            clock=clock,
        )
