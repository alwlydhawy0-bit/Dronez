"""Live sovereign NFZ / GACA feed manager.

Master Plan §2 requires `AirspaceZone` data to be *"synchronized in real time with
local sovereign No-Fly Zone (NFZ) databases over an encrypted sync channel"*, and §5
requires every dispatch to be gated on a clearance derived from that live feed --
*"not a cached or assumed-current snapshot."*

Two refresh paths, and both are needed
--------------------------------------
* **Background loop.** Keeps the cache warm on a bounded interval so the common case
  costs nothing at dispatch time.
* **On-demand refresh before a clearance check.** The background loop can be behind:
  it may have just failed, or the process may have restarted. Checking freshness at
  the moment of decision and refreshing if stale is what makes the data *current at
  dispatch* rather than *current as of the last successful poll*.

Staleness is a denial, not a warning
------------------------------------
If the feed cannot be refreshed and the cache is outside its freshness window, the
clearance check denies. That is a deliberate availability-for-safety trade: during an
incident, the restriction most likely to matter is the one published five minutes ago
that we cannot see. :class:`dronez.airspace.client.AirspaceClearanceService` already
fails closed on `FEED_STALE` and `FEED_NEVER_SYNCED`; this module's job is to give it
the freshest data it can and to never paper over a failure to do so.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from dronez.airspace.client import (
    AirspaceCache,
    AirspaceClearanceService,
    ClearanceDecision,
    NfzChannelError,
    NfzSyncChannel,
)
from dronez.airspace.schema import Polygon
from dronez.safety.envelope import ENVELOPE, SafetyEnvelope

__all__ = ["LiveAirspaceFeed", "SyncReport", "SyncStatus"]


class SyncStatus(StrEnum):
    """Result of a refresh attempt."""

    #: Cache was already inside the freshness window; no network call made.
    FRESH = "fresh"
    #: A new bulletin was accepted.
    REFRESHED = "refreshed"
    #: Refresh attempted and failed. The cache is whatever it was -- possibly stale.
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SyncReport:
    status: SyncStatus
    detail: str = ""
    sequence: int | None = None
    age_s: float | None = None

    @property
    def usable(self) -> bool:
        """Whether the cache is inside its freshness window after this attempt.

        A ``FAILED`` refresh is not automatically unusable: the cache may still be
        fresh enough from a previous sync. The clearance check re-derives freshness
        itself rather than trusting this flag.
        """
        return self.status in (SyncStatus.FRESH, SyncStatus.REFRESHED)


class LiveAirspaceFeed:
    """Owns the airspace cache, its refresh policy, and clearance evaluation."""

    def __init__(
        self,
        cache: AirspaceCache,
        clearance: AirspaceClearanceService,
        channel: NfzSyncChannel,
        *,
        envelope: SafetyEnvelope = ENVELOPE,
        clock: Callable[[], datetime] | None = None,
        refresh_interval_s: float | None = None,
    ) -> None:
        self._cache = cache
        self._clearance = clearance
        self._channel = channel
        self._envelope = envelope
        self._clock = clock or (lambda: datetime.now(UTC))
        # Refresh at half the staleness window so a single failed poll does not
        # immediately put the cache outside it -- there is room for one retry before
        # dispatches start failing closed.
        self._interval = refresh_interval_s or (envelope.nfz_max_staleness_s / 2.0)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.sync_attempts = 0
        self.sync_failures = 0

    # -- refresh ---------------------------------------------------------

    def refresh(self, *, force: bool = False) -> SyncReport:
        """Sync if stale (or if ``force``). Never raises."""
        now = self._clock()
        if not force and self._cache.is_fresh(now):
            state = self._cache.state
            return SyncReport(
                SyncStatus.FRESH, "cache is inside the freshness window",
                state.last_sequence, state.age_s(now),
            )

        with self._lock:
            # Re-check under the lock: a concurrent caller may have just refreshed,
            # and a second network round trip would be wasted work at dispatch time.
            now = self._clock()
            if not force and self._cache.is_fresh(now):
                state = self._cache.state
                return SyncReport(
                    SyncStatus.FRESH, "refreshed by a concurrent caller",
                    state.last_sequence, state.age_s(now),
                )

            self.sync_attempts += 1
            try:
                bulletin = self._cache.sync(self._channel)
            except NfzChannelError as exc:
                self.sync_failures += 1
                state = self._cache.state
                return SyncReport(
                    SyncStatus.FAILED, f"NFZ sync failed: {exc}",
                    state.last_sequence, state.age_s(self._clock()),
                )
            except Exception as exc:
                self.sync_failures += 1
                state = self._cache.state
                return SyncReport(
                    SyncStatus.FAILED, f"NFZ sync raised {type(exc).__name__}",
                    state.last_sequence, state.age_s(self._clock()),
                )

            state = self._cache.state
            return SyncReport(
                SyncStatus.REFRESHED,
                f"accepted bulletin {bulletin.bulletin_id}",
                bulletin.sequence,
                state.age_s(self._clock()),
            )

    # -- clearance -------------------------------------------------------

    def check_clearance(
        self,
        polygon: Polygon,
        altitude_min_m_agl: float,
        altitude_max_m_agl: float,
    ) -> tuple[ClearanceDecision, SyncReport]:
        """Refresh if needed, then evaluate. Returns the decision and the sync report.

        The sync report is returned alongside so the caller can record *why* a denial
        happened -- "the feed was down" and "the airspace is restricted" are both
        denials and need to be distinguishable in the audit trail and on the console.
        """
        report = self.refresh()
        decision = self._clearance.check_clearance(
            polygon, altitude_min_m_agl, altitude_max_m_agl
        )
        return decision, report

    # -- background loop -------------------------------------------------

    def start_background_refresh(self) -> None:
        """Start the periodic refresh thread. Idempotent."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="nfz-refresh", daemon=True
        )
        self._thread.start()

    def stop_background_refresh(self, timeout_s: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout_s)
        self._thread = None

    def _loop(self) -> None:
        # Refresh once immediately so a just-started process is not serving denials
        # for a full interval while it waits for its first tick.
        while not self._stop.is_set():
            self.refresh()
            self._stop.wait(self._interval)

    # -- observability ---------------------------------------------------

    @property
    def status(self) -> dict[str, object]:
        now = self._clock()
        state = self._cache.state
        return {
            "authority": state.authority,
            "last_sequence": state.last_sequence,
            "last_sync_utc": state.last_sync_utc.isoformat() if state.last_sync_utc else None,
            "age_s": state.age_s(now),
            "zone_count": state.zone_count,
            "fresh": self._cache.is_fresh(now),
            "max_staleness_s": self._envelope.nfz_max_staleness_s,
            "consecutive_failures": state.consecutive_failures,
            "sync_attempts": self.sync_attempts,
            "sync_failures": self.sync_failures,
        }
