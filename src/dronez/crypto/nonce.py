"""Single-use nonce store.

Zero-Trust §5.1 requires a receiver to *"persist consumed nonces to reject exact
replays even within the window."* A validity window alone is not replay protection:
inside it, the same signed bytes replay as many times as an attacker likes.

Retention is tied to the maximum signature lifetime plus a clock-skew allowance rather
than chosen independently. Shorter would reopen the window; unbounded would make this
its own exhaustion vector.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final

__all__ = ["CLOCK_SKEW_ALLOWANCE_S", "MAX_SIGNATURE_LIFETIME_S", "NonceStore"]

#: Zero-Trust §1.1 caps short-lived S2S credentials at 300 seconds.
MAX_SIGNATURE_LIFETIME_S: Final[float] = 300.0
#: NTP-disciplined clocks on both ends, with room for drift.
CLOCK_SKEW_ALLOWANCE_S: Final[float] = 120.0


class NonceStore:
    """Thread-safe, TTL-bounded record of consumed nonces."""

    DEFAULT_TTL_S: Final[float] = MAX_SIGNATURE_LIFETIME_S + CLOCK_SKEW_ALLOWANCE_S

    def __init__(
        self,
        *,
        ttl_s: float = DEFAULT_TTL_S,
        max_entries: int = 1 << 16,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._ttl = timedelta(seconds=ttl_s)
        self._max_entries = max_entries
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._seen: dict[str, datetime] = {}

    def consume(self, nonce: str) -> bool:
        """Record ``nonce`` as used. ``False`` if it was already consumed.

        Check and record happen under one lock, so two concurrent replays cannot both
        observe the nonce as unused.
        """
        if not nonce:
            return False
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            if nonce in self._seen:
                return False
            if len(self._seen) >= self._max_entries:
                # Refuse rather than evict. Evicting the oldest entry would make that
                # nonce replayable again, which is exactly what this store prevents --
                # so pressure here degrades availability, never replay protection.
                return False
            self._seen[nonce] = now
            return True

    def seen(self, nonce: str) -> bool:
        """Read-only check. Does not consume."""
        with self._lock:
            return nonce in self._seen

    def _prune_locked(self, now: datetime) -> None:
        cutoff = now - self._ttl
        for nonce in [n for n, at in self._seen.items() if at <= cutoff]:
            del self._seen[nonce]

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)
