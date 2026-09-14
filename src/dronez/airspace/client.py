"""Sovereign NFZ / GACA sync channel: authenticity, freshness, and clearance.

This module implements the Milestone-0 deliverable *"encrypted sync channel to
local sovereign NFZ databases established and tested"* and the decision logic
behind the ``check_airspace_clearance`` tool specified in Master Plan §5.

Security properties enforced here
---------------------------------
=====================================  ==============================================
Control                                Source
=====================================  ==============================================
Fail-closed on every error path        Zero-Trust §0.1 *Default Deny*
Bounded freshness window               Master Plan §4 ``AirspaceZone``
Allow-listed signature algorithm       Zero-Trust §1.1 *JWT alg-confusion defense*
Constant-time signature comparison     Zero-Trust §10 *Constant-Time Comparison*
Monotonic sequence (replay defense)    Zero-Trust §4.3 / §5.1 *Replay Protection*
Strict schema, undeclared fields die   Zero-Trust §3.1 *Reject Unexpected Input*
Feed content is data, never instruction Zero-Trust §4.2 *Indirect Prompt Injection*
Bounded payload size                   Zero-Trust §0.1 (resource-exhaustion)
=====================================  ==============================================

What this module deliberately does **not** do
---------------------------------------------
* It does not open sockets. Transport (mTLS 1.3 to the sovereign endpoint, pinned
  chain, egress-proxied per Zero-Trust §3.3) is the concern of the deployment
  adapter added at Milestone 1. The :class:`NfzSyncChannel` protocol is the seam.
* It does not cache a clearance beyond
  :data:`~dronez.safety.envelope.SafetyEnvelope.nfz_clearance_validity_s`, so a
  decision cannot be minted early and replayed at dispatch time.
* It never emits an "allow" on an exception path. Read :func:`AirspaceClearanceService.
  check_clearance` end to end before changing anything: every ``return`` that is
  not an explicit affirmative clearance is a denial.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final, Protocol

from dronez.airspace.geometry import altitude_bands_overlap, polygons_intersect
from dronez.airspace.schema import (
    AirspaceZone,
    NfzBulletin,
    Polygon,
    SchemaValidationError,
    Severity,
    parse_bulletin,
)
from dronez.safety.envelope import ENVELOPE, SafetyEnvelope

__all__ = [
    "ALLOWED_SIGNATURE_ALGORITHMS",
    "MAX_BULLETIN_BYTES",
    "AirspaceCache",
    "AirspaceClearanceService",
    "ClearanceDecision",
    "DenialReason",
    "FeedState",
    "NfzChannelError",
    "NfzSyncChannel",
    "SigningKey",
    "SigningKeyRegistry",
    "canonical_signing_bytes",
]

#: Hard cap on an accepted bulletin. A feed that needs more than this is a defect
#: or an attack; either way we refuse to allocate for it.
MAX_BULLETIN_BYTES: Final[int] = 8 * 1024 * 1024

#: Explicit algorithm allow-list. The verifier is *always* called with an algorithm
#: from this table; the ``algorithm`` field on an inbound bulletin selects an entry
#: here, it never supplies the implementation. Anything absent - including the
#: classic ``none`` - is rejected before any comparison happens.
ALLOWED_SIGNATURE_ALGORITHMS: Final[frozenset[str]] = frozenset({"hmac-sha256", "ed25519"})

#: Algorithms in the allow-list that this build can actually verify. ``ed25519``
#: is the production algorithm for the sovereign feed and is registered here for
#: crypto-agility (Zero-Trust §0.1), but it is not implemented at Milestone 0 and
#: therefore fails **closed** with an explicit error rather than being skipped.
_IMPLEMENTED_ALGORITHMS: Final[frozenset[str]] = frozenset({"hmac-sha256"})


class NfzChannelError(RuntimeError):
    """Transport-or-protocol failure on the sync channel. Always resolves to denial."""


class DenialReason(StrEnum):
    """Machine-readable reason for a non-affirmative clearance.

    Every value is auditable and maps to a `Command` record, because Master Plan §5
    requires rejected proposals to be logged as a security signal, not discarded.
    """

    CLEARED = "cleared"
    ZONE_CONFLICT = "zone_conflict"
    FEED_STALE = "feed_stale"
    FEED_UNAVAILABLE = "feed_unavailable"
    FEED_NEVER_SYNCED = "feed_never_synced"
    ENVELOPE_VIOLATION = "envelope_violation"
    SCHEMA_REJECTED = "schema_rejected"
    SIGNATURE_INVALID = "signature_invalid"
    REPLAY_DETECTED = "replay_detected"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True, slots=True)
class ClearanceDecision:
    """Binding pre-dispatch airspace decision.

    ``cleared`` is ``True`` only on an explicit affirmative path. Treat any other
    construction of this object as a denial.
    """

    cleared: bool
    reason: DenialReason
    detail: str
    evaluated_utc: datetime
    expires_utc: datetime
    blocking_zone_ids: tuple[str, ...] = ()
    advisory_zone_ids: tuple[str, ...] = ()
    feed_authority: str | None = None
    feed_sequence: int | None = None
    feed_age_s: float | None = None

    def is_valid_at(self, when: datetime) -> bool:
        """A clearance may only be acted on inside its validity window."""
        return self.cleared and when < self.expires_utc

    def to_audit_record(self) -> dict[str, Any]:
        """Flat, log-safe projection. Contains no free text from the feed."""
        return {
            "cleared": self.cleared,
            "reason": self.reason.value,
            "detail": self.detail,
            "evaluated_utc": self.evaluated_utc.isoformat(),
            "expires_utc": self.expires_utc.isoformat(),
            "blocking_zone_ids": list(self.blocking_zone_ids),
            "advisory_zone_ids": list(self.advisory_zone_ids),
            "feed_authority": self.feed_authority,
            "feed_sequence": self.feed_sequence,
            "feed_age_s": self.feed_age_s,
        }


@dataclass(frozen=True, slots=True)
class FeedState:
    """Observable health of the sync channel, for the command-room status panel."""

    authority: str | None
    last_sequence: int | None
    last_bulletin_id: str | None
    last_sync_utc: datetime | None
    zone_count: int
    consecutive_failures: int

    def age_s(self, now: datetime) -> float | None:
        if self.last_sync_utc is None:
            return None
        return (now - self.last_sync_utc).total_seconds()


@dataclass(frozen=True, slots=True)
class SigningKey:
    """A verification key for one issuing authority.

    ``material`` is the shared secret (``hmac-sha256``) or public key (``ed25519``).
    It is injected at runtime from Vault/KMS per Zero-Trust §6.1 - never committed.
    """

    key_id: str
    algorithm: str
    material: bytes
    authority: str


class SigningKeyRegistry:
    """Known-key-set registry for bulletin verification.

    A ``key_id`` is looked up here and *only* here. It is never used to construct a
    filesystem path, URL, or database query - that is the ``kid``-injection defence
    called out in Zero-Trust §1.1.
    """

    def __init__(self, keys: Sequence[SigningKey] = ()) -> None:
        self._keys: dict[str, SigningKey] = {}
        for key in keys:
            self.register(key)

    def register(self, key: SigningKey) -> None:
        if key.algorithm not in ALLOWED_SIGNATURE_ALGORITHMS:
            raise ValueError(
                f"algorithm {key.algorithm!r} is not on the allow-list "
                f"{sorted(ALLOWED_SIGNATURE_ALGORITHMS)}"
            )
        if not key.material:
            raise ValueError("refusing to register a key with empty material")
        self._keys[key.key_id] = key

    def get(self, key_id: str) -> SigningKey | None:
        return self._keys.get(key_id)


def canonical_signing_bytes(payload: Mapping[str, Any]) -> bytes:
    """Deterministic byte string that a bulletin signature covers.

    The signature block is included with its ``value`` removed, so ``algorithm``
    and ``key_id`` are themselves signed. An attacker therefore cannot downgrade
    a bulletin to a weaker algorithm or point it at a different key without
    invalidating the signature.
    """
    body = {k: v for k, v in payload.items() if k != "signature"}
    sig = payload.get("signature")
    if isinstance(sig, Mapping):
        body["signature"] = {k: v for k, v in sig.items() if k != "value"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical.encode("utf-8")


class NfzSyncChannel(Protocol):
    """Transport seam for the sovereign feed.

    Implementations return the raw signed bulletin bytes exactly as received. They
    MUST NOT parse, normalise, or "repair" the payload - doing so would move trust
    ahead of verification.
    """

    def fetch(self, since_sequence: int | None = None) -> bytes:
        """Return raw bulletin bytes, or raise :class:`NfzChannelError`."""
        ...


class AirspaceCache:
    """Verified, freshness-bounded store of sovereign airspace restrictions.

    The cache is authoritative only inside
    :data:`~dronez.safety.envelope.SafetyEnvelope.nfz_max_staleness_s`. Past that it
    reports itself stale and every clearance derived from it is denied.
    """

    def __init__(
        self,
        registry: SigningKeyRegistry,
        envelope: SafetyEnvelope = ENVELOPE,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._envelope = envelope
        self._clock = clock or (lambda: datetime.now(UTC))
        self._zones: dict[str, AirspaceZone] = {}
        self._authority: str | None = None
        self._last_sequence: int | None = None
        self._last_bulletin_id: str | None = None
        self._last_sync_utc: datetime | None = None
        self._consecutive_failures: int = 0

    # -- verification ----------------------------------------------------

    def _verify(self, raw: bytes) -> NfzBulletin:
        """Authenticate then parse. Raises on any failure; never returns partial state."""
        if len(raw) > MAX_BULLETIN_BYTES:
            raise NfzChannelError(
                f"bulletin of {len(raw)} bytes exceeds the {MAX_BULLETIN_BYTES}-byte cap"
            )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NfzChannelError(f"bulletin is not valid UTF-8 JSON: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise NfzChannelError("bulletin root must be a JSON object")

        sig = payload.get("signature")
        if not isinstance(sig, Mapping):
            raise NfzChannelError("bulletin carries no signature block")
        algorithm = sig.get("algorithm")
        key_id = sig.get("key_id")
        value = sig.get("value")
        # Explicit isinstance checks rather than all(...): these narrow the types for
        # the verifier below, so the constant-time comparison provably operates on str.
        if not (
            isinstance(algorithm, str)
            and isinstance(key_id, str)
            and isinstance(value, str)
        ):
            raise NfzChannelError("malformed signature block")

        if algorithm not in ALLOWED_SIGNATURE_ALGORITHMS:
            raise NfzChannelError(f"signature algorithm {algorithm!r} is not allow-listed")
        if algorithm not in _IMPLEMENTED_ALGORITHMS:
            raise NfzChannelError(
                f"signature algorithm {algorithm!r} is allow-listed but not implemented in "
                "this build; failing closed rather than accepting an unverified bulletin"
            )

        key = self._registry.get(key_id)
        if key is None:
            raise NfzChannelError(f"unknown signing key_id {key_id!r}")
        if key.algorithm != algorithm:
            raise NfzChannelError(
                f"key {key_id!r} is registered for {key.algorithm!r} but the bulletin "
                f"claims {algorithm!r}; algorithm-substitution rejected"
            )

        expected = hmac.new(
            key.material, canonical_signing_bytes(payload), hashlib.sha256
        ).hexdigest()
        # Constant-time comparison: Zero-Trust Standard Section 10.
        if not hmac.compare_digest(expected, value):
            raise NfzChannelError("bulletin signature verification failed")

        try:
            bulletin = parse_bulletin(payload)
        except SchemaValidationError as exc:
            raise NfzChannelError(f"bulletin failed strict schema validation: {exc}") from exc

        if bulletin.authority != key.authority:
            raise NfzChannelError(
                f"bulletin claims authority {bulletin.authority!r} but key {key_id!r} is "
                f"bound to {key.authority!r}; cross-authority spoofing rejected"
            )
        return bulletin

    # -- ingestion -------------------------------------------------------

    def apply(self, raw: bytes) -> NfzBulletin:
        """Verify and apply a bulletin. Raises :class:`NfzChannelError` on rejection.

        On rejection the cache is left **entirely unchanged** - a rejected bulletin
        can neither add nor remove a restriction.
        """
        try:
            bulletin = self._verify(raw)
        except NfzChannelError:
            self._consecutive_failures += 1
            raise

        now = self._clock()

        if self._last_sequence is not None and bulletin.sequence <= self._last_sequence:
            self._consecutive_failures += 1
            raise NfzChannelError(
                f"bulletin sequence {bulletin.sequence} is not newer than the last accepted "
                f"sequence {self._last_sequence}; replay rejected"
            )
        if self._authority is not None and bulletin.authority != self._authority:
            self._consecutive_failures += 1
            raise NfzChannelError(
                f"cache is bound to authority {self._authority!r}; refusing a bulletin "
                f"from {bulletin.authority!r}"
            )
        if now >= bulletin.valid_until_utc:
            self._consecutive_failures += 1
            raise NfzChannelError(
                f"bulletin expired at {bulletin.valid_until_utc.isoformat()} "
                f"(now {now.isoformat()})"
            )

        if bulletin.full_snapshot:
            self._zones = {z.zone_id: z for z in bulletin.zones}
        else:
            for zone_id in bulletin.revoked_zone_ids:
                self._zones.pop(zone_id, None)
            for zone in bulletin.zones:
                self._zones[zone.zone_id] = zone

        self._authority = bulletin.authority
        self._last_sequence = bulletin.sequence
        self._last_bulletin_id = bulletin.bulletin_id
        self._last_sync_utc = now
        self._consecutive_failures = 0
        return bulletin

    def sync(self, channel: NfzSyncChannel) -> NfzBulletin:
        """Pull one bulletin from ``channel`` and apply it."""
        try:
            raw = channel.fetch(since_sequence=self._last_sequence)
        except NfzChannelError:
            self._consecutive_failures += 1
            raise
        except Exception as exc:  # any transport defect is a fail-closed condition
            self._consecutive_failures += 1
            raise NfzChannelError(f"sync transport failure: {exc!r}") from exc
        return self.apply(raw)

    # -- inspection ------------------------------------------------------

    @property
    def state(self) -> FeedState:
        return FeedState(
            authority=self._authority,
            last_sequence=self._last_sequence,
            last_bulletin_id=self._last_bulletin_id,
            last_sync_utc=self._last_sync_utc,
            zone_count=len(self._zones),
            consecutive_failures=self._consecutive_failures,
        )

    def is_fresh(self, now: datetime | None = None) -> bool:
        """True only if a bulletin has been accepted inside the freshness window."""
        now = now or self._clock()
        if self._last_sync_utc is None:
            return False
        return (now - self._last_sync_utc).total_seconds() <= self._envelope.nfz_max_staleness_s

    def active_zones(self, now: datetime | None = None) -> tuple[AirspaceZone, ...]:
        """Zones in force at ``now``. Does **not** imply the cache is fresh."""
        now = now or self._clock()
        return tuple(z for z in self._zones.values() if z.is_active_at(now))


class AirspaceClearanceService:
    """Decision logic behind the ``check_airspace_clearance`` MCP tool.

    Master Plan §5 makes this a mandatory pre-dispatch gate:
    ``deploy_recon_waypoint`` MUST receive an affirmative clearance before dispatch,
    and *a stale, unreachable, or negative clearance response fails the dispatch
    closed*. That sentence is the whole contract of this class.
    """

    def __init__(
        self,
        cache: AirspaceCache,
        envelope: SafetyEnvelope = ENVELOPE,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._cache = cache
        self._envelope = envelope
        self._clock = clock or (lambda: datetime.now(UTC))

    def _deny(
        self,
        reason: DenialReason,
        detail: str,
        now: datetime,
        *,
        blocking: tuple[str, ...] = (),
        advisory: tuple[str, ...] = (),
    ) -> ClearanceDecision:
        state = self._cache.state
        return ClearanceDecision(
            cleared=False,
            reason=reason,
            detail=detail,
            evaluated_utc=now,
            # A denial carries no usable validity window.
            expires_utc=now,
            blocking_zone_ids=blocking,
            advisory_zone_ids=advisory,
            feed_authority=state.authority,
            feed_sequence=state.last_sequence,
            feed_age_s=state.age_s(now),
        )

    def check_clearance(
        self,
        polygon: Polygon,
        altitude_min_m_agl: float,
        altitude_max_m_agl: float,
    ) -> ClearanceDecision:
        """Return a binding clearance decision for a proposed mission volume.

        This method does not raise. Every failure mode - including an unexpected
        internal error - is converted into an explicit denial, because an exception
        escaping into the dispatch path is exactly the ambiguity that Zero-Trust
        §0.1 requires us to resolve as "deny".
        """
        now = self._clock()
        try:
            env = self._envelope

            # 1. Safety envelope first. This is independent of any feed state, so a
            #    plan that violates the hard envelope is denied even with a perfect
            #    feed - and is never silently clipped to fit.
            if not altitude_min_m_agl < altitude_max_m_agl:
                return self._deny(
                    DenialReason.ENVELOPE_VIOLATION,
                    "altitude_min_m_agl must be strictly below altitude_max_m_agl",
                    now,
                )
            if altitude_min_m_agl < env.altitude_min_agl_m:
                return self._deny(
                    DenialReason.ENVELOPE_VIOLATION,
                    f"requested floor {altitude_min_m_agl} m AGL is below the "
                    f"{env.altitude_min_agl_m} m AGL envelope floor",
                    now,
                )
            if altitude_max_m_agl > env.altitude_max_agl_m:
                return self._deny(
                    DenialReason.ENVELOPE_VIOLATION,
                    f"requested ceiling {altitude_max_m_agl} m AGL exceeds the "
                    f"{env.altitude_max_agl_m} m AGL envelope ceiling",
                    now,
                )

            # 2. Feed must have synced at all, and must be inside its freshness window.
            state = self._cache.state
            if state.last_sync_utc is None:
                return self._deny(
                    DenialReason.FEED_NEVER_SYNCED,
                    "no sovereign NFZ bulletin has been accepted; refusing to treat an "
                    "empty cache as clear airspace",
                    now,
                )
            if not self._cache.is_fresh(now):
                age = state.age_s(now)
                return self._deny(
                    DenialReason.FEED_STALE,
                    f"NFZ data is {age:.1f}s old, past the {env.nfz_max_staleness_s}s "
                    "freshness window; a cached snapshot is not authoritative past it",
                    now,
                )

            # 3. Geometric + vertical conflict against every zone in force.
            blocking: list[str] = []
            advisory: list[str] = []
            for zone in self._cache.active_zones(now):
                if not altitude_bands_overlap(
                    altitude_min_m_agl,
                    altitude_max_m_agl,
                    zone.altitude_floor_m_agl,
                    zone.altitude_ceiling_m_agl,
                ):
                    continue
                if not polygons_intersect(polygon, zone.geometry):
                    continue
                if zone.severity is Severity.BLOCKING:
                    blocking.append(zone.zone_id)
                else:
                    advisory.append(zone.zone_id)

            if blocking:
                return self._deny(
                    DenialReason.ZONE_CONFLICT,
                    f"proposed volume intersects {len(blocking)} blocking sovereign "
                    "airspace restriction(s)",
                    now,
                    blocking=tuple(sorted(blocking)),
                    advisory=tuple(sorted(advisory)),
                )

            # 4. Affirmative clearance - the single path that sets cleared=True.
            return ClearanceDecision(
                cleared=True,
                reason=DenialReason.CLEARED,
                detail="no blocking sovereign airspace restriction intersects the proposed volume",
                evaluated_utc=now,
                expires_utc=now + timedelta(seconds=env.nfz_clearance_validity_s),
                blocking_zone_ids=(),
                advisory_zone_ids=tuple(sorted(advisory)),
                feed_authority=state.authority,
                feed_sequence=state.last_sequence,
                feed_age_s=state.age_s(now),
            )
        except Exception as exc:
            return self._deny(
                DenialReason.INTERNAL_ERROR,
                f"clearance evaluation raised {type(exc).__name__}; failing closed",
                now,
            )
