"""Deterministic mock of the sovereign NFZ / GACA sync channel.

Purpose
-------
Milestone 0 must demonstrate the sync channel *and its failure behaviour* before
any flight-capable code exists. This mock is the counterpart to
:class:`dronez.airspace.client.AirspaceCache`: it issues correctly signed
bulletins, and - just as importantly - it can issue the malformed, stale, replayed
and tampered ones that the fail-closed paths must reject.

Scope boundary
--------------
This is **test and development scaffolding**. It is not a production data source:

* It carries a hard-coded development signing secret. That secret authenticates
  nothing real; the production channel uses ``ed25519`` over mTLS with key
  material from Vault/KMS (Zero-Trust §6.1 - zero hardcoded keys in git applies to
  *production* secrets, and this constant is explicitly not one).
* Its zone data is illustrative geometry for testing the pipeline, **not** a
  reproduction of any real published restriction. It must never be used to make a
  real flight decision.

:func:`build_mock_channel` wires a cache, a channel and a clearance service
together for tests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final

from dronez.airspace.client import (
    AirspaceCache,
    AirspaceClearanceService,
    NfzChannelError,
    SigningKey,
    SigningKeyRegistry,
    canonical_signing_bytes,
)
from dronez.airspace.schema import SCHEMA_VERSION
from dronez.safety.envelope import ENVELOPE, SafetyEnvelope

__all__ = [
    "DEV_AUTHORITY",
    "DEV_KEY_ID",
    "DEV_SIGNING_SECRET",
    "FaultMode",
    "MockNfzSyncChannel",
    "build_mock_channel",
    "dev_key_registry",
    "sample_zones",
    "sign_bulletin",
]

#: Development-only identifiers. See the module docstring: this secret is inert.
DEV_KEY_ID: Final[str] = "dev-nfz-signing-key-001"
DEV_AUTHORITY: Final[str] = "GACA-SOVEREIGN-NFZ"
DEV_SIGNING_SECRET: Final[bytes] = b"DEVELOPMENT-ONLY-NOT-A-PRODUCTION-SECRET"


class FaultMode(StrEnum):
    """Failure modes the mock can inject, one per fail-closed path under test."""

    NONE = "none"
    UNREACHABLE = "unreachable"                 # transport down -> FEED_UNAVAILABLE
    TAMPERED_BODY = "tampered_body"             # signature no longer covers the body
    BAD_SIGNATURE = "bad_signature"             # signature value corrupted
    UNKNOWN_KEY = "unknown_key"                 # key_id not in the registry
    ALGORITHM_DOWNGRADE = "algorithm_downgrade" # claims an unimplemented/absent alg
    UNDECLARED_FIELD = "undeclared_field"       # mass-assignment probe
    REPLAY = "replay"                           # re-issues the previous sequence
    EXPIRED = "expired"                         # valid_until already past
    OVERSIZED = "oversized"                     # exceeds MAX_BULLETIN_BYTES
    MALFORMED_JSON = "malformed_json"           # not parseable at all
    CROSS_AUTHORITY = "cross_authority"         # body claims a different authority


def dev_key_registry() -> SigningKeyRegistry:
    """Registry holding only the development key."""
    return SigningKeyRegistry([
        SigningKey(
            key_id=DEV_KEY_ID,
            algorithm="hmac-sha256",
            material=DEV_SIGNING_SECRET,
            authority=DEV_AUTHORITY,
        )
    ])


def sign_bulletin(payload: dict[str, Any], secret: bytes = DEV_SIGNING_SECRET) -> dict[str, Any]:
    """Attach a valid ``hmac-sha256`` signature to ``payload`` in place and return it."""
    payload.setdefault("signature", {})
    payload["signature"].setdefault("algorithm", "hmac-sha256")
    payload["signature"].setdefault("key_id", DEV_KEY_ID)
    payload["signature"]["value"] = hmac.new(
        secret, canonical_signing_bytes(payload), hashlib.sha256
    ).hexdigest()
    return payload


def _square(lon: float, lat: float, half_deg: float) -> dict[str, Any]:
    """Axis-aligned square centred on ``(lon, lat)``. Illustrative geometry only."""
    return {
        "type": "Polygon",
        "coordinates": [[
            [lon - half_deg, lat - half_deg],
            [lon + half_deg, lat - half_deg],
            [lon + half_deg, lat + half_deg],
            [lon - half_deg, lat + half_deg],
            [lon - half_deg, lat - half_deg],
        ]],
    }


def _iso(dt: datetime) -> str:
    """UTC ISO-8601 with a ``Z`` suffix, the form the feed publishes."""
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def sample_zones(now: datetime) -> list[dict[str, Any]]:
    """Illustrative restriction set exercising every severity and time-window case.

    Fictional geometry for pipeline testing. Not real published airspace data.
    """
    base = {"authority": DEV_AUTHORITY}
    return [
        {
            **base,
            "zone_id": "NFZ-AERODROME-TEST-01",
            "designation": "Test aerodrome approach corridor",
            "zone_type": "aerodrome",
            "severity": "blocking",
            "geometry": _square(46.7000, 24.7000, 0.0200),
            "altitude_floor_m_agl": 0.0,
            "altitude_ceiling_m_agl": 3000.0,
            "effective_from": _iso(now - timedelta(days=365)),
            "effective_until": None,
            "source_ref": "MOCK/AERODROME/01",
            "remarks": "Permanent. Illustrative geometry for channel testing.",
        },
        {
            **base,
            "zone_id": "NFZ-CRITICAL-INFRA-TEST-02",
            "designation": "Test critical infrastructure exclusion",
            "zone_type": "critical_infrastructure",
            "severity": "blocking",
            "geometry": _square(46.8000, 24.8000, 0.0050),
            "altitude_floor_m_agl": 0.0,
            "altitude_ceiling_m_agl": 500.0,
            "effective_from": _iso(now - timedelta(days=30)),
            "effective_until": None,
            "source_ref": "MOCK/INFRA/02",
            "remarks": "",
        },
        {
            **base,
            "zone_id": "NFZ-TEMP-NOTAM-TEST-03",
            "designation": "Test temporary restriction (active now)",
            "zone_type": "temporary_restriction",
            "severity": "blocking",
            "geometry": _square(46.9000, 24.9000, 0.0100),
            "altitude_floor_m_agl": 50.0,
            "altitude_ceiling_m_agl": 1500.0,
            "effective_from": _iso(now - timedelta(hours=1)),
            "effective_until": _iso(now + timedelta(hours=5)),
            "source_ref": "MOCK/NOTAM/03",
            "remarks": "",
        },
        {
            **base,
            "zone_id": "NFZ-TEMP-NOTAM-TEST-04",
            "designation": "Test temporary restriction (not yet in force)",
            "zone_type": "temporary_restriction",
            "severity": "blocking",
            "geometry": _square(47.0000, 25.0000, 0.0100),
            "altitude_floor_m_agl": 0.0,
            "altitude_ceiling_m_agl": 1500.0,
            "effective_from": _iso(now + timedelta(days=2)),
            "effective_until": _iso(now + timedelta(days=3)),
            "source_ref": "MOCK/NOTAM/04",
            "remarks": "",
        },
        {
            **base,
            "zone_id": "NFZ-ADVISORY-TEST-05",
            "designation": "Test advisory area (surfaced, non-blocking)",
            "zone_type": "danger",
            "severity": "advisory",
            "geometry": _square(46.7500, 24.7500, 0.0150),
            "altitude_floor_m_agl": 0.0,
            "altitude_ceiling_m_agl": 200.0,
            "effective_from": _iso(now - timedelta(days=7)),
            "effective_until": None,
            "source_ref": "MOCK/ADVISORY/05",
            "remarks": "",
        },
    ]


class MockNfzSyncChannel:
    """In-memory :class:`~dronez.airspace.client.NfzSyncChannel` with fault injection.

    Deterministic: the same construction plus the same fault sequence always
    produces byte-identical bulletins, so failures are reproducible in CI.
    """

    def __init__(
        self,
        *,
        zones: Sequence[dict[str, Any]] | None = None,
        clock: Callable[[], datetime] | None = None,
        fault: FaultMode = FaultMode.NONE,
        validity_s: float = 600.0,
        secret: bytes = DEV_SIGNING_SECRET,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._zones = list(zones) if zones is not None else None
        self.fault = fault
        self._validity_s = validity_s
        self._secret = secret
        self._sequence = 0
        self.fetch_count = 0

    def _build_payload(self, now: datetime) -> dict[str, Any]:
        zones = self._zones if self._zones is not None else sample_zones(now)
        issued, valid_until = now, now + timedelta(seconds=self._validity_s)
        if self.fault is FaultMode.EXPIRED:
            issued = now - timedelta(seconds=self._validity_s * 2)
            valid_until = now - timedelta(seconds=1)
        return {
            "bulletin_id": f"MOCK-BULLETIN-{self._sequence:06d}",
            "schema_version": SCHEMA_VERSION,
            "authority": DEV_AUTHORITY,
            "sequence": self._sequence,
            "issued_utc": _iso(issued),
            "valid_until_utc": _iso(valid_until),
            "zones": zones,
            "revoked_zone_ids": [],
            "full_snapshot": True,
        }

    def fetch(self, since_sequence: int | None = None) -> bytes:
        """Produce the next bulletin, applying :attr:`fault`."""
        self.fetch_count += 1
        fault = self.fault

        if fault is FaultMode.UNREACHABLE:
            raise NfzChannelError("mock: sovereign NFZ endpoint unreachable")
        if fault is FaultMode.MALFORMED_JSON:
            return b'{"bulletin_id": "MOCK", "zones": [ '

        if fault is FaultMode.REPLAY:
            # Re-issue the sequence already accepted, validly signed.
            self._sequence = max(0, self._sequence - 1)
        else:
            self._sequence += 1

        now = self._clock()
        payload = self._build_payload(now)

        if fault is FaultMode.CROSS_AUTHORITY:
            payload["authority"] = "IMPERSONATED-AUTHORITY"
            for zone in payload["zones"]:
                zone["authority"] = "IMPERSONATED-AUTHORITY"
        if fault is FaultMode.OVERSIZED:
            payload["zones"] = list(payload["zones"]) + [
                {
                    **payload["zones"][0],
                    "zone_id": f"NFZ-BULK-{i:06d}",
                    "remarks": "x" * 500,
                }
                for i in range(20_000)
            ]

        payload = sign_bulletin(payload, self._secret)

        if fault is FaultMode.BAD_SIGNATURE:
            value = payload["signature"]["value"]
            payload["signature"]["value"] = ("0" if value[0] != "0" else "1") + value[1:]
        elif fault is FaultMode.UNKNOWN_KEY:
            payload["signature"]["key_id"] = "attacker-supplied-key-999"
        elif fault is FaultMode.ALGORITHM_DOWNGRADE:
            payload["signature"]["algorithm"] = "none"
        elif fault is FaultMode.TAMPERED_BODY:
            # Silently drop a blocking restriction after signing - the exact attack
            # the signature exists to catch.
            if payload["zones"]:
                payload["zones"] = payload["zones"][1:]
        elif fault is FaultMode.UNDECLARED_FIELD:
            payload["override_safety_envelope"] = True
            payload = sign_bulletin(payload, self._secret)

        return json.dumps(payload).encode("utf-8")


@dataclass(frozen=True, slots=True)
class MockHarness:
    """Wired mock: channel + cache + clearance service sharing one clock."""

    channel: MockNfzSyncChannel
    cache: AirspaceCache
    clearance: AirspaceClearanceService


def build_mock_channel(
    *,
    clock: Callable[[], datetime] | None = None,
    fault: FaultMode = FaultMode.NONE,
    zones: Sequence[dict[str, Any]] | None = None,
    envelope: SafetyEnvelope = ENVELOPE,
) -> MockHarness:
    """Construct a ready-to-use mock NFZ stack. The cache starts **unsynced**."""
    clock = clock or (lambda: datetime.now(UTC))
    channel = MockNfzSyncChannel(clock=clock, fault=fault, zones=zones)
    cache = AirspaceCache(dev_key_registry(), envelope, clock=clock)
    clearance = AirspaceClearanceService(cache, envelope, clock=clock)
    return MockHarness(channel=channel, cache=cache, clearance=clearance)
