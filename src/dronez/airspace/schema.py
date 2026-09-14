"""Wire schema for the sovereign No-Fly-Zone (NFZ) / GACA sync channel.

Trust posture
-------------
The NFZ feed is an **external data source and therefore untrusted input**, even
though it is authoritative for airspace policy. Master Plan §4 places it behind
the same policy gate as an operator-originated command; Zero-Trust Standard §4.2
(*Indirect Prompt Injection Defense*) requires content retrieved from external
sources to be treated as data, never as instructions, and forbids it from
altering the agent's tool scope, system prompt, or safety envelope.

Concretely, that means everything arriving on this channel is:

1. **Schema-validated before use.** Undeclared fields cause outright rejection
   (Zero-Trust §3.1 *Reject Unexpected Input*, blocking mass-assignment).
2. **Never interpreted as text for the model.** ``designation`` and ``remarks``
   are free-text fields controlled by an external party. They are carried for
   operator display only and are marked untrusted when rendered. No field on this
   channel may widen the safety envelope or grant a capability.
3. **Authenticated and replay-checked** before parsing is trusted - see
   :mod:`dronez.airspace.client`.

This module is stdlib-only and performs no I/O, so it can be fuzzed directly
(Zero-Trust §9 *Fuzzing & Sanitizers as Release Gates*).
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "SCHEMA_VERSION",
    "AirspaceZone",
    "NfzBulletin",
    "Polygon",
    "SchemaValidationError",
    "Severity",
    "SignatureBlock",
    "ZoneType",
    "parse_bulletin",
]

#: Version of the NFZ wire contract. Bumped on any breaking change; the client
#: refuses a bulletin whose major version it does not implement.
SCHEMA_VERSION: Final[str] = "nfz-bulletin/1.0.0"

_MAX_ZONES_PER_BULLETIN: Final[int] = 5_000
_MAX_RING_POSITIONS: Final[int] = 2_000
_MAX_RINGS: Final[int] = 32
_MAX_TEXT_LEN: Final[int] = 512
_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")

#: Absolute ceiling accepted from the feed, as a sanity bound on a hostile or
#: corrupted payload. Well above any altitude this platform may ever fly.
_ABS_MAX_ALT_M: Final[float] = 20_000.0
_ABS_MIN_ALT_M: Final[float] = -500.0

# Declared field sets, used to reject undeclared input (Zero-Trust Sec.3.1).
# These live at module scope rather than on the dataclasses: a `Final`-annotated
# class attribute inside a slots dataclass is turned into a dataclass field, not a
# constant, which would both corrupt the constructor signature and break set
# arithmetic at runtime.
_ZONE_FIELDS: Final[frozenset[str]] = frozenset({
    "zone_id", "authority", "designation", "zone_type", "severity", "geometry",
    "altitude_floor_m_agl", "altitude_ceiling_m_agl", "effective_from",
    "effective_until", "source_ref", "remarks",
})

_SIGNATURE_FIELDS: Final[frozenset[str]] = frozenset({"algorithm", "key_id", "value"})

_BULLETIN_FIELDS: Final[frozenset[str]] = frozenset({
    "bulletin_id", "schema_version", "authority", "sequence", "issued_utc",
    "valid_until_utc", "zones", "revoked_zone_ids", "signature", "full_snapshot",
})


class SchemaValidationError(ValueError):
    """Raised on any schema violation. Callers MUST fail closed, never partially accept."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message


class ZoneType(StrEnum):
    """Classification of a restricted volume, as published by the issuing authority."""

    PROHIBITED = "prohibited"
    RESTRICTED = "restricted"
    DANGER = "danger"
    TEMPORARY_RESTRICTION = "temporary_restriction"
    AERODROME = "aerodrome"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    EMERGENCY_MANAGEMENT = "emergency_management"
    MILITARY = "military"


class Severity(StrEnum):
    """Effect of the zone on a dispatch decision.

    ``ADVISORY`` zones are surfaced to the operator but do not by themselves block
    a dispatch. ``BLOCKING`` zones deny it. An unknown value is never coerced to
    ``ADVISORY`` - it is a schema violation, so an authority adding a new severity
    fails closed rather than silently downgrading to "allowed".
    """

    BLOCKING = "blocking"
    ADVISORY = "advisory"


def _require(cond: bool, path: str, msg: str) -> None:
    if not cond:
        raise SchemaValidationError(path, msg)


def _reject_unknown(obj: Mapping[str, Any], allowed: frozenset[str], path: str) -> None:
    extra = sorted(set(obj) - allowed)
    _require(not extra, path, f"undeclared field(s) rejected: {extra}")


def _get_str(obj: Mapping[str, Any], key: str, path: str, *, max_len: int = _MAX_TEXT_LEN) -> str:
    val = obj.get(key)
    _require(isinstance(val, str), f"{path}.{key}", "must be a string")
    assert isinstance(val, str)
    _require(len(val) <= max_len, f"{path}.{key}", f"exceeds {max_len} characters")
    _require("\x00" not in val, f"{path}.{key}", "contains a NUL byte")
    return val


def _get_id(obj: Mapping[str, Any], key: str, path: str) -> str:
    val = _get_str(obj, key, path, max_len=64)
    _require(
        bool(_ID_RE.fullmatch(val)),
        f"{path}.{key}",
        "must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$",
    )
    return val


def _get_float(obj: Mapping[str, Any], key: str, path: str) -> float:
    val = obj.get(key)
    _require(
        isinstance(val, (int, float)) and not isinstance(val, bool),
        f"{path}.{key}",
        "must be a number",
    )
    assert isinstance(val, (int, float))
    out = float(val)
    _require(math.isfinite(out), f"{path}.{key}", "must be finite (NaN/Infinity rejected)")
    return out


def _get_utc(obj: Mapping[str, Any], key: str, path: str) -> datetime:
    raw = _get_str(obj, key, path, max_len=64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaValidationError(
            f"{path}.{key}", f"not a valid ISO-8601 timestamp: {exc}"
        ) from exc
    _require(parsed.tzinfo is not None, f"{path}.{key}", "must carry an explicit UTC offset")
    return parsed.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class Polygon:
    """A GeoJSON-style polygon in WGS-84, positions ordered ``[longitude, latitude]``.

    ``rings[0]`` is the exterior ring; any further rings are holes. Rings are
    explicitly closed (first position equals last).

    Self-intersection is **not** checked here. Milestone 1 moves authoritative
    geometry to PostGIS (``ST_IsValid`` / ``ST_Intersects``); until then callers
    must treat the containment helpers in :mod:`dronez.airspace.geometry` as
    conservative, and a conservative result always resolves toward denial.
    """

    rings: tuple[tuple[tuple[float, float], ...], ...]

    @property
    def exterior(self) -> tuple[tuple[float, float], ...]:
        return self.rings[0]

    @staticmethod
    def parse(raw: Any, path: str) -> Polygon:
        _require(isinstance(raw, Mapping), path, "must be an object")
        assert isinstance(raw, Mapping)
        _reject_unknown(raw, frozenset({"type", "coordinates"}), path)
        _require(raw.get("type") == "Polygon", f"{path}.type", "must be exactly 'Polygon'")

        coords = raw.get("coordinates")
        _require(isinstance(coords, Sequence) and not isinstance(coords, (str, bytes)),
                 f"{path}.coordinates", "must be an array of rings")
        assert isinstance(coords, Sequence)
        _require(1 <= len(coords) <= _MAX_RINGS,
                 f"{path}.coordinates", f"must hold 1..{_MAX_RINGS} rings")

        rings: list[tuple[tuple[float, float], ...]] = []
        for r_idx, ring in enumerate(coords):
            r_path = f"{path}.coordinates[{r_idx}]"
            _require(isinstance(ring, Sequence) and not isinstance(ring, (str, bytes)),
                     r_path, "must be an array of positions")
            assert isinstance(ring, Sequence)
            _require(4 <= len(ring) <= _MAX_RING_POSITIONS,
                     r_path, f"a closed ring needs 4..{_MAX_RING_POSITIONS} positions")

            positions: list[tuple[float, float]] = []
            for p_idx, pos in enumerate(ring):
                p_path = f"{r_path}[{p_idx}]"
                _require(isinstance(pos, Sequence) and not isinstance(pos, (str, bytes)),
                         p_path, "must be a [lon, lat] pair")
                assert isinstance(pos, Sequence)
                _require(len(pos) == 2, p_path, "must hold exactly 2 values ([lon, lat]); "
                                                "altitude belongs in the zone's altitude band")
                lon, lat = pos[0], pos[1]
                for name, val in (("lon", lon), ("lat", lat)):
                    _require(isinstance(val, (int, float)) and not isinstance(val, bool),
                             f"{p_path}.{name}", "must be a number")
                    _require(math.isfinite(float(val)),
                             f"{p_path}.{name}", "must be finite (NaN/Infinity rejected)")
                lon_f, lat_f = float(lon), float(lat)
                _require(-180.0 <= lon_f <= 180.0, f"{p_path}.lon", "out of range [-180, 180]")
                _require(-90.0 <= lat_f <= 90.0, f"{p_path}.lat", "out of range [-90, 90]")
                positions.append((lon_f, lat_f))

            _require(positions[0] == positions[-1], r_path,
                     "ring must be explicitly closed (first position == last position)")
            distinct = len(set(positions[:-1]))
            _require(distinct >= 3, r_path, "ring must enclose an area (>= 3 distinct positions)")
            rings.append(tuple(positions))

        return Polygon(rings=tuple(rings))

    def to_geojson(self) -> dict[str, Any]:
        return {
            "type": "Polygon",
            "coordinates": [[list(p) for p in ring] for ring in self.rings],
        }


@dataclass(frozen=True, slots=True)
class AirspaceZone:
    """One restricted volume published by the sovereign NFZ / GACA feed."""

    zone_id: str
    authority: str
    designation: str
    zone_type: ZoneType
    severity: Severity
    geometry: Polygon
    altitude_floor_m_agl: float
    altitude_ceiling_m_agl: float
    effective_from: datetime
    effective_until: datetime | None
    source_ref: str
    remarks: str = ""

    @staticmethod
    def parse(raw: Any, path: str) -> AirspaceZone:
        _require(isinstance(raw, Mapping), path, "must be an object")
        assert isinstance(raw, Mapping)
        _reject_unknown(raw, _ZONE_FIELDS, path)

        for required in ("zone_id", "authority", "designation", "zone_type", "severity",
                         "geometry", "altitude_floor_m_agl", "altitude_ceiling_m_agl",
                         "effective_from", "source_ref"):
            _require(required in raw, path, f"missing required field {required!r}")

        zone_type_raw = _get_str(raw, "zone_type", path, max_len=64)
        try:
            zone_type = ZoneType(zone_type_raw)
        except ValueError as exc:
            raise SchemaValidationError(
                f"{path}.zone_type",
                f"unknown zone type {zone_type_raw!r}; an unrecognised classification "
                "fails closed rather than being treated as unrestricted",
            ) from exc

        severity_raw = _get_str(raw, "severity", path, max_len=32)
        try:
            severity = Severity(severity_raw)
        except ValueError as exc:
            raise SchemaValidationError(
                f"{path}.severity",
                f"unknown severity {severity_raw!r}; refusing to downgrade an "
                "unrecognised severity to advisory",
            ) from exc

        floor = _get_float(raw, "altitude_floor_m_agl", path)
        ceiling = _get_float(raw, "altitude_ceiling_m_agl", path)
        _require(_ABS_MIN_ALT_M <= floor <= _ABS_MAX_ALT_M,
                 f"{path}.altitude_floor_m_agl", "implausible altitude")
        _require(_ABS_MIN_ALT_M <= ceiling <= _ABS_MAX_ALT_M,
                 f"{path}.altitude_ceiling_m_agl", "implausible altitude")
        _require(floor < ceiling, path, "altitude_floor_m_agl must be below altitude_ceiling_m_agl")

        effective_from = _get_utc(raw, "effective_from", path)
        effective_until: datetime | None = None
        if raw.get("effective_until") is not None:
            effective_until = _get_utc(raw, "effective_until", path)
            _require(effective_until > effective_from, f"{path}.effective_until",
                     "must be after effective_from")

        return AirspaceZone(
            zone_id=_get_id(raw, "zone_id", path),
            authority=_get_str(raw, "authority", path, max_len=64),
            designation=_get_str(raw, "designation", path),
            zone_type=zone_type,
            severity=severity,
            geometry=Polygon.parse(raw.get("geometry"), f"{path}.geometry"),
            altitude_floor_m_agl=floor,
            altitude_ceiling_m_agl=ceiling,
            effective_from=effective_from,
            effective_until=effective_until,
            source_ref=_get_str(raw, "source_ref", path),
            remarks=_get_str(raw, "remarks", path) if "remarks" in raw else "",
        )

    def is_active_at(self, when: datetime) -> bool:
        """True when this zone is in force at ``when`` (UTC)."""
        if when < self.effective_from:
            return False
        if self.effective_until is not None and when >= self.effective_until:
            return False
        return True


@dataclass(frozen=True, slots=True)
class SignatureBlock:
    """Detached authenticity envelope for a bulletin.

    ``algorithm`` is validated against an explicit allow-list by the client
    (Zero-Trust §1.1 - the verifier is always called with an allow-listed
    algorithm; there is no "take the algorithm the message asked for" path).
    """

    algorithm: str
    key_id: str
    value: str

    @staticmethod
    def parse(raw: Any, path: str) -> SignatureBlock:
        _require(isinstance(raw, Mapping), path, "must be an object")
        assert isinstance(raw, Mapping)
        _reject_unknown(raw, _SIGNATURE_FIELDS, path)
        return SignatureBlock(
            algorithm=_get_str(raw, "algorithm", path, max_len=32),
            key_id=_get_id(raw, "key_id", path),
            value=_get_str(raw, "value", path, max_len=1024),
        )


@dataclass(frozen=True, slots=True)
class NfzBulletin:
    """A signed, sequenced snapshot/delta of sovereign airspace restrictions.

    ``sequence`` is monotonic per ``authority``. The client rejects any bulletin
    whose sequence is not strictly greater than the last accepted one, which is
    what defeats replay of a stale-but-validly-signed bulletin (the same
    monotonic-counter reasoning as MAVLink2 signing in Zero-Trust §4.3).
    """

    bulletin_id: str
    schema_version: str
    authority: str
    sequence: int
    issued_utc: datetime
    valid_until_utc: datetime
    zones: tuple[AirspaceZone, ...]
    revoked_zone_ids: tuple[str, ...]
    signature: SignatureBlock
    full_snapshot: bool = True


def parse_bulletin(raw: Any) -> NfzBulletin:
    """Strictly parse an NFZ bulletin. Raises :class:`SchemaValidationError` on any violation.

    This function is pure and does no I/O. Authenticity, freshness and replay
    checks live in :mod:`dronez.airspace.client` and are applied to the raw bytes
    *before* the result of this parse is trusted for a clearance decision.
    """
    path = "bulletin"
    _require(isinstance(raw, Mapping), path, "must be an object")
    assert isinstance(raw, Mapping)
    _reject_unknown(raw, _BULLETIN_FIELDS, path)

    for required in ("bulletin_id", "schema_version", "authority", "sequence",
                     "issued_utc", "valid_until_utc", "zones", "signature"):
        _require(required in raw, path, f"missing required field {required!r}")

    schema_version = _get_str(raw, "schema_version", path, max_len=64)
    want_major = SCHEMA_VERSION.split("/")[1].split(".")[0]
    _require(schema_version.startswith("nfz-bulletin/"), f"{path}.schema_version",
             f"unrecognised contract; expected nfz-bulletin/* , got {schema_version!r}")
    got_major = schema_version.split("/")[1].split(".")[0]
    _require(got_major == want_major, f"{path}.schema_version",
             f"incompatible major version {schema_version!r}; "
             f"this build implements {SCHEMA_VERSION}")

    sequence = raw.get("sequence")
    _require(isinstance(sequence, int) and not isinstance(sequence, bool),
             f"{path}.sequence", "must be an integer")
    assert isinstance(sequence, int)
    _require(sequence >= 0, f"{path}.sequence", "must be non-negative")

    issued = _get_utc(raw, "issued_utc", path)
    valid_until = _get_utc(raw, "valid_until_utc", path)
    _require(valid_until > issued, f"{path}.valid_until_utc", "must be after issued_utc")

    zones_raw = raw.get("zones")
    _require(isinstance(zones_raw, Sequence) and not isinstance(zones_raw, (str, bytes)),
             f"{path}.zones", "must be an array")
    assert isinstance(zones_raw, Sequence)
    _require(len(zones_raw) <= _MAX_ZONES_PER_BULLETIN, f"{path}.zones",
             f"exceeds {_MAX_ZONES_PER_BULLETIN} zones")

    zones = tuple(AirspaceZone.parse(z, f"{path}.zones[{i}]") for i, z in enumerate(zones_raw))
    seen: set[str] = set()
    for zone in zones:
        _require(zone.zone_id not in seen, f"{path}.zones", f"duplicate zone_id {zone.zone_id!r}")
        seen.add(zone.zone_id)

    revoked_raw = raw.get("revoked_zone_ids", [])
    _require(isinstance(revoked_raw, Sequence) and not isinstance(revoked_raw, (str, bytes)),
             f"{path}.revoked_zone_ids", "must be an array")
    assert isinstance(revoked_raw, Sequence)
    revoked: list[str] = []
    for i, zid in enumerate(revoked_raw):
        r_path = f"{path}.revoked_zone_ids[{i}]"
        _require(isinstance(zid, str), r_path, "must be a string")
        assert isinstance(zid, str)
        _require(bool(_ID_RE.fullmatch(zid)), r_path, "malformed zone id")
        _require(zid not in seen, r_path,
                 f"zone {zid!r} is both published and revoked in the same bulletin")
        revoked.append(zid)

    full_snapshot = raw.get("full_snapshot", True)
    _require(isinstance(full_snapshot, bool), f"{path}.full_snapshot", "must be a boolean")

    authority = _get_str(raw, "authority", path, max_len=64)
    for zone in zones:
        _require(zone.authority == authority, f"{path}.zones",
                 f"zone {zone.zone_id!r} claims authority {zone.authority!r} but the "
                 f"bulletin is issued by {authority!r}; cross-authority injection rejected")

    return NfzBulletin(
        bulletin_id=_get_id(raw, "bulletin_id", path),
        schema_version=schema_version,
        authority=authority,
        sequence=sequence,
        issued_utc=issued,
        valid_until_utc=valid_until,
        zones=zones,
        revoked_zone_ids=tuple(revoked),
        signature=SignatureBlock.parse(raw.get("signature"), f"{path}.signature"),
        full_snapshot=bool(full_snapshot),
    )
