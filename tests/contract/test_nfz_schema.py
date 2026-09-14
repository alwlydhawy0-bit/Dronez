"""Wire-contract tests for the NFZ bulletin schema.

Every test here encodes a rejection that must survive refactoring. A schema that
accepts more than it did yesterday is a security regression, not a convenience.
"""

from __future__ import annotations

import copy
import json
from datetime import timedelta
from pathlib import Path

import pytest
from tests.conftest import T0

from dronez.airspace.mock_client import DEV_AUTHORITY, sample_zones, sign_bulletin
from dronez.airspace.schema import (
    SCHEMA_VERSION,
    AirspaceZone,
    Polygon,
    SchemaValidationError,
    Severity,
    ZoneType,
    parse_bulletin,
)

SCHEMA_FILE = (
    Path(__file__).resolve().parents[2]
    / "src/dronez/airspace/schemas/nfz-bulletin-1.0.0.schema.json"
)


def _bulletin() -> dict:
    def iso(dt) -> str:
        return dt.isoformat().replace("+00:00", "Z")

    return sign_bulletin({
        "bulletin_id": "TEST-BULLETIN-0001",
        "schema_version": SCHEMA_VERSION,
        "authority": DEV_AUTHORITY,
        "sequence": 1,
        "issued_utc": iso(T0),
        "valid_until_utc": iso(T0 + timedelta(hours=1)),
        "zones": sample_zones(T0),
        "revoked_zone_ids": [],
        "full_snapshot": True,
    })


def test_reference_bulletin_parses() -> None:
    bulletin = parse_bulletin(_bulletin())
    assert bulletin.authority == DEV_AUTHORITY
    assert len(bulletin.zones) == len(sample_zones(T0))
    assert bulletin.zones[0].zone_type is ZoneType.AERODROME


def test_undeclared_top_level_field_is_rejected() -> None:
    """Zero-Trust Sec.3.1: excess properties cause outright rejection (mass assignment)."""
    payload = _bulletin()
    payload["override_safety_envelope"] = True
    with pytest.raises(SchemaValidationError, match="undeclared field"):
        parse_bulletin(payload)


def test_undeclared_zone_field_is_rejected() -> None:
    payload = _bulletin()
    payload["zones"][0]["allow_flight"] = True
    with pytest.raises(SchemaValidationError, match="undeclared field"):
        parse_bulletin(payload)


def test_unknown_severity_is_rejected_not_downgraded() -> None:
    """An authority adding a severity must fail closed, never silently become advisory."""
    payload = _bulletin()
    payload["zones"][0]["severity"] = "informational"
    with pytest.raises(SchemaValidationError, match="refusing to downgrade"):
        parse_bulletin(payload)


def test_unknown_zone_type_is_rejected_not_treated_as_unrestricted() -> None:
    payload = _bulletin()
    payload["zones"][0]["zone_type"] = "brand_new_category"
    with pytest.raises(SchemaValidationError, match="fails closed"):
        parse_bulletin(payload)


def test_zone_may_not_claim_a_different_authority_than_the_bulletin() -> None:
    payload = _bulletin()
    payload["zones"][0]["authority"] = "SOME-OTHER-AUTHORITY"
    with pytest.raises(SchemaValidationError, match="cross-authority injection"):
        parse_bulletin(payload)


def test_incompatible_major_schema_version_is_rejected() -> None:
    payload = _bulletin()
    payload["schema_version"] = "nfz-bulletin/2.0.0"
    with pytest.raises(SchemaValidationError, match="incompatible major version"):
        parse_bulletin(payload)


def test_duplicate_zone_ids_are_rejected() -> None:
    payload = _bulletin()
    payload["zones"].append(copy.deepcopy(payload["zones"][0]))
    with pytest.raises(SchemaValidationError, match="duplicate zone_id"):
        parse_bulletin(payload)


def test_zone_cannot_be_published_and_revoked_in_one_bulletin() -> None:
    payload = _bulletin()
    payload["full_snapshot"] = False
    payload["revoked_zone_ids"] = [payload["zones"][0]["zone_id"]]
    with pytest.raises(SchemaValidationError, match="both published and revoked"):
        parse_bulletin(payload)


def test_inverted_altitude_band_is_rejected() -> None:
    payload = _bulletin()
    payload["zones"][0]["altitude_floor_m_agl"] = 900.0
    payload["zones"][0]["altitude_ceiling_m_agl"] = 100.0
    with pytest.raises(SchemaValidationError, match="must be below"):
        parse_bulletin(payload)


def test_naive_timestamp_is_rejected() -> None:
    """A timestamp without an offset is ambiguous; ambiguity fails closed."""
    payload = _bulletin()
    payload["issued_utc"] = "2026-01-15T09:00:00"
    with pytest.raises(SchemaValidationError, match="explicit UTC offset"):
        parse_bulletin(payload)


def test_valid_until_must_follow_issued() -> None:
    payload = _bulletin()
    payload["valid_until_utc"] = payload["issued_utc"]
    with pytest.raises(SchemaValidationError, match="must be after issued_utc"):
        parse_bulletin(payload)


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_coordinates_are_rejected(bad_value: float) -> None:
    """NaN defeats every comparison-based containment test, so it must never parse."""
    with pytest.raises(SchemaValidationError, match="finite"):
        Polygon.parse(
            {
                "type": "Polygon",
                "coordinates": [[[0.0, 0.0], [1.0, 0.0], [bad_value, 1.0], [0.0, 0.0]]],
            },
            "p",
        )


@pytest.mark.parametrize(
    "coords, expected",
    [
        ([[[0.0, 0.0], [1.0, 0.0], [1.0, 1.0]]], "4\\.\\.2000 positions"),
        ([[[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.5, 0.5]]], "explicitly closed"),
        ([[[0.0, 0.0], [0.0, 0.0], [0.0, 0.0], [0.0, 0.0]]], "enclose an area"),
        ([[[181.0, 0.0], [1.0, 0.0], [1.0, 1.0], [181.0, 0.0]]], "out of range"),
        ([[[0.0, 91.0], [1.0, 0.0], [1.0, 1.0], [0.0, 91.0]]], "out of range"),
    ],
)
def test_malformed_rings_are_rejected(coords: list, expected: str) -> None:
    with pytest.raises(SchemaValidationError, match=expected):
        Polygon.parse({"type": "Polygon", "coordinates": coords}, "p")


def test_position_with_altitude_is_rejected() -> None:
    """Altitude belongs to the zone band; a 3-element position is ambiguous input."""
    with pytest.raises(SchemaValidationError, match="exactly 2 values"):
        Polygon.parse(
            {
                "type": "Polygon",
                "coordinates": [[
                    [0.0, 0.0, 100.0], [1.0, 0.0, 1.0], [1.0, 1.0, 1.0], [0.0, 0.0, 1.0],
                ]],
            },
            "p",
        )


def test_zone_time_window_is_honoured() -> None:
    zones = {z.zone_id: z for z in parse_bulletin(_bulletin()).zones}
    active = zones["NFZ-TEMP-NOTAM-TEST-03"]
    future = zones["NFZ-TEMP-NOTAM-TEST-04"]
    assert active.is_active_at(T0)
    assert not future.is_active_at(T0)
    assert future.is_active_at(T0 + timedelta(days=2, hours=1))
    assert not active.is_active_at(T0 + timedelta(hours=6))


def test_published_json_schema_agrees_with_the_validator() -> None:
    """The published contract and the enforcing validator must not drift apart."""
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))

    expected_props = set(_bulletin()) | {"revoked_zone_ids", "full_snapshot"}
    assert schema["properties"].keys() == expected_props
    assert schema["additionalProperties"] is False
    assert schema["$defs"]["airspaceZone"]["additionalProperties"] is False
    assert schema["$defs"]["signature"]["additionalProperties"] is False

    assert set(schema["$defs"]["airspaceZone"]["properties"]) == {
        f.name for f in AirspaceZone.__dataclass_fields__.values()
    }
    assert set(schema["$defs"]["airspaceZone"]["properties"]["zone_type"]["enum"]) == {
        z.value for z in ZoneType
    }
    assert set(schema["$defs"]["airspaceZone"]["properties"]["severity"]["enum"]) == {
        s.value for s in Severity
    }
