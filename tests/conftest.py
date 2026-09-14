"""Shared fixtures. Adds ``src/`` to the path so tests run without an install step."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dronez.airspace.schema import Polygon  # noqa: E402

#: Fixed instant so every geometry and time-window assertion is deterministic.
T0 = datetime(2026, 1, 15, 9, 0, 0, tzinfo=UTC)


@pytest.fixture
def clock():
    """Mutable test clock. ``clock.advance(seconds)`` moves time forward."""

    class Clock:
        def __init__(self) -> None:
            self.now = T0

        def __call__(self) -> datetime:
            return self.now

        def advance(self, seconds: float) -> None:
            from datetime import timedelta

            self.now += timedelta(seconds=seconds)

    return Clock()


def square(lon: float, lat: float, half_deg: float) -> Polygon:
    """Axis-aligned test polygon centred on ``(lon, lat)``."""
    return Polygon.parse(
        {
            "type": "Polygon",
            "coordinates": [[
                [lon - half_deg, lat - half_deg],
                [lon + half_deg, lat - half_deg],
                [lon + half_deg, lat + half_deg],
                [lon - half_deg, lat + half_deg],
                [lon - half_deg, lat - half_deg],
            ]],
        },
        "test",
    )


#: Well clear of every zone in ``dronez.airspace.mock_client.sample_zones``.
CLEAR_AREA = (46.60, 24.60, 0.002)
#: Inside NFZ-AERODROME-TEST-01.
AERODROME_AREA = (46.70, 24.70, 0.002)
#: Inside NFZ-ADVISORY-TEST-05 only.
ADVISORY_AREA = (46.75, 24.75, 0.002)
#: Inside NFZ-TEMP-NOTAM-TEST-03 (altitude band 50-1500 m AGL).
NOTAM_AREA = (46.90, 24.90, 0.002)
