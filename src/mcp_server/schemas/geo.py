"""Geospatial boundary types shared by every tool that describes a volume.

These mirror the constraints already enforced on the sovereign NFZ feed
(:mod:`dronez.airspace.schema`) so that operator-supplied and
authority-supplied geometry are held to the same standard. An operator is not
more trusted than a signed government feed where malformed input is concerned.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from dronez.airspace.schema import Polygon as CorePolygon
from dronez.airspace.schema import SchemaValidationError
from mcp_server.schemas.base import StrictModel

__all__ = ["MAX_RING_POSITIONS", "GeoPolygon", "Latitude", "Longitude", "Position"]

#: Bound on ring size. A recon polygon needs tens of vertices; thousands indicates
#: either a defect or an attempt to make containment checking expensive.
MAX_RING_POSITIONS = 512
MAX_RINGS = 8

Longitude = Annotated[float, Field(ge=-180.0, le=180.0)]
Latitude = Annotated[float, Field(ge=-90.0, le=90.0)]

#: WGS-84 ``[longitude, latitude]``. Altitude is never carried per-position -- it
#: belongs to the request's altitude band, so there is exactly one place to bound it.
Position = Annotated[tuple[Longitude, Latitude], Field()]


class GeoPolygon(StrictModel):
    """A GeoJSON Polygon, validated closed and non-degenerate.

    ``coordinates[0]`` is the exterior ring; further rings are holes. Rings are
    explicitly closed (first position equals last).

    Self-intersection is **not** checked here. PostGIS ``ST_IsValid`` is the
    authority at the persistence boundary, and the policy engine's containment test
    is conservative, so an invalid ring resolves toward denial rather than toward a
    false "contained" result.
    """

    type: Literal["Polygon"] = "Polygon"
    coordinates: Annotated[
        list[Annotated[list[Position], Field(min_length=4, max_length=MAX_RING_POSITIONS)]],
        Field(min_length=1, max_length=MAX_RINGS),
    ]

    @model_validator(mode="after")
    def _rings_are_closed_and_enclose_area(self) -> Self:
        for index, ring in enumerate(self.coordinates):
            if ring[0] != ring[-1]:
                raise ValueError(
                    f"coordinates[{index}]: ring must be explicitly closed "
                    "(first position == last position)"
                )
            if len({tuple(position) for position in ring[:-1]}) < 3:
                raise ValueError(
                    f"coordinates[{index}]: ring must enclose an area "
                    "(needs at least 3 distinct positions)"
                )
        return self

    def to_core(self) -> CorePolygon:
        """Convert to the stdlib polygon used by the airspace clearance path.

        Keeps one geometry implementation behind the clearance check rather than
        two subtly different ones.
        """
        try:
            return CorePolygon.parse(self.model_dump(mode="python"), "polygon")
        except SchemaValidationError as exc:  # pragma: no cover - defence in depth
            raise ValueError(str(exc)) from exc

    def as_rings(self) -> list[list[list[float]]]:
        """Plain nested lists, the shape the Rego policies consume."""
        return [[[p[0], p[1]] for p in ring] for ring in self.coordinates]

    @classmethod
    def from_rings(cls, rings: list[list[list[float]]]) -> GeoPolygon:
        return cls(coordinates=[[(p[0], p[1]) for p in ring] for ring in rings])

    def __len__(self) -> int:
        return len(self.coordinates[0])

    def bounding_box(self) -> tuple[float, float, float, float]:
        """``(min_lon, min_lat, max_lon, max_lat)`` over the exterior ring."""
        ring: Any = self.coordinates[0]
        lons = [p[0] for p in ring]
        lats = [p[1] for p in ring]
        return min(lons), min(lats), max(lons), max(lats)
