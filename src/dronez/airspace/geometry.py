"""Conservative planar geometry for airspace containment tests.

Authority and limits
--------------------
PostGIS is the authoritative geometry engine from Milestone 1 (``ST_Intersects``,
``ST_Contains``, ``ST_IsValid``). This module exists so that Milestone 0 can test
the NFZ channel end-to-end without a database, and so the clearance logic can be
fuzzed as a pure function.

Every predicate here is **conservative in the safe direction**: where a result is
uncertain, it reports the answer that leads to *denial*, never the one that leads
to dispatch. Specifically :func:`polygons_intersect` may return ``True`` for
geometries that a full planar-sweep implementation would separate, and must never
return ``False`` for geometries that genuinely overlap.

Known simplifications, all of which are recorded as open items in ``CLAUDE.md``:

* Coordinates are treated as planar degrees. Over an incident zone of a few
  kilometres the distortion is far smaller than :data:`~dronez.safety.envelope.
  SafetyEnvelope.geofence_soft_buffer_m`, but this is **not** valid at scale and
  is not used for distance computation.
* Polygon holes are ignored for intersection: a mission overlapping the hole of a
  restricted zone is reported as intersecting. That is the conservative answer.
* Self-intersecting rings are not detected here; PostGIS ``ST_IsValid`` is the
  gate for that at Milestone 1.
"""

from __future__ import annotations

from collections.abc import Sequence

from dronez.airspace.schema import Polygon

__all__ = ["altitude_bands_overlap", "point_in_ring", "polygons_intersect", "segments_intersect"]

Position = tuple[float, float]


def point_in_ring(point: Position, ring: Sequence[Position]) -> bool:
    """Ray-casting point-in-polygon. Points exactly on an edge count as inside.

    Treating the boundary as inside is the conservative choice: a mission whose
    corner grazes the edge of a prohibited zone is treated as entering it.
    """
    px, py = point
    inside = False
    n = len(ring)
    for i in range(n - 1):
        x1, y1 = ring[i]
        x2, y2 = ring[i + 1]

        # On-edge test (collinear and within the segment's bounding box).
        cross = (x2 - x1) * (py - y1) - (y2 - y1) * (px - x1)
        if abs(cross) < 1e-12 and min(x1, x2) - 1e-12 <= px <= max(x1, x2) + 1e-12 \
                and min(y1, y2) - 1e-12 <= py <= max(y1, y2) + 1e-12:
            return True

        if (y1 > py) != (y2 > py):
            x_at = x1 + (py - y1) * (x2 - x1) / (y2 - y1)
            if px < x_at:
                inside = not inside
    return inside


def segments_intersect(a1: Position, a2: Position, b1: Position, b2: Position) -> bool:
    """True when closed segments ``a1a2`` and ``b1b2`` share at least one point."""

    def orient(p: Position, q: Position, r: Position) -> int:
        val = (q[0] - p[0]) * (r[1] - p[1]) - (q[1] - p[1]) * (r[0] - p[0])
        if abs(val) < 1e-15:
            return 0
        return 1 if val > 0 else -1

    def on_segment(p: Position, q: Position, r: Position) -> bool:
        return (
            min(p[0], r[0]) - 1e-12 <= q[0] <= max(p[0], r[0]) + 1e-12
            and min(p[1], r[1]) - 1e-12 <= q[1] <= max(p[1], r[1]) + 1e-12
        )

    o1, o2 = orient(a1, a2, b1), orient(a1, a2, b2)
    o3, o4 = orient(b1, b2, a1), orient(b1, b2, a2)

    if o1 != o2 and o3 != o4:
        return True
    if o1 == 0 and on_segment(a1, b1, a2):
        return True
    if o2 == 0 and on_segment(a1, b2, a2):
        return True
    if o3 == 0 and on_segment(b1, a1, b2):
        return True
    if o4 == 0 and on_segment(b1, a2, b2):
        return True
    return False


def _bbox(ring: Sequence[Position]) -> tuple[float, float, float, float]:
    xs = [p[0] for p in ring]
    ys = [p[1] for p in ring]
    return min(xs), min(ys), max(xs), max(ys)


def polygons_intersect(a: Polygon, b: Polygon) -> bool:
    """Conservative overlap test between two polygons' exterior rings.

    Returns ``True`` if the exteriors share any area or boundary point. Holes are
    deliberately ignored (see module docstring).
    """
    ring_a, ring_b = a.exterior, b.exterior

    # Cheap rejection first; a bounding-box miss is a definitive non-overlap.
    ax0, ay0, ax1, ay1 = _bbox(ring_a)
    bx0, by0, bx1, by1 = _bbox(ring_b)
    if ax1 < bx0 or bx1 < ax0 or ay1 < by0 or by1 < ay0:
        return False

    # Any edge crossing means the boundaries meet.
    for i in range(len(ring_a) - 1):
        for j in range(len(ring_b) - 1):
            if segments_intersect(ring_a[i], ring_a[i + 1], ring_b[j], ring_b[j + 1]):
                return True

    # No crossings: either disjoint, or one polygon lies wholly inside the other.
    return point_in_ring(ring_a[0], ring_b) or point_in_ring(ring_b[0], ring_a)


def altitude_bands_overlap(
    floor_a: float, ceiling_a: float, floor_b: float, ceiling_b: float
) -> bool:
    """True when two closed altitude bands share any altitude.

    Bands are closed at both ends: a mission ceiling that exactly touches a zone
    floor counts as overlapping, again resolving the ambiguous case toward denial.
    """
    return floor_a <= ceiling_b and floor_b <= ceiling_a
