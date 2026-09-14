# Planar geometry primitives for containment decisions.
#
# Why the policy engine does its own geometry
# -------------------------------------------
# The obvious alternative is for the MCP server to compute containment (in PostGIS)
# and pass OPA a boolean like `{"contained": true}`. That is rejected: a policy gate
# that accepts a precomputed verdict from the component it is gating is not a gate.
# A compromised or defective server would simply assert containment. So the geometry
# is evaluated here, from raw coordinates, by code the server cannot influence.
#
# Conservative by construction
# ----------------------------
# Every predicate resolves ambiguity toward DENIAL:
#   * A point exactly on a boundary counts as inside that boundary. A mission corner
#     grazing the incident-zone edge is "inside" (permissive for the zone we must be
#     inside), and a corner grazing a no-fly edge is "inside" it too (restrictive for
#     the zone we must avoid).
#   * Containment requires BOTH all-vertices-inside AND no-edge-crossing, so a
#     non-convex zone cannot be exited and re-entered between vertices.
#   * Holes are subtracted: a point inside a hole of the boundary is outside it.
#
# Coordinates are treated as planar degrees. Over an incident zone of a few kilometres
# the distortion is far below the geofence buffer, and no distance is computed here.
# Recorded as TM-06.

package dronez.geometry

import rego.v1

# Adjacent vertex pairs of a closed ring, as [from, to] segments.
edges(ring) := [[ring[i], ring[j]] |
	some i
	ring[i]
	j := i + 1
	ring[j]
]

# Twice the signed area of triangle (p, q, r). Positive means counter-clockwise.
cross_product(p, q, r) := ((q[0] - p[0]) * (r[1] - p[1])) - ((q[1] - p[1]) * (r[0] - p[0]))

# Orientation as -1 / 0 / +1, with an epsilon so near-collinear points are treated as
# collinear rather than producing a spurious crossing from floating-point noise.
orientation(p, q, r) := 1 if {
	cross_product(p, q, r) > 1e-15
}

orientation(p, q, r) := -1 if {
	cross_product(p, q, r) < -1e-15
}

orientation(p, q, r) := 0 if {
	abs(cross_product(p, q, r)) <= 1e-15
}

# True when `point` lies on the closed segment p1-p2.
point_on_segment(point, p1, p2) if {
	orientation(p1, p2, point) == 0
	point[0] >= min([p1[0], p2[0]]) - 1e-12
	point[0] <= max([p1[0], p2[0]]) + 1e-12
	point[1] >= min([p1[1], p2[1]]) - 1e-12
	point[1] <= max([p1[1], p2[1]]) + 1e-12
}

point_on_ring(point, ring) if {
	some edge in edges(ring)
	point_on_segment(point, edge[0], edge[1])
}

# Ray-casting crossing count for a horizontal ray extending in -x from `point`.
crossings(point, ring) := count([1 |
	some edge in edges(ring)
	p1 := edge[0]
	p2 := edge[1]

	# The edge spans the point's latitude (half-open, so a shared vertex is counted once).
	(p1[1] > point[1]) != (p2[1] > point[1])

	x_at := p1[0] + (((point[1] - p1[1]) * (p2[0] - p1[0])) / (p2[1] - p1[1]))
	point[0] < x_at
])

# Strictly inside a single ring, boundary excluded.
point_strictly_in_ring(point, ring) if {
	crossings(point, ring) % 2 == 1
}

# Inside a ring including its boundary.
point_in_ring(point, ring) if {
	point_on_ring(point, ring)
}

point_in_ring(point, ring) if {
	point_strictly_in_ring(point, ring)
}

# `polygon` is [exterior_ring, hole_ring, ...].
point_in_hole(point, polygon) if {
	some i
	i > 0
	polygon[i]
	point_strictly_in_ring(point, polygon[i])
}

# Inside the polygon: within the exterior ring and not strictly inside any hole.
point_in_polygon(point, polygon) if {
	point_in_ring(point, polygon[0])
	not point_in_hole(point, polygon)
}

# Two segments cross at an interior point of both. Touching endpoints do NOT count,
# so an inner polygon may legitimately share a boundary point with the outer one.
segments_properly_intersect(a1, a2, b1, b2) if {
	o1 := orientation(a1, a2, b1)
	o2 := orientation(a1, a2, b2)
	o3 := orientation(b1, b2, a1)
	o4 := orientation(b1, b2, a2)

	o1 != 0
	o2 != 0
	o3 != 0
	o4 != 0
	o1 != o2
	o3 != o4
}

# Any edge of `inner` properly crosses any ring of `outer`.
edges_cross(outer, inner) if {
	some outer_ring in outer
	some outer_edge in edges(outer_ring)
	some inner_edge in edges(inner[0])
	segments_properly_intersect(
		outer_edge[0], outer_edge[1],
		inner_edge[0], inner_edge[1],
	)
}

# THE containment predicate: is `inner` wholly within `outer`?
#
# Both conditions are required. All-vertices-inside alone is insufficient for a
# non-convex outer boundary, where an edge can leave and re-enter between two
# vertices that are both inside.
polygon_contains(outer, inner) if {
	every vertex in inner[0] {
		point_in_polygon(vertex, outer)
	}

	not edges_cross(outer, inner)
}

# Do two polygons share any area or boundary point? Used against no-fly volumes,
# where ANY overlap is disqualifying.
polygons_intersect(a, b) if {
	some vertex in a[0]
	point_in_ring(vertex, b[0])
}

polygons_intersect(a, b) if {
	some vertex in b[0]
	point_in_ring(vertex, a[0])
}

polygons_intersect(a, b) if {
	some edge_a in edges(a[0])
	some edge_b in edges(b[0])
	segments_properly_intersect(edge_a[0], edge_a[1], edge_b[0], edge_b[1])
}

# Closed altitude bands overlap. Closed at both ends: a mission ceiling exactly
# touching a restriction floor counts as overlapping.
altitude_bands_overlap(floor_a, ceiling_a, floor_b, ceiling_b) if {
	floor_a <= ceiling_b
	floor_b <= ceiling_a
}
