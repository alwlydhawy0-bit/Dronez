# Run with:  opa test src/policy_engine/policies/
package dronez.geometry_test

import rego.v1

import data.dronez.geometry

# A 10x10 square with its lower-left corner at the origin.
square := [[[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]]]

# An L-shaped (non-convex) boundary. The notch is the top-right quadrant.
l_shape := [[[0, 0], [10, 0], [10, 5], [5, 5], [5, 10], [0, 10], [0, 0]]]

# A square with a square hole in the middle.
donut := [
	[[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]],
	[[4, 4], [6, 4], [6, 6], [4, 6], [4, 4]],
]

small := [[[2, 2], [3, 2], [3, 3], [2, 3], [2, 2]]]

# --- point containment ------------------------------------------------------

test_point_strictly_inside if {
	geometry.point_in_polygon([5, 5], square)
}

test_point_outside if {
	not geometry.point_in_polygon([15, 5], square)
}

# A point on the boundary counts as inside: ambiguity resolves toward "this point is
# within the restriction", which is the conservative reading in both directions.
test_point_on_edge_counts_as_inside if {
	geometry.point_in_polygon([0, 5], square)
}

test_point_on_vertex_counts_as_inside if {
	geometry.point_in_polygon([0, 0], square)
}

test_point_in_hole_is_outside_polygon if {
	not geometry.point_in_polygon([5, 5], donut)
}

test_point_in_donut_body_is_inside if {
	geometry.point_in_polygon([1, 1], donut)
}

# --- containment ------------------------------------------------------------

test_small_square_contained if {
	geometry.polygon_contains(square, small)
}

test_larger_square_not_contained if {
	not geometry.polygon_contains(small, square)
}

test_partially_overlapping_not_contained if {
	straddling := [[[8, 8], [12, 8], [12, 12], [8, 12], [8, 8]]]
	not geometry.polygon_contains(square, straddling)
}

test_disjoint_not_contained if {
	far := [[[100, 100], [101, 100], [101, 101], [100, 101], [100, 100]]]
	not geometry.polygon_contains(square, far)
}

test_identical_polygon_is_contained if {
	geometry.polygon_contains(square, square)
}

# THE non-convexity case. Both vertices of the spanning polygon sit inside the L, but
# the segment between them crosses the notch. A vertices-only test would wrongly
# report containment here; the edge-crossing check is what catches it.
test_polygon_spanning_a_notch_is_not_contained if {
	spanning := [[[1, 1], [9, 1], [9, 4], [6, 8], [1, 8], [1, 1]]]
	not geometry.polygon_contains(l_shape, spanning)
}

test_polygon_inside_the_l_arm_is_contained if {
	in_arm := [[[1, 1], [4, 1], [4, 4], [1, 4], [1, 1]]]
	geometry.polygon_contains(l_shape, in_arm)
}

# --- intersection -----------------------------------------------------------

test_overlapping_polygons_intersect if {
	straddling := [[[8, 8], [12, 8], [12, 12], [8, 12], [8, 8]]]
	geometry.polygons_intersect(square, straddling)
}

test_disjoint_polygons_do_not_intersect if {
	far := [[[100, 100], [101, 100], [101, 101], [100, 101], [100, 100]]]
	not geometry.polygons_intersect(square, far)
}

test_touching_polygons_intersect if {
	touching := [[[10, 4], [14, 4], [14, 6], [10, 6], [10, 4]]]
	geometry.polygons_intersect(square, touching)
}

test_contained_polygon_intersects if {
	geometry.polygons_intersect(square, small)
}

# --- altitude bands ---------------------------------------------------------

test_overlapping_bands if {
	geometry.altitude_bands_overlap(30, 100, 50, 150)
}

test_disjoint_bands if {
	not geometry.altitude_bands_overlap(20, 45, 50, 150)
}

test_touching_bands_overlap if {
	geometry.altitude_bands_overlap(20, 50, 50, 150)
}
