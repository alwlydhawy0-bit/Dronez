# Run with:  opa test src/policy_engine/policies/
#
# The governing invariant swept below: `valid` is true only when EVERY structural
# property holds. The `cleared` boolean alone never carries the decision -- a
# compromised server that sets it must still fail on expiry, freshness, blocking
# zones, and volume binding.
package dronez.authz.clearance_test

import rego.v1

import data.dronez.authz.clearance as policy

now := "2026-01-15T10:00:00Z"

# The cleared volume, deliberately larger than the requested one.
cleared_polygon := [[[46.0, 24.0], [47.0, 24.0], [47.0, 25.0], [46.0, 25.0], [46.0, 24.0]]]

requested_polygon := [[[46.4, 24.4], [46.6, 24.4], [46.6, 24.6], [46.4, 24.6], [46.4, 24.4]]]

# Disjoint from the cleared volume -- the "desert clearance, aerodrome mission" case.
elsewhere_polygon := [[[10.0, 10.0], [10.2, 10.0], [10.2, 10.2], [10.0, 10.2], [10.0, 10.0]]]

base_request := {
	"polygon": requested_polygon,
	"altitude_min_m_agl": 30,
	"altitude_max_m_agl": 100,
}

base_clearance := {
	"cleared": true,
	"evaluated_utc": "2026-01-15T09:59:00Z",
	"expires_utc": "2026-01-15T10:01:00Z",
	"blocking_zone_ids": [],
	"advisory_zone_ids": [],
	"feed_age_s": 42,
	"polygon": cleared_polygon,
	"altitude_min_m_agl": 0,
	"altitude_max_m_agl": 120,
}

base_input := {
	"now": now,
	"request": base_request,
	"clearance": base_clearance,
}

with_clearance(patch) := object.union(base_input, {"clearance": object.union(base_clearance, patch)})

with_request(patch) := object.union(base_input, {"request": object.union(base_request, patch)})

# --- the happy path ---------------------------------------------------------

test_a_complete_affirmative_clearance_is_valid if {
	policy.valid with input as base_input
}

# --- presence ---------------------------------------------------------------

test_missing_clearance_is_not_valid if {
	not policy.valid with input as object.remove(base_input, ["clearance"])
}

test_null_clearance_is_not_valid if {
	not policy.valid with input as object.union(base_input, {"clearance": null})
}

test_non_object_clearance_is_not_valid if {
	not policy.valid with input as object.union(base_input, {"clearance": "cleared"})
}

test_empty_object_clearance_is_not_valid if {
	not policy.valid with input as object.union(base_input, {"clearance": {}})
}

# --- the affirmative flag is necessary but never sufficient ------------------

test_negative_clearance_is_not_valid if {
	not policy.valid with input as with_clearance({"cleared": false})
}

test_missing_cleared_flag_is_not_valid if {
	not policy.valid with input as object.union(
		base_input,
		{"clearance": object.remove(base_clearance, ["cleared"])},
	)
}

# A truthy-but-not-true value must not pass. `cleared == true` is an identity check,
# not a coercion, so a feed or a caller cannot smuggle a clearance through with a
# string or a non-zero number.
test_truthy_string_is_not_affirmative if {
	not policy.valid with input as with_clearance({"cleared": "true"})
}

test_truthy_number_is_not_affirmative if {
	not policy.valid with input as with_clearance({"cleared": 1})
}

# --- blocking zones ---------------------------------------------------------

test_a_blocking_zone_invalidates_the_clearance if {
	not policy.valid with input as with_clearance({"blocking_zone_ids": ["NFZ-AERODROME-01"]})
}

test_several_blocking_zones_invalidate_the_clearance if {
	not policy.valid with input as with_clearance({"blocking_zone_ids": ["NFZ-1", "NFZ-2"]})
}

# Advisory zones are surfaced to the operator but do not block -- that distinction is
# the whole reason the two lists are separate fields.
test_advisory_zones_do_not_block if {
	policy.valid with input as with_clearance({"advisory_zone_ids": ["ADV-BIRD-HAZARD"]})
}

# A clearance that is affirmative AND names a blocking zone is self-contradictory.
# It must fail, not resolve in favour of the boolean.
test_affirmative_with_a_blocking_zone_still_fails if {
	not policy.valid with input as with_clearance({
		"cleared": true,
		"blocking_zone_ids": ["NFZ-1"],
	})
}

# --- expiry: a decision cannot be minted early and replayed ------------------

test_expired_clearance_is_not_valid if {
	not policy.valid with input as with_clearance({"expires_utc": "2026-01-15T09:59:59Z"})
}

test_clearance_expiring_exactly_now_is_not_valid if {
	not policy.valid with input as with_clearance({"expires_utc": now})
}

test_clearance_expiring_one_second_out_is_valid if {
	policy.valid with input as with_clearance({"expires_utc": "2026-01-15T10:00:01Z"})
}

# --- freshness, checked independently of the server's stamped expiry ---------

# The attack this closes: a server stamps a long expiry on a decision derived from a
# stale cache. The expiry looks fine; the underlying data does not.
test_stale_feed_invalidates_an_unexpired_clearance if {
	not policy.valid with input as with_clearance({
		"feed_age_s": 301,
		"expires_utc": "2026-01-15T11:00:00Z",
	})
}

test_feed_age_at_the_staleness_limit_is_valid if {
	policy.valid with input as with_clearance({"feed_age_s": 300})
}

test_feed_age_one_second_past_the_limit_is_not_valid if {
	not policy.valid with input as with_clearance({"feed_age_s": 301})
}

test_missing_feed_age_is_not_valid if {
	not policy.valid with input as object.union(
		base_input,
		{"clearance": object.remove(base_clearance, ["feed_age_s"])},
	)
}

test_null_feed_age_is_not_valid if {
	not policy.valid with input as with_clearance({"feed_age_s": null})
}

# "unknown age" is not "fresh". A non-numeric age must fail rather than compare.
test_non_numeric_feed_age_is_not_valid if {
	not policy.valid with input as with_clearance({"feed_age_s": "fresh"})
}

# --- volume binding: the property most easily missed ------------------------

test_clearance_for_a_different_polygon_is_not_valid if {
	not policy.valid with input as with_clearance({"polygon": elsewhere_polygon})
}

test_clearance_not_covering_the_whole_requested_polygon_is_not_valid if {
	not policy.valid with input as with_clearance({"polygon": [[
		[46.5, 24.5],
		[46.6, 24.5],
		[46.6, 24.6],
		[46.5, 24.6],
		[46.5, 24.5],
	]]})
}

test_a_larger_cleared_polygon_is_accepted if {
	policy.valid with input as with_clearance({"polygon": [[
		[40.0, 20.0],
		[50.0, 20.0],
		[50.0, 30.0],
		[40.0, 30.0],
		[40.0, 20.0],
	]]})
}

test_clearance_ceiling_below_the_request_is_not_valid if {
	not policy.valid with input as with_clearance({"altitude_max_m_agl": 90})
}

test_clearance_floor_above_the_request_is_not_valid if {
	not policy.valid with input as with_clearance({"altitude_min_m_agl": 40})
}

test_exactly_matching_altitude_band_is_valid if {
	policy.valid with input as with_clearance({
		"altitude_min_m_agl": 30,
		"altitude_max_m_agl": 100,
	})
}

# Raising the request after the clearance was minted must invalidate it -- otherwise
# a legitimate low-altitude clearance authorizes a high-altitude flight.
test_raising_the_requested_ceiling_invalidates_the_clearance if {
	not policy.valid with input as with_request({"altitude_max_m_agl": 121})
}

test_widening_the_requested_polygon_invalidates_the_clearance if {
	not policy.valid with input as with_request({"polygon": elsewhere_polygon})
}

# --- no single property is sufficient on its own ----------------------------

# Everything wrong except the flag. This is the compromised-server case stated
# directly: `cleared: true` buys nothing by itself.
test_affirmative_flag_alone_authorizes_nothing if {
	not policy.valid with input as object.union(base_input, {"clearance": {
		"cleared": true,
		"blocking_zone_ids": ["NFZ-1"],
		"expires_utc": "2020-01-01T00:00:00Z",
		"feed_age_s": 99999,
		"polygon": elsewhere_polygon,
		"altitude_min_m_agl": 100,
		"altitude_max_m_agl": 101,
	}})
}
