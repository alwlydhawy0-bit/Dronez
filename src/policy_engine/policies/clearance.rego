# Sovereign airspace clearance validation.
#
# The MCP server obtains a clearance decision from the NFZ channel and passes it in.
# This package does NOT trust the `cleared` boolean on its own: a compromised server
# could set it. Instead every structural property of the clearance is re-checked here
# -- that it is affirmative, unexpired, derived from fresh feed data, free of blocking
# zones, and BOUND TO THE VOLUME ACTUALLY BEING REQUESTED.
#
# That last property is the one most easily missed. Without it, a clearance legitimately
# obtained for an empty patch of desert could be presented against a mission over an
# aerodrome.

package dronez.authz.clearance

import rego.v1

import data.dronez.geometry
import data.dronez.safety_envelope.constants as envelope

ns_per_s := 1000000000

now_ns := time.parse_rfc3339_ns(input.now)

# --- structural validity ---------------------------------------------------

present if {
	is_object(input.clearance)
}

affirmative if {
	input.clearance.cleared == true
}

no_blocking_zones if {
	count(object.get(input.clearance, "blocking_zone_ids", [])) == 0
}

unexpired if {
	expires_ns := time.parse_rfc3339_ns(input.clearance.expires_utc)
	now_ns < expires_ns
}

# The clearance must not predate the feed's freshness window, independent of the
# expiry the server stamped on it.
derived_from_fresh_feed if {
	age := object.get(input.clearance, "feed_age_s", null)
	is_number(age)
	age <= envelope.nfz_max_staleness_s
}

# --- binding to the requested volume ---------------------------------------

# The cleared volume must cover the requested one. Equality is too brittle (a server
# may legitimately clear a slightly larger envelope), so containment is the test --
# and containment is evaluated here from raw coordinates, not asserted by the caller.
covers_requested_polygon if {
	geometry.polygon_contains(input.clearance.polygon, input.request.polygon)
}

covers_requested_altitude if {
	input.clearance.altitude_min_m_agl <= input.request.altitude_min_m_agl
	input.clearance.altitude_max_m_agl >= input.request.altitude_max_m_agl
}

# --- the single affirmative predicate --------------------------------------

valid if {
	present
	affirmative
	no_blocking_zones
	unexpired
	derived_from_fresh_feed
	covers_requested_polygon
	covers_requested_altitude
}
