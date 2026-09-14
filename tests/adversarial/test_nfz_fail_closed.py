"""Adversarial tests for the sovereign NFZ sync channel.

Master Plan Sec.6 requires chaos/fault-injection testing "for NFZ-feed
staleness/unavailability against ``check_airspace_clearance``'s fail-closed
behavior". These tests are that gate.

The governing invariant, stated once: **there is no input to this channel that
results in an affirmative clearance unless a validly signed, fresh, non-replayed
bulletin says the volume is clear.**
"""

from __future__ import annotations

import pytest
from tests.conftest import ADVISORY_AREA, AERODROME_AREA, CLEAR_AREA, NOTAM_AREA, square

from dronez.airspace.client import DenialReason, NfzChannelError
from dronez.airspace.mock_client import FaultMode, build_mock_channel
from dronez.safety.envelope import ENVELOPE

# Every fault except OVERSIZED, which gets its own test (it is slow to build).
TRANSPORT_FAULTS = [f for f in FaultMode if f not in (FaultMode.NONE, FaultMode.OVERSIZED)]


@pytest.mark.parametrize("fault", TRANSPORT_FAULTS, ids=lambda f: f.value)
def test_no_fault_mode_yields_an_affirmative_clearance(fault: FaultMode, clock) -> None:
    """The headline invariant, swept across every injected fault."""
    harness = build_mock_channel(clock=clock, fault=fault)
    try:
        harness.cache.sync(harness.channel)
    except NfzChannelError:
        pass  # rejection is the expected outcome for most faults

    decision = harness.clearance.check_clearance(square(*CLEAR_AREA), 30.0, 100.0)

    if fault is FaultMode.REPLAY:
        # A first bulletin cannot be a replay of anything; see the dedicated test
        # below for the case a replay can actually arise in.
        return
    assert not decision.cleared, f"fault {fault.value} produced an affirmative clearance"
    assert decision.reason is not DenialReason.CLEARED


def test_unsynced_cache_is_not_clear_airspace(clock) -> None:
    """An empty cache means "we do not know", which is not the same as "clear"."""
    harness = build_mock_channel(clock=clock)
    decision = harness.clearance.check_clearance(square(*CLEAR_AREA), 30.0, 100.0)
    assert not decision.cleared
    assert decision.reason is DenialReason.FEED_NEVER_SYNCED


def test_clearance_is_granted_only_for_a_genuinely_clear_volume(clock) -> None:
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    decision = harness.clearance.check_clearance(square(*CLEAR_AREA), 30.0, 100.0)
    assert decision.cleared
    assert decision.reason is DenialReason.CLEARED
    assert decision.blocking_zone_ids == ()
    assert decision.feed_sequence is not None


def test_blocking_zone_denies_and_names_the_zone(clock) -> None:
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    decision = harness.clearance.check_clearance(square(*AERODROME_AREA), 30.0, 100.0)
    assert not decision.cleared
    assert decision.reason is DenialReason.ZONE_CONFLICT
    assert "NFZ-AERODROME-TEST-01" in decision.blocking_zone_ids


def test_advisory_zone_is_surfaced_but_does_not_block(clock) -> None:
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    decision = harness.clearance.check_clearance(square(*ADVISORY_AREA), 30.0, 100.0)
    assert decision.cleared
    assert "NFZ-ADVISORY-TEST-05" in decision.advisory_zone_ids


def test_altitude_band_is_part_of_the_conflict_test(clock) -> None:
    """A restriction with a floor above the mission ceiling must not block it."""
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    # NFZ-TEMP-NOTAM-TEST-03 occupies 50-1500 m AGL.
    below = harness.clearance.check_clearance(square(*NOTAM_AREA), 20.0, 45.0)
    inside = harness.clearance.check_clearance(square(*NOTAM_AREA), 60.0, 100.0)
    assert below.cleared
    assert not inside.cleared
    assert "NFZ-TEMP-NOTAM-TEST-03" in inside.blocking_zone_ids


def test_stale_feed_denies_even_though_the_cache_holds_clear_data(clock) -> None:
    """Master Plan Sec.4: a cached snapshot is never authoritative past its window."""
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    assert harness.clearance.check_clearance(square(*CLEAR_AREA), 30.0, 100.0).cleared

    clock.advance(ENVELOPE.nfz_max_staleness_s + 1)

    decision = harness.clearance.check_clearance(square(*CLEAR_AREA), 30.0, 100.0)
    assert not decision.cleared
    assert decision.reason is DenialReason.FEED_STALE
    assert decision.feed_age_s > ENVELOPE.nfz_max_staleness_s


def test_freshness_boundary_is_inclusive(clock) -> None:
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    clock.advance(ENVELOPE.nfz_max_staleness_s)
    assert harness.cache.is_fresh(clock())
    clock.advance(0.001)
    assert not harness.cache.is_fresh(clock())


def test_replay_of_an_earlier_bulletin_is_rejected(clock) -> None:
    """Zero-Trust Sec.4.3: monotonic sequence defeats replay of a valid old bulletin."""
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    harness.cache.sync(harness.channel)
    accepted = harness.cache.state.last_sequence

    harness.channel.fault = FaultMode.REPLAY
    with pytest.raises(NfzChannelError, match="replay rejected"):
        harness.cache.sync(harness.channel)

    assert harness.cache.state.last_sequence == accepted


def test_tampered_bulletin_cannot_remove_a_restriction(clock) -> None:
    """The attack the signature exists to stop: silently dropping a blocking zone."""
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)

    harness.channel.fault = FaultMode.TAMPERED_BODY
    with pytest.raises(NfzChannelError, match="signature verification failed"):
        harness.cache.sync(harness.channel)

    decision = harness.clearance.check_clearance(square(*AERODROME_AREA), 30.0, 100.0)
    assert not decision.cleared
    assert "NFZ-AERODROME-TEST-01" in decision.blocking_zone_ids


def test_algorithm_downgrade_is_rejected_before_any_comparison(clock) -> None:
    """Zero-Trust Sec.1.1: 'none' and unlisted algorithms die before signature checking."""
    harness = build_mock_channel(clock=clock, fault=FaultMode.ALGORITHM_DOWNGRADE)
    with pytest.raises(NfzChannelError, match="not allow-listed"):
        harness.cache.sync(harness.channel)


def test_unknown_key_id_is_rejected(clock) -> None:
    harness = build_mock_channel(clock=clock, fault=FaultMode.UNKNOWN_KEY)
    with pytest.raises(NfzChannelError, match="unknown signing key_id"):
        harness.cache.sync(harness.channel)


def test_cross_authority_bulletin_is_rejected(clock) -> None:
    """A validly signed bulletin may not impersonate a different authority."""
    harness = build_mock_channel(clock=clock, fault=FaultMode.CROSS_AUTHORITY)
    with pytest.raises(NfzChannelError, match="cross-authority spoofing"):
        harness.cache.sync(harness.channel)


def test_expired_bulletin_is_rejected(clock) -> None:
    harness = build_mock_channel(clock=clock, fault=FaultMode.EXPIRED)
    with pytest.raises(NfzChannelError, match="expired"):
        harness.cache.sync(harness.channel)


def test_oversized_bulletin_is_refused_without_parsing(clock) -> None:
    """Resource-exhaustion guard: refuse to allocate for an implausible payload."""
    harness = build_mock_channel(clock=clock, fault=FaultMode.OVERSIZED)
    with pytest.raises(NfzChannelError, match="exceeds the"):
        harness.cache.sync(harness.channel)
    assert harness.cache.state.last_sync_utc is None


def test_rejected_bulletin_leaves_the_cache_untouched(clock) -> None:
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    before = harness.cache.state

    for fault in (FaultMode.BAD_SIGNATURE, FaultMode.MALFORMED_JSON, FaultMode.UNDECLARED_FIELD):
        harness.channel.fault = fault
        with pytest.raises(NfzChannelError):
            harness.cache.sync(harness.channel)

    after = harness.cache.state
    assert (after.last_sequence, after.zone_count) == (before.last_sequence, before.zone_count)
    assert after.consecutive_failures == 3


def test_feed_content_cannot_widen_the_safety_envelope(clock) -> None:
    """Zero-Trust Sec.4.2: retrieved content is data and may not alter the envelope."""
    harness = build_mock_channel(clock=clock, fault=FaultMode.UNDECLARED_FIELD)
    with pytest.raises(NfzChannelError, match="undeclared field"):
        harness.cache.sync(harness.channel)
    assert ENVELOPE.altitude_max_agl_m == 120.0


@pytest.mark.parametrize(
    "floor, ceiling, hint",
    [
        (30.0, 500.0, "exceeds"),
        (2.0, 100.0, "below"),
        (100.0, 100.0, "strictly below"),
        (100.0, 30.0, "strictly below"),
    ],
)
def test_envelope_violation_denies_before_the_feed_is_consulted(
    floor: float, ceiling: float, hint: str, clock
) -> None:
    """A plan outside the hard envelope is denied outright, never clipped to fit."""
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    decision = harness.clearance.check_clearance(square(*CLEAR_AREA), floor, ceiling)
    assert not decision.cleared
    assert decision.reason is DenialReason.ENVELOPE_VIOLATION
    assert hint in decision.detail


def test_clearance_expires_and_cannot_be_replayed_at_dispatch(clock) -> None:
    """A clearance minted early must not still be valid later."""
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    decision = harness.clearance.check_clearance(square(*CLEAR_AREA), 30.0, 100.0)
    assert decision.is_valid_at(clock())

    clock.advance(ENVELOPE.nfz_clearance_validity_s + 1)
    assert not decision.is_valid_at(clock())


def test_a_denial_carries_no_usable_validity_window(clock) -> None:
    harness = build_mock_channel(clock=clock)
    decision = harness.clearance.check_clearance(square(*CLEAR_AREA), 30.0, 100.0)
    assert not decision.is_valid_at(clock())
    assert decision.expires_utc == decision.evaluated_utc


def test_internal_error_becomes_a_denial_not_an_exception(clock) -> None:
    """An exception escaping into the dispatch path is the ambiguity Sec.0.1 forbids."""
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)

    class Exploding:
        def __getattr__(self, name: str):
            raise RuntimeError("boom")

    decision = harness.clearance.check_clearance(Exploding(), 30.0, 100.0)  # type: ignore[arg-type]
    assert not decision.cleared
    assert decision.reason is DenialReason.INTERNAL_ERROR


def test_audit_record_is_log_safe_and_complete(clock) -> None:
    """Master Plan Sec.5: rejected proposals are logged; the record must be structured."""
    harness = build_mock_channel(clock=clock)
    harness.cache.sync(harness.channel)
    decision = harness.clearance.check_clearance(square(*AERODROME_AREA), 30.0, 100.0)
    record = decision.to_audit_record()

    assert set(record) == {
        "cleared", "reason", "detail", "evaluated_utc", "expires_utc",
        "blocking_zone_ids", "advisory_zone_ids", "feed_authority",
        "feed_sequence", "feed_age_s",
    }
    assert record["cleared"] is False
    assert record["reason"] == "zone_conflict"
