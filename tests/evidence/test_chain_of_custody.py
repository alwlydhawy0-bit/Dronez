"""Tamper-evidence of the chain of custody, and the write-once store.

The claim being tested is narrow and specific: an artifact that was **altered, deleted,
reordered or inserted** after capture is detectable. Per-artifact hashing alone proves
only the first of those, which is why the records are chained.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from dronez.evidence import (
    GENESIS_CHAIN_HASH,
    ArtifactKind,
    BreakKind,
    ChainOfCustodyRecord,
    CollectingSystem,
    CommitRefused,
    InMemoryWormStore,
    RetentionMode,
    RetentionPolicy,
    WormSink,
    compute_chain_hash,
    verify_chain,
)

T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
SYSTEM = CollectingSystem(
    device_id="jetson-orin-nx-01",
    device_type="jetson-orin-nx",
    firmware_digest="a" * 64,
    drone_id="D-1",
)


def make_chain(count: int, *, stream_id: str = "S-1") -> list[ChainOfCustodyRecord]:
    records: list[ChainOfCustodyRecord] = []
    previous = GENESIS_CHAIN_HASH
    for i in range(count):
        digest = f"{i:064x}"
        captured = T0 + timedelta(seconds=i)
        chain_hash = compute_chain_hash(
            previous_chain_hash=previous,
            stream_id=stream_id,
            sequence=i,
            kind=ArtifactKind.THERMAL_FRAME,
            artifact_sha256=digest,
            artifact_bytes=1024,
            captured_utc=captured,
            collecting_system=SYSTEM,
        )
        records.append(
            ChainOfCustodyRecord(
                # Record ids are globally unique, not per-stream: the store keys on
                # them, and a collision across streams is a genuine WORM refusal.
                record_id=f"coc-{stream_id}-{i:04d}",
                stream_id=stream_id,
                sequence=i,
                kind=ArtifactKind.THERMAL_FRAME,
                artifact_sha256=digest,
                artifact_bytes=1024,
                captured_utc=captured,
                collecting_system=SYSTEM,
                previous_chain_hash=previous,
                chain_hash=chain_hash,
            )
        )
        previous = chain_hash
    return records


# --------------------------------------------------------------------------- #
# Chain verification
# --------------------------------------------------------------------------- #

def test_intact_chain_verifies() -> None:
    result = verify_chain(make_chain(20))
    assert result.intact
    assert result.records_checked == 20
    assert result.head_chain_hash == make_chain(20)[-1].chain_hash


def test_altered_artifact_is_detected() -> None:
    """The case per-artifact hashing already covered."""
    records = make_chain(10)
    records[4] = replace(records[4], artifact_sha256="f" * 64)
    result = verify_chain(records)
    assert not result.intact
    assert BreakKind.ALTERED_RECORD in {b.kind for b in result.breaks}


def test_deleted_records_are_detected(caplog: pytest.LogCaptureFixture) -> None:
    """The case per-artifact hashing does NOT cover.

    An attacker who removes a span of footage leaves every remaining hash valid. Only
    the linkage shows the gap.
    """
    records = make_chain(10)
    del records[4:7]
    result = verify_chain(records)
    assert not result.intact
    kinds = {b.kind for b in result.breaks}
    assert BreakKind.SEQUENCE_GAP in kinds
    assert BreakKind.BROKEN_LINK in kinds

    gap = next(b for b in result.breaks if b.kind is BreakKind.SEQUENCE_GAP)
    assert "3 record(s) are missing" in gap.detail


def test_truncated_tail_is_detected_against_a_known_head() -> None:
    """Truncation needs an external anchor -- the sealed head -- to detect.

    A truncated chain is internally consistent: nothing in it points forward. This is
    why segments are sealed and the seal recorded, and why an auditor compares against
    the sealed head rather than merely verifying the records in hand.
    """
    full = make_chain(10)
    truncated = full[:6]
    assert verify_chain(truncated).intact, "truncation is internally undetectable"
    assert verify_chain(truncated).head_chain_hash != full[-1].chain_hash


def test_reordered_records_are_detected() -> None:
    records = make_chain(10)
    records[3], records[6] = records[6], records[3]
    result = verify_chain(records)
    assert not result.intact
    assert BreakKind.OUT_OF_ORDER in {b.kind for b in result.breaks}


def test_inserted_record_is_detected() -> None:
    """A forged frame spliced into the middle breaks the link at the splice."""
    records = make_chain(10)
    forged = replace(records[5], record_id="coc-S-1-forged", artifact_sha256="e" * 64)
    forged = replace(forged, chain_hash=forged.recompute_chain_hash())
    records.insert(5, forged)
    result = verify_chain(records)
    assert not result.intact


def test_missing_genesis_is_detected() -> None:
    records = make_chain(10)[3:]
    result = verify_chain(records)
    assert BreakKind.MISSING_GENESIS in {b.kind for b in result.breaks}


def test_backwards_capture_time_is_detected() -> None:
    records = make_chain(5)
    tampered = replace(records[3], captured_utc=T0 - timedelta(hours=1))
    records[3] = replace(tampered, chain_hash=tampered.recompute_chain_hash())
    result = verify_chain(records)
    assert BreakKind.TIME_TRAVEL in {b.kind for b in result.breaks}


def test_every_break_is_reported_not_just_the_first() -> None:
    """An investigator needs the extent of a manipulation, not its earliest point."""
    records = make_chain(20)
    records[4] = replace(records[4], artifact_sha256="1" * 64)
    records[9] = replace(records[9], artifact_sha256="2" * 64)
    result = verify_chain(records)
    altered = [b for b in result.breaks if b.kind is BreakKind.ALTERED_RECORD]
    assert len(altered) == 2


def test_empty_chain_verifies_but_reports_nothing_checked() -> None:
    """"No records" and "records that verify" are different claims."""
    result = verify_chain([])
    assert result.intact
    assert result.records_checked == 0


def test_collecting_system_is_inside_the_hash() -> None:
    """An evidentiary claim that cannot name the hardware that produced it is weaker."""
    records = make_chain(3)
    relabelled = replace(
        records[1], collecting_system=replace(SYSTEM, device_id="some-other-device")
    )
    assert not relabelled.is_self_consistent()


def test_records_reject_malformed_digests() -> None:
    with pytest.raises(ValueError, match="64-character hex digest"):
        ChainOfCustodyRecord(
            record_id="x", stream_id="S-1", sequence=0,
            kind=ArtifactKind.THERMAL_FRAME, artifact_sha256="short",
            artifact_bytes=1, captured_utc=T0, collecting_system=SYSTEM,
            previous_chain_hash=GENESIS_CHAIN_HASH, chain_hash="0" * 64,
        )


def test_records_reject_naive_timestamps() -> None:
    with pytest.raises(ValueError, match="explicit UTC offset"):
        ChainOfCustodyRecord(
            record_id="x", stream_id="S-1", sequence=0,
            kind=ArtifactKind.THERMAL_FRAME, artifact_sha256="0" * 64,
            artifact_bytes=1, captured_utc=T0.replace(tzinfo=None),
            collecting_system=SYSTEM,
            previous_chain_hash=GENESIS_CHAIN_HASH, chain_hash="0" * 64,
        )


# --------------------------------------------------------------------------- #
# The WORM store
# --------------------------------------------------------------------------- #

def test_worm_sink_offers_no_deletion_path() -> None:
    """The control is the absence.

    An API that offers deletion and refuses it still teaches every caller that deletion
    is a thing one asks for, and the refusal is one config change from being granted.
    """
    surface = {m for m in dir(WormSink) if not m.startswith("_")}
    assert surface == {"commit", "get", "stream_records"}
    for forbidden in ("delete", "remove", "update", "overwrite", "purge", "set_retention"):
        assert not hasattr(InMemoryWormStore, forbidden)


def test_committed_record_is_retrievable() -> None:
    store = InMemoryWormStore()
    record = make_chain(1)[0]
    receipt = store.commit(record)
    assert store.get(record.record_id) == record
    assert receipt.chain_hash == record.chain_hash
    assert receipt.retention_mode is RetentionMode.COMPLIANCE


def test_second_commit_of_the_same_record_is_refused() -> None:
    store = InMemoryWormStore()
    record = make_chain(1)[0]
    store.commit(record)
    with pytest.raises(CommitRefused, match="already committed"):
        store.commit(record)


def test_commit_of_an_inconsistent_record_is_refused() -> None:
    """Integrity is established at the door, not discovered at audit time."""
    store = InMemoryWormStore()
    record = replace(make_chain(1)[0], artifact_sha256="9" * 64)
    with pytest.raises(CommitRefused, match="does not match its own chain hash"):
        store.commit(record)
    assert len(store) == 0


def test_default_retention_is_compliance_mode() -> None:
    """Governance mode can be overridden by a privileged identity.

    That makes it unsuitable for evidence that might implicate that identity.
    """
    policy = RetentionPolicy()
    assert policy.mode is RetentionMode.COMPLIANCE
    assert not policy.is_overridable
    assert RetentionPolicy(mode=RetentionMode.GOVERNANCE).is_overridable


def test_retention_must_be_positive() -> None:
    with pytest.raises(ValueError, match="at least one day"):
        RetentionPolicy(retain_days=0)


def test_store_verifies_a_stream_end_to_end() -> None:
    store = InMemoryWormStore()
    for record in make_chain(15):
        store.commit(record)
    assert store.verify_stream("S-1").intact
    assert store.verify_stream("S-1").records_checked == 15


def test_streams_are_kept_separate() -> None:
    store = InMemoryWormStore()
    for record in make_chain(5, stream_id="S-1"):
        store.commit(record)
    for record in make_chain(3, stream_id="S-2"):
        store.commit(record)
    assert len(store.stream_records("S-1")) == 5
    assert len(store.stream_records("S-2")) == 3
    assert store.streams() == ("S-1", "S-2")
