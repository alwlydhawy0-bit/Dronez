"""Edge capture: hashing before transmission, degradation, and unconditional archival.

Three invariants are swept here:

* **Hashing happens at capture**, on the edge module, before anything is transmitted.
* **Detection events are never shed** for bandwidth, at any tier.
* **Archival does not depend on a viewer** -- evidence is preserved whether or not
  anyone is watching, and whether or not the link is up.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from dronez.evidence import (
    ArtifactKind,
    CollectingSystem,
    CommitRefused,
    InMemoryWormStore,
    verify_chain,
)
from edge_node import (
    SHEDDABLE,
    BoundingBox,
    DegradationController,
    DetectionClass,
    DetectionEvent,
    EvidencePipeline,
    FrameHasher,
    FrameMetadata,
    LinkQuality,
    PayloadClass,
    StreamTier,
)

T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
SYSTEM = CollectingSystem("jetson-orin-nx-01", "jetson-orin-nx", "a" * 64, "D-1")


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class StubSigner:
    key_id = "secure-element-key-1"

    def __init__(self) -> None:
        self.signed: list[bytes] = []

    def sign(self, payload: bytes) -> bytes:
        self.signed.append(payload)
        return hashlib.sha256(b"stub-key" + payload).digest()


def meta(index: int, sensor: str = "thermal-0") -> FrameMetadata:
    return FrameMetadata(sensor, 640, 512, "y16", index)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def hasher(clock: Clock) -> FrameHasher:
    return FrameHasher(
        stream_id="S-1", collecting_system=SYSTEM, signer=StubSigner(),
        segment_frames=5, clock=clock,
    )


# --------------------------------------------------------------------------- #
# Frame hashing
# --------------------------------------------------------------------------- #

def test_hash_is_of_the_captured_buffer(hasher: FrameHasher) -> None:
    """Computed on the edge, over the frame exactly as captured."""
    buffer = b"\x42" * 4096
    hashed = hasher.hash_frame(buffer, meta(1))
    assert hashed.artifact_sha256 == hashlib.sha256(buffer).hexdigest()
    assert hashed.byte_length == 4096


def test_hashing_accepts_a_zero_copy_view(hasher: FrameHasher) -> None:
    """A caller should be able to hand over a DMA buffer without copying it."""
    buffer = bytearray(b"\x07" * 2048)
    hashed = hasher.hash_frame(memoryview(buffer), meta(1))
    assert hashed.artifact_sha256 == hashlib.sha256(bytes(buffer)).hexdigest()


def test_frames_form_an_intact_chain(hasher: FrameHasher) -> None:
    records = [hasher.hash_frame(bytes([i % 256]) * 512, meta(i)).record for i in range(12)]
    assert verify_chain(records).intact


def test_thermal_and_optical_are_classified_separately(hasher: FrameHasher) -> None:
    thermal = hasher.hash_frame(b"\x01" * 64, meta(1, "thermal-0")).record
    optical = hasher.hash_frame(b"\x02" * 64, meta(2, "optical-0")).record
    assert thermal.kind is ArtifactKind.THERMAL_FRAME
    assert optical.kind is ArtifactKind.OPTICAL_FRAME


def test_empty_frame_is_refused(hasher: FrameHasher) -> None:
    with pytest.raises(ValueError, match="empty frame buffer"):
        hasher.hash_frame(b"", meta(1))


def test_detections_join_the_same_chain_as_frames(hasher: FrameHasher) -> None:
    """A detection outside the frame chain could be added or removed after the fact."""
    frame = hasher.hash_frame(b"\x01" * 512, meta(1)).record
    detection = hasher.hash_artifact(b"detection-payload", ArtifactKind.DETECTION_EVENT)
    assert detection.previous_chain_hash == frame.chain_hash
    assert verify_chain([frame, detection]).intact


# --------------------------------------------------------------------------- #
# Segment sealing
# --------------------------------------------------------------------------- #

def test_seal_is_not_due_before_the_interval(hasher: FrameHasher) -> None:
    for i in range(3):
        hasher.hash_frame(b"\x01" * 64, meta(i))
    assert not hasher.seal_due
    assert hasher.seal_segment() is None


def test_seal_covers_the_segment(hasher: FrameHasher) -> None:
    for i in range(5):
        hasher.hash_frame(b"\x01" * 64, meta(i))
    assert hasher.seal_due
    seal = hasher.seal_segment()
    assert seal is not None
    assert (seal.first_sequence, seal.last_sequence, seal.frame_count) == (0, 4, 5)
    assert seal.signature
    assert seal.key_id == "secure-element-key-1"


def test_seal_binds_the_chain_head(hasher: FrameHasher) -> None:
    """Without a seal the chain is internally consistent but reproducible by anyone."""
    for i in range(5):
        hasher.hash_frame(b"\x01" * 64, meta(i))
    seal = hasher.seal_segment()
    assert seal is not None
    assert seal.head_chain_hash == hasher.state.head_chain_hash


def test_seal_resets_the_segment_window(hasher: FrameHasher) -> None:
    for i in range(5):
        hasher.hash_frame(b"\x01" * 64, meta(i))
    hasher.seal_segment()
    assert hasher.state.frames_since_seal == 0
    assert hasher.state.sealed_through == 4


def test_unsigned_pipeline_refuses_to_pretend_it_sealed(clock: Clock) -> None:
    """Silently skipping the seal would leave the pipeline looking protected."""
    unsigned = FrameHasher(
        stream_id="S-1", collecting_system=SYSTEM, signer=None,
        segment_frames=2, clock=clock,
    )
    unsigned.hash_frame(b"\x01" * 64, meta(1))
    unsigned.hash_frame(b"\x02" * 64, meta(2))
    with pytest.raises(RuntimeError, match="unsigned chain is forgeable"):
        unsigned.seal_segment()


# --------------------------------------------------------------------------- #
# Degradation
# --------------------------------------------------------------------------- #

def test_detection_events_are_never_sheddable() -> None:
    """THE invariant of the degradation module."""
    assert PayloadClass.DETECTION_EVENT not in SHEDDABLE
    assert PayloadClass.TELEMETRY not in SHEDDABLE
    assert SHEDDABLE == {PayloadClass.VIDEO_DELTA, PayloadClass.KEYFRAME}


@pytest.mark.parametrize("tier", list(StreamTier))
def test_every_tier_admits_detection(tier: StreamTier, clock: Clock) -> None:
    controller = DegradationController(initial_tier=tier, clock=clock)
    assert controller.admits(PayloadClass.DETECTION_EVENT)
    assert controller.admits(PayloadClass.TELEMETRY)


def test_floor_tier_carries_detection_but_no_video(clock: Clock) -> None:
    controller = DegradationController(initial_tier=StreamTier.DETECTION_ONLY, clock=clock)
    assert controller.admits(PayloadClass.DETECTION_EVENT)
    assert not controller.admits(PayloadClass.VIDEO_DELTA)
    assert not StreamTier.DETECTION_ONLY.carries_video


def test_degradation_is_immediate(clock: Clock) -> None:
    """A link that cannot carry the tier is already dropping packets."""
    controller = DegradationController(clock=clock)
    decision = controller.observe(LinkQuality(50_000, 0.30, 2500))
    assert decision.changed and decision.degraded
    assert decision.tier is StreamTier.DETECTION_ONLY


def test_recovery_waits_for_the_dwell_period(clock: Clock) -> None:
    """Every tier change costs a renegotiation, so a flapping link must not flap the stream."""
    controller = DegradationController(clock=clock, recovery_dwell_s=10.0)
    controller.observe(LinkQuality(50_000, 0.30, 2500))
    good = LinkQuality(5_000_000, 0.001, 25)

    assert not controller.observe(good).changed
    clock.advance(5)
    assert not controller.observe(good).changed
    clock.advance(6)
    assert controller.observe(good).changed


def test_a_flapping_link_does_not_flap_the_tier(clock: Clock) -> None:
    controller = DegradationController(clock=clock, recovery_dwell_s=10.0)
    good = LinkQuality(5_000_000, 0.001, 25)
    bad = LinkQuality(50_000, 0.30, 2500)
    for _ in range(5):
        controller.observe(bad)
        clock.advance(2)
        controller.observe(good)
        clock.advance(2)
    assert controller.recoveries == 0, "a link that never held should never have recovered"


def test_carrier_loss_drops_to_the_floor(clock: Clock) -> None:
    controller = DegradationController(clock=clock)
    decision = controller.observe(
        LinkQuality(5_000_000, 0.0, 10, carrier_lost=True)
    )
    assert decision.tier is StreamTier.DETECTION_ONLY


def test_loss_caps_the_tier_independently_of_bandwidth(clock: Clock) -> None:
    """A fat pipe dropping one packet in twenty cannot carry inter-frame video."""
    controller = DegradationController(clock=clock)
    decision = controller.observe(LinkQuality(10_000_000, 0.10, 30))
    assert decision.tier <= StreamTier.LOW


def test_latency_caps_the_tier_independently_of_bandwidth(clock: Clock) -> None:
    controller = DegradationController(clock=clock)
    decision = controller.observe(LinkQuality(10_000_000, 0.0, 1500))
    assert decision.tier <= StreamTier.LOW


def test_forced_tier_cannot_exceed_the_ceiling(clock: Clock) -> None:
    """An operator may ask for less than the link can carry, never more than authorized."""
    controller = DegradationController(
        initial_tier=StreamTier.LOW, ceiling=StreamTier.MEDIUM, clock=clock
    )
    decision = controller.force_tier(StreamTier.HIGH, reason="operator request")
    assert decision.tier is StreamTier.MEDIUM


# --------------------------------------------------------------------------- #
# The pipeline
# --------------------------------------------------------------------------- #

def detection(frame_digest: str, when: datetime) -> DetectionEvent:
    return DetectionEvent(
        event_id="ev-1", stream_id="S-1", detection_class=DetectionClass.PERSON,
        confidence=0.91, box=BoundingBox(0.1, 0.1, 0.2, 0.3),
        detected_utc=when, source_frame_sha256=frame_digest, sensor="thermal-0",
    )


def build(clock: Clock, *, transmit=None, worm=None):  # type: ignore[no-untyped-def]
    store = worm or InMemoryWormStore(clock=clock)
    hasher = FrameHasher(
        stream_id="S-1", collecting_system=SYSTEM, signer=StubSigner(),
        segment_frames=5, clock=clock,
    )
    controller = DegradationController(clock=clock)
    pipeline = EvidencePipeline(
        hasher=hasher, worm=store, degradation=controller, transmit=transmit, clock=clock
    )
    return pipeline, store, controller


def test_frames_are_archived_with_no_viewer_attached(clock: Clock) -> None:
    """Archival is unconditional; transmission is what the tier gates."""
    pipeline, store, _ = build(clock, transmit=None)
    outcome = pipeline.capture_frame(b"\x01" * 1024, meta(1))
    assert outcome.archived is True
    assert outcome.transmitted is False
    assert len(store) == 1


def test_detection_is_archived_and_delivered_at_the_floor_tier(clock: Clock) -> None:
    """The headline behaviour: video is shed, the detection still goes out."""
    sent: list[PayloadClass] = []
    pipeline, _store, controller = build(
        clock, transmit=lambda cls, _payload: (sent.append(cls), True)[1]
    )
    controller.observe(LinkQuality(40_000, 0.35, 3000))

    frame = pipeline.capture_frame(b"\x02" * 1024, meta(2))
    assert frame.transmitted is False, "video must be shed at the floor tier"
    assert frame.archived is True, "shed video is still evidence"

    event = pipeline.capture_detection(detection(frame.hashed.artifact_sha256, clock()))
    assert event.transmitted is True, "detection is never shed for bandwidth"
    assert event.archived is True

    assert PayloadClass.DETECTION_EVENT in sent
    assert PayloadClass.VIDEO_DELTA not in sent


def test_archive_survives_a_transport_failure(clock: Clock) -> None:
    """A transport defect must not stop capture or lose evidence."""
    def exploding(_cls: PayloadClass, _payload: bytes) -> bool:
        raise ConnectionError("link down")

    pipeline, _store, _ = build(clock, transmit=exploding)
    outcome = pipeline.capture_frame(b"\x01" * 1024, meta(1))
    assert outcome.transmitted is False
    assert outcome.archived is True


def test_unreachable_store_spools_rather_than_losing_evidence(clock: Clock) -> None:
    class Unreachable:
        def commit(self, record):  # type: ignore[no-untyped-def]
            raise ConnectionError("worm store unreachable")

        def get(self, record_id):  # type: ignore[no-untyped-def]
            return None

        def stream_records(self, stream_id):  # type: ignore[no-untyped-def]
            return ()

    pipeline, _, _ = build(clock, worm=Unreachable())
    outcome = pipeline.capture_frame(b"\x01" * 1024, meta(1))
    assert outcome.archived is False
    assert pipeline.spool_depth == 1
    assert pipeline.stats.records_spooled == 1


def test_spool_flushes_when_the_store_returns(clock: Clock) -> None:
    store = InMemoryWormStore(clock=clock)
    failing = {"down": True}

    class Flaky:
        def commit(self, record):  # type: ignore[no-untyped-def]
            if failing["down"]:
                raise ConnectionError("down")
            return store.commit(record)

        def get(self, record_id):  # type: ignore[no-untyped-def]
            return store.get(record_id)

        def stream_records(self, stream_id):  # type: ignore[no-untyped-def]
            return store.stream_records(stream_id)

    pipeline, _, _ = build(clock, worm=Flaky())
    for i in range(4):
        pipeline.capture_frame(bytes([i]) * 256, meta(i))
    assert pipeline.spool_depth == 4

    failing["down"] = False
    assert pipeline.flush_spool() == 4
    assert pipeline.spool_depth == 0
    assert store.verify_stream("S-1").intact


def test_full_spool_drops_video_before_detection(clock: Clock) -> None:
    """Same priority as live delivery, for the same reason."""
    class Unreachable:
        def commit(self, record):  # type: ignore[no-untyped-def]
            raise ConnectionError("down")

        def get(self, record_id):  # type: ignore[no-untyped-def]
            return None

        def stream_records(self, stream_id):  # type: ignore[no-untyped-def]
            return ()

    store = InMemoryWormStore(clock=clock)
    hasher = FrameHasher(
        stream_id="S-1", collecting_system=SYSTEM, signer=StubSigner(), clock=clock
    )
    pipeline = EvidencePipeline(
        hasher=hasher, worm=Unreachable(), degradation=DegradationController(clock=clock),
        max_spool=3, clock=clock,
    )
    for i in range(3):
        pipeline.capture_frame(bytes([i]) * 128, meta(i))
    assert pipeline.spool_depth == 3

    pipeline.capture_detection(detection("a" * 64, clock()))
    kinds = {r.kind for r in pipeline._spool}
    assert ArtifactKind.DETECTION_EVENT in kinds
    assert pipeline.stats.spool_dropped == 1
    assert store is not None


def test_duplicate_commit_is_counted_not_spooled(clock: Clock) -> None:
    """A refusal would just be retried forever; it is surfaced instead."""
    store = InMemoryWormStore(clock=clock)

    class Refusing:
        def commit(self, record):  # type: ignore[no-untyped-def]
            raise CommitRefused("already committed")

        def get(self, record_id):  # type: ignore[no-untyped-def]
            return None

        def stream_records(self, stream_id):  # type: ignore[no-untyped-def]
            return ()

    pipeline, _, _ = build(clock, worm=Refusing())
    pipeline.capture_frame(b"\x01" * 256, meta(1))
    assert pipeline.stats.commit_failures == 1
    assert pipeline.spool_depth == 0
    assert len(store) == 0


def test_seal_is_archived_as_its_own_record(clock: Clock) -> None:
    pipeline, store, _ = build(clock)
    for i in range(5):
        pipeline.capture_frame(bytes([i]) * 256, meta(i))
    record = pipeline.seal_if_due()
    assert record is not None
    assert record.kind is ArtifactKind.SEGMENT_MANIFEST
    assert store.verify_stream("S-1").intact
    assert pipeline.stats.seals_written == 1


def test_full_capture_run_produces_a_verifiable_chain(clock: Clock) -> None:
    """End to end: frames, detections and seals all in one verifiable chain."""
    pipeline, store, _controller = build(clock, transmit=lambda _c, _p: True)
    for i in range(12):
        frame = pipeline.capture_frame(bytes([i % 256]) * 512, meta(i))
        if i % 4 == 0:
            pipeline.capture_detection(detection(frame.hashed.artifact_sha256, clock()))
        pipeline.seal_if_due()
        clock.advance(0.033)
    pipeline.seal_if_due(force=True)

    verification = store.verify_stream("S-1")
    assert verification.intact, verification.summary()
    assert pipeline.stats.frames_captured == 12
    assert pipeline.stats.detections_captured == 3
