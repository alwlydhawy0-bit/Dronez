"""The edge capture pipeline: hash, archive, then transmit.

Order matters, and it is the order in the name. Master Plan §5: *"Every detection event
is hashed and archived to the WORM store at capture time, **independent of whether the
live viewer was connected**."*

So the pipeline does not ask whether anyone is watching before it preserves evidence.
Archival is unconditional; *transmission* is what the degradation controller gates. A
pipeline built the other way round -- archive what we send -- would lose exactly the
footage from the moments when the link was worst, which are the moments most likely to
matter afterwards.

    capture ──► hash + chain (edge) ──► WORM archive ──────────────► always
                                   └──► transmit ──► tier gate ──► maybe

Buffering
---------
The WORM store is reached over the same degraded link as the video, so archival is
staged through a local spool: records are queued on the edge module and flushed when
connectivity allows. The spool is bounded, and when it is full **video records are
dropped before detection records** -- the same priority that governs live delivery, for
the same reason.

Losing a queued artifact is a real loss of evidence, and the alternative -- an unbounded
spool that eventually exhausts the module's storage and takes down detection with it --
is worse. :attr:`PipelineStats.spool_dropped` makes the loss visible rather than silent.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from dronez.evidence import (
    ArtifactKind,
    ChainOfCustodyRecord,
    CommitRefused,
    WormSink,
)
from edge_node.degradation import DegradationController, PayloadClass, StreamTier
from edge_node.detection import DetectionEvent
from edge_node.frame_hasher import FrameHasher, FrameMetadata, HashedFrame

__all__ = [
    "MAX_SPOOL_RECORDS",
    "DetectionOutcome",
    "EvidencePipeline",
    "FrameOutcome",
    "PipelineStats",
]

#: Bound on the local archival spool. At ~200 bytes per record this is a few megabytes,
#: which a Jetson-class module can hold comfortably while a link recovers.
MAX_SPOOL_RECORDS: Final[int] = 20_000


@dataclass
class PipelineStats:
    """Observable pipeline behaviour. Read by the command room's stream status panel."""

    frames_captured: int = 0
    frames_transmitted: int = 0
    frames_shed: int = 0
    detections_captured: int = 0
    detections_transmitted: int = 0
    records_archived: int = 0
    records_spooled: int = 0
    spool_dropped: int = 0
    commit_failures: int = 0
    seals_written: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "frames_captured": self.frames_captured,
            "frames_transmitted": self.frames_transmitted,
            "frames_shed": self.frames_shed,
            "detections_captured": self.detections_captured,
            "detections_transmitted": self.detections_transmitted,
            "records_archived": self.records_archived,
            "records_spooled": self.records_spooled,
            "spool_dropped": self.spool_dropped,
            "commit_failures": self.commit_failures,
            "seals_written": self.seals_written,
        }


@dataclass(frozen=True, slots=True)
class FrameOutcome:
    """What happened to one captured frame."""

    hashed: HashedFrame
    archived: bool
    transmitted: bool
    tier: StreamTier
    reason: str


@dataclass(frozen=True, slots=True)
class DetectionOutcome:
    """What happened to one detection event.

    ``transmitted`` is false only when there is no transport at all. It is never false
    because of bandwidth: detection is not sheddable.
    """

    event: DetectionEvent
    record: ChainOfCustodyRecord
    archived: bool
    transmitted: bool


class EvidencePipeline:
    """Couples capture, hashing, archival and transmission for one stream.

    One instance per active stream. Thread-safe, because capture and inference run on
    different threads on a Jetson and both produce into the same chain.
    """

    def __init__(
        self,
        *,
        hasher: FrameHasher,
        worm: WormSink,
        degradation: DegradationController,
        transmit: Callable[[PayloadClass, bytes], bool] | None = None,
        max_spool: int = MAX_SPOOL_RECORDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._hasher = hasher
        self._worm = worm
        self._degradation = degradation
        # Returns True when the payload left the module. None means no transport is
        # attached -- capture and archival still run, which is the point.
        self._transmit = transmit
        self._max_spool = max_spool
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._spool: list[ChainOfCustodyRecord] = []
        self.stats = PipelineStats()

    # -- capture ---------------------------------------------------------

    def capture_frame(
        self,
        buffer: bytes | bytearray | memoryview,
        metadata: FrameMetadata,
        *,
        captured_utc: datetime | None = None,
    ) -> FrameOutcome:
        """Hash, archive, then transmit a frame if the tier admits it."""
        hashed = self._hasher.hash_frame(buffer, metadata, captured_utc=captured_utc)
        self.stats.frames_captured += 1

        archived = self._archive(hashed.record)

        payload_class = (
            PayloadClass.KEYFRAME
            if metadata.sensor_frame_index % 30 == 0
            else PayloadClass.VIDEO_DELTA
        )
        tier = self._degradation.tier
        if not self._degradation.admits(payload_class):
            self.stats.frames_shed += 1
            return FrameOutcome(
                hashed=hashed,
                archived=archived,
                transmitted=False,
                tier=tier,
                reason=f"{payload_class.value} is not admitted at tier {tier.label}",
            )

        transmitted = self._send(payload_class, bytes(buffer))
        if transmitted:
            self.stats.frames_transmitted += 1
        return FrameOutcome(
            hashed=hashed,
            archived=archived,
            transmitted=transmitted,
            tier=tier,
            reason="transmitted" if transmitted else "no transport attached",
        )

    def capture_detection(self, event: DetectionEvent) -> DetectionOutcome:
        """Hash, archive and deliver a detection event.

        There is no tier check here, and that absence is the control. A detection is
        never shed for bandwidth -- see :data:`edge_node.degradation.SHEDDABLE`.
        """
        payload = event.canonical_bytes()
        record = self._hasher.hash_artifact(
            payload,
            ArtifactKind.DETECTION_EVENT,
            captured_utc=event.detected_utc,
            metadata={
                "event_id": event.event_id,
                "detection_class": event.detection_class.value,
                "confidence": round(event.confidence, 6),
                "source_frame_sha256": event.source_frame_sha256,
            },
        )
        self.stats.detections_captured += 1
        archived = self._archive(record)

        transmitted = self._send(PayloadClass.DETECTION_EVENT, payload)
        if transmitted:
            self.stats.detections_transmitted += 1
        return DetectionOutcome(
            event=event, record=record, archived=archived, transmitted=transmitted
        )

    # -- archival --------------------------------------------------------

    def _archive(self, record: ChainOfCustodyRecord) -> bool:
        """Commit a record, spooling it locally if the store is unreachable."""
        try:
            self._worm.commit(record)
        except CommitRefused:
            # The store rejected it outright -- a duplicate id, or a record whose chain
            # hash does not match its contents. Spooling would just retry a refusal, so
            # this is counted and surfaced rather than queued.
            self.stats.commit_failures += 1
            return False
        except Exception:
            self._spool_record(record)
            return False
        self.stats.records_archived += 1
        return True

    def _spool_record(self, record: ChainOfCustodyRecord) -> None:
        with self._lock:
            if len(self._spool) >= self._max_spool:
                victim = self._select_spool_victim()
                if victim is None:
                    # Nothing sheddable left: the spool is entirely detection and
                    # telemetry records. Drop the incoming one rather than evict
                    # evidence that is already queued, and count it loudly.
                    self.stats.spool_dropped += 1
                    return
                self._spool.pop(victim)
                self.stats.spool_dropped += 1
            self._spool.append(record)
            self.stats.records_spooled += 1

    def _select_spool_victim(self) -> int | None:
        """Oldest *video* record in the spool, or ``None`` if there is none.

        Same priority as live delivery: video goes before detection.
        """
        for index, record in enumerate(self._spool):
            if record.kind in (ArtifactKind.THERMAL_FRAME, ArtifactKind.OPTICAL_FRAME):
                return index
        return None

    def flush_spool(self) -> int:
        """Attempt to commit spooled records. Returns how many were committed."""
        with self._lock:
            pending = list(self._spool)
            self._spool.clear()

        committed = 0
        requeue: list[ChainOfCustodyRecord] = []
        for record in pending:
            try:
                self._worm.commit(record)
            except CommitRefused:
                self.stats.commit_failures += 1
            except Exception:
                requeue.append(record)
            else:
                committed += 1
                self.stats.records_archived += 1

        if requeue:
            with self._lock:
                self._spool = requeue + self._spool
        return committed

    @property
    def spool_depth(self) -> int:
        with self._lock:
            return len(self._spool)

    # -- sealing ---------------------------------------------------------

    def seal_if_due(self, *, force: bool = False) -> ChainOfCustodyRecord | None:
        """Seal the chain segment when due, archiving the manifest as its own record."""
        seal = self._hasher.seal_segment(force=force)
        if seal is None:
            return None
        record = self._hasher.hash_artifact(
            seal.signing_payload() + bytes.fromhex(seal.signature),
            ArtifactKind.SEGMENT_MANIFEST,
            metadata={
                "seal_id": seal.seal_id,
                "first_sequence": seal.first_sequence,
                "last_sequence": seal.last_sequence,
                "head_chain_hash": seal.head_chain_hash,
                "key_id": seal.key_id,
                "frame_count": seal.frame_count,
            },
        )
        self._archive(record)
        self.stats.seals_written += 1
        return record

    # -- transport -------------------------------------------------------

    def _send(self, payload_class: PayloadClass, payload: bytes) -> bool:
        if self._transmit is None:
            return False
        try:
            return bool(self._transmit(payload_class, payload))
        except Exception:
            return False

    def status(self) -> dict[str, object]:
        return {
            "stream_id": self._hasher.state.stream_id,
            "tier": self._degradation.tier.label,
            "chain": {
                "next_sequence": self._hasher.state.next_sequence,
                "head_chain_hash": self._hasher.state.head_chain_hash,
                "sealed_through": self._hasher.state.sealed_through,
            },
            "spool_depth": self.spool_depth,
            "stats": self.stats.to_dict(),
        }
