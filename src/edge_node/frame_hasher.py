"""Per-frame hashing on the edge compute module, before transmission.

Master Plan §4 is specific about *where* this runs: frames are *"cryptographically
hashed **per frame, on the edge hardware (e.g. NVIDIA Jetson) prior to transmission**,
not after arrival at the command room -- this is what makes the chain-of-custody claim
defensible against an attacker who compromises the network path."*

The distinction is the whole control. A hash computed when a frame reaches the command
room attests that nobody altered it *after* it arrived. An attacker sitting on the RF
link is in a position to make that claim true about frames they substituted. Hashing at
the sensor boundary moves the trust anchor inside the airframe, where the secure element
is.

Throughput
----------
This runs on a Jetson-class module alongside detection inference, at video rate. Two
consequences shape the design:

* **SHA-256 per frame, not a signature per frame.** Hashing a 640x512 thermal frame is
  sub-millisecond; an ECDSA signature is three orders of magnitude slower and would not
  keep up. So every frame is hashed and chained, and the chain is *sealed* periodically
  by signing the head -- one asymmetric operation per segment rather than per frame.
  The segment seal is what binds the chain to the hardware; the chain is what makes one
  seal cover every frame beneath it.
* **Hashing is incremental over the frame buffer.** :meth:`FrameHasher.hash_frame`
  accepts a memoryview so a caller can hand it a zero-copy view of a DMA buffer rather
  than a copy.

The segment interval is a real trade-off and is documented at :data:`DEFAULT_SEGMENT_FRAMES`.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Final, Protocol

from dronez.evidence import (
    GENESIS_CHAIN_HASH,
    ArtifactKind,
    ChainOfCustodyRecord,
    CollectingSystem,
    compute_chain_hash,
)

__all__ = [
    "DEFAULT_SEGMENT_FRAMES",
    "FrameHasher",
    "FrameMetadata",
    "HashChainState",
    "HashedFrame",
    "SecureElementSigner",
    "SegmentSeal",
]

#: Frames per sealed segment.
#:
#: The trade-off: a shorter interval means a compromise of the chain is bounded to fewer
#: frames, but costs more asymmetric operations and more manifest records in the WORM
#: store. At 30 fps, 300 frames is a seal every ten seconds -- so an attacker who
#: somehow rewrites the chain can at worst rewrite the ten seconds since the last seal,
#: and cannot touch anything a seal already covers without the secure element's key.
DEFAULT_SEGMENT_FRAMES: Final[int] = 300

#: Refuse to hash a buffer larger than this. A thermal frame is well under a megabyte;
#: anything approaching this is a defect or a memory-exhaustion attempt.
MAX_FRAME_BYTES: Final[int] = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class FrameMetadata:
    """What a frame is, beyond its bytes.

    Carried into the chain hash via the record, so an attacker cannot relabel a frame's
    sensor, resolution or capture time without breaking the linkage.
    """

    sensor: str
    width: int
    height: int
    pixel_format: str
    #: Monotonic counter from the capture driver. Distinct from the chain sequence:
    #: this one can gap legitimately if the sensor drops a frame, and the difference
    #: between the two is itself diagnostic.
    sensor_frame_index: int

    def to_dict(self) -> dict[str, object]:
        return {
            "sensor": self.sensor,
            "width": self.width,
            "height": self.height,
            "pixel_format": self.pixel_format,
            "sensor_frame_index": self.sensor_frame_index,
        }


@dataclass(frozen=True, slots=True)
class HashedFrame:
    """A frame with its capture-time digest and chain record.

    The record travels with the frame. A pipeline that hashed frames but shipped the
    digests separately would let an attacker drop the digests and leave the frames
    looking unattested rather than looking tampered with.
    """

    record: ChainOfCustodyRecord
    metadata: FrameMetadata
    #: Digest of the frame buffer exactly as captured, before any encoding or transport.
    artifact_sha256: str
    byte_length: int


@dataclass(frozen=True, slots=True)
class SegmentSeal:
    """A signed commitment to a run of chained records.

    Signed by the airframe's secure element, so the seal binds the chain to *this*
    hardware. Without it the chain is internally consistent but reproducible by anyone:
    an attacker who replaced an entire stream could compute a valid chain over their own
    frames. The seal is what they cannot forge.
    """

    seal_id: str
    stream_id: str
    first_sequence: int
    last_sequence: int
    head_chain_hash: str
    sealed_utc: datetime
    key_id: str
    #: Hex-encoded signature over :meth:`signing_payload`.
    signature: str
    frame_count: int

    def signing_payload(self) -> bytes:
        import json

        payload = {
            "v": 1,
            "typ": "segment_seal",
            "stream_id": self.stream_id,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "head_chain_hash": self.head_chain_hash,
            "frame_count": self.frame_count,
            "sealed_utc": self.sealed_utc.astimezone(UTC).isoformat(),
            "key_id": self.key_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SecureElementSigner(Protocol):
    """Signing interface to the airframe's TPM / secure element.

    The private key never leaves that boundary (Zero-Trust §4.3, §7.2), so this is a
    request to sign rather than access to a key.
    """

    @property
    def key_id(self) -> str:
        ...

    def sign(self, payload: bytes) -> bytes:
        ...


@dataclass(frozen=True, slots=True)
class HashChainState:
    """Where a stream's chain has reached."""

    stream_id: str
    next_sequence: int
    head_chain_hash: str
    frames_since_seal: int
    sealed_through: int | None


class FrameHasher:
    """Hashes and chains frames at capture, on the edge module.

    One instance per stream. Thread-safe, because capture and detection typically run on
    separate threads and both produce artifacts into the same chain -- interleaving them
    without a lock would corrupt the sequence, which is indistinguishable from tampering
    to anyone verifying it later.
    """

    def __init__(
        self,
        *,
        stream_id: str,
        collecting_system: CollectingSystem,
        signer: SecureElementSigner | None = None,
        segment_frames: int = DEFAULT_SEGMENT_FRAMES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if segment_frames < 1:
            raise ValueError("segment_frames must be at least 1")
        self._stream_id = stream_id
        self._system = collecting_system
        self._signer = signer
        self._segment_frames = segment_frames
        self._clock = clock or (lambda: datetime.now(UTC))

        self._lock = threading.Lock()
        self._next_sequence = 0
        self._head = GENESIS_CHAIN_HASH
        self._segment_start = 0
        self._frames_since_seal = 0
        self._sealed_through: int | None = None
        self.frames_hashed = 0

    # -- hashing ---------------------------------------------------------

    def hash_frame(
        self,
        buffer: bytes | bytearray | memoryview,
        metadata: FrameMetadata,
        *,
        captured_utc: datetime | None = None,
    ) -> HashedFrame:
        """Hash a captured frame and append it to the chain.

        ``buffer`` may be a ``memoryview`` over a DMA buffer -- no copy is made.
        """
        length = len(buffer)
        if length == 0:
            raise ValueError("refusing to hash an empty frame buffer")
        if length > MAX_FRAME_BYTES:
            raise ValueError(
                f"frame buffer of {length} bytes exceeds the {MAX_FRAME_BYTES}-byte cap"
            )

        digest = hashlib.sha256(buffer).hexdigest()
        return self._append(
            kind=ArtifactKind.THERMAL_FRAME
            if metadata.sensor.startswith("thermal")
            else ArtifactKind.OPTICAL_FRAME,
            artifact_sha256=digest,
            artifact_bytes=length,
            captured_utc=captured_utc,
            metadata=metadata.to_dict(),
            frame_metadata=metadata,
        )

    def hash_artifact(
        self,
        payload: bytes,
        kind: ArtifactKind,
        *,
        captured_utc: datetime | None = None,
        metadata: dict[str, object] | None = None,
    ) -> ChainOfCustodyRecord:
        """Chain a non-frame artifact -- a detection event, a telemetry sample.

        Detection events go through the same chain as frames on purpose. A detection
        that referenced a frame but sat outside its chain could be added or removed
        after the fact without breaking anything.
        """
        digest = hashlib.sha256(payload).hexdigest()
        hashed = self._append(
            kind=kind,
            artifact_sha256=digest,
            artifact_bytes=len(payload),
            captured_utc=captured_utc,
            metadata=metadata or {},
            frame_metadata=None,
        )
        return hashed.record

    def _append(
        self,
        *,
        kind: ArtifactKind,
        artifact_sha256: str,
        artifact_bytes: int,
        captured_utc: datetime | None,
        metadata: dict[str, object],
        frame_metadata: FrameMetadata | None,
    ) -> HashedFrame:
        captured = captured_utc or self._clock()
        with self._lock:
            sequence = self._next_sequence
            previous = self._head
            chain_hash = compute_chain_hash(
                previous_chain_hash=previous,
                stream_id=self._stream_id,
                sequence=sequence,
                kind=kind,
                artifact_sha256=artifact_sha256,
                artifact_bytes=artifact_bytes,
                captured_utc=captured,
                collecting_system=self._system,
            )
            record = ChainOfCustodyRecord(
                record_id=f"coc-{uuid.uuid4().hex}",
                stream_id=self._stream_id,
                sequence=sequence,
                kind=kind,
                artifact_sha256=artifact_sha256,
                artifact_bytes=artifact_bytes,
                captured_utc=captured,
                collecting_system=self._system,
                previous_chain_hash=previous,
                chain_hash=chain_hash,
                metadata=dict(metadata),
            )
            self._next_sequence = sequence + 1
            self._head = chain_hash
            self._frames_since_seal += 1
            self.frames_hashed += 1

        return HashedFrame(
            record=record,
            metadata=frame_metadata
            or FrameMetadata(
                sensor="n/a", width=0, height=0, pixel_format="n/a", sensor_frame_index=-1
            ),
            artifact_sha256=artifact_sha256,
            byte_length=artifact_bytes,
        )

    # -- sealing ---------------------------------------------------------

    @property
    def seal_due(self) -> bool:
        with self._lock:
            return self._frames_since_seal >= self._segment_frames

    def seal_segment(self, *, force: bool = False) -> SegmentSeal | None:
        """Sign the chain head, sealing every record since the last seal.

        Returns ``None`` when no seal is due and ``force`` is false, or when there is
        nothing to seal. Raises if no signer is configured and a seal is genuinely
        required -- an unsigned chain is internally consistent and forgeable, so
        silently skipping the seal would leave the pipeline looking protected when it is
        not.
        """
        with self._lock:
            if self._frames_since_seal == 0:
                return None
            if not force and self._frames_since_seal < self._segment_frames:
                return None
            first = self._segment_start
            last = self._next_sequence - 1
            head = self._head
            count = self._frames_since_seal

        if self._signer is None:
            raise RuntimeError(
                "a segment seal is due but no secure element signer is configured; an "
                "unsigned chain is forgeable, so the pipeline must not continue as "
                "though it were sealed"
            )

        seal = SegmentSeal(
            seal_id=f"seal-{uuid.uuid4().hex}",
            stream_id=self._stream_id,
            first_sequence=first,
            last_sequence=last,
            head_chain_hash=head,
            sealed_utc=self._clock(),
            key_id=self._signer.key_id,
            signature="",
            frame_count=count,
        )
        signature = self._signer.sign(seal.signing_payload()).hex()
        sealed = replace(seal, signature=signature)

        with self._lock:
            self._segment_start = self._next_sequence
            self._frames_since_seal = 0
            self._sealed_through = last
        return sealed

    # -- inspection ------------------------------------------------------

    @property
    def state(self) -> HashChainState:
        with self._lock:
            return HashChainState(
                stream_id=self._stream_id,
                next_sequence=self._next_sequence,
                head_chain_hash=self._head,
                frames_since_seal=self._frames_since_seal,
                sealed_through=self._sealed_through,
            )
