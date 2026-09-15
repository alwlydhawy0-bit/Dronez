"""Chain of custody for evidentiary artifacts.

Master Plan §4 defines ``ChainOfCustodyRecord`` as *"hash + timestamp + collecting
system for every evidentiary artifact"*, and Zero-Trust §8.1 requires that any artifact
collected for forensic purposes be *"hashed at collection time and the hash recorded in
the immutable store."*

Why a chain and not just per-artifact hashes
--------------------------------------------
Hashing each frame independently proves that **the frames you have** were not modified.
It proves nothing about the frames you *don't* have. An attacker who deletes thirty
seconds of footage, or reorders it, leaves every remaining hash valid.

So each record commits to its predecessor: ``chain_hash = H(previous_chain_hash ||
artifact_hash || sequence || captured_at || …)``. A deletion breaks the linkage at the
gap, a reordering breaks it at the swap, and a re-hash of the whole sequence to repair
it requires the signing key that seals each segment. That is what makes the record
*tamper-evident* rather than merely *tamper-resistant*.

What this module does not do
----------------------------
It does not decide retention, and it holds no delete path. Deletion authority is the
one thing that must not exist in code that handles evidence (§8.1: *"no service
identity in the system -- including administrators -- holds delete/modify permission on
committed records"*), so there is nothing here to call.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "GENESIS_CHAIN_HASH",
    "ArtifactKind",
    "BreakKind",
    "ChainBreak",
    "ChainOfCustodyRecord",
    "ChainVerification",
    "CollectingSystem",
    "compute_chain_hash",
    "verify_chain",
]

#: The chain's starting value. A record whose ``previous_chain_hash`` is this is the
#: first of its stream, and nothing precedes it.
GENESIS_CHAIN_HASH: Final[str] = "0" * 64

HASH_ALGORITHM: Final[str] = "sha256"


class ArtifactKind(StrEnum):
    """What was collected. Each has different retention and redaction handling."""

    THERMAL_FRAME = "thermal_frame"
    OPTICAL_FRAME = "optical_frame"
    DETECTION_EVENT = "detection_event"
    TELEMETRY_SAMPLE = "telemetry_sample"
    #: Periodic seal over a run of records, signed by the airframe's secure element.
    SEGMENT_MANIFEST = "segment_manifest"


@dataclass(frozen=True, slots=True)
class CollectingSystem:
    """Which physical system collected an artifact.

    Master Plan §4 requires the collecting system in every record. It is not
    bookkeeping: an evidentiary claim that cannot name the hardware that produced it,
    and the firmware that hardware was running, is substantially weaker in review.
    """

    #: e.g. "jetson-orin-nx", the compute module identifier.
    device_id: str
    device_type: str
    #: Firmware/image digest, attested by the secure element at boot (Zero-Trust §4.3).
    firmware_digest: str
    drone_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "device_id": self.device_id,
            "device_type": self.device_type,
            "firmware_digest": self.firmware_digest,
            "drone_id": self.drone_id,
        }


@dataclass(frozen=True, slots=True)
class ChainOfCustodyRecord:
    """One immutable evidentiary record.

    ``artifact_sha256`` is computed **on the collecting hardware, before transmission**
    (Master Plan §4). A hash computed on arrival would attest only that the bytes
    reaching the server were not altered *after* they arrived -- which is precisely the
    claim an attacker on the network path is in a position to make true.
    """

    record_id: str
    stream_id: str
    sequence: int
    kind: ArtifactKind
    #: Digest of the artifact itself, computed at the point of capture.
    artifact_sha256: str
    artifact_bytes: int
    captured_utc: datetime
    collecting_system: CollectingSystem
    previous_chain_hash: str
    chain_hash: str
    #: Free-form, schema-validated by the producer. Never interpreted as instructions.
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.artifact_sha256) != 64:
            raise ValueError("artifact_sha256 must be a 64-character hex digest")
        if len(self.chain_hash) != 64 or len(self.previous_chain_hash) != 64:
            raise ValueError("chain hashes must be 64-character hex digests")
        if self.sequence < 0:
            raise ValueError("sequence must be non-negative")
        if self.captured_utc.tzinfo is None:
            raise ValueError("captured_utc must carry an explicit UTC offset")

    @property
    def is_genesis(self) -> bool:
        return self.previous_chain_hash == GENESIS_CHAIN_HASH

    def recompute_chain_hash(self) -> str:
        return compute_chain_hash(
            previous_chain_hash=self.previous_chain_hash,
            stream_id=self.stream_id,
            sequence=self.sequence,
            kind=self.kind,
            artifact_sha256=self.artifact_sha256,
            artifact_bytes=self.artifact_bytes,
            captured_utc=self.captured_utc,
            collecting_system=self.collecting_system,
        )

    def is_self_consistent(self) -> bool:
        """Whether this record's own chain hash matches its contents."""
        import hmac as _hmac

        return _hmac.compare_digest(self.recompute_chain_hash(), self.chain_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "stream_id": self.stream_id,
            "sequence": self.sequence,
            "kind": self.kind.value,
            "hash_algorithm": HASH_ALGORITHM,
            "artifact_sha256": self.artifact_sha256,
            "artifact_bytes": self.artifact_bytes,
            "captured_utc": self.captured_utc.astimezone(UTC).isoformat(),
            "collecting_system": self.collecting_system.to_dict(),
            "previous_chain_hash": self.previous_chain_hash,
            "chain_hash": self.chain_hash,
            "metadata": dict(self.metadata),
        }


def compute_chain_hash(
    *,
    previous_chain_hash: str,
    stream_id: str,
    sequence: int,
    kind: ArtifactKind,
    artifact_sha256: str,
    artifact_bytes: int,
    captured_utc: datetime,
    collecting_system: CollectingSystem,
) -> str:
    """Link a record to its predecessor.

    The sequence number and the previous hash are both inside the digest. Either alone
    would be insufficient: the previous hash alone lets an attacker truncate the tail of
    a stream undetectably, and the sequence alone lets them substitute a frame at a
    given index.
    """
    payload = {
        "v": 1,
        "previous_chain_hash": previous_chain_hash,
        "stream_id": stream_id,
        "sequence": sequence,
        "kind": kind.value,
        "artifact_sha256": artifact_sha256,
        "artifact_bytes": artifact_bytes,
        "captured_utc": captured_utc.astimezone(UTC).isoformat(),
        "collecting_system": collecting_system.to_dict(),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class BreakKind(StrEnum):
    """How a chain failed verification. Each points at a different manipulation."""

    #: A record's contents do not match its own chain hash -- the record was altered.
    ALTERED_RECORD = "altered_record"
    #: A record's predecessor hash does not match the previous record -- something was
    #: removed, inserted, or substituted between them.
    BROKEN_LINK = "broken_link"
    #: Sequence numbers are not contiguous -- records were deleted.
    SEQUENCE_GAP = "sequence_gap"
    #: Records arrived out of order relative to their sequence.
    OUT_OF_ORDER = "out_of_order"
    #: The first record does not start from the genesis value.
    MISSING_GENESIS = "missing_genesis"
    #: Capture timestamps move backwards within a stream.
    TIME_TRAVEL = "time_travel"


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """One detected discontinuity, located precisely enough to investigate."""

    kind: BreakKind
    sequence: int
    record_id: str | None
    detail: str


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """Result of verifying a stream's chain."""

    intact: bool
    records_checked: int
    breaks: tuple[ChainBreak, ...] = ()
    first_sequence: int | None = None
    last_sequence: int | None = None
    head_chain_hash: str | None = None

    def summary(self) -> str:
        if self.intact:
            return (
                f"chain intact over {self.records_checked} records "
                f"({self.first_sequence}..{self.last_sequence})"
            )
        kinds = ", ".join(sorted({b.kind.value for b in self.breaks}))
        return f"chain BROKEN: {len(self.breaks)} discontinuity/ies ({kinds})"


def verify_chain(records: list[ChainOfCustodyRecord]) -> ChainVerification:
    """Verify a stream's chain end to end.

    Reports **every** break rather than stopping at the first. An investigator needs the
    extent of a manipulation, not just its earliest point -- and a single break at
    sequence 40 tells you far less than breaks at 40, 41 and 42 telling you a span was
    excised.

    An empty list verifies as intact-but-empty: there is nothing to contradict. Callers
    that require evidence to exist must check ``records_checked`` themselves, because
    "no records" and "records that verify" are different claims and this function should
    not conflate them.
    """
    if not records:
        return ChainVerification(intact=True, records_checked=0)

    ordered = sorted(records, key=lambda r: r.sequence)
    breaks: list[ChainBreak] = []

    if [r.record_id for r in ordered] != [r.record_id for r in records]:
        breaks.append(
            ChainBreak(
                BreakKind.OUT_OF_ORDER,
                ordered[0].sequence,
                None,
                "records were supplied out of sequence order",
            )
        )

    if not ordered[0].is_genesis:
        breaks.append(
            ChainBreak(
                BreakKind.MISSING_GENESIS,
                ordered[0].sequence,
                ordered[0].record_id,
                "the first record does not link to the genesis value; earlier records "
                "are missing from this set",
            )
        )

    previous: ChainOfCustodyRecord | None = None
    for record in ordered:
        if not record.is_self_consistent():
            breaks.append(
                ChainBreak(
                    BreakKind.ALTERED_RECORD,
                    record.sequence,
                    record.record_id,
                    "record contents do not match its own chain hash",
                )
            )

        if previous is not None:
            if record.sequence != previous.sequence + 1:
                breaks.append(
                    ChainBreak(
                        BreakKind.SEQUENCE_GAP,
                        record.sequence,
                        record.record_id,
                        f"sequence jumps from {previous.sequence} to {record.sequence}; "
                        f"{record.sequence - previous.sequence - 1} record(s) are missing",
                    )
                )
            if record.previous_chain_hash != previous.chain_hash:
                breaks.append(
                    ChainBreak(
                        BreakKind.BROKEN_LINK,
                        record.sequence,
                        record.record_id,
                        "predecessor hash does not match the preceding record",
                    )
                )
            if record.captured_utc < previous.captured_utc:
                breaks.append(
                    ChainBreak(
                        BreakKind.TIME_TRAVEL,
                        record.sequence,
                        record.record_id,
                        "capture time precedes that of the previous record",
                    )
                )
        previous = record

    return ChainVerification(
        intact=not breaks,
        records_checked=len(ordered),
        breaks=tuple(breaks),
        first_sequence=ordered[0].sequence,
        last_sequence=ordered[-1].sequence,
        head_chain_hash=ordered[-1].chain_hash,
    )
