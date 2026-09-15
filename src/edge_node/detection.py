"""Detection events produced by on-device inference.

Master Plan §4 lists `DetectionEvent` alongside `ThermalFrame` as an edge-pipeline
artifact archived to the WORM store. §5 makes the delivery priority explicit: *"actionable
detection alerts are prioritized over raw video bandwidth"*, and *"every detection event
is hashed and archived to the WORM store at capture time, independent of whether the
live viewer was connected."*

Detection runs on the edge module so that detection latency does not depend on a cloud
round-trip (Master Plan §4, tech stack). That also means the detection exists before the
link does anything -- which is why archival is unconditional.

Scope boundary
--------------
This is object *detection*, not identification or tracking of a named individual. Master
Plan §3 puts autonomous target engagement and pursuit without a human-confirmed track
permanently out of scope, and §2 requires bystanders to be handled by the redaction
pipeline before footage leaves the tactical boundary. :class:`DetectionClass` is
deliberately coarse for that reason: it says *a person is at this bearing*, not *who*.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

__all__ = ["BoundingBox", "DetectionClass", "DetectionEvent"]


class DetectionClass(StrEnum):
    """What the detector reports.

    Coarse by design. A finer taxonomy would invite the platform to be used for
    identification, which §3 places out of scope -- and a class list is the kind of
    thing that grows quietly once the first entry is specific.
    """

    PERSON = "person"
    VEHICLE = "vehicle"
    ANIMAL = "animal"
    HEAT_SOURCE = "heat_source"
    STRUCTURE_BREACH = "structure_breach"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class BoundingBox:
    """Normalised detection box, origin at the frame's top-left."""

    x: float
    y: float
    width: float
    height: float

    def __post_init__(self) -> None:
        for name, value in (("x", self.x), ("y", self.y)):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be normalised to 0..1")
        for name, value in (("width", self.width), ("height", self.height)):
            if not 0.0 < value <= 1.0:
                raise ValueError(f"{name} must be a positive fraction of the frame")
        if self.x + self.width > 1.0001 or self.y + self.height > 1.0001:
            raise ValueError("bounding box extends beyond the frame")

    def to_dict(self) -> dict[str, float]:
        return {"x": self.x, "y": self.y, "width": self.width, "height": self.height}


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    """One detection, bound to the frame it came from.

    ``source_frame_sha256`` ties the event to a specific frame's capture-time digest.
    Without it a detection is an unfalsifiable assertion: there would be no way to show,
    later, which image the detector was looking at when it fired.
    """

    event_id: str
    stream_id: str
    detection_class: DetectionClass
    confidence: float
    box: BoundingBox
    detected_utc: datetime
    #: Capture-time digest of the frame this detection came from.
    source_frame_sha256: str
    #: Sensor that produced the frame.
    sensor: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if len(self.source_frame_sha256) != 64:
            raise ValueError("source_frame_sha256 must be a 64-character hex digest")
        if self.detected_utc.tzinfo is None:
            raise ValueError("detected_utc must carry an explicit UTC offset")

    def to_dict(self) -> dict[str, object]:
        return {
            "v": 1,
            "typ": "detection_event",
            "event_id": self.event_id,
            "stream_id": self.stream_id,
            "detection_class": self.detection_class.value,
            "confidence": round(self.confidence, 6),
            "box": self.box.to_dict(),
            "detected_utc": self.detected_utc.astimezone(UTC).isoformat(),
            "source_frame_sha256": self.source_frame_sha256,
            "sensor": self.sensor,
        }

    def canonical_bytes(self) -> bytes:
        """Deterministic serialisation, hashed into the chain of custody."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
