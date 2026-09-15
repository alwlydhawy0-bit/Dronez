"""Edge compute node — NVIDIA Jetson-class module on or beside the airframe.

Capture, per-frame hashing before transmission, on-device detection, and the
degradation policy that decides what a stressed link carries.

**Contains no transport.** Nothing here opens a socket or drives a camera; frames and
link measurements are handed in, and delivery is a callback. That keeps the evidentiary
logic testable and keeps this package free of the hardware bindings that would make it
unfuzzable.
"""

from edge_node.degradation import (
    SHEDDABLE,
    DegradationController,
    LinkQuality,
    PayloadClass,
    StreamTier,
    TierDecision,
)
from edge_node.detection import BoundingBox, DetectionClass, DetectionEvent
from edge_node.frame_hasher import (
    FrameHasher,
    FrameMetadata,
    HashedFrame,
    SecureElementSigner,
    SegmentSeal,
)
from edge_node.pipeline import EvidencePipeline, PipelineStats

__all__ = [
    "SHEDDABLE",
    "BoundingBox",
    "DegradationController",
    "DetectionClass",
    "DetectionEvent",
    "EvidencePipeline",
    "FrameHasher",
    "FrameMetadata",
    "HashedFrame",
    "LinkQuality",
    "PayloadClass",
    "PipelineStats",
    "SecureElementSigner",
    "SegmentSeal",
    "StreamTier",
    "TierDecision",
]
