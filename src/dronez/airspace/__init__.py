"""Sovereign No-Fly-Zone (NFZ) / GACA airspace integration.

``schema`` is the wire contract, ``client`` the fail-closed sync and clearance
logic, ``mock_client`` the development/test channel. Nothing here opens a socket;
transport is supplied by a deployment adapter at Milestone 1.
"""

from dronez.airspace.client import (
    AirspaceCache,
    AirspaceClearanceService,
    ClearanceDecision,
    DenialReason,
    FeedState,
    NfzChannelError,
    NfzSyncChannel,
    SigningKey,
    SigningKeyRegistry,
)
from dronez.airspace.schema import (
    SCHEMA_VERSION,
    AirspaceZone,
    NfzBulletin,
    Polygon,
    SchemaValidationError,
    Severity,
    ZoneType,
    parse_bulletin,
)

__all__ = [
    "SCHEMA_VERSION",
    "AirspaceCache",
    "AirspaceClearanceService",
    "AirspaceZone",
    "ClearanceDecision",
    "DenialReason",
    "FeedState",
    "NfzBulletin",
    "NfzChannelError",
    "NfzSyncChannel",
    "Polygon",
    "SchemaValidationError",
    "Severity",
    "SigningKey",
    "SigningKeyRegistry",
    "ZoneType",
    "parse_bulletin",
]
