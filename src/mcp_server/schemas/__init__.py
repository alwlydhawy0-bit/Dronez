"""Strict Pydantic v2 schemas for the MCP tool boundary.

Layer 1 of the authorization chain. These types decide whether a request is
*well-formed* -- shape, ranges, enum membership, closed-world field sets. Whether it
is *authorized* is decided by :mod:`policy_engine`, against the incident zone, live
airspace clearance and fleet state.

Keeping those two layers separate is deliberate: a schema cannot express "inside
this mission's polygon", and a policy engine should not be re-deriving whether a
float is finite.
"""

from mcp_server.schemas.base import SCHEMA_CONTRACT_VERSION, StrictModel
from mcp_server.schemas.geo import GeoPolygon, Position
from mcp_server.schemas.identity import (
    ALLOWED_SIGNATURE_ALGORITHMS,
    CommandSignature,
    OperatorIdentity,
    Role,
    SignatureAlgorithm,
    SignedCommandEnvelope,
    Tier,
    can_override,
)
from mcp_server.schemas.incident_zone import (
    IncidentPriority,
    IncidentZone,
    IncidentZoneStatus,
)
from mcp_server.schemas.tools import (
    AGENT_PROPOSABLE_TOOLS,
    TOOL_REGISTRY,
    TOOL_SCHEMA_VERSIONS,
    RejectionCode,
    ToolName,
    ToolRejection,
)

__all__ = [
    "AGENT_PROPOSABLE_TOOLS",
    "ALLOWED_SIGNATURE_ALGORITHMS",
    "SCHEMA_CONTRACT_VERSION",
    "TOOL_REGISTRY",
    "TOOL_SCHEMA_VERSIONS",
    "CommandSignature",
    "GeoPolygon",
    "IncidentPriority",
    "IncidentZone",
    "IncidentZoneStatus",
    "OperatorIdentity",
    "Position",
    "RejectionCode",
    "Role",
    "SignatureAlgorithm",
    "SignedCommandEnvelope",
    "StrictModel",
    "Tier",
    "ToolName",
    "ToolRejection",
    "can_override",
]
