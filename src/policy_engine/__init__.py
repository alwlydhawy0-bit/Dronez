"""Deterministic, non-LLM authorization gate.

Nothing in this package may consult an LLM, import an agent SDK, or accept a
natural-language argument. Authorization decisions are made by deterministic code
reading structured input only (Zero-Trust §4.2 *Deterministic Policy Gate*).

The decision logic itself lives in ``policies/*.rego``, evaluated by OPA. The Python
here builds inputs, parses decisions, and guarantees that anything other than an
explicit affirmative is a denial.
"""

from policy_engine.client import (
    PolicyEngine,
    PolicyTransport,
    PolicyTransportError,
    StaticPolicyTransport,
    TransportResponse,
)
from policy_engine.models import (
    DenyReason,
    FleetSnapshot,
    PolicyDecision,
    PolicyPath,
    build_deploy_recon_waypoint_input,
)

__all__ = [
    "DenyReason",
    "FleetSnapshot",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyPath",
    "PolicyTransport",
    "PolicyTransportError",
    "StaticPolicyTransport",
    "TransportResponse",
    "build_deploy_recon_waypoint_input",
]
