"""MCP tool handlers.

One module per tool. Handlers receive validated requests and return structured
outcomes; they never write audit records, never raise, and never reach hardware.
"""

from mcp_server.tools.base import CallContext, ToolHandler, ToolOutcome
from mcp_server.tools.clearance import CheckAirspaceClearanceHandler
from mcp_server.tools.confirm import ConfirmFlightPlanHandler
from mcp_server.tools.deploy import DeployReconWaypointHandler

__all__ = [
    "CallContext",
    "CheckAirspaceClearanceHandler",
    "ConfirmFlightPlanHandler",
    "DeployReconWaypointHandler",
    "ToolHandler",
    "ToolOutcome",
]
