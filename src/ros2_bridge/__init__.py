"""ROS2 / MAVLink bridge — airframe-side components.

**Contains no transport.** Nothing in this package opens a socket, a serial port, or a
connection to a flight controller. The Milestone-0 gate (``CLAUDE.md`` §2) forbids code
that commands or arms hardware; cryptographic primitives are security controls, and
keeping this package transport-free is what makes that boundary checkable rather than
merely asserted.

It also does not import :mod:`mcp_server`. The bridge is deployed on or beside the
airframe and must not carry the server's web stack onto it; the primitives both sides
need live in :mod:`dronez.crypto` and :mod:`dronez.authz`.
"""

from ros2_bridge.mavlink_signer import (
    AuthorizedFieldCommand,
    CommandTokenVerifier,
    FieldCommand,
    FieldCommandType,
    MavlinkFrame,
    MavlinkSignatureBlock,
    MavlinkSigner,
    MavlinkSigningKey,
    MavlinkVerifier,
    OperatorToken,
    TimestampAuthority,
    canonical_field_command_bytes,
)

__all__ = [
    "AuthorizedFieldCommand",
    "CommandTokenVerifier",
    "FieldCommand",
    "FieldCommandType",
    "MavlinkFrame",
    "MavlinkSignatureBlock",
    "MavlinkSigner",
    "MavlinkSigningKey",
    "MavlinkVerifier",
    "OperatorToken",
    "TimestampAuthority",
    "canonical_field_command_bytes",
]
