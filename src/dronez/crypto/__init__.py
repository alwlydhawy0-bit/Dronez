"""Shared cryptographic primitives for operator command signing.

One implementation, used by both the MCP server and the ROS2/MAVLink bridge. Neither
owns it, and neither reimplements it: two implementations of a signature check drift,
and the one that is wrong is the one nobody is looking at.

Stdlib only, with ``cryptography`` as an optional import. When it is absent the
asymmetric verifiers are absent from the table rather than silently skipped.
"""

from dronez.crypto.algorithms import (
    ALLOWED_SIGNATURE_ALGORITHMS,
    CRYPTOGRAPHY_AVAILABLE,
    SignatureAlgorithm,
    available_algorithms,
    verify_detached,
)
from dronez.crypto.failures import SignatureFailure, SignatureVerdict
from dronez.crypto.keys import KeyRegistry, VerificationKey
from dronez.crypto.nonce import (
    CLOCK_SKEW_ALLOWANCE_S,
    MAX_SIGNATURE_LIFETIME_S,
    NonceStore,
)

__all__ = [
    "ALLOWED_SIGNATURE_ALGORITHMS",
    "CLOCK_SKEW_ALLOWANCE_S",
    "CRYPTOGRAPHY_AVAILABLE",
    "MAX_SIGNATURE_LIFETIME_S",
    "KeyRegistry",
    "NonceStore",
    "SignatureAlgorithm",
    "SignatureFailure",
    "SignatureVerdict",
    "VerificationKey",
    "available_algorithms",
    "verify_detached",
]
