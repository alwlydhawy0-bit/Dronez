"""Media pipeline security.

Signaling-layer screening of WebRTC offers, and the DTLS/SRTP policy the media engine
is configured with. Nothing here carries media; it decides whether a session may be
created at all.
"""

from mcp_server.media.webrtc import (
    ALLOWED_SRTP_PROFILES,
    MIN_DTLS_VERSION,
    REQUIRED_TRANSPORT_PROFILE,
    DtlsSrtpPolicy,
    SdpGuard,
    SdpRejection,
    SdpVerdict,
)

__all__ = [
    "ALLOWED_SRTP_PROFILES",
    "MIN_DTLS_VERSION",
    "REQUIRED_TRANSPORT_PROFILE",
    "DtlsSrtpPolicy",
    "SdpGuard",
    "SdpRejection",
    "SdpVerdict",
]
