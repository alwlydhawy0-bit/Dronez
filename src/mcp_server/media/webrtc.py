"""WebRTC signaling-layer enforcement of DTLS / SRTP.

Master Plan §5: the media pipeline is *"mandatorily encrypted end-to-end with DTLS 1.3 /
SRTP -- this is non-negotiable given the RF eavesdropping exposure inherent to a
wireless tactical feed, and the stream is rejected at the signaling layer if a client
cannot negotiate it."*

What SDP can and cannot enforce -- read this before changing anything
--------------------------------------------------------------------
It is tempting to write "check the SDP says DTLS 1.3". SDP cannot say that. The DTLS
version is chosen during the DTLS handshake, on the media path, after signaling is
finished. An SDP offer carries no version field for it, and a guard that claimed to
check one would be theatre.

What the signaling layer *can* decide is nonetheless most of the attack surface:

================================  =========================================================
Enforceable in SDP                 Why it matters
================================  =========================================================
Transport profile                  ``RTP/AVP`` is plaintext; ``RTP/SAVP`` is SDES. Only
                                   ``UDP/TLS/RTP/SAVPF`` is DTLS-SRTP.
Absence of ``a=crypto``            SDES puts the master key **in the signaling plane**, so
                                   anyone who can read the offer can decrypt the media.
Fingerprint hash algorithm         A SHA-1 fingerprint binds the DTLS certificate with a
                                   broken hash, so certificate substitution is feasible.
ICE credentials present            No ICE means no consent checks, and the media port
                                   becomes a reflector.
================================  =========================================================

The DTLS *version floor* and the SRTP *protection profile* are enforced where they
actually live: in the media engine's DTLS context, by :class:`DtlsSrtpPolicy`, exactly
as :func:`mcp_server.security.build_tls_context` does for the signaling TLS. Splitting
the responsibility honestly is the point -- a guard that pretends to enforce something
it cannot is worse than one that says where the enforcement really is.

Fail closed
-----------
An offer that cannot be parsed is rejected. Malformed SDP is not something to
best-effort interpret (Zero-Trust §0.1, §3.4): a parser that guesses is a parser
differential between this server and the media engine behind it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

__all__ = [
    "ALLOWED_SRTP_PROFILES",
    "MIN_DTLS_VERSION",
    "REQUIRED_TRANSPORT_PROFILE",
    "DtlsSrtpPolicy",
    "MediaDirection",
    "SdpGuard",
    "SdpRejection",
    "SdpVerdict",
]

#: Only DTLS-SRTP. ``RTP/AVP`` is unencrypted and ``RTP/SAVP`` is SDES-keyed.
REQUIRED_TRANSPORT_PROFILE: Final[str] = "UDP/TLS/RTP/SAVPF"

#: Enforced in the media engine's DTLS context, not in SDP. See the module docstring.
MIN_DTLS_VERSION: Final[str] = "1.3"

#: AEAD only. The SHA1-HMAC profiles are still widely offered and are not acceptable for
#: a tactical feed: an attacker who can flip ciphertext bits in a non-AEAD profile can
#: corrupt a thermal frame without the receiver noticing.
ALLOWED_SRTP_PROFILES: Final[tuple[str, ...]] = (
    "SRTP_AEAD_AES_256_GCM",
    "SRTP_AEAD_AES_128_GCM",
)

#: Fingerprint hashes strong enough to bind a certificate.
_ALLOWED_FINGERPRINT_HASHES: Final[frozenset[str]] = frozenset(
    {"sha-256", "sha-384", "sha-512"}
)

#: Bound on an accepted offer. A legitimate two-track offer is a few kilobytes.
MAX_SDP_BYTES: Final[int] = 64 * 1024
MAX_SDP_LINES: Final[int] = 512

_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(
    r"^a=fingerprint:(?P<hash>[A-Za-z0-9-]+)\s+(?P<value>[0-9A-Fa-f:]+)\s*$"
)
_MEDIA_RE: Final[re.Pattern[str]] = re.compile(
    r"^m=(?P<kind>audio|video|application)\s+(?P<port>\d+)\s+(?P<profile>[A-Za-z0-9/]+)"
)
_SETUP_RE: Final[re.Pattern[str]] = re.compile(
    r"^a=setup:(?P<role>active|passive|actpass|holdconn)"
)


class SdpRejection(StrEnum):
    """Why an offer was refused at the signaling layer."""

    MALFORMED = "sdp_malformed"
    OVERSIZED = "sdp_oversized"
    NO_MEDIA = "sdp_no_media_section"
    INSECURE_PROFILE = "sdp_insecure_transport_profile"
    SDES_OFFERED = "sdp_sdes_key_exchange_offered"
    MISSING_FINGERPRINT = "sdp_missing_dtls_fingerprint"
    WEAK_FINGERPRINT = "sdp_weak_fingerprint_hash"
    MISSING_ICE = "sdp_missing_ice_credentials"
    MISSING_SETUP = "sdp_missing_dtls_setup_role"
    UNSUPPORTED_MEDIA = "sdp_unsupported_media_kind"


class MediaDirection(StrEnum):
    SENDONLY = "sendonly"
    RECVONLY = "recvonly"
    SENDRECV = "sendrecv"
    INACTIVE = "inactive"


@dataclass(frozen=True, slots=True)
class SdpVerdict:
    """Result of screening an offer. ``acceptable`` is true only on the affirmative path."""

    acceptable: bool
    rejection: SdpRejection | None = None
    detail: str = ""
    #: Populated on acceptance, for the audit record.
    fingerprint_hash: str | None = None
    media_kinds: tuple[str, ...] = ()
    transport_profile: str | None = None

    @classmethod
    def reject(cls, rejection: SdpRejection, detail: str) -> SdpVerdict:
        return cls(acceptable=False, rejection=rejection, detail=detail)


@dataclass(frozen=True, slots=True)
class DtlsSrtpPolicy:
    """The DTLS/SRTP settings the media engine must be configured with.

    These are **not** checked against the SDP, because the SDP does not carry them. They
    are the configuration handed to the DTLS context that terminates the media path, and
    the media engine refuses the handshake if the peer cannot meet them. That refusal is
    what actually enforces "DTLS 1.3"; the SDP guard enforces everything around it.
    """

    min_dtls_version: str = MIN_DTLS_VERSION
    srtp_profiles: tuple[str, ...] = ALLOWED_SRTP_PROFILES
    #: Refuse a handshake whose peer certificate fingerprint does not match the one the
    #: offer advertised. Without this check DTLS authenticates *a* peer, not *the* peer
    #: the signaling channel agreed with, and the media path is open to a
    #: man-in-the-middle who never touched signaling.
    require_fingerprint_match: bool = True

    def __post_init__(self) -> None:
        if self.min_dtls_version != MIN_DTLS_VERSION:
            raise ValueError(
                f"DTLS {MIN_DTLS_VERSION} is mandatory for this pipeline; "
                f"{self.min_dtls_version} would be a downgrade (Master Plan Sec.5)"
            )
        if not self.srtp_profiles:
            raise ValueError("at least one SRTP protection profile must be offered")
        weak = [p for p in self.srtp_profiles if p not in ALLOWED_SRTP_PROFILES]
        if weak:
            raise ValueError(
                f"non-AEAD SRTP profiles are not acceptable for a tactical feed: {weak}"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "min_dtls_version": self.min_dtls_version,
            "srtp_profiles": list(self.srtp_profiles),
            "require_fingerprint_match": self.require_fingerprint_match,
        }


@dataclass
class _ParsedOffer:
    media_kinds: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)
    fingerprints: list[tuple[str, str]] = field(default_factory=list)
    has_ice_ufrag: bool = False
    has_ice_pwd: bool = False
    has_setup: bool = False
    has_crypto: bool = False


class SdpGuard:
    """Screens an SDP offer before any media session is created.

    Stateless and pure: it parses text and returns a verdict. It opens no socket and
    creates no peer connection -- the point is to refuse an unacceptable offer *before*
    anything is allocated for it.
    """

    ALLOWED_MEDIA_KINDS: Final[frozenset[str]] = frozenset({"video", "application"})

    def screen(self, sdp: str) -> SdpVerdict:
        """Screen an offer. Never raises."""
        if not isinstance(sdp, str) or not sdp.strip():
            return SdpVerdict.reject(SdpRejection.MALFORMED, "offer is empty")
        if len(sdp.encode("utf-8", errors="ignore")) > MAX_SDP_BYTES:
            return SdpVerdict.reject(
                SdpRejection.OVERSIZED, f"offer exceeds {MAX_SDP_BYTES} bytes"
            )

        lines = [line.strip() for line in sdp.replace("\r\n", "\n").split("\n") if line.strip()]
        if len(lines) > MAX_SDP_LINES:
            return SdpVerdict.reject(
                SdpRejection.OVERSIZED, f"offer exceeds {MAX_SDP_LINES} lines"
            )
        if not any(line.startswith("v=") for line in lines):
            return SdpVerdict.reject(SdpRejection.MALFORMED, "offer has no version line")

        parsed = self._parse(lines)

        if not parsed.media_kinds:
            return SdpVerdict.reject(SdpRejection.NO_MEDIA, "offer contains no media section")

        unsupported = sorted(set(parsed.media_kinds) - self.ALLOWED_MEDIA_KINDS)
        if unsupported:
            # Audio is not part of this pipeline. Accepting a media kind the platform
            # does not use would open a channel nothing is auditing.
            return SdpVerdict.reject(
                SdpRejection.UNSUPPORTED_MEDIA,
                f"media kind(s) {unsupported} are not carried by this pipeline",
            )

        if parsed.has_crypto:
            # SDES. The master key travels in the signaling plane, so anyone who can
            # read the offer can decrypt the media -- including anything that logged it.
            return SdpVerdict.reject(
                SdpRejection.SDES_OFFERED,
                "offer contains an a=crypto line (SDES); SDES places the SRTP master key "
                "in the signaling plane and is refused unconditionally",
            )

        insecure = [p for p in parsed.profiles if p != REQUIRED_TRANSPORT_PROFILE]
        if insecure:
            return SdpVerdict.reject(
                SdpRejection.INSECURE_PROFILE,
                f"transport profile(s) {sorted(set(insecure))} are not DTLS-SRTP; "
                f"{REQUIRED_TRANSPORT_PROFILE} is required",
            )

        if not parsed.fingerprints:
            return SdpVerdict.reject(
                SdpRejection.MISSING_FINGERPRINT,
                "offer carries no a=fingerprint; without it the DTLS certificate is "
                "unbound to the signaling channel and the media path is open to a "
                "man-in-the-middle",
            )

        weak = sorted({
            h.lower()
            for h, _ in parsed.fingerprints
            if h.lower() not in _ALLOWED_FINGERPRINT_HASHES
        })
        if weak:
            return SdpVerdict.reject(
                SdpRejection.WEAK_FINGERPRINT,
                f"fingerprint hash(es) {weak} are too weak to bind a certificate; "
                f"one of {sorted(_ALLOWED_FINGERPRINT_HASHES)} is required",
            )

        if not (parsed.has_ice_ufrag and parsed.has_ice_pwd):
            return SdpVerdict.reject(
                SdpRejection.MISSING_ICE,
                "offer lacks ICE credentials; without consent checks the media port "
                "becomes a reflector",
            )

        if not parsed.has_setup:
            return SdpVerdict.reject(
                SdpRejection.MISSING_SETUP,
                "offer lacks a=setup; the DTLS role is undetermined",
            )

        return SdpVerdict(
            acceptable=True,
            fingerprint_hash=parsed.fingerprints[0][0].lower(),
            media_kinds=tuple(sorted(set(parsed.media_kinds))),
            transport_profile=REQUIRED_TRANSPORT_PROFILE,
        )

    @staticmethod
    def _parse(lines: list[str]) -> _ParsedOffer:
        parsed = _ParsedOffer()
        for line in lines:
            media = _MEDIA_RE.match(line)
            if media:
                parsed.media_kinds.append(media.group("kind"))
                parsed.profiles.append(media.group("profile"))
                continue

            fingerprint = _FINGERPRINT_RE.match(line)
            if fingerprint:
                parsed.fingerprints.append(
                    (fingerprint.group("hash"), fingerprint.group("value"))
                )
                continue

            if line.startswith("a=crypto:"):
                parsed.has_crypto = True
            elif line.startswith("a=ice-ufrag:"):
                parsed.has_ice_ufrag = True
            elif line.startswith("a=ice-pwd:"):
                parsed.has_ice_pwd = True
            elif _SETUP_RE.match(line):
                parsed.has_setup = True
        return parsed
