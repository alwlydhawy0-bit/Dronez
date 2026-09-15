"""Non-repudiation command signing for the ROS2 / MAVLink bridge.

**This module contains no transport.** No socket, no serial port, no MAVLink
publisher, no flight-controller connection. It signs and verifies bytes. The
Milestone-0 gate (``CLAUDE.md`` §2) forbids anything that commands or arms hardware;
a signing primitive is a security control, and keeping it free of transport is what
makes that distinction checkable rather than asserted. ``test_module_has_no_transport``
enforces it.

Two signatures, two different jobs
----------------------------------
A command that reaches an airframe carries two independent cryptographic claims, and
conflating them loses one of them:

========================  ==================================  ========================
                          Operator command token              MAVLink2 message signing
========================  ==================================  ========================
Proves                    *a named human authorized this*     *these bytes are intact
                                                              and came from the bridge*
Primitive                 ECDSA/RSA, asymmetric               HMAC-style SHA-256, shared
                                                              per-link secret
Bound to                  a FIDO2/WebAuthn authenticator      a link, a system, a
                                                              component
Survives                  compromise of the bridge            an RF-adjacent attacker
Non-repudiation           **yes**                             no -- both ends hold the key
========================  ==================================  ========================

Master Plan §5 requires the first: *"every field command dispatched through the MCP
server ... is signed with a short-lived ECDSA/RSA token cryptographically bound to the
issuing operator's FIDO2/WebAuthn hardware security key."* Zero-Trust §4.3 requires the
second: *"MAVLink2 message signing (per-link shared secret, monotonic
timestamp/sequence) is mandatory on all command and telemetry links."*

The binding between them is the point of this module: **a MAVLink frame cannot be
signed without a verified operator authorization that names that exact command.**
:meth:`MavlinkSigner.sign` accepts only an :class:`AuthorizedFieldCommand`, which
exists only as the return value of a successful verification. The ordering is therefore
unskippable by construction rather than by discipline -- there is no argument
combination that signs an unauthorized frame.

A shared secret cannot establish who acted, so the MAVLink layer alone would leave the
system unable to answer "who authorized this flight?" after an incident. That question
is the whole reason the operator token exists.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final

from dronez.authz import Role, may_issue_field_command
from dronez.crypto import (
    KeyRegistry,
    NonceStore,
    SignatureFailure,
    SignatureVerdict,
    available_algorithms,
    verify_detached,
)
from dronez.crypto.algorithms import SignatureAlgorithm
from dronez.crypto.nonce import CLOCK_SKEW_ALLOWANCE_S, MAX_SIGNATURE_LIFETIME_S

__all__ = [
    "MAVLINK_EPOCH",
    "MAVLINK_IFLAG_SIGNED",
    "MAVLINK_SECRET_KEY_LEN",
    "MAVLINK_SIGNATURE_LEN",
    "AuthorizedFieldCommand",
    "CommandTokenVerifier",
    "FieldCommand",
    "FieldCommandType",
    "MavlinkFailure",
    "MavlinkFrame",
    "MavlinkSignatureBlock",
    "MavlinkSigner",
    "MavlinkSigningKey",
    "MavlinkVerdict",
    "MavlinkVerifier",
    "OperatorToken",
    "TimestampAuthority",
    "canonical_field_command_bytes",
]

# --------------------------------------------------------------------------- #
# MAVLink2 signing constants (MAVLink message-signing specification)
# --------------------------------------------------------------------------- #

#: link_id (1) + timestamp (6) + signature (6).
MAVLINK_SIGNATURE_LEN: Final[int] = 13
#: Per-link shared secret. 32 bytes, as specified.
MAVLINK_SECRET_KEY_LEN: Final[int] = 32
#: Truncated SHA-256 output carried on the wire.
MAVLINK_SIGNATURE_DIGEST_LEN: Final[int] = 6
#: incompat_flags bit that marks a packet as signed. A receiver that ignores this bit
#: would accept an unsigned packet as though it were signed.
MAVLINK_IFLAG_SIGNED: Final[int] = 0x01
#: MAVLink signing timestamps count 10-microsecond units from this instant.
MAVLINK_EPOCH: Final[datetime] = datetime(2015, 1, 1, tzinfo=UTC)
#: One timestamp unit, in seconds.
MAVLINK_TIMESTAMP_UNIT_S: Final[float] = 1e-5
#: 48-bit field.
MAVLINK_MAX_TIMESTAMP: Final[int] = (1 << 48) - 1
#: A frame dated further ahead than this is refused even if monotonic. Bounds how far
#: an attacker with a captured key can jump the counter to lock out the real sender.
MAVLINK_MAX_FUTURE_UNITS: Final[int] = int(60.0 / MAVLINK_TIMESTAMP_UNIT_S)


# --------------------------------------------------------------------------- #
# Layer 1 -- the operator command token
# --------------------------------------------------------------------------- #

class FieldCommandType(StrEnum):
    """Commands this bridge will sign.

    A closed set, and deliberately a small one. Reconnaissance only: there is no
    payload-release or weapons member, and `CLAUDE.md` §1.1 is asserted against this
    module's source by the prohibited-capability test.
    """

    MISSION_UPLOAD = "mission_upload"
    MISSION_START = "mission_start"
    LOITER = "loiter"
    RETURN_TO_LAUNCH = "return_to_launch"
    LAND = "land"
    DISARM = "disarm"
    STREAM_REQUEST = "stream_request"


@dataclass(frozen=True, slots=True)
class FieldCommand:
    """A concrete command bound for an airframe.

    ``parameters_sha256`` covers the actual payload rather than embedding it: the
    signature must commit to the exact parameters without this module needing to
    understand their structure.
    """

    command_id: str
    command_type: FieldCommandType
    mission_id: str
    drone_id: str
    parameters_sha256: str
    #: MAVLink message id this command will be encoded as. Carried in the signed bytes
    #: so an authorization for one message cannot be presented for another.
    message_id: int

    def __post_init__(self) -> None:
        if len(self.parameters_sha256) != 64:
            raise ValueError("parameters_sha256 must be a 64-character hex digest")
        if not 0 <= self.message_id <= 0xFFFFFF:
            raise ValueError("message_id must fit MAVLink2's 24-bit field")


@dataclass(frozen=True, slots=True)
class OperatorToken:
    """Short-lived non-repudiation token bound to the issuer's FIDO2 authenticator."""

    algorithm: SignatureAlgorithm
    key_id: str
    fido2_credential_id: str
    #: Hex-encoded detached signature over :func:`canonical_field_command_bytes`.
    value: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    operator_id: str
    role: Role


@dataclass(frozen=True, slots=True)
class AuthorizedFieldCommand:
    """Proof that a command was authorized by a named human.

    **Constructible only by :meth:`CommandTokenVerifier.verify`.** This is the
    capability that :meth:`MavlinkSigner.sign` demands, which is what makes "verify
    before signing" a property of the type system rather than a rule someone has to
    remember.
    """

    command: FieldCommand
    operator_id: str
    role: Role
    key_id: str
    fido2_credential_id: str
    verified_at: datetime
    expires_at: datetime

    #: Set by the verifier. A hand-constructed instance will not carry it.
    _issued_by_verifier: bool = False

    def is_valid_at(self, when: datetime) -> bool:
        return when < self.expires_at


def canonical_field_command_bytes(
    command: FieldCommand,
    *,
    operator_id: str,
    role: Role,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
) -> bytes:
    """Deterministic bytes the operator token covers.

    Everything that changes the meaning of the authorization is inside: which command,
    which airframe, which mission, which exact parameters, who authorized it, in what
    role, and for how long. An authorization that named only the operator and the time
    could be moved onto any command that operator was entitled to issue.
    """
    payload = {
        "v": 1,
        "typ": "field_command",
        "command_id": command.command_id,
        "command_type": command.command_type.value,
        "mission_id": command.mission_id,
        "drone_id": command.drone_id,
        "message_id": command.message_id,
        "parameters_sha256": command.parameters_sha256,
        "operator_id": operator_id,
        "role": role.value,
        "nonce": nonce,
        "issued_at": issued_at.astimezone(UTC).isoformat(),
        "expires_at": expires_at.astimezone(UTC).isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class CommandTokenVerifier:
    """Verifies an operator token against a command, end to end.

    Check order is cheap-to-expensive, with the cryptographic check last and the nonce
    consumed only **after** it passes. Consuming first would let an attacker burn a
    legitimate operator's nonce with a garbage signature, turning verification into a
    denial-of-service primitive.
    """

    def __init__(
        self,
        registry: KeyRegistry,
        nonces: NonceStore,
        *,
        clock: Callable[[], datetime] | None = None,
        clock_skew_s: float = CLOCK_SKEW_ALLOWANCE_S,
        max_lifetime_s: float = MAX_SIGNATURE_LIFETIME_S,
    ) -> None:
        self._registry = registry
        self._nonces = nonces
        self._clock = clock or (lambda: datetime.now(UTC))
        self._skew = timedelta(seconds=clock_skew_s)
        self._max_lifetime = timedelta(seconds=max_lifetime_s)

    def verify(
        self, command: FieldCommand, token: OperatorToken
    ) -> tuple[SignatureVerdict, AuthorizedFieldCommand | None]:
        """Verify ``token`` authorizes ``command``.

        Returns the verdict and, only on success, the capability that permits signing.
        """
        # Tier first: an agent token is refused before any key lookup, so a compromised
        # agent cannot even probe the registry for valid key ids.
        if not may_issue_field_command(token.role):
            return (
                SignatureVerdict.reject(
                    SignatureFailure.TIER_NOT_PERMITTED,
                    f"role {token.role.value!r} may not author a field command; Tier 3 "
                    "proposes and a human tier disposes",
                ),
                None,
            )

        key = self._registry.get(token.key_id)
        if key is None:
            return (
                SignatureVerdict.reject(
                    SignatureFailure.UNKNOWN_KEY,
                    f"key_id {token.key_id!r} is not in the registry",
                ),
                None,
            )
        if key.algorithm is not token.algorithm:
            return (
                SignatureVerdict.reject(
                    SignatureFailure.ALGORITHM_MISMATCH,
                    f"key {token.key_id!r} is registered for {key.algorithm.value}, "
                    f"token claims {token.algorithm.value}",
                ),
                None,
            )
        if key.operator_id != token.operator_id:
            return (
                SignatureVerdict.reject(
                    SignatureFailure.NOT_BOUND_TO_OPERATOR,
                    f"key {token.key_id!r} belongs to a different operator; a valid "
                    "signature from another key is not this operator's authorization",
                ),
                None,
            )
        if key.fido2_credential_id != token.fido2_credential_id:
            return (
                SignatureVerdict.reject(
                    SignatureFailure.NOT_BOUND_TO_CREDENTIAL,
                    "token is not bound to the registered FIDO2 authenticator",
                ),
                None,
            )

        now = self._clock()
        if token.expires_at <= token.issued_at:
            return (
                SignatureVerdict.reject(
                    SignatureFailure.MALFORMED, "token expires at or before its issue time"
                ),
                None,
            )
        if token.expires_at - token.issued_at > self._max_lifetime:
            return (
                SignatureVerdict.reject(
                    SignatureFailure.LIFETIME_TOO_LONG,
                    f"token lifetime exceeds the {self._max_lifetime.total_seconds():.0f}s "
                    "maximum for a short-lived credential",
                ),
                None,
            )
        if now >= token.expires_at:
            return (
                SignatureVerdict.reject(
                    SignatureFailure.EXPIRED,
                    f"token expired at {token.expires_at.isoformat()}",
                ),
                None,
            )
        if now + self._skew < token.issued_at:
            return (
                SignatureVerdict.reject(
                    SignatureFailure.NOT_YET_VALID,
                    "token is dated further ahead than the permitted clock skew",
                ),
                None,
            )

        if token.algorithm not in available_algorithms():
            return (
                SignatureVerdict.reject(
                    SignatureFailure.ALGORITHM_UNAVAILABLE,
                    f"algorithm {token.algorithm.value} is allow-listed but not available "
                    "in this build; failing closed rather than signing on an unverified token",
                ),
                None,
            )

        try:
            raw = bytes.fromhex(token.value)
        except ValueError:
            return (
                SignatureVerdict.reject(
                    SignatureFailure.MALFORMED, "token signature is not valid hex"
                ),
                None,
            )

        signed = canonical_field_command_bytes(
            command,
            operator_id=token.operator_id,
            role=token.role,
            nonce=token.nonce,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
        )
        if not verify_detached(token.algorithm, key.material, signed, raw):
            return (
                SignatureVerdict.reject(
                    SignatureFailure.INVALID,
                    "token does not verify over the canonical command bytes; it may have "
                    "been issued for a different command",
                ),
                None,
            )

        if not self._nonces.consume(token.nonce):
            return (
                SignatureVerdict.reject(
                    SignatureFailure.NONCE_REPLAYED,
                    "token nonce has already been consumed; replay rejected",
                ),
                None,
            )

        return (
            SignatureVerdict.accept(),
            AuthorizedFieldCommand(
                command=command,
                operator_id=token.operator_id,
                role=token.role,
                key_id=token.key_id,
                fido2_credential_id=token.fido2_credential_id,
                verified_at=now,
                expires_at=token.expires_at,
                _issued_by_verifier=True,
            ),
        )


# --------------------------------------------------------------------------- #
# Layer 2 -- MAVLink2 message signing
# --------------------------------------------------------------------------- #

class MavlinkFailure(StrEnum):
    """Why a MAVLink frame was refused."""

    NOT_AUTHORIZED = "mavlink_not_authorized"
    AUTHORIZATION_EXPIRED = "mavlink_authorization_expired"
    AUTHORIZATION_MISMATCH = "mavlink_authorization_mismatch"
    UNSIGNED_FLAG = "mavlink_unsigned_flag"
    UNKNOWN_LINK = "mavlink_unknown_link"
    BAD_SIGNATURE = "mavlink_bad_signature"
    TIMESTAMP_REPLAY = "mavlink_timestamp_replay"
    TIMESTAMP_TOO_FAR_AHEAD = "mavlink_timestamp_too_far_ahead"
    MALFORMED = "mavlink_malformed"
    TIMESTAMP_EXHAUSTED = "mavlink_timestamp_exhausted"


@dataclass(frozen=True, slots=True)
class MavlinkVerdict:
    accepted: bool
    failure: MavlinkFailure | None = None
    detail: str = ""

    @classmethod
    def reject(cls, failure: MavlinkFailure, detail: str) -> MavlinkVerdict:
        return cls(accepted=False, failure=failure, detail=detail)


@dataclass(frozen=True, slots=True)
class MavlinkSigningKey:
    """A 32-byte per-link shared secret.

    Symmetric, so it authenticates the *link*, not a person. Both ends hold it, which
    is precisely why it cannot carry non-repudiation and why the operator token layer
    above exists.
    """

    link_id: int
    secret: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.link_id <= 0xFF:
            raise ValueError("link_id must fit one byte")
        if len(self.secret) != MAVLINK_SECRET_KEY_LEN:
            raise ValueError(
                f"MAVLink signing secret must be exactly {MAVLINK_SECRET_KEY_LEN} bytes, "
                f"got {len(self.secret)}"
            )


@dataclass(frozen=True, slots=True)
class MavlinkFrame:
    """The signable portion of a MAVLink2 packet.

    ``header`` is the 10-byte MAVLink2 header (STX through the 24-bit message id),
    ``payload`` the message body, ``checksum`` the 2-byte CRC. Those three plus the
    link id and timestamp are what the signature covers, per the MAVLink message-signing
    specification.
    """

    header: bytes
    payload: bytes
    checksum: bytes
    src_system: int
    src_component: int
    message_id: int

    def __post_init__(self) -> None:
        if len(self.header) != 10:
            raise ValueError("a MAVLink2 header is 10 bytes (STX through message id)")
        if len(self.checksum) != 2:
            raise ValueError("a MAVLink checksum is 2 bytes")
        if not 0 <= self.src_system <= 0xFF or not 0 <= self.src_component <= 0xFF:
            raise ValueError("system and component ids are single bytes")
        if self.header[0] != 0xFD:
            raise ValueError("MAVLink2 frames start with magic 0xFD")

    @property
    def incompat_flags(self) -> int:
        return self.header[2]

    @property
    def is_marked_signed(self) -> bool:
        return bool(self.incompat_flags & MAVLINK_IFLAG_SIGNED)

    @property
    def stream_key(self) -> tuple[int, int]:
        return (self.src_system, self.src_component)


@dataclass(frozen=True, slots=True)
class MavlinkSignatureBlock:
    """The 13 bytes appended to a signed MAVLink2 packet."""

    link_id: int
    timestamp: int
    signature: bytes

    def to_bytes(self) -> bytes:
        return (
            bytes([self.link_id])
            + self.timestamp.to_bytes(6, "little")
            + self.signature
        )

    @staticmethod
    def parse(raw: bytes) -> MavlinkSignatureBlock:
        if len(raw) != MAVLINK_SIGNATURE_LEN:
            raise ValueError(
                f"a MAVLink signature block is {MAVLINK_SIGNATURE_LEN} bytes, got {len(raw)}"
            )
        return MavlinkSignatureBlock(
            link_id=raw[0],
            timestamp=int.from_bytes(raw[1:7], "little"),
            signature=raw[7:],
        )


def _compute_signature(
    secret: bytes, frame: MavlinkFrame, link_id: int, timestamp: int
) -> bytes:
    """SHA-256 over secret || header || payload || CRC || link_id || timestamp, truncated.

    This is the MAVLink signing construction as specified. It is a prefix-keyed hash
    rather than an HMAC -- that is what the protocol defines, and interoperability with
    PX4/ArduPilot requires matching it exactly rather than substituting a construction
    that is better in the abstract.
    """
    digest = hashlib.sha256()
    digest.update(secret)
    digest.update(frame.header)
    digest.update(frame.payload)
    digest.update(frame.checksum)
    digest.update(bytes([link_id]))
    digest.update(timestamp.to_bytes(6, "little"))
    return digest.digest()[:MAVLINK_SIGNATURE_DIGEST_LEN]


class TimestampAuthority:
    """Monotonic 48-bit signing timestamps, per link and per source.

    Zero-Trust §4.3 requires a *"monotonic timestamp/sequence"* alongside the shared
    secret. Without it a captured frame replays forever: the signature stays valid
    because nothing about it is time-bound.

    State is kept per ``(link_id, src_system, src_component)`` because each stream has
    its own counter; sharing one counter across sources would let a chatty component
    starve a quiet one by advancing past it.
    """

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._last: dict[tuple[int, int, int], int] = {}

    def now_units(self) -> int:
        """Current time in MAVLink signing units (10 microseconds since 2015-01-01)."""
        elapsed = (self._clock() - MAVLINK_EPOCH).total_seconds()
        return max(0, int(elapsed / MAVLINK_TIMESTAMP_UNIT_S))

    def next_timestamp(self, link_id: int, stream: tuple[int, int]) -> int:
        """Allocate a timestamp strictly greater than the last one issued for this stream.

        If the clock has not advanced since the previous frame -- easy at high rates,
        since a unit is 10 microseconds -- the counter is stepped by one rather than
        reusing a value. A reused timestamp would be indistinguishable from a replay to
        the receiver.
        """
        key = (link_id, *stream)
        with self._lock:
            candidate = self.now_units()
            previous = self._last.get(key)
            if previous is not None and candidate <= previous:
                candidate = previous + 1
            if candidate > MAVLINK_MAX_TIMESTAMP:
                raise OverflowError(
                    "MAVLink signing timestamp space is exhausted for this link; "
                    "the link must be re-keyed rather than wrapped"
                )
            self._last[key] = candidate
            return candidate

    def accept_inbound(self, link_id: int, stream: tuple[int, int], timestamp: int) -> bool:
        """Record an inbound timestamp if it is strictly newer. ``False`` rejects a replay."""
        key = (link_id, *stream)
        with self._lock:
            previous = self._last.get(key)
            if previous is not None and timestamp <= previous:
                return False
            self._last[key] = timestamp
            return True


class MavlinkSigner:
    """Signs outbound MAVLink2 frames, and only authorized ones.

    :meth:`sign` takes an :class:`AuthorizedFieldCommand`, which can only come from
    :meth:`CommandTokenVerifier.verify`. There is no overload that signs without one,
    and no flag that skips the check.
    """

    def __init__(
        self,
        keys: dict[int, MavlinkSigningKey],
        *,
        timestamps: TimestampAuthority | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not keys:
            raise ValueError(
                "a signer with no link keys cannot sign anything; configure at least one"
            )
        self._keys = dict(keys)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._timestamps = timestamps or TimestampAuthority(clock=self._clock)

    def sign(
        self,
        frame: MavlinkFrame,
        *,
        authorization: AuthorizedFieldCommand,
        link_id: int,
    ) -> tuple[MavlinkVerdict, MavlinkSignatureBlock | None]:
        """Sign ``frame`` under ``link_id``. Never raises; a refusal is a verdict."""
        if not authorization._issued_by_verifier:
            # A hand-constructed AuthorizedFieldCommand did not come from a verified
            # token. Refusing it stops the capability being forged by a caller that
            # simply instantiates the dataclass.
            return (
                MavlinkVerdict.reject(
                    MavlinkFailure.NOT_AUTHORIZED,
                    "authorization was not produced by CommandTokenVerifier.verify",
                ),
                None,
            )

        now = self._clock()
        if not authorization.is_valid_at(now):
            return (
                MavlinkVerdict.reject(
                    MavlinkFailure.AUTHORIZATION_EXPIRED,
                    f"operator authorization expired at {authorization.expires_at.isoformat()}; "
                    "a command may not be signed on a lapsed authorization",
                ),
                None,
            )

        if frame.message_id != authorization.command.message_id:
            return (
                MavlinkVerdict.reject(
                    MavlinkFailure.AUTHORIZATION_MISMATCH,
                    f"frame carries message {frame.message_id} but the authorization names "
                    f"{authorization.command.message_id}",
                ),
                None,
            )

        if not frame.is_marked_signed:
            return (
                MavlinkVerdict.reject(
                    MavlinkFailure.UNSIGNED_FLAG,
                    "frame does not set MAVLINK_IFLAG_SIGNED; signing it would produce a "
                    "packet a receiver treats as unsigned",
                ),
                None,
            )

        key = self._keys.get(link_id)
        if key is None:
            return (
                MavlinkVerdict.reject(
                    MavlinkFailure.UNKNOWN_LINK, f"no signing key for link {link_id}"
                ),
                None,
            )

        try:
            timestamp = self._timestamps.next_timestamp(link_id, frame.stream_key)
        except OverflowError as exc:
            return (
                MavlinkVerdict.reject(MavlinkFailure.TIMESTAMP_EXHAUSTED, str(exc)),
                None,
            )

        signature = _compute_signature(key.secret, frame, link_id, timestamp)
        return (
            MavlinkVerdict(accepted=True),
            MavlinkSignatureBlock(link_id=link_id, timestamp=timestamp, signature=signature),
        )


class MavlinkVerifier:
    """Verifies inbound signed MAVLink2 frames (telemetry, and command echoes).

    Rejects, in order: an unsigned frame claiming to be signed, an unknown link, a
    timestamp too far ahead of local time, a bad signature, and a replayed timestamp.
    The replay check runs **last**, after the signature verifies, so a forged frame
    cannot advance a stream's counter and lock out the genuine sender.
    """

    def __init__(
        self,
        keys: dict[int, MavlinkSigningKey],
        *,
        timestamps: TimestampAuthority | None = None,
        clock: Callable[[], datetime] | None = None,
        max_future_units: int = MAVLINK_MAX_FUTURE_UNITS,
    ) -> None:
        self._keys = dict(keys)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._timestamps = timestamps or TimestampAuthority(clock=self._clock)
        self._max_future = max_future_units

    def verify(self, frame: MavlinkFrame, block: MavlinkSignatureBlock) -> MavlinkVerdict:
        if not frame.is_marked_signed:
            return MavlinkVerdict.reject(
                MavlinkFailure.UNSIGNED_FLAG,
                "frame carries a signature block without MAVLINK_IFLAG_SIGNED set",
            )

        if len(block.signature) != MAVLINK_SIGNATURE_DIGEST_LEN:
            return MavlinkVerdict.reject(
                MavlinkFailure.MALFORMED,
                f"signature must be {MAVLINK_SIGNATURE_DIGEST_LEN} bytes",
            )

        key = self._keys.get(block.link_id)
        if key is None:
            return MavlinkVerdict.reject(
                MavlinkFailure.UNKNOWN_LINK, f"no signing key for link {block.link_id}"
            )

        horizon = self._timestamps.now_units() + self._max_future
        if block.timestamp > horizon:
            return MavlinkVerdict.reject(
                MavlinkFailure.TIMESTAMP_TOO_FAR_AHEAD,
                "frame timestamp is further ahead than the permitted horizon; accepting it "
                "would let an attacker jump the counter and lock out the genuine sender",
            )

        expected = _compute_signature(key.secret, frame, block.link_id, block.timestamp)
        # Constant-time: the signature is a secret-derived value an attacker would
        # otherwise discover byte by byte through timing (Zero-Trust §10).
        if not hmac.compare_digest(expected, block.signature):
            return MavlinkVerdict.reject(
                MavlinkFailure.BAD_SIGNATURE, "MAVLink signature does not verify"
            )

        if not self._timestamps.accept_inbound(block.link_id, frame.stream_key, block.timestamp):
            return MavlinkVerdict.reject(
                MavlinkFailure.TIMESTAMP_REPLAY,
                "frame timestamp is not newer than the last accepted one for this stream",
            )

        return MavlinkVerdict(accepted=True)


def build_mavlink2_header(
    *,
    payload_len: int,
    sequence: int,
    src_system: int,
    src_component: int,
    message_id: int,
    signed: bool = True,
    compat_flags: int = 0,
) -> bytes:
    """Assemble a 10-byte MAVLink2 header.

    A helper for constructing frames to sign; it emits header bytes and nothing else --
    no framing onto a link, no transmission.
    """
    if not 0 <= payload_len <= 0xFF:
        raise ValueError("payload length must fit one byte")
    incompat = MAVLINK_IFLAG_SIGNED if signed else 0
    return struct.pack(
        "<BBBBBBB",
        0xFD,
        payload_len,
        incompat,
        compat_flags,
        sequence & 0xFF,
        src_system,
        src_component,
    ) + message_id.to_bytes(3, "little")
