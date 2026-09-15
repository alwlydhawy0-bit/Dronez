"""Non-repudiation command signing at the airframe boundary.

The governing invariant: **a MAVLink frame cannot be signed without a verified operator
authorization that names that exact command.** Everything below is a way of trying to
get a signature without one.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from dronez.authz import Role
from dronez.crypto import KeyRegistry, NonceStore, SignatureFailure, VerificationKey
from dronez.crypto.algorithms import SignatureAlgorithm
from ros2_bridge.mavlink_signer import (
    MAVLINK_IFLAG_SIGNED,
    MAVLINK_SIGNATURE_LEN,
    AuthorizedFieldCommand,
    CommandTokenVerifier,
    FieldCommand,
    FieldCommandType,
    MavlinkFailure,
    MavlinkFrame,
    MavlinkSignatureBlock,
    MavlinkSigner,
    MavlinkSigningKey,
    MavlinkVerifier,
    OperatorToken,
    TimestampAuthority,
    build_mavlink2_header,
    canonical_field_command_bytes,
)

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
OPERATOR, CREDENTIAL, KEY_ID = "op-cr-001", "cred-cr-1", "key-cr-1"
MESSAGE_ID = 76  # COMMAND_LONG


class Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def signing_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def registry(signing_key: ec.EllipticCurvePrivateKey) -> KeyRegistry:
    return KeyRegistry((
        VerificationKey(
            key_id=KEY_ID,
            algorithm=SignatureAlgorithm.ES256,
            material=signing_key.public_key(),
            operator_id=OPERATOR,
            fido2_credential_id=CREDENTIAL,
        ),
    ))


@pytest.fixture
def command() -> FieldCommand:
    return FieldCommand(
        command_id="CMD-0001",
        command_type=FieldCommandType.MISSION_UPLOAD,
        mission_id="M-001",
        drone_id="D-1",
        parameters_sha256=hashlib.sha256(b"params").hexdigest(),
        message_id=MESSAGE_ID,
    )


def make_token(
    signing_key: ec.EllipticCurvePrivateKey,
    command: FieldCommand,
    *,
    operator_id: str = OPERATOR,
    credential: str = CREDENTIAL,
    key_id: str = KEY_ID,
    role: Role = Role.COMMAND_ROOM,
    nonce: str = "nonce-000000000001",
    issued_at: datetime = T0,
    lifetime_s: float = 120.0,
    sign_command: FieldCommand | None = None,
) -> OperatorToken:
    expires_at = issued_at + timedelta(seconds=lifetime_s)
    blob = canonical_field_command_bytes(
        sign_command or command,
        operator_id=operator_id,
        role=role,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    signature = signing_key.sign(blob, ec.ECDSA(hashes.SHA256()))
    return OperatorToken(
        algorithm=SignatureAlgorithm.ES256,
        key_id=key_id,
        fido2_credential_id=credential,
        value=signature.hex(),
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        operator_id=operator_id,
        role=role,
    )


def make_frame(*, message_id: int = MESSAGE_ID, signed: bool = True) -> MavlinkFrame:
    header = build_mavlink2_header(
        payload_len=4, sequence=7, src_system=1, src_component=1,
        message_id=message_id, signed=signed,
    )
    return MavlinkFrame(
        header=header, payload=b"\x01\x02\x03\x04", checksum=b"\xab\xcd",
        src_system=1, src_component=1, message_id=message_id,
    )


def verifier(registry: KeyRegistry, clock: Clock) -> CommandTokenVerifier:
    return CommandTokenVerifier(registry, NonceStore(clock=clock), clock=clock)


# --------------------------------------------------------------------------- #
# The operator token
# --------------------------------------------------------------------------- #

def test_valid_token_authorizes_the_command(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    verdict, authorized = verifier(registry, clock).verify(
        command, make_token(signing_key, command)
    )
    assert verdict.valid
    assert authorized is not None
    assert authorized.operator_id == OPERATOR
    assert authorized.role is Role.COMMAND_ROOM


def test_agent_token_is_refused_before_any_key_lookup(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """Tier 3 proposes; a human tier disposes.

    Refused on tier alone, so a compromised agent cannot use this path to probe the
    registry for valid key ids.
    """
    clock = Clock()
    verdict, authorized = verifier(registry, clock).verify(
        command, make_token(signing_key, command, role=Role.AI_AGENT)
    )
    assert not verdict.valid
    assert verdict.failure is SignatureFailure.TIER_NOT_PERMITTED
    assert authorized is None


def test_token_for_a_different_command_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """A signature that did not name this command cannot authorize it."""
    other = FieldCommand(
        command_id="CMD-0002",
        command_type=FieldCommandType.LAND,
        mission_id="M-001",
        drone_id="D-1",
        parameters_sha256=hashlib.sha256(b"other").hexdigest(),
        message_id=MESSAGE_ID,
    )
    clock = Clock()
    verdict, authorized = verifier(registry, clock).verify(
        command, make_token(signing_key, command, sign_command=other)
    )
    assert not verdict.valid
    assert verdict.failure is SignatureFailure.INVALID
    assert authorized is None


def test_token_for_a_different_drone_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """An authorization for one airframe must not move to another."""
    other_drone = FieldCommand(
        command_id=command.command_id,
        command_type=command.command_type,
        mission_id=command.mission_id,
        drone_id="D-99",
        parameters_sha256=command.parameters_sha256,
        message_id=command.message_id,
    )
    clock = Clock()
    verdict, _ = verifier(registry, clock).verify(
        command, make_token(signing_key, command, sign_command=other_drone)
    )
    assert not verdict.valid


def test_token_for_different_parameters_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """The digest commits to the exact parameters without the signer parsing them."""
    tampered = FieldCommand(
        command_id=command.command_id,
        command_type=command.command_type,
        mission_id=command.mission_id,
        drone_id=command.drone_id,
        parameters_sha256=hashlib.sha256(b"tampered").hexdigest(),
        message_id=command.message_id,
    )
    clock = Clock()
    verdict, _ = verifier(registry, clock).verify(
        command, make_token(signing_key, command, sign_command=tampered)
    )
    assert not verdict.valid


def test_unknown_key_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    verdict, _ = verifier(registry, clock).verify(
        command, make_token(signing_key, command, key_id="attacker-key")
    )
    assert verdict.failure is SignatureFailure.UNKNOWN_KEY


def test_key_belonging_to_another_operator_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """Verifying the maths proves someone signed, not that this operator signed."""
    clock = Clock()
    verdict, _ = verifier(registry, clock).verify(
        command, make_token(signing_key, command, operator_id="op-someone-else")
    )
    assert verdict.failure is SignatureFailure.NOT_BOUND_TO_OPERATOR
    assert verdict.failure.is_impersonation_signal


def test_wrong_fido2_credential_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    verdict, _ = verifier(registry, clock).verify(
        command, make_token(signing_key, command, credential="cred-other")
    )
    assert verdict.failure is SignatureFailure.NOT_BOUND_TO_CREDENTIAL


def test_expired_token_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    token = make_token(signing_key, command, lifetime_s=60.0)
    clock.advance(61)
    verdict, _ = verifier(registry, clock).verify(command, token)
    assert verdict.failure is SignatureFailure.EXPIRED


def test_overlong_lifetime_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """A "short-lived" credential valid for a day is not short-lived."""
    clock = Clock()
    verdict, _ = verifier(registry, clock).verify(
        command, make_token(signing_key, command, lifetime_s=86400.0)
    )
    assert verdict.failure is SignatureFailure.LIFETIME_TOO_LONG


def test_future_dated_token_beyond_skew_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    verdict, _ = verifier(registry, clock).verify(
        command, make_token(signing_key, command, issued_at=T0 + timedelta(hours=1))
    )
    assert verdict.failure is SignatureFailure.NOT_YET_VALID


def test_replayed_nonce_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    token_verifier = verifier(registry, clock)
    first, _ = token_verifier.verify(command, make_token(signing_key, command))
    assert first.valid
    second, authorized = token_verifier.verify(command, make_token(signing_key, command))
    assert second.failure is SignatureFailure.NONCE_REPLAYED
    assert authorized is None


def test_a_bad_signature_does_not_burn_the_nonce(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """Otherwise verification becomes a denial-of-service primitive.

    An attacker who could spend a legitimate operator's nonce with garbage would lock
    that operator out of issuing the command at all.
    """
    clock = Clock()
    token_verifier = verifier(registry, clock)
    forged = make_token(signing_key, command)
    forged = replace(forged, value="00" * 70)
    bad, _ = token_verifier.verify(command, forged)
    assert not bad.valid

    good, authorized = token_verifier.verify(command, make_token(signing_key, command))
    assert good.valid, "the legitimate token's nonce must still be available"
    assert authorized is not None


def test_malformed_signature_hex_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    token = make_token(signing_key, command)
    token = replace(token, value="not-hex")
    verdict, _ = verifier(registry, clock).verify(command, token)
    assert verdict.failure is SignatureFailure.MALFORMED


# --------------------------------------------------------------------------- #
# The binding: no signature without an authorization
# --------------------------------------------------------------------------- #

def test_signing_requires_a_verified_authorization(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """THE headline test for this module.

    A hand-constructed AuthorizedFieldCommand is refused, so the capability cannot be
    forged by a caller that simply instantiates the dataclass.
    """
    clock = Clock()
    signer = MavlinkSigner({1: MavlinkSigningKey(1, bytes(range(32)))}, clock=clock)
    forged = AuthorizedFieldCommand(
        command=command,
        operator_id=OPERATOR,
        role=Role.COMMAND_ROOM,
        key_id=KEY_ID,
        fido2_credential_id=CREDENTIAL,
        verified_at=T0,
        expires_at=T0 + timedelta(seconds=120),
    )
    verdict, block = signer.sign(make_frame(), authorization=forged, link_id=1)
    assert not verdict.accepted
    assert verdict.failure is MavlinkFailure.NOT_AUTHORIZED
    assert block is None


def test_authorized_command_is_signed(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    _, authorized = verifier(registry, clock).verify(command, make_token(signing_key, command))
    assert authorized is not None
    signer = MavlinkSigner({1: MavlinkSigningKey(1, bytes(range(32)))}, clock=clock)
    verdict, block = signer.sign(make_frame(), authorization=authorized, link_id=1)
    assert verdict.accepted
    assert block is not None
    assert len(block.to_bytes()) == MAVLINK_SIGNATURE_LEN


def test_expired_authorization_cannot_sign(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    _, authorized = verifier(registry, clock).verify(
        command, make_token(signing_key, command, lifetime_s=60.0)
    )
    assert authorized is not None
    clock.advance(61)
    signer = MavlinkSigner({1: MavlinkSigningKey(1, bytes(range(32)))}, clock=clock)
    verdict, block = signer.sign(make_frame(), authorization=authorized, link_id=1)
    assert verdict.failure is MavlinkFailure.AUTHORIZATION_EXPIRED
    assert block is None


def test_frame_must_match_the_authorized_message(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """An authorization for one message id cannot sign a different one."""
    clock = Clock()
    _, authorized = verifier(registry, clock).verify(command, make_token(signing_key, command))
    assert authorized is not None
    signer = MavlinkSigner({1: MavlinkSigningKey(1, bytes(range(32)))}, clock=clock)
    verdict, _ = signer.sign(
        make_frame(message_id=400), authorization=authorized, link_id=1
    )
    assert verdict.failure is MavlinkFailure.AUTHORIZATION_MISMATCH


def test_unsigned_flag_frame_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """Signing a frame a receiver treats as unsigned achieves nothing."""
    clock = Clock()
    _, authorized = verifier(registry, clock).verify(command, make_token(signing_key, command))
    assert authorized is not None
    signer = MavlinkSigner({1: MavlinkSigningKey(1, bytes(range(32)))}, clock=clock)
    verdict, _ = signer.sign(make_frame(signed=False), authorization=authorized, link_id=1)
    assert verdict.failure is MavlinkFailure.UNSIGNED_FLAG


def test_unknown_link_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    _, authorized = verifier(registry, clock).verify(command, make_token(signing_key, command))
    assert authorized is not None
    signer = MavlinkSigner({1: MavlinkSigningKey(1, bytes(range(32)))}, clock=clock)
    verdict, _ = signer.sign(make_frame(), authorization=authorized, link_id=9)
    assert verdict.failure is MavlinkFailure.UNKNOWN_LINK


def test_signer_with_no_keys_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="cannot sign anything"):
        MavlinkSigner({})


# --------------------------------------------------------------------------- #
# MAVLink2 message signing
# --------------------------------------------------------------------------- #

LINK_KEY = MavlinkSigningKey(1, bytes(range(32)))


def test_secret_key_length_is_enforced() -> None:
    """The MAVLink specification fixes this at 32 bytes."""
    with pytest.raises(ValueError, match="32 bytes"):
        MavlinkSigningKey(1, b"too-short")


def test_signature_block_is_thirteen_bytes_and_round_trips() -> None:
    block = MavlinkSignatureBlock(link_id=2, timestamp=123456789, signature=b"\x01" * 6)
    raw = block.to_bytes()
    assert len(raw) == MAVLINK_SIGNATURE_LEN
    assert MavlinkSignatureBlock.parse(raw) == block


def test_signature_block_rejects_a_wrong_length() -> None:
    with pytest.raises(ValueError, match="13 bytes"):
        MavlinkSignatureBlock.parse(b"\x00" * 12)


def test_header_sets_the_signed_flag() -> None:
    assert make_frame().incompat_flags & MAVLINK_IFLAG_SIGNED
    assert not (make_frame(signed=False).incompat_flags & MAVLINK_IFLAG_SIGNED)


def test_frame_rejects_a_non_mavlink2_magic() -> None:
    with pytest.raises(ValueError, match="0xFD"):
        MavlinkFrame(
            header=b"\xfe" + bytes(9), payload=b"", checksum=b"\x00\x00",
            src_system=1, src_component=1, message_id=1,
        )


def _sign_frame(clock: Clock, frame: MavlinkFrame, registry, command, signing_key, nonce: str):  # type: ignore[no-untyped-def]
    _, authorized = verifier(registry, clock).verify(
        command, make_token(signing_key, command, nonce=nonce)
    )
    assert authorized is not None
    signer = MavlinkSigner({1: LINK_KEY}, clock=clock)
    verdict, block = signer.sign(frame, authorization=authorized, link_id=1)
    assert verdict.accepted
    return block


def test_signed_frame_verifies(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    frame = make_frame()
    block = _sign_frame(clock, frame, registry, command, signing_key, "n-1")
    assert block is not None
    assert MavlinkVerifier({1: LINK_KEY}, clock=clock).verify(frame, block).accepted


def test_tampered_payload_fails_verification(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """The signature covers header, payload and CRC -- altering any of them breaks it."""
    clock = Clock()
    frame = make_frame()
    block = _sign_frame(clock, frame, registry, command, signing_key, "n-1")
    assert block is not None

    tampered = MavlinkFrame(
        header=frame.header, payload=b"\xff\xff\xff\xff", checksum=frame.checksum,
        src_system=1, src_component=1, message_id=frame.message_id,
    )
    verdict = MavlinkVerifier({1: LINK_KEY}, clock=clock).verify(tampered, block)
    assert verdict.failure is MavlinkFailure.BAD_SIGNATURE


def test_wrong_link_key_fails_verification(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    frame = make_frame()
    block = _sign_frame(clock, frame, registry, command, signing_key, "n-1")
    assert block is not None
    other = MavlinkSigningKey(1, bytes([0xAA]) * 32)
    verdict = MavlinkVerifier({1: other}, clock=clock).verify(frame, block)
    assert verdict.failure is MavlinkFailure.BAD_SIGNATURE


def test_replayed_frame_is_rejected(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """Zero-Trust §4.3: the monotonic timestamp is what stops a captured frame replaying.

    Without it the signature stays valid forever, because nothing about it is
    time-bound.
    """
    clock = Clock()
    frame = make_frame()
    block = _sign_frame(clock, frame, registry, command, signing_key, "n-1")
    assert block is not None

    receiver = MavlinkVerifier({1: LINK_KEY}, clock=clock)
    assert receiver.verify(frame, block).accepted
    replayed = receiver.verify(frame, block)
    assert replayed.failure is MavlinkFailure.TIMESTAMP_REPLAY


def test_forged_frame_cannot_advance_the_replay_counter(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    """The replay check runs after the signature check, deliberately.

    If it ran first, an attacker could send a far-future timestamp with a garbage
    signature and lock the genuine sender out of the stream.
    """
    clock = Clock()
    frame = make_frame()
    genuine = _sign_frame(clock, frame, registry, command, signing_key, "n-1")
    assert genuine is not None

    receiver = MavlinkVerifier({1: LINK_KEY}, clock=clock)
    forged = MavlinkSignatureBlock(
        link_id=1, timestamp=genuine.timestamp + 1_000, signature=b"\x00" * 6
    )
    assert receiver.verify(frame, forged).failure is MavlinkFailure.BAD_SIGNATURE
    assert receiver.verify(frame, genuine).accepted, (
        "a forged frame must not have advanced the counter past the genuine one"
    )


def test_far_future_timestamp_is_refused(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    frame = make_frame()
    receiver = MavlinkVerifier({1: LINK_KEY}, clock=clock)
    authority = TimestampAuthority(clock=clock)
    far = authority.now_units() + 10_000_000_000
    from ros2_bridge.mavlink_signer import _compute_signature

    block = MavlinkSignatureBlock(
        link_id=1, timestamp=far, signature=_compute_signature(LINK_KEY.secret, frame, 1, far)
    )
    assert receiver.verify(frame, block).failure is MavlinkFailure.TIMESTAMP_TOO_FAR_AHEAD


def test_unknown_link_fails_verification(registry, command, signing_key) -> None:  # type: ignore[no-untyped-def]
    clock = Clock()
    frame = make_frame()
    block = _sign_frame(clock, frame, registry, command, signing_key, "n-1")
    assert block is not None
    receiver = MavlinkVerifier({7: MavlinkSigningKey(7, bytes(32))}, clock=clock)
    verdict = receiver.verify(frame, block)
    assert verdict.failure is MavlinkFailure.UNKNOWN_LINK


def test_timestamps_are_monotonic_even_within_one_clock_tick() -> None:
    """A unit is 10 microseconds, so a frozen clock is easy to hit at rate.

    A reused timestamp is indistinguishable from a replay to the receiver.
    """
    clock = Clock()
    authority = TimestampAuthority(clock=clock)
    issued = [authority.next_timestamp(1, (1, 1)) for _ in range(50)]
    assert issued == sorted(issued)
    assert len(set(issued)) == 50


def test_streams_have_independent_counters() -> None:
    """Sharing one counter would let a chatty component starve a quiet one."""
    clock = Clock()
    authority = TimestampAuthority(clock=clock)
    for _ in range(10):
        authority.next_timestamp(1, (1, 1))
    assert authority.accept_inbound(1, (1, 2), 5) is True


def test_module_has_no_transport() -> None:
    """The Milestone-0 gate forbids code that commands hardware.

    A signing primitive is a security control; keeping it transport-free is what makes
    that distinction checkable rather than asserted.
    """
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[2] / "src/ros2_bridge/mavlink_signer.py"
    ).read_text(encoding="utf-8")
    code = "\n".join(line.split("#")[0] for line in source.splitlines())
    forbidden_imports = (
        "import socket", "import serial", "pymavlink", "rclpy", "asyncio", "requests",
    )
    for forbidden in forbidden_imports:
        assert forbidden not in code, f"{forbidden} has no place in a signing module"
