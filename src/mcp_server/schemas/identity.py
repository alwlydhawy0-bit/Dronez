"""Operator identity, command signing, and the cryptographic role precedence matrix.

Master Plan §5 requires that *"every field command dispatched through the MCP
server -- from either the command room or a tactical field leader -- is signed with
a short-lived ECDSA/RSA token cryptographically bound to the issuing operator's
FIDO2/WebAuthn hardware security key. An unsigned or improperly-bound command is
rejected before it reaches the policy engine, not after."*

This module defines the shapes that make that enforceable. It deliberately does
**not** verify signatures: verification needs key material and a clock, and lives
in the server's crypto boundary. What lives here is the guarantee that an unsigned
command cannot even be *constructed* as a dispatchable request -- the type system
carries the requirement, so it cannot be forgotten at a call site.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Annotated, Self

from pydantic import Field, model_validator

from mcp_server.schemas.base import StrictModel

__all__ = [
    "ALLOWED_SIGNATURE_ALGORITHMS",
    "CommandSignature",
    "OperatorIdentity",
    "Role",
    "SignatureAlgorithm",
    "SignedCommandEnvelope",
    "Tier",
    "can_override",
]


class Tier(IntEnum):
    """Precedence tier. **Lower value means higher authority.**

    Comparing tiers with ``<`` therefore reads as "outranks", which is the whole
    point of using an ``IntEnum`` here rather than free-form strings that invite
    an accidental string comparison.
    """

    COMMAND_ROOM = 1
    FIELD_LEADER = 2
    AI_AGENT = 3


class Role(StrEnum):
    """Issuing role. Maps 1:1 onto a :class:`Tier`."""

    COMMAND_ROOM = "command_room"
    FIELD_LEADER = "field_leader"
    AI_AGENT = "ai_agent"

    @property
    def tier(self) -> Tier:
        return _ROLE_TIER[self]


_ROLE_TIER: dict[Role, Tier] = {
    Role.COMMAND_ROOM: Tier.COMMAND_ROOM,
    Role.FIELD_LEADER: Tier.FIELD_LEADER,
    Role.AI_AGENT: Tier.AI_AGENT,
}


def can_override(actor: Role, target: Role) -> bool:
    """Whether ``actor`` may cancel or override a command issued by ``target``.

    The Precedence Matrix from Master Plan §5, as executable code:

    =================  ===========================================
    Tier               May override
    =================  ===========================================
    1 Command Room     any Tier 2 or Tier 3 command
    2 Field Leader     Tier 3 only; never the Command Room
    3 AI Agent         **nothing**, regardless of stated urgency
    =================  ===========================================

    Two properties are load-bearing and are asserted by tests:

    * The AI agent can never override anything, **including another agent
      proposal**. An agent that could cancel its own earlier proposal could
      launder a rejected plan into an accepted one.
    * Authority is strictly by tier, never by recency. A later command does not
      win by virtue of arriving second.
    """
    if actor is Role.AI_AGENT:
        return False
    return actor.tier < target.tier


class SignatureAlgorithm(StrEnum):
    """Allow-listed command-signing algorithms.

    This enum *selects* a verifier the server already trusts; it never supplies
    one. There is deliberately no ``none`` member -- the classic algorithm-confusion
    payload cannot even be spelled (Zero-Trust §1.1).
    """

    ES256 = "ES256"
    ES384 = "ES384"
    RS256 = "RS256"
    PS256 = "PS256"


ALLOWED_SIGNATURE_ALGORITHMS: frozenset[str] = frozenset(a.value for a in SignatureAlgorithm)

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"

OperatorId = Annotated[str, Field(min_length=3, max_length=64, pattern=_ID_PATTERN)]
SessionId = Annotated[str, Field(min_length=8, max_length=128, pattern=_ID_PATTERN)]


class OperatorIdentity(StrictModel):
    """The authenticated principal behind a command.

    ``role`` is **server-derived from the authenticated session**, never taken from
    a request body or from anything the agent claims. A request that could set its
    own role would make the precedence matrix decorative.
    """

    operator_id: OperatorId
    role: Role
    #: Credential ID of the FIDO2/WebAuthn authenticator that backs this session.
    #: Required for the two human tiers: Zero-Trust §1.1 mandates hardware MFA for
    #: tactical operations, and §5 binds the command signature to this key.
    fido2_credential_id: Annotated[str | None, Field(max_length=256)] = None
    #: ``IncidentZone`` IDs this principal is authorized against. Scoping is never
    #: fleet-wide (Master Plan §4 trust boundaries).
    authorized_zone_ids: Annotated[frozenset[str], Field(max_length=64)] = frozenset()

    @model_validator(mode="after")
    def _human_tiers_require_hardware_mfa(self) -> Self:
        if self.role is not Role.AI_AGENT and not self.fido2_credential_id:
            raise ValueError(
                f"role {self.role.value!r} requires a FIDO2 credential: hardware MFA is "
                "mandatory for tactical operations (Zero-Trust 1.1)"
            )
        if self.role is Role.AI_AGENT and self.fido2_credential_id:
            raise ValueError(
                "an AI agent identity must not carry a FIDO2 credential; an agent "
                "cannot hold a human's hardware authenticator"
            )
        return self

    @property
    def tier(self) -> Tier:
        return self.role.tier

    def is_authorized_for(self, incident_zone_id: str) -> bool:
        return incident_zone_id in self.authorized_zone_ids


class CommandSignature(StrictModel):
    """Short-lived non-repudiation token bound to the issuer's hardware key."""

    algorithm: SignatureAlgorithm
    #: Resolved against a known-key registry only -- never used to build a path,
    #: URL, or database lookup (the ``kid``-injection defence, Zero-Trust §1.1).
    key_id: Annotated[str, Field(min_length=3, max_length=128, pattern=_ID_PATTERN)]
    #: Credential ID of the FIDO2 authenticator the signing key is bound to. Must
    #: match the issuing identity, or the signature is not *that operator's*.
    fido2_credential_id: Annotated[str, Field(min_length=1, max_length=256)]
    value: Annotated[str, Field(min_length=16, max_length=2048)]
    signed_at: datetime
    expires_at: datetime
    #: Single-use nonce. Persisted on consumption so an exact replay is rejected
    #: even inside the validity window (Zero-Trust §5.1 generalized replay protection).
    nonce: Annotated[str, Field(min_length=16, max_length=128)]

    @model_validator(mode="after")
    def _window_is_sane(self) -> Self:
        if self.expires_at <= self.signed_at:
            raise ValueError("signature expires_at must be after signed_at")
        if (self.expires_at - self.signed_at).total_seconds() > 300:
            raise ValueError(
                "command signature lifetime exceeds the 300s maximum for short-lived "
                "S2S credentials (Zero-Trust 1.1)"
            )
        if self.signed_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("signature timestamps must carry an explicit UTC offset")
        return self

    def is_valid_at(self, when: datetime) -> bool:
        return self.signed_at <= when < self.expires_at


class SignedCommandEnvelope(StrictModel):
    """Wrapper proving a command was issued by a human tier with a bound signature.

    A dispatchable command carries one of these. An AI agent cannot construct one:
    :meth:`_agent_cannot_sign` rejects it, because a Tier-3 proposal is a *proposal*
    and must be authorized by a human before anything reaches hardware.
    """

    issuer: OperatorIdentity
    signature: CommandSignature
    #: Binds the signature to one mission, so a token minted for mission A cannot
    #: be presented against mission B.
    mission_id: Annotated[str, Field(min_length=3, max_length=64)]

    @model_validator(mode="after")
    def _agent_cannot_sign(self) -> Self:
        if self.issuer.role is Role.AI_AGENT:
            raise ValueError(
                "an AI agent proposal cannot carry a command signature; Tier 3 "
                "proposes and a human tier disposes (Master Plan Sec.5 precedence matrix)"
            )
        if self.signature.fido2_credential_id != self.issuer.fido2_credential_id:
            raise ValueError(
                "signature is not bound to the issuing operator's FIDO2 credential"
            )
        return self
