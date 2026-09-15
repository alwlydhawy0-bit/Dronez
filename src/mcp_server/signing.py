"""Operator command-signature verification for the MCP server.

Closes ``TM-14``. The cryptographic primitives live in :mod:`dronez.crypto`, shared
with the airframe-side bridge; what is here is the part specific to *this* server's
decisions -- the canonical bytes a confirmation covers, and the order in which the
checks run.

What a signature must prove
---------------------------
Four separate claims, each with its own failure mode:

1. **Authenticity** -- the bytes were signed by a key in the registry.
2. **Binding to the operator** -- that key belongs to *this* operator's FIDO2
   authenticator. A valid signature from someone else's key is not this operator's
   authorization.
3. **Binding to the decision** -- the signature covers the flight-plan digest and the
   approve/reject choice, so a signature captured from one approval cannot authorize
   a different plan.
4. **Freshness** -- inside its validity window, and its nonce not seen before.

Dropping any one leaves a usable attack. (3) is the subtle one: a signature over
"operator X approved something at time T" that does not name *what* was approved is a
signature an attacker can move between plans.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from dronez.crypto import (
    CRYPTOGRAPHY_AVAILABLE,
    KeyRegistry,
    NonceStore,
    SignatureAlgorithm,
    SignatureFailure,
    SignatureVerdict,
    VerificationKey,
    available_algorithms,
    verify_detached,
)
from mcp_server.schemas.identity import (
    CommandSignature,
    OperatorIdentity,
    SignedCommandEnvelope,
)

__all__ = [
    "CRYPTOGRAPHY_AVAILABLE",
    "KeyRegistry",
    "NonceStore",
    "SignatureFailure",
    "SignatureVerdict",
    "SignatureVerifier",
    "VerificationKey",
    "canonical_authorization_bytes",
]


def canonical_authorization_bytes(
    *,
    flight_plan_id: str,
    flight_plan_digest: str,
    decision: str,
    mission_id: str,
    operator_id: str,
    nonce: str,
    signed_at: datetime,
    expires_at: datetime,
) -> bytes:
    """Deterministic bytes a confirmation signature covers.

    Every field that changes the meaning of the authorization is inside the signed
    bytes. In particular ``flight_plan_digest`` and ``decision``: without them a
    captured signature could be replayed against a different plan, or an approval
    reused to mean a rejection.
    """
    payload = {
        "v": 1,
        "typ": "confirm_flight_plan",
        "flight_plan_id": flight_plan_id,
        "flight_plan_digest": flight_plan_digest,
        "decision": decision,
        "mission_id": mission_id,
        "operator_id": operator_id,
        "nonce": nonce,
        "signed_at": signed_at.astimezone(UTC).isoformat(),
        "expires_at": expires_at.astimezone(UTC).isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SignatureVerifier:
    """Verifies a confirmation authorization end to end.

    Order matters: cheap structural checks first, the cryptographic check last, and
    the nonce consumed **only after** the signature verifies. Consuming a nonce before
    verification would let an attacker burn a legitimate operator's nonce with a
    garbage signature, turning verification into a denial-of-service primitive.
    """

    def __init__(
        self,
        registry: KeyRegistry,
        nonce_store: NonceStore,
        *,
        clock: Callable[[], datetime] | None = None,
        clock_skew_s: float = 60.0,
    ) -> None:
        self._registry = registry
        self._nonces = nonce_store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._skew = timedelta(seconds=clock_skew_s)

    def verify_confirmation(
        self,
        envelope: SignedCommandEnvelope,
        *,
        flight_plan_id: str,
        flight_plan_digest: str,
        decision: str,
    ) -> SignatureVerdict:
        """Verify an authorization for one specific plan and decision."""
        signature: CommandSignature = envelope.signature
        issuer: OperatorIdentity = envelope.issuer

        key = self._registry.get(signature.key_id)
        if key is None:
            return SignatureVerdict.reject(
                SignatureFailure.UNKNOWN_KEY,
                f"key_id {signature.key_id!r} is not in the registry",
            )
        if key.algorithm is not signature.algorithm:
            return SignatureVerdict.reject(
                SignatureFailure.ALGORITHM_MISMATCH,
                f"key {signature.key_id!r} is registered for {key.algorithm.value}, "
                f"request claims {signature.algorithm.value}",
            )
        if key.operator_id != issuer.operator_id:
            return SignatureVerdict.reject(
                SignatureFailure.NOT_BOUND_TO_OPERATOR,
                f"key {signature.key_id!r} belongs to a different operator; a valid "
                "signature from another key is not this operator's authorization",
            )
        if key.fido2_credential_id != signature.fido2_credential_id:
            return SignatureVerdict.reject(
                SignatureFailure.NOT_BOUND_TO_CREDENTIAL,
                "signature is not bound to the registered FIDO2 authenticator",
            )

        now = self._clock()
        if now >= signature.expires_at:
            return SignatureVerdict.reject(
                SignatureFailure.EXPIRED,
                f"signature expired at {signature.expires_at.isoformat()}",
            )
        if now + self._skew < signature.signed_at:
            return SignatureVerdict.reject(
                SignatureFailure.NOT_YET_VALID,
                "signature is dated further in the future than the permitted clock skew",
            )

        if signature.algorithm not in available_algorithms():
            return SignatureVerdict.reject(
                SignatureFailure.ALGORITHM_UNAVAILABLE,
                f"algorithm {signature.algorithm.value} is allow-listed but not available "
                "in this build; failing closed rather than accepting it unverified",
            )

        try:
            raw_signature = bytes.fromhex(signature.value)
        except ValueError:
            return SignatureVerdict.reject(
                SignatureFailure.MALFORMED, "signature value is not valid hex"
            )

        signed = canonical_authorization_bytes(
            flight_plan_id=flight_plan_id,
            flight_plan_digest=flight_plan_digest,
            decision=decision,
            mission_id=envelope.mission_id,
            operator_id=issuer.operator_id,
            nonce=signature.nonce,
            signed_at=signature.signed_at,
            expires_at=signature.expires_at,
        )

        if not verify_detached(signature.algorithm, key.material, signed, raw_signature):
            return SignatureVerdict.reject(
                SignatureFailure.INVALID,
                "signature does not verify over the canonical authorization bytes",
            )

        # Only now, with a proven-good signature, is the nonce spent. See the class
        # docstring for why this ordering matters.
        if not self._nonces.consume(signature.nonce):
            return SignatureVerdict.reject(
                SignatureFailure.NONCE_REPLAYED,
                "signature nonce has already been consumed; replay rejected",
            )

        return SignatureVerdict(valid=True)

    @property
    def available_algorithms(self) -> frozenset[SignatureAlgorithm]:
        """Algorithms this build can verify. Empty means every signature is rejected."""
        return frozenset(available_algorithms())
