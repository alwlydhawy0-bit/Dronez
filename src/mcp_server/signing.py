"""Command signature verification and replay rejection.

Closes ``TM-14`` (signature verification) and ``TM-15`` (nonce store).

Master Plan §5: *"every field command dispatched through the MCP server -- from
either the command room or a tactical field leader -- is signed with a short-lived
ECDSA/RSA token cryptographically bound to the issuing operator's FIDO2/WebAuthn
hardware security key. An unsigned or improperly-bound command is rejected before it
reaches the policy engine, not after."*

What a signature must prove
---------------------------
Four separate claims, each of which has its own failure mode:

1. **Authenticity** -- the bytes were signed by a key in the registry.
2. **Binding to the operator** -- that key belongs to *this* operator's FIDO2
   authenticator. A valid signature from someone else's key is not this operator's
   authorization.
3. **Binding to the decision** -- the signature covers the flight-plan digest and the
   approve/reject choice, so a signature captured from one approval cannot authorize
   a different plan.
4. **Freshness** -- inside its validity window, and its nonce not seen before.

Dropping any one of these leaves a usable attack. (3) is the subtle one: a signature
over "operator X approved something at time T" that does not name *what* was approved
is a signature an attacker can move between plans.

Algorithm handling
------------------
The verifier is always selected from an allow-list by the server; the ``algorithm``
field on a request *selects* a verifier the server already trusts and never supplies
one. There is no ``none`` member in :class:`SignatureAlgorithm` to begin with, so the
classic algorithm-confusion payload cannot be spelled (Zero-Trust §1.1).

``cryptography`` is an optional import. When it is unavailable the ES256/ES384
verifiers are **not silently skipped** -- they are absent from the registry, so a
request naming them is rejected with an explicit error rather than passing unverified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Protocol

from mcp_server.schemas.identity import (
    CommandSignature,
    OperatorIdentity,
    SignatureAlgorithm,
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

try:  # pragma: no cover - import guard, exercised by the availability test
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    CRYPTOGRAPHY_AVAILABLE = True
except Exception:  # pragma: no cover - environment without the optional dependency
    CRYPTOGRAPHY_AVAILABLE = False


class SignatureFailure(StrEnum):
    """Why a signature was rejected. Each maps to an auditable security event."""

    MISSING = "signature_missing"
    ALGORITHM_NOT_ALLOWED = "signature_algorithm_not_allowed"
    ALGORITHM_UNAVAILABLE = "signature_algorithm_unavailable"
    UNKNOWN_KEY = "signature_unknown_key"
    ALGORITHM_MISMATCH = "signature_algorithm_mismatch"
    NOT_BOUND_TO_OPERATOR = "signature_not_bound_to_operator"
    NOT_BOUND_TO_CREDENTIAL = "signature_not_bound_to_credential"
    EXPIRED = "signature_expired"
    NOT_YET_VALID = "signature_not_yet_valid"
    NONCE_REPLAYED = "signature_nonce_replayed"
    INVALID = "signature_invalid"
    MALFORMED = "signature_malformed"


@dataclass(frozen=True, slots=True)
class SignatureVerdict:
    """Outcome of verification. ``valid`` is true only on the single affirmative path."""

    valid: bool
    failure: SignatureFailure | None = None
    detail: str = ""

    @classmethod
    def reject(cls, failure: SignatureFailure, detail: str) -> SignatureVerdict:
        return cls(valid=False, failure=failure, detail=detail)


@dataclass(frozen=True, slots=True)
class VerificationKey:
    """A registered public key, bound to one operator and one authenticator.

    The binding fields are why this is not just a key store: verifying the maths
    proves someone signed, not that *this operator* signed.
    """

    key_id: str
    algorithm: SignatureAlgorithm
    #: DER/PEM-decoded public key object, or raw bytes for the HMAC dev algorithm.
    material: object
    operator_id: str
    fido2_credential_id: str


class KeyRegistry:
    """Known-key-set registry.

    A ``key_id`` is resolved here and **only** here. It never constructs a filesystem
    path, URL, or database query -- the ``kid``-injection defence from Zero-Trust §1.1.
    """

    def __init__(self, keys: tuple[VerificationKey, ...] = ()) -> None:
        self._keys: dict[str, VerificationKey] = {}
        for key in keys:
            self.register(key)

    def register(self, key: VerificationKey) -> None:
        if not key.key_id:
            raise ValueError("a verification key needs a key_id")
        if not key.operator_id or not key.fido2_credential_id:
            raise ValueError(
                "a verification key must be bound to an operator and a FIDO2 credential; "
                "an unbound key proves someone signed, not who"
            )
        self._keys[key.key_id] = key

    def get(self, key_id: str) -> VerificationKey | None:
        return self._keys.get(key_id)

    def __len__(self) -> int:
        return len(self._keys)


class NonceStore:
    """Single-use nonce store with a bounded TTL. Closes ``TM-15``.

    Zero-Trust §5.1 requires that a receiver *"persists consumed nonces to reject exact
    replays even within the window."* A validity window alone is not replay protection:
    inside it, the same signed bytes are replayable as many times as an attacker likes.

    Entries are retained for the signature lifetime plus a clock-skew allowance, then
    pruned. Retaining them for less would reopen the window; retaining them forever
    would be an unbounded structure, so the TTL is tied to the maximum signature
    lifetime rather than chosen independently.
    """

    #: Max signature lifetime (Zero-Trust §1.1 caps short-lived credentials at 300s)
    #: plus an NTP-skew allowance on both ends.
    DEFAULT_TTL_S: Final[float] = 300.0 + 120.0

    def __init__(
        self,
        *,
        ttl_s: float = DEFAULT_TTL_S,
        max_entries: int = 1 << 16,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._ttl = timedelta(seconds=ttl_s)
        self._max_entries = max_entries
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._seen: dict[str, datetime] = {}

    def consume(self, nonce: str) -> bool:
        """Record ``nonce`` as used. Returns ``False`` if it was already consumed.

        Check-and-record happen under one lock so two concurrent replays cannot both
        observe the nonce as unused.
        """
        if not nonce:
            return False
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            if nonce in self._seen:
                return False
            if len(self._seen) >= self._max_entries:
                # At capacity we refuse rather than evict. Evicting the oldest entry
                # would make that nonce replayable again, which is precisely the
                # property this store exists to prevent -- so pressure here degrades
                # availability, never replay protection.
                return False
            self._seen[nonce] = now
            return True

    def _prune_locked(self, now: datetime) -> None:
        cutoff = now - self._ttl
        expired = [n for n, seen_at in self._seen.items() if seen_at <= cutoff]
        for nonce in expired:
            del self._seen[nonce]

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


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


class _AlgorithmVerifier(Protocol):
    def __call__(self, key: VerificationKey, signed: bytes, signature: bytes) -> bool:
        ...


def _verify_hmac_sha256(key: VerificationKey, signed: bytes, signature: bytes) -> bool:
    """Development-only symmetric algorithm.

    Present so the full confirmation path can be exercised without hardware keys. It
    is **not** on :data:`SignatureAlgorithm`, so it can never be selected by a request
    -- only by a test or dev deployment that registers such a key deliberately.
    """
    material = key.material
    if not isinstance(material, (bytes, bytearray)):
        return False
    expected = hmac.new(bytes(material), signed, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def _verify_ecdsa(curve_hash: hashes.HashAlgorithm) -> _AlgorithmVerifier:
    def verify(key: VerificationKey, signed: bytes, signature: bytes) -> bool:
        public = key.material
        if not isinstance(public, ec.EllipticCurvePublicKey):
            return False
        try:
            public.verify(signature, signed, ec.ECDSA(curve_hash))
        except InvalidSignature:
            return False
        except Exception:
            return False
        return True

    return verify


def _verify_rsa_pkcs1(key: VerificationKey, signed: bytes, signature: bytes) -> bool:
    public = key.material
    if not isinstance(public, rsa.RSAPublicKey):
        return False
    try:
        public.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def _verify_rsa_pss(key: VerificationKey, signed: bytes, signature: bytes) -> bool:
    public = key.material
    if not isinstance(public, rsa.RSAPublicKey):
        return False
    try:
        public.verify(
            signature,
            signed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def _build_verifier_table() -> dict[SignatureAlgorithm, _AlgorithmVerifier]:
    """Algorithms this build can actually verify.

    An algorithm absent from this table is rejected with
    :attr:`SignatureFailure.ALGORITHM_UNAVAILABLE` rather than skipped -- the same
    fail-closed treatment the NFZ channel gives an unimplemented ``ed25519``.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        return {}
    return {
        SignatureAlgorithm.ES256: _verify_ecdsa(hashes.SHA256()),
        SignatureAlgorithm.ES384: _verify_ecdsa(hashes.SHA384()),
        SignatureAlgorithm.RS256: _verify_rsa_pkcs1,
        SignatureAlgorithm.PS256: _verify_rsa_pss,
    }


#: Symmetric dev algorithm, keyed off a sentinel that no request can name.
DEV_HMAC_ALGORITHM: Final[str] = "dev-hmac-sha256"


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
        self._verifiers = _build_verifier_table()

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

        verifier = self._verifiers.get(signature.algorithm)
        if verifier is None:
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

        if not verifier(key, signed, raw_signature):
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
        return frozenset(self._verifiers)
