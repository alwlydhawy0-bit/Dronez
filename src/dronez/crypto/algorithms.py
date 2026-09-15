"""Signature algorithms and detached verification.

Why this lives in ``dronez`` rather than in the server
-----------------------------------------------------
Two components verify operator command signatures: the MCP server (before it
authorizes anything) and the ROS2/MAVLink bridge (before it signs a frame for the
airframe). They must agree exactly. Two implementations of a signature check drift,
and the one that is wrong is the one nobody is looking at -- so there is one
implementation, here, in a package neither side owns.

It is also why the bridge does not import from ``mcp_server``: the bridge is deployed
on or beside the airframe and must not pull the server's web stack onto it.

Algorithm selection
-------------------
The ``algorithm`` field on a request *selects* a verifier the receiver already trusts;
it never supplies one. :class:`SignatureAlgorithm` has no ``none`` member, so the
classic algorithm-confusion payload cannot be spelled at all (Zero-Trust §1.1).

``cryptography`` is an optional dependency. When it is absent the asymmetric verifiers
are **not silently skipped** -- they are absent from the table, and a request naming
one is rejected with :attr:`SignatureFailure.ALGORITHM_UNAVAILABLE`. An unverifiable
signature is never an accepted signature.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Protocol

__all__ = [
    "ALLOWED_SIGNATURE_ALGORITHMS",
    "CRYPTOGRAPHY_AVAILABLE",
    "AlgorithmVerifier",
    "SignatureAlgorithm",
    "available_algorithms",
    "verify_detached",
]

try:  # pragma: no cover - import guard, covered by the availability test
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    CRYPTOGRAPHY_AVAILABLE = True
except Exception:  # pragma: no cover - environment without the optional dependency
    CRYPTOGRAPHY_AVAILABLE = False


class SignatureAlgorithm(StrEnum):
    """Allow-listed operator command-signing algorithms.

    Deliberately no ``none``, and deliberately no symmetric option: a command signature
    is a *non-repudiation* token, and a shared secret cannot prove which of the parties
    holding it signed.
    """

    ES256 = "ES256"
    ES384 = "ES384"
    RS256 = "RS256"
    PS256 = "PS256"


ALLOWED_SIGNATURE_ALGORITHMS: Final[frozenset[str]] = frozenset(
    a.value for a in SignatureAlgorithm
)


class AlgorithmVerifier(Protocol):
    """Verifies ``signature`` over ``signed`` using ``public_key``."""

    def __call__(self, public_key: object, signed: bytes, signature: bytes) -> bool:
        ...


def _ecdsa(curve_hash: object) -> AlgorithmVerifier:
    def verify(public_key: object, signed: bytes, signature: bytes) -> bool:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        try:
            public_key.verify(signature, signed, ec.ECDSA(curve_hash))  # type: ignore[arg-type]
        except InvalidSignature:
            return False
        except Exception:
            return False
        return True

    return verify


def _rsa_pkcs1(public_key: object, signed: bytes, signature: bytes) -> bool:
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    try:
        public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def _rsa_pss(public_key: object, signed: bytes, signature: bytes) -> bool:
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    try:
        public_key.verify(
            signature,
            signed,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def _build_table() -> dict[SignatureAlgorithm, AlgorithmVerifier]:
    if not CRYPTOGRAPHY_AVAILABLE:
        return {}
    return {
        SignatureAlgorithm.ES256: _ecdsa(hashes.SHA256()),
        SignatureAlgorithm.ES384: _ecdsa(hashes.SHA384()),
        SignatureAlgorithm.RS256: _rsa_pkcs1,
        SignatureAlgorithm.PS256: _rsa_pss,
    }


_VERIFIERS: Final[dict[SignatureAlgorithm, AlgorithmVerifier]] = _build_table()


def available_algorithms() -> frozenset[SignatureAlgorithm]:
    """Algorithms this build can actually verify."""
    return frozenset(_VERIFIERS)


def verify_detached(
    algorithm: SignatureAlgorithm, public_key: object, signed: bytes, signature: bytes
) -> bool:
    """Verify a detached signature. Returns ``False`` for anything unverifiable.

    Never raises: a malformed signature, a wrong key type, and an unavailable algorithm
    are all the same answer to the caller -- no.
    """
    verifier = _VERIFIERS.get(algorithm)
    if verifier is None:
        return False
    return verifier(public_key, signed, signature)
