"""Verification failure taxonomy shared by the server and the airframe bridge.

Every member is an auditable security event, and the set is deliberately fine-grained:
"signature invalid" and "key belongs to a different operator" are both rejections, but
only one of them means somebody presented another person's authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = ["SignatureFailure", "SignatureVerdict"]


class SignatureFailure(StrEnum):
    MISSING = "signature_missing"
    ALGORITHM_NOT_ALLOWED = "signature_algorithm_not_allowed"
    ALGORITHM_UNAVAILABLE = "signature_algorithm_unavailable"
    UNKNOWN_KEY = "signature_unknown_key"
    ALGORITHM_MISMATCH = "signature_algorithm_mismatch"
    NOT_BOUND_TO_OPERATOR = "signature_not_bound_to_operator"
    NOT_BOUND_TO_CREDENTIAL = "signature_not_bound_to_credential"
    EXPIRED = "signature_expired"
    NOT_YET_VALID = "signature_not_yet_valid"
    LIFETIME_TOO_LONG = "signature_lifetime_too_long"
    NONCE_REPLAYED = "signature_nonce_replayed"
    SUBJECT_MISMATCH = "signature_subject_mismatch"
    TIER_NOT_PERMITTED = "signature_tier_not_permitted"
    INVALID = "signature_invalid"
    MALFORMED = "signature_malformed"

    @property
    def is_impersonation_signal(self) -> bool:
        """Failures that suggest someone is presenting an authorization not their own.

        These warrant a security review rather than a retry prompt: a wrong-operator or
        wrong-credential binding is not a typo.
        """
        return self in {
            SignatureFailure.NOT_BOUND_TO_OPERATOR,
            SignatureFailure.NOT_BOUND_TO_CREDENTIAL,
            SignatureFailure.NONCE_REPLAYED,
            SignatureFailure.SUBJECT_MISMATCH,
            SignatureFailure.TIER_NOT_PERMITTED,
        }


@dataclass(frozen=True, slots=True)
class SignatureVerdict:
    """Result of verification. ``valid`` is true only on the affirmative path."""

    valid: bool
    failure: SignatureFailure | None = None
    detail: str = ""

    @classmethod
    def reject(cls, failure: SignatureFailure, detail: str) -> SignatureVerdict:
        return cls(valid=False, failure=failure, detail=detail)

    @classmethod
    def accept(cls) -> SignatureVerdict:
        return cls(valid=True)
