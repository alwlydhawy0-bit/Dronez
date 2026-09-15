"""Known-key registry for operator command signatures.

Binding, not just keys
----------------------
Verifying the mathematics proves *someone* signed. It does not prove *this operator*
signed. A :class:`VerificationKey` therefore carries the operator and the FIDO2
authenticator it belongs to, and a registry entry cannot be created without both --
an unbound key would silently reduce non-repudiation to authenticity.
"""

from __future__ import annotations

from dataclasses import dataclass

from dronez.crypto.algorithms import SignatureAlgorithm

__all__ = ["KeyRegistry", "VerificationKey"]


@dataclass(frozen=True, slots=True)
class VerificationKey:
    """A registered public key, bound to one operator and one authenticator."""

    key_id: str
    algorithm: SignatureAlgorithm
    #: Public key object (``cryptography`` key type). Never a private key.
    material: object
    operator_id: str
    fido2_credential_id: str


class KeyRegistry:
    """Resolves a ``key_id`` to a registered key, and nothing else.

    A ``key_id`` is attacker-controlled text used for exactly one thing: a dictionary
    lookup. It never constructs a filesystem path, URL, or database query -- the
    ``kid``-injection defence from Zero-Trust §1.1.
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
        if key.material is None:
            raise ValueError("a verification key needs public key material")
        self._keys[key.key_id] = key

    def get(self, key_id: str) -> VerificationKey | None:
        return self._keys.get(key_id)

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, key_id: object) -> bool:
        return isinstance(key_id, str) and key_id in self._keys
