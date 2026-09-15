"""Authorization primitives shared across the server, the policy engine and the bridge.

Stdlib only. The Rego bundle mirrors :mod:`dronez.authz.precedence` and is
machine-checked against it, so the three enforcement points cannot drift apart.
"""

from dronez.authz.precedence import (
    PRECEDENCE_MATRIX,
    ROLE_TIER,
    Role,
    SupersessionAttempt,
    Tier,
    can_override,
    classify_supersession,
    may_issue_field_command,
)

__all__ = [
    "PRECEDENCE_MATRIX",
    "ROLE_TIER",
    "Role",
    "SupersessionAttempt",
    "Tier",
    "can_override",
    "classify_supersession",
    "may_issue_field_command",
]
