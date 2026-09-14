"""Safety-envelope regression gates.

These tests exist to make a silent relaxation of a safety decision impossible.
If one fails, the correct response is to update ``CLAUDE.md`` deliberately - not
to update the expected value to match the code.
"""

from __future__ import annotations

import re
from dataclasses import fields
from pathlib import Path

import pytest

from dronez.safety.envelope import (
    ENFORCEMENT,
    ENVELOPE,
    PROHIBITED_CAPABILITIES,
    SIGN_OFF,
    EnforcementLocus,
    EnvelopeConsistencyError,
    SafetyEnvelope,
    envelope_digest,
    validate_envelope,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"


def test_envelope_is_self_consistent() -> None:
    validate_envelope()


def test_every_constant_has_a_recorded_enforcement_locus() -> None:
    """A bound with no recorded locus is undocumented drift. Master Plan Sec.6."""
    declared = {f.name for f in fields(ENVELOPE)}
    assert declared == set(ENFORCEMENT), (
        "safety constants and their enforcement registry have diverged: "
        f"{declared ^ set(ENFORCEMENT)}"
    )


def test_no_kinetic_bound_is_enforced_only_at_the_server() -> None:
    """Master Plan Sec.2: a server outage must degrade capability, never safety."""
    offenders = [
        name
        for name, bound in ENFORCEMENT.items()
        if bound.kinetic and bound.locus is EnforcementLocus.SERVER
    ]
    assert not offenders, (
        f"kinetic bounds {offenders} are enforced only at the MCP server; they must "
        "be enforced onboard (firmware or companion computer)"
    )


def test_every_bound_records_a_rationale_and_source() -> None:
    for name, bound in ENFORCEMENT.items():
        assert bound.rationale.strip(), f"{name} has no rationale"
        assert bound.source.strip(), f"{name} has no source citation"


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"altitude_min_agl_m": 200.0}, "altitude floor"),
        ({"battery_rtl_trigger_pct": 5.0}, "battery thresholds"),
        ({"battery_range_reserve_factor": 1.0}, "range reserve"),
        ({"degraded_descent_rate_mps": 9.0}, "degraded-landing descent"),
        ({"nfz_clearance_validity_s": 99_999.0}, "clearance may not outlive"),
        ({"agent_proposals_per_second": 0.0}, "must be positive"),
    ],
)
def test_incoherent_envelope_fails_closed(overrides: dict, expected: str) -> None:
    """An incoherent envelope must raise at construction, never be silently used."""
    with pytest.raises(EnvelopeConsistencyError, match=expected):
        validate_envelope(SafetyEnvelope(**overrides))


def test_recon_only_prohibitions_are_declared() -> None:
    """Master Plan Sec.3: no payload-release or offensive capability, at any phase."""
    for capability in ("payload_release", "weapon_release", "target_engagement"):
        assert capability in PROHIBITED_CAPABILITIES


def test_no_prohibited_capability_appears_as_a_tool_or_symbol() -> None:
    """Release gate: the prohibitions are asserted against the source, not just declared."""
    offenders: list[str] = []
    for path in (REPO_ROOT / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for capability in PROHIBITED_CAPABILITIES:
            # Match a definition or call site, not a mention inside the prohibition
            # list or a docstring explaining what is forbidden.
            if re.search(rf"^\s*(?:def|class)\s+{re.escape(capability)}\b", text, re.MULTILINE):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{capability}")
    assert not offenders, f"prohibited capability implemented: {offenders}"


def test_envelope_digest_matches_project_memory() -> None:
    """Drift control: CLAUDE.md must record the digest of the envelope in force.

    Changing a constant without updating project memory fails here, which is the
    whole point - a future session cannot silently re-relax a deliberate decision.
    """
    digest = envelope_digest()
    assert CLAUDE_MD.exists(), "CLAUDE.md is missing; it is a Milestone-0 deliverable"
    recorded = CLAUDE_MD.read_text(encoding="utf-8")
    assert digest in recorded, (
        f"safety-envelope digest {digest} is not recorded in CLAUDE.md. A constant "
        "changed without updating project memory. Update CLAUDE.md deliberately, "
        "including the rationale, rather than editing this test."
    )


def test_milestone_0_sign_off_block_exists() -> None:
    """The sign-off block must be present and explicit about its own status."""
    assert set(SIGN_OFF) >= {"status", "owner", "role", "reviewed_utc", "milestone"}
    assert SIGN_OFF["status"] in {"PENDING_REVIEW", "SIGNED_OFF"}
    if SIGN_OFF["status"] == "SIGNED_OFF":
        assert SIGN_OFF["owner"], "a signed-off envelope must name an accountable owner"
        assert SIGN_OFF["reviewed_utc"], "a signed-off envelope must carry a review date"
