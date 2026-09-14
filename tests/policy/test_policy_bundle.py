"""Structural checks on the Rego policy bundle.

**Scope and honest limits.** These tests do NOT evaluate Rego. They cannot: they check
structure and cross-file consistency, not semantics. Semantic verification is
``opa check --strict`` plus the ``*_test.rego`` suites, run by
``scripts/verify_policies.sh``, which CI must execute with ``--require-opa``.

What these tests *do* catch is the class of mistake that would otherwise reach a
reviewer unnoticed: a policy that lost its ``default allow := false``, a deny rule that
reads a free-text field, an envelope constant duplicated into Rego as a literal, or a
generated data document that has drifted from the Python envelope.
"""

from __future__ import annotations

import json
import re
from dataclasses import fields
from pathlib import Path

import pytest

from dronez.safety.envelope import ENVELOPE, PROHIBITED_CAPABILITIES, envelope_digest

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "src/policy_engine/policies"
DATA_FILE = POLICY_DIR / "data/safety_envelope.json"

POLICY_FILES = sorted(p for p in POLICY_DIR.glob("*.rego") if not p.name.endswith("_test.rego"))
TEST_FILES = sorted(POLICY_DIR.glob("*_test.rego"))
MAIN_POLICY = POLICY_DIR / "deploy_recon_waypoint.rego"


def test_bundle_is_not_empty() -> None:
    assert POLICY_FILES, "no .rego policies found"
    assert TEST_FILES, "no *_test.rego suites found"


@pytest.mark.parametrize("path", POLICY_FILES + TEST_FILES, ids=lambda p: p.name)
def test_every_file_declares_a_package_and_imports_rego_v1(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert re.search(r"^package\s+[\w.]+", text, re.MULTILINE), "missing package declaration"
    assert re.search(r"^import rego\.v1", text, re.MULTILINE), (
        "missing `import rego.v1`; without it the file is parsed under legacy semantics "
        "where `if` and `contains` behave differently"
    )


@pytest.mark.parametrize("path", POLICY_FILES + TEST_FILES, ids=lambda p: p.name)
def test_braces_and_brackets_are_balanced(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for opener, closer in (("{", "}"), ("[", "]"), ("(", ")")):
        assert text.count(opener) == text.count(closer), f"unbalanced {opener}{closer}"


def test_main_policy_defaults_to_deny() -> None:
    """The single most important line in the bundle."""
    text = MAIN_POLICY.read_text(encoding="utf-8")
    assert re.search(r"^default allow := false\s*$", text, re.MULTILINE), (
        "the authorization policy must declare `default allow := false`"
    )


def test_allow_requires_input_completeness_not_just_an_empty_deny_set() -> None:
    """Checking only `count(deny) == 0` would allow an empty input.

    No deny rule fires when there is nothing there to violate, so completeness has to
    be established positively.
    """
    text = MAIN_POLICY.read_text(encoding="utf-8")
    allow_rule = re.search(r"^allow if \{(.*?)^\}", text, re.MULTILINE | re.DOTALL)
    assert allow_rule, "could not locate the `allow if { ... }` rule"
    body = allow_rule.group(1)
    assert "input_complete" in body
    assert "count(deny) == 0" in body


def test_policy_never_reads_a_natural_language_field() -> None:
    """Zero-Trust §4.2: natural-language claims of authority are not a credential.

    The gate must not be reachable by prose. The input builder already omits free text;
    this asserts the policy does not reach for it either, so the two defences cannot
    drift apart.
    """
    forbidden = (
        "justification", "rationale", "urgency", "urgent", "reason_text",
        "note", "description", "comment", "message", "prompt", "reference",
    )
    offenders: list[str] = []
    for path in POLICY_FILES:
        text = path.read_text(encoding="utf-8")
        # Strip comments: these words appear legitimately in explanatory prose.
        code = "\n".join(line.split("#")[0] for line in text.splitlines())
        for token in forbidden:
            if re.search(rf"input\.[\w.]*\b{token}\b", code):
                offenders.append(f"{path.name}: input.*{token}")
    assert not offenders, f"policy reads natural-language input: {offenders}"


def test_policy_takes_its_bounds_from_data_not_input() -> None:
    """A gate must not accept the limits it is being judged against from the caller.

    ``input.safety_envelope`` would let a compromised server widen its own bounds.
    """
    for path in POLICY_FILES:
        code = "\n".join(
            line.split("#")[0] for line in path.read_text(encoding="utf-8").splitlines()
        )
        assert "input.safety_envelope" not in code, (
            f"{path.name} reads the safety envelope from input; it must come from data"
        )
        assert "input.envelope" not in code, f"{path.name} reads an envelope from input"


def test_envelope_constants_are_not_duplicated_as_rego_literals() -> None:
    """A literal bound in Rego is a second source of truth that will drift silently.

    Only values distinctive enough to be unambiguous are scanned. Short values such as
    ``15`` occur legitimately (a float epsilon like ``1e-15``, a loop bound), so
    flagging them would be noise rather than signal.
    """
    candidates = {
        name: f"{getattr(ENVELOPE, name):g}"
        for name in (
            "altitude_max_agl_m",
            "ground_speed_max_mps",
            "incident_zone_max_duration_s",
            "mission_duration_max_s",
            "nfz_max_staleness_s",
        )
    }
    distinctive = {name: lit for name, lit in candidates.items() if len(lit) >= 3}
    assert distinctive, "no envelope constant is distinctive enough to scan for"

    for path in POLICY_FILES:
        code = "\n".join(
            line.split("#")[0] for line in path.read_text(encoding="utf-8").splitlines()
        )
        for name, literal in distinctive.items():
            # Exclude `-` and `e` from the preceding context so an exponent such as
            # 1e-120 is not mistaken for the constant 120.
            assert not re.search(rf"(?<![\w.\-]){re.escape(literal)}(?![\w.])", code), (
                f"{path.name} hardcodes {name} as the literal {literal}; read it from "
                "data.dronez.safety_envelope.constants instead"
            )


# --------------------------------------------------------------------------- #
# Generated data document
# --------------------------------------------------------------------------- #

def test_generated_data_exists_and_is_valid_json() -> None:
    assert DATA_FILE.exists(), "run: python3 scripts/gen_policy_data.py"
    json.loads(DATA_FILE.read_text(encoding="utf-8"))


def test_generated_data_matches_the_live_envelope() -> None:
    """Drift gate. The bundle's bounds must be the envelope's bounds."""
    document = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    generated = document["dronez"]["safety_envelope"]

    assert generated["digest"] == envelope_digest(), (
        "the generated policy data is stale; run: python3 scripts/gen_policy_data.py"
    )
    assert generated["constants"] == {f.name: getattr(ENVELOPE, f.name) for f in fields(ENVELOPE)}
    assert generated["prohibited_capabilities"] == list(PROHIBITED_CAPABILITIES)


def test_every_envelope_constant_reaches_the_bundle() -> None:
    document = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    generated = set(document["dronez"]["safety_envelope"]["constants"])
    assert generated == {f.name for f in fields(ENVELOPE)}


# --------------------------------------------------------------------------- #
# Coverage of the required decision surface
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "code",
    [
        "outside_incident_zone",
        "envelope_violation",
        "zone_altitude_violation",
        "clearance_invalid",
        "airspace_conflict",
        "zone_inactive",
        "not_authorized_for_zone",
        "pattern_not_allowed",
        "prohibited_capability",
        "precedence_violation",
        "unknown_role",
        "malformed_input",
        "fleet_unavailable",
        "insufficient_battery_range",
    ],
)
def test_required_denial_code_is_implemented(code: str) -> None:
    """Each code corresponds to a control this milestone was asked to enforce."""
    assert f'"code": "{code}"' in MAIN_POLICY.read_text(encoding="utf-8")


def test_containment_is_evaluated_from_coordinates() -> None:
    """Not asserted by the caller: a gate that accepts a precomputed verdict is not a gate."""
    text = MAIN_POLICY.read_text(encoding="utf-8")
    assert "geometry.polygon_contains" in text
    code = "\n".join(line.split("#")[0] for line in text.splitlines())
    for shortcut in ("input.contained", "input.request.contained", "input.is_contained"):
        assert shortcut not in code, f"policy trusts a caller-supplied {shortcut}"


def test_geometry_implements_both_containment_conditions() -> None:
    """All-vertices-inside is insufficient for a non-convex boundary."""
    text = (POLICY_DIR / "geometry.rego").read_text(encoding="utf-8")
    contains_rule = re.search(r"polygon_contains\(outer, inner\) if \{(.*?)^\}", text, re.S | re.M)
    assert contains_rule, "could not locate polygon_contains"
    body = contains_rule.group(1)
    assert "every vertex in inner[0]" in body, "missing the all-vertices-inside condition"
    assert "not edges_cross" in body, "missing the no-edge-crossing condition"


def test_clearance_policy_binds_the_decision_to_the_requested_volume() -> None:
    """Otherwise a clearance for an empty area could be presented for a restricted one."""
    text = (POLICY_DIR / "clearance.rego").read_text(encoding="utf-8")
    assert "covers_requested_polygon" in text
    assert "covers_requested_altitude" in text
    valid_rule = re.search(r"^valid if \{(.*?)^\}", text, re.S | re.M)
    assert valid_rule
    body = valid_rule.group(1)
    for condition in (
        "present", "affirmative", "no_blocking_zones", "unexpired",
        "derived_from_fresh_feed", "covers_requested_polygon", "covers_requested_altitude",
    ):
        assert condition in body, f"clearance.valid does not require {condition}"


def test_agent_can_never_override_in_rego() -> None:
    text = (POLICY_DIR / "precedence.rego").read_text(encoding="utf-8")
    assert 'actor_role != "ai_agent"' in text, (
        "the precedence policy must exclude the agent tier from override authority"
    )


def test_verification_script_is_executable() -> None:
    script = REPO_ROOT / "scripts/verify_policies.sh"
    assert script.exists()
    assert script.stat().st_mode & 0o111, "verify_policies.sh must be executable"
