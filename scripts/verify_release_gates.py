#!/usr/bin/env python3
"""Zero-Trust §11.1 release gate.

    python3 scripts/verify_release_gates.py
    python3 scripts/verify_release_gates.py --report gates.json

Every gate reports one of three states, and the distinction is the point:

``PASS``      checked, and satisfied.
``FAIL``      checked, and violated. Blocks release.
``NOT MET``   **not checkable here** -- the evidence is produced outside this
              repository (an SCA service, a signed SBOM, a pen-test report, a HIL
              rig). Treated as blocking, because "we could not check" is not
              "we are fine". Default-deny applies to the release process too.

A gate that cannot be evaluated is never reported as passing. That is the whole
design: it would be trivial to make this script exit 0, and doing so would attach a
green release gate to work nobody did.

This script does NOT decide whether the Milestone-0 gate is closed -- that is a human
owner's call (CLAUDE.md §10.5) -- but it does report that an open Milestone-0 gate
makes a production release structurally impossible, since no flight-capable code may
exist yet.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


class State(StrEnum):
    # S105 suppressed: ruff reads `PASS = "PASS"` as a hardcoded credential. It is a
    # release-gate state name, not a secret.
    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    NOT_MET = "NOT MET"


@dataclass(frozen=True, slots=True)
class GateResult:
    gate_id: str
    title: str
    state: State
    detail: str
    #: Zero-Trust section this gate comes from.
    reference: str = "§11.1"
    #: What would have to happen for a NOT MET gate to become checkable.
    remedy: str = ""

    @property
    def blocking(self) -> bool:
        return self.state is not State.PASS

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "gate_id": self.gate_id,
            "title": self.title,
            "state": self.state.value,
            "detail": self.detail,
            "reference": self.reference,
            "remedy": self.remedy,
            "blocking": self.blocking,
        }


def _run(cmd: list[str], timeout: int = 900) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"{type(exc).__name__}: {exc}"
    return proc.returncode, (proc.stdout + proc.stderr)


# --------------------------------------------------------------------------- #
# Gates that this repository CAN check
# --------------------------------------------------------------------------- #

def gate_tests() -> GateResult:
    code, out = _run([sys.executable, "-m", "pytest", "tests", "-q"])
    match = re.search(r"(\d+) passed", out)
    count = match.group(1) if match else "?"
    if code == 0:
        return GateResult(
            "RG-01", "Security regression suite passes", State.PASS,
            f"{count} tests passed",
        )
    failures = re.findall(r"^FAILED (\S+)", out, re.MULTILINE)[:10]
    return GateResult(
        "RG-01", "Security regression suite passes", State.FAIL,
        f"pytest exited {code}; failures: {failures or 'see output'}",
    )


def gate_lint() -> GateResult:
    code, out = _run([sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"])
    if code == 0:
        return GateResult("RG-02", "Static lint clean", State.PASS, "ruff clean")
    return GateResult("RG-02", "Static lint clean", State.FAIL, out.strip()[-400:])


def gate_types() -> GateResult:
    code, out = _run([sys.executable, "-m", "mypy", "src"])
    if code == 0:
        return GateResult(
            "RG-03", "Strict type check clean", State.PASS, out.strip().splitlines()[-1]
        )
    return GateResult("RG-03", "Strict type check clean", State.FAIL, out.strip()[-400:])


def gate_secrets() -> GateResult:
    """Zero-Trust §11.1: **any** hardcoded secret in version-control history blocks.

    This is a shallow scan of the working tree, not of history -- so it is reported
    as a partial check rather than as satisfying the gate on its own.
    """
    patterns = [
        (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
        (
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|password)\s*[:=]\s*['\"][^'\"]{12,}",
            "credential literal",
        ),
        (r"(?i)\baws_secret_access_key\s*[:=]", "AWS secret"),
        (r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub token"),
    ]
    hits: list[str] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if path.suffix not in {
            ".py", ".rego", ".json", ".sh", ".md", ".toml", ".yaml", ".yml", ".sql", ".tf",
        }:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern, label in patterns:
            if re.search(pattern, text):
                hits.append(f"{path.relative_to(REPO_ROOT)}: {label}")
    if hits:
        return GateResult(
            "RG-04", "No hardcoded secrets", State.FAIL, "; ".join(hits[:10])
        )
    return GateResult(
        "RG-04", "No hardcoded secrets (working tree only)", State.NOT_MET,
        "working tree is clean, but git HISTORY was not scanned",
        remedy="run gitleaks/trufflehog over the full history in CI",
    )


def gate_envelope() -> GateResult:
    code, out = _run([sys.executable, "scripts/verify_milestone0.py"])
    digest = re.search(r"envelope digest: ([0-9a-f]{64})", out)
    if code == 0 and digest:
        return GateResult(
            "RG-05", "Safety envelope digest matches project memory", State.PASS,
            f"digest {digest.group(1)[:16]}...",
            reference="CLAUDE.md §4",
        )
    return GateResult(
        "RG-05", "Safety envelope digest matches project memory", State.FAIL,
        out.strip()[-300:], reference="CLAUDE.md §4",
    )


def gate_policy_bundle() -> GateResult:
    """`opa test` has never run here -- TM-13, blocked by egress policy."""
    code, _out = _run(["bash", "-c", "command -v opa"])
    if code != 0:
        return GateResult(
            "RG-06", "Rego bundle verified with `opa test`", State.NOT_MET,
            "the opa binary is unavailable in this environment (TM-13); the bundle is "
            "verified only structurally by tests/policy/test_policy_bundle.py",
            remedy="run scripts/verify_policies.sh --require-opa where opa is installed",
        )
    code, out = _run(["bash", "scripts/verify_policies.sh", "--require-opa"])
    state = State.PASS if code == 0 else State.FAIL
    return GateResult("RG-06", "Rego bundle verified with `opa test`", state, out.strip()[-300:])


def gate_redteam() -> GateResult:
    """Zero-Trust §11.1: any regression against the injection corpus blocks."""
    code, out = _run([sys.executable, "scripts/run_redteam.py"])
    rate = re.search(r"detection rate\s+([\d.]+%)", out)
    if code == 0:
        return GateResult(
            "RG-07", "No regression against the prompt-injection corpus", State.PASS,
            f"detection rate {rate.group(1) if rate else 'n/a'}, no unexpected miss",
            reference="§11.1 (agentic)",
        )
    reason = "unexpected misses" if "UNEXPECTED MISSES" in out else "false positives"
    return GateResult(
        "RG-07", "No regression against the prompt-injection corpus", State.FAIL,
        f"{reason}; see scripts/run_redteam.py", reference="§11.1 (agentic)",
    )


def gate_tool_scope() -> GateResult:
    """Zero-Trust §11.1: a tool-permission scope broader than the documented minimum."""
    from mcp_server.schemas.tools import AGENT_PROPOSABLE_TOOLS, ToolName

    forbidden = {
        ToolName.CONFIRM_FLIGHT_PLAN,
        ToolName.REQUEST_EMERGENCY_STOP,
        ToolName.EXECUTE_SAFE_RETURN,
    }
    overlap = AGENT_PROPOSABLE_TOOLS & forbidden
    if overlap:
        return GateResult(
            "RG-08", "Agent tool scope is the documented minimum", State.FAIL,
            f"agent can invoke authorizing tools: {sorted(t.value for t in overlap)}",
            reference="§11.1 (agentic)",
        )
    return GateResult(
        "RG-08", "Agent tool scope is the documented minimum", State.PASS,
        f"{len(AGENT_PROPOSABLE_TOOLS)} of {len(ToolName)} tools agent-proposable, "
        "none of them authorizing",
        reference="§11.1 (agentic)",
    )


def gate_python_fuzzing() -> GateResult:
    code, out = _run(
        [sys.executable, "scripts/fuzz_parsers.py", "--iterations", "20000"], timeout=600
    )
    if code == 0:
        return GateResult(
            "RG-09", "Python parser fuzzing clean", State.PASS,
            "20000 cases, no crash and no malformed input accepted",
            reference="§9 (partial)",
        )
    return GateResult(
        "RG-09", "Python parser fuzzing clean", State.FAIL, out.strip()[-400:],
        reference="§9 (partial)",
    )


def gate_native_fuzzing() -> GateResult:
    code, out = _run(["bash", "scripts/fuzz_native.sh"])
    if "NO TARGET" in out:
        return GateResult(
            "RG-10", "Native parser fuzzing + ASan/UBSan/MSan", State.NOT_MET,
            "no native code exists yet, so the gate has not been reached (TM-31)",
            reference="§9",
            remedy="build libFuzzer harnesses for the MAVLink2/ROS2 parsers when they exist",
        )
    state = State.PASS if code == 0 else State.FAIL
    return GateResult(
        "RG-10", "Native parser fuzzing + ASan/UBSan/MSan", state,
        out.strip()[-300:], reference="§9",
    )


def gate_hil() -> GateResult:
    code, out = _run([sys.executable, "scripts/run_hil.py", "--require-hardware"])
    if code == 0:
        return GateResult(
            "RG-11", "Fail-safe behaviour verified on hardware", State.PASS,
            out.strip()[-200:], reference="Milestone 4 gate",
        )
    return GateResult(
        "RG-11", "Fail-safe behaviour verified on hardware", State.NOT_MET,
        "no HIL rig exists (TM-12) and no airframe is selected (TM-27); the scenario "
        "suite passes against a model only, which is not hardware evidence",
        reference="Milestone 4 gate",
        remedy="run scripts/run_hil.py --backend rig --require-hardware on the rig",
    )


# --------------------------------------------------------------------------- #
# Gates whose evidence lives outside this repository
# --------------------------------------------------------------------------- #

def _external(gate_id: str, title: str, detail: str, remedy: str) -> Callable[[], GateResult]:
    def check() -> GateResult:
        return GateResult(gate_id, title, State.NOT_MET, detail, remedy=remedy)

    return check


gate_sca = _external(
    "RG-12", "No Critical/High SCA finding; every dependency has an SBOM entry",
    "no SCA service is reachable from this environment and no SBOM is attached",
    "run the org SCA scanner and attach a CycloneDX/SPDX SBOM to the release artifact",
)
gate_sbom = _external(
    "RG-13", "SBOM, artifact signature and provenance attached",
    "no signed artifact exists; nothing is built or published from this repository yet",
    "sign the release artifact and attach in-toto/SLSA provenance",
)
gate_container = _external(
    "RG-14", "Container image scanned",
    "no container image is built here",
    "scan the runtime image and attach the report",
)
gate_dast = _external(
    "RG-15", "No unresolved critical SAST/DAST finding",
    "SAST/DAST run outside this repository; ruff and mypy are not a substitute",
    "run the org SAST/DAST pipeline against a deployed instance",
)
gate_pentest = _external(
    "RG-16", "Current penetration test on file",
    "no penetration test has been commissioned",
    "commission a pen test covering the agent->MCP->hardware chain",
)
gate_egress = _external(
    "RG-17", "No outbound request to a user-influenced host bypasses the egress proxy",
    "transport is not implemented (TM-08); NfzSyncChannel is a seam with no socket",
    "verify at deployment, once the live NFZ endpoint and egress proxy exist",
)


def gate_threat_model() -> GateResult:
    """§11.1: a STRIDE threat model is required for every new trust boundary."""
    doc = REPO_ROOT / "docs/02-security-threat-model.md"
    if not doc.exists():
        return GateResult(
            "RG-18", "STRIDE threat model covers every trust boundary", State.FAIL,
            "docs/02-security-threat-model.md is missing",
        )
    text = doc.read_text(encoding="utf-8")
    if "draft" in text.lower() and "sign-off" in text.lower():
        return GateResult(
            "RG-18", "STRIDE threat model covers every trust boundary", State.NOT_MET,
            "the model exists and is comprehensive, but is marked DRAFT pending "
            "security review sign-off (Milestone-0 criterion 1)",
            remedy="obtain security review sign-off",
        )
    return GateResult(
        "RG-18", "STRIDE threat model covers every trust boundary", State.PASS,
        "threat model present and signed off",
    )


def gate_exceptions() -> GateResult:
    """CLAUDE.md §9: an exception past its expiry is release-blocking."""
    text = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    section = text.split("## 9. Signed risk-acceptance exception log")[-1].split("## 10.")[0]
    if "*(none)*" in section:
        return GateResult(
            "RG-19", "No expired risk-acceptance exception", State.PASS,
            "no exceptions granted", reference="CLAUDE.md §9",
        )
    return GateResult(
        "RG-19", "No expired risk-acceptance exception", State.NOT_MET,
        "exceptions are recorded; expiry dates must be checked by a human reviewer",
        reference="CLAUDE.md §9",
        remedy="review each exception's expiry against today's date",
    )


def gate_milestone_zero() -> GateResult:
    """The gate above all the others: Milestone 0 is not closed."""
    _code, out = _run([sys.executable, "scripts/verify_milestone0.py"])
    open_count = len(re.findall(r"^\[ open \]", out, re.MULTILINE))
    if "gate is NOT closed" in out or open_count:
        return GateResult(
            "RG-00", "Milestone-0 gate closed", State.NOT_MET,
            f"{open_count} item(s) still open; no flight-capable code may exist yet, "
            "so a production release is structurally out of reach",
            reference="CLAUDE.md §2",
            remedy="a named human owner closes each criterion; this script never does",
        )
    return GateResult(
        "RG-00", "Milestone-0 gate closed", State.PASS, out.strip()[-200:],
        reference="CLAUDE.md §2",
    )


GATES: list[Callable[[], GateResult]] = [
    gate_milestone_zero,
    gate_tests,
    gate_lint,
    gate_types,
    gate_secrets,
    gate_envelope,
    gate_policy_bundle,
    gate_redteam,
    gate_tool_scope,
    gate_python_fuzzing,
    gate_native_fuzzing,
    gate_hil,
    gate_sca,
    gate_sbom,
    gate_container,
    gate_dast,
    gate_pentest,
    gate_egress,
    gate_threat_model,
    gate_exceptions,
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="write JSON results here")
    parser.add_argument(
        "--skip-slow",
        action="store_true",
        help="skip the test suite and fuzzing, for a fast structural check",
    )
    args = parser.parse_args()

    slow = {gate_tests, gate_python_fuzzing}
    checks = [g for g in GATES if not (args.skip_slow and g in slow)]

    print("Zero-Trust §11.1 release gate")
    print("=" * 78)
    print()

    results: list[GateResult] = []
    for check in checks:
        result = check()
        results.append(result)
        marker = {State.PASS: "  ok  ", State.FAIL: " FAIL ", State.NOT_MET: "not met"}[
            result.state
        ]
        print(f"[{marker}] {result.gate_id}  {result.title}")
        print(f"           {result.detail}")
        if result.remedy:
            print(f"           -> {result.remedy}")
        print()

    passed = sum(1 for r in results if r.state is State.PASS)
    failed = [r for r in results if r.state is State.FAIL]
    not_met = [r for r in results if r.state is State.NOT_MET]

    print("=" * 78)
    print(f"{passed} passed, {len(failed)} failed, {len(not_met)} not met")
    print()

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(
                {
                    "summary": {
                        "passed": passed,
                        "failed": len(failed),
                        "not_met": len(not_met),
                        "release_permitted": not failed and not not_met,
                    },
                    "gates": [r.to_dict() for r in results],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"report written to {args.report}")
        print()

    if failed:
        print("BLOCKING FAILURES:")
        for result in failed:
            print(f"  {result.gate_id}  {result.title}")
        print()

    if not_met:
        print("GATES NOT MET (evidence missing, not satisfied):")
        for result in not_met:
            print(f"  {result.gate_id}  {result.title}")
        print()

    print(
        "RESULT: RELEASE BLOCKED."
        if (failed or not_met)
        else "RESULT: all gates satisfied."
    )
    if failed or not_met:
        print()
        print(
            "A 'not met' gate is blocking on purpose: its evidence is produced\n"
            "outside this repository, and an unchecked gate is not a satisfied one.\n"
            "Default-deny applies to the release process too (Zero-Trust §0.1)."
        )
    return 1 if (failed or not_met) else 0


if __name__ == "__main__":
    raise SystemExit(main())
