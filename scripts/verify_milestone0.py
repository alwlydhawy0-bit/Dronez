#!/usr/bin/env python3
"""Milestone-0 gate check.

Runs the invariants that must hold before the gate can close, and prints the state
of each exit criterion. Exits non-zero if a *hard* invariant is violated; an open
criterion is reported, not failed, because closing one is a human owner's decision.

    python3 scripts/verify_milestone0.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dronez.safety.envelope import (  # noqa: E402
    ENFORCEMENT,
    SIGN_OFF,
    EnforcementLocus,
    envelope_digest,
    validate_envelope,
)

OK, WARN, BAD = "  ok  ", " open ", " FAIL "


def main() -> int:
    failures: list[str] = []
    print("Milestone-0 gate check\n" + "=" * 60)

    # --- hard invariants ---------------------------------------------------
    print("\nInvariants")
    try:
        validate_envelope()
        print(f"[{OK}] safety envelope is internally consistent")
    except Exception as exc:
        print(f"[{BAD}] safety envelope inconsistent: {exc}")
        failures.append("envelope consistency")

    server_kinetic = [
        n for n, b in ENFORCEMENT.items()
        if b.kinetic and b.locus is EnforcementLocus.SERVER
    ]
    if server_kinetic:
        print(f"[{BAD}] kinetic bounds enforced only at the server: {server_kinetic}")
        failures.append("kinetic bound locus")
    else:
        print(f"[{OK}] no kinetic bound is enforced only at the MCP server")

    digest = envelope_digest()
    claude_md = ROOT / "CLAUDE.md"
    if claude_md.exists() and digest in claude_md.read_text(encoding="utf-8"):
        print(f"[{OK}] envelope digest matches CLAUDE.md")
    else:
        print(f"[{BAD}] envelope digest {digest} not recorded in CLAUDE.md")
        failures.append("envelope digest drift")

    data_check = subprocess.run(
        [sys.executable, "scripts/gen_policy_data.py", "--check"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if data_check.returncode == 0:
        print(f"[{OK}] OPA policy data matches the safety envelope")
    else:
        print(f"[{BAD}] OPA policy data is stale: run scripts/gen_policy_data.py")
        failures.append("policy data drift")

    opa = shutil.which("opa")
    if opa:
        # S603: the argument vector is a repo-relative path plus a fixed flag --
        # nothing here is caller-influenced.
        policy_check = subprocess.run(  # noqa: S603
            [str(ROOT / "scripts/verify_policies.sh"), "--require-opa"],
            cwd=ROOT, capture_output=True, text=True,
        )
        if policy_check.returncode == 0:
            print(f"[{OK}] Rego policy bundle verified (opa check + opa test)")
        else:
            print(f"[{BAD}] Rego policy bundle failed verification")
            failures.append("rego bundle")
    else:
        # Not a hard failure locally, but it IS one in CI: an unverified authorization
        # gate is TM-13, and the gate cannot close while it stands.
        print(f"[{WARN}] Rego bundle UNVERIFIED -- opa not installed (TM-13)")

    result = subprocess.run(
        # -q already comes from the addopts in pyproject.toml; passing it again
        # would be -qq and suppress the summary line we want to report.
        [sys.executable, "-m", "pytest", "tests"],
        cwd=ROOT, capture_output=True, text=True,
    )
    summary = next(
        (ln.strip() for ln in reversed(result.stdout.splitlines())
         if "passed" in ln or "failed" in ln or "error" in ln),
        "no summary line",
    )
    if result.returncode == 0:
        print(f"[{OK}] test suite passes ({summary})")
    else:
        print(f"[{BAD}] test suite failed ({summary})")
        failures.append("tests")

    # --- exit criteria -----------------------------------------------------
    print("\nExit criteria (open items are decisions for a human owner)")
    signed = SIGN_OFF.get("status") == "SIGNED_OFF" and SIGN_OFF.get("owner")
    criteria = [
        ((ROOT / "docs/02-security-threat-model.md").exists(),
         "1. STRIDE threat model drafted (review sign-off still required)"),
        (bool(signed),
         "2. Safety envelope signed off by a named accountable owner"),
        (False,
         "3. Live sovereign NFZ endpoint connected (mock only -- TM-04)"),
        (False,
         "4. IncidentZone model finalized -- IMPLEMENTED, awaiting review (TM-01)"),
        (False,
         "5. GACA registration / spectrum licensing initiated (TM-11)"),
        # Criteria 3-6 are tracked by hand: each closes on evidence a script cannot
        # see (a real endpoint synced, a reviewed data model, a filed licence
        # application, a policy bundle verified by `opa test`). Flip these as they close.
        (False,
         "6. Policy-engine schema defined -- IMPLEMENTED, unverified (TM-02, TM-13)"),
    ]
    open_count = 0
    for done, label in criteria:
        print(f"[{OK if done else WARN}] {label}")
        open_count += 0 if done else 1

    print("\n" + "=" * 60)
    print(f"envelope digest: {digest}")
    if failures:
        print(f"RESULT: FAILED -- {', '.join(failures)}")
        return 1
    print(f"RESULT: invariants hold. {open_count} exit criteria still open -- "
          "the Milestone-0 gate is NOT closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
