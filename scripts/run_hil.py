#!/usr/bin/env python3
"""Run the fail-safe scenario suite and report what the results actually prove.

    python3 scripts/run_hil.py                    # model backend (default)
    python3 scripts/run_hil.py --backend sitl     # PX4/Gazebo -- not implemented
    python3 scripts/run_hil.py --backend rig      # HIL rig -- no rig exists
    python3 scripts/run_hil.py --require-hardware # non-zero unless a rig ran
    python3 scripts/run_hil.py --report out.json  # machine-readable results

The `--require-hardware` flag is the one CI should carry on any job claiming to close
`TM-12` or `TM-27`. Without it a green run means "the scenarios and oracles are
well-formed"; with it, a green run means an airframe actually did these things. The
difference is the whole point, so this script refuses to blur it: the evidence class
is printed on every run, above the summary, whether or not anyone asked.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from sitl_harness import (  # noqa: E402  - path set above
    SCENARIOS,
    EvidenceClass,
    HilRigBackend,
    Px4SitlBackend,
    SimulatedFirmware,
    SitlBackend,
    run_suite,
)

BACKENDS: dict[str, SitlBackend] = {
    "model": SimulatedFirmware(),
    "sitl": Px4SitlBackend(),
    "rig": HilRigBackend(),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=sorted(BACKENDS), default="model")
    parser.add_argument(
        "--tag", help="run only scenarios carrying this tag (e.g. dual-failure, TM-12)"
    )
    parser.add_argument("--report", type=Path, help="write JSON results here")
    parser.add_argument(
        "--require-hardware",
        action="store_true",
        help="exit non-zero unless the run was hardware-in-the-loop",
    )
    args = parser.parse_args()

    backend = BACKENDS[args.backend]
    scenarios = (
        tuple(s for s in SCENARIOS if args.tag in s.tags) if args.tag else SCENARIOS
    )
    if not scenarios:
        print(f"no scenarios tagged {args.tag!r}", file=sys.stderr)
        return 2

    result = run_suite(backend, scenarios)

    print("Fail-safe scenario suite")
    print("=" * 72)
    print(f"backend:        {result.backend_name}")
    print(f"evidence class: {result.evidence_class.value}")
    print()
    print(result.caveat())
    print("=" * 72)
    print()

    for case in result.cases:
        marker = {"PASS": "  ok  ", "FAIL": " FAIL ", "UNAVAILABLE": " n/a  "}[case.status]
        print(f"[{marker}] {case.scenario.scenario_id}  {case.scenario.title}")
        for failure in case.failures:
            print(f"           -> {failure}")
        if case.unavailable_reason:
            for line in _wrap(case.unavailable_reason):
                print(f"           {line}")

    print()
    print(
        f"{result.passed} passed, {result.failed} failed, "
        f"{result.unavailable} unavailable, {len(result.cases)} total"
    )

    if args.report:
        result.write_report(args.report)
        print(f"report written to {args.report}")

    print()
    if args.require_hardware and not result.closes_hil_gate():
        print(
            "RESULT: FAIL -- --require-hardware was set, but this run has evidence "
            f"class {result.evidence_class.value!r}. TM-12 and TM-27 stay OPEN."
        )
        return 1
    if not result.ok:
        print("RESULT: FAIL")
        return 1

    if result.evidence_class is EvidenceClass.HARDWARE_IN_THE_LOOP:
        print("RESULT: PASS on hardware. This run closes TM-12 and TM-27.")
    else:
        print(
            "RESULT: scenarios and oracles hold against "
            f"{result.backend_name}. This is NOT hardware evidence, and the "
            "Milestone-4 HIL gate remains open."
        )
    return 0


def _wrap(text: str, width: int = 62) -> list[str]:
    import textwrap

    return textwrap.wrap(text, width=width)


if __name__ == "__main__":
    raise SystemExit(main())
