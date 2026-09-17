#!/usr/bin/env python3
"""Score the adversarial corpus and enforce the release gate (`TM-10`).

    python3 scripts/run_redteam.py                 # measure and print
    python3 scripts/run_redteam.py --report r.json # machine-readable output
    python3 scripts/run_redteam.py --strict        # fail on ANY miss, not just new ones

Exit codes
----------
``0`` no unexpected miss and no new false positive.
``1`` a regression against the corpus -- release-blocking per Zero-Trust §11.1.

What the numbers mean is documented in `redteam.report`; the short version is that
the detection rate is the least important line printed here. `--strict` exists for a
team that wants to drive the known gaps to zero, but it is deliberately not the
default: a gate that fails on documented, understood gaps trains people to delete
cases.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from mcp_server.guardrails.sanitizer import (  # noqa: E402  - path set above
    PromptSanitizer,
    StaticSanitizerClient,
)
from redteam import score_corpus  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="write JSON results here")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail on any miss, including documented ones",
    )
    args = parser.parse_args()

    # The deployed classifier is an isolated service (TM-09: not yet deployed), so
    # this measures the heuristic layer plus a permissive stub. That is the honest
    # floor -- the real stack can only do better, and the floor is what a gate needs.
    report = score_corpus(PromptSanitizer(StaticSanitizerClient()))

    print("Adversarial corpus (TM-10)")
    print("=" * 72)
    print(
        "Measured against the HEURISTIC screen plus a permissive classifier stub.\n"
        "The deployed Llama Guard node is not wired up (TM-09), so these numbers are\n"
        "a floor, not the production detection rate."
    )
    print("=" * 72)
    print()

    print(f"adversarial cases   {report.total}")
    print(f"blocked             {report.blocked}")
    print(f"detection rate      {report.detection_rate:.1%}")
    print(f"documented gaps     {len(report.known_misses)}")
    print(f"unexpected misses   {len(report.unexpected_misses)}")
    print(f"benign controls     {len(report.benign)}")
    print(f"false positives     {len(report.false_positives)}")
    print()

    print("by technique")
    for technique, row in sorted(report.by_technique().items()):
        bar = f"{row['blocked']}/{row['total']}"
        print(f"  {technique:24} {bar:>8}")
    print()

    if report.weakest_techniques():
        print("weakest coverage:", ", ".join(report.weakest_techniques()))
        print()

    if report.unexpected_misses:
        print("UNEXPECTED MISSES -- regression, release-blocking:")
        for outcome in report.unexpected_misses:
            print(f"  {outcome.case.case_id}  {outcome.case.objective}")
        print()

    if report.false_positives:
        print("FALSE POSITIVES -- legitimate traffic blocked:")
        for benign in report.false_positives:
            print(f"  {benign.case.case_id}  {benign.case.content!r}")
            print(f"      {benign.case.why_it_resembles_an_attack}")
        print()

    if report.unexpected_catches:
        print("STALE ANNOTATIONS -- marked as misses but now caught:")
        for outcome in report.unexpected_catches:
            print(f"  {outcome.case.case_id}")
        print()

    if args.strict and report.known_misses:
        print("DOCUMENTED GAPS (--strict):")
        for outcome in report.known_misses:
            print(f"  {outcome.case.case_id}  {outcome.case.technique.value}")
            print(f"      {outcome.case.fn_note}")
        print()

    if args.report:
        report.write(args.report)
        print(f"report written to {args.report}")
        print()

    failed = bool(report.unexpected_misses) or bool(report.false_positives)
    if args.strict:
        failed = failed or bool(report.known_misses)

    if failed:
        print("RESULT: FAIL -- see above. Zero-Trust §11.1 blocks release on a")
        print("regression against this corpus for any agentic feature.")
        return 1

    print("RESULT: PASS -- no regression against the corpus.")
    print(
        "This bounds the guardrail layer only. The control is the deterministic "
        "policy gate\n(CLAUDE.md §3.2), covered by "
        "tests/server/test_injection_end_to_end.py."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
