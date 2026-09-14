#!/usr/bin/env python3
"""Print the safety-envelope digest and its Markdown table.

Run this after changing any constant in ``dronez.safety.envelope`` and paste the
output into the corresponding section of ``CLAUDE.md``. The digest test in
``tests/unit/test_safety_envelope.py`` fails until you do - deliberately.

    python3 scripts/envelope_report.py [--table | --digest]
"""

from __future__ import annotations

import sys
from dataclasses import fields
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dronez.safety.envelope import (
    ENFORCEMENT,
    ENVELOPE,
    SCHEMA_VERSION,
    envelope_digest,
)

_UNITS = {
    "_m": "m", "_m_agl": "m AGL", "_agl_m": "m AGL", "_mps": "m/s",
    "_pct": "%", "_s": "s", "_factor": "x", "_per_second": "/s",
}


def unit_for(name: str) -> str:
    for suffix, unit in sorted(_UNITS.items(), key=lambda kv: -len(kv[0])):
        if name.endswith(suffix):
            return unit
    return ""


def table() -> str:
    rows = [
        "| Constant | Value | Enforced at | Kinetic | Why this value |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in fields(ENVELOPE):
        bound = ENFORCEMENT[f.name]
        value = getattr(ENVELOPE, f.name)
        unit = unit_for(f.name)
        shown = f"{value:g}{(' ' + unit) if unit else ''}"
        rationale = " ".join(bound.rationale.split())
        rows.append(
            f"| `{f.name}` | {shown} | **{bound.locus.value}** | "
            f"{'yes' if bound.kinetic else 'no'} | {rationale} |"
        )
    return "\n".join(rows)


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "--all"
    if arg in ("--digest", "--all"):
        print(f"schema_version: {SCHEMA_VERSION}")
        print(f"digest: {envelope_digest()}")
        if arg == "--all":
            print()
    if arg in ("--table", "--all"):
        print(table())
