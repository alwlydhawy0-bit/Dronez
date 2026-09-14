#!/usr/bin/env python3
"""Generate the OPA data document from the Python safety envelope.

Why this exists
---------------
The safety envelope must be available to the Rego policies, and there are three
ways to do that, two of which are wrong:

* **Hardcode the constants in Rego.** Two sources of truth that drift silently.
  Rejected.
* **Pass the envelope in ``input``.** Then a compromised or buggy MCP server can
  hand OPA a wider envelope than the real one, and the policy gate validates
  against the attacker's bounds. Rejected -- the gate must not take its own limits
  from the thing it is gating.
* **Ship it as OPA ``data``, generated from the Python module.** One source of
  truth, and the bounds arrive with the policy bundle rather than with the request.
  This is what we do.

The generated file is committed so the bundle is reproducible, and a test asserts it
matches the live envelope, so regenerating is not something anyone has to remember.

    python3 scripts/gen_policy_data.py [--check]
"""

from __future__ import annotations

import json
import sys
from dataclasses import fields
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dronez.safety.envelope import (  # noqa: E402
    ENVELOPE,
    PROHIBITED_CAPABILITIES,
    SCHEMA_VERSION,
    envelope_digest,
)

OUTPUT = ROOT / "src/policy_engine/policies/data/safety_envelope.json"


def build() -> dict[str, object]:
    """Serialise the envelope as OPA ``data.dronez.safety_envelope``."""
    return {
        "dronez": {
            "safety_envelope": {
                "_generated_by": "scripts/gen_policy_data.py -- do not edit by hand",
                "schema_version": SCHEMA_VERSION,
                "digest": envelope_digest(),
                "constants": {f.name: getattr(ENVELOPE, f.name) for f in fields(ENVELOPE)},
                "prohibited_capabilities": list(PROHIBITED_CAPABILITIES),
            }
        }
    }


def render(document: dict[str, object]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main() -> int:
    document = render(build())
    check_only = "--check" in sys.argv

    if check_only:
        if not OUTPUT.exists():
            print(f"MISSING: {OUTPUT.relative_to(ROOT)}", file=sys.stderr)
            return 1
        if OUTPUT.read_text(encoding="utf-8") != document:
            print(
                f"STALE: {OUTPUT.relative_to(ROOT)} does not match the current safety "
                "envelope. Run: python3 scripts/gen_policy_data.py",
                file=sys.stderr,
            )
            return 1
        print(f"up to date: {OUTPUT.relative_to(ROOT)}")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(document, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} (digest {envelope_digest()[:16]}...)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
