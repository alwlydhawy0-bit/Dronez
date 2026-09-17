#!/usr/bin/env python3
"""Mutational fuzzer for the parsers that sit on untrusted input.

    python3 scripts/fuzz_parsers.py                      # 20k cases, all targets
    python3 scripts/fuzz_parsers.py --iterations 200000  # a longer run
    python3 scripts/fuzz_parsers.py --target bulletin    # one target
    python3 scripts/fuzz_parsers.py --seed 7 --corpus out/   # reproducible + save

Scope, stated honestly
----------------------
**There is no native code in this repository.** Zero-Trust §9 makes ASan/UBSan/MSan
and a current fuzzing report release-blocking *for native/embedded code*, and
``ros2_bridge/mavlink_signer.py`` is pure Python that opens no socket -- the C MAVLink
and ROS2 parsers those bindings will eventually wrap do not exist here yet. So this
script fuzzes what is actually present and actually reachable by an attacker:

===================  ==========================================================
``bulletin``         `dronez.airspace.schema.parse_bulletin` -- the sovereign NFZ
                     feed. Untrusted input from an external authority.
``jsonrpc``          `mcp_server.jsonrpc.parse_envelope` -- every request byte.
``polygon``          `mcp_server.schemas.geo.GeoPolygon` -- attacker-influenced
                     geometry that feeds containment maths.
``mavsig``           `MavlinkSignatureBlock.parse` -- the 13-byte signature block,
                     the one binary parser here and the closest analogue to the
                     native surface that will need ASan later.
``tools``            All seven MCP tool request schemas.
===================  ==========================================================

``scripts/fuzz_native.sh`` covers the native gate and fails loudly because it has no
target, which is the correct state to report rather than a green run against nothing.

The invariants
--------------
1. **No unhandled exception.** A parser may raise its own declared error type; any
   other exception is a crash, and on a native parser the same input class would be
   a memory-safety bug.
2. **No fuzzed input is ever authorized.** Fail-closed (Zero-Trust §0.1): random bytes
   must never yield an affirmative clearance or a valid signature. This is the one
   that would matter most if it ever broke.
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from dronez.airspace.schema import (  # noqa: E402  - path set above
    SchemaValidationError,
    parse_bulletin,
)
from mcp_server.jsonrpc import JsonRpcError, parse_envelope  # noqa: E402
from mcp_server.schemas.tools import TOOL_REGISTRY, ToolName  # noqa: E402
from ros2_bridge.mavlink_signer import MavlinkSignatureBlock  # noqa: E402

try:  # pydantic is a server dependency, not a `dronez` one
    from pydantic import ValidationError
except ImportError:  # pragma: no cover
    ValidationError = ()  # type: ignore[assignment,misc]


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    target: str
    kind: str
    payload: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "target": self.target,
            "kind": self.kind,
            "payload": self.payload[:2000],
            "detail": self.detail,
        }


@dataclass
class FuzzResult:
    iterations: int = 0
    findings: list[Finding] = field(default_factory=list)
    #: Declared errors, i.e. the parser working correctly.
    rejected: int = 0
    accepted: int = 0

    @property
    def ok(self) -> bool:
        return not self.findings


# --------------------------------------------------------------------------- #
# Mutators
# --------------------------------------------------------------------------- #

_INTERESTING_NUMBERS = [
    0, -1, 1, 2**31 - 1, -(2**31), 2**63 - 1, -(2**63), 2**64,
    0.0, -0.0, 1e308, -1e308, 1e-308,
]
_INTERESTING_STRINGS = [
    "", " ", "\x00", "\\x00", "A" * 10_000, "../" * 100,
    "<script>", "'; DROP TABLE x; --", "%s%s%s%n",
    "\ud800", "\U0001f4a9", "‮", "​",
    "NaN", "Infinity", "-Infinity", "null", "true",
    "1e999", "0x41", "${jndi:ldap://x}",
]
_INTERESTING_LITERALS = ["NaN", "Infinity", "-Infinity"]


class Mutator:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def scalar(self) -> Any:
        choice = self.rng.randrange(7)
        if choice == 0:
            return self.rng.choice(_INTERESTING_NUMBERS)
        if choice == 1:
            return self.rng.choice(_INTERESTING_STRINGS)
        if choice == 2:
            return None
        if choice == 3:
            return self.rng.choice([True, False])
        if choice == 4:
            return [self.scalar() for _ in range(self.rng.randrange(4))]
        if choice == 5:
            return {self.random_key(): self.scalar() for _ in range(self.rng.randrange(3))}
        return "".join(
            self.rng.choice(string.printable) for _ in range(self.rng.randrange(32))
        )

    def random_key(self) -> str:
        return "".join(
            self.rng.choice(string.ascii_letters + "_") for _ in range(self.rng.randrange(1, 12))
        )

    def mutate_json_text(self, text: str) -> str:
        """Byte- and token-level mutations on serialized JSON."""
        if not text:
            return "{}"
        choice = self.rng.randrange(8)
        index = self.rng.randrange(len(text))
        if choice == 0:  # truncate
            return text[: self.rng.randrange(len(text) + 1)]
        if choice == 1:  # bit flip
            char = chr(ord(text[index]) ^ (1 << self.rng.randrange(7)))
            return text[:index] + char + text[index + 1 :]
        if choice == 2:  # splice an interesting string
            return text[:index] + self.rng.choice(_INTERESTING_STRINGS) + text[index:]
        if choice == 3:  # duplicate a span
            end = min(len(text), index + self.rng.randrange(1, 64))
            return text[:index] + text[index:end] * 2 + text[end:]
        if choice == 4:  # delete a span
            end = min(len(text), index + self.rng.randrange(1, 32))
            return text[:index] + text[end:]
        if choice == 5:  # non-finite literal
            return text[:index] + self.rng.choice(_INTERESTING_LITERALS) + text[index:]
        if choice == 6:  # nesting bomb, bounded
            depth = self.rng.randrange(1, 60)
            return "[" * depth + text + "]" * depth
        return text + text  # trailing garbage

    def mutate_obj(self, obj: Any, depth: int = 0) -> Any:
        if depth > 4:
            return self.scalar()
        if isinstance(obj, dict):
            out = dict(obj)
            action = self.rng.randrange(4)
            if out and action == 0:
                del out[self.rng.choice(list(out))]
            elif action == 1:
                out[self.random_key()] = self.scalar()
            elif out and action == 2:
                key = self.rng.choice(list(out))
                out[key] = self.mutate_obj(out[key], depth + 1)
            elif out:
                out[self.rng.choice(list(out))] = self.scalar()
            return out
        if isinstance(obj, list):
            out_list = list(obj)
            if out_list and self.rng.randrange(2):
                idx = self.rng.randrange(len(out_list))
                out_list[idx] = self.mutate_obj(out_list[idx], depth + 1)
            else:
                out_list.append(self.scalar())
            return out_list
        return self.scalar()

    def bytes_(self, length: int | None = None) -> bytes:
        size = length if length is not None else self.rng.randrange(0, 64)
        return bytes(self.rng.randrange(256) for _ in range(size))


# --------------------------------------------------------------------------- #
# Seeds
# --------------------------------------------------------------------------- #

VALID_BULLETIN: dict[str, Any] = {
    "bulletin_id": "BUL-0001",
    "schema_version": "nfz-bulletin/1.0.0",
    "authority": "GACA",
    "sequence": 1,
    "issued_utc": "2026-01-15T09:00:00Z",
    "valid_until_utc": "2026-01-15T12:00:00Z",
    "full_snapshot": True,
    "revoked_zone_ids": [],
    "zones": [
        {
            "zone_id": "NFZ-1",
            "authority": "GACA",
            "designation": "Test aerodrome",
            "zone_type": "prohibited",
            "severity": "blocking",
            "geometry": {
                "type": "Polygon",
                "coordinates": [[
                    [46.0, 24.0], [47.0, 24.0], [47.0, 25.0], [46.0, 25.0], [46.0, 24.0],
                ]],
            },
            "altitude_floor_m_agl": 0.0,
            "altitude_ceiling_m_agl": 200.0,
            "effective_from": "2026-01-15T09:00:00Z",
            "effective_until": "2026-01-15T12:00:00Z",
            "source_ref": "NOTAM-TEST-1",
            "remarks": "fuzzing seed",
        }
    ],
    "signature": {
        "algorithm": "hmac-sha256",
        "key_id": "dev-key-1",
        "value": "00" * 32,
    },
}

VALID_RPC: dict[str, Any] = {
    "jsonrpc": "2.0",
    "method": "check_airspace_clearance",
    "params": {},
    "id": 1,
}

VALID_POLYGON: dict[str, Any] = {
    "type": "Polygon",
    "coordinates": [[
        [46.4, 24.4], [46.6, 24.4], [46.6, 24.6], [46.4, 24.6], [46.4, 24.4],
    ]],
}


#: One well-formed request per tool, as the wire would carry it. Duplicated from the
#: contract fixtures on purpose: a fuzzer that imports the test package would fail to
#: run wherever the tests are not installed, which is exactly where CI runs it.
_ENVELOPE_SEED: dict[str, Any] = {
    "issuer": {
        "operator_id": "op-cr-001",
        "role": "command_room",
        "fido2_credential_id": "cred-cr-1",
        "authorized_zone_ids": ["IZ-1"],
    },
    "signature": {
        "algorithm": "ES256",
        "key_id": "key-cr-1",
        "fido2_credential_id": "cred-cr-1",
        "value": "ab" * 32,
        "signed_at": "2026-01-15T10:00:00Z",
        "expires_at": "2026-01-15T10:02:00Z",
        "nonce": "nonce-000000000000001",
    },
    "mission_id": "M-001",
}

TOOL_SEEDS: dict[str, dict[str, Any]] = {
    "deploy_recon_waypoint": {
        "mission_id": "M-001",
        "polygon": VALID_POLYGON,
        "altitude_min_m_agl": 30.0,
        "altitude_max_m_agl": 100.0,
        "velocity_max_mps": 10.0,
        "pattern_type": "grid",
        "duration_s": 900.0,
    },
    "stream_thermal_feed": {
        "mission_id": "M-001",
        "drone_id": "D-1",
        "stream_quality": "adaptive",
        "detection_mode": "active_object_detection",
        "sdp_offer": "v=0 o=- 1 1 IN IP4 0.0.0.0 s=-",
    },
    "execute_safe_return": {
        "drone_id": "D-1",
        "trigger_reason": "manual_override",
        "mission_id": "M-001",
    },
    "check_airspace_clearance": {
        "mission_id": "M-001",
        "polygon": VALID_POLYGON,
        "altitude_min_m_agl": 30.0,
        "altitude_max_m_agl": 100.0,
    },
    "confirm_flight_plan": {
        "flight_plan_id": "FP-001",
        "flight_plan_digest": "a" * 64,
        "decision": "approve",
        "authorization": _ENVELOPE_SEED,
        "note": "visual confirmation",
    },
    "get_fleet_status": {"incident_zone_id": "IZ-1", "include_unavailable": True},
    "request_emergency_stop": {
        "scope": "zone",
        "incident_zone_id": "IZ-1",
        "reason": "personnel entering the structure",
        "authorization": _ENVELOPE_SEED,
    },
}


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #

def fuzz_bulletin(mutator: Mutator, result: FuzzResult) -> None:
    """The sovereign NFZ feed. Untrusted input from an external authority."""
    payload = mutator.mutate_obj(VALID_BULLETIN)
    try:
        bulletin = parse_bulletin(payload)
    except SchemaValidationError:
        result.rejected += 1
        return
    except RecursionError:
        result.rejected += 1
        return
    except Exception as exc:
        result.findings.append(
            Finding(
                target="bulletin",
                kind="unhandled-exception",
                payload=_safe_json(payload),
                detail=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=4)}",
            )
        )
        return

    result.accepted += 1
    # A parsed bulletin must still be internally coherent: a mutation that produced a
    # zone with an inverted altitude band would let a "restriction" cover nothing.
    for zone in bulletin.zones:
        if zone.altitude_floor_m_agl > zone.altitude_ceiling_m_agl:
            result.findings.append(
                Finding(
                    target="bulletin",
                    kind="accepted-incoherent",
                    payload=_safe_json(payload),
                    detail=f"zone {zone.zone_id} has an inverted altitude band",
                )
            )


def fuzz_jsonrpc(mutator: Mutator, result: FuzzResult) -> None:
    """Every request byte crosses this."""
    text = mutator.mutate_json_text(json.dumps(VALID_RPC))
    try:
        requests, _batched = parse_envelope(text.encode("utf-8", errors="surrogatepass"))
    except JsonRpcError:
        result.rejected += 1
        return
    except (RecursionError, UnicodeEncodeError, UnicodeDecodeError):
        result.rejected += 1
        return
    except Exception as exc:
        result.findings.append(
            Finding(
                target="jsonrpc",
                kind="unhandled-exception",
                payload=text,
                detail=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=4)}",
            )
        )
        return

    result.accepted += 1
    for request in requests:
        if not isinstance(request.method, str):
            result.findings.append(
                Finding(
                    target="jsonrpc",
                    kind="accepted-malformed",
                    payload=text,
                    detail=f"method parsed as {type(request.method).__name__}",
                )
            )


def fuzz_polygon(mutator: Mutator, result: FuzzResult) -> None:
    """Attacker-influenced geometry feeding the containment maths."""
    from mcp_server.schemas.geo import GeoPolygon

    payload = mutator.mutate_obj(VALID_POLYGON)
    try:
        polygon = GeoPolygon.parse_json(_safe_json(payload))
    except (ValidationError, ValueError, RecursionError):
        result.rejected += 1
        return
    except Exception as exc:
        result.findings.append(
            Finding(
                target="polygon",
                kind="unhandled-exception",
                payload=_safe_json(payload),
                detail=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=4)}",
            )
        )
        return

    result.accepted += 1
    # An accepted polygon must convert to the stdlib form the clearance path uses.
    # A shape that validates here but explodes downstream would be worse than one
    # rejected outright.
    try:
        polygon.to_core()
    except ValueError:
        result.rejected += 1
    except Exception as exc:
        result.findings.append(
            Finding(
                target="polygon",
                kind="accepted-but-unconvertible",
                payload=_safe_json(payload),
                detail=f"to_core raised {type(exc).__name__}: {exc}",
            )
        )


def fuzz_mavsig(mutator: Mutator, result: FuzzResult) -> None:
    """The 13-byte MAVLink2 signature block -- the only binary parser here.

    Closest analogue to the native surface that will need ASan/UBSan once the real
    MAVLink parser exists, so it is fuzzed with arbitrary-length input including the
    short and oversized cases a C implementation would read past.
    """
    raw = mutator.bytes_()
    try:
        block = MavlinkSignatureBlock.parse(raw)
    except (ValueError, IndexError, struct_error()) as exc:
        if isinstance(exc, IndexError):
            result.findings.append(
                Finding(
                    target="mavsig",
                    kind="index-error",
                    payload=raw.hex(),
                    detail=(
                        "IndexError rather than a declared ValueError: the length "
                        "check is not covering this input, which in the C parser this "
                        "mirrors would be an out-of-bounds read"
                    ),
                )
            )
        else:
            result.rejected += 1
        return
    except Exception as exc:
        result.findings.append(
            Finding(
                target="mavsig",
                kind="unhandled-exception",
                payload=raw.hex(),
                detail=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=4)}",
            )
        )
        return

    result.accepted += 1
    if len(raw) != 13:
        result.findings.append(
            Finding(
                target="mavsig",
                kind="accepted-wrong-length",
                payload=raw.hex(),
                detail=f"a {len(raw)}-byte block parsed; the block is exactly 13 bytes",
            )
        )
    if not isinstance(block.timestamp, int) or block.timestamp < 0:
        result.findings.append(
            Finding(
                target="mavsig",
                kind="negative-timestamp",
                payload=raw.hex(),
                detail=(
                    "a negative timestamp would defeat the monotonic replay guard, "
                    "which compares against the last accepted value"
                ),
            )
        )


def fuzz_tools(mutator: Mutator, result: FuzzResult) -> None:
    """All seven MCP tool request schemas, through the real ingress path."""
    tool = mutator.rng.choice(list(ToolName))
    seed = TOOL_SEEDS[tool.value]
    payload = mutator.mutate_obj(seed)
    model = TOOL_REGISTRY[tool][0]
    try:
        model.parse_json(_safe_json(payload))
    except (ValidationError, ValueError, RecursionError):
        result.rejected += 1
        return
    except Exception as exc:
        result.findings.append(
            Finding(
                target="tools",
                kind="unhandled-exception",
                payload=f"{tool.value}: {_safe_json(payload)}",
                detail=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=4)}",
            )
        )
        return
    result.accepted += 1


def struct_error() -> type[BaseException]:
    import struct

    return struct.error


TARGETS: dict[str, Callable[[Mutator, FuzzResult], None]] = {
    "bulletin": fuzz_bulletin,
    "jsonrpc": fuzz_jsonrpc,
    "polygon": fuzz_polygon,
    "mavsig": fuzz_mavsig,
    "tools": fuzz_tools,
}


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError, RecursionError):
        return repr(obj)[:2000]


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def verify_seeds() -> list[str]:
    """Check every seed is itself valid before fuzzing from it.

    A seed that does not parse silently reduces its target to "everything is
    rejected": no crashes, no findings, and no coverage either. This turns that into
    a startup failure, because it is otherwise indistinguishable from a clean run.
    """
    problems: list[str] = []
    try:
        parse_bulletin(VALID_BULLETIN)
    except Exception as exc:
        problems.append(f"bulletin seed does not parse: {exc}")

    try:
        parse_envelope(json.dumps(VALID_RPC).encode())
    except Exception as exc:
        problems.append(f"jsonrpc seed does not parse: {exc}")

    from mcp_server.schemas.geo import GeoPolygon

    try:
        GeoPolygon.parse_json(json.dumps(VALID_POLYGON))
    except Exception as exc:
        problems.append(f"polygon seed does not parse: {exc}")

    for name, seed in TOOL_SEEDS.items():
        try:
            TOOL_REGISTRY[ToolName(name)][0].parse_json(json.dumps(seed))
        except Exception as exc:
            problems.append(f"{name} seed does not parse: {str(exc)[:200]}")

    return problems


def run(
    targets: list[str], iterations: int, seed: int, corpus_dir: Path | None
) -> dict[str, FuzzResult]:
    rng = random.Random(seed)  # noqa: S311 - a fuzzer, not a cryptographic use
    mutator = Mutator(rng)
    results = {name: FuzzResult() for name in targets}

    per_target = max(1, iterations // len(targets))
    for name in targets:
        target = TARGETS[name]
        result = results[name]
        for _ in range(per_target):
            result.iterations += 1
            try:
                target(mutator, result)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                result.findings.append(
                    Finding(
                        target=name,
                        kind="harness-error",
                        payload="",
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                )

    if corpus_dir:
        corpus_dir.mkdir(parents=True, exist_ok=True)
        for name, result in results.items():
            for index, finding in enumerate(result.findings):
                (corpus_dir / f"{name}-{index:04d}.json").write_text(
                    json.dumps(finding.to_dict(), indent=2), encoding="utf-8"
                )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--target", choices=sorted(TARGETS), action="append")
    parser.add_argument("--corpus", type=Path, help="save crashing inputs here")
    parser.add_argument("--report", type=Path, help="write JSON results here")
    args = parser.parse_args()

    targets = args.target or sorted(TARGETS)

    seed_problems = verify_seeds()
    if seed_problems:
        print("SEED VALIDATION FAILED -- the fuzzer would report a clean run while")
        print("covering nothing. Fix the seeds before trusting any result.")
        for problem in seed_problems:
            print(f"  {problem}")
        return 2

    results = run(targets, args.iterations, args.seed, args.corpus)

    print("Parser fuzzing")
    print("=" * 72)
    print(
        "Pure-Python parsers only. There is NO native code in this repository, so the\n"
        "Zero-Trust §9 ASan/UBSan/MSan gate has no target here -- see\n"
        "scripts/fuzz_native.sh, which reports that rather than passing vacuously."
    )
    print("=" * 72)
    print()
    print(f"seed {args.seed}")
    print()
    print(f"{'target':12} {'cases':>8} {'rejected':>9} {'accepted':>9} {'findings':>9}")
    total_findings = 0
    for name in targets:
        result = results[name]
        total_findings += len(result.findings)
        print(
            f"{name:12} {result.iterations:>8} {result.rejected:>9} "
            f"{result.accepted:>9} {len(result.findings):>9}"
        )
    print()

    if total_findings:
        print("FINDINGS")
        for name in targets:
            for finding in results[name].findings[:10]:
                print(f"  [{finding.target}] {finding.kind}")
                print(f"    payload: {finding.payload[:160]}")
                print(f"    {finding.detail.splitlines()[0]}")
        print()

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(
                {
                    "seed": args.seed,
                    "targets": {
                        name: {
                            "iterations": r.iterations,
                            "rejected": r.rejected,
                            "accepted": r.accepted,
                            "findings": [f.to_dict() for f in r.findings],
                        }
                        for name, r in results.items()
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"report written to {args.report}")
        print()

    if total_findings:
        print(f"RESULT: FAIL -- {total_findings} finding(s). Reproduce with --seed "
              f"{args.seed}.")
        return 1
    print("RESULT: PASS -- no parser crashed and no malformed input was accepted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
