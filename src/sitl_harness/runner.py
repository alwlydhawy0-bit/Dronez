"""Scenario execution and the oracle that judges an :class:`Observation`.

The oracle is deliberately separate from every backend. It reads only the external
observations in :class:`~sitl_harness.backend.Observation`, so the identical judgement
applies to the model, to PX4 SITL, and to a rig -- and a backend cannot grade its own
homework by reporting a shape the oracle happens to accept.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from sitl_harness.backend import BackendUnavailable, Observation, SitlBackend
from sitl_harness.scenarios import SCENARIOS, EvidenceClass, Expectation, Scenario

__all__ = ["CaseResult", "SuiteResult", "judge", "run_suite"]


@dataclass(frozen=True, slots=True)
class CaseResult:
    scenario: Scenario
    passed: bool
    #: One line per violated expectation. Empty on a pass.
    failures: tuple[str, ...] = ()
    observation: Observation | None = None
    #: Set when the backend could not run at all.
    unavailable_reason: str | None = None

    @property
    def status(self) -> str:
        if self.unavailable_reason is not None:
            return "UNAVAILABLE"
        return "PASS" if self.passed else "FAIL"

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario.scenario_id,
            "title": self.scenario.title,
            "spec_ref": self.scenario.spec_ref,
            "tags": list(self.scenario.tags),
            "status": self.status,
            "failures": list(self.failures),
            "unavailable_reason": self.unavailable_reason,
            "state_trace": (
                [s.value for s in self.observation.state_trace]
                if self.observation
                else None
            ),
            "notes": list(self.observation.notes) if self.observation else [],
        }


@dataclass(frozen=True, slots=True)
class SuiteResult:
    backend_name: str
    evidence_class: EvidenceClass
    cases: tuple[CaseResult, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.cases if c.status == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for c in self.cases if c.status == "FAIL")

    @property
    def unavailable(self) -> int:
        return sum(1 for c in self.cases if c.status == "UNAVAILABLE")

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.unavailable == 0

    def closes_hil_gate(self) -> bool:
        """Whether this run can close `TM-12` / `TM-27`.

        Only a hardware run can. A green model run is a statement about the scenario
        suite, not about an airframe -- and the difference is the whole reason this
        method exists rather than a boolean `passed` being read as sufficient.
        """
        return self.ok and self.evidence_class is EvidenceClass.HARDWARE_IN_THE_LOOP

    def caveat(self) -> str:
        match self.evidence_class:
            case EvidenceClass.MODEL_ONLY:
                return (
                    "MODEL ONLY -- these results describe a model written from the "
                    "specification, so agreement with that specification is circular. "
                    "They say the scenarios and oracles are well-formed. They say "
                    "nothing about PX4, ArduPilot, or any airframe. TM-12 and TM-27 "
                    "remain OPEN."
                )
            case EvidenceClass.SOFTWARE_IN_THE_LOOP:
                return (
                    "SOFTWARE IN THE LOOP -- real autopilot logic, simulated sensors "
                    "and dynamics. Does not close TM-12/TM-27, which need the rig."
                )
            case EvidenceClass.HARDWARE_IN_THE_LOOP:
                return (
                    "HARDWARE IN THE LOOP -- real flight controller and real sensors. "
                    "A green run here is what closes TM-12 and TM-27."
                )

    def to_dict(self) -> dict[str, object]:
        return {
            "backend": self.backend_name,
            "evidence_class": self.evidence_class.value,
            "caveat": self.caveat(),
            "closes_hil_gate": self.closes_hil_gate(),
            "summary": {
                "total": len(self.cases),
                "passed": self.passed,
                "failed": self.failed,
                "unavailable": self.unavailable,
            },
            "cases": [c.to_dict() for c in self.cases],
        }

    def write_report(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")


def judge(expect: Expectation, observed: Observation) -> tuple[str, ...]:
    """Return one message per violated expectation. Empty means the case passed."""
    failures: list[str] = []
    trace = observed.state_trace

    if expect.final_state is not None and observed.final_state is not expect.final_state:
        failures.append(
            f"final state {observed.final_state.value!r}, "
            f"expected {expect.final_state.value!r}"
        )

    # `passes_through` is ordered but not contiguous: the airframe may visit other
    # states between two required ones.
    remaining = list(expect.passes_through)
    for state in trace:
        if remaining and state is remaining[0]:
            remaining.pop(0)
    if remaining:
        failures.append(
            "never entered "
            + ", ".join(s.value for s in remaining)
            + f" (trace: {' -> '.join(s.value for s in trace)})"
        )

    # `never_enters` is judged against states the airframe *moved into*, so the
    # initial state is excluded. Several scenarios legitimately start in a state they
    # must never return to -- HIL-D-09 begins ON_STATION and forbids resuming
    # navigation -- and counting the start as an entry would fail them on their own
    # premise.
    entered = trace[1:]
    for forbidden in expect.never_enters:
        if forbidden in entered:
            failures.append(f"entered forbidden state {forbidden.value!r}")

    if expect.descent_rate_mps is not None:
        if observed.descent_rate_mps is None:
            failures.append("no descent rate observed")
        elif abs(observed.descent_rate_mps - expect.descent_rate_mps) > expect.rate_tolerance:
            failures.append(
                f"descent rate {observed.descent_rate_mps:.3f} m/s, expected "
                f"{expect.descent_rate_mps:.3f} +/- {expect.rate_tolerance}"
            )

    if (
        expect.commanded_lateral_translation is not None
        and observed.commanded_lateral_translation != expect.commanded_lateral_translation
    ):
        failures.append(
            f"commanded lateral translation was {observed.commanded_lateral_translation}, "
            f"expected {expect.commanded_lateral_translation}"
        )

    if expect.min_obstacle_clearance_m is not None:
        if observed.min_obstacle_clearance_m is None:
            failures.append("no obstacle clearance observed")
        elif observed.min_obstacle_clearance_m < expect.min_obstacle_clearance_m:
            failures.append(
                f"clearance fell to {observed.min_obstacle_clearance_m:.2f} m, "
                f"floor is {expect.min_obstacle_clearance_m:.2f} m"
            )

    if expect.disarmed is not None and observed.disarmed != expect.disarmed:
        failures.append(f"disarmed was {observed.disarmed}, expected {expect.disarmed}")

    missing_flags = set(expect.telemetry_flags) - set(observed.telemetry_flags)
    if missing_flags:
        failures.append(f"telemetry did not raise {sorted(missing_flags)}")

    not_ignored = set(expect.ignored_commands) - set(observed.ignored_commands)
    if not_ignored:
        failures.append(
            "these commands were not ignored: "
            + ", ".join(sorted(f.value for f in not_ignored))
        )

    return tuple(failures)


def run_suite(
    backend: SitlBackend, scenarios: Sequence[Scenario] | None = None
) -> SuiteResult:
    """Run every scenario against ``backend`` and judge the results."""
    selected: Iterable[Scenario] = scenarios if scenarios is not None else SCENARIOS
    cases: list[CaseResult] = []

    for scenario in selected:
        try:
            observation = backend.run(scenario)
        except BackendUnavailable as exc:
            cases.append(
                CaseResult(scenario=scenario, passed=False, unavailable_reason=str(exc))
            )
            continue

        failures = judge(scenario.expect, observation)
        cases.append(
            CaseResult(
                scenario=scenario,
                passed=not failures,
                failures=failures,
                observation=observation,
            )
        )

    return SuiteResult(
        backend_name=backend.name,
        evidence_class=backend.evidence_class,
        cases=tuple(cases),
    )
