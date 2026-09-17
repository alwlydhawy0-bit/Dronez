"""Mutation tests for the HIL oracles.

A scenario suite that passes tells you nothing until you know it *can* fail. Every
test here deliberately breaks one property and asserts the oracle catches it -- so a
green HIL run means the oracle looked and found nothing, not that it never looked.

This is the part of the harness that has real value before a rig exists. The model
agreeing with the spec is circular (see `sitl_harness.model`); the oracle rejecting a
0.5 m/s descent that runs at 3.0 m/s is not.
"""

from __future__ import annotations

import pytest

from dronez.safety.states import DroneState
from sitl_harness import (
    SCENARIOS,
    BackendUnavailable,
    EvidenceClass,
    Expectation,
    Fault,
    HilRigBackend,
    Observation,
    Px4SitlBackend,
    SimulatedFirmware,
    judge,
    run_suite,
    scenario_by_id,
)

DVIL = DroneState.DEGRADED_VISUAL_INERTIAL_LANDING

#: A nominal degraded-landing observation, mutated per test below.
GOOD = Observation(
    state_trace=(DroneState.ON_STATION, DroneState.FAILSAFE, DVIL, DroneState.POST_FLIGHT),
    descent_rate_mps=0.5,
    commanded_lateral_translation=False,
    min_obstacle_clearance_m=1.5,
    disarmed=True,
    telemetry_flags=frozenset(),
    ignored_commands=frozenset(),
)

BASELINE = Expectation(
    final_state=DroneState.POST_FLIGHT,
    passes_through=(DroneState.FAILSAFE, DVIL),
    descent_rate_mps=0.5,
    commanded_lateral_translation=False,
    disarmed=True,
)


def test_the_baseline_observation_passes() -> None:
    """The control. Without this, every mutation below could 'fail' for the wrong
    reason and the suite would still look meaningful."""
    assert judge(BASELINE, GOOD) == ()


# --------------------------------------------------------------------------- #
# Each mutation must be caught
# --------------------------------------------------------------------------- #

def test_a_wrong_final_state_is_caught() -> None:
    mutated = Observation(
        state_trace=(DroneState.ON_STATION, DroneState.FAILSAFE, DVIL),
        descent_rate_mps=0.5,
        commanded_lateral_translation=False,
        disarmed=True,
    )
    failures = judge(BASELINE, mutated)
    assert any("final state" in f for f in failures)


def test_skipping_a_required_state_is_caught() -> None:
    """An airframe that reached POST_FLIGHT without passing through DVIL did
    something else entirely -- possibly crashed."""
    mutated = Observation(
        state_trace=(DroneState.ON_STATION, DroneState.LANDING, DroneState.POST_FLIGHT),
        descent_rate_mps=0.5,
        commanded_lateral_translation=False,
        disarmed=True,
    )
    failures = judge(BASELINE, mutated)
    assert any("never entered" in f for f in failures)


def test_required_states_out_of_order_are_caught() -> None:
    """DVIL before FAILSAFE would mean it is not a sub-state of it."""
    mutated = Observation(
        state_trace=(DroneState.ON_STATION, DVIL, DroneState.FAILSAFE, DroneState.POST_FLIGHT),
        descent_rate_mps=0.5,
        commanded_lateral_translation=False,
        disarmed=True,
    )
    failures = judge(BASELINE, mutated)
    assert any("never entered" in f for f in failures)


def test_entering_a_forbidden_state_is_caught() -> None:
    """The HIL-D-09 property: resuming navigation after a spoofed GNSS recovery."""
    expect = Expectation(never_enters=(DroneState.IN_TRANSIT,))
    mutated = Observation(
        state_trace=(DroneState.ON_STATION, DVIL, DroneState.IN_TRANSIT),
    )
    failures = judge(expect, mutated)
    assert any("forbidden state" in f for f in failures)


def test_a_too_fast_descent_is_caught() -> None:
    """3 m/s is the *normal* descent limit and far too fast for the arrays to bind
    (spec §3.1). Reading it as a pass would defeat the whole case."""
    mutated = Observation(
        state_trace=GOOD.state_trace,
        descent_rate_mps=3.0,
        commanded_lateral_translation=False,
        disarmed=True,
    )
    failures = judge(BASELINE, mutated)
    assert any("descent rate" in f for f in failures)


def test_a_slightly_off_descent_rate_is_within_tolerance() -> None:
    """The oracle must not be so tight that sensor noise fails a good run."""
    mutated = Observation(
        state_trace=GOOD.state_trace,
        descent_rate_mps=0.55,
        commanded_lateral_translation=False,
        disarmed=True,
    )
    assert judge(BASELINE, mutated) == ()


def test_a_missing_descent_rate_is_caught() -> None:
    """Absent is not the same as correct. A backend that failed to instrument the
    descent must not read as a pass."""
    mutated = Observation(
        state_trace=GOOD.state_trace,
        descent_rate_mps=None,
        commanded_lateral_translation=False,
        disarmed=True,
    )
    failures = judge(BASELINE, mutated)
    assert any("no descent rate" in f for f in failures)


def test_commanded_lateral_translation_is_caught() -> None:
    """DVIL bypasses waypoint navigation entirely. Commanded translation means the
    position controller is still driving, which is the failure the state exists to
    prevent."""
    mutated = Observation(
        state_trace=GOOD.state_trace,
        descent_rate_mps=0.5,
        commanded_lateral_translation=True,
        disarmed=True,
    )
    failures = judge(BASELINE, mutated)
    assert any("lateral translation" in f for f in failures)


def test_a_clearance_breach_is_caught() -> None:
    expect = Expectation(min_obstacle_clearance_m=1.5)
    mutated = Observation(state_trace=GOOD.state_trace, min_obstacle_clearance_m=0.8)
    failures = judge(expect, mutated)
    assert any("clearance fell" in f for f in failures)


def test_missing_clearance_data_is_caught() -> None:
    expect = Expectation(min_obstacle_clearance_m=1.5)
    mutated = Observation(state_trace=GOOD.state_trace, min_obstacle_clearance_m=None)
    failures = judge(expect, mutated)
    assert any("no obstacle clearance" in f for f in failures)


def test_failing_to_disarm_is_caught() -> None:
    """An airframe on the ground with rotors live is a hazard to the team recovering
    it."""
    mutated = Observation(
        state_trace=GOOD.state_trace,
        descent_rate_mps=0.5,
        commanded_lateral_translation=False,
        disarmed=False,
    )
    failures = judge(BASELINE, mutated)
    assert any("disarmed" in f for f in failures)


def test_a_missing_telemetry_flag_is_caught() -> None:
    """HIL-D-11: an unguided descent that does not announce itself leaves the command
    room believing the arrays are still holding clearance."""
    expect = Expectation(telemetry_flags=("descent_unguided",))
    mutated = Observation(state_trace=GOOD.state_trace, telemetry_flags=frozenset())
    failures = judge(expect, mutated)
    assert any("descent_unguided" in f for f in failures)


def test_an_obeyed_ground_command_is_caught() -> None:
    """The single most important negative in the suite: a mid-air disarm obeyed
    during a fail-safe."""
    expect = Expectation(ignored_commands=(Fault.GROUND_COMMANDS_DISARM,))
    mutated = Observation(state_trace=GOOD.state_trace, ignored_commands=frozenset())
    failures = judge(expect, mutated)
    assert any("not ignored" in f for f in failures)


def test_several_violations_are_all_reported() -> None:
    """One message per broken property, so a failing run says everything that is
    wrong rather than the first thing."""
    mutated = Observation(
        state_trace=(DroneState.ON_STATION,),
        descent_rate_mps=3.0,
        commanded_lateral_translation=True,
        disarmed=False,
    )
    assert len(judge(BASELINE, mutated)) >= 4


# --------------------------------------------------------------------------- #
# The suite itself
# --------------------------------------------------------------------------- #

def test_the_model_passes_every_scenario() -> None:
    """Expected, and nearly meaningless on its own -- see `sitl_harness.model`. It is
    here so that a regression in the model or the scenarios is visible."""
    result = run_suite(SimulatedFirmware())
    assert result.failed == 0, [
        (c.scenario.scenario_id, c.failures) for c in result.cases if not c.passed
    ]


def test_a_model_run_does_not_close_the_hil_gate() -> None:
    """The load-bearing assertion of this whole module.

    A green model run must never be reportable as hardware evidence. If this ever
    passes trivially because someone relabelled the model's evidence class, TM-12 and
    TM-27 would appear closed without a rig existing.
    """
    result = run_suite(SimulatedFirmware())
    assert result.ok
    assert not result.closes_hil_gate()
    assert result.evidence_class is EvidenceClass.MODEL_ONLY
    assert "TM-12" in result.caveat()


def test_every_scenario_asserts_something() -> None:
    """An Expectation with no fields set passes vacuously."""
    for scenario in SCENARIOS:
        expect = scenario.expect
        asserted = any((
            expect.final_state is not None,
            expect.passes_through,
            expect.never_enters,
            expect.descent_rate_mps is not None,
            expect.commanded_lateral_translation is not None,
            expect.min_obstacle_clearance_m is not None,
            expect.disarmed is not None,
            expect.telemetry_flags,
            expect.ignored_commands,
        ))
        assert asserted, f"{scenario.scenario_id} asserts nothing"


def test_every_scenario_explains_itself() -> None:
    """A case whose rationale is missing is a case nobody can evaluate when it fails."""
    for scenario in SCENARIOS:
        assert scenario.rationale.strip(), f"{scenario.scenario_id} has no rationale"
        assert scenario.spec_ref.strip(), f"{scenario.scenario_id} cites no spec section"


def test_all_eighteen_degraded_landing_cases_are_present() -> None:
    """The spec's §8 table lists HIL-D-01 .. HIL-D-18. A missing case is a silent
    coverage gap, since nothing else counts them."""
    present = {s.scenario_id for s in SCENARIOS if s.scenario_id.startswith("HIL-D-")}
    assert present == {f"HIL-D-{i:02d}" for i in range(1, 19)}


def test_the_dual_failure_cases_outnumber_the_single_failure_ones() -> None:
    """DVIL is a dual-failure state; a suite weighted toward single failures would be
    testing mostly the cases where it must NOT trigger."""
    dual = sum(1 for s in SCENARIOS if "dual-failure" in s.tags)
    single = sum(1 for s in SCENARIOS if "single-failure" in s.tags)
    assert dual > single


def test_independence_cases_cover_all_three_severable_dependencies() -> None:
    """Server, link, companion computer. Missing any one leaves a claim untested."""
    faults: set[Fault] = set()
    for scenario in SCENARIOS:
        if "independence" in scenario.tags:
            faults |= set(scenario.faults)
    assert {
        Fault.MCP_SERVER_POWERED_OFF,
        Fault.C2_LINK_SEVERED,
        Fault.COMPANION_COMPUTER_HALTED,
    } <= faults


# --------------------------------------------------------------------------- #
# The unimplemented backends must refuse loudly
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("backend", [Px4SitlBackend(), HilRigBackend()])
def test_an_unimplemented_backend_raises_rather_than_returning_a_pass(
    backend: Px4SitlBackend | HilRigBackend,
) -> None:
    with pytest.raises(BackendUnavailable):
        backend.run(scenario_by_id("HIL-D-04"))


@pytest.mark.parametrize("backend", [Px4SitlBackend(), HilRigBackend()])
def test_an_unavailable_backend_reports_every_case_unavailable_not_passed(
    backend: Px4SitlBackend | HilRigBackend,
) -> None:
    """Never silently green. A suite that cannot run must say so per case."""
    result = run_suite(backend, SCENARIOS[:3])
    assert result.unavailable == 3
    assert result.passed == 0
    assert not result.ok
    assert not result.closes_hil_gate()


def test_the_sitl_backend_explains_why_it_cannot_run_here() -> None:
    """The reason is a scope boundary, not a missing feature, and the message says
    so -- otherwise someone will 'fix' it by writing the publisher."""
    with pytest.raises(BackendUnavailable, match="MAVLink"):
        Px4SitlBackend().run(scenario_by_id("HIL-D-04"))


def test_the_rig_backend_names_the_open_threat_items() -> None:
    with pytest.raises(BackendUnavailable, match="TM-12"):
        HilRigBackend().run(scenario_by_id("HIL-D-04"))
