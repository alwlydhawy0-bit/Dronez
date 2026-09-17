"""SITL / HIL scenario harness for the firmware fail-safe paths.

Stdlib only, and **no transport**: nothing here opens a socket or publishes MAVLink.
The scenarios are data, the oracle is a pure function, and the only executable backend
is a model (`model.py`) whose limits are stated in its own docstring.

Read `backend.py` before adding a backend that talks to real hardware -- CLAUDE.md
§2.1 governs what may exist in this repository.
"""

from sitl_harness.backend import (
    BackendUnavailable,
    HilRigBackend,
    Observation,
    Px4SitlBackend,
    SitlBackend,
)
from sitl_harness.model import SimulatedFirmware
from sitl_harness.runner import CaseResult, SuiteResult, judge, run_suite
from sitl_harness.scenarios import (
    SCENARIOS,
    EvidenceClass,
    Expectation,
    Fault,
    Scenario,
    scenario_by_id,
    scenarios_tagged,
)

__all__ = [
    "SCENARIOS",
    "BackendUnavailable",
    "CaseResult",
    "EvidenceClass",
    "Expectation",
    "Fault",
    "HilRigBackend",
    "Observation",
    "Px4SitlBackend",
    "Scenario",
    "SimulatedFirmware",
    "SitlBackend",
    "SuiteResult",
    "judge",
    "run_suite",
    "scenario_by_id",
    "scenarios_tagged",
]
