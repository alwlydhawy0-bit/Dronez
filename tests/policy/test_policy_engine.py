"""Fail-closed behaviour of the policy-engine client, and correctness of its input.

The governing invariant: **the only way to obtain ``allowed=True`` is for the policy
to have returned a literal ``"allow": true``.** Everything else -- an outage, a
timeout, a malformed body, a truthy-but-not-true value -- denies.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from dronez.airspace.client import ClearanceDecision, DenialReason
from mcp_server.schemas.geo import GeoPolygon
from mcp_server.schemas.identity import OperatorIdentity, Role
from mcp_server.schemas.incident_zone import (
    IncidentPriority,
    IncidentZone,
    IncidentZoneStatus,
)
from mcp_server.schemas.tools import DeployReconWaypointRequest, PatternType
from policy_engine import (
    FleetSnapshot,
    PolicyDecision,
    PolicyEngine,
    PolicyPath,
    StaticPolicyTransport,
    build_deploy_recon_waypoint_input,
)
from policy_engine.client import HttpPolicyTransport, PolicyTransportError

T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
PATH = PolicyPath.DEPLOY_RECON_WAYPOINT


def square(lon: float, lat: float, half: float) -> GeoPolygon:
    return GeoPolygon.from_rings([[
        [lon - half, lat - half], [lon + half, lat - half],
        [lon + half, lat + half], [lon - half, lat + half],
        [lon - half, lat - half],
    ]])


def engine(**transport_kwargs: object) -> PolicyEngine:
    return PolicyEngine(StaticPolicyTransport(**transport_kwargs))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The affirmative path
# --------------------------------------------------------------------------- #

def test_explicit_allow_is_honoured() -> None:
    decision = engine(result={"allow": True, "deny": [], "policy_version": "v1"}).evaluate(
        PATH, {"request": {}}
    )
    assert decision.allowed is True
    assert decision.policy_version == "v1"


def test_denial_carries_its_reasons() -> None:
    decision = engine(result={
        "allow": False,
        "deny": [
            {"code": "outside_incident_zone", "detail": "not contained"},
            {"code": "envelope_violation", "detail": "too high"},
        ],
    }).evaluate(PATH, {"request": {}})
    assert decision.allowed is False
    assert set(decision.codes) == {"outside_incident_zone", "envelope_violation"}


# --------------------------------------------------------------------------- #
# Fail-closed sweep
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "truthy",
    ["true", 1, "yes", [1], {"a": 1}, "True"],
    ids=["str-true", "int-1", "str-yes", "list", "dict", "str-True"],
)
def test_truthy_but_not_true_denies(truthy: object) -> None:
    """A policy says yes by returning the boolean true, not by returning something truthy."""
    decision = engine(result={"allow": truthy, "deny": []}).evaluate(PATH, {})
    assert decision.allowed is False


@pytest.mark.parametrize(
    "kwargs, expected_code, unavailable",
    [
        ({"body": b"{}"}, "policy_undefined", False),
        ({"body": b"{oops"}, "policy_malformed", False),
        ({"body": b"[]"}, "policy_malformed", False),
        ({"body": b'{"result": "yes"}'}, "policy_malformed", False),
        ({"status": 500, "body": b"{}"}, "policy_engine_error", True),
        ({"status": 404, "body": b"{}"}, "policy_engine_error", False),
        ({"status": 403, "body": b"{}"}, "policy_engine_error", False),
        ({"raise_error": PolicyTransportError("refused")}, "policy_engine_unavailable", True),
        ({"raise_error": TimeoutError("timed out")}, "policy_engine_unavailable", True),
        ({"raise_error": RuntimeError("boom")}, "policy_engine_unavailable", True),
    ],
)
def test_every_failure_mode_denies(
    kwargs: dict, expected_code: str, unavailable: bool
) -> None:
    decision = engine(**kwargs).evaluate(PATH, {"request": {}})
    assert decision.allowed is False
    assert expected_code in decision.codes
    assert decision.engine_unavailable is unavailable


def test_undefined_policy_path_is_not_an_open_gate() -> None:
    """OPA omits `result` when a policy failed to load. That is an outage, not an allow."""
    decision = engine(body=b"{}").evaluate(PATH, {})
    assert decision.allowed is False
    assert "policy_undefined" in decision.codes


def test_oversized_decision_body_is_refused() -> None:
    huge = b'{"result": {"allow": true, "pad": "' + b"A" * (2 << 20) + b'"}}'
    decision = engine(body=huge).evaluate(PATH, {})
    assert decision.allowed is False
    assert "policy_malformed" in decision.codes


def test_incoherent_policy_result_denies() -> None:
    """allow=true alongside denials indicates a Rego defect. Deny and surface it."""
    decision = engine(result={
        "allow": True,
        "deny": [{"code": "envelope_violation", "detail": "too high"}],
    }).evaluate(PATH, {})
    assert decision.allowed is False
    assert "policy_incoherent" in decision.codes


def test_silent_denial_still_names_a_reason() -> None:
    decision = engine(result={"allow": False, "deny": []}).evaluate(PATH, {})
    assert decision.allowed is False
    assert "policy_denied" in decision.codes


def test_unserialisable_input_denies_without_calling_the_engine() -> None:
    transport = StaticPolicyTransport(result={"allow": True, "deny": []})
    decision = PolicyEngine(transport).evaluate(PATH, {"bad": {1, 2, 3}})
    assert decision.allowed is False
    assert "policy_input_unserialisable" in decision.codes
    assert transport.calls == [], "a request that cannot be serialised never reaches the engine"


def test_nan_in_policy_input_is_refused() -> None:
    """NaN is not valid JSON and would be silently accepted by a lax encoder."""
    decision = engine(result={"allow": True, "deny": []}).evaluate(
        PATH, {"request": {"altitude_max_m_agl": float("nan")}}
    )
    assert decision.allowed is False
    assert "policy_input_unserialisable" in decision.codes


def test_evaluate_denies_even_outside_the_exception_hierarchy() -> None:
    """A pathological transport must not put an exception in the dispatch path."""

    class Hostile:
        def post(self, path: str, document: bytes, *, timeout_s: float) -> None:
            raise BaseException("not even an Exception")

    decision = PolicyEngine(Hostile()).evaluate(PATH, {})  # type: ignore[arg-type]
    assert decision.allowed is False
    assert "policy_engine_unavailable" in decision.codes


@pytest.mark.parametrize("signal", [KeyboardInterrupt, SystemExit])
def test_shutdown_signals_still_propagate(signal: type[BaseException]) -> None:
    """Interpreter shutdown is not a policy denial.

    Swallowing it would hide a terminating process from its supervisor and leave the
    server looking merely unlucky rather than gone.
    """

    class Shutting:
        def post(self, path: str, document: bytes, *, timeout_s: float) -> None:
            raise signal()

    with pytest.raises(signal):
        PolicyEngine(Shutting()).evaluate(PATH, {})  # type: ignore[arg-type]


def test_audit_sink_defect_cannot_change_the_verdict() -> None:
    def broken_sink(path: str, decision: PolicyDecision) -> None:
        raise RuntimeError("audit pipeline down")

    engine_with_sink = PolicyEngine(
        StaticPolicyTransport(result={"allow": True, "deny": []}), on_decision=broken_sink
    )
    assert engine_with_sink.evaluate(PATH, {}).allowed is True


def test_every_decision_reaches_the_audit_sink() -> None:
    """Master Plan §5: rejected proposals are part of the audit backbone."""
    seen: list[PolicyDecision] = []
    allow_engine = PolicyEngine(
        StaticPolicyTransport(result={"allow": True, "deny": []}),
        on_decision=lambda _p, d: seen.append(d),
    )
    deny_engine = PolicyEngine(
        StaticPolicyTransport(result={"allow": False, "deny": [{"code": "x", "detail": "y"}]}),
        on_decision=lambda _p, d: seen.append(d),
    )
    allow_engine.evaluate(PATH, {})
    deny_engine.evaluate(PATH, {})
    assert [d.allowed for d in seen] == [True, False]


def test_policy_engine_must_be_a_loopback_sidecar() -> None:
    """A remote policy engine puts a network partition in the dispatch path."""
    HttpPolicyTransport("http://127.0.0.1:8181")
    with pytest.raises(ValueError, match="loopback sidecar"):
        HttpPolicyTransport("https://policy.example.com")


# --------------------------------------------------------------------------- #
# Policy input construction
# --------------------------------------------------------------------------- #

@pytest.fixture
def zone() -> IncidentZone:
    return IncidentZone(
        incident_zone_id="IZ-1",
        boundary=square(46.5, 24.5, 0.5),
        priority=IncidentPriority.P1_CRITICAL,
        status=IncidentZoneStatus.ACTIVE,
        authorized_from=T0 - timedelta(hours=1),
        authorized_until=T0 + timedelta(hours=1),
        altitude_ceiling_m_agl=110.0,
        altitude_floor_m_agl=20.0,
        declared_by=OperatorIdentity(
            operator_id="op-cr-001",
            role=Role.COMMAND_ROOM,
            fido2_credential_id="cred-1",
            authorized_zone_ids=frozenset({"IZ-1"}),
        ),
        authorized_operator_ids=frozenset({"op-cr-001"}),
        reference="CASE-SENSITIVE-REF",
    )


@pytest.fixture
def request_() -> DeployReconWaypointRequest:
    return DeployReconWaypointRequest(
        mission_id="M-001",
        polygon=square(46.5, 24.5, 0.01),
        altitude_min_m_agl=30.0,
        altitude_max_m_agl=100.0,
        velocity_max_mps=10.0,
        pattern_type=PatternType.GRID,
        duration_s=900.0,
    )


@pytest.fixture
def clearance() -> ClearanceDecision:
    return ClearanceDecision(
        cleared=True,
        reason=DenialReason.CLEARED,
        detail="clear",
        evaluated_utc=T0 - timedelta(seconds=30),
        expires_utc=T0 + timedelta(seconds=90),
        feed_age_s=42.0,
        feed_sequence=7,
        feed_authority="GACA-SOVEREIGN-NFZ",
    )


def build(zone, request_, clearance, **kwargs):  # type: ignore[no-untyped-def]
    return build_deploy_recon_waypoint_input(
        request=request_,
        principal=zone.declared_by,
        incident_zone=zone,
        clearance=clearance,
        fleet=FleetSnapshot(
            available_drone_ids=("D-1",),
            candidate_drone_id="D-1",
            candidate_battery_pct=95.0,
            candidate_endurance_s=1800.0,
        ),
        now=T0,
        cleared_polygon=square(46.5, 24.5, 0.5),
        cleared_altitude_min_m_agl=0.0,
        cleared_altitude_max_m_agl=120.0,
        **kwargs,
    )


def test_policy_input_is_json_serialisable(zone, request_, clearance) -> None:  # type: ignore[no-untyped-def]
    json.dumps(build(zone, request_, clearance), allow_nan=False)


def test_policy_input_carries_the_cleared_volume(zone, request_, clearance) -> None:  # type: ignore[no-untyped-def]
    """Without it the policy could only check a clearance exists, not that it covers this."""
    document = build(zone, request_, clearance)
    assert "polygon" in document["clearance"]
    assert document["clearance"]["altitude_max_m_agl"] == 120.0


def test_policy_input_omits_free_text(zone, request_, clearance) -> None:  # type: ignore[no-untyped-def]
    """Natural-language claims of authority are not a credential (Zero-Trust §4.2).

    The cleanest guarantee that the gate ignores free text is to never show it any.
    """
    blob = json.dumps(build(zone, request_, clearance))
    assert "CASE-SENSITIVE-REF" not in blob
    for key in ("justification", "rationale", "urgency", "note", "reference"):
        assert f'"{key}"' not in blob


def test_supersession_id_is_carried_only_when_asserted(zone, request_, clearance) -> None:  # type: ignore[no-untyped-def]
    assert "supersedes_command_id" not in build(zone, request_, clearance)["request"]
    with_supersede = build(zone, request_, clearance, supersedes_command_id="CMD-HUMAN-1")
    assert with_supersede["request"]["supersedes_command_id"] == "CMD-HUMAN-1"


def test_missing_clearance_is_simply_absent(zone, request_) -> None:  # type: ignore[no-untyped-def]
    """The policy denies on an absent clearance; it must not receive a forged stub."""
    document = build_deploy_recon_waypoint_input(
        request=request_,
        principal=zone.declared_by,
        incident_zone=zone,
        clearance=None,
        fleet=FleetSnapshot(),
        now=T0,
    )
    assert "clearance" not in document
