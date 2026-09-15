"""End-to-end behaviour of the three implemented tools.

The governing invariants, swept below:

* **No clearance, no plan.** ``deploy_recon_waypoint`` obtains a clearance itself and
  refuses without an affirmative, current one.
* **No policy allow, no plan.** Including when the policy engine is unreachable.
* **No valid human signature, no dispatch.** And a valid one can only be used once.
* **Nothing reaches hardware.** Even a fully authorized, human-confirmed plan.
"""

from __future__ import annotations

import pytest
from tests.server.conftest import (
    AERODROME_AREA,
    AGENT_TOKEN,
    CR_ID,
    FL_TOKEN,
    Harness,
    clearance_params,
    deploy_params,
)

from dronez.airspace.mock_client import FaultMode
from mcp_server.audit import Outcome
from mcp_server.dispatch import DispatchOutcome, DispatchResult, GatedDispatcher
from mcp_server.schemas.tools import DroneState, DroneStatus
from policy_engine import StaticPolicyTransport
from policy_engine.client import PolicyTransportError


def result_of(response) -> dict:  # type: ignore[no-untyped-def]
    body = response.json()
    assert "result" in body, f"expected a result, got {body}"
    return body["result"]


# --------------------------------------------------------------------------- #
# check_airspace_clearance
# --------------------------------------------------------------------------- #

def test_clear_volume_is_cleared(harness: Harness) -> None:
    result = result_of(harness.rpc("check_airspace_clearance", clearance_params()))
    assert result["cleared"] is True
    assert result["expires_utc"] is not None
    assert result["feed_sequence"] is not None


def test_restricted_volume_is_denied_and_names_the_zone(harness: Harness) -> None:
    result = result_of(harness.rpc("check_airspace_clearance", clearance_params(AERODROME_AREA)))
    assert result["cleared"] is False
    assert result["reason"] == "zone_conflict"
    assert "NFZ-AERODROME-TEST-01" in result["blocking_zone_ids"]


def test_clearance_is_evaluated_against_the_live_feed(harness: Harness) -> None:
    """The handler refreshes before deciding, so the first call syncs."""
    assert harness.channel.fetch_count == 0
    harness.rpc("check_airspace_clearance", clearance_params())
    assert harness.channel.fetch_count >= 1


def test_stale_feed_fails_closed(harness: Harness) -> None:
    """Master Plan §4: a cached snapshot is never authoritative past its window."""
    harness.rpc("check_airspace_clearance", clearance_params())
    harness.channel.fault = FaultMode.UNREACHABLE
    harness.clock.advance(600)

    result = result_of(harness.rpc("check_airspace_clearance", clearance_params()))
    assert result["cleared"] is False
    assert result["reason"] == "feed_stale"
    assert "feed refresh failed" in result["detail"]


def test_unreachable_feed_on_first_call_fails_closed(harness: Harness) -> None:
    """An empty cache means 'we do not know', which is not 'clear'."""
    harness.channel.fault = FaultMode.UNREACHABLE
    result = result_of(harness.rpc("check_airspace_clearance", clearance_params()))
    assert result["cleared"] is False
    assert result["reason"] == "feed_never_synced"


def test_tampered_bulletin_cannot_open_restricted_airspace(harness: Harness) -> None:
    harness.rpc("check_airspace_clearance", clearance_params())
    harness.channel.fault = FaultMode.TAMPERED_BODY
    harness.clock.advance(600)

    result = result_of(harness.rpc("check_airspace_clearance", clearance_params(AERODROME_AREA)))
    assert result["cleared"] is False


def test_clearance_denial_is_audited(harness: Harness) -> None:
    harness.rpc("check_airspace_clearance", clearance_params(AERODROME_AREA))
    assert harness.ctx.audit_sink.by_outcome(Outcome.REJECTED_CLEARANCE)


# --------------------------------------------------------------------------- #
# deploy_recon_waypoint
# --------------------------------------------------------------------------- #

def test_valid_proposal_is_staged_not_dispatched(harness: Harness) -> None:
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params()))
    assert result["accepted"] is True
    assert result["requires_confirmation"] is True
    assert result["flight_plan_id"] and result["flight_plan_digest"]
    assert result["assigned_drone_id"] == "D-1"
    assert len(harness.ctx.store) == 1


def test_staging_is_audited_as_staged_not_dispatched(harness: Harness) -> None:
    harness.rpc("deploy_recon_waypoint", deploy_params())
    assert harness.ctx.audit_sink.by_outcome(Outcome.STAGED)
    assert not harness.ctx.audit_sink.by_outcome(Outcome.DISPATCHED)


def test_deploy_obtains_its_own_clearance(harness: Harness) -> None:
    """The caller cannot supply one, and the handler does not proceed without one."""
    before = harness.channel.fetch_count
    harness.rpc("deploy_recon_waypoint", deploy_params())
    assert harness.channel.fetch_count > before


def test_deploy_over_restricted_airspace_is_refused(harness: Harness) -> None:
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params(AERODROME_AREA)))
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "airspace_denied"
    assert "NFZ-AERODROME-TEST-01" in result["rejection"]["offending_ids"]
    assert len(harness.ctx.store) == 0


def test_deploy_with_a_stale_feed_is_refused(harness: Harness) -> None:
    harness.rpc("check_airspace_clearance", clearance_params())
    harness.channel.fault = FaultMode.UNREACHABLE
    harness.clock.advance(600)

    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params()))
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "clearance_stale"


def test_deploy_is_refused_when_the_policy_denies(harness: Harness) -> None:
    harness.ctx.policy = _policy(harness, result={
        "allow": False,
        "deny": [{"code": "outside_incident_zone", "detail": "not contained"}],
    })
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params()))
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "outside_incident_zone"
    assert len(harness.ctx.store) == 0


def test_deploy_is_refused_when_the_policy_engine_is_unreachable(harness: Harness) -> None:
    """An outage of the gate is a denial, never a bypass."""
    harness.ctx.policy = _policy(harness, raise_error=PolicyTransportError("connection refused"))
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params()))
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "policy_engine_unavailable"


def test_deploy_is_refused_when_the_policy_is_undefined(harness: Harness) -> None:
    """OPA omits `result` when a policy failed to load. That is not an open gate."""
    harness.ctx.policy = _policy(harness, body=b"{}")
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params()))
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "policy_engine_unavailable"


def test_deploy_is_refused_for_an_unknown_mission(harness: Harness) -> None:
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params(mission_id="M-UNKNOWN")))
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "zone_inactive"


def test_deploy_is_refused_when_no_drone_is_available(harness: Harness) -> None:
    harness.fleet.set_drones(
        (
            DroneStatus(
                drone_id="D-1", state=DroneState.MAINTENANCE, battery_pct=95.0,
                available=False, airframe_type="quad-micro", maintenance_grounded=True,
            ),
        ),
        endurance_s_by_drone={},
    )
    harness.ctx.policy = _policy(harness, result={
        "allow": False,
        "deny": [{"code": "fleet_unavailable", "detail": "no drone available"}],
    })
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params()))
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "fleet_unavailable"


def test_rejection_carries_its_audit_record_id(harness: Harness) -> None:
    """A rejected proposal is traceable back to its Command record."""
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params(AERODROME_AREA)))
    assert result["rejection"]["command_record_id"].startswith("cmd-")


@pytest.mark.parametrize(
    "override",
    [
        {"altitude_max_m_agl": 500.0},
        {"altitude_min_m_agl": 2.0},
        {"velocity_max_mps": 40.0},
        {"pattern_type": "freeform"},
        {"duration_s": 99999.0},
    ],
)
def test_envelope_violations_are_refused_at_the_schema(harness: Harness, override: dict) -> None:
    """These never reach a handler; the type system rejects them first."""
    body = harness.rpc("deploy_recon_waypoint", deploy_params(**override)).json()
    assert body["error"]["code"] == -32602


def _policy(harness: Harness, **kwargs: object):  # type: ignore[no-untyped-def]
    from policy_engine import PolicyEngine

    engine = PolicyEngine(StaticPolicyTransport(**kwargs))  # type: ignore[arg-type]
    harness.ctx.handlers = harness.ctx.handlers  # keep the mapping identity stable
    from mcp_server.context import build_handlers

    harness.ctx.policy = engine
    harness.ctx.handlers = build_handlers(harness.ctx)
    return engine


# --------------------------------------------------------------------------- #
# confirm_flight_plan
# --------------------------------------------------------------------------- #

def _stage(harness: Harness) -> tuple[str, str]:
    result = result_of(harness.rpc("deploy_recon_waypoint", deploy_params()))
    assert result["accepted"] is True
    return result["flight_plan_id"], result["flight_plan_digest"]


def test_confirmed_plan_is_authorized_but_not_dispatched(harness: Harness) -> None:
    """THE headline test.

    Every gate passes -- schema, clearance, policy, human signature, digest -- and the
    plan still does not reach an airframe, because the Milestone-0 gate is open.
    """
    plan_id, digest = _stage(harness)
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id,
        "flight_plan_digest": digest,
        "decision": "approve",
        "authorization": harness.sign_confirmation(flight_plan_id=plan_id, digest=digest),
    }))

    assert result["decision"] == "approve"
    assert result["confirmed_by_operator_id"] == CR_ID
    assert result["dispatched"] is False
    assert "Milestone-0 gate is open" in result["rejection"]["detail"]

    records = harness.ctx.audit_sink.by_outcome(Outcome.REJECTED_DISPATCH_GATE)
    assert records and records[-1].decision["authorization_complete"] is True
    assert not harness.ctx.audit_sink.by_outcome(Outcome.DISPATCHED)


def test_confirmation_consumes_the_plan_exactly_once(harness: Harness) -> None:
    """A captured confirmation cannot dispatch a second sortie."""
    plan_id, digest = _stage(harness)
    auth = harness.sign_confirmation(flight_plan_id=plan_id, digest=digest)
    params = {
        "flight_plan_id": plan_id, "flight_plan_digest": digest,
        "decision": "approve", "authorization": auth,
    }
    first = result_of(harness.rpc("confirm_flight_plan", params))
    assert first["rejection"]["code"] == "dispatch_gate_closed"

    second = result_of(harness.rpc("confirm_flight_plan", params))
    assert second["dispatched"] is False
    # Rejected at the signature stage: the nonce was already spent.
    assert second["rejection"]["code"] in {"nonce_replayed", "signature_invalid"}
    assert len(harness.ctx.store) == 0


def test_replayed_nonce_is_rejected(harness: Harness) -> None:
    """Closes TM-15: a validity window alone is not replay protection."""
    plan_id, digest = _stage(harness)
    harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id, "flight_plan_digest": digest, "decision": "approve",
        "authorization": harness.sign_confirmation(
            flight_plan_id=plan_id, digest=digest, nonce="nonce-reused-0000001"
        ),
    })

    plan_id2, digest2 = _stage(harness)
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id2, "flight_plan_digest": digest2, "decision": "approve",
        "authorization": harness.sign_confirmation(
            flight_plan_id=plan_id2, digest=digest2, nonce="nonce-reused-0000001"
        ),
    }))
    assert result["rejection"]["code"] == "nonce_replayed"


def test_digest_mismatch_is_refused(harness: Harness) -> None:
    """The operator confirms what they reviewed, not merely an identifier."""
    plan_id, _staged_digest = _stage(harness)
    wrong = "f" * 64
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id, "flight_plan_digest": wrong, "decision": "approve",
        "authorization": harness.sign_confirmation(flight_plan_id=plan_id, digest=wrong),
    }))
    assert result["rejection"]["code"] == "plan_digest_mismatch"
    assert len(harness.ctx.store) == 1, "a mismatched confirmation must not consume the plan"


def test_signature_for_a_different_plan_is_refused(harness: Harness) -> None:
    """A signature that did not name this plan cannot authorize it."""
    plan_id, digest = _stage(harness)
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id, "flight_plan_digest": digest, "decision": "approve",
        "authorization": harness.sign_confirmation(
            flight_plan_id="FP-somethingelse", digest=digest
        ),
    }))
    assert result["rejection"]["code"] == "signature_invalid"


def test_signature_for_a_different_decision_is_refused(harness: Harness) -> None:
    """An approval cannot be replayed as a rejection, or the reverse."""
    plan_id, digest = _stage(harness)
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id, "flight_plan_digest": digest, "decision": "approve",
        "authorization": harness.sign_confirmation(
            flight_plan_id=plan_id, digest=digest, decision="reject"
        ),
    }))
    assert result["rejection"]["code"] == "signature_invalid"


def test_forged_signature_is_refused(harness: Harness) -> None:
    plan_id, digest = _stage(harness)
    auth = harness.sign_confirmation(flight_plan_id=plan_id, digest=digest)
    auth["signature"]["value"] = "00" * 70
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id, "flight_plan_digest": digest,
        "decision": "approve", "authorization": auth,
    }))
    assert result["rejection"]["code"] == "signature_invalid"


def test_unknown_signing_key_is_refused(harness: Harness) -> None:
    plan_id, digest = _stage(harness)
    auth = harness.sign_confirmation(flight_plan_id=plan_id, digest=digest)
    auth["signature"]["key_id"] = "attacker-key-999"
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id, "flight_plan_digest": digest,
        "decision": "approve", "authorization": auth,
    }))
    assert result["rejection"]["code"] == "signature_invalid"


def test_session_must_match_the_signing_operator(harness: Harness) -> None:
    """A field leader may not submit the command room's authorization."""
    plan_id, digest = _stage(harness)
    result = result_of(harness.rpc(
        "confirm_flight_plan",
        {
            "flight_plan_id": plan_id, "flight_plan_digest": digest, "decision": "approve",
            "authorization": harness.sign_confirmation(flight_plan_id=plan_id, digest=digest),
        },
        token=FL_TOKEN,
    ))
    assert result["rejection"]["code"] == "signature_invalid"


def test_agent_session_cannot_confirm(harness: Harness) -> None:
    plan_id, digest = _stage(harness)
    body = harness.rpc(
        "confirm_flight_plan",
        {
            "flight_plan_id": plan_id, "flight_plan_digest": digest, "decision": "approve",
            "authorization": harness.sign_confirmation(flight_plan_id=plan_id, digest=digest),
        },
        token=AGENT_TOKEN,
    ).json()
    assert body["error"]["code"] == -32002


def test_expired_plan_cannot_be_confirmed(harness: Harness) -> None:
    """A staged plan dies with the clearance it was authorized against."""
    plan_id, digest = _stage(harness)
    harness.clock.advance(600)
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id, "flight_plan_digest": digest, "decision": "approve",
        "authorization": harness.sign_confirmation(flight_plan_id=plan_id, digest=digest),
    }))
    assert result["rejection"]["code"] in {"clearance_stale", "signature_invalid"}


def test_operator_rejection_is_recorded_and_consumes_the_plan(harness: Harness) -> None:
    plan_id, digest = _stage(harness)
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id, "flight_plan_digest": digest, "decision": "reject",
        "authorization": harness.sign_confirmation(
            flight_plan_id=plan_id, digest=digest, decision="reject"
        ),
    }))
    assert result["decision"] == "reject"
    assert result["dispatched"] is False
    assert result["rejection"] is None
    assert len(harness.ctx.store) == 0


def test_dispatch_seam_is_the_only_path_to_hardware(harness: Harness) -> None:
    """Swapping the dispatcher is the single change that would let a plan fly.

    Asserted explicitly so that if someone implements dispatch, this test tells them
    exactly which gate they just opened.
    """
    class RecordingDispatcher:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def dispatch(self, plan):  # type: ignore[no-untyped-def]
            self.calls.append(plan.flight_plan_id)
            return DispatchResult(
                dispatched=True, outcome=DispatchOutcome.DISPATCHED,
                detail="test dispatcher", drone_id=plan.assigned_drone_id,
                dispatched_utc=harness.clock(),
            )

    recorder = RecordingDispatcher()
    harness.ctx.dispatcher = recorder
    from mcp_server.context import build_handlers

    harness.ctx.handlers = build_handlers(harness.ctx)

    plan_id, digest = _stage(harness)
    result = result_of(harness.rpc("confirm_flight_plan", {
        "flight_plan_id": plan_id, "flight_plan_digest": digest, "decision": "approve",
        "authorization": harness.sign_confirmation(flight_plan_id=plan_id, digest=digest),
    }))
    assert result["dispatched"] is True
    assert recorder.calls == [plan_id]

    # And the shipped default refuses.
    assert GatedDispatcher().dispatch(
        harness.ctx.store.peek(plan_id) or _FakePlan()
    ).dispatched is False


class _FakePlan:
    flight_plan_id = "FP-none"
    assigned_drone_id = None
