"""``request_emergency_stop`` over the real HTTP surface.

The contract from Master Plan §5: a swarm/zone-wide broadcast kill switch, *"delivered
over a channel independent of the primary mission command path, callable by any
authenticated field leader physically in the affected zone without needing
command-room mediation."*

Three properties are load-bearing, and each has an obvious failure mode:

* **Independent channel.** A stop that travels down the path that failed is worth
  nothing in the case it exists for.
* **Signed.** An unauthenticated stop endpoint is a fleet-wide denial-of-service
  primitive.
* **Not policy-gated.** Fail-closed means denying *authority*, not denying *safety*.
  A stop makes the fleet strictly less capable, so an unreachable policy engine must
  not be able to prevent one.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from tests.server.conftest import (
    AGENT_TOKEN,
    CR_CRED,
    CR_ID,
    CR_TOKEN,
    FL_TOKEN,
    T0,
    ZONE_ID,
    Harness,
)

from dronez.safety.states import DroneState as FleetDroneState
from fleet_manager import DroneRecord
from mcp_server.emergency import (
    ChannelIndependenceError,
    EmergencyStop,
    InMemoryBroadcastChannel,
    StopReason,
    StopScope,
    assert_channel_independence,
)
from mcp_server.schemas.identity import Role


def stop_params(harness: Harness, **overrides: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "scope": "zone",
        "incident_zone_id": ZONE_ID,
        "reason": "personnel entering the structure",
        "authorization": harness.sign_stop(),
    }
    params.update(overrides)
    return params


def call(harness: Harness, params: dict[str, Any], *, token: str = FL_TOKEN) -> Any:
    body = harness.rpc("request_emergency_stop", params, token=token).json()
    assert "error" not in body, body
    return body["result"]


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #

def test_a_field_leader_can_stop_the_zone_without_command_room_mediation(
    harness: Harness,
) -> None:
    result = call(harness, stop_params(harness))
    assert result["broadcast"] is True
    assert result["channel"] == "independent-broadcast"
    assert result["broadcast_utc"]


def test_the_stop_targets_airborne_drones_in_that_zone(harness: Harness) -> None:
    """D-2 is on station in IZ-1; D-1 is idle; D-9 is flying in another zone."""
    result = call(harness, stop_params(harness))
    assert result["affected_drone_ids"] == ["D-2"]


def test_a_single_drone_stop_targets_only_that_drone(harness: Harness) -> None:
    result = call(
        harness, stop_params(harness, scope="single_drone", drone_id="D-2")
    )
    assert result["affected_drone_ids"] == ["D-2"]


def test_a_stop_with_nothing_airborne_is_a_success(harness: Harness) -> None:
    """The zone is already clear, which is the outcome the operator wanted."""
    harness.ctx.drones.upsert(
        DroneRecord(
            drone_id="D-2", airframe_type="quad-micro", state=FleetDroneState.RTL_TRIGGERED,
            battery_pct=60.0, endurance_s=1200.0, last_seen_utc=harness.clock(),
            home_zone_id=ZONE_ID,
        )
    )
    harness.ctx.drones.upsert(
        DroneRecord(
            drone_id="D-2", airframe_type="quad-micro", state=FleetDroneState.LANDING,
            battery_pct=58.0, endurance_s=1100.0, last_seen_utc=harness.clock(),
            home_zone_id=ZONE_ID,
        )
    )
    harness.ctx.drones.upsert(
        DroneRecord(
            drone_id="D-2", airframe_type="quad-micro", state=FleetDroneState.POST_FLIGHT,
            battery_pct=56.0, endurance_s=1000.0, last_seen_utc=harness.clock(),
            home_zone_id=ZONE_ID,
        )
    )
    result = call(harness, stop_params(harness))
    assert result["broadcast"] is True
    assert result["affected_drone_ids"] == []


def test_a_drone_in_degraded_landing_is_still_a_stop_target(harness: Harness) -> None:
    """The stop will not change its behaviour -- DVIL is firmware-resident and ignores
    inbound commands (spec §5) -- but the airframe must still appear in the target set
    so the operator sees the full picture of what is flying."""
    for state in (
        FleetDroneState.FAILSAFE,
        FleetDroneState.DEGRADED_VISUAL_INERTIAL_LANDING,
    ):
        harness.ctx.drones.upsert(
            DroneRecord(
                drone_id="D-2", airframe_type="quad-micro", state=state,
                battery_pct=55.0, endurance_s=900.0, last_seen_utc=harness.clock(),
                home_zone_id=ZONE_ID,
            )
        )
    assert call(harness, stop_params(harness))["affected_drone_ids"] == ["D-2"]


# --------------------------------------------------------------------------- #
# Authentication: the one check a stop cannot skip
# --------------------------------------------------------------------------- #

def test_an_unsigned_stop_is_impossible_to_express(harness: Harness) -> None:
    """The authorization is a required field, so there is no unsigned request shape."""
    params = stop_params(harness)
    del params["authorization"]
    assert harness.rpc(
        "request_emergency_stop", params, token=FL_TOKEN
    ).json()["error"]["code"] == -32602


def test_a_forged_signature_is_rejected(harness: Harness) -> None:
    auth = harness.sign_stop()
    auth["signature"]["value"] = "00" * 70
    result = call(harness, stop_params(harness, authorization=auth))
    assert result["broadcast"] is False
    assert result["rejection"]["code"] == "signature_invalid"


def test_a_stop_signature_cannot_be_replayed(harness: Harness) -> None:
    """Single-use nonces apply here too: a captured stop is a fleet-wide DoS if it can
    be resent."""
    auth = harness.sign_stop(nonce="nonce-stop-replay-0001")
    assert call(harness, stop_params(harness, authorization=auth))["broadcast"] is True

    replayed = call(harness, stop_params(harness, authorization=auth))
    assert replayed["broadcast"] is False
    assert replayed["rejection"]["code"] == "signature_invalid"


def test_a_session_cannot_present_another_operators_authorization(
    harness: Harness,
) -> None:
    """Zero-Trust §1.2: a signature is bound to a session, not merely valid."""
    command_room_auth = harness.sign_confirmation(
        flight_plan_id=ZONE_ID,
        digest="0" * 64,
        decision="emergency_stop",
        operator_id=CR_ID,
        credential=CR_CRED,
        nonce="nonce-stop-crossover-1",
    )
    result = call(harness, stop_params(harness, authorization=command_room_auth))
    assert result["broadcast"] is False
    assert "does not match" in result["rejection"]["detail"]


def test_a_flight_plan_approval_cannot_be_replayed_as_a_stop(harness: Harness) -> None:
    """Domain separation: the decision string is inside the signed bytes, so an
    approval signature does not verify against the stop's canonical form."""
    approval = harness.sign_stop()
    approval_over_approve = harness.sign_confirmation(
        flight_plan_id=ZONE_ID,
        digest="0" * 64,
        decision="approve",
        operator_id=approval["issuer"]["operator_id"],
        credential=approval["issuer"]["fido2_credential_id"],
        nonce="nonce-stop-domainsep-1",
        role="field_leader",
        key_id="key-fl-1",
        key=harness.fl_signing_key,
    )
    result = call(harness, stop_params(harness, authorization=approval_over_approve))
    assert result["broadcast"] is False
    assert result["rejection"]["code"] == "signature_invalid"


def test_a_stop_signed_for_another_zone_does_not_verify(harness: Harness) -> None:
    auth = harness.sign_stop(incident_zone_id="IZ-OTHER")
    result = call(harness, stop_params(harness, authorization=auth))
    assert result["broadcast"] is False
    assert result["rejection"]["code"] == "signature_invalid"


def test_an_unauthenticated_call_never_reaches_the_handler(harness: Harness) -> None:
    body = harness.rpc(
        "request_emergency_stop", stop_params(harness), token=""
    ).json()
    assert "error" in body


# --------------------------------------------------------------------------- #
# The agent cannot stop the fleet
# --------------------------------------------------------------------------- #

def test_an_agent_session_is_not_scoped_to_the_stop_tool(harness: Harness) -> None:
    """Refused at the capability gate, before the handler. A stop is a human judgement
    about physical safety, and an agent that could issue one could ground the fleet."""
    body = harness.rpc(
        "request_emergency_stop", stop_params(harness), token=AGENT_TOKEN
    ).json()
    assert "error" in body
    assert body["error"]["code"] == -32002  # FORBIDDEN_SCOPE


def test_an_agent_cannot_sign_a_stop_authorization() -> None:
    """The envelope schema refuses it outright -- Tier 3 proposes, a human disposes.

    Built through ``parse_json`` because that is the ingress path: strict mode is
    stricter in Python mode than in JSON mode, so a hand-built dict would be rejected
    for the wrong reason and prove nothing about the rule under test.
    """
    import json

    from pydantic import ValidationError

    from mcp_server.schemas.identity import SignedCommandEnvelope

    envelope = {
        "issuer": {
            "operator_id": "agent-session-7",
            "role": "ai_agent",
            "authorized_zone_ids": [ZONE_ID],
        },
        "signature": {
            "algorithm": "ES256",
            "key_id": "key-agent-1",
            "fido2_credential_id": "cred-agent-1",
            "value": "ab" * 32,
            "signed_at": T0.isoformat(),
            "expires_at": (T0 + timedelta(seconds=120)).isoformat(),
            "nonce": "nonce-agent-00000001",
        },
        "mission_id": "M-001",
    }
    with pytest.raises(ValidationError, match="cannot carry a command signature"):
        SignedCommandEnvelope.parse_json(json.dumps(envelope))


def test_an_agent_issued_stop_is_refused_by_the_domain_object() -> None:
    """Defence in depth: even constructed directly, the stop refuses an agent issuer."""
    with pytest.raises(ValueError, match="AI agent"):
        EmergencyStop(
            stop_id="stop-1", scope=StopScope.ZONE, incident_zone_id=ZONE_ID,
            reason=StopReason.OPERATOR_JUDGEMENT, issued_by_operator_id="agent-1",
            issued_by_role=Role.AI_AGENT, issued_utc=T0,
        )


# --------------------------------------------------------------------------- #
# Zone scoping
# --------------------------------------------------------------------------- #

def test_a_stop_for_an_unscoped_zone_is_refused(harness: Harness) -> None:
    auth = harness.sign_stop(incident_zone_id="IZ-OTHER")
    result = call(
        harness, stop_params(harness, incident_zone_id="IZ-OTHER", authorization=auth)
    )
    assert result["broadcast"] is False
    assert result["rejection"]["code"] == "not_authorized_for_zone"


def test_scope_is_checked_after_the_signature(harness: Harness) -> None:
    """Otherwise the endpoint enumerates which zones exist for an unsigned caller."""
    auth = harness.sign_stop()
    auth["signature"]["value"] = "00" * 70
    result = call(
        harness, stop_params(harness, incident_zone_id="IZ-OTHER", authorization=auth)
    )
    assert result["rejection"]["code"] == "signature_invalid"


# --------------------------------------------------------------------------- #
# Fail-closed means denying authority, not denying safety
# --------------------------------------------------------------------------- #

def test_a_stop_succeeds_with_the_policy_engine_unreachable(harness: Harness) -> None:
    """A deploy would be denied here. A stop must not be: denying a safety action is
    the wrong direction, and the policy engine is on the path that may have failed."""
    harness.transport.fail_with = RuntimeError("opa unreachable")
    assert call(harness, stop_params(harness))["broadcast"] is True


def test_a_stop_succeeds_with_the_airspace_feed_stale(harness: Harness) -> None:
    harness.clock.advance(10_000)
    harness.ctx.drones.upsert(
        DroneRecord(
            drone_id="D-2", airframe_type="quad-micro", state=FleetDroneState.ON_STATION,
            battery_pct=60.0, endurance_s=1200.0, last_seen_utc=harness.clock(),
            home_zone_id=ZONE_ID,
        )
    )
    result = call(harness, stop_params(harness))
    assert result["broadcast"] is True
    assert result["affected_drone_ids"] == ["D-2"]


# --------------------------------------------------------------------------- #
# Channel independence and delivery honesty
# --------------------------------------------------------------------------- #

def test_a_channel_sharing_the_dispatcher_refuses_to_compose() -> None:
    """Caught at composition time, so a server wired this way does not start."""
    shared = InMemoryBroadcastChannel()
    with pytest.raises(ChannelIndependenceError, match="same object"):
        assert_channel_independence(shared, shared)


def test_a_channel_sharing_a_transport_refuses_to_compose() -> None:
    class Sharing:
        channel_name = "sharing"

        def __init__(self, transport: object) -> None:
            self._transport = transport

        def broadcast(self, stop: object, drone_ids: object) -> tuple[Any, ...]:
            return ()

    transport = object()
    with pytest.raises(ChannelIndependenceError, match="shared transport"):
        assert_channel_independence(
            Sharing(transport),  # type: ignore[arg-type]
            Sharing(transport),
        )


def test_an_independent_channel_composes(harness: Harness) -> None:
    assert_channel_independence(InMemoryBroadcastChannel(), harness.ctx.dispatcher)


def test_partial_delivery_is_reported_as_partial(harness: Harness) -> None:
    """A stop that reached three of four drones has not met its contract, and the
    operator needs the list of which one it missed -- not a boolean."""
    from mcp_server.audit import Outcome
    from mcp_server.emergency import EmergencyStopService

    channel = InMemoryBroadcastChannel(unreachable=frozenset({"D-2"}))
    service = EmergencyStopService(channel, harness.ctx.audit, clock=harness.clock)
    result = service.broadcast(
        EmergencyStop(
            stop_id="stop-partial", scope=StopScope.ZONE, incident_zone_id=ZONE_ID,
            reason=StopReason.OPERATOR_JUDGEMENT, issued_by_operator_id=CR_ID,
            issued_by_role=Role.COMMAND_ROOM, issued_utc=harness.clock(),
        ),
        ("D-1", "D-2"),
    )
    assert result.delivered == ("D-1",)
    assert result.undelivered == ("D-2",)
    assert not result.complete
    assert harness.ctx.audit_sink.records()[-1].outcome is Outcome.ERROR


def test_a_raising_channel_reports_everything_undelivered_rather_than_raising(
    harness: Harness,
) -> None:
    """An exception carries no list of which drones were missed."""
    from mcp_server.emergency import EmergencyStopService

    class Broken:
        channel_name = "broken"

        def broadcast(self, stop: object, drone_ids: object) -> tuple[Any, ...]:
            raise OSError("rf link down")

    service = EmergencyStopService(
        Broken(),  # type: ignore[arg-type]
        harness.ctx.audit,
        clock=harness.clock,
    )
    result = service.broadcast(
        EmergencyStop(
            stop_id="stop-broken", scope=StopScope.ZONE, incident_zone_id=ZONE_ID,
            reason=StopReason.OPERATOR_JUDGEMENT, issued_by_operator_id=CR_ID,
            issued_by_role=Role.COMMAND_ROOM, issued_utc=harness.clock(),
        ),
        ("D-1", "D-2"),
    )
    assert result.delivered == ()
    assert result.undelivered == ("D-1", "D-2")
    assert not result.complete


# --------------------------------------------------------------------------- #
# Every attempt is on the record
# --------------------------------------------------------------------------- #

def test_a_stop_is_audited(harness: Harness) -> None:
    call(harness, stop_params(harness))
    tools = [r.tool for r in harness.ctx.audit_sink.records()]
    assert "request_emergency_stop" in tools


def test_a_rejected_stop_is_audited(harness: Harness) -> None:
    """CLAUDE.md §10.4: rejected attempts are a security signal. A pattern of forged
    stops is exactly the signal a SOC needs."""
    auth = harness.sign_stop()
    auth["signature"]["value"] = "00" * 70
    call(harness, stop_params(harness, authorization=auth))

    record = harness.ctx.audit_sink.records()[-1]
    assert record.tool == "request_emergency_stop"
    assert "signature_invalid" in record.reason_codes


def test_the_command_room_can_also_stop(harness: Harness) -> None:
    """Tier 1 is not excluded by the field-leader path."""
    auth = harness.sign_confirmation(
        flight_plan_id=ZONE_ID,
        digest="0" * 64,
        decision="emergency_stop",
        nonce="nonce-stop-cr-000000001",
    )
    assert call(
        harness, stop_params(harness, authorization=auth), token=CR_TOKEN
    )["broadcast"] is True
