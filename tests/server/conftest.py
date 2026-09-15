"""Harness for end-to-end tests over the real HTTP surface.

These tests drive the actual FastAPI app through `TestClient`, so every middleware,
the JSON-RPC envelope, authentication, rate limiting, the sanitizer and the audit
trail are all in the path. Testing the handlers directly would skip exactly the layers
most likely to be misassembled.

The policy engine is driven by a `StaticPolicyTransport` rather than a live OPA. The
Rego itself is verified separately by `scripts/verify_policies.sh` (see `TM-13`); what
these tests verify is that the server *consults* the gate and *obeys* it -- including
when it is unavailable.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from dronez.airspace.client import AirspaceCache, AirspaceClearanceService
from dronez.airspace.mock_client import MockNfzSyncChannel, dev_key_registry
from dronez.safety.states import DroneState as FleetDroneState
from fleet_manager import DroneRecord, FleetRegistry
from mcp_server.app import RPC_PATH, create_app
from mcp_server.context import ServerContext
from mcp_server.feed import LiveAirspaceFeed
from mcp_server.guardrails.rate_limiter import AgentProposalLimiter
from mcp_server.guardrails.sanitizer import PromptSanitizer, StaticSanitizerClient
from mcp_server.repositories import (
    InMemoryFleetProvider,
    InMemoryMissionRegistry,
    MissionBinding,
)
from mcp_server.schemas.geo import GeoPolygon
from mcp_server.schemas.identity import (
    OperatorIdentity,
    Role,
    SignatureAlgorithm,
)
from mcp_server.schemas.incident_zone import (
    IncidentPriority,
    IncidentZone,
    IncidentZoneStatus,
)
from mcp_server.schemas.tools import DroneState, DroneStatus
from mcp_server.security import AuthenticatedPrincipal, StaticTokenResolver
from mcp_server.signing import (
    EMERGENCY_STOP_DECISION,
    NO_PLAN_DIGEST,
    KeyRegistry,
    NonceStore,
    VerificationKey,
    canonical_authorization_bytes,
)
from mcp_server.store import FlightPlanStore
from policy_engine import PolicyEngine, StaticPolicyTransport

T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)

# Opaque development bearer credentials. Not secrets: they authenticate nothing
# outside this test harness, which is why S105 is suppressed rather than obeyed.
CR_TOKEN = "dev-token-command-room"  # noqa: S105
FL_TOKEN = "dev-token-field-leader"  # noqa: S105
AGENT_TOKEN = "dev-token-agent"  # noqa: S105

CR_ID, FL_ID, AGENT_ID = "op-cr-001", "op-fl-001", "agent-session-7"
CR_CRED, FL_CRED = "cred-cr-1", "cred-fl-1"
MISSION_ID, ZONE_ID = "M-001", "IZ-1"

#: Inside the incident zone and clear of every mock NFZ restriction.
CLEAR_AREA = (46.60, 24.60, 0.002)
#: Inside NFZ-AERODROME-TEST-01.
AERODROME_AREA = (46.70, 24.70, 0.002)


def square(lon: float, lat: float, half: float) -> dict[str, Any]:
    return {
        "type": "Polygon",
        "coordinates": [[
            [lon - half, lat - half], [lon + half, lat - half],
            [lon + half, lat + half], [lon - half, lat + half],
            [lon - half, lat - half],
        ]],
    }


class Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@dataclass
class Harness:
    client: TestClient
    ctx: ServerContext
    clock: Clock
    channel: MockNfzSyncChannel
    transport: StaticPolicyTransport
    fleet: InMemoryFleetProvider
    drones: FleetRegistry
    signing_key: ec.EllipticCurvePrivateKey
    #: The field leader's own key. Master Plan §5 lets a field leader stop the zone
    #: without command-room mediation, so the harness must be able to sign as one.
    fl_signing_key: ec.EllipticCurvePrivateKey

    def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        token: str = CR_TOKEN,
        request_id: Any = 1,
        raw: Any = None,
        advance_s: float = 0.6,
    ) -> Any:
        """Issue one call.

        The clock advances by ``advance_s`` first, because the 2 proposals/second
        limit is real and a test clock frozen at one instant would trip it on the
        third call in every multi-step scenario. 0.6s keeps a steady stream under the
        limit indefinitely. Pass ``advance_s=0`` to test the limiter itself.
        """
        self.clock.advance(advance_s)
        payload = raw if raw is not None else {
            "jsonrpc": "2.0", "method": method, "params": params or {}, "id": request_id,
        }
        headers = {"Host": "localhost"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.client.post(RPC_PATH, json=payload, headers=headers)

    def sign_confirmation(
        self,
        *,
        flight_plan_id: str,
        digest: str,
        decision: str = "approve",
        operator_id: str = CR_ID,
        credential: str = CR_CRED,
        nonce: str = "nonce-0000000000000001",
        mission_id: str = MISSION_ID,
        role: str = "command_room",
        key_id: str = "key-cr-1",
        key: ec.EllipticCurvePrivateKey | None = None,
    ) -> dict[str, Any]:
        signer = key or self.signing_key
        signed_at = self.clock()
        expires_at = signed_at + timedelta(seconds=120)
        blob = canonical_authorization_bytes(
            flight_plan_id=flight_plan_id,
            flight_plan_digest=digest,
            decision=decision,
            mission_id=mission_id,
            operator_id=operator_id,
            nonce=nonce,
            signed_at=signed_at,
            expires_at=expires_at,
        )
        sig = signer.sign(blob, ec.ECDSA(hashes.SHA256()))
        return {
            "issuer": {
                "operator_id": operator_id,
                "role": role,
                "fido2_credential_id": credential,
                "authorized_zone_ids": [ZONE_ID],
            },
            "signature": {
                "algorithm": "ES256",
                "key_id": key_id,
                "fido2_credential_id": credential,
                "value": sig.hex(),
                "signed_at": signed_at.isoformat(),
                "expires_at": expires_at.isoformat(),
                "nonce": nonce,
            },
            "mission_id": mission_id,
        }

    def sign_stop(
        self,
        *,
        incident_zone_id: str = ZONE_ID,
        operator_id: str = FL_ID,
        credential: str = FL_CRED,
        role: str = "field_leader",
        key_id: str = "key-fl-1",
        key: ec.EllipticCurvePrivateKey | None = None,
        nonce: str = "nonce-stop-000000000001",
    ) -> dict[str, Any]:
        """Sign an emergency-stop authorization over the stop's own domain."""
        return self.sign_confirmation(
            flight_plan_id=incident_zone_id,
            digest=NO_PLAN_DIGEST,
            decision=EMERGENCY_STOP_DECISION,
            operator_id=operator_id,
            credential=credential,
            nonce=nonce,
            role=role,
            key_id=key_id,
            key=key or self.fl_signing_key,
        )


def _allow_transport() -> StaticPolicyTransport:
    return StaticPolicyTransport(
        result={"allow": True, "deny": [], "policy_version": "deploy_recon_waypoint/1.0.0"}
    )


@pytest.fixture
def harness() -> Iterator[Harness]:
    clock = Clock()

    channel = MockNfzSyncChannel(clock=clock)
    cache = AirspaceCache(dev_key_registry(), clock=clock)
    clearance = AirspaceClearanceService(cache, clock=clock)
    feed = LiveAirspaceFeed(cache, clearance, channel, clock=clock)

    command_room = OperatorIdentity(
        operator_id=CR_ID, role=Role.COMMAND_ROOM,
        fido2_credential_id=CR_CRED, authorized_zone_ids=frozenset({ZONE_ID}),
    )
    field_leader = OperatorIdentity(
        operator_id=FL_ID, role=Role.FIELD_LEADER,
        fido2_credential_id=FL_CRED, authorized_zone_ids=frozenset({ZONE_ID}),
    )
    agent = OperatorIdentity(
        operator_id=AGENT_ID, role=Role.AI_AGENT, authorized_zone_ids=frozenset({ZONE_ID})
    )

    zone = IncidentZone(
        incident_zone_id=ZONE_ID,
        # from_rings, not model_validate: strict Python mode rejects a list where a
        # tuple is declared. The same distinction the ingress path documents.
        boundary=GeoPolygon.from_rings(square(46.65, 24.65, 0.30)["coordinates"]),
        priority=IncidentPriority.P1_CRITICAL,
        status=IncidentZoneStatus.ACTIVE,
        authorized_from=T0 - timedelta(hours=1),
        authorized_until=T0 + timedelta(hours=2),
        altitude_ceiling_m_agl=110.0,
        altitude_floor_m_agl=20.0,
        declared_by=command_room,
        authorized_operator_ids=frozenset({CR_ID, FL_ID, AGENT_ID}),
    )

    signing_key = ec.generate_private_key(ec.SECP256R1())
    fl_signing_key = ec.generate_private_key(ec.SECP256R1())
    key_registry = KeyRegistry((
        VerificationKey(
            key_id="key-cr-1",
            algorithm=SignatureAlgorithm.ES256,
            material=signing_key.public_key(),
            operator_id=CR_ID,
            fido2_credential_id=CR_CRED,
        ),
        VerificationKey(
            key_id="key-fl-1",
            algorithm=SignatureAlgorithm.ES256,
            material=fl_signing_key.public_key(),
            operator_id=FL_ID,
            fido2_credential_id=FL_CRED,
        ),
    ))

    fleet = InMemoryFleetProvider(
        (
            DroneStatus(
                drone_id="D-1", state=DroneState.IDLE, battery_pct=95.0,
                available=True, airframe_type="quad-micro",
            ),
        ),
        endurance_s_by_drone={"D-1": 2400.0},
    )
    # The fleet registry is the richer view: it carries state, endurance, telemetry age
    # and home zone, which the flat DroneStatus DTO deliberately does not expose.
    drones = FleetRegistry(
        (
            DroneRecord(
                drone_id="D-1", airframe_type="quad-micro",
                state=FleetDroneState.IDLE, battery_pct=95.0, endurance_s=2400.0,
                last_seen_utc=T0, home_zone_id=ZONE_ID,
            ),
            DroneRecord(
                drone_id="D-2", airframe_type="quad-micro",
                state=FleetDroneState.ON_STATION, battery_pct=64.0, endurance_s=1500.0,
                last_seen_utc=T0, home_zone_id=ZONE_ID, current_mission_id=MISSION_ID,
            ),
            DroneRecord(
                drone_id="D-3", airframe_type="quad-micro",
                state=FleetDroneState.IDLE, battery_pct=88.0, endurance_s=2200.0,
                last_seen_utc=T0, home_zone_id=ZONE_ID, maintenance_grounded=True,
            ),
            DroneRecord(
                drone_id="D-9", airframe_type="quad-micro",
                state=FleetDroneState.ON_STATION, battery_pct=70.0, endurance_s=1800.0,
                last_seen_utc=T0, home_zone_id="IZ-OTHER",
            ),
        ),
        clock=clock,
    )
    transport = _allow_transport()

    ctx = ServerContext(
        feed=feed,
        policy=PolicyEngine(transport),
        missions=InMemoryMissionRegistry((MissionBinding(MISSION_ID, zone),)),
        fleet=fleet,
        sanitizer=PromptSanitizer(StaticSanitizerClient()),
        resolver=StaticTokenResolver({
            CR_TOKEN: AuthenticatedPrincipal(command_room, "sess-cr", device_attested=True),
            FL_TOKEN: AuthenticatedPrincipal(field_leader, "sess-fl", device_attested=True),
            AGENT_TOKEN: AuthenticatedPrincipal(agent, "sess-agent"),
        }),
        store=FlightPlanStore(clock=clock),
        fleet_registry=drones,
        key_registry=key_registry,
        nonces=NonceStore(clock=clock),
        proposal_limiter=AgentProposalLimiter(clock=lambda: clock().timestamp()),
        clock=clock,
    )

    app = create_app(
        ctx, allowed_hosts=("localhost", "testserver"),
        require_tls=False, start_feed_refresh=False,
    )
    with TestClient(app) as client:
        yield Harness(
            client, ctx, clock, channel, transport, fleet, drones,
            signing_key, fl_signing_key,
        )


def deploy_params(
    area: tuple[float, float, float] = CLEAR_AREA, **overrides: Any
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "mission_id": MISSION_ID,
        "polygon": square(*area),
        "altitude_min_m_agl": 30.0,
        "altitude_max_m_agl": 100.0,
        "velocity_max_mps": 10.0,
        "pattern_type": "grid",
        "duration_s": 900.0,
    }
    params.update(overrides)
    return params


def clearance_params(area: tuple[float, float, float] = CLEAR_AREA) -> dict[str, Any]:
    return {
        "mission_id": MISSION_ID,
        "polygon": square(*area),
        "altitude_min_m_agl": 30.0,
        "altitude_max_m_agl": 100.0,
    }
