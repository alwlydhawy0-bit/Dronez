"""Transport, authentication and JSON-RPC envelope behaviour over the real HTTP surface."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from tests.server.conftest import AGENT_TOKEN, CR_TOKEN, Harness, clearance_params

from dronez.airspace.client import AirspaceCache, AirspaceClearanceService
from dronez.airspace.mock_client import MockNfzSyncChannel, dev_key_registry
from mcp_server.app import RPC_PATH, create_app
from mcp_server.audit import Outcome
from mcp_server.context import ServerContext
from mcp_server.feed import LiveAirspaceFeed
from mcp_server.guardrails.sanitizer import PromptSanitizer, StaticSanitizerClient
from mcp_server.repositories import InMemoryFleetProvider, InMemoryMissionRegistry
from mcp_server.security import SECURITY_HEADERS, StaticTokenResolver
from policy_engine import PolicyEngine, StaticPolicyTransport


def test_healthz_needs_no_credential(harness: Harness) -> None:
    response = harness.client.get("/healthz", headers={"Host": "localhost"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_security_headers_on_every_response(harness: Harness) -> None:
    for response in (
        harness.client.get("/healthz", headers={"Host": "localhost"}),
        harness.rpc("check_airspace_clearance", clearance_params()),
        harness.rpc("check_airspace_clearance", {}, token=""),
    ):
        for header, value in SECURITY_HEADERS.items():
            assert response.headers.get(header) == value, f"{header} missing on {response.url}"


def test_unauthenticated_request_is_refused(harness: Harness) -> None:
    response = harness.rpc("check_airspace_clearance", clearance_params(), token="")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == -32001
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_unknown_credential_is_refused(harness: Harness) -> None:
    response = harness.rpc(
        "check_airspace_clearance", clearance_params(), token="not-a-token"  # noqa: S106
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "header",
    ["Token abc", "Bearer", "Bearer  ", "bearer  abc  def", "abc"],
)
def test_malformed_authorization_header_is_refused(harness: Harness, header: str) -> None:
    """A lenient parser here is a differential between the server and whatever audits it."""
    response = harness.client.post(
        RPC_PATH,
        json={"jsonrpc": "2.0", "method": "check_airspace_clearance", "params": {}, "id": 1},
        headers={"Host": "localhost", "Authorization": header},
    )
    assert response.status_code == 401


def test_unauthenticated_attempt_is_audited(harness: Harness) -> None:
    harness.rpc("check_airspace_clearance", clearance_params(), token="")
    assert harness.ctx.audit_sink.by_outcome(Outcome.REJECTED_AUTH)


def test_host_header_must_be_allow_listed(harness: Harness) -> None:
    """Wildcard or absent Host validation is forbidden (Zero-Trust §3.3)."""
    response = harness.client.post(
        RPC_PATH,
        json={"jsonrpc": "2.0", "method": "check_airspace_clearance", "params": {}, "id": 1},
        headers={"Host": "evil.example.com", "Authorization": f"Bearer {CR_TOKEN}"},
    )
    assert response.status_code == 421


def test_oversized_body_is_refused(harness: Harness) -> None:
    response = harness.client.post(
        RPC_PATH,
        content=b"x" * (300 * 1024),
        headers={
            "Host": "localhost",
            "Authorization": f"Bearer {CR_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == -32005


def test_docs_endpoints_are_not_exposed(harness: Harness) -> None:
    """The tool catalogue is reconnaissance; it is not published unauthenticated."""
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert harness.client.get(path, headers={"Host": "localhost"}).status_code == 404


@pytest.mark.parametrize(
    "body, expected_code",
    [
        (b"{oops", -32700),
        (b'{"jsonrpc":"1.0","method":"check_airspace_clearance","id":1}', -32600),
        (b'{"jsonrpc":"2.0","method":"check_airspace_clearance","params":[1],"id":1}', -32602),
        (b'{"jsonrpc":"2.0","method":"x","id":1,"extra":true}', -32600),
        (b"[]", -32600),
    ],
)
def test_malformed_envelopes_are_rejected(
    harness: Harness, body: bytes, expected_code: int
) -> None:
    response = harness.client.post(
        RPC_PATH,
        content=body,
        headers={
            "Host": "localhost",
            "Authorization": f"Bearer {CR_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    assert response.json()["error"]["code"] == expected_code


def test_unknown_method_is_method_not_found(harness: Harness) -> None:
    assert harness.rpc("no_such_tool", {}).json()["error"]["code"] == -32601


def test_specified_but_unimplemented_tool_is_method_not_found(harness: Harness) -> None:
    """A tool with a contract but no handler is not advertised as available.

    ``execute_safe_return`` is the remaining case: an RTL is a command to an airborne
    airframe, so every path to it runs through the dispatch seam CLAUDE.md §2.1 holds
    closed. The server reports it as absent rather than registering a placeholder that
    would advertise a capability it does not have.
    """
    body = harness.rpc("execute_safe_return", {}).json()
    assert body["error"]["code"] == -32601
    assert "not implemented" in body["error"]["message"]


def test_invalid_params_report_locations_not_values(harness: Harness) -> None:
    """An error body reaches a caller who may be an attacker."""
    params = clearance_params()
    params["altitude_max_m_agl"] = 9999.0
    params["mission_id"] = "SENSITIVE-MISSION-NAME"
    body = harness.rpc("check_airspace_clearance", params).json()
    assert body["error"]["code"] == -32602
    blob = json.dumps(body)
    assert "9999" not in blob
    assert "SENSITIVE-MISSION-NAME" not in blob


def test_notification_gets_no_response(harness: Harness) -> None:
    response = harness.rpc(
        "", None, raw={"jsonrpc": "2.0", "method": "check_airspace_clearance",
                       "params": clearance_params()},
    )
    assert response.status_code == 204


def test_notification_is_still_audited(harness: Harness) -> None:
    """A notification's only trace is the audit record, so it must be unconditional."""
    before = len(harness.ctx.audit_sink)
    harness.rpc(
        "", None, raw={"jsonrpc": "2.0", "method": "check_airspace_clearance",
                       "params": clearance_params()},
    )
    assert len(harness.ctx.audit_sink) > before


def test_batch_returns_one_result_per_call(harness: Harness) -> None:
    body = harness.rpc(
        "", None,
        raw=[
            {"jsonrpc": "2.0", "method": "check_airspace_clearance",
             "params": clearance_params(), "id": "a"},
            {"jsonrpc": "2.0", "method": "no_such_tool", "params": {}, "id": "b"},
        ],
    ).json()
    assert isinstance(body, list)
    assert {r["id"] for r in body} == {"a", "b"}
    assert "result" in body[0] and "error" in body[1]


def test_oversized_batch_is_rejected(harness: Harness) -> None:
    calls = [
        {"jsonrpc": "2.0", "method": "check_airspace_clearance", "params": {}, "id": i}
        for i in range(25)
    ]
    assert harness.rpc("", None, raw=calls).json()["error"]["code"] == -32600


def test_agent_cannot_invoke_a_human_only_tool(harness: Harness) -> None:
    """Confirmation is human authority, not agent capability."""
    body = harness.rpc("confirm_flight_plan", {}, token=AGENT_TOKEN).json()
    assert body["error"]["code"] == -32002


def test_scope_rejection_is_audited_as_a_security_signal(harness: Harness) -> None:
    harness.rpc("confirm_flight_plan", {}, token=AGENT_TOKEN)
    records = harness.ctx.audit_sink.by_outcome(Outcome.REJECTED_SCOPE)
    assert records and records[-1].outcome.is_security_signal


def test_status_requires_authentication(harness: Harness) -> None:
    assert harness.client.get("/status", headers={"Host": "localhost"}).status_code == 401
    ok = harness.client.get(
        "/status", headers={"Host": "localhost", "Authorization": f"Bearer {CR_TOKEN}"}
    )
    assert ok.status_code == 200
    assert "feed" in ok.json()


def test_plaintext_is_refused_when_tls_is_required() -> None:
    """The default posture. TestClient speaks http, so this must be refused."""
    clock_now = None  # the app under test does no clock work on this path
    channel = MockNfzSyncChannel()
    cache = AirspaceCache(dev_key_registry())
    feed = LiveAirspaceFeed(cache, AirspaceClearanceService(cache), channel)
    ctx = ServerContext(
        feed=feed,
        policy=PolicyEngine(StaticPolicyTransport(result={"allow": False, "deny": []})),
        missions=InMemoryMissionRegistry(),
        fleet=InMemoryFleetProvider(),
        sanitizer=PromptSanitizer(StaticSanitizerClient()),
        resolver=StaticTokenResolver({}),
    )
    app = create_app(
        ctx, allowed_hosts=("localhost", "testserver"),
        require_tls=True, start_feed_refresh=False,
    )
    with TestClient(app) as client:
        response = client.post(
            RPC_PATH, json={"jsonrpc": "2.0", "method": "x", "id": 1},
            headers={"Host": "localhost"},
        )
    assert clock_now is None
    assert response.status_code == 426
    assert response.json()["error"]["code"] == -32006
