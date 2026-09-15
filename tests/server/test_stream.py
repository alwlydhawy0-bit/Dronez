"""``stream_thermal_feed`` over the real HTTP surface.

Master Plan §5 gives this tool three obligations and all three are swept: authorization
against the mission's incident zone, time-boxing to that zone's window, and rejection at
the signaling layer of any client that cannot negotiate DTLS/SRTP.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from tests.server.conftest import AGENT_TOKEN, FL_TOKEN, Harness

from mcp_server.audit import Outcome
from mcp_server.media import ALLOWED_SRTP_PROFILES, MIN_DTLS_VERSION, DtlsSrtpPolicy

VALID_SDP = """v=0
o=- 4611731400430051336 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96 97
c=IN IP4 0.0.0.0
a=ice-ufrag:F7gI
a=ice-pwd:x9cml/YzichV2+XlhiMu8g
a=fingerprint:sha-256 D1:2C:BE:AD:C4:F6:64:5C:25:16:4E:4C:1D:0B:6F:2E
a=setup:actpass
a=mid:0
a=sendonly
a=rtcp-mux
a=rtpmap:96 VP8/90000
"""


FINGERPRINT_LINE = "a=fingerprint:sha-256 D1:2C:BE:AD:C4:F6:64:5C:25:16:4E:4C:1D:0B:6F:2E"


def stream_params(sdp: str = VALID_SDP, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "mission_id": "M-001",
        "drone_id": "D-1",
        "stream_quality": "adaptive",
        "detection_mode": "active_object_detection",
        "sdp_offer": sdp,
    }
    params.update(overrides)
    return params


def result_of(response):  # type: ignore[no-untyped-def]
    body = response.json()
    assert "result" in body, f"expected a result, got {body}"
    return body["result"]


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #

def test_authorized_stream_opens(harness: Harness) -> None:
    result = result_of(harness.rpc("stream_thermal_feed", stream_params()))
    assert result["accepted"] is True
    assert result["session_id"]
    assert result["transport"] == "dtls1.3-srtp"
    assert result["frame_hash_algorithm"] == "sha256-edge"


def test_session_is_time_boxed_to_the_zone_window(harness: Harness) -> None:
    """A session cannot outlive the authorization that created it."""
    result = result_of(harness.rpc("stream_thermal_feed", stream_params()))
    expires = datetime.fromisoformat(result["expires_utc"])
    zone = harness.ctx.missions.binding_for("M-001").incident_zone  # type: ignore[union-attr]
    assert expires <= zone.authorized_until


def test_session_is_registered(harness: Harness) -> None:
    result = result_of(harness.rpc("stream_thermal_feed", stream_params()))
    session = harness.ctx.stream_sessions.get(result["session_id"])
    assert session is not None
    assert session.mission_id == "M-001"


def test_agent_sessions_may_request_a_feed(harness: Harness) -> None:
    """Read-only sensing is within an agent's scope; actuation is not."""
    result = result_of(harness.rpc("stream_thermal_feed", stream_params(), token=AGENT_TOKEN))
    assert result["accepted"] is True


# --------------------------------------------------------------------------- #
# Transport enforcement at the signaling layer
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "mutation, label",
    [
        (("UDP/TLS/RTP/SAVPF", "RTP/AVP"), "plaintext RTP"),
        (("UDP/TLS/RTP/SAVPF", "RTP/SAVP"), "SDES-keyed SAVP"),
        (("sha-256", "sha-1"), "SHA-1 fingerprint"),
        (("a=ice-ufrag:F7gI\n", ""), "no ICE ufrag"),
        ((FINGERPRINT_LINE + "\n", ""), "no fingerprint"),
        (("a=setup:actpass\n", ""), "no DTLS setup role"),
        (("m=video", "m=audio"), "audio track"),
    ],
)
def test_unacceptable_offers_are_rejected(
    harness: Harness, mutation: tuple[str, str], label: str
) -> None:
    sdp = VALID_SDP.replace(*mutation)
    assert sdp != VALID_SDP, f"{label}: mutation did not apply"
    result = result_of(harness.rpc("stream_thermal_feed", stream_params(sdp)))
    assert result["accepted"] is False, f"{label} must be refused"
    assert result["session_id"] is None


def test_sdes_key_exchange_is_refused(harness: Harness) -> None:
    """SDES puts the SRTP master key in the signaling plane.

    Anyone who can read the offer -- including anything that logged it -- can then
    decrypt the media.
    """
    sdp = VALID_SDP.replace(
        "a=setup:actpass",
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwK\na=setup:actpass",
    )
    result = result_of(harness.rpc("stream_thermal_feed", stream_params(sdp)))
    assert result["accepted"] is False
    assert "SDES" in result["rejection"]["detail"]


def test_rejected_offer_allocates_no_session(harness: Harness) -> None:
    """An unacceptable offer must cost nothing."""
    before = len(harness.ctx.stream_sessions)
    insecure = VALID_SDP.replace("UDP/TLS/RTP/SAVPF", "RTP/AVP")
    harness.rpc("stream_thermal_feed", stream_params(insecure))
    assert len(harness.ctx.stream_sessions) == before


def test_signaling_rejection_is_audited(harness: Harness) -> None:
    harness.rpc("stream_thermal_feed", stream_params(VALID_SDP.replace("sha-256", "sha-1")))
    records = harness.ctx.audit_sink.by_outcome(Outcome.REJECTED_SCHEMA)
    assert any("sdp" in code for r in records for code in r.reason_codes)


def test_oversized_offer_is_refused_by_the_schema(harness: Harness) -> None:
    body = harness.rpc("stream_thermal_feed", stream_params("v=0\n" + "a=x\n" * 40_000)).json()
    assert body["error"]["code"] == -32602


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #

def test_unscoped_operator_is_refused(harness: Harness) -> None:
    zone = harness.ctx.missions.binding_for("M-001").incident_zone  # type: ignore[union-attr]
    from dataclasses import replace as _replace  # noqa: F401 - IncidentZone is pydantic

    narrowed = zone.model_copy(update={"authorized_operator_ids": frozenset({"op-cr-001"})})
    from mcp_server.repositories import MissionBinding

    harness.ctx.missions.register(MissionBinding("M-001", narrowed))  # type: ignore[attr-defined]

    result = result_of(harness.rpc("stream_thermal_feed", stream_params(), token=FL_TOKEN))
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "not_authorized_for_zone"


def test_unknown_mission_is_refused(harness: Harness) -> None:
    result = result_of(
        harness.rpc("stream_thermal_feed", stream_params(mission_id="M-UNKNOWN"))
    )
    assert result["accepted"] is False
    assert result["rejection"]["code"] == "zone_inactive"


def test_sessions_are_revoked_when_the_zone_closes(harness: Harness) -> None:
    """Master Plan §5: revoked on mission close or IncidentZone expiry."""
    result = result_of(harness.rpc("stream_thermal_feed", stream_params()))
    assert harness.ctx.stream_sessions.get(result["session_id"]) is not None

    revoked = harness.ctx.stream_sessions.revoke_zone("IZ-1")
    assert revoked == 1
    assert harness.ctx.stream_sessions.get(result["session_id"]) is None


def test_expired_session_is_not_retrievable(harness: Harness) -> None:
    """Expiry is checked on read, not swept on a timer that could fall behind."""
    result = result_of(harness.rpc("stream_thermal_feed", stream_params()))
    harness.clock.advance(4 * 3600)
    assert harness.ctx.stream_sessions.get(result["session_id"]) is None


# --------------------------------------------------------------------------- #
# The DTLS policy the media engine is configured with
# --------------------------------------------------------------------------- #

def test_dtls_policy_refuses_a_downgrade() -> None:
    """The version floor lives in the media engine; SDP cannot carry it."""
    with pytest.raises(ValueError, match="downgrade"):
        DtlsSrtpPolicy(min_dtls_version="1.2")


def test_dtls_policy_refuses_non_aead_srtp_profiles() -> None:
    """An attacker who can flip bits in a non-AEAD profile corrupts frames silently."""
    with pytest.raises(ValueError, match="non-AEAD"):
        DtlsSrtpPolicy(srtp_profiles=("SRTP_AES128_CM_HMAC_SHA1_80",))


def test_dtls_policy_defaults_are_aead_and_1_3() -> None:
    policy = DtlsSrtpPolicy()
    assert policy.min_dtls_version == MIN_DTLS_VERSION == "1.3"
    assert policy.srtp_profiles == ALLOWED_SRTP_PROFILES
    assert all("GCM" in p for p in policy.srtp_profiles)
    assert policy.require_fingerprint_match is True


def test_accepted_response_records_the_dtls_policy(harness: Harness) -> None:
    harness.rpc("stream_thermal_feed", stream_params())
    record = harness.ctx.audit_sink.records()[-1]
    assert record.decision["dtls_policy"]["min_dtls_version"] == "1.3"
    assert record.decision["sdp"]["fingerprint_hash"] == "sha-256"
