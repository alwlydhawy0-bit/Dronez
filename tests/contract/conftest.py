"""Wire fixtures for the MCP tool contracts.

Everything here is built as **JSON text**, never as a Python dict, because
`StrictModel.parse_json` on raw bytes is the documented ingress path (CLAUDE.md §5).
Pydantic's strict mode is stricter in Python mode than in JSON mode -- it rejects a
list for a tuple and a string for an enum, which are JSON's only encodings for those --
so a dict-built fixture would test a path no request ever takes.
"""

from __future__ import annotations

import json
from typing import Any

SQUARE = [[
    [46.40, 24.40],
    [46.60, 24.40],
    [46.60, 24.60],
    [46.40, 24.60],
    [46.40, 24.40],
]]

DIGEST = "a" * 64

SIGNED_ENVELOPE: dict[str, Any] = {
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

#: One well-formed request body per tool, as the wire would carry it.
VALID_REQUESTS: dict[str, dict[str, Any]] = {
    "deploy_recon_waypoint": {
        "mission_id": "M-001",
        "polygon": {"type": "Polygon", "coordinates": SQUARE},
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
        "sdp_offer": "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\n",
    },
    "execute_safe_return": {
        "drone_id": "D-1",
        "trigger_reason": "manual_override",
        "mission_id": "M-001",
    },
    "check_airspace_clearance": {
        "mission_id": "M-001",
        "polygon": {"type": "Polygon", "coordinates": SQUARE},
        "altitude_min_m_agl": 30.0,
        "altitude_max_m_agl": 100.0,
    },
    "confirm_flight_plan": {
        "flight_plan_id": "FP-001",
        "flight_plan_digest": DIGEST,
        "decision": "approve",
        "authorization": SIGNED_ENVELOPE,
        "note": "visual confirmation from the north approach",
    },
    "get_fleet_status": {
        "incident_zone_id": "IZ-1",
        "include_unavailable": True,
    },
    "request_emergency_stop": {
        "scope": "zone",
        "incident_zone_id": "IZ-1",
        "reason": "personnel entering the structure",
        "authorization": SIGNED_ENVELOPE,
    },
}


def wire(tool: str, **overrides: Any) -> str:
    """A valid request for ``tool`` as JSON text, with fields replaced or added.

    Passing ``None`` for a key removes it, so a test can assert a required field is
    actually required.
    """
    body = dict(VALID_REQUESTS[tool])
    for key, value in overrides.items():
        if value is _REMOVE:
            body.pop(key, None)
        else:
            body[key] = value
    return json.dumps(body)


class _Remove:
    def __repr__(self) -> str:
        return "<remove>"


#: Sentinel for :func:`wire` meaning "omit this key entirely".
_REMOVE = _Remove()
REMOVE: Any = _REMOVE
