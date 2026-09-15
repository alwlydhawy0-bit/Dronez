"""Append-only `Command` record -- the audit backbone.

Master Plan §4 defines the `Command` entity as *"Raw NL input + agent-parsed intent +
the exact tool-call payload proposed + the human/policy decision -- this triple is the
audit backbone."* §5 adds the rule that makes it useful defensively: *"the failure is
logged as a `Command` record regardless of outcome, including agent-proposed-but-
rejected attempts, since a pattern of rejected proposals is itself a security signal."*

So this module records **every** attempt: rate-limited, sanitizer-blocked,
schema-invalid, policy-denied, and approved alike. Dropping rejections would destroy
the evidence of exactly the behaviour worth detecting.

Redaction
---------
Zero-Trust §8.1 requires a log redactor to strip authorization headers, tokens,
session ids and PII *before* stdout emission. Raw request payloads carry operator free
text and tactical detail, so what is recorded is a **hash** of the payload plus a
structured projection -- never the payload itself. The hash is enough to prove which
bytes were submitted when the full record is retrieved from the WORM store under its
own retention policy.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

__all__ = [
    "REDACTED",
    "AuditSink",
    "AuditTrail",
    "CommandRecord",
    "CompositeAuditSink",
    "InMemoryAuditSink",
    "Outcome",
]

REDACTED = "[redacted]"

#: Keys whose values never reach a log line, at any nesting depth.
_SENSITIVE_KEYS = frozenset({
    "authorization", "auth", "token", "access_token", "refresh_token", "bearer",
    "password", "secret", "api_key", "apikey", "session_id", "cookie",
    "signature", "value", "private_key", "material", "nonce",
})


class Outcome(StrEnum):
    """What happened to an attempt. Every terminal state is represented."""

    ACCEPTED = "accepted"
    STAGED = "staged"
    DISPATCHED = "dispatched"
    REJECTED_SCHEMA = "rejected_schema"
    REJECTED_AUTH = "rejected_auth"
    REJECTED_RATE_LIMIT = "rejected_rate_limit"
    REJECTED_SANITIZER = "rejected_sanitizer"
    REJECTED_SCOPE = "rejected_scope"
    REJECTED_SIGNATURE = "rejected_signature"
    REJECTED_POLICY = "rejected_policy"
    REJECTED_CLEARANCE = "rejected_clearance"
    REJECTED_DISPATCH_GATE = "rejected_dispatch_gate"
    ERROR = "error"

    @property
    def is_security_signal(self) -> bool:
        """Outcomes worth correlating for attack detection.

        A single rejection is routine; a pattern of them from one session is not. These
        are the ones a SIEM rule should count (Zero-Trust §8.2).
        """
        return self in {
            Outcome.REJECTED_AUTH,
            Outcome.REJECTED_RATE_LIMIT,
            Outcome.REJECTED_SANITIZER,
            Outcome.REJECTED_SCOPE,
            Outcome.REJECTED_SIGNATURE,
            Outcome.REJECTED_POLICY,
        }


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Recursively strip sensitive values. Depth-bounded against hostile nesting."""
    if _depth > 12:
        return REDACTED
    if isinstance(value, dict):
        return {
            k: (REDACTED if str(k).lower() in _SENSITIVE_KEYS else redact(v, _depth=_depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth=_depth + 1) for v in value[:256]]
    if isinstance(value, str):
        return value[:512]
    return value


@dataclass(frozen=True, slots=True)
class CommandRecord:
    """One immutable attempt record."""

    record_id: str
    recorded_utc: datetime
    tool: str
    outcome: Outcome
    #: Server-derived, never taken from the request body.
    operator_id: str | None
    role: str | None
    session_id: str | None
    #: SHA-256 of the exact request bytes. The bytes themselves go to the WORM store.
    payload_sha256: str
    payload_bytes: int
    #: Structured, redacted projection of the decision -- never free text from a user.
    decision: dict[str, Any] = field(default_factory=dict)
    reason_codes: tuple[str, ...] = ()
    detail: str = ""

    def to_log_line(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "recorded_utc": self.recorded_utc.isoformat(),
            "tool": self.tool,
            "outcome": self.outcome.value,
            "security_signal": self.outcome.is_security_signal,
            "operator_id": self.operator_id,
            "role": self.role,
            "session_id": self.session_id,
            "payload_sha256": self.payload_sha256,
            "payload_bytes": self.payload_bytes,
            "reason_codes": list(self.reason_codes),
            "detail": self.detail[:512],
            "decision": redact(self.decision),
        }


class AuditSink(Protocol):
    """Destination for command records.

    Implementations must not raise into the request path: an audit outage is an
    operational problem, but dropping the request because logging failed would let a
    log outage become a denial of service on the whole platform.
    """

    def write(self, record: CommandRecord) -> None:
        ...


class InMemoryAuditSink:
    """Bounded ring buffer. Development, tests, and the in-process status endpoint.

    Production ships records asynchronously to append-only WORM storage with object
    lock (Zero-Trust §8.1); this is not that, and is explicitly lossy at the tail.
    """

    def __init__(self, capacity: int = 4096) -> None:
        self._capacity = capacity
        self._lock = threading.Lock()
        self._records: list[CommandRecord] = []

    def write(self, record: CommandRecord) -> None:
        with self._lock:
            self._records.append(record)
            if len(self._records) > self._capacity:
                del self._records[: len(self._records) - self._capacity]

    def records(self) -> tuple[CommandRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def by_outcome(self, outcome: Outcome) -> tuple[CommandRecord, ...]:
        return tuple(r for r in self.records() if r.outcome is outcome)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)


class CompositeAuditSink:
    """Fan out to several sinks. A failing sink never blocks the others."""

    def __init__(self, *sinks: AuditSink) -> None:
        self._sinks = sinks

    def write(self, record: CommandRecord) -> None:
        for sink in self._sinks:
            try:
                sink.write(record)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException:  # noqa: S112 - see below
                # Not logged from here: this IS the logging path, so reporting a sink
                # failure through the sinks would recurse. Sink health is monitored
                # where the sinks are constructed. A failing sink must never take the
                # others down with it, nor fail the request.
                continue


class AuditTrail:
    """Records every attempt. The one call site that must never be skipped."""

    def __init__(
        self,
        sink: AuditSink,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._sink = sink
        self._clock = clock or (lambda: datetime.now(UTC))

    def record(
        self,
        *,
        tool: str,
        outcome: Outcome,
        payload: bytes,
        operator_id: str | None = None,
        role: str | None = None,
        session_id: str | None = None,
        decision: dict[str, Any] | None = None,
        reason_codes: tuple[str, ...] = (),
        detail: str = "",
    ) -> CommandRecord:
        record = CommandRecord(
            record_id=f"cmd-{uuid.uuid4().hex}",
            recorded_utc=self._clock(),
            tool=tool,
            outcome=outcome,
            operator_id=operator_id,
            role=role,
            session_id=session_id,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            payload_bytes=len(payload),
            decision=decision or {},
            reason_codes=reason_codes,
            detail=detail,
        )
        try:
            self._sink.write(record)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:  # noqa: S110 - see AuditSink docstring
            pass
        return record
