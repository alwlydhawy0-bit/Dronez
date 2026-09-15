"""Write-once, read-many evidentiary store.

Zero-Trust §8.1: security audit logs and forensic artifacts are shipped to *"an
immutable append-only storage bucket (WORM -- Write Once Read Many) with object locking
enabled."* Master Plan §4 makes the requirement sharper: *"no service identity in the
system -- including administrators -- holds delete/modify permission on committed
records."*

How that is enforced here
-------------------------
:class:`WormSink` has **no delete method and no update method.** Not a method that
raises, not one gated behind a permission check -- none. An API that offers deletion and
refuses it still teaches every caller that deletion is a thing one asks for, and the
refusal is one config change away from being granted. The absence is the control.

The same reasoning applies to the ``commit`` path: a record that is already committed
cannot be re-committed with different content. :meth:`InMemoryWormStore.commit` refuses
a second write to the same record id even when the content is identical, because
"identical" is a judgement the store should not be making about evidence.

Object lock is the real control
-------------------------------
This module enforces immutability in the application layer, which stops the
application. It does not stop someone with credentials to the bucket. The production
implementation is S3 Object Lock in compliance mode (or the equivalent), where the
retention period cannot be shortened by any principal including the account root --
that is what actually resists an attacker who has taken the platform. :class:`WormSink`
is the seam; :class:`InMemoryWormStore` is for tests and is explicitly not that.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from dronez.evidence.chain_of_custody import (
    ChainOfCustodyRecord,
    ChainVerification,
    verify_chain,
)

__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "CommitReceipt",
    "CommitRefused",
    "InMemoryWormStore",
    "RetentionMode",
    "RetentionPolicy",
    "WormSink",
]

#: Evidentiary retention floor. Shorter than the plausible interval between an incident
#: and a legal proceeding would make the store useless for its main purpose. The actual
#: figure is a legal/compliance decision, not an engineering one -- this is a default
#: that errs long, and is flagged for the same named-owner review as the safety envelope.
DEFAULT_RETENTION_DAYS: int = 365 * 7


class RetentionMode(StrEnum):
    """Object-lock mode.

    ``COMPLIANCE`` is the one that means what it says: no principal, including the
    account root, can shorten the retention period or delete the object before it
    expires. ``GOVERNANCE`` can be overridden by a sufficiently privileged identity,
    which makes it unsuitable for evidence that might implicate that identity.
    """

    COMPLIANCE = "compliance"
    GOVERNANCE = "governance"


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """Object-lock settings applied at commit."""

    mode: RetentionMode = RetentionMode.COMPLIANCE
    retain_days: int = DEFAULT_RETENTION_DAYS

    def __post_init__(self) -> None:
        if self.retain_days < 1:
            raise ValueError("retention must be at least one day")

    def retain_until(self, committed_at: datetime) -> datetime:
        return committed_at + timedelta(days=self.retain_days)

    @property
    def is_overridable(self) -> bool:
        """Whether a privileged identity could shorten this retention."""
        return self.mode is RetentionMode.GOVERNANCE


class CommitRefused(RuntimeError):
    """A commit was refused. The store is unchanged.

    Raised rather than returned because a refused evidentiary write is not a routine
    branch the caller should be able to ignore by not checking a return value.
    """


@dataclass(frozen=True, slots=True)
class CommitReceipt:
    """Proof that a record was committed, and under what terms."""

    record_id: str
    stream_id: str
    sequence: int
    chain_hash: str
    committed_utc: datetime
    retain_until_utc: datetime
    retention_mode: RetentionMode
    #: Storage-layer object identifier, for retrieval and for the audit trail.
    object_key: str

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "stream_id": self.stream_id,
            "sequence": self.sequence,
            "chain_hash": self.chain_hash,
            "committed_utc": self.committed_utc.isoformat(),
            "retain_until_utc": self.retain_until_utc.isoformat(),
            "retention_mode": self.retention_mode.value,
            "object_key": self.object_key,
        }


class WormSink(Protocol):
    """Append-only evidentiary store.

    Note what this Protocol does not declare: no ``delete``, no ``update``, no
    ``set_retention``. An implementation that adds one is not a WORM sink, and the
    absence here is what makes that reviewable at the type level.
    """

    def commit(self, record: ChainOfCustodyRecord) -> CommitReceipt:
        """Commit a record. Raises :class:`CommitRefused` if it already exists."""
        ...

    def get(self, record_id: str) -> ChainOfCustodyRecord | None:
        ...

    def stream_records(self, stream_id: str) -> tuple[ChainOfCustodyRecord, ...]:
        """Records for one stream, in sequence order."""
        ...


class InMemoryWormStore:
    """Development and test WORM store.

    **Not production storage.** It holds records in a dict in one process: it is lost on
    restart and offers no object lock, so it provides the *interface* contract and none
    of the durability or the resistance to a privileged attacker. Production is S3
    Object Lock in compliance mode, and the difference is the entire point of §8.1.
    """

    def __init__(
        self,
        *,
        retention: RetentionPolicy | None = None,
        clock: object | None = None,
    ) -> None:
        self._retention = retention or RetentionPolicy()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._records: dict[str, ChainOfCustodyRecord] = {}
        self._receipts: dict[str, CommitReceipt] = {}
        self._by_stream: dict[str, list[str]] = {}
        self.commit_count = 0
        self.refused_count = 0

    def commit(self, record: ChainOfCustodyRecord) -> CommitReceipt:
        """Commit a record. Write-once, including against identical content."""
        if not record.is_self_consistent():
            self.refused_count += 1
            raise CommitRefused(
                f"record {record.record_id} does not match its own chain hash; refusing "
                "to commit an artifact whose integrity cannot be established at the door"
            )

        with self._lock:
            if record.record_id in self._records:
                self.refused_count += 1
                raise CommitRefused(
                    f"record {record.record_id} is already committed; a WORM store does "
                    "not accept a second write, even of identical content"
                )

            committed_at = self._clock()  # type: ignore[operator]
            receipt = CommitReceipt(
                record_id=record.record_id,
                stream_id=record.stream_id,
                sequence=record.sequence,
                chain_hash=record.chain_hash,
                committed_utc=committed_at,
                retain_until_utc=self._retention.retain_until(committed_at),
                retention_mode=self._retention.mode,
                object_key=f"{record.stream_id}/{record.sequence:012d}/{record.record_id}",
            )
            self._records[record.record_id] = record
            self._receipts[record.record_id] = receipt
            self._by_stream.setdefault(record.stream_id, []).append(record.record_id)
            self.commit_count += 1
            return receipt

    def get(self, record_id: str) -> ChainOfCustodyRecord | None:
        with self._lock:
            return self._records.get(record_id)

    def receipt(self, record_id: str) -> CommitReceipt | None:
        with self._lock:
            return self._receipts.get(record_id)

    def stream_records(self, stream_id: str) -> tuple[ChainOfCustodyRecord, ...]:
        with self._lock:
            ids = list(self._by_stream.get(stream_id, ()))
            records = [self._records[i] for i in ids]
        return tuple(sorted(records, key=lambda r: r.sequence))

    def streams(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._by_stream))

    def verify_stream(self, stream_id: str) -> ChainVerification:
        """Verify a stream's chain as stored.

        This is the query an auditor runs. It answers "is the evidence for this mission
        intact?" -- and, when it is not, where the discontinuities are.
        """
        return verify_chain(list(self.stream_records(stream_id)))

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def __iter__(self) -> Iterator[ChainOfCustodyRecord]:
        with self._lock:
            return iter(list(self._records.values()))


def commit_all(sink: WormSink, records: Iterable[ChainOfCustodyRecord]) -> list[CommitReceipt]:
    """Commit a batch, stopping at the first refusal.

    Deliberately not atomic and deliberately not best-effort. Partial commits are the
    correct outcome for an append-only store: the records that reached it are real
    evidence and must not be discarded because a later one failed, and continuing past
    a refusal would hide the failure.
    """
    receipts: list[CommitReceipt] = []
    for record in records:
        receipts.append(sink.commit(record))
    return receipts
