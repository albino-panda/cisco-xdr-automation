"""Execution state store: double-execution protection per (package, idempotency key).

Before an approved action is sent to an adapter, the runner atomically *claims* it with
:meth:`ExecutionStateStore.begin`. A second run of the same package (a retry of ``execute``, a
crash-restart, a concurrent worker) finds the existing record and never calls the adapter again:

* ``COMPLETED`` records replay the stored (already redacted) :class:`ActionResult`;
* ``IN_PROGRESS`` records mean an earlier attempt never finished; its outcome is unknown, so the
  action is reported ``FAILED`` and must be verified manually (never re-sent blindly).

This is distinct from ``interfaces.StateStore`` (an alias of ``IncidentStore``, which holds
incidents). Two implementations: :class:`InMemoryExecutionStateStore` and
:class:`SqliteExecutionStateStore`. Records are never deleted.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import AwareDatetime

from xdr_response.clock import utc
from xdr_response.models import ActionResult, FrozenModel

__all__ = [
    "ExecutionPhase",
    "ExecutionRecord",
    "ExecutionStateStore",
    "InMemoryExecutionStateStore",
    "SqliteExecutionStateStore",
]


class ExecutionPhase(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"


class ExecutionRecord(FrozenModel):
    """One claimed execution of an approved action within one package."""

    package_id: str
    idempotency_key: str
    incident_id: str
    token_id: str
    phase: ExecutionPhase
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    result: ActionResult | None = None


@runtime_checkable
class ExecutionStateStore(Protocol):
    def begin(self, *, package_id: str, idempotency_key: str, incident_id: str, token_id: str,
              at: datetime) -> ExecutionRecord | None:
        """Atomically claim the action. Returns None when claimed, else the existing record."""
        ...

    def complete(self, *, package_id: str, idempotency_key: str, result: ActionResult,
                 at: datetime) -> ExecutionRecord:
        """Store the final result of a claimed (IN_PROGRESS) action. KeyError if never claimed."""
        ...

    def get(self, package_id: str, idempotency_key: str) -> ExecutionRecord | None:
        ...

    def list(self, *, incident_id: str | None = None,
             package_id: str | None = None) -> list[ExecutionRecord]:
        ...


def _check_completable(record: ExecutionRecord | None, package_id: str, key: str) -> ExecutionRecord:
    if record is None:
        raise KeyError(f"no claimed execution for {package_id}/{key}")
    if record.phase is ExecutionPhase.COMPLETED:
        raise ValueError(f"execution {package_id}/{key} is already completed")
    return record


class InMemoryExecutionStateStore:
    """Thread-safe in-memory store (tests, simulator, single-process lab runs)."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], ExecutionRecord] = {}
        self._lock = threading.Lock()

    def begin(self, *, package_id: str, idempotency_key: str, incident_id: str, token_id: str,
              at: datetime) -> ExecutionRecord | None:
        key = (package_id, idempotency_key)
        with self._lock:
            existing = self._records.get(key)
            if existing is not None:
                return existing
            self._records[key] = ExecutionRecord(
                package_id=package_id, idempotency_key=idempotency_key, incident_id=incident_id,
                token_id=token_id, phase=ExecutionPhase.IN_PROGRESS, started_at=utc(at),
            )
            return None

    def complete(self, *, package_id: str, idempotency_key: str, result: ActionResult,
                 at: datetime) -> ExecutionRecord:
        key = (package_id, idempotency_key)
        with self._lock:
            record = _check_completable(self._records.get(key), package_id, idempotency_key)
            done = record.model_copy(update={"phase": ExecutionPhase.COMPLETED,
                                             "finished_at": utc(at), "result": result})
            self._records[key] = done
            return done

    def get(self, package_id: str, idempotency_key: str) -> ExecutionRecord | None:
        with self._lock:
            return self._records.get((package_id, idempotency_key))

    def list(self, *, incident_id: str | None = None,
             package_id: str | None = None) -> list[ExecutionRecord]:
        with self._lock:
            records = list(self._records.values())
        return [r for r in records
                if (incident_id is None or r.incident_id == incident_id)
                and (package_id is None or r.package_id == package_id)]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS execution_records (
    package_id      TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    incident_id     TEXT NOT NULL,
    token_id        TEXT NOT NULL,
    phase           TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    result_json     TEXT,
    PRIMARY KEY (package_id, idempotency_key)
)
"""
_COLUMNS = ("package_id, idempotency_key, incident_id, token_id, phase, started_at, "
            "finished_at, result_json")


class SqliteExecutionStateStore:
    """Durable store backed by SQLite (stdlib). ``path`` may be ``":memory:"``.

    The claim is a single ``INSERT OR IGNORE`` on the primary key, so it is atomic across threads
    and across processes sharing the database file.
    """

    def __init__(self, path: Path | str = ":memory:") -> None:
        target = str(path)
        if target != ":memory:":
            Path(target).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(target, check_same_thread=False, isolation_level=None)
        with self._lock:
            self._conn.execute(_SCHEMA)

    def close(self) -> None:
        """Close the underlying connection."""
        with self._lock:
            self._conn.close()

    @staticmethod
    def _row_to_record(row: tuple[str, ...]) -> ExecutionRecord:
        package_id, key, incident_id, token_id, phase, started, finished, result_json = row
        return ExecutionRecord(
            package_id=package_id, idempotency_key=key, incident_id=incident_id, token_id=token_id,
            phase=ExecutionPhase(phase), started_at=datetime.fromisoformat(started),
            finished_at=datetime.fromisoformat(finished) if finished else None,
            result=ActionResult.model_validate_json(result_json) if result_json else None,
        )

    def _fetch(self, package_id: str, idempotency_key: str) -> ExecutionRecord | None:
        row = self._conn.execute(
            f"SELECT {_COLUMNS} FROM execution_records WHERE package_id = ? AND idempotency_key = ?",
            (package_id, idempotency_key),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def begin(self, *, package_id: str, idempotency_key: str, incident_id: str, token_id: str,
              at: datetime) -> ExecutionRecord | None:
        with self._lock:
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO execution_records "
                "(package_id, idempotency_key, incident_id, token_id, phase, started_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (package_id, idempotency_key, incident_id, token_id,
                 ExecutionPhase.IN_PROGRESS.value, utc(at).isoformat()),
            )
            if cursor.rowcount == 1:
                return None
            return self._fetch(package_id, idempotency_key)

    def complete(self, *, package_id: str, idempotency_key: str, result: ActionResult,
                 at: datetime) -> ExecutionRecord:
        with self._lock:
            _check_completable(self._fetch(package_id, idempotency_key), package_id, idempotency_key)
            self._conn.execute(
                "UPDATE execution_records SET phase = ?, finished_at = ?, result_json = ? "
                "WHERE package_id = ? AND idempotency_key = ? AND phase = ?",
                (ExecutionPhase.COMPLETED.value, utc(at).isoformat(), result.model_dump_json(),
                 package_id, idempotency_key, ExecutionPhase.IN_PROGRESS.value),
            )
            record = self._fetch(package_id, idempotency_key)
        if record is None:  # pragma: no cover - row cannot disappear (no delete path exists)
            raise KeyError(f"execution {package_id}/{idempotency_key} vanished")
        return record

    def get(self, package_id: str, idempotency_key: str) -> ExecutionRecord | None:
        with self._lock:
            return self._fetch(package_id, idempotency_key)

    def list(self, *, incident_id: str | None = None,
             package_id: str | None = None) -> list[ExecutionRecord]:
        clauses: list[str] = []
        args: list[str] = []
        if incident_id is not None:
            clauses.append("incident_id = ?")
            args.append(incident_id)
        if package_id is not None:
            clauses.append("package_id = ?")
            args.append(package_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_COLUMNS} FROM execution_records{where} ORDER BY started_at, idempotency_key",
                args,
            ).fetchall()
        return [self._row_to_record(r) for r in rows]
