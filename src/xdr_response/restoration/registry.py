"""Temporary control registry (architecture sections 8.1 and 13.17).

Every control the automation created (an isolation, a block, a disabled account, ...) is recorded
here so that it can later be released with a separate human release approval.

Design rules enforced by this module:

* The registry is an **append-only event log** (``REGISTERED``, ``RELEASE_PENDING``, ``RELEASED``,
  ``RELEASE_FAILED``). The current view of a control is its latest snapshot. Nothing is ever
  deleted: there is deliberately no delete, remove, clear or close method.
* ``register`` is idempotent by ``control_key``. Only ``SUCCESS`` results of catalog actions with
  ``creates_control=True`` become controls (:func:`control_from_result`); ``ALREADY_CONTAINED``
  results are never registered, so a release can never remove a control someone else created.
* Status changes follow a fixed table: ``ACTIVE``/``RELEASE_FAILED`` -> ``RELEASE_PENDING`` ->
  ``RELEASED`` | ``RELEASE_FAILED``. ``RELEASE_FAILED`` means the release attempt did not take
  effect, so the control is still in force and may be released again with a new approval.
* Closing an incident never touches the registry; ``review_due_at`` only drives a reminder.
* Integrity: every event must follow the status table, its snapshot status must match the event,
  and the identity of a control (incident, action, target, integration, workflow, package, token,
  decision, approval level, created_at, rollback) never changes between events of one
  registration. The JSONL log is additionally hash-chained (``prev_hash`` / ``hash`` per line), so
  an in-place edit (for example ELEVATED -> STANDARD) or an appended forged event is refused on
  replay (fail closed, :class:`RegistryError`).

Three storage backends share the same logic: :class:`InMemoryControlRegistry` (tests, simulator),
:class:`JsonlControlRegistry` (append-only file, the Phase 0 default) and
:class:`SqliteControlRegistry` (append-only table protected by triggers).
"""
from __future__ import annotations

import builtins
import hashlib
import json
import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from xdr_response.clock import Clock, SystemClock, utc
from xdr_response.errors import RegistryError
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import (
    ActionOutcome,
    ActionPackage,
    ActionResult,
    ActionResultStatus,
    ApprovalPurpose,
    ApprovalToken,
    ControlStatus,
    ErrorInfo,
    RecommendedAction,
    TemporaryControl,
    get_action_spec,
)

__all__ = [
    "RELEASABLE_STATUSES",
    "ControlEventType",
    "ControlEvent",
    "InMemoryControlRegistry",
    "JsonlControlRegistry",
    "SqliteControlRegistry",
    "control_from_result",
    "check_event_sequence",
    "IDENTITY_FIELDS",
]

#: Statuses of a control that is still in force and may be put into a release package.
RELEASABLE_STATUSES: frozenset[ControlStatus] = frozenset(
    {ControlStatus.ACTIVE, ControlStatus.RELEASE_FAILED}
)


class ControlEventType(StrEnum):
    """Event names of the append-only registry log."""

    REGISTERED = "REGISTERED"
    #: A later approved write of the same key replaced an earlier one whose write had no effect.
    SUPERSEDED = "SUPERSEDED"
    RELEASE_PENDING = "RELEASE_PENDING"
    RELEASED = "RELEASED"
    RELEASE_FAILED = "RELEASE_FAILED"


@dataclass(frozen=True)
class ControlEvent:
    """One appended registry event with the control snapshot *after* the event."""

    seq: int
    event: ControlEventType
    control_key: str
    at: datetime
    control: TemporaryControl

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable form (used by the JSONL backend)."""
        return {
            "seq": self.seq,
            "event": self.event.value,
            "control_key": self.control_key,
            "at": utc(self.at).isoformat(),
            "control": self.control.model_dump(mode="json"),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ControlEvent":
        """Parse :meth:`to_dict` output. Malformed data raises :class:`RegistryError`."""
        try:
            control = TemporaryControl.model_validate(data["control"])
            event = cls(
                seq=int(data["seq"]),
                event=ControlEventType(data["event"]),
                control_key=str(data["control_key"]),
                at=utc(datetime.fromisoformat(str(data["at"]))),
                control=control,
            )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise RegistryError(f"malformed registry event: {type(exc).__name__}") from exc
        if event.control_key != control.control_key:
            raise RegistryError(f"registry event {event.seq} key does not match its snapshot")
        return event


# ------------------------------------------------------------------ helpers --
#: Fields that identify one registration; they never change between its events.
IDENTITY_FIELDS: tuple[str, ...] = (
    "control_key", "incident_id", "action_type", "target", "target_kind", "integration", "workflow_id",
    "workflow_version", "package_id", "token_id", "decision_id", "approval_level", "created_at",
    "rollback_action_type", "rollback_params", "external_ref",
)

#: Fields a SUPERSEDED event may never change (the control is the same key, target and integration).
SUPERSEDE_FIXED_FIELDS: tuple[str, ...] = (
    "control_key", "incident_id", "action_type", "target", "target_kind", "integration",
    "rollback_action_type",
)

_EVENT_STATUS: dict[ControlEventType, ControlStatus] = {
    ControlEventType.REGISTERED: ControlStatus.ACTIVE,
    ControlEventType.SUPERSEDED: ControlStatus.ACTIVE,
    ControlEventType.RELEASE_PENDING: ControlStatus.RELEASE_PENDING,
    ControlEventType.RELEASED: ControlStatus.RELEASED,
    ControlEventType.RELEASE_FAILED: ControlStatus.RELEASE_FAILED,
}


def check_event_sequence(previous: TemporaryControl | None, event: ControlEventType,
                         control: TemporaryControl) -> None:
    """Refuse an event that breaks the status table or changes the identity of a registration."""
    if control.status is not _EVENT_STATUS[event]:
        raise RegistryError(f"{event.value} event carries status {control.status.value}")
    if event is ControlEventType.REGISTERED:
        if previous is not None and previous.status is not ControlStatus.RELEASED:
            raise RegistryError(f"control {control.control_key} re-registered while {previous.status.value}")
        return
    if event is ControlEventType.SUPERSEDED:
        if previous is None or previous.status not in RELEASABLE_STATUSES:
            raise RegistryError(f"SUPERSEDED needs a control in force ({control.control_key})")
        before, after = previous.model_dump(mode="json"), control.model_dump(mode="json")
        changed = [name for name in SUPERSEDE_FIXED_FIELDS if before.get(name) != after.get(name)]
        if changed:
            raise RegistryError(f"SUPERSEDED event changes fixed fields {changed} of control {control.control_key}")
        if previous.package_id == control.package_id:
            raise RegistryError("SUPERSEDED needs a later approved package")
        return
    if previous is None:
        raise RegistryError(f"{event.value} event for unregistered control {control.control_key}")
    allowed_from = (RELEASABLE_STATUSES if event is ControlEventType.RELEASE_PENDING
                    else frozenset({ControlStatus.RELEASE_PENDING}))
    if previous.status not in allowed_from:
        raise RegistryError(f"{event.value} is not allowed from {previous.status.value} "
                            f"(control {control.control_key})")
    before, after = previous.model_dump(mode="json"), control.model_dump(mode="json")
    changed = [name for name in IDENTITY_FIELDS if before.get(name) != after.get(name)]
    if changed:
        raise RegistryError(f"{event.value} event changes identity fields {changed} of control "
                            f"{control.control_key}")


def _event_hash(body: Mapping[str, Any]) -> str:
    data = {k: v for k, v in body.items() if k != "hash"}
    encoded = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_GENESIS = "0" * 64


def _evolve(control: TemporaryControl, **changes: Any) -> TemporaryControl:
    """Validated copy of ``control`` with ``changes`` applied."""
    data = control.model_dump(mode="python")
    data.update(changes)
    return TemporaryControl.model_validate(data)


def _sensitive_paths(value: Any, prefix: str = "") -> builtins.list[str]:
    """Dotted paths of keys in ``value`` that the central redactor treats as secrets."""
    redactor = get_redactor()
    found: builtins.list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(key, str) and redactor.is_sensitive_key(key):
                found.append(path)
            found.extend(_sensitive_paths(item, path))
    elif isinstance(value, (builtins.list, tuple)):
        for index, item in enumerate(value):
            found.extend(_sensitive_paths(item, f"{prefix}[{index}]"))
    return found


def _check_registrable(control: TemporaryControl) -> None:
    """A new registration must be a clean ACTIVE entry without secrets in its rollback params."""
    if not isinstance(control, TemporaryControl):
        raise TypeError("control must be a TemporaryControl")
    if control.status is not ControlStatus.ACTIVE:
        raise RegistryError(f"a new control must be ACTIVE, got {control.status.value}")
    if control.released_at or control.release_package_id or control.release_token_id or control.last_error:
        raise RegistryError("a new control must not carry release fields")
    secret_keys = _sensitive_paths(control.rollback_params)
    if secret_keys:
        raise RegistryError(
            f"rollback_params of {control.control_key} contain secret-like keys {secret_keys}; "
            "secrets are never stored in the registry"
        )


# --------------------------------------------------------------- base class --
class _ControlRegistryBase(ABC):
    """Shared registry logic. Subclasses provide storage primitives only."""

    def __init__(self, *, clock: Clock | None = None) -> None:
        self._clock: Clock = clock or SystemClock()

    # storage primitives ----------------------------------------------------
    @abstractmethod
    def _transaction(self) -> Any:
        """Context manager making a read-check-append sequence atomic."""

    @abstractmethod
    def _load(self, control_key: str) -> TemporaryControl | None:
        """Latest snapshot of ``control_key`` or None."""

    @abstractmethod
    def _load_all(self) -> builtins.list[TemporaryControl]:
        """Latest snapshot of every control."""

    @abstractmethod
    def _append(self, event: ControlEventType, control: TemporaryControl, at: datetime) -> None:
        """Append one event (inside :meth:`_transaction`)."""

    @abstractmethod
    def history(self, control_key: str) -> builtins.list[ControlEvent]:
        """Every event of ``control_key`` in append order (empty list when unknown)."""

    # public API -------------------------------------------------------------
    def register(self, control: TemporaryControl) -> TemporaryControl:
        """Record a control created by automation. Idempotent by ``control_key``.

        An existing entry that is still in force (``ACTIVE`` or ``RELEASE_FAILED``) is returned
        unchanged. A ``RELEASED`` entry is re-registered as a new ``ACTIVE`` control (the same
        target was contained again under a new approval). A ``RELEASE_PENDING`` entry raises
        :class:`RegistryError` because a release of that control is in progress.
        """
        _check_registrable(control)
        with self._transaction():
            existing = self._load(control.control_key)
            if existing is not None:
                if existing.status is ControlStatus.RELEASE_PENDING:
                    raise RegistryError(f"control {control.control_key} is being released")
                if existing.status in RELEASABLE_STATUSES:
                    return existing
            self._append(ControlEventType.REGISTERED, control, self._clock.now())
            return control

    def supersede(self, control: TemporaryControl) -> TemporaryControl:
        """Replace the entry in force for ``control.control_key`` with a later approved write.

        Used when a later package re-sent the write (the earlier one was not verified) and the
        vendor object now in force is the new one: the registry must point at the control that is
        really in force (its rollback params and external ref), never at the ineffective write.
        The earlier registration stays in the append-only history.
        """
        _check_registrable(control)
        with self._transaction():
            existing = self._load(control.control_key)
            if existing is None or existing.status is ControlStatus.RELEASED:
                self._append(ControlEventType.REGISTERED, control, self._clock.now())
                return control
            if existing.status is ControlStatus.RELEASE_PENDING:
                raise RegistryError(f"control {control.control_key} is being released")
            if existing.package_id == control.package_id:
                return existing
            self._append(ControlEventType.SUPERSEDED, control, self._clock.now())
            return control

    def get(self, control_key: str) -> TemporaryControl | None:
        """Current view of one control, or None when the key was never registered."""
        return self._load(control_key)

    def list(self, *, incident_id: str | None = None,
             status: ControlStatus | None = None) -> builtins.list[TemporaryControl]:
        """Controls filtered by incident and status, ordered by (created_at, control_key)."""
        items = [
            c for c in self._load_all()
            if (incident_id is None or c.incident_id == incident_id)
            and (status is None or c.status is status)
        ]
        return sorted(items, key=lambda c: (c.created_at, c.control_key))

    def list_active(self, incident_id: str | None = None) -> builtins.list[TemporaryControl]:
        """``ACTIVE`` controls (optionally of one incident)."""
        return self.list(incident_id=incident_id, status=ControlStatus.ACTIVE)

    def list_releasable(self, incident_id: str | None = None) -> builtins.list[TemporaryControl]:
        """Controls still in force (``ACTIVE`` or ``RELEASE_FAILED``)."""
        return [c for c in self.list(incident_id=incident_id) if c.status in RELEASABLE_STATUSES]

    def due_for_review(self, now: datetime | None = None) -> builtins.list[TemporaryControl]:
        """Controls possibly in force whose review is due. A reminder only: nothing is released.

        ``ACTIVE`` / ``RELEASE_FAILED`` controls whose ``review_due_at`` passed, plus every
        ``RELEASE_PENDING`` control (a release that may have died before reaching the vendor).
        """
        moment = utc(now) if now is not None else self._clock.now()
        return [
            c for c in self.list()
            if (c.status is ControlStatus.RELEASE_PENDING)
            or (c.status in RELEASABLE_STATUSES and c.review_due_at is not None and c.review_due_at <= moment)
        ]

    def mark_release_pending(self, control_key: str, *, release_package_id: str,
                             token_id: str) -> TemporaryControl:
        """``ACTIVE``/``RELEASE_FAILED`` -> ``RELEASE_PENDING`` (bound to the release approval)."""
        if not release_package_id or not token_id:
            raise RegistryError("release_package_id and token_id are required")
        with self._transaction():
            control = self._require(control_key)
            if control.status not in RELEASABLE_STATUSES:
                raise RegistryError(
                    f"control {control_key} is {control.status.value}; only controls in force can be released"
                )
            updated = _evolve(control, status=ControlStatus.RELEASE_PENDING,
                              release_package_id=release_package_id, release_token_id=token_id)
            self._append(ControlEventType.RELEASE_PENDING, updated, self._clock.now())
            return updated

    def mark_released(self, control_key: str, *, at: datetime) -> TemporaryControl:
        """``RELEASE_PENDING`` -> ``RELEASED``."""
        released_at = utc(at)
        with self._transaction():
            control = self._require_pending(control_key)
            updated = _evolve(control, status=ControlStatus.RELEASED, released_at=released_at,
                              last_error=None)
            self._append(ControlEventType.RELEASED, updated, released_at)
            return updated

    def mark_release_failed(self, control_key: str, *, error: ErrorInfo) -> TemporaryControl:
        """``RELEASE_PENDING`` -> ``RELEASE_FAILED`` (control still in force)."""
        if not isinstance(error, ErrorInfo):
            raise TypeError("error must be an ErrorInfo")
        with self._transaction():
            control = self._require_pending(control_key)
            updated = _evolve(control, status=ControlStatus.RELEASE_FAILED, last_error=error)
            self._append(ControlEventType.RELEASE_FAILED, updated, self._clock.now())
            return updated

    # internals --------------------------------------------------------------
    def _require(self, control_key: str) -> TemporaryControl:
        control = self._load(control_key)
        if control is None:
            raise RegistryError(f"unknown control key: {control_key}")
        return control

    def _require_pending(self, control_key: str) -> TemporaryControl:
        control = self._require(control_key)
        if control.status is not ControlStatus.RELEASE_PENDING:
            raise RegistryError(f"control {control_key} is {control.status.value}, not RELEASE_PENDING")
        return control


# ---------------------------------------------------------------- in memory --
class InMemoryControlRegistry(_ControlRegistryBase):
    """Thread-safe in-memory registry (tests, simulator, lab). Implements ``ControlRegistry``."""

    def __init__(self, *, clock: Clock | None = None) -> None:
        super().__init__(clock=clock)
        self._lock = threading.RLock()
        self._events: builtins.list[ControlEvent] = []
        self._view: dict[str, TemporaryControl] = {}

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            yield

    def _load(self, control_key: str) -> TemporaryControl | None:
        with self._lock:
            return self._view.get(control_key)

    def _load_all(self) -> builtins.list[TemporaryControl]:
        with self._lock:
            return builtins.list(self._view.values())

    def _append(self, event: ControlEventType, control: TemporaryControl, at: datetime) -> None:
        record = ControlEvent(seq=len(self._events), event=event, control_key=control.control_key,
                              at=utc(at), control=control)
        self._persist(record)
        self._apply(record)

    def _apply(self, record: ControlEvent) -> None:
        check_event_sequence(self._view.get(record.control_key), record.event, record.control)
        self._events.append(record)
        self._view[record.control_key] = record.control

    def _persist(self, record: ControlEvent) -> None:
        """Hook for durable subclasses; called before the in-memory view changes."""

    def history(self, control_key: str) -> builtins.list[ControlEvent]:
        with self._lock:
            return [e for e in self._events if e.control_key == control_key]

    def events(self) -> builtins.list[ControlEvent]:
        """Every event in append order."""
        with self._lock:
            return builtins.list(self._events)


# -------------------------------------------------------------------- JSONL --
class JsonlControlRegistry(InMemoryControlRegistry):
    """Append-only JSONL event log with an in-memory view. Implements ``ControlRegistry``.

    The file is replayed on start-up; every event is flushed and fsynced before the in-memory view
    changes. Each line carries ``prev_hash`` and ``hash`` (SHA-256 over the line without ``hash``);
    a malformed line, a sequence gap, a broken hash chain, an illegal status transition or a change
    of identity fields raises :class:`RegistryError` (fail closed).
    """

    def __init__(self, path: Path | str, *, clock: Clock | None = None) -> None:
        super().__init__(clock=clock)
        self._path = Path(path)
        self._head_hash = _GENESIS
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._replay()

    @property
    def path(self) -> Path:
        return self._path

    def _replay(self) -> None:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise RegistryError(f"{self._path.name}:{line_no}: invalid JSON") from exc
                if not isinstance(data, dict):
                    raise RegistryError(f"{self._path.name}:{line_no}: not a registry event")
                record = ControlEvent.from_dict(data)
                if record.seq != len(self._events):
                    raise RegistryError(f"{self._path.name}:{line_no}: sequence gap at {record.seq}")
                if data.get("prev_hash") != self._head_hash:
                    raise RegistryError(f"{self._path.name}:{line_no}: prev_hash does not chain "
                                        "(event removed, reordered, inserted or unchained)")
                if not isinstance(data.get("hash"), str) or _event_hash(data) != data["hash"]:
                    raise RegistryError(f"{self._path.name}:{line_no}: hash mismatch (event modified)")
                self._apply(record)
                self._head_hash = data["hash"]

    def _append(self, event: ControlEventType, control: TemporaryControl, at: datetime) -> None:
        check_event_sequence(self._view.get(control.control_key), event, control)
        super()._append(event, control, at)

    def _persist(self, record: ControlEvent) -> None:
        body = {**record.to_dict(), "prev_hash": self._head_hash}
        body["hash"] = _event_hash(body)
        line = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        try:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise RegistryError(f"could not append to the control registry: {type(exc).__name__}") from exc
        self._head_hash = body["hash"]


# ------------------------------------------------------------------- SQLite --
_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS control_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    control_key TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    event TEXT NOT NULL,
    at TEXT NOT NULL,
    snapshot TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_control_events_key ON control_events (control_key, seq);
CREATE TRIGGER IF NOT EXISTS control_events_no_update BEFORE UPDATE ON control_events
BEGIN SELECT RAISE(ABORT, 'control_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS control_events_no_delete BEFORE DELETE ON control_events
BEGIN SELECT RAISE(ABORT, 'control_events is append-only'); END;
"""

_LATEST_SQL = """
SELECT e.snapshot FROM control_events AS e
JOIN (SELECT control_key, MAX(seq) AS m FROM control_events GROUP BY control_key) AS latest
ON e.seq = latest.m
"""


class SqliteControlRegistry(_ControlRegistryBase):
    """SQLite-backed registry. Implements ``ControlRegistry``.

    Events go to an append-only table (UPDATE and DELETE are aborted by triggers). Reads always come
    from the database, so several processes can share one file; status changes run inside
    ``BEGIN IMMEDIATE`` transactions so a check-and-set is atomic across processes.
    """

    def __init__(self, path: Path | str = ":memory:", *, clock: Clock | None = None) -> None:
        super().__init__(clock=clock)
        target = str(path)
        if target != ":memory:":
            Path(target).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(target, isolation_level=None, check_same_thread=False)
        self._conn.executescript(_SQLITE_SCHEMA)

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SqliteControlRegistry":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def _query(self, sql: str, params: tuple[Any, ...] = ()) -> builtins.list[tuple[Any, ...]]:
        try:
            with self._lock:
                return self._conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise RegistryError(f"control registry query failed: {type(exc).__name__}") from exc

    @staticmethod
    def _parse(snapshot: str) -> TemporaryControl:
        try:
            return TemporaryControl.model_validate_json(snapshot)
        except ValidationError as exc:
            raise RegistryError("malformed control snapshot in registry") from exc

    def _load(self, control_key: str) -> TemporaryControl | None:
        rows = self._query(
            "SELECT snapshot FROM control_events WHERE control_key = ? ORDER BY seq DESC LIMIT 1",
            (control_key,),
        )
        return self._parse(rows[0][0]) if rows else None

    def _load_all(self) -> builtins.list[TemporaryControl]:
        return [self._parse(row[0]) for row in self._query(_LATEST_SQL)]

    def _append(self, event: ControlEventType, control: TemporaryControl, at: datetime) -> None:
        check_event_sequence(self._load(control.control_key), event, control)
        try:
            self._conn.execute(
                "INSERT INTO control_events (control_key, incident_id, event, at, snapshot) "
                "VALUES (?, ?, ?, ?, ?)",
                (control.control_key, control.incident_id, event.value, utc(at).isoformat(),
                 control.model_dump_json()),
            )
        except sqlite3.Error as exc:
            raise RegistryError(f"could not append to the control registry: {type(exc).__name__}") from exc

    def history(self, control_key: str) -> builtins.list[ControlEvent]:
        rows = self._query(
            "SELECT seq, event, at, snapshot FROM control_events WHERE control_key = ? ORDER BY seq",
            (control_key,),
        )
        return [
            ControlEvent(seq=int(seq) - 1, event=ControlEventType(event), control_key=control_key,
                         at=utc(datetime.fromisoformat(at)), control=self._parse(snapshot))
            for seq, event, at, snapshot in rows
        ]


# ------------------------------------------------------- result -> control --
def _check_result_binding(action: RecommendedAction, result: ActionResult, outcome: ActionOutcome,
                          package: ActionPackage, token: ApprovalToken) -> None:
    """The result, package and token must all describe exactly this approved action."""
    if result.status is not ActionResultStatus.SUCCESS or outcome.status is not ActionResultStatus.SUCCESS:
        raise RegistryError("only SUCCESS results create controls (ALREADY_CONTAINED is never registered)")
    if not get_action_spec(action.action_type).creates_control:
        raise RegistryError(f"{action.action_type.value} does not create a temporary control")
    if result.idempotency_key != action.idempotency_key:
        raise RegistryError("result does not belong to this action")
    if action.idempotency_key not in package.keys or package.incident_id != action.incident_id:
        raise RegistryError("action is not part of the package")
    claims = token.claims
    if claims.purpose is not ApprovalPurpose.CONTAINMENT or claims.package_id != package.package_id:
        raise RegistryError("token is not the containment approval of this package")
    if claims.grant(action.idempotency_key) is None:
        raise RegistryError("token does not grant this action")


def control_from_result(action: RecommendedAction, result: ActionResult, outcome: ActionOutcome, *,
                        package: ActionPackage, token: ApprovalToken, decision_id: str,
                        review_after_hours: Mapping[str, int], clock: Clock) -> TemporaryControl:
    """Build the registry entry for a successful, approved, control-creating action.

    ``rollback_params`` come from the adapter outcome; ``integration`` defaults to the integration
    that executed the action. ``review_due_at`` is set from ``review_after_hours`` (reminder only).
    Raises :class:`RegistryError` when the result must not be registered.
    """
    _check_result_binding(action, result, outcome, package, token)
    spec = get_action_spec(action.action_type)
    created_at = clock.now()
    hours = review_after_hours.get(action.action_type.value)
    rollback_params = {**outcome.rollback_params}
    rollback_params.setdefault("integration", outcome.integration or action.integration)
    return TemporaryControl(
        control_key=action.idempotency_key,
        incident_id=action.incident_id,
        action_type=action.action_type,
        target=action.target,
        target_kind=action.target_kind,
        integration=outcome.integration or action.integration,
        workflow_id=package.workflow_id,
        workflow_version=package.workflow_version,
        package_id=package.package_id,
        token_id=token.token_id,
        decision_id=decision_id,
        approval_level=action.approval_level,
        created_at=created_at,
        rollback_action_type=spec.rollback_action_type,
        rollback_params=rollback_params,
        external_ref=outcome.external_ref,
        review_due_at=created_at + timedelta(hours=hours) if hours else None,
    )
