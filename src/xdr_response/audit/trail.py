"""Append-only, hash-chained audit trail (architecture section 13.12).

:class:`AuditTrail` writes one canonical-JSON record per line. Each record carries ``seq``,
``prev_hash`` and ``hash``; the payload is passed through the central :class:`Redactor` before it
is hashed or written, so secrets never reach disk. Appends are serialized by a thread lock and a
cross-process file lock; before every append the writer re-reads (and verifies) whatever other
writers appended since its last look, and refuses to write if the file shrank or the new tail does
not chain. There is deliberately no update, delete or truncate method.

Head anchor: after every append the writer atomically records the new head ``(seq, hash)`` in a
sidecar file (default ``<audit file>.head``; place it on separate storage or permissions where
possible). Opening the trail, re-syncing with other writers and :meth:`AuditTrail.verify` all check
the chain against it, so dropping the newest records (for example a final REJECT decision) or
appending a well-chained forged record offline is detected, not only edits in the middle of the
chain. The anchor is authenticated: it carries an HMAC-SHA256 ``mac`` keyed with the audit chain
key (:mod:`xdr_response.audit.keys`: ``AUDIT_CHAIN_KEY`` from the secrets interface or the
environment, else a per-user key file outside the audit directory), so rewriting the history and
re-anchoring the new head with the public hashing helpers is detected: without the key no valid
anchor MAC can be produced. A non-empty audit file without its head anchor is refused (fail closed). If a crash happens
between writing a record and its anchor, the trail refuses to open until an operator has verified
the file (``tools/validation/verify_audit_chain.py``) and restored the anchor.

:class:`MemoryAuditTrail` implements the same contract in memory for unit tests.
"""
from __future__ import annotations

import io
import json
import math
import os
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from xdr_response.audit.hashing import (
    compute_record_hash,
    encode_record_line,
    hash_of_record,
    parse_canonical_record_line,
)
import hmac as _hmac

from xdr_response.audit.keys import anchor_mac, resolve_chain_key
from xdr_response.audit.locking import InterProcessLock, lock_path_for
from xdr_response.audit.verify import (
    AuditAnchor,
    ChainChecker,
    iter_file_lines,
    verify_chain,
    verify_lines,
    verify_records,
)
from xdr_response.clock import DEFAULT_CLOCK, Clock, utc
from xdr_response.errors import AuditError, AuditIntegrityError
from xdr_response.logs.redaction import Redactor, get_redactor
from xdr_response.models.audit import GENESIS_HASH, AuditRecord, ChainVerification
from xdr_response.models.canonical import canonical_json
from xdr_response.models.enums import AuditEventType

__all__ = ["AuditTrail", "MemoryAuditTrail", "compute_record_hash", "prepare_payload",
           "head_anchor_path_for"]

IdFactory = Callable[[], str]


def _default_id() -> str:
    return f"aud-{uuid.uuid4().hex}"


# ------------------------------------------------------------- payloads ---
def prepare_payload(payload: Mapping[str, Any], redactor: Redactor) -> dict[str, Any]:
    """Redact ``payload`` and reduce it to plain JSON types (what is hashed and stored).

    Values under sensitive keys, registered secret values, bearer/basic credentials and JWT-shaped
    strings are replaced by ``[REDACTED]``; string keys are scrubbed too. Non-finite floats and
    naive datetimes become strings. Raises :class:`AuditError` if the result is not serializable.
    """
    if not isinstance(payload, Mapping):
        raise AuditError("audit payload must be a mapping")
    redacted = redactor.redact(_presort(dict(payload)))
    cleaned = _json_safe(redacted, redactor)
    try:
        return json.loads(canonical_json(cleaned, allow_floats=True))
    except ValueError as exc:
        raise AuditError(f"audit payload is not serializable: {type(exc).__name__}") from None


def _presort(value: Any) -> Any:
    """Dump models and turn sets into sorted lists so stored payloads are deterministic."""
    if isinstance(value, BaseModel):
        return _presort(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {k: _presort(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_presort(v) for v in value]
    if isinstance(value, (set, frozenset)):
        items = [_presort(v) for v in value]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True, default=repr))
    return value


def _json_safe(value: Any, redactor: Redactor) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, datetime) and value.utcoffset() is None:
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool, Enum, datetime, date)):
        return value
    if isinstance(value, Mapping):
        return {_safe_key(k, redactor): _json_safe(v, redactor) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v, redactor) for v in value]
    return redactor.redact_text(repr(value))


def _safe_key(key: Any, redactor: Redactor) -> Any:
    if isinstance(key, str):
        return redactor.redact_text(key)
    if isinstance(key, (int, Enum)) and not isinstance(key, bool):
        return key
    return redactor.redact_text(str(key))


def _optional_text(value: str | None, field: str, redactor: Redactor) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AuditError(f"audit field {field} must be a string or None")
    return redactor.redact_text(value)


# --------------------------------------------------------------- builder ---
class _RecordBuilder:
    """Turns an append call into a hashed :class:`AuditRecord` (no I/O)."""

    def __init__(self, clock: Clock | None, redactor: Redactor | None,
                 id_factory: IdFactory | None) -> None:
        self._clock = clock or DEFAULT_CLOCK
        self._redactor = redactor or get_redactor()
        self._new_id = id_factory or _default_id

    def build(self, event_type: AuditEventType | str, *, seq: int, prev_hash: str,
              incident_id: str | None, actor: str, payload: Mapping[str, Any],
              workflow_id: str | None, workflow_version: str | None) -> AuditRecord:
        try:
            event = AuditEventType(event_type)
        except ValueError:
            raise AuditError(f"unknown audit event type: {event_type!r}") from None
        if not isinstance(actor, str) or not actor.strip():
            raise AuditError("audit actor must be a non-empty string")
        r = self._redactor
        try:
            timestamp = utc(self._clock.now())
        except (TypeError, ValueError):
            raise AuditError("audit clock must return a timezone-aware datetime") from None
        body: dict[str, Any] = {
            "seq": seq,
            "record_id": self._new_id(),
            "timestamp": timestamp,
            "event_type": event,
            "incident_id": _optional_text(incident_id, "incident_id", r),
            "workflow_id": _optional_text(workflow_id, "workflow_id", r),
            "workflow_version": _optional_text(workflow_version, "workflow_version", r),
            "actor": r.redact_text(actor),
            "payload": prepare_payload(payload, r),
            "prev_hash": prev_hash,
        }
        try:
            record = AuditRecord(**body, hash=compute_record_hash(body))
        except ValueError as exc:
            raise AuditError(f"invalid audit record: {type(exc).__name__}") from None
        if hash_of_record(record) != record.hash:  # defensive: validation must not change bytes
            raise AuditError("audit record hash is not stable under model validation")
        return record


def _filter(records: list[AuditRecord], incident_id: str | None) -> Iterator[AuditRecord]:
    if incident_id is None:
        return iter(records)
    return iter([r for r in records if r.incident_id == incident_id])


def _anchor(next_seq: int, head_hash: str) -> AuditAnchor | None:
    return None if next_seq == 0 else AuditAnchor(seq=next_seq - 1, hash=head_hash)


def head_anchor_path_for(path: Path) -> Path:
    """Default location of the head anchor file of the audit file ``path``."""
    return path.with_name(path.name + ".head")


def _check_head(result: ChainVerification, head: AuditAnchor) -> ChainVerification:
    """The chain must end exactly at the head anchor (no record beyond it, none missing)."""
    if not result.ok:
        return result
    if result.records != head.seq + 1 or result.head_hash != head.hash:
        return result.model_copy(update={
            "ok": False, "first_bad_seq": head.seq + 1,
            "reason": (f"chain has {result.records} record(s) but the head anchor names seq {head.seq}: "
                       "records were appended without the audit writer (forged) or removed"),
        })
    return result


# ------------------------------------------------------------ file trail ---
@dataclass
class _FileHead:
    next_seq: int = 0
    head_hash: str = GENESIS_HASH
    size: int = 0  # bytes of the file this writer has verified


class _Exclusive:
    """Thread mutex plus file lock; the file lock is taken once per outermost entry."""

    def __init__(self, mutex: threading.RLock, file_lock: InterProcessLock) -> None:
        self._mutex = mutex
        self._file_lock = file_lock
        self._owner = False

    def __enter__(self) -> None:
        self._mutex.acquire()
        try:
            if not self._file_lock.held:
                self._file_lock.acquire()
                self._owner = True
        except BaseException:
            self._mutex.release()
            raise

    def __exit__(self, *exc: object) -> None:
        try:
            if self._owner:
                self._file_lock.release()
        finally:
            self._mutex.release()


class AuditTrail:
    """JSONL audit trail with a SHA-256 hash chain. Implements ``AuditSink``.

    On construction the existing file is fully verified; a broken chain raises
    :class:`AuditIntegrityError` and the trail refuses to append.
    """

    def __init__(self, path: Path | str, *, clock: Clock | None = None,
                 redactor: Redactor | None = None, fsync: bool = True,
                 lock_timeout: float = 10.0, id_factory: IdFactory | None = None,
                 anchor_path: Path | str | None = None, chain_key: Any = None) -> None:
        self._path = Path(path)
        self._chain_key = resolve_chain_key(chain_key)
        self._anchor_path = Path(anchor_path) if anchor_path is not None else head_anchor_path_for(self._path)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._anchor_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditError(f"cannot create audit directory: {type(exc).__name__}") from None
        self._builder = _RecordBuilder(clock, redactor, id_factory)
        self._fsync = fsync
        self._mutex = threading.RLock()
        self._file_lock = InterProcessLock(lock_path_for(self._path), timeout=lock_timeout)
        self._head = _FileHead()
        with self._exclusive():
            self._load()

    # -------------------------------------------------------------- public --
    @property
    def path(self) -> Path:
        """Location of the JSONL file."""
        return self._path

    @property
    def anchor_path(self) -> Path:
        """Location of the head anchor file."""
        return self._anchor_path

    @property
    def head_hash(self) -> str:
        """Hash of the newest record (``GENESIS_HASH`` when empty), other writers included."""
        with self._exclusive():
            self._sync()
            return self._head.head_hash

    def append(self, event_type: AuditEventType, *, incident_id: str | None, actor: str,
               payload: Mapping[str, Any], workflow_id: str | None = None,
               workflow_version: str | None = None) -> AuditRecord:
        """Redact, hash, chain and durably write one record. :class:`AuditError` on any failure."""
        with self._exclusive():
            self._sync()
            record = self._builder.build(
                event_type, seq=self._head.next_seq, prev_hash=self._head.head_hash,
                incident_id=incident_id, actor=actor, payload=payload,
                workflow_id=workflow_id, workflow_version=workflow_version)
            self._write(encode_record_line(record))
            self._head.next_seq += 1
            self._head.head_hash = record.hash
            self._write_anchor(AuditAnchor(seq=record.seq, hash=record.hash))
            return record

    def records(self, incident_id: str | None = None) -> Iterator[AuditRecord]:
        """All records (optionally of one incident), verified; :class:`AuditIntegrityError` if broken."""
        with self._exclusive():
            self._sync()
            collected = self._read_verified(self._head.size)
        return _filter(collected, incident_id)

    def verify(self, *, anchors: tuple[AuditAnchor, ...] = ()) -> ChainVerification:
        """Full verification of the file against the head anchor (never raises for a broken chain)."""
        with self._exclusive():
            try:
                head = self._read_anchor()
            except AuditIntegrityError as exc:
                return ChainVerification(ok=False, records=0, head_hash=GENESIS_HASH, first_bad_seq=None,
                                         reason=str(exc))
            size = self._file_size() or 0
            if head is None:
                if size:
                    return ChainVerification(ok=False, records=0, head_hash=GENESIS_HASH, first_bad_seq=None,
                                             reason="audit head anchor is missing for a non-empty audit file")
                return verify_chain(self._path, anchors=anchors) if self._path.is_file() else ChainVerification(
                    ok=True, records=0, head_hash=GENESIS_HASH, first_bad_seq=None, reason="")
            result = verify_chain(self._path, anchors=(*anchors, head))
            return _check_head(result, head)

    def anchor(self) -> AuditAnchor | None:
        """Current ``(seq, hash)`` checkpoint to export to an external system; None when empty."""
        with self._exclusive():
            self._sync()
            return _anchor(self._head.next_seq, self._head.head_hash)

    def __len__(self) -> int:
        with self._exclusive():
            self._sync()
            return self._head.next_seq

    def __repr__(self) -> str:
        return f"AuditTrail(path={str(self._path)!r})"

    # ------------------------------------------------------------- private --
    def _exclusive(self) -> _Exclusive:
        return _Exclusive(self._mutex, self._file_lock)

    def _file_size(self) -> int | None:
        try:
            return self._path.stat().st_size
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AuditError(f"cannot stat audit file: {type(exc).__name__}") from None

    def _load(self) -> None:
        size = self._file_size()
        head = self._read_anchor()
        if not size:
            if head is not None:
                raise AuditIntegrityError(
                    f"audit file is empty but its head anchor names seq {head.seq}: truncation detected; "
                    "refusing to append")
            self._head = _FileHead()
            return
        if head is None:
            raise AuditIntegrityError(
                "audit head anchor is missing for a non-empty audit file (deleted anchor or unanchored "
                "file); refusing to append until an operator verified the chain")
        result = _check_head(verify_lines(iter_file_lines(self._path, limit=size), anchors=(head,)), head)
        if not result.ok:
            raise AuditIntegrityError(
                f"audit trail failed verification at seq {result.first_bad_seq}: {result.reason}; "
                "refusing to append")
        self._head = _FileHead(next_seq=result.records, head_hash=result.head_hash, size=size)

    def _read_anchor(self) -> AuditAnchor | None:
        try:
            raw = self._anchor_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AuditError(f"cannot read audit head anchor: {type(exc).__name__}") from None
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("not an object")
            mac = data.pop("mac", None)
            anchor = AuditAnchor.model_validate(data)
        except ValueError:
            raise AuditIntegrityError("audit head anchor is malformed") from None
        expected = anchor_mac(self._chain_key, anchor.seq, anchor.hash)
        if not isinstance(mac, str) or not _hmac.compare_digest(expected.encode("ascii"), mac.encode("utf-8")):
            raise AuditIntegrityError(
                "audit head anchor is not authenticated (missing or wrong MAC): the anchor was written "
                "without the audit chain key (history rewritten and re-anchored?); refusing to trust it")
        return anchor

    def _write_anchor(self, anchor: AuditAnchor) -> None:
        body = anchor.model_dump(mode="json")
        body["mac"] = anchor_mac(self._chain_key, anchor.seq, anchor.hash)
        data = json.dumps(body, sort_keys=True).encode("utf-8")
        tmp = self._anchor_path.with_name(self._anchor_path.name + ".tmp")
        try:
            with tmp.open("wb") as fh:
                fh.write(data)
                fh.flush()
                if self._fsync:
                    os.fsync(fh.fileno())
            os.replace(tmp, self._anchor_path)
        except OSError as exc:
            raise AuditError(f"audit head anchor write failed: {type(exc).__name__}") from None

    def _sync(self) -> None:
        """Adopt (after verifying) records other writers appended; detect shrinking files."""
        size = self._file_size()
        known = self._head.size
        if size is None:
            if known:
                raise AuditIntegrityError("audit file disappeared: deletion detected")
            return
        if size < known:
            raise AuditIntegrityError(
                f"audit file shrank from {known} to {size} bytes: truncation detected")
        if size == known:
            return
        tail = self._read_bytes(known, size)
        result = verify_lines(io.BytesIO(tail), start_seq=self._head.next_seq,
                              start_hash=self._head.head_hash)
        if not result.ok:
            raise AuditIntegrityError(
                f"audit records appended by another writer do not chain at seq "
                f"{result.first_bad_seq}: {result.reason}")
        next_seq = self._head.next_seq + result.records
        head = self._read_anchor()
        if head is None or head.seq != next_seq - 1 or head.hash != result.head_hash:
            raise AuditIntegrityError(
                "audit records were appended without a matching head anchor (not written by an "
                "audit writer): refusing to adopt them")
        self._head = _FileHead(next_seq=next_seq, head_hash=result.head_hash, size=size)

    def _read_bytes(self, start: int, end: int) -> bytes:
        try:
            with self._path.open("rb") as fh:
                fh.seek(start)
                return fh.read(end - start)
        except OSError as exc:
            raise AuditError(f"cannot read audit file: {type(exc).__name__}") from None

    def _read_verified(self, size: int) -> list[AuditRecord]:
        checker = ChainChecker()
        out: list[AuditRecord] = []
        try:
            for line in (iter_file_lines(self._path, limit=size) if size else ()):
                record = parse_canonical_record_line(line)
                if not checker.feed(record):
                    break
                out.append(record)
        except ValueError:
            checker.fail("unparsable audit line")
        except OSError as exc:
            raise AuditError(f"cannot read audit file: {type(exc).__name__}") from None
        result = checker.result()
        if not result.ok:
            raise AuditIntegrityError(
                f"audit trail failed verification at seq {result.first_bad_seq}: {result.reason}")
        return out

    def _write(self, line: bytes) -> None:
        try:
            with self._path.open("ab") as fh:
                fh.write(line)
                fh.flush()
                if self._fsync:
                    os.fsync(fh.fileno())
        except OSError as exc:
            raise AuditError(f"audit write failed: {type(exc).__name__}") from None
        self._head.size += len(line)


# ---------------------------------------------------------- memory trail ---
class MemoryAuditTrail:
    """In-memory ``AuditSink`` with the same redaction and hash chain, for unit tests.

    ``fail_when`` (optional predicate on the event type) makes ``append`` raise :class:`AuditError`,
    so callers can test that an audit failure blocks execution.
    """

    def __init__(self, *, clock: Clock | None = None, redactor: Redactor | None = None,
                 id_factory: IdFactory | None = None,
                 fail_when: Callable[[AuditEventType], bool] | None = None) -> None:
        self._builder = _RecordBuilder(clock, redactor, id_factory)
        self._records: list[AuditRecord] = []
        self._mutex = threading.RLock()
        self.fail_when = fail_when

    @property
    def head_hash(self) -> str:
        """Hash of the newest record (``GENESIS_HASH`` when empty)."""
        with self._mutex:
            return self._records[-1].hash if self._records else GENESIS_HASH

    def append(self, event_type: AuditEventType, *, incident_id: str | None, actor: str,
               payload: Mapping[str, Any], workflow_id: str | None = None,
               workflow_version: str | None = None) -> AuditRecord:
        """Redact, hash and chain one record in memory."""
        with self._mutex:
            predicate = self.fail_when
            if predicate is not None:
                try:
                    event = AuditEventType(event_type)
                except ValueError:
                    raise AuditError(f"unknown audit event type: {event_type!r}") from None
                if predicate(event):
                    raise AuditError(f"simulated audit failure for {event.value}")
            record = self._builder.build(
                event_type, seq=len(self._records), prev_hash=self.head_hash,
                incident_id=incident_id, actor=actor, payload=payload,
                workflow_id=workflow_id, workflow_version=workflow_version)
            self._records.append(record)
            return record

    def records(self, incident_id: str | None = None) -> Iterator[AuditRecord]:
        """Snapshot iterator over the records (optionally of one incident)."""
        with self._mutex:
            return _filter(list(self._records), incident_id)

    def snapshot(self) -> tuple[AuditRecord, ...]:
        """Immutable copy of every record, in order."""
        with self._mutex:
            return tuple(self._records)

    def verify(self, *, anchors: tuple[AuditAnchor, ...] = ()) -> ChainVerification:
        """Verify the in-memory chain."""
        return verify_records(self.snapshot(), anchors=anchors)

    def anchor(self) -> AuditAnchor | None:
        """Current ``(seq, hash)`` checkpoint; None when empty."""
        with self._mutex:
            return _anchor(len(self._records), self.head_hash)

    def __len__(self) -> int:
        with self._mutex:
            return len(self._records)

    def __repr__(self) -> str:
        return f"MemoryAuditTrail(records={len(self)})"
