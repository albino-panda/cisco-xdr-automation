"""Hash-chain verification (architecture section 13.12).

The verifier never raises for a broken chain; it reports the first failure in a
:class:`ChainVerification`. Checks, in order, for every record:

1. the line is UTF-8 JSON that validates as an :class:`AuditRecord`, ends with a newline, has no
   duplicated keys and is byte-for-byte the canonical encoding of the record (raw lines only);
2. ``seq`` is contiguous from 0 (a deleted, duplicated or reordered record breaks this);
3. ``prev_hash`` equals the previous record's ``hash`` (``GENESIS_HASH`` for seq 0);
4. ``hash`` equals the recomputed hash (an edited record breaks this);
5. optional anchors: a record whose ``seq`` is anchored must carry the anchored hash, and every
   anchored ``seq`` must be present. Anchors are head hashes kept outside the audit file (the
   :class:`~xdr_response.audit.trail.AuditTrail` head anchor file, or an external system); they
   detect truncation of the tail, records appended without the writer, and rewritten chains.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from pydantic import Field

from xdr_response.audit.hashing import hash_of_record, parse_canonical_record_line
from xdr_response.models._base import FrozenModel
from xdr_response.models.audit import GENESIS_HASH, AuditRecord, ChainVerification

__all__ = ["AuditAnchor", "ChainChecker", "verify_chain", "verify_records", "verify_lines"]


class AuditAnchor(FrozenModel):
    """A ``(seq, hash)`` checkpoint of the chain, exported outside the audit file."""

    seq: int = Field(ge=0)
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def parse(cls, text: str) -> "AuditAnchor":
        """Parse ``"<seq>:<hash>"``. Raises ``ValueError`` on bad input."""
        seq_text, sep, hash_text = text.strip().partition(":")
        if not sep or not seq_text.isdigit():
            raise ValueError("anchor must look like '<seq>:<64 hex hash>'")
        return cls(seq=int(seq_text), hash=hash_text.lower())


class ChainChecker:
    """Incremental chain checker. Feed records in file order; stops at the first failure."""

    def __init__(self, *, start_seq: int = 0, start_hash: str = GENESIS_HASH,
                 anchors: Iterable[AuditAnchor] = ()) -> None:
        self._next_seq = start_seq
        self._head = start_hash
        self._count = 0
        self._anchors = {a.seq: a.hash for a in anchors if a.seq >= start_seq}
        self._bad_seq: int | None = None
        self._reason = ""

    @property
    def failed(self) -> bool:
        """True once a failure has been recorded."""
        return self._bad_seq is not None

    @property
    def next_seq(self) -> int:
        """Sequence number the next valid record must carry."""
        return self._next_seq

    @property
    def head_hash(self) -> str:
        """Hash of the last accepted record (or the start hash)."""
        return self._head

    def fail(self, reason: str) -> None:
        """Record a failure at the current position (for unparsable input)."""
        if not self.failed:
            self._bad_seq = self._next_seq
            self._reason = reason

    def feed(self, record: AuditRecord) -> bool:
        """Check one record; returns False (and records the reason) when it breaks the chain."""
        if self.failed:
            return False
        reason = self._problem(record)
        if reason:
            self.fail(reason)
            return False
        self._head = record.hash
        self._next_seq += 1
        self._count += 1
        return True

    def _problem(self, record: AuditRecord) -> str:
        expected = self._next_seq
        if record.seq != expected:
            return (f"seq {record.seq} found where {expected} was expected "
                    "(record deleted, duplicated or reordered)")
        if record.prev_hash != self._head:
            return f"prev_hash of seq {expected} does not match the hash of the previous record"
        if hash_of_record(record) != record.hash:
            return f"hash of seq {expected} does not match its content (record modified)"
        anchored = self._anchors.get(expected)
        if anchored is not None and anchored != record.hash:
            return f"hash of seq {expected} does not match the external anchor"
        return ""

    def result(self) -> ChainVerification:
        """Final verdict, including the anchor presence check."""
        if not self.failed:
            missing = sorted(seq for seq in self._anchors if seq >= self._next_seq)
            if missing:
                self.fail(f"chain truncated: anchored seq {missing[0]} is missing "
                          f"(chain ends before seq {self._next_seq})")
        return ChainVerification(ok=not self.failed, records=self._count, head_hash=self._head,
                                 first_bad_seq=self._bad_seq, reason=self._reason)


def verify_records(records: Iterable[AuditRecord | Mapping[str, Any]], *,
                   anchors: Iterable[AuditAnchor] = ()) -> ChainVerification:
    """Verify an in-memory sequence of records (or record dicts) from seq 0."""
    checker = ChainChecker(anchors=anchors)
    for item in records:
        try:
            record = item if isinstance(item, AuditRecord) else AuditRecord.model_validate(item)
        except ValueError as exc:
            checker.fail(f"record {checker.next_seq} is malformed: {_short(exc)}")
            break
        if not checker.feed(record):
            break
    return checker.result()


def verify_lines(lines: Iterable[bytes], *, start_seq: int = 0, start_hash: str = GENESIS_HASH,
                 anchors: Iterable[AuditAnchor] = ()) -> ChainVerification:
    """Verify raw JSONL lines (each including its trailing newline), starting at ``start_seq``."""
    checker = ChainChecker(start_seq=start_seq, start_hash=start_hash, anchors=anchors)
    for line in lines:
        if not line.endswith(b"\n"):
            checker.fail(f"line for seq {checker.next_seq} is incomplete (no newline; truncated write)")
            break
        try:
            record = parse_canonical_record_line(line)
        except ValueError as exc:
            checker.fail(f"line for seq {checker.next_seq} is not a valid audit record: {_short(exc)}")
            break
        if not checker.feed(record):
            break
    return checker.result()


def iter_file_lines(path: Path, *, limit: int | None = None) -> Iterator[bytes]:
    """Yield the raw lines of ``path`` (binary), reading at most ``limit`` bytes."""
    remaining = limit
    with path.open("rb") as fh:
        for line in fh:
            if remaining is not None:
                if remaining <= 0:
                    return
                line = line[:remaining]
                remaining -= len(line)
            yield line


def verify_chain(path: Path | str, *, anchors: Iterable[AuditAnchor] = ()) -> ChainVerification:
    """Verify the JSONL audit file at ``path``. A missing file is reported, not raised."""
    file_path = Path(path)
    if not file_path.is_file():
        return ChainVerification(ok=False, records=0, head_hash=GENESIS_HASH, first_bad_seq=None,
                                 reason=f"audit file not found: {file_path}")
    try:
        return verify_lines(iter_file_lines(file_path), anchors=anchors)
    except OSError as exc:
        return ChainVerification(ok=False, records=0, head_hash=GENESIS_HASH, first_bad_seq=None,
                                 reason=f"audit file unreadable: {type(exc).__name__}")


def _short(exc: Exception) -> str:
    text = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    return text[:200]
