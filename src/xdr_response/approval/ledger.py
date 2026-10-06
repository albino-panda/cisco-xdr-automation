"""Token use ledgers: each ``(token_id, idempotency_key)`` pair may be consumed exactly once.

Both classes implement :class:`xdr_response.interfaces.TokenUseLedger`. The JSONL ledger is
append-only (there is no method that removes an entry) and refuses to start from a corrupt file,
so a damaged ledger can never silently re-allow a used approval.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from xdr_response.audit.locking import InterProcessLock, lock_path_for
from xdr_response.clock import Clock, SystemClock
from xdr_response.errors import ConfigError, TokenReplayError
from xdr_response.models import format_datetime

__all__ = ["InMemoryTokenUseLedger", "JsonlTokenUseLedger"]


def _check(token_id: str, idempotency_key: str) -> tuple[str, str]:
    if not isinstance(token_id, str) or not token_id:
        raise ValueError("token_id must be a non-empty string")
    if not isinstance(idempotency_key, str) or not idempotency_key:
        raise ValueError("idempotency_key must be a non-empty string")
    return token_id, idempotency_key


def _replay(token_id: str, idempotency_key: str) -> TokenReplayError:
    return TokenReplayError(
        f"approval token {token_id} was already used for action {idempotency_key}"
    )


class InMemoryTokenUseLedger:
    """Thread-safe in-memory ledger (tests, simulator, single-process lab)."""

    def __init__(self) -> None:
        self._used: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def consume(self, token_id: str, idempotency_key: str) -> None:
        """Record the use; raise :class:`TokenReplayError` if it was already recorded."""
        pair = _check(token_id, idempotency_key)
        with self._lock:
            if pair in self._used:
                raise _replay(*pair)
            self._used.add(pair)

    def is_consumed(self, token_id: str, idempotency_key: str) -> bool:
        """True when the pair was consumed before."""
        return _check(token_id, idempotency_key) in self._used


class JsonlTokenUseLedger:
    """Append-only JSONL ledger, one ``{"token_id", "idempotency_key", "consumed_at"}`` per line.

    New lines written by another ledger instance on the same file are picked up before every check.
    ``consume`` holds an OS-level exclusive file lock (``<path>.lock``) around refresh, check and
    append, so two instances on one file (two workers, two processes, two runtimes in one process)
    can never both consume the same ``(token_id, idempotency_key)``.
    """

    def __init__(self, path: Path | str, *, clock: Clock | None = None, fsync: bool = True,
                 lock_timeout: float = 10.0) -> None:
        self._path = Path(path)
        self._clock = clock or SystemClock()
        self._fsync = fsync
        self._used: set[tuple[str, str]] = set()
        self._offset = 0
        self._lines = 0
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file_lock = InterProcessLock(lock_path_for(self._path), timeout=lock_timeout)
        with self._lock:
            self._refresh()

    @property
    def path(self) -> Path:
        """Location of the ledger file."""
        return self._path

    def _refresh(self) -> None:
        if not self._path.exists():
            return
        with self._path.open("rb") as fh:
            fh.seek(self._offset)
            data = fh.read()
        if not data:
            return
        if not data.endswith(b"\n"):
            raise ConfigError(f"token ledger {self._path} ends with an incomplete line; refusing to use it")
        for raw in data.splitlines():
            self._lines += 1
            self._used.add(self._parse(raw))
        self._offset += len(data)

    def _parse(self, raw: bytes) -> tuple[str, str]:
        try:
            entry = json.loads(raw.decode("utf-8"))
            return _check(entry["token_id"], entry["idempotency_key"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ConfigError(
                f"token ledger {self._path} line {self._lines} is corrupt; refusing to use it"
            ) from exc

    def _append(self, token_id: str, idempotency_key: str) -> None:
        line = json.dumps(
            {"token_id": token_id, "idempotency_key": idempotency_key,
             "consumed_at": format_datetime(self._clock.now())},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        with self._path.open("ab") as fh:
            fh.write(line)
            fh.flush()
            if self._fsync:
                os.fsync(fh.fileno())
        self._offset += len(line)
        self._lines += 1

    def consume(self, token_id: str, idempotency_key: str) -> None:
        """Durably record the use; raise :class:`TokenReplayError` if it was already recorded."""
        pair = _check(token_id, idempotency_key)
        with self._lock, self._file_lock:  # thread mutex plus cross-instance / cross-process lock
            self._refresh()
            if pair in self._used:
                raise _replay(*pair)
            self._append(*pair)
            self._used.add(pair)

    def is_consumed(self, token_id: str, idempotency_key: str) -> bool:
        """True when the pair was consumed before (including by another instance on this file)."""
        pair = _check(token_id, idempotency_key)
        with self._lock:
            self._refresh()
            return pair in self._used
