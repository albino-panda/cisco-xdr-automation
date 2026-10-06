"""Cross-process exclusive lock for audit appends.

Uses ``msvcrt.locking`` on Windows and ``fcntl.flock`` elsewhere, on a sidecar ``<file>.lock``
file. Two :class:`InterProcessLock` objects on the same path exclude each other whether they
live in different processes or in the same process (each opens its own handle).
"""
from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import IO

from xdr_response.errors import AuditError

__all__ = ["InterProcessLock", "lock_path_for"]

if os.name == "nt":  # pragma: no cover - platform branch
    import msvcrt

    def _try_lock(fh: IO[bytes]) -> bool:
        fh.seek(0)
        try:
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    def _unlock(fh: IO[bytes]) -> None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)

else:  # pragma: no cover - platform branch
    import errno
    import fcntl

    def _try_lock(fh: IO[bytes]) -> bool:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                return False
            raise
        return True

    def _unlock(fh: IO[bytes]) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def lock_path_for(path: Path) -> Path:
    """Sidecar lock file of an audit file."""
    return path.with_name(path.name + ".lock")


class InterProcessLock:
    """Exclusive, non-reentrant file lock with a timeout. Use as a context manager."""

    def __init__(self, path: Path | str, *, timeout: float = 10.0, poll_interval: float = 0.005,
                 sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self._path = Path(path)
        self._timeout = timeout
        self._poll = poll_interval
        self._sleep = sleep
        self._monotonic = monotonic
        self._fh: IO[bytes] | None = None

    @property
    def held(self) -> bool:
        """True while this object holds the lock."""
        return self._fh is not None

    def acquire(self) -> None:
        """Block until the lock is held; :class:`AuditError` after ``timeout`` seconds."""
        if self._fh is not None:
            raise AuditError("audit lock is not reentrant")
        try:
            fh = self._path.open("a+b")
        except OSError as exc:
            raise AuditError(f"cannot open audit lock file: {type(exc).__name__}") from None
        deadline = self._monotonic() + self._timeout
        while not _try_lock(fh):
            if self._monotonic() >= deadline:
                fh.close()
                raise AuditError(f"timed out after {self._timeout}s waiting for the audit lock")
            self._sleep(self._poll)
        self._fh = fh

    def release(self) -> None:
        """Release the lock (no-op when not held)."""
        fh, self._fh = self._fh, None
        if fh is None:
            return
        try:
            _unlock(fh)
        finally:
            fh.close()

    def __enter__(self) -> "InterProcessLock":
        self.acquire()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.release()
