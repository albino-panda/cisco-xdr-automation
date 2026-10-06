"""File locking: concurrent writers (threads with separate handles, and processes) keep one chain."""
from __future__ import annotations

import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from xdr_response.audit import AuditTrail, verify_chain
from xdr_response.audit.locking import InterProcessLock, lock_path_for
from xdr_response.errors import AuditError
from xdr_response.models import AuditEventType

REPO_ROOT = Path(__file__).resolve().parents[3]


class FakeTime:
    """Deterministic monotonic clock; ``sleep`` advances it instead of waiting."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_lock_excludes_second_holder_and_times_out(tmp_path):
    path = tmp_path / "x.lock"
    fake = FakeTime()
    holder = InterProcessLock(path)
    contender = InterProcessLock(path, timeout=0.05, poll_interval=0.01,
                                 sleep=fake.sleep, monotonic=fake.monotonic)
    with holder:
        with pytest.raises(AuditError, match="timed out"):
            contender.acquire()
    assert fake.sleeps and fake.now >= 0.05
    assert not contender.held
    with contender:  # free again once released
        assert contender.held
    assert not contender.held


def test_lock_is_not_reentrant_on_one_object(tmp_path):
    lock = InterProcessLock(tmp_path / "y.lock")
    with lock:
        with pytest.raises(AuditError, match="reentrant"):
            lock.acquire()


def test_release_without_acquire_is_noop(tmp_path):
    InterProcessLock(tmp_path / "z.lock").release()


def test_lock_path_is_a_sidecar(tmp_path):
    assert lock_path_for(tmp_path / "audit.jsonl") == tmp_path / "audit.jsonl.lock"


def test_append_waits_for_lock_then_fails_closed(make_trail, audit_path):
    trail = make_trail(lock_timeout=0.05)
    with InterProcessLock(lock_path_for(audit_path)):
        with pytest.raises(AuditError, match="timed out"):
            trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test", payload={})
    trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test", payload={})
    assert len(trail) == 1


def test_threads_with_independent_trails_share_one_chain(make_trail, audit_path, ids):
    writers = [make_trail(id_factory=ids(f"w{i}")) for i in range(4)]
    per_writer = 15
    errors: list[BaseException] = []
    start = threading.Barrier(len(writers))

    def work(trail: AuditTrail, n: int) -> None:
        try:
            start.wait()
            for i in range(per_writer):
                trail.append(AuditEventType.API_CALL, incident_id=f"XDR-{n}",
                             actor="automation:test", payload={"writer": n, "i": i})
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(t, n)) for n, t in enumerate(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors
    result = verify_chain(audit_path)
    assert result.ok and result.records == len(writers) * per_writer
    for writer in writers:  # every writer sees the shared head
        assert writer.head_hash == result.head_hash


def test_threads_sharing_one_trail(make_trail, audit_path):
    trail = make_trail()

    def work(n: int) -> None:
        for i in range(10):
            trail.append(AuditEventType.API_CALL, incident_id="XDR-83921", actor="automation:test",
                         payload={"thread": n, "i": i})

    threads = [threading.Thread(target=work, args=(n,)) for n in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    result = verify_chain(audit_path)
    assert result.ok and result.records == 50


_CHILD = textwrap.dedent("""
    import sys
    sys.path.insert(0, {src!r})
    from datetime import datetime, timezone
    from xdr_response.audit import AuditTrail
    from xdr_response.clock import FixedClock
    from xdr_response.models import AuditEventType
    trail = AuditTrail({path!r}, clock=FixedClock(datetime(2026, 1, 15, tzinfo=timezone.utc)),
                       fsync=False, lock_timeout=60)
    for i in range({count}):
        trail.append(AuditEventType.API_CALL, incident_id="XDR-83921", actor="automation:proc",
                     payload={{"proc": int(sys.argv[1]), "i": i}})
""")


def test_separate_processes_append_to_one_chain(audit_path):
    count, procs = 20, 3
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    script = _CHILD.format(src=str(REPO_ROOT / "src"), path=str(audit_path), count=count)
    children = [subprocess.Popen([sys.executable, "-c", script, str(n)], cwd=str(REPO_ROOT),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for n in range(procs)]
    for child in children:
        _, err = child.communicate(timeout=120)
        assert child.returncode == 0, err.decode(errors="replace")
    result = verify_chain(audit_path)
    assert result.ok, result.reason
    assert result.records == count * procs
