"""Execution state stores: atomic claim, completion, replay data, durability (SQLite)."""
from __future__ import annotations

import threading
from datetime import timedelta

import pytest

from tests.unit.execution.execution_harness import FIXED_NOW, make_result
from xdr_response.execution import (
    ExecutionPhase,
    ExecutionStateStore,
    InMemoryExecutionStateStore,
    SqliteExecutionStateStore,
)

KEY = "XDR-83921:isolate_endpoint:TH-LT-1"


@pytest.fixture(params=["memory", "sqlite-memory", "sqlite-file"])
def store(request, tmp_path):
    if request.param == "memory":
        yield InMemoryExecutionStateStore()
        return
    path = ":memory:" if request.param == "sqlite-memory" else tmp_path / "state" / "exec.db"
    s = SqliteExecutionStateStore(path)
    yield s
    s.close()


def _begin(store, package_id="pkg-1", key=KEY, incident_id="XDR-83921"):
    return store.begin(package_id=package_id, idempotency_key=key, incident_id=incident_id,
                       token_id="tok-1", at=FIXED_NOW)


def test_implements_protocol(store):
    assert isinstance(store, ExecutionStateStore)


def test_first_begin_claims_second_returns_existing(store):
    assert _begin(store) is None
    existing = _begin(store)
    assert existing is not None
    assert existing.phase is ExecutionPhase.IN_PROGRESS
    assert existing.token_id == "tok-1"
    assert existing.result is None


def test_same_key_in_another_package_is_a_separate_claim(store):
    assert _begin(store, package_id="pkg-1") is None
    assert _begin(store, package_id="pkg-2") is None


def test_complete_stores_result(store):
    _begin(store)
    result = make_result()
    done = store.complete(package_id="pkg-1", idempotency_key=KEY, result=result,
                          at=FIXED_NOW + timedelta(seconds=5))
    assert done.phase is ExecutionPhase.COMPLETED
    fetched = store.get("pkg-1", KEY)
    assert fetched is not None and fetched.result == result
    assert fetched.finished_at == FIXED_NOW + timedelta(seconds=5)


def test_complete_requires_claim_and_happens_once(store):
    with pytest.raises(KeyError):
        store.complete(package_id="pkg-1", idempotency_key=KEY, result=make_result(), at=FIXED_NOW)
    _begin(store)
    store.complete(package_id="pkg-1", idempotency_key=KEY, result=make_result(), at=FIXED_NOW)
    with pytest.raises(ValueError):
        store.complete(package_id="pkg-1", idempotency_key=KEY, result=make_result(), at=FIXED_NOW)


def test_list_filters(store):
    _begin(store, package_id="pkg-1")
    _begin(store, package_id="pkg-2", key="XDR-1:isolate_endpoint:TH-LT-2", incident_id="XDR-1")
    assert len(store.list()) == 2
    assert [r.package_id for r in store.list(incident_id="XDR-1")] == ["pkg-2"]
    assert [r.incident_id for r in store.list(package_id="pkg-1")] == ["XDR-83921"]


def test_get_unknown_is_none(store):
    assert store.get("nope", KEY) is None


def test_concurrent_claims_have_exactly_one_winner(store):
    barrier = threading.Barrier(8, timeout=5)
    outcomes: list[object] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        r = _begin(store)
        with lock:
            outcomes.append(r)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for r in outcomes if r is None) == 1


def test_sqlite_is_durable_across_instances(tmp_path):
    path = tmp_path / "exec.db"
    first = SqliteExecutionStateStore(path)
    _begin(first)
    first.complete(package_id="pkg-1", idempotency_key=KEY, result=make_result(), at=FIXED_NOW)
    first.close()
    second = SqliteExecutionStateStore(path)
    try:
        existing = _begin(second)
        assert existing is not None and existing.phase is ExecutionPhase.COMPLETED
        assert existing.result == make_result()
    finally:
        second.close()
