"""AuditTrail / MemoryAuditTrail: chaining, persistence, payload normalization, API surface."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from enum import Enum

import pytest

from tests.fixtures.factories import FIXED_NOW
from xdr_response.audit import AuditTrail, MemoryAuditTrail, compute_record_hash, verify_chain
from xdr_response.audit.hashing import hash_of_record, parse_record_line
from xdr_response.clock import FixedClock
from xdr_response.errors import AuditError, AuditIntegrityError
from xdr_response.interfaces import AuditSink
from xdr_response.models import GENESIS_HASH, AuditEventType, canonical_json, sha256_hex


class _Color(Enum):
    RED = "red"


# ------------------------------------------------------------- chaining ---
@pytest.mark.parametrize("kind", ["file", "memory"])
def test_records_are_chained_from_genesis(kind, make_trail, memory_trail, fill):
    trail = make_trail() if kind == "file" else memory_trail
    fill(trail, 3)
    records = list(trail.records())
    assert [r.seq for r in records] == [0, 1, 2]
    assert records[0].prev_hash == GENESIS_HASH
    assert records[1].prev_hash == records[0].hash
    assert records[2].prev_hash == records[1].hash
    assert trail.head_hash == records[-1].hash
    assert len(trail) == 3
    assert trail.verify().ok


@pytest.mark.parametrize("kind", ["file", "memory"])
def test_hash_is_sha256_of_canonical_record_without_hash(kind, make_trail, memory_trail):
    trail = make_trail() if kind == "file" else memory_trail
    record = trail.append(AuditEventType.INCIDENT_RECEIVED, incident_id="XDR-83921",
                          actor="automation:test", payload={"trigger": {"rule": "r1"}})
    body = record.model_dump(mode="python", exclude={"hash"})
    assert record.hash == sha256_hex(canonical_json(body, allow_floats=True))
    assert compute_record_hash(record.model_dump(mode="python")) == record.hash  # "hash" key ignored
    assert hash_of_record(record) == record.hash


@pytest.mark.parametrize("kind", ["file", "memory"])
def test_empty_trail(kind, make_trail, memory_trail):
    trail = make_trail() if kind == "file" else memory_trail
    assert trail.head_hash == GENESIS_HASH
    assert list(trail.records()) == []
    assert trail.anchor() is None
    assert len(trail) == 0
    assert trail.verify().ok if kind == "memory" else True


def test_record_fields_are_populated(make_trail):
    trail = make_trail()
    record = trail.append(AuditEventType.ACTION_STARTED, incident_id="XDR-83921",
                          actor="analyst.one@example.com", payload={"target": "TH-LT-1047"},
                          workflow_id="powershell", workflow_version="1.0.0")
    assert record.record_id == "aud-000001"
    assert record.timestamp == FIXED_NOW
    assert record.event_type is AuditEventType.ACTION_STARTED
    assert record.incident_id == "XDR-83921"
    assert (record.workflow_id, record.workflow_version) == ("powershell", "1.0.0")
    assert record.actor == "analyst.one@example.com"
    assert record.payload == {"target": "TH-LT-1047"}


def test_records_filter_by_incident(make_trail, fill):
    trail = make_trail()
    fill(trail, 2, incident_id="XDR-1")
    fill(trail, 3, incident_id="XDR-2")
    trail.append(AuditEventType.HEALTH_CHECK, incident_id=None, actor="automation:test", payload={})
    assert len(list(trail.records("XDR-1"))) == 2
    assert len(list(trail.records("XDR-2"))) == 3
    assert len(list(trail.records())) == 6


def test_anchor_points_at_head(make_trail, fill):
    trail = make_trail()
    fill(trail, 4)
    anchor = trail.anchor()
    assert anchor is not None
    assert anchor.seq == 3 and anchor.hash == trail.head_hash


# ------------------------------------------------------------ persistence ---
def test_file_is_one_canonical_json_object_per_lf_line(make_trail, fill, audit_path):
    trail = make_trail()
    fill(trail, 3)
    raw = audit_path.read_bytes()
    assert b"\r\n" not in raw
    lines = raw.split(b"\n")
    assert lines[-1] == b"" and len(lines) == 4
    for line in lines[:-1]:
        data = json.loads(line)
        assert set(data) == {"seq", "record_id", "timestamp", "event_type", "incident_id",
                             "workflow_id", "workflow_version", "actor", "payload", "prev_hash", "hash"}
        assert parse_record_line(line + b"\n").hash == data["hash"]


def test_reopen_recovers_seq_and_head(make_trail, fill, ids):
    first = make_trail()
    fill(first, 3)
    head = first.head_hash
    second = make_trail(id_factory=ids("b"))
    assert second.head_hash == head
    record = second.append(AuditEventType.ERROR, incident_id="XDR-83921", actor="automation:test",
                           payload={"code": "API_ERROR"})
    assert record.seq == 3 and record.prev_hash == head
    assert verify_chain(second.path).ok


def test_creates_parent_directories(tmp_path, clock, redactor):
    path = tmp_path / "a" / "b" / "c" / "audit.jsonl"
    trail = AuditTrail(path, clock=clock, redactor=redactor, fsync=False)
    trail.append(AuditEventType.HEALTH_CHECK, incident_id=None, actor="automation:test", payload={})
    assert path.is_file()


def test_fsync_enabled_append_works(make_trail):
    trail = make_trail(fsync=True)
    trail.append(AuditEventType.HEALTH_CHECK, incident_id=None, actor="automation:test", payload={})
    assert trail.verify().ok


def test_opening_a_tampered_file_is_refused(make_trail, fill, audit_path):
    fill(make_trail(), 3)
    lines = audit_path.read_bytes().split(b"\n")
    lines[1] = lines[1].replace(b'"index":1', b'"index":7')
    audit_path.write_bytes(b"\n".join(lines))
    with pytest.raises(AuditIntegrityError, match="seq 1"):
        make_trail()


def test_write_failure_raises_audit_error(make_trail, audit_path, monkeypatch):
    trail = make_trail()
    original_open = type(audit_path).open

    def failing_open(self, mode="r", *args, **kwargs):
        if self == audit_path and "a" in mode:
            raise PermissionError("denied")
        return original_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(type(audit_path), "open", failing_open)
    with pytest.raises(AuditError, match="audit write failed"):
        trail.append(AuditEventType.HEALTH_CHECK, incident_id=None, actor="automation:test", payload={})
    monkeypatch.undo()
    assert len(trail) == 0  # state not advanced
    trail.append(AuditEventType.HEALTH_CHECK, incident_id=None, actor="automation:test", payload={})
    assert trail.verify().ok


# ---------------------------------------------------------------- payloads ---
@pytest.mark.parametrize("kind", ["file", "memory"])
def test_payload_is_normalized_to_json_and_round_trips(kind, make_trail, memory_trail):
    trail = make_trail() if kind == "file" else memory_trail
    payload = {
        "float": 1.25, "nan": float("nan"), "inf": float("inf"),
        "aware": datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc),
        "naive": datetime(2026, 1, 15, 12, 0),
        "tuple": (1, 2), "set": {"b", "a"}, "enum": _Color.RED, 7: "int key",
        "nested": {"list": [{"x": None, "y": True}]},
    }
    record = trail.append(AuditEventType.ENRICHMENT_RESULT, incident_id="XDR-83921",
                          actor="automation:test", payload=payload)
    assert record.payload == {
        "float": 1.25, "nan": "nan", "inf": "inf", "aware": "2026-01-15T12:00:00.000000Z",
        "naive": "2026-01-15T12:00:00", "tuple": [1, 2], "set": ["a", "b"], "enum": "red",
        "7": "int key", "nested": {"list": [{"x": None, "y": True}]},
    }
    stored = list(trail.records())[0]
    assert stored == record
    assert trail.verify().ok


def test_unknown_objects_are_stored_as_redacted_repr(memory_trail):
    class Opaque:
        def __repr__(self) -> str:
            return "Opaque(Bearer abcdefghijklmnop)"

    record = memory_trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test",
                                 payload={"obj": Opaque()})
    assert "abcdefghijklmnop" not in record.payload["obj"]


@pytest.mark.parametrize("kwargs, message", [
    ({"actor": ""}, "actor"),
    ({"actor": "   "}, "actor"),
    ({"payload": ["not", "a", "mapping"]}, "mapping"),
    ({"incident_id": 42}, "incident_id"),
    ({"workflow_id": 1}, "workflow_id"),
])
def test_invalid_input_raises_audit_error(memory_trail, kwargs, message):
    args = {"incident_id": "XDR-83921", "actor": "automation:test", "payload": {}}
    args.update(kwargs)
    with pytest.raises(AuditError, match=message):
        memory_trail.append(AuditEventType.ERROR, **args)
    assert len(memory_trail) == 0


def test_unknown_event_type_raises_audit_error(make_trail, memory_trail):
    for trail in (make_trail(), memory_trail):
        with pytest.raises(AuditError, match="unknown audit event type"):
            trail.append("NOT_AN_EVENT", incident_id=None, actor="automation:test", payload={})


def test_naive_clock_raises_audit_error(redactor):
    class NaiveClock:
        def now(self) -> datetime:
            return datetime(2026, 1, 15, 12, 0)

    trail = MemoryAuditTrail(clock=NaiveClock(), redactor=redactor)
    with pytest.raises(AuditError, match="timezone-aware"):
        trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test", payload={})


def test_timestamps_come_from_injected_clock(redactor):
    clock = FixedClock(FIXED_NOW)
    trail = MemoryAuditTrail(clock=clock, redactor=redactor)
    first = trail.append(AuditEventType.ERROR, incident_id=None, actor="a", payload={})
    clock.advance(timedelta(minutes=5))
    second = trail.append(AuditEventType.ERROR, incident_id=None, actor="a", payload={})
    assert second.timestamp - first.timestamp == timedelta(minutes=5)


def test_default_record_ids_are_unique(redactor):
    trail = MemoryAuditTrail(redactor=redactor)
    ids = {trail.append(AuditEventType.ERROR, incident_id=None, actor="a", payload={}).record_id
           for _ in range(20)}
    assert len(ids) == 20


# ------------------------------------------------------------ API surface ---
@pytest.mark.parametrize("cls", [AuditTrail, MemoryAuditTrail])
def test_no_update_delete_or_truncate_api(cls):
    forbidden = {"update", "delete", "remove", "truncate", "clear", "pop", "edit", "replace",
                 "rewrite", "__setitem__", "__delitem__", "insert", "extend"}
    assert not forbidden & set(dir(cls))


def test_both_trails_implement_audit_sink(make_trail, memory_trail):
    assert isinstance(make_trail(), AuditSink)
    assert isinstance(memory_trail, AuditSink)


def test_memory_records_are_immutable_snapshots(memory_trail, fill):
    fill(memory_trail, 2)
    snapshot = memory_trail.snapshot()
    with pytest.raises(Exception):
        snapshot[0].payload = {}  # type: ignore[misc]  # frozen model
    fill(memory_trail, 1)
    assert len(snapshot) == 2 and len(memory_trail) == 3


def test_memory_fail_when_simulates_audit_outage(memory_trail):
    memory_trail.fail_when = lambda event: event is AuditEventType.ACTION_STARTED
    with pytest.raises(AuditError, match="simulated audit failure"):
        memory_trail.append(AuditEventType.ACTION_STARTED, incident_id="XDR-83921",
                            actor="automation:test", payload={})
    memory_trail.append(AuditEventType.ERROR, incident_id="XDR-83921", actor="automation:test",
                        payload={})
    assert [r.event_type for r in memory_trail.records()] == [AuditEventType.ERROR]
    assert memory_trail.verify().ok


def test_sets_are_stored_sorted(redactor):
    from xdr_response.audit import prepare_payload

    values = frozenset(f"role-{i:02d}" for i in range(30))
    assert prepare_payload({"roles": values}, redactor) == {"roles": sorted(values)}


def test_file_and_memory_trails_hash_identically(tmp_path, redactor, ids, fill):
    file_trail = AuditTrail(tmp_path / "a.jsonl", clock=FixedClock(FIXED_NOW), redactor=redactor,
                            fsync=False, id_factory=ids())
    memory = MemoryAuditTrail(clock=FixedClock(FIXED_NOW), redactor=redactor, id_factory=ids())
    fill(file_trail, 3)
    fill(memory, 3)
    assert file_trail.head_hash == memory.head_hash
    assert list(file_trail.records()) == list(memory.records())
