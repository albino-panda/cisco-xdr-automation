"""Notification sinks: memory, JSONL outbox and the UNVERIFIED Cisco XDR note sink."""
from __future__ import annotations

import ast
import json
from datetime import timedelta
from pathlib import Path

import pytest

from tests.unit.atomics.notifications import _builders as b
from xdr_response.atomics.notifications import (
    DeliveryStatus,
    JsonlNotificationSink,
    LifecycleEventKind,
    MemoryNotificationSink,
    NotificationDraft,
    NotificationSink,
    XdrIncidentNoteSink,
    render_incident_note,
    render_soc_notification,
)
from xdr_response.atomics.notifications import sinks as sinks_module
from xdr_response.clock import FixedClock
from xdr_response.models import canonical_json


def _draft(kind: LifecycleEventKind = LifecycleEventKind.PACKAGE_PROPOSED) -> NotificationDraft:
    return render_incident_note(b.event(kind))


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(b.NOW + timedelta(minutes=30))


def test_every_sink_satisfies_the_protocol(tmp_path: Path, clock: FixedClock) -> None:
    sinks = (MemoryNotificationSink(clock=clock), JsonlNotificationSink(tmp_path / "o.jsonl", clock=clock),
             XdrIncidentNoteSink(clock=clock))
    assert [s.name for s in sinks] == ["memory", "jsonl", "cisco_xdr_note"]
    assert all(isinstance(s, NotificationSink) for s in sinks)


# --------------------------------------------------------------------------------------- memory --
def test_memory_sink_stores_drafts(clock: FixedClock) -> None:
    sink = MemoryNotificationSink(clock=clock)
    draft = _draft()
    record = sink.deliver(draft)
    assert sink.drafts == [draft]
    assert record.status is DeliveryStatus.STORED
    assert (record.notification_id, record.sink, record.at) == (draft.notification_id, "memory", clock.now())


def test_memory_sink_never_raises_on_a_bad_argument(clock: FixedClock) -> None:
    sink = MemoryNotificationSink(clock=clock)
    record = sink.deliver({"title": "not a draft"})  # type: ignore[arg-type]
    assert record.status is DeliveryStatus.FAILED
    assert record.notification_id == "unknown"
    assert sink.drafts == []


# ---------------------------------------------------------------------------------------- jsonl --
def test_jsonl_sink_appends_one_canonical_line_per_draft(tmp_path: Path, clock: FixedClock) -> None:
    path = tmp_path / "nested" / "dir" / "outbox.jsonl"
    sink = JsonlNotificationSink(path, clock=clock)
    first = _draft()
    second = render_soc_notification(b.event(LifecycleEventKind.CONTAINMENT_COMPLETED))
    records = [sink.deliver(first), sink.deliver(second)]
    assert [r.status for r in records] == [DeliveryStatus.STORED, DeliveryStatus.STORED]
    assert records[0].at == clock.now()
    raw = path.read_bytes()
    assert raw == canonical_json(first) + b"\n" + canonical_json(second) + b"\n"
    lines = raw.decode("utf-8").splitlines()
    assert NotificationDraft.model_validate(json.loads(lines[0])) == first
    assert NotificationDraft.model_validate(json.loads(lines[1])) == second
    assert sink.path == path


def test_jsonl_sink_never_truncates_existing_content(tmp_path: Path, clock: FixedClock) -> None:
    path = tmp_path / "outbox.jsonl"
    path.write_bytes(b'{"existing":true}\n')
    JsonlNotificationSink(str(path), clock=clock).deliver(_draft())
    JsonlNotificationSink(path, clock=clock).deliver(_draft())
    lines = path.read_bytes().splitlines()
    assert lines[0] == b'{"existing":true}'
    assert len(lines) == 3


def test_jsonl_sink_reports_a_write_failure_without_raising(tmp_path: Path, clock: FixedClock) -> None:
    directory = tmp_path / "is-a-directory"
    directory.mkdir()
    record = JsonlNotificationSink(directory, clock=clock).deliver(_draft())
    assert record.status is DeliveryStatus.FAILED
    assert record.detail.startswith("outbox write failed: ")
    assert str(tmp_path) not in record.detail


def test_jsonl_sink_rejects_a_non_draft_without_writing(tmp_path: Path, clock: FixedClock) -> None:
    path = tmp_path / "outbox.jsonl"
    record = JsonlNotificationSink(path, clock=clock).deliver("not a draft")  # type: ignore[arg-type]
    assert record.status is DeliveryStatus.FAILED
    assert not path.exists()


@pytest.mark.parametrize("bad", ["", "   ", None, 42])
def test_jsonl_sink_needs_a_path(bad: object) -> None:
    with pytest.raises(ValueError):
        JsonlNotificationSink(bad)  # type: ignore[arg-type]


# ------------------------------------------------------------------------------------ cisco xdr --
@pytest.mark.parametrize("kind", tuple(LifecycleEventKind))
def test_xdr_note_sink_is_always_not_delivered_unverified(kind: LifecycleEventKind, clock: FixedClock) -> None:
    draft = _draft(kind)
    record = XdrIncidentNoteSink(clock=clock).deliver(draft)
    assert record.status is DeliveryStatus.NOT_DELIVERED_UNVERIFIED
    assert record.sink == "cisco_xdr_note"
    assert "UNVERIFIED" in record.detail and "nothing was posted" in record.detail
    assert record.notification_id == draft.notification_id
    assert record.at == clock.now()


def test_xdr_note_sink_never_raises_on_a_bad_argument() -> None:
    record = XdrIncidentNoteSink().deliver(None)  # type: ignore[arg-type]
    assert record.status is DeliveryStatus.NOT_DELIVERED_UNVERIFIED
    assert record.notification_id == "unknown"


def test_sinks_module_touches_no_adapter_or_network() -> None:
    tree = ast.parse(Path(sinks_module.__file__).read_text(encoding="utf-8"))
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any(m.startswith(("xdr_response.integrations", "httpx", "socket", "urllib", "http"))
                   for m in imported)
