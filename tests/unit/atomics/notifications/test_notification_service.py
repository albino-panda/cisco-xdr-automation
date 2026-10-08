"""NotificationService: routing, delivery and failure isolation (never raises)."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from tests.unit.atomics.notifications import _builders as b
from xdr_response.atomics.notifications import (
    DEFAULT_ROUTING,
    DeliveryRecord,
    DeliveryStatus,
    JsonlNotificationSink,
    LifecycleEvent,
    LifecycleEventKind,
    MemoryNotificationSink,
    NotificationDraft,
    NotificationKind,
    NotificationService,
    XdrIncidentNoteSink,
)
from xdr_response.atomics.notifications import service as service_module
from xdr_response.clock import FixedClock

E, K = LifecycleEventKind, NotificationKind


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(b.NOW + timedelta(hours=1))


class RaisingSink:
    name = "raising"

    def deliver(self, draft: NotificationDraft) -> DeliveryRecord:
        raise RuntimeError("sink broke its contract")


class JunkSink:
    name = "junk"

    def deliver(self, draft: NotificationDraft) -> DeliveryRecord:
        return "ok"  # type: ignore[return-value]


def test_default_routing_matches_the_contract() -> None:
    assert dict(DEFAULT_ROUTING) == {
        E.PACKAGE_PROPOSED: (K.INCIDENT_NOTE, K.SOC_NOTIFICATION, K.ANALYST_SUMMARY),
        E.DECISION_RECORDED: (K.INCIDENT_NOTE,),
        E.CONTAINMENT_COMPLETED: (K.INCIDENT_NOTE, K.SOC_NOTIFICATION),
        E.RESTORATION_COMPLETED: (K.INCIDENT_NOTE, K.SOC_NOTIFICATION),
        E.RELEASE_PROPOSED: (K.SOC_NOTIFICATION,),
        E.DETECTION_COMPLETED: (K.INCIDENT_NOTE,),
        E.INCIDENT_CLOSED: (K.INCIDENT_NOTE,),
    }
    with pytest.raises(TypeError):
        DEFAULT_ROUTING[E.INCIDENT_CLOSED] = ()  # type: ignore[index]


@pytest.mark.parametrize("kind", tuple(LifecycleEventKind))
def test_on_event_renders_routed_kinds_to_every_sink(kind: LifecycleEventKind, clock: FixedClock) -> None:
    memory = MemoryNotificationSink(clock=clock)
    xdr = XdrIncidentNoteSink(clock=clock)
    records = NotificationService([memory, xdr], clock=clock).on_event(b.event(kind))
    expected = DEFAULT_ROUTING[kind]
    assert [d.kind for d in memory.drafts] == list(expected)
    assert len(records) == 2 * len(expected)
    assert [r.sink for r in records] == ["memory", "cisco_xdr_note"] * len(expected)
    assert {r.status for r in records} == {DeliveryStatus.STORED, DeliveryStatus.NOT_DELIVERED_UNVERIFIED}
    assert [r.notification_id for r in records[::2]] == [d.notification_id for d in memory.drafts]


def test_on_event_is_deterministic(clock: FixedClock) -> None:
    event = b.event(E.PACKAGE_PROPOSED)
    first = NotificationService([MemoryNotificationSink(clock=clock)], clock=clock).on_event(event)
    second = NotificationService([MemoryNotificationSink(clock=clock)], clock=clock).on_event(event)
    assert first == second


def test_jsonl_outbox_end_to_end(tmp_path: Path, clock: FixedClock) -> None:
    path = tmp_path / "var" / "notifications" / "outbox.jsonl"
    service = NotificationService([JsonlNotificationSink(path, clock=clock)], clock=clock)
    for kind in (E.PACKAGE_PROPOSED, E.DECISION_RECORDED, E.CONTAINMENT_COMPLETED):
        service.on_event(b.event(kind))
    assert len(path.read_text(encoding="utf-8").splitlines()) == 3 + 1 + 2


def test_a_raising_sink_does_not_stop_the_others(clock: FixedClock) -> None:
    memory = MemoryNotificationSink(clock=clock)
    service = NotificationService([RaisingSink(), memory, JunkSink()], clock=clock)
    records = service.on_event(b.event(E.CONTAINMENT_COMPLETED))
    assert len(memory.drafts) == 2
    by_sink = {r.sink: r for r in records}
    assert by_sink["raising"].status is DeliveryStatus.FAILED
    assert by_sink["raising"].detail == "sink raised RuntimeError"
    assert by_sink["raising"].at == clock.now()
    assert by_sink["junk"].status is DeliveryStatus.FAILED
    assert by_sink["memory"].status is DeliveryStatus.STORED


def test_a_render_failure_is_one_failed_record(monkeypatch: pytest.MonkeyPatch, clock: FixedClock) -> None:
    def broken(event: LifecycleEvent) -> NotificationDraft:
        raise ValueError("render broke")

    renderers = dict(service_module._RENDERERS)
    renderers[K.SOC_NOTIFICATION] = broken
    monkeypatch.setattr(service_module, "_RENDERERS", renderers)
    memory = MemoryNotificationSink(clock=clock)
    records = NotificationService([memory], clock=clock).on_event(b.event(E.PACKAGE_PROPOSED))
    assert [d.kind for d in memory.drafts] == [K.INCIDENT_NOTE, K.ANALYST_SUMMARY]
    failed = [r for r in records if r.status is DeliveryStatus.FAILED]
    assert len(failed) == 1
    assert (failed[0].sink, failed[0].detail, failed[0].at) == ("render", "ValueError", clock.now())
    assert len(failed[0].notification_id) == 32


def test_on_event_never_raises(clock: FixedClock) -> None:
    service = NotificationService([MemoryNotificationSink(clock=clock)], clock=clock)
    assert service.on_event("not an event") == ()  # type: ignore[arg-type]
    assert service.on_event(None) == ()  # type: ignore[arg-type]


def test_custom_routing_is_validated_and_frozen(clock: FixedClock) -> None:
    memory = MemoryNotificationSink(clock=clock)
    routing = {"incident_closed": ["soc_notification", "soc_notification"]}
    service = NotificationService([memory], clock=clock, routing=routing)  # type: ignore[arg-type]
    assert dict(service.routing) == {E.INCIDENT_CLOSED: (K.SOC_NOTIFICATION,)}
    assert service.on_event(b.event(E.PACKAGE_PROPOSED)) == ()
    service.on_event(b.event(E.INCIDENT_CLOSED))
    assert [d.kind for d in memory.drafts] == [K.SOC_NOTIFICATION]
    routing["incident_closed"].append("analyst_summary")
    assert service.routing[E.INCIDENT_CLOSED] == (K.SOC_NOTIFICATION,)


@pytest.mark.parametrize("routing", [
    {"no_such_event": ("incident_note",)}, {"incident_closed": ("no_such_kind",)},
    {"incident_closed": "incident_note"}, ["incident_closed"]])
def test_invalid_routing_is_rejected(routing: object) -> None:
    with pytest.raises((ValueError, TypeError)):
        NotificationService([MemoryNotificationSink()], routing=routing)  # type: ignore[arg-type]


@pytest.mark.parametrize("sinks", [[object()], "memory", [MemoryNotificationSink(), 42]])
def test_invalid_sinks_are_rejected(sinks: object) -> None:
    with pytest.raises(TypeError):
        NotificationService(sinks)  # type: ignore[arg-type]


def test_no_sinks_means_no_records(clock: FixedClock) -> None:
    assert NotificationService([], clock=clock).on_event(b.event(E.PACKAGE_PROPOSED)) == ()


def test_dry_run_events_produce_dry_run_titles(clock: FixedClock) -> None:
    memory = MemoryNotificationSink(clock=clock)
    NotificationService([memory], clock=clock).on_event(b.event(E.PACKAGE_PROPOSED, dry_run=True))
    assert memory.drafts and all(d.title.startswith("[DRY RUN] ") for d in memory.drafts)


def test_service_exposes_sinks_in_order(clock: FixedClock) -> None:
    sinks = [MemoryNotificationSink(clock=clock), XdrIncidentNoteSink(clock=clock)]
    assert NotificationService(sinks, clock=clock).sinks == tuple(sinks)
