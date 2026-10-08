"""Notification service: a lifecycle observer that renders drafts and hands them to sinks (14.1.8).

The service is bookkeeping only. It never changes incident state, never sees tokens, never calls an
adapter and never raises: a render or sink failure becomes a ``FAILED`` :class:`DeliveryRecord`.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType

from xdr_response.atomics.notifications.models import (
    DeliveryRecord,
    DeliveryStatus,
    LifecycleEvent,
    LifecycleEventKind,
    NotificationDraft,
    NotificationKind,
)
from xdr_response.atomics.notifications.render import (
    _notification_id,
    render_analyst_summary,
    render_incident_note,
    render_soc_notification,
)
from xdr_response.atomics.notifications.sinks import NotificationSink
from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.logs.setup import get_logger

__all__ = ["DEFAULT_ROUTING", "NotificationService"]

_log = get_logger("atomics.notifications")
_RENDER_SINK = "render"

_K = NotificationKind
_E = LifecycleEventKind
DEFAULT_ROUTING: Mapping[LifecycleEventKind, tuple[NotificationKind, ...]] = MappingProxyType({
    _E.DETECTION_COMPLETED: (_K.INCIDENT_NOTE,),
    _E.PACKAGE_PROPOSED: (_K.INCIDENT_NOTE, _K.SOC_NOTIFICATION, _K.ANALYST_SUMMARY),
    _E.DECISION_RECORDED: (_K.INCIDENT_NOTE,),
    _E.CONTAINMENT_COMPLETED: (_K.INCIDENT_NOTE, _K.SOC_NOTIFICATION),
    _E.RELEASE_PROPOSED: (_K.SOC_NOTIFICATION,),
    _E.RESTORATION_COMPLETED: (_K.INCIDENT_NOTE, _K.SOC_NOTIFICATION),
    _E.INCIDENT_CLOSED: (_K.INCIDENT_NOTE,),
})

_RENDERERS: Mapping[NotificationKind, Callable[[LifecycleEvent], NotificationDraft]] = MappingProxyType({
    _K.INCIDENT_NOTE: render_incident_note,
    _K.SOC_NOTIFICATION: render_soc_notification,
    _K.ANALYST_SUMMARY: render_analyst_summary,
})


def _freeze_routing(
    routing: Mapping[LifecycleEventKind, Sequence[NotificationKind]],
) -> Mapping[LifecycleEventKind, tuple[NotificationKind, ...]]:
    """Validated, read-only copy of a routing table (unknown kinds raise ValueError)."""
    if not isinstance(routing, Mapping):
        raise TypeError("routing must be a mapping of LifecycleEventKind to NotificationKind tuples")
    frozen: dict[LifecycleEventKind, tuple[NotificationKind, ...]] = {}
    for event_kind, kinds in routing.items():
        if isinstance(kinds, (str, bytes)) or not isinstance(kinds, Sequence):
            raise TypeError(f"routing for {event_kind!r} must be a sequence of NotificationKind")
        unique = dict.fromkeys(NotificationKind(k) for k in kinds)
        frozen[LifecycleEventKind(event_kind)] = tuple(unique)
    return MappingProxyType(frozen)


def _check_sinks(sinks: Sequence[NotificationSink]) -> tuple[NotificationSink, ...]:
    """Sinks as a tuple; every item must satisfy :class:`NotificationSink`."""
    if isinstance(sinks, (str, bytes)) or not isinstance(sinks, Sequence):
        raise TypeError("sinks must be a sequence of NotificationSink")
    checked = tuple(sinks)
    for sink in checked:
        if not isinstance(sink, NotificationSink) or not isinstance(sink.name, str) or not sink.name:
            raise TypeError(f"{type(sink).__name__} is not a NotificationSink with a non-empty name")
    return checked


class NotificationService:
    """Lifecycle observer: renders the routed notification kinds and delivers them to every sink."""

    def __init__(self, sinks: Sequence[NotificationSink], *, clock: Clock | None = None,
                 routing: Mapping[LifecycleEventKind, tuple[NotificationKind, ...]] = DEFAULT_ROUTING) -> None:
        self._sinks = _check_sinks(sinks)
        self._clock: Clock = clock if clock is not None else DEFAULT_CLOCK
        self._routing = _freeze_routing(routing)

    @property
    def sinks(self) -> tuple[NotificationSink, ...]:
        """The configured sinks, in delivery order."""
        return self._sinks

    @property
    def routing(self) -> Mapping[LifecycleEventKind, tuple[NotificationKind, ...]]:
        """Read-only routing table."""
        return self._routing

    def on_event(self, event: LifecycleEvent) -> tuple[DeliveryRecord, ...]:
        """Render and deliver every routed kind; one record per (draft, sink). Never raises."""
        try:
            if not isinstance(event, LifecycleEvent):
                _log.warning("notification skipped: not a LifecycleEvent (%s)", type(event).__name__)
                return ()
            records: list[DeliveryRecord] = []
            for kind in self._routing.get(event.kind, ()):
                records.extend(self._notify(kind, event))
            return tuple(records)
        except Exception as exc:  # noqa: BLE001 - an observer never raises
            _log.error("notification service failed: %s", type(exc).__name__)
            return ()

    def _notify(self, kind: NotificationKind, event: LifecycleEvent) -> list[DeliveryRecord]:
        """Render one kind and deliver it; a render failure is one FAILED record."""
        try:
            draft = _RENDERERS[kind](event)
        except Exception as exc:  # noqa: BLE001 - rendering must not break the lifecycle
            _log.error("notification render failed for %s: %s", kind.value, type(exc).__name__)
            return [self._failed(_notification_id(kind, event), _RENDER_SINK, type(exc).__name__)]
        return [self._deliver(sink, draft) for sink in self._sinks]

    def _deliver(self, sink: NotificationSink, draft: NotificationDraft) -> DeliveryRecord:
        """Hand one draft to one sink; a sink that breaks its contract is recorded as FAILED."""
        try:
            record = sink.deliver(draft)
        except Exception as exc:  # noqa: BLE001 - sinks must not raise, but never trust that
            _log.error("notification sink %s raised: %s", sink.name, type(exc).__name__)
            return self._failed(draft.notification_id, sink.name, f"sink raised {type(exc).__name__}")
        if not isinstance(record, DeliveryRecord):
            return self._failed(draft.notification_id, sink.name, "sink returned no DeliveryRecord")
        return record

    def _failed(self, notification_id: str, sink: str, detail: str) -> DeliveryRecord:
        """A FAILED record stamped with the service clock."""
        return DeliveryRecord(notification_id=notification_id, sink=sink, status=DeliveryStatus.FAILED,
                              detail=detail, at=self._clock.now())
