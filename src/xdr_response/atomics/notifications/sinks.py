"""Notification sinks (architecture section 14.1.8).

A sink stores or (later) delivers a rendered draft and reports what it did. ``deliver`` never
raises. No sink touches an adapter: the Cisco XDR worklog note path is UNVERIFIED
(``docs/integrations.md``), so :class:`XdrIncidentNoteSink` always answers
``NOT_DELIVERED_UNVERIFIED`` and nothing is posted to XDR. :class:`JsonlNotificationSink` is the one
read-zone module allowed to open a file: its own append-only outbox.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Protocol, runtime_checkable

from xdr_response.atomics.notifications.models import DeliveryRecord, DeliveryStatus, NotificationDraft
from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.models import canonical_json

__all__ = ["NotificationSink", "MemoryNotificationSink", "JsonlNotificationSink", "XdrIncidentNoteSink"]

_UNKNOWN_ID = "unknown"
_XDR_UNVERIFIED_DETAIL = (
    "Cisco XDR incident worklog note path is UNVERIFIED (docs/integrations.md); nothing was posted"
)


@runtime_checkable
class NotificationSink(Protocol):
    """Anything that accepts drafts."""

    name: str

    def deliver(self, draft: NotificationDraft) -> DeliveryRecord:  # never raises
        ...


def _record(draft: object, sink: str, status: DeliveryStatus, detail: str, clock: Clock) -> DeliveryRecord:
    """A delivery record; tolerates a non-draft argument (records it as ``unknown``)."""
    notification_id = draft.notification_id if isinstance(draft, NotificationDraft) else _UNKNOWN_ID
    return DeliveryRecord(notification_id=notification_id, sink=sink, status=status, detail=detail,
                          at=clock.now())


def _not_a_draft(draft: object) -> str:
    """Failure detail for an argument that is not a :class:`NotificationDraft`."""
    return f"expected NotificationDraft, got {type(draft).__name__}"


class MemoryNotificationSink:
    """In-process sink for tests and simulations; keeps every draft in ``drafts``."""

    name = "memory"

    def __init__(self, *, clock: Clock | None = None) -> None:
        self._clock: Clock = clock if clock is not None else DEFAULT_CLOCK
        self.drafts: list[NotificationDraft] = []
        self._lock = threading.Lock()

    def deliver(self, draft: NotificationDraft) -> DeliveryRecord:
        """Append the draft; ``STORED``."""
        try:
            if not isinstance(draft, NotificationDraft):
                return _record(draft, self.name, DeliveryStatus.FAILED, _not_a_draft(draft), self._clock)
            with self._lock:
                self.drafts.append(draft)
            return _record(draft, self.name, DeliveryStatus.STORED, "", self._clock)
        except Exception as exc:  # noqa: BLE001 - a sink never raises
            return _record(draft, self.name, DeliveryStatus.FAILED, type(exc).__name__, DEFAULT_CLOCK)


class JsonlNotificationSink:
    """Append-only JSONL outbox: one canonical JSON line per draft."""

    name = "jsonl"

    def __init__(self, path: Path | str, *, clock: Clock | None = None) -> None:
        if not isinstance(path, (str, Path)) or not str(path).strip():
            raise ValueError("path must be a non-empty str or Path")
        self._path = Path(path)
        self._clock: Clock = clock if clock is not None else DEFAULT_CLOCK
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        """The outbox file."""
        return self._path

    def deliver(self, draft: NotificationDraft) -> DeliveryRecord:
        """Append one line; ``STORED``, or ``FAILED`` when the file cannot be written."""
        if not isinstance(draft, NotificationDraft):
            return _record(draft, self.name, DeliveryStatus.FAILED, _not_a_draft(draft), self._clock)
        try:
            self._append(canonical_json(draft) + b"\n")
        except Exception as exc:  # noqa: BLE001 - a sink never raises
            detail = f"outbox write failed: {type(exc).__name__}"
            return _record(draft, self.name, DeliveryStatus.FAILED, detail, self._clock)
        return _record(draft, self.name, DeliveryStatus.STORED, "", self._clock)

    def _append(self, line: bytes) -> None:
        """Append ``line`` to the outbox (creates the parent directory), serialized by a lock."""
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "ab") as handle:
                handle.write(line)
                handle.flush()


class XdrIncidentNoteSink:
    """Placeholder for the Cisco XDR worklog note: always ``NOT_DELIVERED_UNVERIFIED``.

    It holds no adapter and makes no call; it exists so routing to XDR is explicit and auditable
    once the endpoint is VERIFIED (a later contract change).
    """

    name = "cisco_xdr_note"

    def __init__(self, *, clock: Clock | None = None) -> None:
        self._clock: Clock = clock if clock is not None else DEFAULT_CLOCK

    def deliver(self, draft: NotificationDraft) -> DeliveryRecord:
        """Never delivers; records why."""
        try:
            return _record(draft, self.name, DeliveryStatus.NOT_DELIVERED_UNVERIFIED,
                           _XDR_UNVERIFIED_DETAIL, self._clock)
        except Exception as exc:  # noqa: BLE001 - a sink never raises
            return _record(draft, self.name, DeliveryStatus.FAILED, type(exc).__name__, DEFAULT_CLOCK)
