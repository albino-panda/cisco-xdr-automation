"""Lifecycle observers (architecture 14.3.6).

The orchestrator emits a :class:`~xdr_response.atomics.notifications.models.LifecycleEvent` to every
observer after investigation and proposal, decisions, release proposals and closing. Observers are
bookkeeping only (for example the notification outbox): they never change state, never see a
token, and their exceptions are logged and swallowed by :func:`notify_observers`.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from xdr_response.logs.redaction import get_redactor
from xdr_response.logs.setup import get_logger

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.notifications.models import LifecycleEvent

__all__ = ["LifecycleObserver", "notify_observers"]

_log = get_logger("lifecycle.observers")


@runtime_checkable
class LifecycleObserver(Protocol):
    def on_event(self, event: "LifecycleEvent") -> object:
        ...


def notify_observers(observers: Sequence[LifecycleObserver], event: "LifecycleEvent") -> None:
    """Deliver ``event`` to every observer; an observer failure is logged and never propagates."""
    for observer in observers:
        try:
            observer.on_event(event)
        except Exception as exc:  # noqa: BLE001 - observers can never break the lifecycle
            reason = get_redactor().redact_text(f"{type(exc).__name__}: {exc}")[:300]
            _log.error("lifecycle observer %s failed on %s: %s", type(observer).__name__,
                       event.kind.value, reason)
