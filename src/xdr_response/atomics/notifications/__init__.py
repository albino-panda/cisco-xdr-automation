"""Notifications (architecture section 14.1.8): incident notes, SOC notifications, analyst summaries.

Read-zone bookkeeping only: drafts are rendered deterministically, redacted, and stored in an
outbox. Nothing here approves, executes, releases or posts to a vendor.
"""
from __future__ import annotations

from xdr_response.atomics.notifications.models import (
    DeliveryRecord,
    DeliveryStatus,
    LifecycleEvent,
    LifecycleEventKind,
    NotificationDraft,
    NotificationKind,
    WorkflowSummary,
)
from xdr_response.atomics.notifications.render import (
    render_analyst_summary,
    render_incident_note,
    render_soc_notification,
)
from xdr_response.atomics.notifications.service import DEFAULT_ROUTING, NotificationService
from xdr_response.atomics.notifications.sinks import (
    JsonlNotificationSink,
    MemoryNotificationSink,
    NotificationSink,
    XdrIncidentNoteSink,
)

__all__ = [
    "NotificationKind",
    "LifecycleEventKind",
    "WorkflowSummary",
    "LifecycleEvent",
    "NotificationDraft",
    "DeliveryStatus",
    "DeliveryRecord",
    "render_incident_note",
    "render_soc_notification",
    "render_analyst_summary",
    "NotificationSink",
    "MemoryNotificationSink",
    "JsonlNotificationSink",
    "XdrIncidentNoteSink",
    "DEFAULT_ROUTING",
    "NotificationService",
]
