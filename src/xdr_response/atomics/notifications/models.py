"""Notification models (architecture section 14.1.8).

Notifications are read-zone bookkeeping: rendered, redacted text kept in an outbox. A draft can
never approve, execute or release anything, and nothing here touches an adapter.
"""
from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from xdr_response.models import (
    AnalystDecision,
    BlastRadius,
    ContainmentPackage,
    ContainmentReport,
    Incident,
    ReleasePackage,
    RestorationReport,
    RiskBand,
)
from xdr_response.models._base import FrozenModel, Score

__all__ = [
    "NotificationKind",
    "LifecycleEventKind",
    "WorkflowSummary",
    "LifecycleEvent",
    "NotificationDraft",
    "DeliveryStatus",
    "DeliveryRecord",
]

#: Heading under which AI text may appear (analyst summary only).
_AI_NARRATIVE_HEADING = "AI narrative (not evidence, not reviewed)"
_MAX_TITLE_CHARS = 200
_MAX_BODY_BYTES = 16 * 1024
_NOTIFICATION_ID = re.compile(r"^[0-9a-f]{32}$")


class NotificationKind(StrEnum):
    """What is rendered."""

    INCIDENT_NOTE = "incident_note"
    SOC_NOTIFICATION = "soc_notification"
    ANALYST_SUMMARY = "analyst_summary"


class LifecycleEventKind(StrEnum):
    """Lifecycle moments the orchestrator reports to observers."""

    DETECTION_COMPLETED = "detection_completed"  # investigation done, nothing proposed
    PACKAGE_PROPOSED = "package_proposed"
    DECISION_RECORDED = "decision_recorded"
    CONTAINMENT_COMPLETED = "containment_completed"
    RELEASE_PROPOSED = "release_proposed"
    RESTORATION_COMPLETED = "restoration_completed"
    INCIDENT_CLOSED = "incident_closed"


#: The audience each notification kind is written for.
_AUDIENCE: dict[NotificationKind, str] = {
    NotificationKind.INCIDENT_NOTE: "incident",
    NotificationKind.SOC_NOTIFICATION: "soc",
    NotificationKind.ANALYST_SUMMARY: "analyst",
}


class WorkflowSummary(FrozenModel):
    """Read-zone facts of one workflow run."""

    workflow_id: str
    workflow_version: str
    risk_score: Score
    confidence_score: Score
    risk_band: RiskBand
    evidence: tuple[str, ...] = ()  # "[<record_id>] <evidence summary>" of cited records
    degraded_sources: tuple[str, ...] = ()
    unrouted: tuple[str, ...] = ()  # "<action_type> <target>: <reason>"
    below_threshold: tuple[str, ...] = ()
    blast_radius: BlastRadius = BlastRadius()
    considered: tuple[str, ...] = ()  # "<subject>: <reason> [<record ids>]": examined, deliberately not proposed
    manual_steps: tuple[str, ...] = ()  # "<subject>: <what to do> [<record ids>]": no VERIFIED write exists
    handoffs: tuple[str, ...] = ()  # "<workflow> for <subjects>: <reason> [<record ids>]": suggestions only


class LifecycleEvent(FrozenModel):
    """One lifecycle moment, as seen by observers (never carries a token)."""

    kind: LifecycleEventKind
    at: AwareDatetime
    incident: Incident
    package: ContainmentPackage | ReleasePackage | None = None
    decision: AnalystDecision | None = None
    report: ContainmentReport | RestorationReport | None = None
    summary: WorkflowSummary | None = None
    notes: tuple[str, ...] = ()
    dry_run: bool = False

    @model_validator(mode="after")
    def _same_incident(self) -> "LifecycleEvent":
        """Package, decision and report must all belong to the event's incident."""
        incident_id = self.incident.incident_id
        for name, part in (("package", self.package), ("decision", self.decision), ("report", self.report)):
            if part is not None and part.incident_id != incident_id:
                raise ValueError(f"{name} belongs to incident {part.incident_id!r}, not {incident_id!r}")
        return self


class NotificationDraft(FrozenModel):
    """A rendered, redacted notification (bookkeeping only)."""

    notification_id: str  # sha256_hex(canonical_json([kind, incident_id, event, ref]))[:32]
    kind: NotificationKind
    event: LifecycleEventKind
    incident_id: str = Field(min_length=1)
    created_at: AwareDatetime
    audience: Literal["incident", "soc", "analyst"]
    title: str  # <= 200 chars; "[DRY RUN] " prefix in dry run
    body: str  # <= 16 KiB, redacted
    workflow_id: str | None = None
    workflow_version: str | None = None
    contains_ai_text: bool = False

    @field_validator("notification_id")
    @classmethod
    def _id_format(cls, value: str) -> str:
        """32 lowercase hex characters."""
        if not _NOTIFICATION_ID.match(value):
            raise ValueError("notification_id must be 32 lowercase hex characters")
        return value

    @field_validator("title")
    @classmethod
    def _title_limits(cls, value: str) -> str:
        """Non-empty, single line, at most 200 characters."""
        if not value.strip():
            raise ValueError("title must not be empty")
        if len(value) > _MAX_TITLE_CHARS:
            raise ValueError(f"title must be at most {_MAX_TITLE_CHARS} characters")
        if "\n" in value or "\r" in value:
            raise ValueError("title must be a single line")
        return value

    @field_validator("body")
    @classmethod
    def _body_limits(cls, value: str) -> str:
        """Non-empty and at most 16 KiB of UTF-8."""
        if not value.strip():
            raise ValueError("body must not be empty")
        if len(value.encode("utf-8")) > _MAX_BODY_BYTES:
            raise ValueError(f"body must be at most {_MAX_BODY_BYTES} bytes of UTF-8")
        return value

    @model_validator(mode="after")
    def _audience_and_ai(self) -> "NotificationDraft":
        """Audience matches the kind; AI text only in analyst summaries, always flagged."""
        if _AUDIENCE[self.kind] != self.audience:
            raise ValueError(f"{self.kind.value} is written for audience {_AUDIENCE[self.kind]!r}")
        has_heading = _AI_NARRATIVE_HEADING in self.body.splitlines()
        if has_heading != self.contains_ai_text:
            raise ValueError("contains_ai_text must be set exactly when the AI narrative heading is present")
        if self.contains_ai_text and self.kind is not NotificationKind.ANALYST_SUMMARY:
            raise ValueError("AI text may appear only in the analyst summary")
        return self


class DeliveryStatus(StrEnum):
    """Outcome of handing a draft to a sink."""

    STORED = "STORED"
    DELIVERED = "DELIVERED"
    NOT_DELIVERED_UNVERIFIED = "NOT_DELIVERED_UNVERIFIED"
    FAILED = "FAILED"


class DeliveryRecord(FrozenModel):
    """What a sink did with one draft."""

    notification_id: str
    sink: str
    status: DeliveryStatus
    detail: str = ""
    at: AwareDatetime
