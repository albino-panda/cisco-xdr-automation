"""Test support for the approval component: a recording AuditSink and a release package factory."""
from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping
from datetime import timedelta
from typing import Any

from tests.fixtures.factories import FIXED_NOW, make_recommendation
from xdr_response.errors import AuditError
from xdr_response.models import (
    GENESIS_HASH,
    ActionType,
    AuditEventType,
    AuditRecord,
    EvidenceDraft,
    ReleasePackage,
    Severity,
    canonical_json,
    evidence_snapshot_hash,
    number_evidence,
    sha256_hex,
)

__all__ = ["RecordingAudit", "make_release_package"]


class RecordingAudit:
    """In-memory AuditSink with a simple hash chain; can be told to fail for chosen event types."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self.fail_on: set[AuditEventType] = set()

    def append(self, event_type: AuditEventType, *, incident_id: str | None, actor: str,
               payload: Mapping[str, Any], workflow_id: str | None = None,
               workflow_version: str | None = None) -> AuditRecord:
        if event_type in self.fail_on:
            raise AuditError(f"simulated audit failure for {event_type.value}")
        body = {
            "seq": len(self._records), "record_id": uuid.uuid4().hex, "timestamp": FIXED_NOW,
            "event_type": event_type, "incident_id": incident_id, "workflow_id": workflow_id,
            "workflow_version": workflow_version, "actor": actor, "payload": dict(payload),
            "prev_hash": self.head_hash,
        }
        record = AuditRecord(**body, hash=sha256_hex(canonical_json(body, allow_floats=True)))
        self._records.append(record)
        return record

    def records(self, incident_id: str | None = None) -> Iterator[AuditRecord]:
        return iter([r for r in self._records if incident_id is None or r.incident_id == incident_id])

    @property
    def head_hash(self) -> str:
        return self._records[-1].hash if self._records else GENESIS_HASH

    def events(self) -> list[AuditEventType]:
        return [r.event_type for r in self._records]

    def of(self, event_type: AuditEventType) -> list[AuditRecord]:
        return [r for r in self._records if r.event_type is event_type]


def make_release_package(*actions, incident_id: str = "XDR-83921", **overrides: Any) -> ReleasePackage:
    """Release package mirroring ``make_package``; each action must carry ``params['restores']``."""
    if not actions:
        actions = (make_recommendation(ActionType.RELEASE_ENDPOINT, incident_id=incident_id,
                                       restores=f"{incident_id}:isolate_endpoint:TH-LT-1047"),)
    drafts = [EvidenceDraft(**e.model_dump(exclude={"number"})) for a in actions for e in a.evidence]
    evidence = number_evidence(drafts)
    data: dict[str, Any] = {
        "package_id": uuid.uuid4().hex, "incident_id": incident_id, "workflow_id": "malicious-powershell",
        "workflow_version": "1.0.0", "created_at": FIXED_NOW, "expires_at": FIXED_NOW + timedelta(minutes=240),
        "requested_by": "automation:restoration_planner", "severity": Severity.HIGH, "risk_score": 40,
        "confidence_score": 90, "summary": "Test release package", "evidence": evidence,
        "evidence_snapshot_hash": evidence_snapshot_hash(evidence), "actions": tuple(actions),
        "control_keys": tuple(a.params["restores"] for a in actions),
    }
    data.update(overrides)
    return ReleasePackage(**data)
