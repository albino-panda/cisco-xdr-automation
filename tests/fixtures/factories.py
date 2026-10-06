"""Model factories (architecture section 13.20). Fake data only."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from xdr_response.models import (
    ActionType,
    ApprovalLevel,
    Asset,
    ContainmentPackage,
    Evidence,
    EvidenceDraft,
    Incident,
    Observable,
    ObservableType,
    RecommendedAction,
    Severity,
    TargetKind,
    evidence_snapshot_hash,
    get_action_spec,
    make_idempotency_key,
    normalize_target,
    number_evidence,
)

__all__ = [
    "FIXED_NOW",
    "FAKE_SHA256",
    "make_incident",
    "make_evidence",
    "make_recommendation",
    "make_package",
]

FIXED_NOW: datetime = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
FAKE_SHA256 = "a" * 64


def make_incident(incident_id: str = "XDR-83921", **overrides: Any) -> Incident:
    data: dict[str, Any] = {
        "incident_id": incident_id,
        "title": "Malicious PowerShell on TH-LT-1047",
        "severity": Severity.HIGH,
        "created_at": FIXED_NOW,
        "workflow_id": "powershell",
        "workflow_version": "1.0.0",
        "observables": (
            Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047", source="cisco_xdr"),
            Observable(type=ObservableType.DOMAIN, value="bad.example.test", source="cisco_xdr"),
            Observable(type=ObservableType.IP, value="203.0.113.10", source="cisco_xdr"),
            Observable(type=ObservableType.SHA256, value=FAKE_SHA256, source="secure_endpoint"),
        ),
        "assets": (Asset(name="TH-LT-1047", kind=TargetKind.ENDPOINT, groups=("Workstations",)),),
        "users": ("j.doe@example.com",),
        "trigger": {"source": "cisco_xdr", "rule": "test-trigger"},
    }
    data.update(overrides)
    return Incident(**data)


def make_evidence(n: int = 2, source: str = "secure_endpoint") -> tuple[Evidence, ...]:
    drafts = [
        EvidenceDraft(
            source=source,
            summary=f"Test evidence {i}: encoded PowerShell launched by WINWORD.EXE on TH-LT-1047",
            observed_at=FIXED_NOW - timedelta(minutes=30 - i),
            reference=f"evt-{i:04d}",
            data={"index": i},
        )
        for i in range(1, n + 1)
    ]
    return number_evidence(drafts)


def make_recommendation(
    action_type: ActionType = ActionType.ISOLATE_ENDPOINT,
    target: str = "TH-LT-1047",
    integration: str = "secure_endpoint",
    incident_id: str = "XDR-83921",
    approval_level: ApprovalLevel = ApprovalLevel.STANDARD,
    **params: Any,
) -> RecommendedAction:
    spec = get_action_spec(action_type)
    kind = spec.target_kind
    normalized = normalize_target(kind, target)
    if spec.always_elevated:
        approval_level = ApprovalLevel.ELEVATED
    return RecommendedAction(
        incident_id=incident_id,
        idempotency_key=make_idempotency_key(incident_id, spec.action_type, normalized),
        action_type=spec.action_type,
        target=normalized,
        target_kind=kind,
        params={"integration": integration, **params},
        evidence=make_evidence(),
        risk_score=85,
        confidence_score=80,
        approval_level=approval_level,
        rationale=f"Test rationale for {spec.action_type.value} on {normalized}",
    )


def make_package(*actions: RecommendedAction, incident_id: str = "XDR-83921", **overrides: Any) -> ContainmentPackage:
    if not actions:
        actions = (make_recommendation(incident_id=incident_id),)
    drafts = [EvidenceDraft(**e.model_dump(exclude={"number"})) for a in actions for e in a.evidence]
    evidence = overrides.pop("evidence", None) or number_evidence(drafts)
    data: dict[str, Any] = {
        "package_id": uuid.uuid4().hex,
        "incident_id": incident_id,
        "workflow_id": "powershell",
        "workflow_version": "1.0.0",
        "created_at": FIXED_NOW,
        "expires_at": FIXED_NOW + timedelta(minutes=240),
        "requested_by": "automation:package_builder",
        "severity": Severity.HIGH,
        "risk_score": max(a.risk_score for a in actions),
        "confidence_score": min(a.confidence_score for a in actions),
        "summary": "Test containment package",
        "endpoints": tuple(sorted({a.target for a in actions if a.target_kind is TargetKind.ENDPOINT})),
        "users": tuple(sorted({a.target for a in actions if a.target_kind is TargetKind.USER})),
        "evidence": evidence,
        "evidence_snapshot_hash": evidence_snapshot_hash(evidence),
        "actions": tuple(actions),
    }
    data.update(overrides)
    return ContainmentPackage(**data)
