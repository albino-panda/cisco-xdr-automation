"""Shared fixtures for the audit unit tests: deterministic clock, ids and a private redactor."""
from __future__ import annotations

import itertools
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from tests.fixtures.factories import FIXED_NOW
from xdr_response.audit import AuditTrail, MemoryAuditTrail
from xdr_response.clock import FixedClock
from xdr_response.logs.redaction import Redactor
from xdr_response.models import AuditEventType


class TickingClock(FixedClock):
    """FixedClock that advances one second per read, so timestamps are distinct and predictable."""

    def now(self):  # type: ignore[override]
        value = super().now()
        self.advance(timedelta(seconds=1))
        return value


def counter_ids(prefix: str = "aud") -> Callable[[], str]:
    """Deterministic record id factory."""
    numbers = itertools.count(1)
    return lambda: f"{prefix}-{next(numbers):06d}"


@pytest.fixture
def clock() -> TickingClock:
    return TickingClock(FIXED_NOW)


@pytest.fixture
def redactor() -> Redactor:
    return Redactor()


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit" / "audit.jsonl"


@pytest.fixture
def make_trail(audit_path: Path, clock: TickingClock, redactor: Redactor) -> Callable[..., AuditTrail]:
    def factory(path: Path | None = None, **kwargs: object) -> AuditTrail:
        kwargs.setdefault("clock", clock)
        kwargs.setdefault("redactor", redactor)
        kwargs.setdefault("fsync", False)
        kwargs.setdefault("id_factory", counter_ids())
        return AuditTrail(path or audit_path, **kwargs)  # type: ignore[arg-type]
    return factory


@pytest.fixture
def memory_trail(clock: TickingClock, redactor: Redactor) -> MemoryAuditTrail:
    return MemoryAuditTrail(clock=clock, redactor=redactor, id_factory=counter_ids())


def _fill(trail: object, n: int, incident_id: str = "XDR-83921") -> None:
    for i in range(n):
        trail.append(AuditEventType.STATE_TRANSITION, incident_id=incident_id,  # type: ignore[attr-defined]
                     actor="automation:test", payload={"index": i, "host": "TH-LT-1047"},
                     workflow_id="malicious-powershell", workflow_version="1.0.0")


@pytest.fixture
def fill() -> Callable[..., None]:
    """``fill(trail, n, incident_id=...)`` appends ``n`` simple records."""
    return _fill


@pytest.fixture
def ids() -> Callable[..., Callable[[], str]]:
    """Factory of deterministic record id generators."""
    return counter_ids


# ------------------------------------------------------- lifecycle models ---
def _first_investigation_type():
    from xdr_response.models import ActionCategory, ActionType, get_action_spec

    return next(a for a in ActionType if get_action_spec(a).category is ActionCategory.INVESTIGATION)


@pytest.fixture
def lifecycle():
    """One consistent set of lifecycle models for incident XDR-83921 (fake data only)."""
    from types import SimpleNamespace

    from tests.fixtures.factories import make_evidence, make_incident, make_package, make_recommendation
    from tests.fixtures.guard_helpers import make_token
    from xdr_response.models import (
        ActionRequest, ActionResult, ActionResultStatus, ActionType, AnalystDecision, ApiCallSummary,
        ApprovalLevel, ApprovalPurpose, AuthenticatedPrincipal, ContainmentOverall, ContainmentReport,
        ControlStatus, DecisionType, EnrichmentResult, ErrorCode, ErrorInfo, HealthStatus, IncidentState,
        IntegrationHealth, InvestigationResult, Observable, ObservableType, OperationKind, PrincipalKind,
        ReleasePackage, RestorationOverall, RestorationReport, SkipReason, StateTransition, TargetKind,
        TemporaryControl, Verdict, VerificationResult, VerificationStatus,
    )

    incident = make_incident()
    isolate = make_recommendation()
    block = make_recommendation(ActionType.BLOCK_DOMAIN, target="bad.example.test", integration="umbrella")
    package = make_package(isolate, block)
    request = ActionRequest.from_recommendation(isolate)
    analyst = AuthenticatedPrincipal(principal_id="analyst.one@example.com", display_name="Analyst One",
                                     kind=PrincipalKind.HUMAN, roles=frozenset({"xdr-approver", "b-role"}),
                                     authenticator="test", authenticated_at=FIXED_NOW)
    decision = AnalystDecision(
        decision_id="dec-1", package_id=package.package_id, incident_id=incident.incident_id,
        purpose=ApprovalPurpose.CONTAINMENT, decision=DecisionType.APPROVE_SELECTED,
        analyst_identity=analyst.principal_id, approvers=(analyst,),
        decided_at=FIXED_NOW + timedelta(minutes=5),
        approved_action_keys=(isolate.idempotency_key,), rejected_action_keys=(block.idempotency_key,),
        comment="isolate only", workflow_id="malicious-powershell", workflow_version="1.0.0",
        evidence_snapshot_hash=package.evidence_snapshot_hash, token_id="tok-1")
    token = make_token(isolate, token_id="tok-1")
    api_call = ApiCallSummary(
        integration="secure_endpoint", operation="isolate", method="PUT",
        url="https://api.example.test/v1/computers/guid-1/isolation", kind=OperationKind.STATE_CHANGING,
        status_code=200, duration_ms=120, attempt=1, request_summary={"comment": "XDR-83921"},
        response_summary={"status": "pending_start"})
    verification = VerificationResult(
        idempotency_key=isolate.idempotency_key, status=VerificationStatus.VERIFIED,
        integration="secure_endpoint", method="get_isolation", checked_at=FIXED_NOW + timedelta(minutes=7))
    started = FIXED_NOW + timedelta(minutes=6)
    success = ActionResult(
        idempotency_key=isolate.idempotency_key, action_type=isolate.action_type, target=isolate.target,
        integration="secure_endpoint", approval_level=ApprovalLevel.STANDARD,
        status=ActionResultStatus.SUCCESS, started_at=started, finished_at=started,
        api_calls=(api_call,), verification=verification, control_registered=True)
    error = ErrorInfo(code=ErrorCode.RATE_LIMITED, message="rate limited", integration="umbrella",
                      http_status=429, retryable=True)
    skipped = ActionResult(
        idempotency_key=block.idempotency_key, action_type=block.action_type, target=block.target,
        integration="umbrella", approval_level=ApprovalLevel.STANDARD, status=ActionResultStatus.SKIPPED,
        skip_reason=SkipReason.REJECTED_BY_ANALYST, started_at=started, finished_at=started)
    failed = ActionResult(
        idempotency_key=block.idempotency_key, action_type=block.action_type, target=block.target,
        integration="umbrella", approval_level=ApprovalLevel.STANDARD, status=ActionResultStatus.FAILED,
        started_at=started, finished_at=started, error=error)
    report = ContainmentReport(
        report_id="rep-1", incident_id=incident.incident_id, package_id=package.package_id,
        token_id="tok-1", dry_run=False, started_at=started, finished_at=started,
        results=(success, skipped), overall=ContainmentOverall.CONTAINED)
    control = TemporaryControl(
        control_key=isolate.idempotency_key, incident_id=incident.incident_id,
        action_type=isolate.action_type, target=isolate.target, target_kind=TargetKind.ENDPOINT,
        integration="secure_endpoint", workflow_id="malicious-powershell", workflow_version="1.0.0",
        package_id=package.package_id, token_id="tok-1", decision_id="dec-1",
        approval_level=ApprovalLevel.STANDARD, created_at=started,
        rollback_action_type=ActionType.RELEASE_ENDPOINT, rollback_params={"integration": "secure_endpoint"},
        status=ControlStatus.ACTIVE)
    release_action = make_recommendation(ActionType.RELEASE_ENDPOINT, restores=isolate.idempotency_key)
    release_base = make_package().model_dump(exclude={"purpose"})
    release_base["actions"] = (release_action,)
    release_package = ReleasePackage(**release_base, control_keys=(isolate.idempotency_key,))
    restored_at = started + timedelta(hours=2)
    restored = ActionResult(
        idempotency_key=release_action.idempotency_key, action_type=release_action.action_type,
        target=release_action.target, integration="secure_endpoint",
        approval_level=release_action.approval_level, status=ActionResultStatus.SUCCESS,
        started_at=restored_at, finished_at=restored_at)
    restoration_report = RestorationReport(
        report_id="rep-2", incident_id=incident.incident_id, package_id=release_package.package_id,
        token_id="tok-2", dry_run=False, started_at=restored_at, finished_at=restored_at,
        results=(restored,), overall=RestorationOverall.RESTORED)
    subject = Observable(type=ObservableType.SHA256, value="a" * 64, source="secure_endpoint")
    investigation = InvestigationResult(integration="secure_endpoint",
                                        action_type=_first_investigation_type(), subject=subject,
                                        findings=({"count": 2, "score": 0.75},))
    enrichment = EnrichmentResult(type=ObservableType.DOMAIN, value="bad.example.test", risk_score=90,
                                  confidence=80, sources=("umbrella",), verdict=Verdict.MALICIOUS,
                                  integration="umbrella")
    health = IntegrationHealth(integration="umbrella", status=HealthStatus.DEGRADED,
                               checked_at=FIXED_NOW, detail="slow")
    transition = StateTransition(from_state=IncidentState.NOT_STARTED,
                                 to_state=IncidentState.AWAITING_APPROVAL, at=FIXED_NOW,
                                 actor="automation:lifecycle", package_id=package.package_id)
    return SimpleNamespace(
        incident=incident, isolate=isolate, block=block, package=package, request=request,
        decision=decision, token=token, api_call=api_call, verification=verification, success=success,
        skipped=skipped, failed=failed, error=error, report=report, control=control,
        release_package=release_package, restored=restored, restoration_report=restoration_report,
        investigation=investigation, evidence=make_evidence(), enrichment=enrichment, health=health,
        transition=transition)
