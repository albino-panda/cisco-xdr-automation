"""Deterministic lifecycle events for the notification tests (fake data only).

Params and vendor messages carry marker strings so the tests can prove they never reach a
notification. No value here is a real secret, token or indicator.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from xdr_response.atomics.notifications import LifecycleEvent, LifecycleEventKind, WorkflowSummary
from xdr_response.models import (
    ActionResult,
    ActionResultStatus,
    ActionType,
    AnalystDecision,
    ApprovalLevel,
    AuthenticatedPrincipal,
    BlastRadius,
    ContainmentOverall,
    ContainmentPackage,
    ContainmentReport,
    CriticalAssetClass,
    CriticalAssetWarning,
    DecisionType,
    ErrorCode,
    ErrorInfo,
    EvidenceDraft,
    ExcludedTarget,
    Incident,
    PrincipalKind,
    RecommendedAction,
    ReleasePackage,
    RestorationOverall,
    RestorationReport,
    RiskBand,
    Severity,
    SkipReason,
    TargetKind,
    Asset,
    VerificationResult,
    VerificationStatus,
    evidence_snapshot_hash,
    get_action_spec,
    make_idempotency_key,
    normalize_target,
    number_evidence,
)

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
INCIDENT_ID = "XDR-83921"
PACKAGE_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
RELEASE_PACKAGE_ID = "1a2b3c4d5e6f708192a3b4c5d6e7f809"
TOKEN_ID = "9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a3"
ANALYST = "analyst.one@example.com"
LEAD = "lead.two@example.com"
ROLE_TARGET = "jsmith@example.com/62e90394-69f5-4237-9190-012177145e10"

#: Marker values that must never appear in any notification.
PARAM_MARKER = "PARAM-MARKER-not-rendered-7f3a"
VENDOR_MESSAGE_MARKER = "VENDOR-MESSAGE-not-rendered-91c2"
ERROR_MESSAGE_MARKER = "ERROR-MESSAGE-not-rendered-44d1"
FORBIDDEN_MARKERS = (PARAM_MARKER, VENDOR_MESSAGE_MARKER, ERROR_MESSAGE_MARKER, TOKEN_ID)

EV_SE = EvidenceDraft(
    source="secure_endpoint", summary="Ransomware detection on TH-LT-1047",
    observed_at=NOW - timedelta(minutes=20), reference="se-evt-0001", data={"secret_note": PARAM_MARKER})
EV_UMB = EvidenceDraft(
    source="umbrella", summary="TH-LT-1047 resolved evil.example.com (category: malware)",
    observed_at=NOW - timedelta(minutes=18), reference="umb-0001")
EV_ENTRA = EvidenceDraft(
    source="entra", summary="jsmith@example.com signed in from 203.0.113.50 (unfamiliar location)",
    observed_at=NOW - timedelta(minutes=25), reference="signin-0001")
EV_DC = EvidenceDraft(
    source="cisco_xdr", summary="DC-01 contacted evil.example.com over HTTPS",
    observed_at=NOW - timedelta(minutes=15), reference="xdr-sighting-0001")


def incident(**overrides: Any) -> Incident:
    """The test incident (no AI narrative unless given)."""
    data: dict[str, Any] = {
        "incident_id": INCIDENT_ID, "title": "Potential ransomware on TH-LT-1047",
        "severity": Severity.CRITICAL, "created_at": NOW - timedelta(hours=1),
        "workflow_id": "ransomware", "workflow_version": "1.0.0",
        "assets": (Asset(name="TH-LT-1047", kind=TargetKind.ENDPOINT),), "users": ("jsmith@example.com",),
    }
    data.update(overrides)
    return Incident(**data)


def action(action_type: ActionType, target: str, integration: str, evidence: Sequence[EvidenceDraft], *,
           level: ApprovalLevel = ApprovalLevel.STANDARD, risk: int = 90, confidence: int = 85,
           warnings: Sequence[CriticalAssetWarning] = (), **params: Any) -> RecommendedAction:
    """A RecommendedAction whose params carry the marker."""
    spec = get_action_spec(action_type)
    normalized = normalize_target(spec.target_kind, target)
    return RecommendedAction(
        incident_id=INCIDENT_ID, idempotency_key=make_idempotency_key(INCIDENT_ID, action_type, normalized),
        action_type=action_type, target=normalized, target_kind=spec.target_kind,
        params={"integration": integration, "connector_guid": PARAM_MARKER, **params},
        evidence=number_evidence(list(evidence)), risk_score=risk, confidence_score=confidence,
        approval_level=ApprovalLevel.ELEVATED if spec.always_elevated else level,
        warnings=tuple(warnings), rationale=f"{action_type.value} on {normalized}",
    )


def _package_data(actions: Sequence[RecommendedAction], **overrides: Any) -> dict[str, Any]:
    drafts = [EvidenceDraft(**e.model_dump(exclude={"number"})) for a in actions for e in a.evidence]
    evidence = number_evidence(drafts)
    data: dict[str, Any] = {
        "package_id": PACKAGE_ID, "incident_id": INCIDENT_ID, "workflow_id": "ransomware",
        "workflow_version": "1.0.0", "created_at": NOW, "expires_at": NOW + timedelta(hours=4),
        "requested_by": "automation:package_builder", "severity": Severity.CRITICAL,
        "risk_score": 97, "confidence_score": 64, "summary": "Potential ransomware",
        "evidence": evidence, "evidence_snapshot_hash": evidence_snapshot_hash(evidence),
        "actions": tuple(actions),
    }
    data.update(overrides)
    return data


def standard_actions() -> tuple[RecommendedAction, ...]:
    """isolate TH-LT-1047, block evil.example.com, revoke sessions of jsmith@example.com."""
    return (
        action(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", "secure_endpoint", [EV_SE, EV_UMB], risk=97),
        action(ActionType.BLOCK_DOMAIN, "evil.example.com", "umbrella", [EV_UMB]),
        action(ActionType.REVOKE_SESSIONS, "jsmith@example.com", "entra", [EV_ENTRA], risk=80),
    )


def containment_package(**overrides: Any) -> ContainmentPackage:
    """Three STANDARD actions."""
    return ContainmentPackage(**_package_data(standard_actions(), **overrides))


def dc_warning() -> CriticalAssetWarning:
    """Critical-asset warning for DC-01."""
    return CriticalAssetWarning(
        asset="DC-01", asset_class=CriticalAssetClass.DOMAIN_CONTROLLER,
        role="Active Directory domain controller", action_type=ActionType.ISOLATE_ENDPOINT,
        potential_impact="Isolating a domain controller can stop authentication for the domain.",
        message="WARNING: ELEVATED APPROVAL REQUIRED - isolate_endpoint on DC-01 (domain controller)")


def elevated_package(**overrides: Any) -> ContainmentPackage:
    """A critical asset, an always-elevated action, an exclusion and a blast radius."""
    actions = (
        action(ActionType.ISOLATE_ENDPOINT, "DC-01", "cisco_xdr", [EV_DC], level=ApprovalLevel.ELEVATED,
               warnings=[dc_warning()], risk=88, confidence=70),
        action(ActionType.REMOVE_PRIVILEGED_ROLE, ROLE_TARGET, "entra", [EV_ENTRA], risk=85, confidence=80),
        action(ActionType.BLOCK_DOMAIN, "evil.example.com", "umbrella", [EV_UMB]),
    )
    data = _package_data(
        actions, severity=Severity.HIGH, risk_score=88, confidence_score=70,
        excluded_targets=(ExcludedTarget(action_type=ActionType.BLOCK_DOMAIN, target="example.com",
                                         reason="allowlists.never_block.domains: example.com"),),
        blast_radius=BlastRadius(endpoints=("DC-01",), users=("jsmith@example.com",),
                                 indicators=("evil.example.com", "203.0.113.50")))
    data.update(overrides)
    return ContainmentPackage(**data)


def release_package(**overrides: Any) -> ReleasePackage:
    """Release of two temporary controls."""
    registry = EvidenceDraft(source="temporary_control_registry", summary="2 ACTIVE temporary controls",
                             observed_at=NOW + timedelta(hours=4), reference="registry")
    keys = (f"{INCIDENT_ID}:isolate_endpoint:TH-LT-1047", f"{INCIDENT_ID}:block_domain:evil.example.com")
    actions = (
        action(ActionType.RELEASE_ENDPOINT, "TH-LT-1047", "secure_endpoint", [registry], restores=keys[0]),
        action(ActionType.UNBLOCK_DOMAIN, "evil.example.com", "umbrella", [registry], restores=keys[1]),
    )
    data = _package_data(actions, package_id=RELEASE_PACKAGE_ID, created_at=NOW + timedelta(hours=4),
                         expires_at=NOW + timedelta(hours=8), requested_by=ANALYST, control_keys=keys)
    data.update(overrides)
    return ReleasePackage(**data)


def principal(principal_id: str = ANALYST, name: str = "Analyst One") -> AuthenticatedPrincipal:
    """An authenticated human."""
    return AuthenticatedPrincipal(principal_id=principal_id, display_name=name, kind=PrincipalKind.HUMAN,
                                  roles=frozenset({"xdr-approver"}), authenticator="static",
                                  authenticated_at=NOW + timedelta(minutes=2))


def decision(package: ContainmentPackage | ReleasePackage | None = None, *,
             kind: DecisionType = DecisionType.APPROVE_SELECTED, comment: str = "Approved after review",
             approvers: Sequence[AuthenticatedPrincipal] | None = None) -> AnalystDecision:
    """A human decision: approves all but the last action for APPROVE_SELECTED."""
    pkg = package if package is not None else containment_package()
    keys = pkg.keys
    if kind is DecisionType.APPROVE_ALL:
        approved, rejected = keys, ()
    elif kind is DecisionType.APPROVE_SELECTED:
        approved, rejected = keys[:-1], keys[-1:]
    else:
        approved, rejected = (), keys
    people = tuple(approvers) if approvers is not None else (principal(),)
    return AnalystDecision(
        decision_id="d-0001", package_id=pkg.package_id, incident_id=INCIDENT_ID, purpose=pkg.purpose,
        decision=kind, analyst_identity=people[0].principal_id, approvers=people,
        decided_at=NOW + timedelta(minutes=3), approved_action_keys=approved, rejected_action_keys=rejected,
        comment=comment, workflow_id=pkg.workflow_id, workflow_version=pkg.workflow_version,
        evidence_snapshot_hash=pkg.evidence_snapshot_hash,
        token_id=TOKEN_ID if approved else None)


def _verified(key: str) -> VerificationResult:
    return VerificationResult(idempotency_key=key, status=VerificationStatus.VERIFIED, integration=None,
                              method="get_state", checked_at=NOW + timedelta(minutes=6))


def containment_report(*, dry_run: bool = False) -> ContainmentReport:
    """PARTIALLY_CONTAINED: success, failure needing attention, rejected (or all DRY_RUN)."""
    iso, blk, rev = standard_actions()
    t0, t1 = NOW + timedelta(minutes=5), NOW + timedelta(minutes=6)
    if dry_run:
        results = tuple(
            ActionResult(idempotency_key=a.idempotency_key, action_type=a.action_type, target=a.target,
                         integration=a.integration, approval_level=a.approval_level,
                         status=ActionResultStatus.DRY_RUN, started_at=t0, finished_at=t1,
                         dry_run_line=f"Would {a.action_type.value}: {a.target}")
            for a in (iso, blk))
        return ContainmentReport(report_id="r-dry", incident_id=INCIDENT_ID, package_id=PACKAGE_ID,
                                 token_id=None, dry_run=True, started_at=t0, finished_at=t1,
                                 results=results, overall=None)
    results = (
        ActionResult(idempotency_key=iso.idempotency_key, action_type=iso.action_type, target=iso.target,
                     integration="secure_endpoint", approval_level=ApprovalLevel.STANDARD,
                     status=ActionResultStatus.SUCCESS, started_at=t0, finished_at=t1,
                     message=VENDOR_MESSAGE_MARKER, verification=_verified(iso.idempotency_key),
                     control_registered=True),
        ActionResult(idempotency_key=blk.idempotency_key, action_type=blk.action_type, target=blk.target,
                     integration="umbrella", approval_level=ApprovalLevel.STANDARD,
                     status=ActionResultStatus.FAILED, started_at=t0, finished_at=t1,
                     error=ErrorInfo(code=ErrorCode.RATE_LIMITED, message=ERROR_MESSAGE_MARKER,
                                     integration="umbrella", http_status=429, retryable=True),
                     requires_attention=True,
                     recommended_escalation="Block evil.example.com manually and record it"),
        ActionResult(idempotency_key=rev.idempotency_key, action_type=rev.action_type, target=rev.target,
                     integration="entra", approval_level=ApprovalLevel.STANDARD,
                     status=ActionResultStatus.SKIPPED, skip_reason=SkipReason.REJECTED_BY_ANALYST,
                     started_at=t0, finished_at=t0),
    )
    return ContainmentReport(report_id="r-0001", incident_id=INCIDENT_ID, package_id=PACKAGE_ID,
                             token_id=TOKEN_ID, dry_run=False, started_at=t0, finished_at=t1,
                             results=results, overall=ContainmentOverall.PARTIALLY_CONTAINED,
                             attention=("block_domain evil.example.com failed: RATE_LIMITED",))


def restoration_report() -> RestorationReport:
    """RESTORED: every release verified."""
    pkg = release_package()
    t0, t1 = NOW + timedelta(hours=5), NOW + timedelta(hours=5, minutes=1)
    results = tuple(
        ActionResult(idempotency_key=a.idempotency_key, action_type=a.action_type, target=a.target,
                     integration=a.integration, approval_level=a.approval_level,
                     status=ActionResultStatus.SUCCESS, started_at=t0, finished_at=t1,
                     verification=_verified(a.idempotency_key))
        for a in pkg.actions)
    return RestorationReport(report_id="r-0002", incident_id=INCIDENT_ID, package_id=RELEASE_PACKAGE_ID,
                             token_id=TOKEN_ID, dry_run=False, started_at=t0, finished_at=t1,
                             results=results, overall=RestorationOverall.RESTORED)


def summary(**overrides: Any) -> WorkflowSummary:
    """Workflow facts with a degraded source, an unrouted action and a below-threshold finding."""
    data: dict[str, Any] = {
        "workflow_id": "ransomware", "workflow_version": "1.0.0", "risk_score": 42,
        "confidence_score": 55, "risk_band": RiskBand.MEDIUM,
        "evidence": ("[rec-0001] secure_endpoint: Ransomware detection on TH-LT-1047",
                     "[rec-0002] umbrella: TH-LT-1047 resolved evil.example.com"),
        "degraded_sources": ("defender_endpoint: UNAVAILABLE",),
        "unrouted": ("quarantine_file TH-LT-1047: no capable adapter",),
        "below_threshold": ("block_ip 198.51.100.7: risk 20 below threshold 60",),
        "blast_radius": BlastRadius(endpoints=("TH-LT-1047",), users=("jsmith@example.com",)),
    }
    data.update(overrides)
    return WorkflowSummary(**data)


def event(kind: LifecycleEventKind, **overrides: Any) -> LifecycleEvent:
    """A complete event of ``kind`` with the parts the orchestrator would attach."""
    data: dict[str, Any] = {"kind": kind, "at": NOW + timedelta(minutes=10), "incident": incident()}
    data.update(_parts(kind))
    data.update(overrides)
    return LifecycleEvent(**data)


def _parts(kind: LifecycleEventKind) -> dict[str, Any]:
    pkg = containment_package()
    rel = release_package()
    parts: dict[LifecycleEventKind, dict[str, Any]] = {
        LifecycleEventKind.DETECTION_COMPLETED: {"summary": summary(), "notes": ("no containment needed",)},
        LifecycleEventKind.PACKAGE_PROPOSED: {"package": pkg, "summary": summary(risk_score=97,
                                                                                 risk_band=RiskBand.CRITICAL)},
        LifecycleEventKind.DECISION_RECORDED: {"package": pkg, "decision": decision(pkg)},
        LifecycleEventKind.CONTAINMENT_COMPLETED: {"package": pkg, "decision": decision(pkg),
                                                   "report": containment_report()},
        LifecycleEventKind.RELEASE_PROPOSED: {"package": rel},
        LifecycleEventKind.RESTORATION_COMPLETED: {
            "package": rel, "decision": decision(rel, kind=DecisionType.APPROVE_ALL),
            "report": restoration_report()},
        LifecycleEventKind.INCIDENT_CLOSED: {"notes": ("closed by analyst.one@example.com",)},
    }
    return parts[kind]

