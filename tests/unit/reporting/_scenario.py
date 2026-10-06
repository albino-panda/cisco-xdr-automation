"""Deterministic packages and reports for the reporting and dry-run tests (fake data only)."""
from __future__ import annotations

import os
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

from tests.fixtures.factories import FIXED_NOW
from xdr_response.models import (
    ActionResult,
    ActionResultStatus,
    ActionType,
    ApprovalLevel,
    BlastRadius,
    ContainmentOverall,
    ContainmentPackage,
    ContainmentReport,
    CriticalAssetClass,
    CriticalAssetWarning,
    ErrorCode,
    ErrorInfo,
    EvidenceDraft,
    ExcludedTarget,
    RecommendedAction,
    ReleasePackage,
    RestorationOverall,
    RestorationReport,
    Severity,
    SkipReason,
    VerificationResult,
    VerificationStatus,
    evidence_snapshot_hash,
    get_action_spec,
    make_idempotency_key,
    normalize_target,
    number_evidence,
)

INCIDENT_ID = "XDR-83921"
PACKAGE_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
RELEASE_PACKAGE_ID = "1a2b3c4d5e6f708192a3b4c5d6e7f809"
TOKEN_ID = "9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a3"
FAKE_HASH = "a" * 64
ROLE_TARGET = "jsmith@example.com/62e90394-69f5-4237-9190-012177145e10"
GOLDEN_DIR = Path(__file__).parent / "golden"

EV_SE = EvidenceDraft(
    source="secure_endpoint",
    summary=f"Ransomware detection Win.Ransomware.Example on TH-LT-1047 (sha256 {FAKE_HASH[:8]}...)",
    observed_at=FIXED_NOW - timedelta(minutes=20), reference="se-evt-0001")
EV_UMB = EvidenceDraft(
    source="umbrella", summary="TH-LT-1047 resolved evil.example.com (category: malware)",
    observed_at=FIXED_NOW - timedelta(minutes=18), reference="umb-0001")
EV_ENTRA = EvidenceDraft(
    source="entra", summary="jsmith@example.com signed in from 203.0.113.50 (unfamiliar location)",
    observed_at=FIXED_NOW - timedelta(minutes=25), reference="signin-0001")
EV_DC = EvidenceDraft(
    source="cisco_xdr", summary="DC-01 contacted evil.example.com over HTTPS",
    observed_at=FIXED_NOW - timedelta(minutes=15), reference="xdr-sighting-0001")


def action(action_type: ActionType, target: str, integration: str, evidence: Sequence[EvidenceDraft], *,
           level: ApprovalLevel = ApprovalLevel.STANDARD, risk: int = 90, confidence: int = 90,
           warnings: Sequence[CriticalAssetWarning] = (), incident_id: str = INCIDENT_ID,
           **params: Any) -> RecommendedAction:
    """A RecommendedAction with its own numbered evidence."""
    spec = get_action_spec(action_type)
    normalized = normalize_target(spec.target_kind, target)
    return RecommendedAction(
        incident_id=incident_id,
        idempotency_key=make_idempotency_key(incident_id, action_type, normalized),
        action_type=action_type, target=normalized, target_kind=spec.target_kind,
        params={"integration": integration, **params}, evidence=number_evidence(list(evidence)),
        risk_score=risk, confidence_score=confidence,
        approval_level=ApprovalLevel.ELEVATED if spec.always_elevated else level,
        warnings=tuple(warnings), rationale=f"{action_type.value} on {normalized}",
    )


def _package_data(actions: Sequence[RecommendedAction], **overrides: Any) -> dict[str, Any]:
    drafts = [EvidenceDraft(**e.model_dump(exclude={"number"})) for a in actions for e in a.evidence]
    evidence = number_evidence(drafts)
    data: dict[str, Any] = {
        "package_id": PACKAGE_ID, "incident_id": INCIDENT_ID, "workflow_id": "ransomware",
        "workflow_version": "1.0.0", "created_at": FIXED_NOW,
        "expires_at": FIXED_NOW + timedelta(minutes=240), "requested_by": "automation:package_builder",
        "severity": Severity.CRITICAL, "risk_score": 97, "confidence_score": 94,
        "summary": "Potential ransomware",
        "endpoints": tuple(sorted({a.target for a in actions if a.target_kind.value == "ENDPOINT"})),
        "users": tuple(sorted({a.target for a in actions if a.target_kind.value == "USER"})),
        "evidence": evidence, "evidence_snapshot_hash": evidence_snapshot_hash(evidence),
        "actions": tuple(actions),
    }
    data.update(overrides)
    return data


def ransomware_actions() -> tuple[RecommendedAction, ...]:
    """isolate TH-LT-1047, block evil.example.com, revoke sessions of jsmith@example.com."""
    return (
        action(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", "secure_endpoint", [EV_SE, EV_UMB],
               risk=97, confidence=94, connector_guid="11111111-2222-3333-4444-555555555555"),
        action(ActionType.BLOCK_DOMAIN, "evil.example.com", "umbrella", [EV_UMB], risk=90, confidence=92),
        action(ActionType.REVOKE_SESSIONS, "jsmith@example.com", "entra", [EV_ENTRA], risk=80, confidence=75),
    )


def package_of(actions: Sequence[RecommendedAction], **overrides: Any) -> ContainmentPackage:
    """A containment package for ``actions`` (evidence merged from the actions)."""
    return ContainmentPackage(**_package_data(actions, **overrides))


def ransomware_package(**overrides: Any) -> ContainmentPackage:
    """The section 9 example package: three STANDARD actions."""
    return package_of(ransomware_actions(), **overrides)


def dc_warning() -> CriticalAssetWarning:
    return CriticalAssetWarning(
        asset="DC-01", asset_class=CriticalAssetClass.DOMAIN_CONTROLLER,
        role="Active Directory domain controller", action_type=ActionType.ISOLATE_ENDPOINT,
        potential_impact="Isolating a domain controller can stop authentication, Group Policy and DNS "
                         "for the whole domain.",
        message="WARNING: ELEVATED APPROVAL REQUIRED - isolate_endpoint on DC-01 (domain controller)")


def elevated_package(**overrides: Any) -> ContainmentPackage:
    """A package with a critical asset, an always-elevated action and an allow-listed exclusion."""
    actions = (
        action(ActionType.ISOLATE_ENDPOINT, "DC-01", "cisco_xdr", [EV_DC], level=ApprovalLevel.ELEVATED,
               warnings=[dc_warning()], risk=88, confidence=70),
        action(ActionType.REMOVE_PRIVILEGED_ROLE, ROLE_TARGET, "entra", [EV_ENTRA], risk=85, confidence=80),
        action(ActionType.BLOCK_DOMAIN, "evil.example.com", "umbrella", [EV_UMB], risk=90, confidence=92),
    )
    data = _package_data(actions, severity=Severity.HIGH, risk_score=88, confidence_score=70,
                         summary="Domain controller beaconing to evil.example.com",
                         users=("jsmith@example.com",),
                         excluded_targets=(ExcludedTarget(
                             action_type=ActionType.BLOCK_DOMAIN, target="example.com",
                             reason="allowlists.never_block.domains: example.com"),),
                         blast_radius=BlastRadius(endpoints=("DC-01",), users=("jsmith@example.com",),
                                                  indicators=("evil.example.com", "203.0.113.50")))
    data.update(overrides)
    return ContainmentPackage(**data)


def release_package(**overrides: Any) -> ReleasePackage:
    """Release of three temporary controls (one ELEVATED)."""
    registry_ev = EvidenceDraft(source="temporary_control_registry",
                                summary="3 ACTIVE temporary controls for XDR-83921",
                                observed_at=FIXED_NOW + timedelta(hours=4), reference="registry")
    keys = (f"{INCIDENT_ID}:isolate_endpoint:TH-LT-1047", f"{INCIDENT_ID}:block_domain:evil.example.com",
            f"{INCIDENT_ID}:remove_privileged_role:{ROLE_TARGET}")
    actions = (
        action(ActionType.RELEASE_ENDPOINT, "TH-LT-1047", "secure_endpoint", [registry_ev],
               restores=keys[0], connector_guid="11111111-2222-3333-4444-555555555555"),
        action(ActionType.UNBLOCK_DOMAIN, "evil.example.com", "umbrella", [registry_ev],
               restores=keys[1], destination_list_id="1234567", destination_id="7654321"),
        action(ActionType.RESTORE_PRIVILEGED_ROLE, ROLE_TARGET, "entra", [registry_ev], restores=keys[2],
               roleDefinitionId="62e90394-69f5-4237-9190-012177145e10", directoryScopeId="/"),
    )
    data = _package_data(actions, package_id=RELEASE_PACKAGE_ID, created_at=FIXED_NOW + timedelta(hours=4),
                         expires_at=FIXED_NOW + timedelta(hours=8), requested_by="analyst.one@example.com",
                         summary="Release temporary controls for XDR-83921", control_keys=keys)
    data.update(overrides)
    return ReleasePackage(**data)


def _verified(key: str, status: VerificationStatus, details: str = "") -> VerificationResult:
    return VerificationResult(idempotency_key=key, status=status, integration=None, method="get_state",
                              checked_at=FIXED_NOW + timedelta(minutes=6), details=details)


def containment_report() -> ContainmentReport:
    """PARTIALLY_CONTAINED: one success, one failure needing attention, one rejected by the analyst."""
    iso, blk, rev = ransomware_actions()
    t0, t1 = FIXED_NOW + timedelta(minutes=5), FIXED_NOW + timedelta(minutes=6)
    results = (
        ActionResult(idempotency_key=iso.idempotency_key, action_type=iso.action_type, target=iso.target,
                     integration="secure_endpoint", approval_level=ApprovalLevel.STANDARD,
                     status=ActionResultStatus.SUCCESS, started_at=t0, finished_at=t1,
                     message="isolation requested",
                     verification=_verified(iso.idempotency_key, VerificationStatus.VERIFIED, "isolated"),
                     control_registered=True),
        ActionResult(idempotency_key=blk.idempotency_key, action_type=blk.action_type, target=blk.target,
                     integration="umbrella", approval_level=ApprovalLevel.STANDARD,
                     status=ActionResultStatus.FAILED, started_at=t0, finished_at=t1,
                     error=ErrorInfo(code=ErrorCode.RATE_LIMITED, message="rate limited after 3 attempts",
                                     integration="umbrella", http_status=429, retryable=True),
                     requires_attention=True,
                     recommended_escalation="Block evil.example.com manually in Umbrella and record it"),
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
    """RESTORED: both releases verified."""
    pkg = release_package()
    t0, t1 = FIXED_NOW + timedelta(hours=5), FIXED_NOW + timedelta(hours=5, minutes=1)
    results = tuple(
        ActionResult(idempotency_key=a.idempotency_key, action_type=a.action_type, target=a.target,
                     integration=a.integration, approval_level=a.approval_level,
                     status=ActionResultStatus.SUCCESS, started_at=t0, finished_at=t1,
                     verification=_verified(a.idempotency_key, VerificationStatus.VERIFIED))
        for a in pkg.actions
    )
    return RestorationReport(report_id="r-0002", incident_id=INCIDENT_ID, package_id=RELEASE_PACKAGE_ID,
                             token_id=TOKEN_ID, dry_run=False, started_at=t0, finished_at=t1,
                             results=results, overall=RestorationOverall.RESTORED)


def assert_golden(name: str, text: str) -> None:
    """Compare ``text`` with ``golden/<name>``; ``UPDATE_GOLDEN=1`` rewrites the file."""
    path = GOLDEN_DIR / name
    if os.environ.get("UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(text + "\n")
    assert path.exists(), f"missing golden file {path}; run with UPDATE_GOLDEN=1 and review it"
    expected = path.read_text(encoding="utf-8")
    assert text + "\n" == expected, f"output differs from golden/{name}"
