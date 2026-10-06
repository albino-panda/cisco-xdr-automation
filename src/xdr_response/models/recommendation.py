"""Recommendations and action packages (containment and release)."""
from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from xdr_response.models._base import FrozenModel, JsonDict, Score
from xdr_response.models._validation import check_action_binding, check_integration_param
from xdr_response.models.canonical import params_hash as _params_hash
from xdr_response.models.catalog import ActionType, get_action_spec
from xdr_response.models.enums import (
    ApprovalLevel,
    ApprovalPurpose,
    CriticalAssetClass,
    RiskBand,
    Severity,
    TargetKind,
)
from xdr_response.models.evidence import Evidence, EvidenceDraft, evidence_snapshot_hash
from xdr_response.models.incident import Asset

__all__ = [
    "risk_band",
    "CriticalAssetWarning",
    "ExcludedTarget",
    "BlastRadius",
    "ProposedAction",
    "RecommendedAction",
    "ActionPackage",
    "ContainmentPackage",
    "ReleasePackage",
]


def risk_band(score: int) -> RiskBand:
    """0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL; anything else raises ValueError."""
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError(f"score must be an int in 0..100, got {score!r}")
    if score >= 80:
        return RiskBand.CRITICAL
    if score >= 60:
        return RiskBand.HIGH
    if score >= 30:
        return RiskBand.MEDIUM
    return RiskBand.LOW


class CriticalAssetWarning(FrozenModel):
    asset: str
    asset_class: CriticalAssetClass | None  # None for blast-radius warnings
    role: str
    action_type: ActionType
    potential_impact: str
    message: str  # "WARNING: ELEVATED APPROVAL REQUIRED - ..."


class ExcludedTarget(FrozenModel):
    action_type: ActionType
    target: str
    reason: str = Field(min_length=1)


class BlastRadius(FrozenModel):
    endpoints: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    messages: int = Field(default=0, ge=0)


class ProposedAction(FrozenModel):
    """Input to PackageBuilder (from workflows or the plan bridge)."""

    action_type: ActionType
    target: str = Field(min_length=1)
    target_kind: TargetKind
    params: JsonDict
    evidence: tuple[EvidenceDraft, ...] = Field(min_length=1)
    risk_score: Score
    confidence_score: Score
    rationale: str
    asset: Asset | None = None

    @field_validator("params")
    @classmethod
    def _integration(cls, value: JsonDict) -> JsonDict:
        check_integration_param(value)
        return value


class RecommendedAction(FrozenModel):
    incident_id: str = Field(min_length=1)
    idempotency_key: str
    action_type: ActionType
    target: str
    target_kind: TargetKind
    params: JsonDict
    evidence: tuple[Evidence, ...] = Field(min_length=1)
    risk_score: Score
    confidence_score: Score
    approval_level: ApprovalLevel
    warnings: tuple[CriticalAssetWarning, ...] = ()
    rationale: str = ""

    @model_validator(mode="after")
    def _validate(self) -> "RecommendedAction":
        spec = get_action_spec(self.action_type)
        if not spec.state_changing:
            raise ValueError(f"{self.action_type.value} is not state-changing; it needs no approval")
        check_action_binding(
            incident_id=self.incident_id, idempotency_key=self.idempotency_key,
            action_type=self.action_type, target=self.target, target_kind=self.target_kind,
            params=self.params,
        )
        if spec.always_elevated and self.approval_level is not ApprovalLevel.ELEVATED:
            raise ValueError(f"{self.action_type.value} always requires ELEVATED approval")
        if self.warnings and self.approval_level is not ApprovalLevel.ELEVATED:
            raise ValueError("an action with critical-asset or blast-radius warnings must be ELEVATED")
        _params_hash(self.params)  # params must be canonicalizable (no floats)
        return self

    @property
    def params_hash(self) -> str:
        return _params_hash(self.params)

    @property
    def integration(self) -> str:
        return str(self.params["integration"])


class ActionPackage(FrozenModel):
    package_id: str = Field(min_length=1)
    purpose: ApprovalPurpose
    incident_id: str
    workflow_id: str
    workflow_version: str
    created_at: AwareDatetime
    expires_at: AwareDatetime
    requested_by: str = Field(min_length=1)
    severity: Severity
    risk_score: Score
    confidence_score: Score
    summary: str
    endpoints: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...]
    evidence_snapshot_hash: str
    actions: tuple[RecommendedAction, ...] = Field(min_length=1)
    excluded_targets: tuple[ExcludedTarget, ...] = ()
    blast_radius: BlastRadius = BlastRadius()
    dry_run: bool = False

    @model_validator(mode="after")
    def _validate_package(self) -> "ActionPackage":
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if evidence_snapshot_hash(self.evidence) != self.evidence_snapshot_hash:
            raise ValueError("evidence_snapshot_hash does not match the package evidence")
        keys = [a.idempotency_key for a in self.actions]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate idempotency keys in package")
        if any(a.incident_id != self.incident_id for a in self.actions):
            raise ValueError("every action must belong to the package incident")
        numbers = [e.number for e in self.evidence]
        if len(set(numbers)) != len(numbers):
            raise ValueError("duplicate evidence numbers in package")
        for a in self.actions:
            if get_action_spec(a.action_type).purpose != self.purpose:
                raise ValueError(
                    f"action {a.idempotency_key} has purpose "
                    f"{get_action_spec(a.action_type).purpose} but the package purpose is {self.purpose}"
                )
        return self

    def action(self, idempotency_key: str) -> RecommendedAction:
        for a in self.actions:
            if a.idempotency_key == idempotency_key:
                return a
        raise KeyError(idempotency_key)

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(a.idempotency_key for a in self.actions)

    @property
    def has_elevated(self) -> bool:
        return any(a.approval_level is ApprovalLevel.ELEVATED for a in self.actions)


class ContainmentPackage(ActionPackage):
    purpose: Literal[ApprovalPurpose.CONTAINMENT] = ApprovalPurpose.CONTAINMENT


class ReleasePackage(ActionPackage):
    purpose: Literal[ApprovalPurpose.RELEASE] = ApprovalPurpose.RELEASE
    control_keys: tuple[str, ...]

    @model_validator(mode="after")
    def _validate_release(self) -> "ReleasePackage":
        if len(self.control_keys) != len(self.actions):
            raise ValueError("control_keys must list one registry key per action, in action order")
        if len(set(self.control_keys)) != len(self.control_keys):
            raise ValueError("duplicate control_keys in release package")
        for key, action in zip(self.control_keys, self.actions):
            if action.params.get("restores") != key:
                raise ValueError(f'action {action.idempotency_key} params["restores"] must be {key!r}')
        return self
