"""Action requests, outcomes, results and execution reports."""
from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models._common import ApiCallSummary, ErrorInfo
from xdr_response.models._validation import check_action_binding
from xdr_response.models.canonical import params_hash as _params_hash
from xdr_response.models.catalog import ActionType
from xdr_response.models.enums import (
    ActionResultStatus,
    ApprovalLevel,
    ContainmentOverall,
    RestorationOverall,
    SkipReason,
    TargetKind,
    TargetState,
)
from xdr_response.models.recommendation import RecommendedAction
from xdr_response.models.verification import VerificationResult

__all__ = [
    "ErrorInfo",
    "ApiCallSummary",
    "ActionRequest",
    "TargetStateCheck",
    "ActionOutcome",
    "ActionResult",
    "ContainmentReport",
    "RestorationReport",
]


class ActionRequest(FrozenModel):
    """What an adapter receives. The guard binds it to an approval token grant."""

    incident_id: str = Field(min_length=1)
    idempotency_key: str
    action_type: ActionType
    target: str
    target_kind: TargetKind
    params: JsonDict  # contains "integration"

    @model_validator(mode="after")
    def _validate(self) -> "ActionRequest":
        check_action_binding(
            incident_id=self.incident_id, idempotency_key=self.idempotency_key,
            action_type=self.action_type, target=self.target, target_kind=self.target_kind,
            params=self.params,
        )
        return self

    @property
    def integration(self) -> str:
        return str(self.params["integration"])

    @property
    def params_hash(self) -> str:
        return _params_hash(self.params)

    @classmethod
    def from_recommendation(cls, action: RecommendedAction) -> "ActionRequest":
        return cls(
            incident_id=action.incident_id,
            idempotency_key=action.idempotency_key,
            action_type=action.action_type,
            target=action.target,
            target_kind=action.target_kind,
            params=dict(action.params),
        )


class TargetStateCheck(FrozenModel):
    state: TargetState
    detail: str = ""
    api_calls: tuple[ApiCallSummary, ...] = ()


class ActionOutcome(FrozenModel):
    """Returned by adapters for SUCCESS / ALREADY_CONTAINED. Failures are raised as IntegrationError."""

    status: Literal[ActionResultStatus.SUCCESS, ActionResultStatus.ALREADY_CONTAINED]
    integration: str
    message: str = ""
    external_ref: str | None = None
    rollback_params: JsonDict = {}
    api_calls: tuple[ApiCallSummary, ...] = ()
    executed_at: AwareDatetime


class ActionResult(FrozenModel):
    idempotency_key: str
    action_type: ActionType
    target: str
    integration: str | None
    approval_level: ApprovalLevel
    status: ActionResultStatus
    skip_reason: SkipReason | None = None
    started_at: AwareDatetime
    finished_at: AwareDatetime
    message: str = ""
    error: ErrorInfo | None = None
    api_calls: tuple[ApiCallSummary, ...] = ()
    verification: VerificationResult | None = None
    control_registered: bool = False
    requires_attention: bool = False
    recommended_escalation: str | None = None
    dry_run_line: str | None = None  # "Would isolate: TH-LT-1047"

    @model_validator(mode="after")
    def _validate(self) -> "ActionResult":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not be before started_at")
        if self.status is ActionResultStatus.SKIPPED and self.skip_reason is None:
            raise ValueError("SKIPPED results need a skip_reason")
        if self.status is not ActionResultStatus.SKIPPED and self.skip_reason is not None:
            raise ValueError("skip_reason is only valid for SKIPPED results")
        if self.status is ActionResultStatus.DRY_RUN and not self.dry_run_line:
            raise ValueError("DRY_RUN results need a dry_run_line")
        return self


class ContainmentReport(FrozenModel):
    report_id: str
    incident_id: str
    package_id: str
    token_id: str | None
    dry_run: bool
    started_at: AwareDatetime
    finished_at: AwareDatetime
    results: tuple[ActionResult, ...]
    overall: ContainmentOverall | None  # None when dry_run
    attention: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _dry_run_has_no_overall(self) -> "ContainmentReport":
        if self.dry_run and self.overall is not None:
            raise ValueError("a dry-run report has no overall containment state")
        return self


class RestorationReport(FrozenModel):
    report_id: str
    incident_id: str
    package_id: str
    token_id: str | None
    dry_run: bool
    started_at: AwareDatetime
    finished_at: AwareDatetime
    results: tuple[ActionResult, ...]
    overall: RestorationOverall | None
    attention: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _dry_run_has_no_overall(self) -> "RestorationReport":
        if self.dry_run and self.overall is not None:
            raise ValueError("a dry-run report has no overall restoration state")
        return self
