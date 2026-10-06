"""Investigation query and result (Phase 0 minimal; Phase 1 adds typed result models)."""
from __future__ import annotations

from pydantic import AwareDatetime, Field, model_validator

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models._common import ApiCallSummary, ErrorInfo
from xdr_response.models.catalog import ActionType, get_action_spec
from xdr_response.models.enums import ActionCategory, HealthStatus
from xdr_response.models.evidence import EvidenceDraft
from xdr_response.models.observable import Observable

__all__ = ["InvestigationQuery", "InvestigationResult"]


class InvestigationQuery(FrozenModel):
    action_type: ActionType  # an INVESTIGATION-category action type
    subject: Observable
    time_from: AwareDatetime | None = None
    time_to: AwareDatetime | None = None
    limit: int = Field(default=100, ge=1, le=10000)
    options: JsonDict = {}

    @model_validator(mode="after")
    def _validate(self) -> "InvestigationQuery":
        if get_action_spec(self.action_type).category is not ActionCategory.INVESTIGATION:
            raise ValueError(f"{self.action_type.value} is not an INVESTIGATION action type")
        if self.time_from and self.time_to and self.time_to < self.time_from:
            raise ValueError("time_to must not be before time_from")
        return self


class InvestigationResult(FrozenModel):
    integration: str
    action_type: ActionType
    subject: Observable
    findings: tuple[JsonDict, ...] = ()
    evidence: tuple[EvidenceDraft, ...] = ()
    api_calls: tuple[ApiCallSummary, ...] = ()
    health: HealthStatus = HealthStatus.CONNECTED
    errors: tuple[ErrorInfo, ...] = ()
