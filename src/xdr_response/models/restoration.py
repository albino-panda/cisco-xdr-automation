"""Temporary control registry entry."""
from __future__ import annotations

from pydantic import AwareDatetime, Field, field_validator, model_validator

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models._common import ErrorInfo
from xdr_response.models._validation import check_integration_param
from xdr_response.models.canonical import make_idempotency_key
from xdr_response.models.catalog import ActionType, get_action_spec
from xdr_response.models.enums import ApprovalLevel, ControlStatus, TargetKind

__all__ = ["TemporaryControl"]


class TemporaryControl(FrozenModel):
    control_key: str = Field(min_length=1)  # == idempotency key of the containment action
    incident_id: str
    action_type: ActionType
    target: str
    target_kind: TargetKind
    integration: str
    workflow_id: str
    workflow_version: str
    package_id: str
    token_id: str
    decision_id: str
    approval_level: ApprovalLevel
    created_at: AwareDatetime
    rollback_action_type: ActionType
    rollback_params: JsonDict  # must contain "integration"
    external_ref: str | None = None
    status: ControlStatus = ControlStatus.ACTIVE
    review_due_at: AwareDatetime | None = None
    released_at: AwareDatetime | None = None
    release_package_id: str | None = None
    release_token_id: str | None = None
    last_error: ErrorInfo | None = None

    @field_validator("rollback_params")
    @classmethod
    def _integration(cls, value: JsonDict) -> JsonDict:
        check_integration_param(value, "rollback_params")
        return value

    @model_validator(mode="after")
    def _validate(self) -> "TemporaryControl":
        spec = get_action_spec(self.action_type)
        if not spec.creates_control:
            raise ValueError(f"{self.action_type.value} does not create a temporary control")
        if spec.rollback_action_type != self.rollback_action_type:
            raise ValueError(
                f"rollback for {self.action_type.value} must be {spec.rollback_action_type}"
            )
        expected = make_idempotency_key(self.incident_id, self.action_type, self.target)
        if self.control_key != expected:
            raise ValueError(f"control_key must be {expected!r} (incident, action type and target of the control)")
        if self.status is ControlStatus.RELEASED and self.released_at is None:
            raise ValueError("RELEASED controls need released_at")
        return self
