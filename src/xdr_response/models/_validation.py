"""Validation helpers shared by RecommendedAction, ActionRequest and TemporaryControl."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from xdr_response.models.canonical import make_idempotency_key, normalize_target
from xdr_response.models.catalog import ActionType, get_action_spec
from xdr_response.models.enums import TargetKind


def check_integration_param(params: Mapping[str, Any], field: str = "params") -> str:
    integration = params.get("integration")
    if not isinstance(integration, str) or not integration:
        raise ValueError(f'{field} must contain "integration" (non-empty string)')
    return integration


def check_action_binding(
    *,
    incident_id: str,
    idempotency_key: str,
    action_type: ActionType,
    target: str,
    target_kind: TargetKind,
    params: Mapping[str, Any],
) -> None:
    spec = get_action_spec(action_type)
    if target_kind != spec.target_kind:
        raise ValueError(
            f"target_kind {target_kind.value} does not match catalog target kind "
            f"{spec.target_kind.value} for {action_type.value}"
        )
    if normalize_target(target_kind, target) != target:
        raise ValueError(f"target {target!r} is not normalized for {target_kind.value}")
    expected = make_idempotency_key(incident_id, action_type, target)
    if idempotency_key != expected:
        raise ValueError(f"idempotency_key must be {expected!r}")
    check_integration_param(params)
