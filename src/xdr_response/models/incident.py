"""Incident, asset and state transition models. Incidents are frozen; changes produce copies."""
from __future__ import annotations

from typing import Any

from pydantic import AwareDatetime, Field, model_validator

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models.canonical import normalize_target
from xdr_response.models.enums import IncidentState, Severity, TargetKind
from xdr_response.models.observable import Observable

__all__ = ["Asset", "StateTransition", "Incident"]


class Asset(FrozenModel):
    name: str  # normalized target value
    kind: TargetKind
    groups: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    ip: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_name(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("name"), str) and data.get("kind") is not None:
            try:
                kind = TargetKind(data["kind"])
            except ValueError:
                return data
            data = {**data, "name": normalize_target(kind, data["name"])}
        return data


class StateTransition(FrozenModel):
    from_state: IncidentState
    to_state: IncidentState
    at: AwareDatetime
    actor: str = Field(min_length=1)  # principal id or "automation:<component>"
    reason: str = ""
    package_id: str | None = None
    token_id: str | None = None


class Incident(FrozenModel):
    incident_id: str = Field(min_length=1)
    title: str
    severity: Severity
    state: IncidentState = IncidentState.NOT_STARTED
    source: str = "cisco_xdr"
    created_at: AwareDatetime
    workflow_id: str
    workflow_version: str
    observables: tuple[Observable, ...] = ()
    assets: tuple[Asset, ...] = ()
    users: tuple[str, ...] = ()
    trigger: JsonDict = {}
    ai_narrative: str | None = None  # AI-written, flagged, never evidence
    history: tuple[StateTransition, ...] = ()
