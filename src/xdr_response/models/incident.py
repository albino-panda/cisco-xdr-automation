"""Incident, asset and state transition models. Incidents are frozen; changes produce copies."""
from __future__ import annotations

from typing import Any

from pydantic import AwareDatetime, Field, model_validator

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models.canonical import normalize_target
from xdr_response.models.enums import IncidentState, Severity, TargetKind
from xdr_response.models.observable import Observable

__all__ = ["Asset", "StateTransition", "Incident", "asset_addresses", "merge_asset_context"]


class Asset(FrozenModel):
    name: str  # normalized target value
    kind: TargetKind
    groups: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    ip: str | None = None
    #: Further addresses of the asset (a host's other interfaces, as its records report them). Matched
    #: against the critical-asset ``ip_cidrs`` like ``ip``: any address in a critical range counts.
    ips: tuple[str, ...] = ()
    #: The identity source marks the account privileged (``UserProfileRecord.privileged``: a flag of
    #: the source, or a directory role it reports outside the static role list). An account with
    #: this flag is in the ``privileged_account`` critical-asset class.
    privileged: bool = False
    #: Accounts that use the asset (an endpoint's logged-on users, a message's recipient mailboxes).
    #: Matched against the critical-asset ``users`` / ``user_patterns`` (executive endpoint or mailbox).
    users: tuple[str, ...] = ()

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


def asset_addresses(*assets: Asset | None) -> tuple[str, ...]:
    """Every address (``ip`` and ``ips``) of the given assets, first-seen order, without duplicates."""
    out: dict[str, None] = {}
    for asset in assets:
        if asset is None:
            continue
        for value in (asset.ip, *asset.ips):
            if value and value.strip():
                out.setdefault(value.strip(), None)
    return tuple(out)


def merge_asset_context(primary: Asset, extra: Asset) -> Asset:
    """``primary`` with the context of ``extra`` added (never removed): groups, tags, roles, users and
    addresses unioned, ``privileged`` when either says so. ``primary`` keeps its name and first IP."""
    def merged(a: tuple[str, ...], b: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*a, *b)))

    ip = primary.ip or extra.ip
    return primary.model_copy(update={
        "groups": merged(primary.groups, extra.groups), "tags": merged(primary.tags, extra.tags),
        "roles": merged(primary.roles, extra.roles), "users": merged(primary.users, extra.users),
        "ip": ip, "ips": tuple(a for a in asset_addresses(primary, extra) if a != (ip or "").strip()),
        "privileged": primary.privileged or extra.privileged,
    })


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
