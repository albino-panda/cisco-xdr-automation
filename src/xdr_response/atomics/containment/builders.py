"""Containment recommendation builders (architecture 14.1.7): recommend, never execute.

Every builder turns a workflow rule's decision into a :class:`BuiltRecommendation` holding a
:class:`ProposedAction`. It normalizes the target, chooses the integration native first
(:func:`choose_route`), previews the critical-asset warnings (ELEVATED approval with a visible
warning, never a silent skip) and the allow-list exclusion, and exposes the catalog rollback.

What a builder never does: call an adapter write, enter a guard context, construct a token,
``RecommendedAction``, ``ActionRequest`` or package, or choose an approval level. ``PackageBuilder``
packages the proposal, a human approves it, and only then does the lifecycle orchestrator execute.

The builder function names match the brief (``block_ip``, ``quarantine_email`` ...); they are
recommendation builders and share only their names with the adapter methods.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal

from xdr_response.approval.critical_assets import find_incident_asset
from xdr_response.atomics.containment.models import BuiltRecommendation
from xdr_response.atomics.containment.routing import (
    _containment_spec,
    _normalize_containment_target,
    choose_route,
)
from xdr_response.config import FORBIDDEN_KEYS
from xdr_response.errors import UnverifiedEndpointError
from xdr_response.logs import get_redactor
from xdr_response.models.catalog import ActionType
from xdr_response.models.enums import TargetKind
from xdr_response.models.evidence import EvidenceDraft
from xdr_response.models.incident import Asset
from xdr_response.models.recommendation import ProposedAction

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.context import AtomicContext

__all__ = [
    "APPROVAL_MARKER_KEYS",
    "RESERVED_PARAM_KEYS",
    "build_containment",
    "isolate_secure_endpoint",
    "isolate_defender_endpoint",
    "block_domain_umbrella",
    "block_url",
    "block_ip",
    "block_hash",
    "revoke_entra_sessions",
    "disable_entra_user",
    "quarantine_email",
    "delete_malicious_email",
    "intune_device_action",
    "terminate_process",
    "quarantine_file",
    "remove_persistence",
    "remove_privileged_role",
    "CONTAINMENT_BUILDERS",
]

#: Keys that would mark an action as (not) needing approval; refused at every depth of the params.
#: The same set as the workflow definition's ``APPROVAL_LIKE_KEYS``: the builder is never weaker.
APPROVAL_MARKER_KEYS: frozenset[str] = frozenset(FORBIDDEN_KEYS) | frozenset(
    {"approval_level", "requires_approval", "approve", "approved"})

#: Param keys only the router (or the restoration planner / package builder) may set.
RESERVED_PARAM_KEYS: frozenset[str] = frozenset({
    "integration", "verify_integration", "restores", "module_instance_id", "action_id",
    "observable_type", "observable_value", "approval_level",
}) | APPROVAL_MARKER_KEYS

#: Soft deletes the email adapters support; a hard delete is never recommended.
_SOFT_DELETE_ACTIONS = frozenset({"softDelete", "moveToDeletedItems"})
_RECORD_ID = re.compile(r"rec_[0-9a-f]{32}")
_ENDPOINT_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS,
                             TargetKind.PERSISTENCE_ITEM})
_USER_KINDS = frozenset({TargetKind.USER, TargetKind.ROLE_ASSIGNMENT})
_COMPOSITE_KINDS = frozenset({TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM,
                              TargetKind.ROLE_ASSIGNMENT})


class _UnverifiedDeviceActionError(UnverifiedEndpointError, ValueError):
    """An Intune device action other than ``lock``: UNVERIFIED in docs/integrations.md."""


# ------------------------------------------------------------- validation --
def _check_score(name: str, value: object) -> int:
    """An int in 0..100 (bool refused)."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ValueError(f"{name} must be an int in 0..100, got {value!r}")
    return value


def _check_evidence(evidence: Sequence[EvidenceDraft]) -> tuple[EvidenceDraft, ...]:
    """At least one draft; every draft cites an investigation or enrichment record by id."""
    drafts = tuple(evidence)
    if not drafts:
        raise ValueError("a containment recommendation needs at least one evidence item")
    for draft in drafts:
        if not isinstance(draft, EvidenceDraft):
            raise ValueError(f"evidence must be EvidenceDraft objects, got {type(draft).__name__}")
        record_id = draft.data.get("record_id")
        if not isinstance(record_id, str) or not _RECORD_ID.fullmatch(record_id):
            raise ValueError("every evidence item must cite a record (data['record_id']); "
                             "build evidence with the evidence builder, never by hand")
    return drafts


def _check_key(key: object, *, top_level: bool) -> str:
    """A string param key that is neither reserved (top level), approval-bypassing nor sensitive."""
    if not isinstance(key, str) or not key.strip():
        raise ValueError(f"param keys must be non-empty strings, got {key!r}")
    folded = key.strip().lower()
    if top_level and folded in RESERVED_PARAM_KEYS:
        raise ValueError(f"param {key!r} is reserved for the router and the approval engine")
    if folded in APPROVAL_MARKER_KEYS:
        raise ValueError(f"param {key!r} is an approval marker; approval is never a param (any depth)")
    if get_redactor().is_sensitive_key(key):
        raise ValueError(f"param {key!r} looks like a secret; params never carry credentials")
    return key


def _json_value(value: Any, path: str) -> Any:
    """A deep, JSON-compatible copy of ``value``; floats and non-JSON types are refused."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        raise ValueError(f"param {path} is a float; params are hashed canonically and must not use floats")
    if isinstance(value, Mapping):
        return {_check_key(k, top_level=False): _json_value(v, f"{path}.{k}") for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(v, f"{path}[{i}]") for i, v in enumerate(value)]
    raise ValueError(f"param {path} has a non-JSON type {type(value).__name__}")


def _check_params(params: Mapping[str, Any] | None) -> dict[str, Any]:
    """Caller params, validated and copied (reserved, bypass and sensitive keys refused)."""
    if params is None:
        return {}
    if not isinstance(params, Mapping):
        raise ValueError("params must be a mapping")
    return {_check_key(k, top_level=True): _json_value(v, str(k)) for k, v in params.items()}


def _check_action_params(action_type: ActionType, params: Mapping[str, Any]) -> None:
    """Action-specific rules: an email delete is always a soft delete."""
    if action_type is ActionType.DELETE_EMAIL:
        choice = params.get("delete_action")
        if choice is not None and choice not in _SOFT_DELETE_ACTIONS:
            raise ValueError(f"delete_action must be one of {sorted(_SOFT_DELETE_ACTIONS)}; "
                             "a hard delete is never recommended")


def _check_rationale(rationale: object) -> str:
    """A non-empty, redacted rationale (derived statements belong here, never in evidence)."""
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("a containment recommendation needs a rationale")
    return get_redactor().redact_text(rationale.strip())


# ---------------------------------------------------------------- preview --
def _merge_assets(primary: Asset | None, extra: Asset | None) -> Asset | None:
    """Union of two asset contexts (groups, tags, roles); ``primary`` wins for the IP."""
    if primary is None or extra is None:
        return primary or extra
    return primary.model_copy(update={
        "groups": tuple(dict.fromkeys((*primary.groups, *extra.groups))),
        "tags": tuple(dict.fromkeys((*primary.tags, *extra.tags))),
        "roles": tuple(dict.fromkeys((*primary.roles, *extra.roles))),
        "ip": primary.ip or extra.ip,
    })


def _preview_asset(ctx: "AtomicContext", target: str, kind: TargetKind, asset: Asset | None) -> Asset | None:
    """The incident's asset record for the target merged with the caller's (never shrinks).

    The record is found by name, or for an IP-named endpoint by the asset's ``ip``
    (:func:`~xdr_response.approval.critical_assets.find_incident_asset`, as ``PackageBuilder`` does).
    """
    name = target.partition("/")[0] if kind in _COMPOSITE_KINDS else target
    wanted = TargetKind.ENDPOINT if kind in _ENDPOINT_KINDS else TargetKind.USER if kind in _USER_KINDS else kind
    return _merge_assets(find_incident_asset(ctx.incident.assets, name, wanted), asset)


# ------------------------------------------------------------------ build --
def build_containment(ctx: "AtomicContext", action_type: ActionType, target: str, *,
                      evidence: Sequence[EvidenceDraft], risk_score: int, confidence_score: int, rationale: str,
                      asset: Asset | None = None, params: Mapping[str, Any] | None = None,
                      product: str | None = None) -> BuiltRecommendation:
    """Build one containment recommendation (never executes anything).

    ValueError (a caller bug) when the action type is not CONTAINMENT or REMEDIATION, the evidence
    is empty or cites no record, params use a reserved, bypass or sensitive key or contain floats,
    the scores are out of range, the rationale is empty or the target cannot be normalized.
    The proposal params are the caller's params plus the route params (the route wins).
    An unroutable action is still returned (``proposal=None`` with ``unrouted_reason``) so it is
    reported for manual handling instead of being dropped.
    """
    spec = _containment_spec(action_type)
    drafts = _check_evidence(evidence)
    risk = _check_score("risk_score", risk_score)
    confidence = _check_score("confidence_score", confidence_score)
    text = _check_rationale(rationale)
    caller_params = _check_params(params)
    _check_action_params(spec.action_type, caller_params)
    if asset is not None and not isinstance(asset, Asset):
        raise ValueError("asset must be an Asset or None")
    normalized = _normalize_containment_target(spec.target_kind, target)
    route = choose_route(ctx, spec.action_type, normalized, product=product)
    preview = _preview_asset(ctx, normalized, spec.target_kind, asset)
    warnings = tuple(ctx.critical_assets.evaluate(spec.action_type, normalized, spec.target_kind, preview))
    excluded = ctx.allowlists.excluded_reason(spec.action_type, normalized, spec.target_kind)
    proposal = None
    if route.integration is not None:
        proposal = ProposedAction(action_type=spec.action_type, target=normalized, target_kind=spec.target_kind,
                                  params={**caller_params, **route.params}, evidence=drafts, risk_score=risk,
                                  confidence_score=confidence, rationale=text, asset=asset)
    return BuiltRecommendation(action_type=spec.action_type, target=normalized, proposal=proposal, route=route,
                               warnings=warnings, excluded_reason=excluded,
                               unrouted_reason=None if proposal is not None else route.reason)


# ---------------------------------------------------------- named builders --
def _named(ctx: "AtomicContext", action_type: ActionType, product: str | None, target: str,
           evidence: Sequence[EvidenceDraft], risk_score: int, confidence_score: int, rationale: str,
           asset: Asset | None, params: Mapping[str, Any] | None) -> BuiltRecommendation:
    """Shared body of the named builders: :func:`build_containment` with a fixed type and product."""
    return build_containment(ctx, action_type, target, evidence=evidence, risk_score=risk_score,
                             confidence_score=confidence_score, rationale=rationale, asset=asset,
                             params=params, product=product)


def isolate_secure_endpoint(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                            risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                            params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend isolating an endpoint in Secure Endpoint (native or direct; rollback release_endpoint)."""
    return _named(ctx, ActionType.ISOLATE_ENDPOINT, "secure_endpoint", target, evidence, risk_score,
                  confidence_score, rationale, asset, params)


def isolate_defender_endpoint(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                              risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                              params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend isolating an endpoint in Defender for Endpoint (native or direct; rollback release_endpoint)."""
    return _named(ctx, ActionType.ISOLATE_ENDPOINT, "defender_endpoint", target, evidence, risk_score,
                  confidence_score, rationale, asset, params)


def block_domain_umbrella(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                          risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                          params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend blocking a domain in Umbrella (native or direct; rollback unblock_domain)."""
    return _named(ctx, ActionType.BLOCK_DOMAIN, "umbrella", target, evidence, risk_score, confidence_score,
                  rationale, asset, params)


def block_url(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft], risk_score: int,
              confidence_score: int, rationale: str, asset: Asset | None = None,
              params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend blocking a URL (catalog order; rollback unblock_url)."""
    return _named(ctx, ActionType.BLOCK_URL, None, target, evidence, risk_score, confidence_score, rationale,
                  asset, params)


def block_ip(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft], risk_score: int,
             confidence_score: int, rationale: str, asset: Asset | None = None,
             params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend blocking an IP address (catalog order; rollback unblock_ip)."""
    return _named(ctx, ActionType.BLOCK_IP, None, target, evidence, risk_score, confidence_score, rationale,
                  asset, params)


def block_hash(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft], risk_score: int,
               confidence_score: int, rationale: str, asset: Asset | None = None,
               params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend blocking a file hash (catalog order; rollback unblock_hash)."""
    return _named(ctx, ActionType.BLOCK_HASH, None, target, evidence, risk_score, confidence_score, rationale,
                  asset, params)


def revoke_entra_sessions(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                          risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                          params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend revoking a user's Entra sign-in sessions (direct only; not reversible)."""
    return _named(ctx, ActionType.REVOKE_SESSIONS, "entra", target, evidence, risk_score, confidence_score,
                  rationale, asset, params)


def disable_entra_user(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                       risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                       params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend disabling an Entra user (native or direct; rollback enable_user)."""
    return _named(ctx, ActionType.DISABLE_USER, "entra", target, evidence, risk_score, confidence_score,
                  rationale, asset, params)


def quarantine_email(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft], risk_score: int,
                     confidence_score: int, rationale: str, asset: Asset | None = None,
                     params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend quarantining an email message (catalog order; rollback release_email)."""
    return _named(ctx, ActionType.QUARANTINE_EMAIL, None, target, evidence, risk_score, confidence_score,
                  rationale, asset, params)


def delete_malicious_email(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                           risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                           params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend a soft delete of an email message (catalog order; never a hard delete; not reversible)."""
    return _named(ctx, ActionType.DELETE_EMAIL, None, target, evidence, risk_score, confidence_score,
                  rationale, asset, params)


def intune_device_action(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                         risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                         params: Mapping[str, Any] | None = None,
                         action: Literal["lock"] = "lock") -> BuiltRecommendation:
    """Recommend an Intune remote lock (direct; not reversible).

    Only ``action="lock"`` is VERIFIED; any other device action raises a ``ValueError`` that is
    also an :class:`~xdr_response.errors.UnverifiedEndpointError`.
    """
    if action != "lock":
        raise _UnverifiedDeviceActionError("intune", f"device_action:{action}")
    return _named(ctx, ActionType.LOCK_DEVICE, "intune", target, evidence, risk_score, confidence_score,
                  rationale, asset, params)


def terminate_process(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                      risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                      params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend terminating a process (``<ENDPOINT>/<sha256 or pid>``; unrouted with real adapters)."""
    return _named(ctx, ActionType.TERMINATE_PROCESS, None, target, evidence, risk_score, confidence_score,
                  rationale, asset, params)


def quarantine_file(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft], risk_score: int,
                    confidence_score: int, rationale: str, asset: Asset | None = None,
                    params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend quarantining a file (``<ENDPOINT>/<sha256>``; rollback restore_file; unrouted with real adapters)."""
    return _named(ctx, ActionType.QUARANTINE_FILE, None, target, evidence, risk_score, confidence_score,
                  rationale, asset, params)


def remove_persistence(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                       risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                       params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend removing a persistence item (``<ENDPOINT>/<item id>``; no adapter: always unrouted)."""
    return _named(ctx, ActionType.REMOVE_PERSISTENCE, None, target, evidence, risk_score, confidence_score,
                  rationale, asset, params)


def remove_privileged_role(ctx: "AtomicContext", target: str, *, evidence: Sequence[EvidenceDraft],
                           risk_score: int, confidence_score: int, rationale: str, asset: Asset | None = None,
                           params: Mapping[str, Any] | None = None) -> BuiltRecommendation:
    """Recommend removing a privileged role (``<user>/<roleDefinitionId>``; always ELEVATED by the catalog)."""
    return _named(ctx, ActionType.REMOVE_PRIVILEGED_ROLE, "entra", target, evidence, risk_score,
                  confidence_score, rationale, asset, params)


#: The 15 named builders (the brief's names), composed by ``atomics.containment_builders()``.
CONTAINMENT_BUILDERS: Mapping[str, Callable[..., BuiltRecommendation]] = MappingProxyType({
    "isolate_secure_endpoint": isolate_secure_endpoint,
    "isolate_defender_endpoint": isolate_defender_endpoint,
    "block_domain_umbrella": block_domain_umbrella,
    "block_url": block_url,
    "block_ip": block_ip,
    "block_hash": block_hash,
    "revoke_entra_sessions": revoke_entra_sessions,
    "disable_entra_user": disable_entra_user,
    "quarantine_email": quarantine_email,
    "delete_malicious_email": delete_malicious_email,
    "intune_device_action": intune_device_action,
    "terminate_process": terminate_process,
    "quarantine_file": quarantine_file,
    "remove_persistence": remove_persistence,
    "remove_privileged_role": remove_privileged_role,
})
