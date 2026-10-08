"""Bridge from the legacy ``xdr_plan`` planner to runtime proposals (architecture 12, 14.3.8).

Legacy replay is a migration and regression tool: it turns a legacy scenario (incident, legacy
enrichment and investigation results, guardrails) and the legacy :class:`xdr_plan.planner.Plan`
into what the Phase 0 runtime understands:

* :func:`legacy_incident` builds the runtime :class:`Incident` (workflow version ``"legacy"``);
* :func:`legacy_records` turns every legacy result item into a citable :class:`GenericRecord`
  (and :func:`legacy_incident_record` the incident itself), so every proposal carries numbered
  evidence that cites real scenario data and nothing invented;
* :func:`guardrails_to_settings` maps the legacy guardrails onto critical assets, allow-lists and
  blast-radius caps, so ``PackageBuilder`` (not this module) decides ELEVATED and exclusions;
* :func:`bridge_plan` turns the planned legacy actions into :class:`ProposedAction` objects.

This module is in the read zone (14.0.1): it only builds data. It never executes, approves,
chooses an approval level or builds a package; the proposals go to ``PackageBuilder`` and wait for
a human decision. It is never on the production path (an unmigrated workflow takes the Phase 0
generic path) and is deleted at the end of Phase 5 together with ``engine/xdr_plan`` (14.4.3).
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from xdr_response.atomics.evidence import EvidenceBuilder, RecordIndex
from xdr_response.atomics.records import GenericRecord
from xdr_response.config import Settings
from xdr_response.models import (
    ActionType,
    Asset,
    CriticalAssetClass,
    Incident,
    Observable,
    ObservableType,
    ProposedAction,
    Severity,
    TargetKind,
    get_action_spec,
    normalize_target,
)

if TYPE_CHECKING:  # pragma: no cover - type only; the planner lives in engine/xdr_plan
    from xdr_plan.planner import Plan

    from xdr_response.atomics.containment.models import RouteDecision

__all__ = [
    "LEGACY_CONTAINMENT",
    "LEGACY_RESULT_SOURCES",
    "LEGACY_RESULT_SUBJECTS",
    "LEGACY_SEVERITY_RISK",
    "LEGACY_CONFIDENCE",
    "LEGACY_VERSION",
    "LEGACY_INCIDENT_ATOMIC",
    "LEGACY_PROTECTED_HOST_TAG",
    "LEGACY_PROTECTED_USER_TAG",
    "BridgedAction",
    "BridgeResult",
    "legacy_incident",
    "legacy_records",
    "legacy_incident_record",
    "guardrails_to_settings",
    "bridge_plan",
]

LEGACY_CONTAINMENT: Mapping[str, ActionType] = MappingProxyType({
    "isolate-endpoint": ActionType.ISOLATE_ENDPOINT,
    "block-domain": ActionType.BLOCK_DOMAIN,
    "block-url": ActionType.BLOCK_URL,
    "block-ip": ActionType.BLOCK_IP,
    "block-hash": ActionType.BLOCK_HASH,
    "disable-user": ActionType.DISABLE_USER,
    "revoke-session": ActionType.REVOKE_SESSIONS,
    "quarantine-email": ActionType.QUARANTINE_EMAIL,
})
"""Legacy containment atomic -> runtime action type."""

LEGACY_RESULT_SOURCES: Mapping[str, str] = MappingProxyType({
    "enrich-ip": "cisco_xdr",
    "enrich-domain": "umbrella",
    "enrich-hash": "cisco_xdr",
    "investigate-host": "secure_endpoint",
    "investigate-user": "entra",
})
"""Legacy read atomic -> the integration its result items are attributed to."""

LEGACY_RESULT_SUBJECTS: Mapping[str, tuple[str, ObservableType]] = MappingProxyType({
    "enrich-ip": ("ip", ObservableType.IP),
    "enrich-domain": ("domain", ObservableType.DOMAIN),
    "enrich-hash": ("sha256", ObservableType.SHA256),
    "investigate-host": ("host", ObservableType.HOSTNAME),
    "investigate-user": ("user", ObservableType.USER),
})
"""Legacy read atomic -> (result item field, observable type) naming the record's subject."""

LEGACY_SEVERITY_RISK: Mapping[str, int] = MappingProxyType(
    {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 90})
LEGACY_CONFIDENCE = 50
LEGACY_VERSION = "legacy"
LEGACY_INCIDENT_ATOMIC = "legacy:incident"
LEGACY_INCIDENT_INTEGRATION = "cisco_xdr"

#: Asset tags carried by a proposal whose legacy investigation item says ``is_protected: true``.
#: :func:`guardrails_to_settings` makes them critical-asset matches, so PackageBuilder elevates.
LEGACY_PROTECTED_HOST_TAG = "legacy-protected-host"
LEGACY_PROTECTED_USER_TAG = "legacy-protected-user"

#: Legacy incident observable types -> runtime observable types (others, such as
#: ``email_subject``, are kept in ``incident.trigger`` only).
_OBSERVABLE_TYPES: Mapping[str, ObservableType] = MappingProxyType({
    "ip": ObservableType.IP, "ipv6": ObservableType.IPV6, "domain": ObservableType.DOMAIN,
    "url": ObservableType.URL, "sha256": ObservableType.SHA256, "sha1": ObservableType.SHA1,
    "md5": ObservableType.MD5, "email": ObservableType.EMAIL_ADDRESS,
    "email_address": ObservableType.EMAIL_ADDRESS, "user": ObservableType.USER,
    "host": ObservableType.HOSTNAME, "hostname": ObservableType.HOSTNAME,
})
_HOST_FIELDS = ("host", "hostname")
_PLANNED = "planned"
#: ``xdr_plan.planner.PROTECTED_REASON`` (C3); kept literal so the runtime never imports the legacy engine.
_LEGACY_PROTECTED_REASON = "protected asset: ELEVATED approval required"


@dataclass(frozen=True)
class BridgedAction:
    """One legacy plan action and what the bridge made of it."""

    rule: str
    legacy_atomic: str
    legacy_target: str
    status: str                       # planned | skipped_allowlisted | skipped_internal
    elevated: bool                    # the legacy planner's verdict (PackageBuilder decides the runtime level)
    action_type: ActionType
    target: str                       # runtime target (isolate: host name from the result item)
    proposal: ProposedAction | None   # None for skipped and unrouted actions
    note: str = ""


@dataclass(frozen=True)
class BridgeResult:
    """Proposals for PackageBuilder plus what happened to every legacy action."""

    proposals: tuple[ProposedAction, ...]
    actions: tuple[BridgedAction, ...]
    records: tuple[GenericRecord, ...]
    unrouted: tuple[BridgedAction, ...]
    notes: tuple[str, ...]
    escalate: bool

    @property
    def risk_score(self) -> int:
        return max((p.risk_score for p in self.proposals), default=0)

    @property
    def confidence_score(self) -> int:
        return max((p.confidence_score for p in self.proposals), default=0)


# ----------------------------------------------------------------------------------- incident --
def _observable(kind: str, value: Any) -> Observable | None:
    """Runtime observable for a legacy ``{type, value}``; None for unknown types or bad values."""
    otype = _OBSERVABLE_TYPES.get(str(kind).strip().lower())
    if otype is None or value is None or not str(value).strip():
        return None
    text = str(value).strip()
    if otype is ObservableType.IP:
        try:
            otype = ObservableType.IPV6 if ipaddress.ip_address(text).version == 6 else ObservableType.IP
        except ValueError:
            return None
    try:
        return Observable(type=otype, value=text)
    except ValueError:
        return None


def legacy_incident(data: Mapping[str, Any], *, workflow_id: str, created_at: datetime) -> Incident:
    """The runtime incident of a legacy scenario ``incident`` block.

    ``id`` -> ``incident_id``, severity upper-cased, known observables, title, source, targets ->
    users / assets; ``workflow_version`` is ``"legacy"``. The legacy context, the observables the
    runtime has no type for and the targets are kept in ``trigger`` (data, never evidence by itself).
    """
    incident_id = str(data.get("id") or data.get("incident_id") or "").strip()
    if not incident_id:
        raise ValueError("a legacy incident needs an id")
    observables: list[Observable] = []
    unmapped: list[dict[str, Any]] = []
    for item in data.get("observables") or ():
        observable = _observable(item.get("type"), item.get("value")) if isinstance(item, Mapping) else None
        if observable is None:
            unmapped.append(dict(item) if isinstance(item, Mapping) else {"value": str(item)})
        elif observable not in observables:
            observables.append(observable)
    users: list[str] = []
    assets: list[Asset] = []
    for target in data.get("targets") or ():
        if not isinstance(target, Mapping) or not str(target.get("value") or "").strip():
            continue
        kind, value = str(target.get("type") or "").lower(), str(target["value"]).strip()
        if kind in ("endpoint", "host", "hostname"):
            asset = Asset(name=value, kind=TargetKind.ENDPOINT)
            if asset not in assets:
                assets.append(asset)
        elif kind in ("user", "email") and value.lower() not in users:
            users.append(value.lower())
    trigger = {"legacy_source": str(data.get("source") or ""), "legacy_context": dict(data.get("context") or {}),
               "legacy_targets": [dict(t) for t in data.get("targets") or () if isinstance(t, Mapping)],
               "legacy_unmapped_observables": unmapped}
    return Incident(
        incident_id=incident_id, title=str(data.get("title") or incident_id),
        severity=Severity(str(data.get("severity") or "medium").upper()),
        source=str(data.get("source") or "legacy"), created_at=created_at, workflow_id=workflow_id,
        workflow_version=LEGACY_VERSION, observables=tuple(observables), assets=tuple(assets),
        users=tuple(users), trigger=trigger)


# ------------------------------------------------------------------------------------ records --
def _record(atomic: str, item: Mapping[str, Any]) -> GenericRecord | None:
    """The GenericRecord of one legacy result item, or None when its subject cannot be parsed."""
    if atomic not in LEGACY_RESULT_SOURCES:
        raise ValueError(f"results.{atomic} is not a legacy enrichment or investigation atomic "
                         f"(known: {sorted(LEGACY_RESULT_SOURCES)})")
    field, otype = LEGACY_RESULT_SUBJECTS[atomic]
    value = item.get(field)
    if field == "host" and not value:
        value = item.get("hostname")
    observable = _observable(otype.value, value)
    if observable is None:
        return None
    try:
        return GenericRecord(integration=LEGACY_RESULT_SOURCES[atomic], atomic=f"legacy:{atomic}",
                             subject=observable, name=f"legacy:{atomic}", attributes=dict(item))
    except ValueError:
        return None


def legacy_records(results: Mapping[str, Sequence[Mapping[str, Any]]]) -> tuple[GenericRecord, ...]:
    """One :class:`GenericRecord` per legacy result item (items whose subject cannot be parsed are skipped).

    Integration ``LEGACY_RESULT_SOURCES[atomic]``, atomic and name ``"legacy:<atomic>"``, attributes
    the item (redacted and capped by the record model). Identical items share one record id.
    """
    records: list[GenericRecord] = []
    for atomic in results:
        for item in results[atomic] or ():
            record = _record(atomic, item) if isinstance(item, Mapping) else None
            if record is not None and record not in records:
                records.append(record)
    return tuple(records)


def legacy_incident_record(data: Mapping[str, Any]) -> GenericRecord | None:
    """The legacy incident itself as a citable record (title, source, observables, targets, context).

    Some legacy rules take their target from the incident (a reported sender, an alerted URL);
    this record is their evidence. Its subject is the first incident observable the runtime can
    parse; None when there is none.
    """
    subject = next((o for o in (_observable(i.get("type"), i.get("value"))
                                for i in data.get("observables") or () if isinstance(i, Mapping))
                    if o is not None), None)
    if subject is None:
        return None
    attributes = {key: data[key] for key in ("id", "title", "severity", "source", "observables", "targets",
                                             "context") if key in data}
    try:
        return GenericRecord(integration=LEGACY_INCIDENT_INTEGRATION, atomic=LEGACY_INCIDENT_ATOMIC,
                             subject=subject, name=LEGACY_INCIDENT_ATOMIC, attributes=attributes)
    except ValueError:
        return None


# ---------------------------------------------------------------------------------- guardrails --
def _is_network(pattern: str) -> bool:
    if "/" not in pattern and not pattern.replace(".", "").isdigit() and ":" not in pattern:
        return False
    try:
        ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False
    return True


def _strings(values: Any) -> list[str]:
    return [str(v).strip() for v in values or () if str(v).strip()]


def guardrails_to_settings(guardrails: Mapping[str, Any], base: Settings) -> Settings:
    """``base`` with critical assets, allow-lists and blast-radius caps taken from legacy guardrails.

    * ``protected.hosts`` -> critical asset class ``production_server`` (glob patterns as hostname
      patterns, CIDRs as IP ranges, plus the :data:`LEGACY_PROTECTED_HOST_TAG` tag);
    * ``protected.users`` / ``protected.groups`` -> ``privileged_account`` (user patterns, groups,
      plus :data:`LEGACY_PROTECTED_USER_TAG`);
    * ``allowlist.domains`` / ``ip_ranges`` / ``hashes`` -> ``allowlists.never_block`` domains / cidrs
      / hashes; ``url_block_allowed_domains`` as is; ``approved_rmm`` names -> ``approved_rmm``;
    * ``blast_radius`` max_hosts_isolated / max_users_disabled / max_indicators_blocked /
      max_messages_quarantined -> ``thresholds.blast_radius`` max_endpoints / max_users /
      max_indicators / max_messages.

    The base critical assets and allow-lists are replaced (not merged) so a replay is judged by the
    scenario's own guardrails. Everything else in ``base`` is kept. Approval-disabling keys never
    reach this point (``xdr_plan.repo.load_guardrails`` refuses them).
    """
    protected = guardrails.get("protected") or {}
    allow = guardrails.get("allowlist") or {}
    caps = guardrails.get("blast_radius") or {}
    hosts = _strings(protected.get("hosts"))
    host_cidrs = [h for h in hosts if _is_network(h)]
    data = base.model_dump()
    data["critical_assets"] = {"classes": {
        CriticalAssetClass.PRODUCTION_SERVER.value: {
            "display_name": "Protected host (legacy guardrails)",
            "role": "host listed in guardrails protected.hosts",
            "potential_impact": "Containment of a protected host needs ELEVATED approval (legacy guardrails C3).",
            "match": {"hostname_patterns": [h for h in hosts if h not in host_cidrs], "ip_cidrs": host_cidrs,
                      "tags": [LEGACY_PROTECTED_HOST_TAG]},
        },
        CriticalAssetClass.PRIVILEGED_ACCOUNT.value: {
            "display_name": "Protected account (legacy guardrails)",
            "role": "account listed in guardrails protected.users or protected.groups",
            "potential_impact": "Containment of a protected account needs ELEVATED approval (legacy guardrails C3).",
            "match": {"user_patterns": _strings(protected.get("users")), "groups": _strings(protected.get("groups")),
                      "tags": [LEGACY_PROTECTED_USER_TAG]},
        },
    }}
    data["allowlists"] = {
        "never_block": {"domains": _strings(allow.get("domains")), "cidrs": _strings(allow.get("ip_ranges")),
                        "hashes": [h.lower() for h in _strings(allow.get("hashes"))]},
        "url_block_allowed_domains": _strings(allow.get("url_block_allowed_domains")),
        "approved_rmm": [{"name": name} for name in _strings(allow.get("approved_rmm"))],
    }
    blast = dict(data["thresholds"]["blast_radius"])
    for legacy, runtime in (("max_hosts_isolated", "max_endpoints"), ("max_users_disabled", "max_users"),
                            ("max_indicators_blocked", "max_indicators"),
                            ("max_messages_quarantined", "max_messages")):
        if caps.get(legacy) is not None:
            blast[runtime] = int(caps[legacy])
    data["thresholds"]["blast_radius"] = blast
    return Settings.model_validate(data)


# -------------------------------------------------------------------------------------- bridge --
def _mentions(value: Any, needle: str) -> bool:
    """True when ``needle`` equals (case-insensitively) a string anywhere inside ``value``."""
    if isinstance(value, Mapping):
        return any(_mentions(v, needle) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_mentions(v, needle) for v in value)
    return isinstance(value, str) and value.strip().lower() == needle


def _source_item(results: Mapping[str, Sequence[Mapping[str, Any]]], source: tuple[str, int] | None
                 ) -> tuple[str, Mapping[str, Any]] | None:
    if source is None:
        return None
    key, index = source
    items = results.get(key) or ()
    if not 0 <= index < len(items) or not isinstance(items[index], Mapping):
        return None
    return key, items[index]


def _evidence_records(target: str, source: tuple[str, Mapping[str, Any]] | None,
                      results: Mapping[str, Sequence[Mapping[str, Any]]],
                      incident_data: Mapping[str, Any], incident_record: GenericRecord | None
                      ) -> list[GenericRecord]:
    """The source item's record; else every result record mentioning the target; else the incident."""
    if source is not None:
        record = _record(*source)
        if record is not None:
            return [record]
    needle = target.strip().lower()
    found: list[GenericRecord] = []
    for atomic in results:
        for item in results[atomic] or ():
            if isinstance(item, Mapping) and _mentions(item, needle):
                record = _record(atomic, item)
                if record is not None and record not in found:
                    found.append(record)
    if not found and incident_record is not None and _mentions(
            {k: incident_data.get(k) for k in ("observables", "targets", "context")}, needle):
        found.append(incident_record)
    return found


def _first_ip(item: Mapping[str, Any]) -> str | None:
    """The item's ``ip``, else a host field whose value is an IP address (legacy hosts can be IPs)."""
    for name in ("ip", *_HOST_FIELDS):
        value = item.get(name)
        if not value:
            continue
        try:
            return ipaddress.ip_address(str(value).strip()).compressed
        except ValueError:
            continue
    return None


def _runtime_target(atomic: str, legacy_target: str, item: Mapping[str, Any] | None
                    ) -> tuple[str, dict[str, Any], str]:
    """(runtime target, extra params, note). Isolation targets a host name, not a connector GUID."""
    if atomic != "isolate-endpoint":
        return legacy_target, {}, ""
    host = next((str(item[f]).strip() for f in _HOST_FIELDS if item and item.get(f)), "")
    if host:
        return host, {"connector_guid": legacy_target}, ""
    return legacy_target, {"connector_guid": legacy_target}, (
        "no host name in the legacy result item: the connector GUID is used as the endpoint name")


def _asset(action_type: ActionType, target: str, item: Mapping[str, Any] | None) -> Asset | None:
    """Investigated asset context of the legacy item (PackageBuilder merges it; it can only add)."""
    if not item:
        return None
    protected = bool(item.get("is_protected"))
    if action_type is ActionType.ISOLATE_ENDPOINT:
        return Asset(name=target, kind=TargetKind.ENDPOINT, ip=_first_ip(item),
                     tags=(LEGACY_PROTECTED_HOST_TAG,) if protected else ())
    if action_type in (ActionType.DISABLE_USER, ActionType.REVOKE_SESSIONS):
        profile = item.get("profile") if isinstance(item.get("profile"), Mapping) else {}
        return Asset(name=target, kind=TargetKind.USER, groups=tuple(_strings(profile.get("groups"))),
                     tags=(LEGACY_PROTECTED_USER_TAG,) if protected else ())
    return None


def _legacy_protected(action: Any) -> bool:
    """True when the legacy planner elevated the action for a protected asset (C3).

    An elevation explained only by blast-radius caps (C5) is not a protected-asset verdict;
    PackageBuilder applies its own caps. An elevation with no reason at all is treated as
    protected (the runtime may be stricter, never weaker: 14.9.1).
    """
    if not action.elevated:
        return False
    reasons = [str(r) for r in action.reasons or ()]
    return _LEGACY_PROTECTED_REASON in reasons or not reasons


def _protected_asset(action_type: ActionType, target: str, asset: Asset | None) -> Asset | None:
    """``asset`` plus the legacy protected tag of the action's kind (it can only add)."""
    if action_type is ActionType.ISOLATE_ENDPOINT:
        kind, tag = TargetKind.ENDPOINT, LEGACY_PROTECTED_HOST_TAG
    elif action_type in (ActionType.DISABLE_USER, ActionType.REVOKE_SESSIONS):
        kind, tag = TargetKind.USER, LEGACY_PROTECTED_USER_TAG
    else:
        return asset
    if asset is None:
        return Asset(name=target, kind=kind, tags=(tag,))
    return asset.model_copy(update={"tags": tuple(dict.fromkeys((*asset.tags, tag)))})


def bridge_plan(plan: "Plan", *, incident: Incident, results: Mapping[str, Sequence[Mapping[str, Any]]],
                route: "Callable[[ActionType, str], RouteDecision]",
                incident_data: Mapping[str, Any] | None = None) -> BridgeResult:
    """Turn the planned actions of a legacy plan into proposals for ``PackageBuilder``.

    Evidence is the GenericRecord of ``Action.source`` (results key and index), else every legacy
    record whose attributes mention the target, else the legacy incident record when the incident
    (observables, targets, context) mentions it. Risk is ``LEGACY_SEVERITY_RISK[severity]``,
    confidence ``LEGACY_CONFIDENCE``. ``skipped_*`` actions are not proposed; a planned action
    without a route or without any citable record is reported (``unrouted``) instead of proposed.
    The legacy ``elevated`` flag is never copied into the proposal as an approval level: ELEVATED
    comes from ``PackageBuilder`` (critical assets from :func:`guardrails_to_settings`, investigated
    asset context, blast-radius caps). When the legacy planner elevated an action for a protected
    asset (C3: ``PROTECTED_REASON``, or an elevation with no reason), the proposal asset carries
    :data:`LEGACY_PROTECTED_HOST_TAG` / :data:`LEGACY_PROTECTED_USER_TAG`, so the bridged package is
    never weaker than the legacy verdict (a host protected by GUID or IP glob, a user protected by
    upn/email, a protected item that is not the plan source).
    """
    records = list(legacy_records(results))
    data = dict(incident_data or {})
    incident_record = legacy_incident_record(data) if data else None
    risk = LEGACY_SEVERITY_RISK[incident.severity.value.lower()]
    actions: list[BridgedAction] = []
    proposals: list[ProposedAction] = []
    unrouted: list[BridgedAction] = []
    notes: list[str] = [*plan.reasons]
    for action in plan.actions:
        action_type = LEGACY_CONTAINMENT.get(action.atomic)
        if action_type is None:
            raise ValueError(f"legacy atomic {action.atomic!r} is not a containment atomic")
        source = _source_item(results, action.source)
        item = source[1] if source else None
        raw_target, extra, note = _runtime_target(action.atomic, str(action.target), item)
        kind = get_action_spec(action_type).target_kind
        try:
            target = normalize_target(kind, raw_target)
        except ValueError as exc:
            target, note = raw_target, f"target cannot be normalized: {exc}"
        base = dict(rule=action.rule, legacy_atomic=action.atomic, legacy_target=str(action.target),
                    status=action.status, elevated=bool(action.elevated), action_type=action_type, target=target)
        if action.status != _PLANNED:
            actions.append(BridgedAction(**base, proposal=None, note=f"not proposed: {action.status}"))
            continue
        bridged = _bridge_one(action, base, target, kind, extra, note, item, results, data, incident_record,
                              risk, route)
        actions.append(bridged)
        if bridged.proposal is None:
            unrouted.append(bridged)
            notes.append(f"legacy rule {action.rule}: {action_type.value} {target} not proposed ({bridged.note})")
        else:
            proposals.append(bridged.proposal)
    cited = {rid for proposal in proposals for rid in EvidenceBuilder.record_ids(proposal.evidence)}
    if incident_record is not None and incident_record.record_id in cited and incident_record not in records:
        records.append(incident_record)
    return BridgeResult(proposals=tuple(proposals), actions=tuple(actions), records=tuple(records),
                        unrouted=tuple(unrouted), notes=tuple(notes), escalate=bool(plan.escalate))


def _bridge_one(action: Any, base: Mapping[str, Any], target: str, kind: TargetKind, extra: Mapping[str, Any],
                note: str, item: Mapping[str, Any] | None, results: Mapping[str, Sequence[Mapping[str, Any]]],
                incident_data: Mapping[str, Any], incident_record: GenericRecord | None, risk: int,
                route: "Callable[[ActionType, str], RouteDecision]") -> BridgedAction:
    if note.startswith("target cannot be normalized"):
        return BridgedAction(**base, proposal=None, note=note)
    source = _source_item(results, action.source)
    cited = _evidence_records(str(action.target), source, results, incident_data, incident_record)
    if base["action_type"] is ActionType.ISOLATE_ENDPOINT and not cited:
        cited = _evidence_records(target, None, results, incident_data, incident_record)
    if not cited:
        return BridgedAction(**base, proposal=None, note="no legacy record mentions the target (no evidence)")
    try:
        decision = route(base["action_type"], target)
    except ValueError as exc:
        return BridgedAction(**base, proposal=None, note=f"cannot route: {exc}")
    if decision.integration is None:
        return BridgedAction(**base, proposal=None, note=decision.reason or "no route")
    evidence = EvidenceBuilder(RecordIndex(records=cited)).cite(r.record_id for r in cited)
    reasons = "; ".join(action.reasons)
    rationale = f"legacy plan rule {action.rule} (replay; scores not computed)" + (
        f"; legacy guardrails: {reasons}" if reasons else "")
    asset = _asset(base["action_type"], target, item)
    if _legacy_protected(action):
        asset = _protected_asset(base["action_type"], target, asset)
    proposal = ProposedAction(
        action_type=base["action_type"], target=target, target_kind=kind,
        params={**dict(decision.params), **dict(extra)}, evidence=evidence, risk_score=risk,
        confidence_score=LEGACY_CONFIDENCE, rationale=rationale, asset=asset)
    return BridgedAction(**base, proposal=proposal, note=note)
