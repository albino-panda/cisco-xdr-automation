"""Blast radius / scoping (architecture section 14.1.5).

Pure: reads the incident, the correlation result, the run's records, the blast-radius thresholds and
the critical-asset policy from the context; never calls an adapter. ``exceeds`` and the critical-asset
hits are informational: ``PackageBuilder`` alone decides ELEVATED approval (13.25), and a critical
asset in scope is always reported, never skipped.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

from xdr_response.atomics.correlation.aliases import EntityAliases
from xdr_response.atomics.correlation.correlate import _Mentions, _observable_entity, _ref, _resolve_aliases
from xdr_response.atomics.correlation.models import (
    BLAST_RADIUS_CAP_NAMES,
    BlastRadiusReport,
    CorrelationResult,
    CriticalAssetHit,
    EntityRef,
)
from xdr_response.atomics.evidence import RecordIndex
from xdr_response.atomics.records import EmailMessageRecord, EndpointRecord, UserProfileRecord
from xdr_response.models.enums import TargetKind
from xdr_response.models.incident import Asset, Incident

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.context import AtomicContext
    from xdr_response.atomics.records import AtomicResult

__all__ = ["blast_radius"]

_INDICATOR_KINDS = (TargetKind.DOMAIN, TargetKind.URL, TargetKind.IP, TargetKind.HASH)
_ASSET_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.USER})
_CLASSIFIED_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.USER, TargetKind.EMAIL_ADDRESS, TargetKind.IP})


def _incident_entities(incident: Incident, aliases: EntityAliases | None = None) -> tuple[EntityRef, ...]:
    """Entities the incident itself names: observables, assets and users (sorted, unique, canonical)."""
    aliases = aliases if aliases is not None else EntityAliases()
    refs = [_observable_entity(o) for o in incident.observables]
    refs += [_ref(a.kind, a.name) for a in incident.assets]
    refs += [_ref(TargetKind.USER, u) for u in incident.users]
    unique = {c.key(): c for c in (aliases.canon(r) for r in refs if r is not None)}
    return tuple(sorted(unique.values(), key=EntityRef.sort_key))


def _default_scope(incident: Incident, correlation: CorrelationResult, index: RecordIndex,
                   mentions: _Mentions) -> dict[str, EntityRef]:
    """The clusters that contain an incident entity (plus those entities), widened by one hop.

    The hop adds what a record about an in-scope entity names directly, without waiting for a
    two-asset link rule: the endpoints and users it mentions (a hash seen on one endpoint puts that
    endpoint in scope) and, for an in-scope email message, its recipients and carried indicators.
    Indicators other records merely mention (any domain a host queried) are not added.
    """
    scope: dict[str, EntityRef] = {}
    for seed in _incident_entities(incident, mentions.aliases):
        scope[seed.key()] = seed
        for entity in correlation.cluster_of(seed):
            scope.setdefault(entity.key(), entity)
    for key in sorted(scope):
        for record_id in mentions.by_entity.get(key, []):
            record = index.get(record_id)
            carried = isinstance(record, EmailMessageRecord) and scope[key].kind is TargetKind.EMAIL_MESSAGE
            for entity in mentions.by_record[record_id]:
                if entity.kind in _ASSET_KINDS or (carried and entity.kind in _INDICATOR_KINDS):
                    scope.setdefault(entity.key(), entity)
    return scope


def _values(scope: dict[str, EntityRef], kinds: Iterable[TargetKind]) -> tuple[str, ...]:
    """Values of the scope entities of these kinds, grouped by kind in the given order, sorted inside."""
    out: list[str] = []
    for kind in kinds:
        out += sorted({e.value for e in scope.values() if e.kind is kind} - set(out))
    return tuple(out)


def _asset_context(entity: EntityRef, index: RecordIndex, incident: Incident,
                   aliases: EntityAliases | None = None) -> Asset | None:
    """Groups, tags, roles and first IP the run's own records (and the incident) report for an asset.

    With aliases, the records and incident assets of every spelling of the entity contribute.
    """
    aliases = aliases if aliases is not None else EntityAliases()

    def same(kind: TargetKind, value: str | None) -> bool:
        ref = _ref(kind, value)
        return ref is not None and aliases.canon(ref) == entity

    groups: list[str] = []
    tags: list[str] = []
    roles: list[str] = []
    ip: str | None = None
    for record in index.records():
        if isinstance(record, EndpointRecord) and entity.kind is TargetKind.ENDPOINT \
                and same(TargetKind.ENDPOINT, record.hostname):
            groups += record.groups
            tags += record.tags
            ip = ip or (record.ip_addresses[0] if record.ip_addresses else None)
        elif isinstance(record, UserProfileRecord) and entity.kind is TargetKind.USER \
                and same(TargetKind.USER, record.user):
            groups += record.groups
            roles += record.roles
    for asset in incident.assets:
        if asset.kind is entity.kind and (asset.name == entity.value or same(asset.kind, asset.name)):
            groups += asset.groups
            tags += asset.tags
            roles += asset.roles
            ip = ip or asset.ip
    if not (groups or tags or roles or ip) or entity.kind not in (TargetKind.ENDPOINT, TargetKind.USER):
        return None
    return Asset(name=entity.value, kind=entity.kind, groups=tuple(dict.fromkeys(groups)),
                 tags=tuple(dict.fromkeys(tags)), roles=tuple(dict.fromkeys(roles)), ip=ip)


def _critical_hits(ctx: AtomicContext, scope: dict[str, EntityRef], index: RecordIndex,
                   mentions: _Mentions) -> tuple[CriticalAssetHit, ...]:
    hits: list[CriticalAssetHit] = []
    for entity in sorted(scope.values(), key=EntityRef.sort_key):
        if entity.kind not in _CLASSIFIED_KINDS:
            continue
        asset = _asset_context(entity, index, ctx.incident, mentions.aliases)
        # Every spelling is classified: a policy that names the host by its DNS name still matches
        # when the canonical spelling is the short name (a critical asset is never skipped).
        found = list(ctx.critical_assets.classify(entity.value, entity.kind, asset))
        for alias in mentions.aliases.aliases_of(entity):
            found += ctx.critical_assets.classify(alias.value, alias.kind, asset)
        classes = list(dict.fromkeys(found))
        if classes:
            ids = tuple(sorted(set(mentions.by_entity.get(entity.key(), []))))
            hits.append(CriticalAssetHit(entity=entity, classes=tuple(classes), record_ids=ids))
    return tuple(hits)


def _caps(ctx: AtomicContext) -> dict[str, int]:
    limits = ctx.settings.thresholds.blast_radius
    return {"endpoints": limits.max_endpoints, "users": limits.max_users,
            "indicators": limits.max_indicators, "messages": limits.max_messages}


def blast_radius(ctx: AtomicContext, correlation: CorrelationResult, results: Sequence[AtomicResult], *,
                 scope: Sequence[EntityRef] | None = None, merge_aliases: bool = False) -> BlastRadiusReport:
    """Endpoints, users, indicators and messages in scope, critical assets among them, and caps exceeded.

    ``scope`` defaults to the clusters that contain an incident observable, asset or user, plus those
    incident entities, widened by one hop (``_default_scope``). An explicit ``scope`` is used as given
    (mapped to canonical spellings when ``merge_aliases``). ``merge_aliases`` (opt-in) must match the
    flag the correlation was computed with: one host named two ways then counts once, and the
    critical-asset policy is checked against every spelling.
    """
    index = RecordIndex(results)
    mentions = _Mentions.build(index, _resolve_aliases(index) if merge_aliases else None)
    if scope is None:
        in_scope = _default_scope(ctx.incident, correlation, index, mentions)
    else:
        refs = (mentions.aliases.canon(EntityRef.model_validate(x)) for x in scope)
        in_scope = {e.key(): e for e in refs}
    counts = {
        "endpoints": _values(in_scope, (TargetKind.ENDPOINT,)),
        "users": _values(in_scope, (TargetKind.USER,)),
        "indicators": _values(in_scope, _INDICATOR_KINDS),
    }
    messages = sum(1 for e in in_scope.values() if e.kind is TargetKind.EMAIL_MESSAGE)
    caps = _caps(ctx)
    sizes = {**{k: len(v) for k, v in counts.items()}, "messages": messages}
    record_ids = {rid for key in in_scope for rid in mentions.by_entity.get(key, [])}
    return BlastRadiusReport(
        endpoints=counts["endpoints"],
        users=counts["users"],
        indicators=counts["indicators"],
        messages=messages,
        critical_assets=_critical_hits(ctx, in_scope, index, mentions),
        caps=caps,
        exceeds=tuple(name for name in BLAST_RADIUS_CAP_NAMES if sizes[name] > caps[name]),
        record_ids=tuple(sorted(record_ids)),
    )
