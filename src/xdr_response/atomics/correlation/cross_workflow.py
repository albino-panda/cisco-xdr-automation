"""Cross-workflow correlation (Phase 5): link incidents whose runs share entities, roll up blast radius.

A phishing click, an account takeover and C2 beaconing are investigated by three workflows, often
as three incidents. Each run only sees its own records. :func:`correlate_workflows` reads several
finished runs and reports:

* **links** between two incidents whose in-scope entities overlap (same host, same user, same hash,
  domain, URL or IP), citing, per incident, the records of that run that mention the shared entity;
* **groups** (connected components of the links) ordered by the time of each run's earliest dated
  record, so the chain reads in evidence order (for example phishing -> account-takeover -> c2);
* **profiles** that merge every source's evidence about each shared entity across the incidents;
* a **blast-radius rollup** per group: the union of the runs' scopes, critical assets with the
  incidents they appear in, and the caps the union exceeds.

Rules:

* Entities are compared under their canonical spelling (:class:`EntityAliases` over all runs).
* An entity links two incidents only when it is in each run's blast-radius scope (endpoints, users,
  indicators) and at least one record of each run mentions it. A run whose blast radius is empty
  (for example the step failed) links on every endpoint, user and indicator its records mention.
* Private, loopback and link-local IPs, and entities passed in ``ignore`` (allow-listed shared
  infrastructure), never link incidents.
* With a ``window``, two incidents whose cited evidence is further apart than the window are not
  linked (noted). Undated evidence never blocks a link.
* Link confidence rises **only with independent sources**: it counts the independent first-hand
  source families (:func:`independent_families` over the non-enrichment records cited), never the
  number of records, entities or incidents; reputation ratings alone give a low fixed confidence;
  a link resting only on shared IPs is capped (NAT, VPN egress and CDNs are shared).
* A degraded or failed source never blocks a link backed by the records that are there; the
  degraded integrations are reported per incident.

Read zone (14.0.1): pure functions over finished runs. Nothing here approves, executes, changes an
approval level or writes audit records. Critical assets are always reported with a visible warning;
``exceeds`` and the warnings are informational (``PackageBuilder`` decides ELEVATED approval).
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from pydantic import AwareDatetime, Field, field_validator, model_validator

from xdr_response.atomics.correlation.aliases import EntityAliases
from xdr_response.atomics.correlation.correlate import _Mentions, _record_entities, _record_time
from xdr_response.atomics.correlation.models import (
    BLAST_RADIUS_CAP_NAMES,
    BlastRadiusReport,
    EntityRef,
)
from xdr_response.atomics.correlation.sources import EntityProfile, build_profile, independent_families
from xdr_response.atomics.evidence import RecordIndex
from xdr_response.atomics.records import AtomicResult, EnrichmentRecord, RecordBase, SourceOutcome
from xdr_response.models._base import FrozenModel, Score
from xdr_response.models.canonical import canonical_json, sha256_hex
from xdr_response.models.enums import CriticalAssetClass, TargetKind
from xdr_response.models.recommendation import BlastRadius

__all__ = [
    "DEFAULT_CROSS_WINDOW",
    "LINK_CONFIDENCE_BASE",
    "LINK_CONFIDENCE_MAX",
    "LINK_CONFIDENCE_STEP",
    "REPUTATION_ONLY_CONFIDENCE",
    "SHARED_IP_ONLY_CAP",
    "BlastRadiusRollup",
    "CrossWorkflowCorrelation",
    "IncidentCitation",
    "IncidentGroup",
    "IncidentLink",
    "IncidentSummary",
    "LinkBasis",
    "RollupCriticalAsset",
    "RunSnapshot",
    "SharedEntity",
    "correlate_workflows",
    "link_confidence",
    "rollup_blast_radius",
]

DEFAULT_CROSS_WINDOW = timedelta(days=7)
LINK_CONFIDENCE_BASE = 40  # one independent first-hand source family
LINK_CONFIDENCE_STEP = 15  # per additional independent family
LINK_CONFIDENCE_MAX = 85  # a cross-incident link is context, never certainty
REPUTATION_ONLY_CONFIDENCE = 30  # only reputation ratings cite the shared entities
SHARED_IP_ONLY_CAP = 50  # every shared entity is an IP address

_ASSET_KINDS = (TargetKind.ENDPOINT, TargetKind.USER)
_INDICATOR_KINDS = (TargetKind.DOMAIN, TargetKind.URL, TargetKind.IP, TargetKind.HASH)
_LINKABLE_KINDS = frozenset(_ASSET_KINDS + _INDICATOR_KINDS)
_NON_ROUTABLE = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10", "::/128"))
_MAX_NAMED_ENTITIES = 5


# ------------------------------------------------------------------------------------------ inputs


class _WorkflowLike(Protocol):
    @property
    def id(self) -> str: ...


class RunLike(Protocol):
    """The parts of a ``WorkflowRun`` this module reads (atomics never import the workflow layer)."""

    @property
    def workflow(self) -> _WorkflowLike: ...
    @property
    def incident_id(self) -> str: ...
    @property
    def results(self) -> Sequence[AtomicResult]: ...
    @property
    def blast_radius(self) -> BlastRadiusReport: ...


@dataclass(frozen=True)
class RunSnapshot:
    """One finished run: its incident, workflow, atomic results and blast radius."""

    incident_id: str
    workflow_id: str
    results: tuple[AtomicResult, ...] = ()
    blast_radius: BlastRadiusReport = field(default_factory=BlastRadiusReport)

    def __post_init__(self) -> None:
        if not str(self.incident_id).strip() or not str(self.workflow_id).strip():
            raise ValueError("a run snapshot needs an incident id and a workflow id")
        if any(not isinstance(r, AtomicResult) for r in self.results):
            raise ValueError("results must be AtomicResult objects")

    @classmethod
    def of(cls, run: RunLike | RunSnapshot) -> RunSnapshot:
        """A snapshot of a ``WorkflowRun`` (or the snapshot itself)."""
        if isinstance(run, RunSnapshot):
            return run
        return cls(incident_id=run.incident_id, workflow_id=run.workflow.id, results=tuple(run.results),
                   blast_radius=run.blast_radius)

    def degraded_sources(self) -> tuple[str, ...]:
        """Integrations that FAILED in any atomic result, sorted."""
        return tuple(sorted({s.integration for r in self.results for s in r.sources
                             if s.outcome is SourceOutcome.FAILED}))


# ------------------------------------------------------------------------------------------ models


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


class LinkBasis(StrEnum):
    SHARED_ASSET = "shared_asset"  # a shared endpoint or user
    SHARED_INDICATOR = "shared_indicator"  # a shared hash, domain, URL or IP


class IncidentCitation(FrozenModel):
    """The records of one incident's run that mention a shared entity."""

    incident_id: str = Field(min_length=1)
    workflow_id: str = Field(min_length=1)
    record_ids: tuple[str, ...] = Field(min_length=1)  # sorted, unique; all in that run's RecordIndex
    integrations: tuple[str, ...] = Field(min_length=1)  # sorted, unique

    @field_validator("record_ids", "integrations")
    @classmethod
    def _sorted(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        if list(value) != list(_sorted_unique(value)):
            raise ValueError(f"{info.field_name} must be unique and sorted")
        return value


class SharedEntity(FrozenModel):
    """An entity in scope of two or more incidents, with each incident's citing records."""

    entity: EntityRef
    aliases: tuple[EntityRef, ...] = ()
    citations: tuple[IncidentCitation, ...] = Field(min_length=2)  # one per incident, sorted by incident id

    @model_validator(mode="after")
    def _consistent(self) -> "SharedEntity":
        ids = [c.incident_id for c in self.citations]
        if ids != sorted(set(ids)):
            raise ValueError("citations must be one per incident, sorted by incident id")
        return self

    @property
    def incidents(self) -> tuple[str, ...]:
        return tuple(c.incident_id for c in self.citations)


def _link_id(incidents: Sequence[str], entities: Sequence[EntityRef]) -> str:
    return "xwl_" + sha256_hex(canonical_json([list(incidents), [e.key() for e in entities]]))[:24]


def _group_id(incidents: Iterable[str]) -> str:
    return "xwg_" + sha256_hex(canonical_json(sorted(incidents)))[:24]


class IncidentLink(FrozenModel):
    """Two incidents whose runs share in-scope entities. Every shared entity cites both runs' records."""

    link_id: str
    incidents: tuple[str, str]  # sorted
    workflows: tuple[str, str]  # aligned with ``incidents``
    shared: tuple[SharedEntity, ...] = Field(min_length=1)  # sorted by entity
    basis: tuple[LinkBasis, ...] = Field(min_length=1)
    sequence: tuple[str, str]  # the two incidents in evidence order (earliest dated record first)
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    sources: tuple[str, ...]  # every integration cited, sorted
    first_hand_families: tuple[str, ...]  # independent families of the non-enrichment records cited
    independent_sources: int = Field(ge=0)  # len(first_hand_families)
    confidence_score: Score
    note: str = Field(min_length=1)  # deterministic template

    @model_validator(mode="after")
    def _consistent(self) -> "IncidentLink":
        if list(self.incidents) != sorted(set(self.incidents)) or len(self.incidents) != 2:
            raise ValueError("a link names two distinct incidents, sorted")
        if sorted(self.sequence) != list(self.incidents):
            raise ValueError("sequence must order the link's two incidents")
        keys = [s.entity.sort_key() for s in self.shared]
        if keys != sorted(set(keys)):
            raise ValueError("shared entities must be unique and sorted")
        if any(s.incidents != self.incidents for s in self.shared):
            raise ValueError("every shared entity must cite both incidents of the link")
        if self.link_id != _link_id(self.incidents, [s.entity for s in self.shared]):
            raise ValueError("link_id does not match incidents and shared entities")
        if self.independent_sources != len(self.first_hand_families):
            raise ValueError("independent_sources must count first_hand_families")
        return self

    @property
    def entities(self) -> tuple[EntityRef, ...]:
        return tuple(s.entity for s in self.shared)

    def record_ids(self, incident_id: str | None = None) -> tuple[str, ...]:
        """Cited record ids (of one incident's run when ``incident_id`` is given), sorted."""
        return _sorted_unique(rid for s in self.shared for c in s.citations
                              if incident_id is None or c.incident_id == incident_id for rid in c.record_ids)

    def other(self, incident_id: str) -> str:
        """The incident at the other end of the link."""
        if incident_id not in self.incidents:
            raise KeyError(incident_id)
        return self.incidents[1] if self.incidents[0] == incident_id else self.incidents[0]

    def rule_item(self) -> dict[str, Any]:
        item = self.model_dump(mode="json")
        item["entities"] = [e.model_dump(mode="json") for e in self.entities]
        item["record_ids"] = list(self.record_ids())
        return item


class RollupCriticalAsset(FrozenModel):
    """A critical asset in the scope of one or more incidents of a group (always reported)."""

    entity: EntityRef
    classes: tuple[CriticalAssetClass, ...] = Field(min_length=1)
    incidents: tuple[str, ...] = Field(min_length=1)  # incidents whose blast radius classified it
    in_scope_of: tuple[str, ...] = Field(min_length=1)  # every incident whose scope contains it
    record_ids: tuple[str, ...] = ()

    @property
    def unclassified_in(self) -> tuple[str, ...]:
        """Incidents that have the asset in scope but did not classify it as critical."""
        return tuple(i for i in self.in_scope_of if i not in self.incidents)


class IncidentSummary(FrozenModel):
    """One run as seen by the cross-workflow correlation."""

    incident_id: str = Field(min_length=1)
    workflow_id: str = Field(min_length=1)
    onset: AwareDatetime | None = None  # earliest dated record of the run
    endpoints: int = Field(default=0, ge=0)
    users: int = Field(default=0, ge=0)
    indicators: int = Field(default=0, ge=0)
    messages: int = Field(default=0, ge=0)
    exceeds: tuple[str, ...] = ()
    degraded_sources: tuple[str, ...] = ()


class BlastRadiusRollup(FrozenModel):
    """Union of the blast radius of several incidents (canonical spellings, critical assets kept)."""

    incident_ids: tuple[str, ...] = ()  # sorted
    workflows: tuple[str, ...] = ()  # distinct workflow ids, sorted
    endpoints: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()  # grouped as domains, URLs, IPs, hashes
    messages: int = Field(default=0, ge=0)  # per-incident counts summed (a message in two incidents counts twice)
    shared: tuple[EntityRef, ...] = ()  # entities in scope of two or more of the incidents
    critical_assets: tuple[RollupCriticalAsset, ...] = ()
    caps: Mapping[str, int] = {}  # the strictest cap of the runs, per name
    exceeds: tuple[str, ...] = ()  # caps the union exceeds (informational)
    per_incident: tuple[IncidentSummary, ...] = ()
    warnings: tuple[str, ...] = ()  # one visible line per critical asset

    @field_validator("caps")
    @classmethod
    def _caps(cls, value: Mapping[str, int]) -> Mapping[str, int]:
        if set(value) - set(BLAST_RADIUS_CAP_NAMES) or any(v < 0 for v in value.values()):
            raise ValueError(f"caps must be non-negative values of {BLAST_RADIUS_CAP_NAMES}")
        return dict(value)

    @property
    def has_critical_asset(self) -> bool:
        return bool(self.critical_assets)

    def to_blast_radius(self) -> BlastRadius:
        """The Phase 0 ``BlastRadius`` model (counts and names only)."""
        return BlastRadius(endpoints=self.endpoints, users=self.users, indicators=self.indicators,
                           messages=self.messages)

    def rule_item(self) -> dict[str, Any]:
        item = self.model_dump(mode="json")
        item["endpoint_count"] = len(self.endpoints)
        item["user_count"] = len(self.users)
        item["indicator_count"] = len(self.indicators)
        item["critical_asset_classes"] = sorted({c.value for hit in self.critical_assets for c in hit.classes})
        item["has_critical_asset"] = self.has_critical_asset
        return item


class IncidentGroup(FrozenModel):
    """Incidents connected by links (a connected component); a lone incident is a group of one."""

    group_id: str
    incidents: tuple[str, ...] = Field(min_length=1)  # evidence order: (onset, incident id), undated last
    workflows: tuple[str, ...] = Field(min_length=1)  # aligned with ``incidents``
    link_ids: tuple[str, ...] = ()  # sorted
    shared_entities: tuple[EntityRef, ...] = ()  # sorted
    chain: str = Field(min_length=1)  # deterministic "workflow incident -> ..." line
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    blast_radius: BlastRadiusRollup
    degraded_sources: tuple[str, ...] = ()  # "<incident id>: <integration>", sorted

    @model_validator(mode="after")
    def _consistent(self) -> "IncidentGroup":
        if len(self.incidents) != len(set(self.incidents)) or len(self.workflows) != len(self.incidents):
            raise ValueError("incidents must be unique and aligned with workflows")
        if self.group_id != _group_id(self.incidents):
            raise ValueError("group_id does not match the incidents")
        return self

    @property
    def warnings(self) -> tuple[str, ...]:
        return self.blast_radius.warnings


class CrossWorkflowCorrelation(FrozenModel):
    """Links, groups and merged entity profiles over several workflow runs."""

    incidents: tuple[IncidentSummary, ...] = ()  # sorted by incident id
    links: tuple[IncidentLink, ...] = ()  # sorted by link_id
    groups: tuple[IncidentGroup, ...] = ()  # partition of the incidents, sorted by first incident
    profiles: tuple[EntityProfile, ...] = ()  # one per linking entity, sorted by entity
    notes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> "CrossWorkflowCorrelation":
        ids = [i.incident_id for i in self.incidents]
        if ids != sorted(set(ids)):
            raise ValueError("incidents must be unique and sorted")
        members = [i for g in self.groups for i in g.incidents]
        if sorted(members) != ids:
            raise ValueError("groups must partition the incidents")
        link_ids = [link.link_id for link in self.links]
        if link_ids != sorted(set(link_ids)):
            raise ValueError("links must be unique and sorted by link_id")
        return self

    def group_of(self, incident_id: str) -> IncidentGroup | None:
        for group in self.groups:
            if incident_id in group.incidents:
                return group
        return None

    def links_for(self, incident_id: str) -> tuple[IncidentLink, ...]:
        return tuple(link for link in self.links if incident_id in link.incidents)

    def linked_incidents(self, incident_id: str) -> tuple[str, ...]:
        """Incidents directly linked to ``incident_id``, sorted."""
        return tuple(sorted({link.other(incident_id) for link in self.links_for(incident_id)}))

    def profile(self, entity: EntityRef) -> EntityProfile | None:
        for profile in self.profiles:
            if profile.entity == entity or entity in profile.aliases:
                return profile
        return None

    def rule_item(self) -> dict[str, Any]:
        return {
            "incidents": [i.model_dump(mode="json") for i in self.incidents],
            "links": [link.rule_item() for link in self.links],
            "groups": [g.model_dump(mode="json") for g in self.groups],
            "profiles": [p.rule_item() for p in self.profiles],
            "notes": list(self.notes),
        }


# ------------------------------------------------------------------------------------------- views


@dataclass
class _Run:
    """One snapshot prepared for linking (private)."""

    snapshot: RunSnapshot
    index: RecordIndex
    mentions: _Mentions
    scope: dict[str, EntityRef]  # linkable, canonical, cited by at least one record of the run
    onset: datetime | None

    @property
    def incident_id(self) -> str:
        return self.snapshot.incident_id

    @property
    def workflow_id(self) -> str:
        return self.snapshot.workflow_id

    def citation(self, key: str) -> IncidentCitation:
        ids = _sorted_unique(self.mentions.by_entity.get(key, ()))
        self.index.require(ids)
        return IncidentCitation(incident_id=self.incident_id, workflow_id=self.workflow_id, record_ids=ids,
                                integrations=_sorted_unique(self.index.get(r).integration for r in ids))


def _non_routable(entity: EntityRef) -> bool:
    if entity.kind is not TargetKind.IP:
        return False
    try:
        address = ipaddress.ip_address(entity.value)
    except ValueError:
        return False
    return any(address.version == net.version and address in net for net in _NON_ROUTABLE)


def _blast_refs(report: BlastRadiusReport, aliases: EntityAliases) -> set[str]:
    """Canonical keys of the run's blast-radius endpoints and users, and its indicator values."""
    keys = {aliases.canon(EntityRef(kind=TargetKind.ENDPOINT, value=v)).key() for v in report.endpoints}
    keys |= {aliases.canon(EntityRef(kind=TargetKind.USER, value=v)).key() for v in report.users}
    return keys


def _scope(snapshot: RunSnapshot, mentions: _Mentions, aliases: EntityAliases,
           notes: list[str]) -> dict[str, EntityRef]:
    report = snapshot.blast_radius
    linkable = {k: e for k, e in mentions.entities.items() if e.kind in _LINKABLE_KINDS}
    if not (report.endpoints or report.users or report.indicators):
        if linkable:
            notes.append(f"{snapshot.incident_id}: blast radius is empty; linking on the endpoints, users and "
                         f"indicators its records mention")
        return linkable
    assets = _blast_refs(report, aliases)
    indicators = set(report.indicators)
    return {k: e for k, e in linkable.items()
            if k in assets or (e.kind in _INDICATOR_KINDS and e.value in indicators)}


def _onset(index: RecordIndex) -> datetime | None:
    times = [t for t in (_record_time(r) for r in index.records()) if t is not None]
    return min(times) if times else None


def _order_key(run: _Run) -> tuple[int, float, str]:
    """Evidence order: dated runs by onset, then undated runs; ties by incident id."""
    return (0, run.onset.timestamp(), run.incident_id) if run.onset is not None else (1, 0.0, run.incident_id)


def _prepare(snapshots: Sequence[RunSnapshot], ignore: Collection[EntityRef],
             notes: list[str]) -> tuple[list[_Run], EntityAliases]:
    indexes = [RecordIndex(s.results) for s in snapshots]
    raw: list[EntityRef] = [e for index in indexes for r in index.records() for e in _record_entities(r)]
    for s in snapshots:
        raw += [EntityRef(kind=TargetKind.ENDPOINT, value=v) for v in s.blast_radius.endpoints]
        raw += [EntityRef(kind=TargetKind.USER, value=v) for v in s.blast_radius.users]
    aliases = EntityAliases.resolve(raw)
    for alias, canonical in aliases.items():
        notes.append(f"{alias.key()} and {canonical.key()} are the same entity (merged)")
    ignored = {aliases.canon(EntityRef.model_validate(e)).key() for e in ignore}
    private: set[str] = set()
    runs: list[_Run] = []
    for snapshot, index in zip(snapshots, indexes):
        mentions = _Mentions.build(index, aliases)
        scope = {}
        for key, entity in _scope(snapshot, mentions, aliases, notes).items():
            if key in ignored or not mentions.by_entity.get(key):
                continue
            if _non_routable(entity):
                private.add(entity.value)
                continue
            scope[key] = entity
        runs.append(_Run(snapshot, index, mentions, scope, _onset(index)))
    for value in sorted(private):
        notes.append(f"IP {value} is a private or local address: not used to link incidents")
    return runs, aliases


def _dedupe(runs: Sequence[RunLike | RunSnapshot], notes: list[str]) -> list[RunSnapshot]:
    by_incident: dict[str, RunSnapshot] = {}
    for run in runs:
        snapshot = RunSnapshot.of(run)
        if snapshot.incident_id in by_incident:
            notes.append(f"{snapshot.incident_id}: several runs given; the last one is used")
        by_incident[snapshot.incident_id] = snapshot
    return [by_incident[k] for k in sorted(by_incident)]


# ----------------------------------------------------------------------------------------- linking


def link_confidence(first_hand_families: int, *, reputation_only: bool = False, ip_only: bool = False) -> int:
    """Confidence of a cross-incident link from the count of independent first-hand source families.

    ``LINK_CONFIDENCE_BASE`` for one family, ``+LINK_CONFIDENCE_STEP`` per additional family, at most
    ``LINK_CONFIDENCE_MAX``; ``REPUTATION_ONLY_CONFIDENCE`` when only reputation ratings cite the
    shared entities; at most ``SHARED_IP_ONLY_CAP`` when every shared entity is an IP address.
    """
    if first_hand_families < 0:
        raise ValueError("the family count must be >= 0")
    if first_hand_families == 0 or reputation_only:
        score = REPUTATION_ONLY_CONFIDENCE
    else:
        score = min(LINK_CONFIDENCE_MAX, LINK_CONFIDENCE_BASE + LINK_CONFIDENCE_STEP * (first_hand_families - 1))
    return min(score, SHARED_IP_ONLY_CAP) if ip_only else score


def _span(index: RecordIndex, ids: Iterable[str]) -> tuple[datetime | None, datetime | None]:
    times = [t for t in (_record_time(index.get(r)) for r in ids) if t is not None]
    return (min(times), max(times)) if times else (None, None)


def _gap(a: tuple[datetime | None, datetime | None], b: tuple[datetime | None, datetime | None]) -> timedelta | None:
    if None in a or None in b:
        return None
    return max(timedelta(0), max(a[0], b[0]) - min(a[1], b[1]))  # type: ignore[type-var,operator]


def _hours(delta: timedelta) -> str:
    return f"{delta.total_seconds() / 3600:g}"


def _named(entities: Sequence[EntityRef]) -> str:
    names = ", ".join(e.key() for e in entities[:_MAX_NAMED_ENTITIES])
    more = len(entities) - _MAX_NAMED_ENTITIES
    return names + (f" (+{more} more)" if more > 0 else "")


def _link(a: _Run, b: _Run, keys: Sequence[str], aliases: EntityAliases, window: timedelta | None,
          notes: list[str]) -> IncidentLink | None:
    first, second = sorted((a, b), key=lambda r: r.incident_id)
    entities = sorted((first.scope[k] for k in keys), key=EntityRef.sort_key)
    shared = tuple(SharedEntity(entity=e, aliases=aliases.aliases_of(e),
                                citations=(first.citation(e.key()), second.citation(e.key()))) for e in entities)
    ids = {run.incident_id: _sorted_unique(rid for s in shared for c in s.citations
                                           if c.incident_id == run.incident_id for rid in c.record_ids)
           for run in (first, second)}
    span_a, span_b = _span(first.index, ids[first.incident_id]), _span(second.index, ids[second.incident_id])
    gap = _gap(span_a, span_b)
    if window is not None and gap is not None and gap > window:
        notes.append(f"{first.incident_id} and {second.incident_id} share {_named(entities)} but their evidence is "
                     f"{_hours(gap)} hours apart (window {_hours(window)} hours): not linked")
        return None
    records: list[RecordBase] = [run.index.get(r) for run in (first, second) for r in ids[run.incident_id]]
    first_hand = [r.integration for r in records if not isinstance(r, EnrichmentRecord)]
    families = independent_families(first_hand) if first_hand else ()
    ip_only = all(e.kind is TargetKind.IP for e in entities)
    confidence = link_confidence(len(families), ip_only=ip_only)
    basis = sorted({LinkBasis.SHARED_ASSET if e.kind in _ASSET_KINDS else LinkBasis.SHARED_INDICATOR
                    for e in entities}, key=lambda v: v.value)
    times = [t for span in (span_a, span_b) for t in span if t is not None]
    sequence = tuple(r.incident_id for r in sorted((first, second), key=_order_key))
    note = (f"{first.workflow_id} {first.incident_id} and {second.workflow_id} {second.incident_id} share "
            f"{_named(entities)}; attested by {len(families)} independent first-hand source(s)"
            + (f" ({', '.join(families)})" if families else " (reputation ratings only)")
            + ("; shared IPs only (NAT, VPN egress and CDNs can be shared)" if ip_only else ""))
    return IncidentLink(
        link_id=_link_id((first.incident_id, second.incident_id), entities),
        incidents=(first.incident_id, second.incident_id),
        workflows=(first.workflow_id, second.workflow_id),
        shared=shared,
        basis=tuple(basis),
        sequence=sequence,  # type: ignore[arg-type]
        first_seen=min(times) if times else None,
        last_seen=max(times) if times else None,
        sources=_sorted_unique(r.integration for r in records),
        first_hand_families=families,
        independent_sources=len(families),
        confidence_score=confidence,
        note=note,
    )


def _links(runs: Sequence[_Run], aliases: EntityAliases, window: timedelta | None,
           notes: list[str]) -> list[IncidentLink]:
    links: list[IncidentLink] = []
    for i, a in enumerate(runs):
        for b in runs[i + 1:]:
            keys = sorted(set(a.scope) & set(b.scope))
            if keys:
                link = _link(a, b, keys, aliases, window, notes)
                if link is not None:
                    links.append(link)
    return sorted(links, key=lambda link: link.link_id)


def _components(runs: Sequence[_Run], links: Sequence[IncidentLink]) -> list[list[_Run]]:
    parent = {r.incident_id: r.incident_id for r in runs}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for link in links:
        x, y = find(link.incidents[0]), find(link.incidents[1])
        if x != y:
            parent[max(x, y)] = min(x, y)
    groups: dict[str, list[_Run]] = defaultdict(list)
    for run in runs:
        groups[find(run.incident_id)].append(run)
    return [sorted(members, key=_order_key) for members in groups.values()]


# ---------------------------------------------------------------------------------------- rollup


def _indicator_order(value: str, kinds: Mapping[str, TargetKind]) -> tuple[int, str]:
    kind = kinds.get(value, TargetKind.DOMAIN)
    return (_INDICATOR_KINDS.index(kind) if kind in _INDICATOR_KINDS else 0, value)


def _summary(run: _Run) -> IncidentSummary:
    report = run.snapshot.blast_radius
    return IncidentSummary(incident_id=run.incident_id, workflow_id=run.workflow_id, onset=run.onset,
                           endpoints=len(report.endpoints), users=len(report.users),
                           indicators=len(report.indicators), messages=report.messages, exceeds=report.exceeds,
                           degraded_sources=run.snapshot.degraded_sources())


def _strictest_caps(runs: Sequence[_Run]) -> dict[str, int]:
    caps: dict[str, int] = {}
    for run in runs:
        for name, value in run.snapshot.blast_radius.caps.items():
            caps[name] = min(value, caps.get(name, value))
    return caps


def _critical(runs: Sequence[_Run], aliases: EntityAliases,
              in_scope: Mapping[str, set[str]]) -> tuple[RollupCriticalAsset, ...]:
    classes: dict[str, set[CriticalAssetClass]] = defaultdict(set)
    incidents: dict[str, set[str]] = defaultdict(set)
    record_ids: dict[str, set[str]] = defaultdict(set)
    refs: dict[str, EntityRef] = {}
    for run in runs:
        for hit in run.snapshot.blast_radius.critical_assets:
            entity = aliases.canon(hit.entity)
            refs[entity.key()] = entity
            classes[entity.key()].update(hit.classes)
            incidents[entity.key()].add(run.incident_id)
            record_ids[entity.key()].update(hit.record_ids)
    out = []
    for key in sorted(refs, key=lambda k: refs[k].sort_key()):
        scope = incidents[key] | in_scope.get(key, set())
        out.append(RollupCriticalAsset(entity=refs[key], classes=tuple(sorted(classes[key], key=lambda c: c.value)),
                                       incidents=_sorted_unique(incidents[key]), in_scope_of=_sorted_unique(scope),
                                       record_ids=_sorted_unique(record_ids[key])))
    return tuple(out)


def _warning(hit: RollupCriticalAsset) -> str:
    line = (f"critical asset {hit.entity.key()} ({', '.join(c.value for c in hit.classes)}) is in scope of "
            f"{len(hit.in_scope_of)} incident(s): {', '.join(hit.in_scope_of)}")
    if hit.unclassified_in:
        line += (f"; not classified as critical in {', '.join(hit.unclassified_in)}: review the approval level of "
                 f"actions on it there")
    return line


def _rollup(runs: Sequence[_Run], aliases: EntityAliases, caps: Mapping[str, int] | None) -> BlastRadiusRollup:
    endpoints: set[str] = set()
    users: set[str] = set()
    indicators: set[str] = set()
    kinds: dict[str, TargetKind] = {}
    in_scope: dict[str, set[str]] = defaultdict(set)
    refs: dict[str, EntityRef] = {}
    for run in runs:
        report = run.snapshot.blast_radius
        for value in report.endpoints:
            ref = aliases.canon(EntityRef(kind=TargetKind.ENDPOINT, value=value))
            endpoints.add(ref.value)
            in_scope[ref.key()].add(run.incident_id)
            refs[ref.key()] = ref
        for value in report.users:
            ref = aliases.canon(EntityRef(kind=TargetKind.USER, value=value))
            users.add(ref.value)
            in_scope[ref.key()].add(run.incident_id)
            refs[ref.key()] = ref
        indicators.update(report.indicators)
        for entity in run.mentions.entities.values():
            if entity.kind in _INDICATOR_KINDS:
                kinds.setdefault(entity.value, entity.kind)
        for key, entity in run.scope.items():
            in_scope[key].add(run.incident_id)
            refs[key] = entity
    limits = dict(caps) if caps is not None else _strictest_caps(runs)
    sizes = {"endpoints": len(endpoints), "users": len(users), "indicators": len(indicators),
             "messages": sum(r.snapshot.blast_radius.messages for r in runs)}
    hits = _critical(runs, aliases, in_scope)
    shared = sorted((refs[k] for k, ids in in_scope.items() if len(ids) >= 2), key=EntityRef.sort_key)
    return BlastRadiusRollup(
        incident_ids=_sorted_unique(r.incident_id for r in runs),
        workflows=_sorted_unique(r.workflow_id for r in runs),
        endpoints=tuple(sorted(endpoints)),
        users=tuple(sorted(users)),
        indicators=tuple(sorted(indicators, key=lambda v: _indicator_order(v, kinds))),
        messages=sizes["messages"],
        shared=tuple(shared),
        critical_assets=hits,
        caps=limits,
        exceeds=tuple(n for n in BLAST_RADIUS_CAP_NAMES if n in limits and sizes[n] > limits[n]),
        per_incident=tuple(_summary(r) for r in sorted(runs, key=lambda r: r.incident_id)),
        warnings=tuple(_warning(h) for h in hits),
    )


def rollup_blast_radius(runs: Sequence[RunLike | RunSnapshot], *,
                        caps: Mapping[str, int] | None = None) -> BlastRadiusRollup:
    """The blast-radius rollup of ``runs`` taken together (whether or not they are linked).

    ``caps`` defaults to the strictest cap of the runs, per name.
    """
    notes: list[str] = []
    prepared, aliases = _prepare(_dedupe(runs, notes), (), notes)
    return _rollup(prepared, aliases, caps)


# --------------------------------------------------------------------------------------- correlate


def _group(members: Sequence[_Run], links: Sequence[IncidentLink], aliases: EntityAliases,
           caps: Mapping[str, int] | None) -> IncidentGroup:
    ids = {r.incident_id for r in members}
    own = [link for link in links if link.incidents[0] in ids]
    shared = sorted({e.key(): e for link in own for e in link.entities}.values(), key=EntityRef.sort_key)
    chain = " -> ".join(f"{r.workflow_id} {r.incident_id}" for r in members)
    if shared:
        chain += f" via {_named(shared)}"
    times = [t for link in own for t in (link.first_seen, link.last_seen) if t is not None]
    degraded = sorted(f"{r.incident_id}: {name}" for r in members for name in r.snapshot.degraded_sources())
    incidents = tuple(r.incident_id for r in members)
    return IncidentGroup(
        group_id=_group_id(incidents), incidents=incidents, workflows=tuple(r.workflow_id for r in members),
        link_ids=tuple(sorted(link.link_id for link in own)), shared_entities=tuple(shared), chain=chain,
        first_seen=min(times) if times else None, last_seen=max(times) if times else None,
        blast_radius=_rollup(members, aliases, caps), degraded_sources=tuple(degraded))


def _profiles(runs: Sequence[_Run], links: Sequence[IncidentLink], aliases: EntityAliases) -> tuple[EntityProfile, ...]:
    by_id = {r.incident_id: r for r in runs}
    entities: dict[str, EntityRef] = {}
    incidents: dict[str, set[str]] = defaultdict(set)
    for link in links:
        for shared in link.shared:
            entities[shared.entity.key()] = shared.entity
            incidents[shared.entity.key()].update(shared.incidents)
    profiles = []
    for key in sorted(entities, key=lambda k: entities[k].sort_key()):
        records = [by_id[i].index.get(rid) for i in sorted(incidents[key])
                   for rid in by_id[i].mentions.by_entity.get(key, ())]
        profiles.append(build_profile(entities[key], records, aliases=aliases.aliases_of(entities[key]),
                                      incidents=incidents[key]))
    return tuple(profiles)


def correlate_workflows(runs: Sequence[RunLike | RunSnapshot], *, window: timedelta | None = DEFAULT_CROSS_WINDOW,
                        ignore: Collection[EntityRef] = (),
                        caps: Mapping[str, int] | None = None) -> CrossWorkflowCorrelation:
    """Links, groups, merged profiles and blast-radius rollups over finished workflow runs.

    ``runs`` are ``WorkflowRun`` objects or :class:`RunSnapshot` (one per incident; when an incident
    appears twice the last run is used, noted). ``window`` (``None``: no limit) bounds the time between
    two incidents' cited evidence; ``ignore`` lists entities that never link incidents (allow-listed
    shared infrastructure); ``caps`` overrides the strictest per-run blast-radius caps of the rollups.
    """
    if window is not None and window <= timedelta(0):
        raise ValueError("the cross-workflow window must be positive")
    notes: list[str] = []
    prepared, aliases = _prepare(_dedupe(runs, notes), ignore, notes)
    links = _links(prepared, aliases, window, notes)
    groups = [_group(members, links, aliases, caps) for members in _components(prepared, links)]
    return CrossWorkflowCorrelation(
        incidents=tuple(_summary(r) for r in sorted(prepared, key=lambda r: r.incident_id)),
        links=tuple(links),
        groups=tuple(sorted(groups, key=lambda g: min(g.incidents))),
        profiles=_profiles(prepared, links, aliases),
        notes=tuple(dict.fromkeys(notes)),
    )
