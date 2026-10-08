"""Correlation and blast-radius models (architecture section 14.1.5).

Pure data: entities, links between entities that cite the records they were computed from, the
incident timeline and the blast-radius report. Nothing here calls an adapter or decides an approval
level; ``exceeds`` and ``critical_assets`` are informational and ``PackageBuilder`` stays the only
component that turns them into ELEVATED approval.
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, Field, field_validator, model_validator

from xdr_response.atomics.records import RecordKind
from xdr_response.models._base import FrozenModel
from xdr_response.models.canonical import canonical_json, normalize_target, sha256_hex
from xdr_response.models.enums import CriticalAssetClass, TargetKind
from xdr_response.models.recommendation import BlastRadius

__all__ = [
    "EntityRef",
    "LinkKind",
    "CorrelationLink",
    "TimelineEntry",
    "CorrelationResult",
    "CriticalAssetHit",
    "BlastRadiusReport",
    "FRAMEWORK_ORIGIN",
    "BLAST_RADIUS_CAP_NAMES",
]

FRAMEWORK_ORIGIN = "framework"
WORKFLOW_ORIGIN_PREFIX = "workflow:"
BLAST_RADIUS_CAP_NAMES: tuple[str, ...] = ("endpoints", "users", "indicators", "messages")


class EntityRef(FrozenModel):
    """One entity (endpoint, user, indicator, message, ...) named by records; the value is normalized."""

    kind: TargetKind
    value: str = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        if isinstance(data, Mapping) and isinstance(data.get("value"), str) and data.get("kind") is not None:
            data = {**data, "value": normalize_target(TargetKind(data["kind"]), data["value"])}
        return data

    def sort_key(self) -> tuple[str, str]:
        """``(kind, value)``: the order used everywhere entities are sorted."""
        return (self.kind.value, self.value)

    def key(self) -> str:
        """``"<KIND>:<value>"``, the key of ``CorrelationResult.rule_item()["related"]``."""
        return f"{self.kind.value}:{self.value}"


class LinkKind(StrEnum):
    SAME_HASH = "same_hash"
    SAME_DOMAIN = "same_domain"
    SAME_IP = "same_ip"
    SAME_URL = "same_url"
    SAME_USER = "same_user"
    SAME_ENDPOINT = "same_endpoint"
    PROCESS_LINEAGE = "process_lineage"
    SIGN_IN_TO_ACTIVITY = "sign_in_to_activity"
    EMAIL_TO_CLICK = "email_to_click"
    CAMPAIGN = "campaign"
    WORKFLOW = "workflow"  # links contributed by a workflow hook (14.3.3)


def _sorted_entities(entities: Any) -> tuple[EntityRef, ...]:
    """Unique entities sorted by ``(kind, value)``."""
    refs = {e.key(): e for e in (EntityRef.model_validate(x) for x in entities)}
    return tuple(sorted(refs.values(), key=EntityRef.sort_key))


def _link_id(kind: LinkKind, entities: tuple[EntityRef, ...], record_ids: tuple[str, ...]) -> str:
    """``"lnk_" + sha256_hex(canonical_json([kind, entities, record_ids]))[:24]``."""
    return "lnk_" + sha256_hex(canonical_json([kind, list(entities), list(record_ids)]))[:24]


class CorrelationLink(FrozenModel):
    """A relation between two or more entities, citing the records it was computed from.

    ``entities`` and ``record_ids`` are de-duplicated and sorted on validation; ``link_id`` is derived
    from them (it may be omitted; a supplied value must match). Framework links never use the
    ``WORKFLOW`` kind and workflow-hook links always do, so a hook cannot pass off a link as a
    framework rule.
    """

    link_id: str
    kind: LinkKind
    entities: tuple[EntityRef, ...] = Field(min_length=2)
    record_ids: tuple[str, ...] = Field(min_length=1)
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    note: str = Field(min_length=1)
    origin: str = FRAMEWORK_ORIGIN

    @model_validator(mode="before")
    @classmethod
    def _canonical(cls, data: Any) -> Any:
        if not isinstance(data, Mapping):
            return data
        data = dict(data)
        if isinstance(data.get("entities"), (list, tuple)):
            data["entities"] = _sorted_entities(data["entities"])
        if isinstance(data.get("record_ids"), (list, tuple)):
            data["record_ids"] = tuple(sorted(set(data["record_ids"])))
        if "link_id" not in data and {"kind", "entities", "record_ids"} <= data.keys():
            data["link_id"] = _link_id(LinkKind(data["kind"]), data["entities"], data["record_ids"])
        return data

    @field_validator("record_ids")
    @classmethod
    def _ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not isinstance(v, str) or not v.strip() for v in value):
            raise ValueError("record ids must be non-empty strings")
        return value

    @field_validator("origin")
    @classmethod
    def _origin(cls, value: str) -> str:
        if value == FRAMEWORK_ORIGIN:
            return value
        if value.startswith(WORKFLOW_ORIGIN_PREFIX) and value[len(WORKFLOW_ORIGIN_PREFIX):].strip():
            return value
        raise ValueError(f"origin must be {FRAMEWORK_ORIGIN!r} or 'workflow:<workflow id>', got {value!r}")

    @model_validator(mode="after")
    def _consistent(self) -> "CorrelationLink":
        if self.link_id != _link_id(self.kind, self.entities, self.record_ids):
            raise ValueError("link_id does not match kind, entities and record_ids")
        if (self.kind is LinkKind.WORKFLOW) != (self.origin != FRAMEWORK_ORIGIN):
            raise ValueError("WORKFLOW links come only from workflow hooks (origin 'workflow:<id>') and "
                             "workflow hooks may only contribute WORKFLOW links")
        if self.first_seen and self.last_seen and self.first_seen > self.last_seen:
            raise ValueError("first_seen must not be after last_seen")
        return self

    def rule_item(self) -> dict[str, Any]:
        """JSON-mode dump for workflow rule expressions."""
        return self.model_dump(mode="json")


class TimelineEntry(FrozenModel):
    at: AwareDatetime
    record_id: str
    kind: RecordKind
    integration: str
    summary: str  # evidence_summary(record)


class CorrelationResult(FrozenModel):
    """Entities, links, connected components (clusters) and the timeline of one run.

    Every entity belongs to exactly one cluster; an entity no link touches is a cluster of its own.
    """

    incident_id: str = Field(min_length=1)
    entities: tuple[EntityRef, ...] = ()
    links: tuple[CorrelationLink, ...] = ()
    clusters: tuple[tuple[EntityRef, ...], ...] = ()
    timeline: tuple[TimelineEntry, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> "CorrelationResult":
        if list(self.entities) != list(_sorted_entities(self.entities)):
            raise ValueError("entities must be unique and sorted by (kind, value)")
        ids = [link.link_id for link in self.links]
        if ids != sorted(set(ids)):
            raise ValueError("links must be unique and sorted by link_id")
        known = {e.key() for e in self.entities}
        if any(e.key() not in known for link in self.links for e in link.entities):
            raise ValueError("every link entity must be listed in entities")
        self._check_clusters(known)
        order = [(t.at, t.record_id) for t in self.timeline]
        if order != sorted(order):
            raise ValueError("timeline must be sorted by (at, record_id)")
        return self

    def _check_clusters(self, known: set[str]) -> None:
        members = [e.key() for cluster in self.clusters for e in cluster]
        if len(members) != len(set(members)) or set(members) != known:
            raise ValueError("clusters must partition entities")
        for cluster in self.clusters:
            if not cluster or list(cluster) != list(_sorted_entities(cluster)):
                raise ValueError("every cluster must be non-empty and sorted by (kind, value)")
        keys = [[e.sort_key() for e in cluster] for cluster in self.clusters]
        if keys != sorted(keys):
            raise ValueError("clusters must be sorted")

    def cluster_of(self, entity: EntityRef) -> tuple[EntityRef, ...]:
        """The cluster containing ``entity`` (``()`` when the entity is unknown)."""
        for cluster in self.clusters:
            if entity in cluster:
                return cluster
        return ()

    def related(self, entity: EntityRef) -> tuple[EntityRef, ...]:
        """Entities of the same cluster, ``entity`` excluded."""
        return tuple(e for e in self.cluster_of(entity) if e != entity)

    def links_for(self, entity: EntityRef) -> tuple[CorrelationLink, ...]:
        """Links naming ``entity``, in link order."""
        return tuple(link for link in self.links if entity in link.entities)

    def rule_item(self) -> dict[str, Any]:
        """``{"entities", "links", "clusters", "related"}`` in JSON mode for rule expressions."""
        return {
            "entities": [e.model_dump(mode="json") for e in self.entities],
            "links": [link.rule_item() for link in self.links],
            "clusters": [[e.model_dump(mode="json") for e in cluster] for cluster in self.clusters],
            "related": {e.key(): [r.model_dump(mode="json") for r in self.related(e)] for e in self.entities},
        }


class CriticalAssetHit(FrozenModel):
    entity: EntityRef
    classes: tuple[CriticalAssetClass, ...] = Field(min_length=1)
    record_ids: tuple[str, ...] = ()


def _sorted_unique(values: tuple[str, ...], name: str) -> tuple[str, ...]:
    if list(values) != sorted(set(values)):
        raise ValueError(f"{name} must be unique and sorted")
    return values


class BlastRadiusReport(FrozenModel):
    """Scope of the incident: affected assets, indicators, messages and critical assets in scope."""

    endpoints: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()  # domains, URLs, IPs, hashes
    messages: int = Field(default=0, ge=0)
    critical_assets: tuple[CriticalAssetHit, ...] = ()
    caps: Mapping[str, int] = {}  # thresholds.blast_radius as {"endpoints", "users", "indicators", "messages"}
    exceeds: tuple[str, ...] = ()  # informational; PackageBuilder decides ELEVATED
    record_ids: tuple[str, ...] = ()

    @field_validator("endpoints", "users", "record_ids")
    @classmethod
    def _unique(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        return _sorted_unique(value, info.field_name)

    @field_validator("indicators")
    @classmethod
    def _unique_indicators(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("indicators must be unique")
        return value

    @field_validator("caps")
    @classmethod
    def _caps(cls, value: Mapping[str, int]) -> Mapping[str, int]:
        unknown = set(value) - set(BLAST_RADIUS_CAP_NAMES)
        if unknown:
            raise ValueError(f"unknown blast-radius caps {sorted(unknown)}")
        if any(v < 0 for v in value.values()):
            raise ValueError("blast-radius caps must be >= 0")
        return dict(value)

    @field_validator("exceeds")
    @classmethod
    def _exceeds(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(v not in BLAST_RADIUS_CAP_NAMES for v in value) or len(value) != len(set(value)):
            raise ValueError(f"exceeds must name distinct caps of {BLAST_RADIUS_CAP_NAMES}")
        return value

    def to_blast_radius(self) -> BlastRadius:
        """The Phase 0 ``BlastRadius`` model (counts and names only)."""
        return BlastRadius(endpoints=self.endpoints, users=self.users, indicators=self.indicators,
                           messages=self.messages)

    def rule_item(self) -> dict[str, Any]:
        """JSON-mode dump plus counts and the union of critical-asset classes for rule expressions."""
        item = self.model_dump(mode="json")
        item["endpoint_count"] = len(self.endpoints)
        item["user_count"] = len(self.users)
        item["indicator_count"] = len(self.indicators)
        item["critical_asset_classes"] = sorted({c.value for hit in self.critical_assets for c in hit.classes})
        item["has_critical_asset"] = bool(self.critical_assets)
        return item
