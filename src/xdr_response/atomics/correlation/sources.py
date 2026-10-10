"""Cross-source evidence: one profile per entity, merged over every source that reported it (Phase 5).

Secure Endpoint, Defender, Umbrella, Secure Cloud Analytics, Entra, the email gateways and the intel
services each report their own records about the same host, user or indicator. A profile groups
those records per source (integration), under the entity's canonical spelling (aliases merged), and
says how many **independent** sources attest the entity.

Independence is about provenance, not about the number of records:

* every integration belongs to one source family (``SOURCE_FAMILIES``); more records, more atomics or
  more incidents from the same family never count twice;
* aggregators (``cisco_xdr``, ``microsoft_cloud``, ``splunk``) relay what other products saw, so they
  add an independent source only when no first-hand source reported the entity;
* an integration the table does not know is a family of its own.

Pure and deterministic: records are only read and cited by id, nothing is inferred or invented.
Confidence derived from these counts is context for the analyst; it never changes an approval level.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from types import MappingProxyType
from typing import Any

from pydantic import AwareDatetime, Field, model_validator

from xdr_response.atomics.correlation.aliases import EntityAliases
from xdr_response.atomics.correlation.correlate import _record_entities, _record_time, _resolve_aliases
from xdr_response.atomics.correlation.models import EntityRef
from xdr_response.atomics.evidence import RecordIndex
from xdr_response.atomics.records import (
    AtomicResult,
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EnrichmentRecord,
    HashPrevalenceRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
    RecordBase,
    RecordKind,
)
from xdr_response.models._base import FrozenModel
from xdr_response.models.enums import Verdict

__all__ = [
    "AGGREGATOR_PREFIX",
    "SOURCE_FAMILIES",
    "EntityProfile",
    "SourceObservation",
    "build_profile",
    "independent_families",
    "profile_entities",
    "source_family",
    "worst_verdict",
]

AGGREGATOR_PREFIX = "aggregator:"

#: Provenance family per integration. Different Microsoft or Cisco products are different sensors
#: (an EDR, a mail gateway, a DNS resolver, the identity provider) and count as independent;
#: aggregators relay other products and are marked with ``AGGREGATOR_PREFIX``.
SOURCE_FAMILIES: Mapping[str, str] = MappingProxyType({
    "secure_endpoint": "cisco_secure_endpoint",
    "secure_email": "cisco_secure_email",
    "secure_malware_analytics": "cisco_secure_malware_analytics",
    "secure_cloud_analytics": "cisco_secure_cloud_analytics",
    "umbrella": "cisco_umbrella",
    "meraki": "cisco_meraki",
    "cisco_xdr": AGGREGATOR_PREFIX + "cisco_xdr",
    "entra": "microsoft_entra",
    "defender_endpoint": "microsoft_defender_endpoint",
    "defender_o365": "microsoft_defender_office",
    "intune": "microsoft_intune",
    "microsoft_cloud": AGGREGATOR_PREFIX + "microsoft_defender_xdr",
    "virustotal": "virustotal",
    "alienvault_otx": "alienvault_otx",
    "hibp": "hibp",
    "splunk": AGGREGATOR_PREFIX + "splunk",
})

_VERDICT_RANK: Mapping[Verdict, int] = MappingProxyType(
    {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3})
_VERDICT_RECORDS = (EnrichmentRecord, DetectionRecord, ProcessEventRecord, NetworkConnectionRecord, DnsQueryRecord,
                    HashPrevalenceRecord, PersistenceItemRecord, EmailMessageRecord)


def source_family(integration: str) -> str:
    """The provenance family of an integration (the integration name itself when unknown)."""
    return SOURCE_FAMILIES.get(integration, integration)


def independent_families(integrations: Iterable[str]) -> tuple[str, ...]:
    """Independent source families behind ``integrations``, sorted.

    Aggregator families count only when no first-hand family is present.
    """
    families = {source_family(i) for i in integrations}
    first_hand = {f for f in families if not f.startswith(AGGREGATOR_PREFIX)}
    return tuple(sorted(first_hand or families))


def worst_verdict(verdicts: Iterable[Verdict]) -> Verdict:
    """MALICIOUS > SUSPICIOUS > CLEAN > UNKNOWN (UNKNOWN when there is none)."""
    return max(verdicts, key=_VERDICT_RANK.__getitem__, default=Verdict.UNKNOWN)


def _record_verdict(record: RecordBase) -> Verdict:
    if isinstance(record, _VERDICT_RECORDS):
        return record.verdict
    return Verdict.UNKNOWN


def _sorted_ids(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


class SourceObservation(FrozenModel):
    """What one integration reported about one entity."""

    integration: str = Field(min_length=1)
    family: str = Field(min_length=1)
    record_ids: tuple[str, ...] = Field(min_length=1)  # sorted, unique
    kinds: tuple[RecordKind, ...] = Field(min_length=1)  # record kinds, sorted
    verdict: Verdict = Verdict.UNKNOWN  # worst rating of the entity itself (its enrichment records)
    activity_verdict: Verdict = Verdict.UNKNOWN  # worst verdict of any of its records (detections, traffic)
    reputation_only: bool = False  # every record is an enrichment (a rating, not an observation)

    @model_validator(mode="after")
    def _consistent(self) -> "SourceObservation":
        if list(self.record_ids) != list(_sorted_ids(self.record_ids)):
            raise ValueError("record_ids must be unique and sorted")
        if self.family != source_family(self.integration):
            raise ValueError("family must be source_family(integration)")
        return self


class EntityProfile(FrozenModel):
    """Every source's evidence about one entity (canonical spelling), merged across sources."""

    entity: EntityRef
    aliases: tuple[EntityRef, ...] = ()  # other spellings merged into ``entity``
    observations: tuple[SourceObservation, ...] = Field(min_length=1)  # sorted by integration
    families: tuple[str, ...]  # independent_families(integrations), sorted
    independent_sources: int = Field(ge=1)
    first_hand_sources: int = Field(ge=0)  # independent families with a non-enrichment record
    verdict: Verdict = Verdict.UNKNOWN  # worst rating of the entity itself over the observations
    activity_verdict: Verdict = Verdict.UNKNOWN  # worst verdict of the activity it is part of
    contradicted: bool = False  # one family rates it CLEAN while another rates it SUSPICIOUS or MALICIOUS
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    incidents: tuple[str, ...] = ()  # cross-workflow profiles: the incidents whose records cite it

    @model_validator(mode="after")
    def _consistent(self) -> "EntityProfile":
        names = [o.integration for o in self.observations]
        if names != sorted(set(names)):
            raise ValueError("observations must be unique per integration and sorted")
        if self.families != independent_families(names) or self.independent_sources != len(self.families):
            raise ValueError("families and independent_sources must follow the observations")
        if self.entity in self.aliases:
            raise ValueError("an entity is not its own alias")
        return self

    @property
    def integrations(self) -> tuple[str, ...]:
        return tuple(o.integration for o in self.observations)

    @property
    def record_ids(self) -> tuple[str, ...]:
        return _sorted_ids(rid for o in self.observations for rid in o.record_ids)

    def rule_item(self) -> dict[str, Any]:
        """JSON-mode dump plus ``integrations`` and ``record_ids`` for rule expressions."""
        item = self.model_dump(mode="json")
        item["integrations"] = list(self.integrations)
        item["record_ids"] = list(self.record_ids)
        return item


def _observation(integration: str, records: Sequence[RecordBase]) -> SourceObservation:
    return SourceObservation(
        integration=integration,
        family=source_family(integration),
        record_ids=_sorted_ids(r.record_id for r in records),
        kinds=tuple(sorted({r.kind for r in records}, key=lambda k: k.value)),
        verdict=worst_verdict(r.verdict for r in records if isinstance(r, EnrichmentRecord)),
        activity_verdict=worst_verdict(_record_verdict(r) for r in records),
        reputation_only=all(isinstance(r, EnrichmentRecord) for r in records),
    )


def _contradicted(records: Sequence[RecordBase]) -> bool:
    """A family rates the entity CLEAN while another family rates it SUSPICIOUS or MALICIOUS."""
    ratings = [r for r in records if isinstance(r, EnrichmentRecord)]
    clean = {source_family(r.integration) for r in ratings if r.verdict is Verdict.CLEAN}
    bad = {source_family(r.integration) for r in ratings if r.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)}
    return any(c != b for c in clean for b in bad)


def build_profile(entity: EntityRef, records: Sequence[RecordBase], *, aliases: Sequence[EntityRef] = (),
                  incidents: Iterable[str] = ()) -> EntityProfile:
    """The profile of ``entity`` from the records that mention it (at least one)."""
    unique = {r.record_id: r for r in records}
    by_integration: dict[str, list[RecordBase]] = defaultdict(list)
    for record in unique.values():
        by_integration[record.integration].append(record)
    observations = tuple(_observation(name, by_integration[name]) for name in sorted(by_integration))
    families = independent_families(by_integration)
    first_hand = independent_families(o.integration for o in observations if not o.reputation_only) \
        if any(not o.reputation_only for o in observations) else ()
    times = [t for t in (_record_time(r) for r in unique.values()) if t is not None]
    return EntityProfile(
        entity=entity,
        aliases=tuple(sorted({a.key(): a for a in aliases if a != entity}.values(), key=EntityRef.sort_key)),
        observations=observations,
        families=families,
        independent_sources=len(families),
        first_hand_sources=len(first_hand),
        verdict=worst_verdict(o.verdict for o in observations),
        activity_verdict=worst_verdict(o.activity_verdict for o in observations),
        contradicted=_contradicted(list(unique.values())),
        first_seen=min(times) if times else None,
        last_seen=max(times) if times else None,
        incidents=tuple(sorted(set(incidents))),
    )


def profile_entities(results: Sequence[AtomicResult] | RecordIndex, *,
                     entities: Collection[EntityRef] | None = None,
                     merge_aliases: bool = True) -> tuple[EntityProfile, ...]:
    """One profile per entity the records mention (or per entity of ``entities``), sorted by entity.

    ``merge_aliases`` (default on here: profiles exist to merge sources) maps every mention to its
    canonical spelling first. An entity of ``entities`` that no record mentions has no profile.
    """
    index = results if isinstance(results, RecordIndex) else RecordIndex(results)
    aliases = _resolve_aliases(index) if merge_aliases else EntityAliases()
    mentions: dict[str, list[RecordBase]] = defaultdict(list)
    refs: dict[str, EntityRef] = {}
    for record in index.records():
        seen: set[str] = set()
        for raw in _record_entities(record):
            canonical = aliases.canon(raw)
            if canonical.key() in seen:
                continue
            seen.add(canonical.key())
            refs.setdefault(canonical.key(), canonical)
            mentions[canonical.key()].append(record)
    wanted = None if entities is None else {aliases.canon(EntityRef.model_validate(e)).key() for e in entities}
    keys = sorted((k for k in refs if wanted is None or k in wanted), key=lambda k: refs[k].sort_key())
    return tuple(build_profile(refs[k], mentions[k], aliases=aliases.aliases_of(refs[k])) for k in keys)
