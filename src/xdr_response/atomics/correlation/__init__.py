"""Correlation and blast radius over atomic results (architecture section 14.1.5).

Pure, deterministic functions: no adapter calls, no state changes. Links and blast-radius reports cite
the records they were computed from; ELEVATED approval stays with ``PackageBuilder``.

Phase 5 adds cross-source correlation: entity aliases (``aliases``), per-entity evidence merged over
independent sources (``sources``) and links, groups and blast-radius rollups across workflow runs
(``cross_workflow``).
"""
from __future__ import annotations

from xdr_response.atomics.correlation.aliases import EntityAliases
from xdr_response.atomics.correlation.blast_radius import blast_radius
from xdr_response.atomics.correlation.correlate import (
    DEFAULT_WINDOW,
    FRAMEWORK_LINK_KINDS,
    build_timeline,
    correlate,
)
from xdr_response.atomics.correlation.cross_workflow import (
    DEFAULT_CROSS_WINDOW,
    BlastRadiusRollup,
    CrossWorkflowCorrelation,
    IncidentCitation,
    IncidentGroup,
    IncidentLink,
    IncidentSummary,
    LinkBasis,
    RollupCriticalAsset,
    RunSnapshot,
    SharedEntity,
    correlate_workflows,
    link_confidence,
    rollup_blast_radius,
)
from xdr_response.atomics.correlation.models import (
    BLAST_RADIUS_CAP_NAMES,
    BlastRadiusReport,
    CorrelationLink,
    CorrelationResult,
    CriticalAssetHit,
    EntityRef,
    LinkKind,
    TimelineEntry,
)
from xdr_response.atomics.correlation.sources import (
    SOURCE_FAMILIES,
    EntityProfile,
    SourceObservation,
    independent_families,
    profile_entities,
    source_family,
)

__all__ = [
    "BLAST_RADIUS_CAP_NAMES",
    "DEFAULT_CROSS_WINDOW",
    "DEFAULT_WINDOW",
    "FRAMEWORK_LINK_KINDS",
    "SOURCE_FAMILIES",
    "BlastRadiusReport",
    "BlastRadiusRollup",
    "CorrelationLink",
    "CorrelationResult",
    "CriticalAssetHit",
    "CrossWorkflowCorrelation",
    "EntityAliases",
    "EntityProfile",
    "EntityRef",
    "IncidentCitation",
    "IncidentGroup",
    "IncidentLink",
    "IncidentSummary",
    "LinkBasis",
    "LinkKind",
    "RollupCriticalAsset",
    "RunSnapshot",
    "SharedEntity",
    "SourceObservation",
    "TimelineEntry",
    "blast_radius",
    "build_timeline",
    "correlate",
    "correlate_workflows",
    "independent_families",
    "link_confidence",
    "profile_entities",
    "rollup_blast_radius",
    "source_family",
]
