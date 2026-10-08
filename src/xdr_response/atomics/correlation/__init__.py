"""Correlation and blast radius over atomic results (architecture section 14.1.5).

Pure, deterministic functions: no adapter calls, no state changes. Links and blast-radius reports cite
the records they were computed from; ELEVATED approval stays with ``PackageBuilder``.
"""
from __future__ import annotations

from xdr_response.atomics.correlation.blast_radius import blast_radius
from xdr_response.atomics.correlation.correlate import (
    DEFAULT_WINDOW,
    FRAMEWORK_LINK_KINDS,
    build_timeline,
    correlate,
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

__all__ = [
    "BLAST_RADIUS_CAP_NAMES",
    "DEFAULT_WINDOW",
    "FRAMEWORK_LINK_KINDS",
    "BlastRadiusReport",
    "CorrelationLink",
    "CorrelationResult",
    "CriticalAssetHit",
    "EntityRef",
    "LinkKind",
    "TimelineEntry",
    "blast_radius",
    "build_timeline",
    "correlate",
]
