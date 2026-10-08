"""Threat scoring (architecture 14.2, docs/threat-scoring.md).

Risk and confidence are two separate integers in 0..100, never merged. The engine is pure and
deterministic, takes only record-backed ``ScoringSignal`` objects and explains every point in a
``ScoreBreakdown``. Scores inform the analyst; they never approve, execute or change an approval
level. The models live in ``xdr_response.models.scoring``.
"""
from xdr_response.scoring.engine import ScoringEngine
from xdr_response.scoring.signals import (
    ENRICHMENT_CATEGORY,
    LEVEL_POINTS,
    RECORD_CONFIDENCE,
    SEVERITY_POINTS,
    signals_from_enrichment,
    signals_from_records,
)
from xdr_response.scoring.verdict import aggregate_verdict

__all__ = [
    "ScoringEngine",
    "aggregate_verdict",
    "ENRICHMENT_CATEGORY",
    "SEVERITY_POINTS",
    "LEVEL_POINTS",
    "RECORD_CONFIDENCE",
    "signals_from_enrichment",
    "signals_from_records",
]
