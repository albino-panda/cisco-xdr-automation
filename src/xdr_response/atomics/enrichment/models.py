"""Enrichment report model (architecture 14.1.3, layer 0 model module).

:class:`ObservableReport` is the brief's normalized observable
(``{"type", "value", "risk_score", "confidence", "sources", "verdict"}``) together with the
per-source detail every read atomic carries: one :class:`SourceStatus` per enricher, one
:class:`EnrichmentRecord` per answering source and the scoring breakdown. Risk and confidence are
two separate numbers taken from the breakdown; the verdict is the aggregate over all sources, never
one vendor's word.
"""
from __future__ import annotations

from typing import Any

from pydantic import model_validator

from xdr_response.atomics.records import AtomicResult, EnrichmentRecord, RecordKind, SourceOutcome
from xdr_response.models import ActionCategory, ObservableType, Verdict, get_action_spec
from xdr_response.models._base import Score
from xdr_response.models.scoring import ScoreBreakdown

__all__ = ["ObservableReport"]


class ObservableReport(AtomicResult):
    """The result of every enrichment atomic: one normalized observable and its sources."""

    type: ObservableType
    value: str  # normalized (== subject.value)
    risk_score: Score
    confidence: Score
    verdict: Verdict  # scoring.verdict.aggregate_verdict (never one vendor's word)
    breakdown: ScoreBreakdown

    @model_validator(mode="after")
    def _report_consistent(self) -> "ObservableReport":
        if (self.type, self.value) != (self.subject.type, self.subject.value):
            raise ValueError("type and value must equal the normalized subject")
        if get_action_spec(self.action_type).category is not ActionCategory.ENRICHMENT:
            raise ValueError("an ObservableReport needs an ENRICHMENT action type")
        if any(r.kind is not RecordKind.ENRICHMENT for r in self.records):
            raise ValueError("an ObservableReport holds enrichment records only")
        if (self.risk_score, self.confidence) != (self.breakdown.risk_score, self.breakdown.confidence_score):
            raise ValueError("risk_score and confidence must come from the breakdown")
        return self

    # ------------------------------------------------------------ views --
    @property
    def not_queried(self) -> tuple[str, ...]:
        """Sources deliberately not asked (disclosure policy), ``INTEGRATION_NAMES`` order."""
        return tuple(s.integration for s in self.sources if s.outcome is SourceOutcome.NOT_QUERIED)

    def enrichment_records(self) -> tuple[EnrichmentRecord, ...]:
        """The records, typed (the validator admits enrichment records only)."""
        return tuple(r for r in self.records if isinstance(r, EnrichmentRecord))

    def categories(self) -> tuple[str, ...]:
        """Union of the vendor categories of every record, sorted."""
        return tuple(sorted({c for r in self.enrichment_records() for c in r.categories}))

    def source_verdicts(self) -> dict[str, str]:
        """``{integration: verdict}`` of every answering source."""
        return {r.integration: r.verdict.value for r in self.enrichment_records()}

    def normalized(self) -> dict[str, Any]:
        """Exactly ``{"type", "value", "risk_score", "confidence", "sources", "verdict"}``."""
        return {
            "type": self.type.value,
            "value": self.value,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "sources": list(self.answered),
            "verdict": self.verdict.value,
        }

    def rule_item(self) -> dict[str, Any]:
        """Common read-atomic keys + :meth:`normalized` + per-source detail (14.1.3)."""
        item = dict(super().rule_item())
        item.update(self.normalized())
        item.update({
            "record_ids": list(self.record_ids()),
            "failed_sources": list(self.failed),
            "not_queried": list(self.not_queried),
            "degraded": self.degraded,
            "categories": list(self.categories()),
            "source_verdicts": self.source_verdicts(),
        })
        return item

