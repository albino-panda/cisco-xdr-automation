"""Scoring one enriched observable (architecture 14.1.3 steps 3 and 4).

``score_observable`` builds the :class:`ScoringContext` (critical-asset classes of the observable,
every enricher as an expected source, failed and not-queried sources) and asks the scoring engine
for the breakdown and the aggregate verdict. Risk and confidence come only from the engine; no
single vendor's verdict is ever copied into the report.

The engine is reached through :data:`_backend` so unit tests of this key can stand in a local fake
for the scoring key's behaviour (14.0.3); production always uses :func:`engine_backend`. The
scoring modules are imported when first used, which keeps this model-adjacent package importable
on its own.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence

from xdr_response.atomics.context import AtomicContext
from xdr_response.atomics.enrichment._sources import SourceAnswer
from xdr_response.atomics.records import EnrichmentRecord, SourceOutcome
from xdr_response.config.schema import ScoringSettings
from xdr_response.models import ActionType, CriticalAssetClass, Observable, Verdict, get_action_spec
from xdr_response.models.scoring import ScoreBreakdown, ScoringContext

__all__ = ["ScoringBackend", "engine_backend", "scoring_context", "score_observable"]

#: ``(settings, enrichment records, context) -> (breakdown, aggregate verdict)``.
ScoringBackend = Callable[[ScoringSettings, Sequence[EnrichmentRecord], ScoringContext],
                          tuple[ScoreBreakdown, Verdict]]


def engine_backend(settings: ScoringSettings, records: Sequence[EnrichmentRecord],
                   context: ScoringContext) -> tuple[ScoreBreakdown, Verdict]:
    """The scoring key's engine: ``signals_from_enrichment`` -> ``ScoringEngine.score`` -> verdict."""
    from xdr_response.scoring.engine import ScoringEngine
    from xdr_response.scoring.signals import signals_from_enrichment
    from xdr_response.scoring.verdict import aggregate_verdict

    signals = signals_from_enrichment(records)
    breakdown = ScoringEngine(settings).score(signals, context=context)
    return breakdown, aggregate_verdict(signals, breakdown, bands=settings.bands)


_backend: ScoringBackend = engine_backend


def _critical_classes(ctx: AtomicContext, action_type: ActionType,
                      subject: Observable) -> tuple[CriticalAssetClass, ...]:
    """Critical-asset classes of the subject for the atomic's catalog target kind."""
    kind = get_action_spec(action_type).target_kind
    return tuple(ctx.critical_assets.classify(subject.value, kind))


def scoring_context(ctx: AtomicContext, action_type: ActionType, subject: Observable,
                    answers: Sequence[SourceAnswer]) -> ScoringContext:
    """Expected, failed and not-queried sources plus the subject's critical-asset classes."""
    statuses = [a.status for a in answers]
    return ScoringContext(
        critical_asset_classes=_critical_classes(ctx, action_type, subject),
        expected_sources=tuple(s.integration for s in statuses),
        failed_sources=tuple((s.integration, s.health) for s in statuses if s.outcome is SourceOutcome.FAILED),
        not_queried=tuple((s.integration, s.reason) for s in statuses if s.outcome is SourceOutcome.NOT_QUERIED),
    )


def score_observable(ctx: AtomicContext, records: Sequence[EnrichmentRecord],
                     context: ScoringContext) -> tuple[ScoreBreakdown, Verdict]:
    """Breakdown and aggregate verdict for one observable's enrichment records."""
    return _backend(ctx.settings.thresholds.scoring, tuple(records), context)
