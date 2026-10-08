"""Aggregate verdict over several sources (architecture 14.2.2).

No single vendor's verdict is absolute truth: one vendor's ``MALICIOUS`` on its own is
``SUSPICIOUS`` unless the risk reaches the HIGH band through a behavioural detection (a
non-reputation signal that is not a vendor verdict), or at least two distinct integrations give a
``MALICIOUS`` vendor verdict (reputation or enrichment answer) and none rates the target ``CLEAN``.
An enrichment answer (``ScoringSignal.vendor_verdict``) is a vendor verdict whatever its category:
a sandbox, email-gateway or identity verdict alone is ``SUSPICIOUS``.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from xdr_response.models.enums import RiskBand, Verdict
from xdr_response.models.scoring import ScoreBreakdown, ScoringSignal, SignalCategory

__all__ = ["aggregate_verdict"]

_DEFAULT_HIGH = 60


def _high_bound(bands: Mapping[str, int] | None) -> int:
    if bands is None:
        return _DEFAULT_HIGH
    return int(bands[RiskBand.HIGH.value])


def _is_vendor_verdict(signal: ScoringSignal) -> bool:
    return signal.vendor_verdict or signal.category is SignalCategory.REPUTATION


def _is_malicious(signals: Sequence[ScoringSignal], breakdown: ScoreBreakdown, high: int) -> bool:
    behavioural = any(s.verdict is Verdict.MALICIOUS and not _is_vendor_verdict(s) for s in signals)
    if breakdown.risk_score >= high and behavioural:
        return True
    vendor_sources = {s.integration for s in signals if s.verdict is Verdict.MALICIOUS and _is_vendor_verdict(s)}
    any_clean = any(s.verdict is Verdict.CLEAN for s in signals)
    return len(vendor_sources) >= 2 and not any_clean


def aggregate_verdict(signals: Sequence[ScoringSignal], breakdown: ScoreBreakdown, *,
                      bands: Mapping[str, int] | None = None) -> Verdict:
    """Combine the signals of one target into one verdict.

    ``bands`` are the configured risk bands (``ScoringSettings.bands``); None uses the built-in
    HIGH lower bound of 60. UNKNOWN signals are ignored.
    """
    considered = [s for s in signals if s.verdict is not Verdict.UNKNOWN]
    if _is_malicious(considered, breakdown, _high_bound(bands)):
        return Verdict.MALICIOUS
    if any(s.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) for s in considered):
        return Verdict.SUSPICIOUS
    if any(s.verdict is Verdict.CLEAN for s in considered) and not breakdown.failed_sources:
        return Verdict.CLEAN
    return Verdict.UNKNOWN
