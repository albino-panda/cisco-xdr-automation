"""Deterministic scoring engine (architecture 14.2.2, docs/threat-scoring.md section 5).

The engine turns record-backed ``ScoringSignal`` objects for one target into two separate numbers:

* **risk** (impact if the evidence is right): highest weighted category, reputation cap,
  corroboration bonus (only from another integration: a source never corroborates itself),
  single-source cap (one integration never reaches CRITICAL unless it is a high-severity
  behavioural detection), critical-asset bonus;
* **confidence** (strength of the evidence): base, reputation-only cap, independent-source bonus,
  contradiction penalty, failed-source penalty.

Rounding happens once at the end (half up), then the scores are clamped to 0..100. Input order
never changes the output. Scores only inform the analyst: the engine has no way to approve,
execute or change an approval level, and it accepts nothing but signals that cite record ids.
"""
from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from xdr_response.config.schema import ScoringSettings
from xdr_response.models.canonical import canonical_json, sha256_hex
from xdr_response.models.enums import HealthStatus, Verdict
from xdr_response.models.recommendation import risk_band
from xdr_response.models.scoring import (
    Contribution,
    ScoreBreakdown,
    ScoringContext,
    ScoringSignal,
    SignalCategory,
)

__all__ = ["ScoringEngine"]

_SUPPORTING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
#: Categories that are never a behavioural detection (a vendor's word or a derived association).
_NOT_BEHAVIOURAL = frozenset({SignalCategory.REPUTATION, SignalCategory.CAMPAIGN_ASSOCIATION})
_FAILING_HEALTH = frozenset({HealthStatus.UNAVAILABLE, HealthStatus.AUTH_FAILED, HealthStatus.RATE_LIMITED})


# --------------------------------------------------------------- helpers --
def _round_half_up(value: float) -> int:
    """Round once, half up (``math.floor(x + 0.5)``).

    Binary float noise from weight multiplication (``x.4999999999``) is removed first so that a
    mathematically exact half always rounds up.
    """
    return math.floor(round(value, 9) + 0.5)


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def _sort_key(signal: ScoringSignal) -> tuple[object, ...]:
    """Total order over signals so that input order never matters."""
    return (signal.category.value, signal.integration, signal.observable.type.value, signal.observable.value,
            signal.record_ids, signal.verdict.value, signal.severity, signal.confidence, signal.health.value,
            signal.origin, signal.note)


def _observable_key(signal: ScoringSignal) -> tuple[str, str]:
    return signal.observable.type.value, signal.observable.value.strip().lower()


def _record_ids(signals: Iterable[ScoringSignal]) -> tuple[str, ...]:
    return tuple(sorted({rid for s in signals for rid in s.record_ids}))


def _dedupe(items: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def _resolve_weights(settings: ScoringSettings,
                     overrides: Mapping[SignalCategory, float] | None) -> dict[SignalCategory, float]:
    """Effective category weights: workflow override, else configured, else DEFAULT_WEIGHTS."""
    weights = {category: settings.weight(category) for category in SignalCategory}
    for key, value in (overrides or {}).items():
        category = SignalCategory(key)  # ValueError for an unknown category
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f"weight for {category.value} must be a number, got {value!r}")
        if not 0.0 <= float(value) <= 1.0:
            raise ValueError(f"weight for {category.value} must be in 0.0..1.0, got {value!r}")
        weights[category] = float(value)
    return weights


def _settings_hash(settings: ScoringSettings, overrides: Mapping[SignalCategory, float] | None) -> str:
    """Hash of the scoring settings actually used (overridden weights included)."""
    data = settings.model_dump(mode="python")
    if overrides:
        data["weights"] = {**data["weights"], **{SignalCategory(k): float(v) for k, v in overrides.items()}}
    return sha256_hex(canonical_json(data, allow_floats=True))


# ------------------------------------------------------------------ risk --
@dataclass(frozen=True)
class _CategoryValue:
    category: SignalCategory
    integration: str
    weighted: float
    record_ids: tuple[str, ...]
    members: tuple[ScoringSignal, ...] = ()


def _weighted(signal: ScoringSignal, weights: Mapping[SignalCategory, float], settings: ScoringSettings) -> float:
    """``severity * weight``; the reputation category capped."""
    value = signal.severity * weights[signal.category]
    if signal.category is SignalCategory.REPUTATION:
        value = min(value, float(settings.caps.reputation_max_contribution))
    return value


def _category_values(supporting: Sequence[ScoringSignal], weights: Mapping[SignalCategory, float],
                     settings: ScoringSettings) -> tuple[list[_CategoryValue], list[str]]:
    """Per category: highest severity times weight; the reputation category is capped."""
    values: list[_CategoryValue] = []
    caps: list[str] = []
    for category in sorted({s.category for s in supporting}, key=lambda c: c.value):
        members = [s for s in supporting if s.category is category]
        top = max(members, key=lambda s: s.severity)  # max keeps the first of equal values
        weighted = top.severity * weights[category]
        cap = settings.caps.reputation_max_contribution
        if category is SignalCategory.REPUTATION and weighted > cap:
            weighted = float(cap)
            caps.append(f"reputation capped at {cap}")
        values.append(_CategoryValue(category, top.integration, weighted, _record_ids(members), tuple(members)))
    return values, caps


def _critical_bound(settings: ScoringSettings) -> int:
    return int(settings.bands["CRITICAL"])


def _high_severity_detection(supporting: Sequence[ScoringSignal], settings: ScoringSettings) -> bool:
    """A behavioural detection (not a vendor verdict, reputation or association) of CRITICAL-band severity."""
    bound = _critical_bound(settings)
    return any(s.verdict is Verdict.MALICIOUS and not s.vendor_verdict and s.category not in _NOT_BEHAVIOURAL
               and s.severity >= bound for s in supporting)


def _independent_value(value: _CategoryValue, base_integration: str, weights: Mapping[SignalCategory, float],
                       settings: ScoringSettings) -> float:
    """The category's weighted value from integrations other than the base signal's (0.0 when none)."""
    return max((_weighted(s, weights, settings) for s in value.members if s.integration != base_integration),
               default=0.0)


def _weighty_integrations(supporting: Sequence[ScoringSignal], base: _CategoryValue,
                          weights: Mapping[SignalCategory, float], settings: ScoringSettings) -> set[str]:
    """The base integration plus every other integration with a signal worth corroboration.min."""
    floor = settings.corroboration.min
    return {base.integration} | {s.integration for s in supporting
                                 if s.integration != base.integration and _weighted(s, weights, settings) >= floor}


def _risk(values: list[_CategoryValue], supporting: Sequence[ScoringSignal], context: ScoringContext,
          weights: Mapping[SignalCategory, float],
          settings: ScoringSettings) -> tuple[float, list[Contribution], list[str]]:
    """Base risk, corroboration bonus, single-source cap and critical-asset bonus (5.1, 5.4)."""
    base = max(values, key=lambda v: v.weighted)  # first of equal values wins
    corro = settings.corroboration
    others = [v for v in values if v is not base]
    # A source never corroborates itself: a category corroborates only through another integration.
    independent = {v.category: _independent_value(v, base.integration, weights, settings) for v in others}
    corroborating = [v for v in others if independent[v.category] >= corro.min]
    contributions = [Contribution(category=base.category, integration=base.integration,
                                  points=_round_half_up(base.weighted), applies_to="risk",
                                  record_ids=base.record_ids, note="base")]
    for v in others:
        if v in corroborating:
            note = "corroborates"
        elif v.weighted >= corro.min:
            note = f"same source as base ({base.integration}): does not corroborate"
        else:
            note = f"below corroboration minimum {corro.min}"
        contributions.append(Contribution(category=v.category, integration=v.integration,
                                          points=_round_half_up(v.weighted), applies_to="risk",
                                          record_ids=v.record_ids, note=note))
    caps: list[str] = []
    bonus = min(len(corroborating) * corro.step, corro.max)
    if len(corroborating) * corro.step > corro.max:
        caps.append(f"corroboration capped at {corro.max}")
    if bonus:
        contributions.append(Contribution(
            category="corroboration", integration=None, points=bonus, applies_to="risk",
            record_ids=_record_ids_of(corroborating),
            note=", ".join(v.category.value for v in corroborating)))
    total = base.weighted + bonus
    single_cap = _critical_bound(settings) - 1
    if (len(_weighty_integrations(supporting, base, weights, settings)) == 1 and total > single_cap
            and not _high_severity_detection(supporting, settings)):
        # 5.4: a single source never reaches CRITICAL on its own unless it is a high-severity
        # behavioural detection (an enrichment verdict, reputation or association never is).
        # A second integration whose weighted value stays below corroboration.min carries no
        # weight and does not make the risk multi-source.
        total = float(single_cap)
        caps.append(f"single source capped at {single_cap}")
    if context.critical_asset_classes and settings.context.critical_asset_bonus:
        points = settings.context.critical_asset_bonus
        total += points
        contributions.append(Contribution(
            category="critical_asset", integration=None, points=points, applies_to="risk",
            note=", ".join(c.value for c in context.critical_asset_classes)))
    return total, contributions, caps


def _record_ids_of(values: Iterable[_CategoryValue]) -> tuple[str, ...]:
    return tuple(sorted({rid for v in values for rid in v.record_ids}))


# ------------------------------------------------------------ confidence --
def _base_confidence(supporting: Sequence[ScoringSignal],
                     settings: ScoringSettings) -> tuple[ScoringSignal, int, bool, list[str]]:
    """Highest non-reputation confidence; reputation-only evidence is capped (5.2 steps 1-2)."""
    behavioural = [s for s in supporting if s.category is not SignalCategory.REPUTATION]
    if behavioural:
        top = max(behavioural, key=lambda s: s.confidence)
        return top, top.confidence, False, []
    top = max(supporting, key=lambda s: s.confidence)
    cap = settings.caps.reputation_only_confidence_cap
    if top.confidence > cap:
        return top, cap, True, [f"reputation-only confidence capped at {cap}"]
    return top, top.confidence, True, []


def _independent_sources(supporting: Sequence[ScoringSignal], base: ScoringSignal, base_points: int,
                         reputation_only: bool,
                         settings: ScoringSettings) -> tuple[int, list[Contribution], list[str]]:
    """Bonus per additional distinct supporting integration (5.2 step 3)."""
    conf = settings.confidence
    extra = sorted({s.integration for s in supporting} - {base.integration})
    if not extra:
        return 0, [], []
    caps: list[str] = []
    bonus = min(len(extra) * conf.independent_source_step, conf.independent_source_max)
    if len(extra) * conf.independent_source_step > conf.independent_source_max:
        caps.append(f"independent-source bonus capped at {conf.independent_source_max}")
    if reputation_only:
        headroom = max(0, settings.caps.reputation_only_confidence_cap - base_points)
        if bonus > headroom:
            bonus = headroom
            caps.append(f"reputation-only confidence capped at {settings.caps.reputation_only_confidence_cap}")
    if not bonus:
        return 0, [], caps
    ids = _record_ids(s for s in supporting if s.integration in extra)
    return bonus, [Contribution(category="independent_sources", integration=None, points=bonus,
                                applies_to="confidence", record_ids=ids, note=", ".join(extra))], caps


def _contradictions(supporting: Sequence[ScoringSignal], clean: Sequence[ScoringSignal],
                    settings: ScoringSettings) -> tuple[int, list[Contribution]]:
    """Penalty per integration rating a supported observable CLEAN (5.2 step 4)."""
    supported = {_observable_key(s) for s in supporting}
    contradicting = [s for s in clean if _observable_key(s) in supported]
    penalty = settings.confidence.contradiction_penalty
    contributions = []
    for integration in sorted({s.integration for s in contradicting}):
        ids = _record_ids(s for s in contradicting if s.integration == integration)
        contributions.append(Contribution(category="contradiction", integration=integration, points=-penalty,
                                          applies_to="confidence", record_ids=ids, note="rated CLEAN"))
    return penalty * len(contributions), contributions


def _failed_sources(context: ScoringContext, settings: ScoringSettings) -> tuple[int, list[Contribution], list[str]]:
    """Penalty per expected source that failed, capped in total (5.2 step 5).

    Only UNAVAILABLE, AUTH_FAILED and RATE_LIMITED cost confidence, once per integration even
    when it failed with several of them in one run. When the caller names no
    expected sources, every failed source counts as expected (it was queried and did not answer).
    """
    conf = settings.confidence
    expected = set(context.expected_sources)
    penalised: list[tuple[str, HealthStatus]] = []
    for name, health in context.failed_sources:  # sorted by (integration, health)
        if health not in _FAILING_HEALTH or (expected and name not in expected):
            continue
        if any(name == seen for seen, _ in penalised):
            continue  # one source is penalised once, whatever its mix of failures
        penalised.append((name, health))
    remaining = conf.failed_source_max_penalty
    total = 0
    contributions = []
    caps: list[str] = []
    for name, health in penalised:
        points = min(conf.failed_source_penalty, remaining)
        if points < conf.failed_source_penalty:
            caps.append(f"failed-source penalty capped at {conf.failed_source_max_penalty}")
        remaining -= points
        total += points
        contributions.append(Contribution(category="failed_sources", integration=name, points=-points,
                                          applies_to="confidence", note=health.value))
    return total, contributions, caps


def _confidence(supporting: Sequence[ScoringSignal], clean: Sequence[ScoringSignal], context: ScoringContext,
                settings: ScoringSettings) -> tuple[float, list[Contribution], list[str], bool]:
    base, base_points, reputation_only, caps = _base_confidence(supporting, settings)
    contributions = [Contribution(category=base.category, integration=base.integration, points=base_points,
                                  applies_to="confidence", record_ids=base.record_ids, note="base")]
    bonus, bonus_contribs, bonus_caps = _independent_sources(supporting, base, base_points, reputation_only,
                                                             settings)
    contradiction, contra_contribs = _contradictions(supporting, clean, settings)
    failed, failed_contribs, failed_caps = _failed_sources(context, settings)
    contributions += bonus_contribs + contra_contribs + failed_contribs
    total = base_points + bonus - contradiction - failed
    return total, contributions, caps + bonus_caps + failed_caps, reputation_only


# ---------------------------------------------------------------- engine --
class ScoringEngine:
    """Scores one target from record-backed signals. Pure and deterministic."""

    def __init__(self, settings: ScoringSettings) -> None:
        self._settings = settings
        self._hash = _settings_hash(settings, None)

    @property
    def settings_hash(self) -> str:
        """sha256 of the canonical scoring settings (no workflow weight overrides)."""
        return self._hash

    def score(self, signals: Sequence[ScoringSignal], *, context: ScoringContext,
              weights: Mapping[SignalCategory, float] | None = None) -> ScoreBreakdown:
        """Risk and confidence for one target.

        ``weights`` are workflow overrides of category weights only; caps, steps and penalties
        are not overridable. Signals with verdict UNKNOWN are ignored; CLEAN signals only count
        for the contradiction penalty and never lower risk.
        """
        settings = self._settings
        effective = _resolve_weights(settings, weights)
        ordered = sorted(signals, key=_sort_key)
        supporting = [s for s in ordered if s.verdict in _SUPPORTING]
        clean = [s for s in ordered if s.verdict is Verdict.CLEAN]
        failed = tuple(f"{name} ({health.value})" for name, health in context.failed_sources)
        not_queried = tuple(f"{name} ({reason})" for name, reason in context.not_queried)
        settings_hash = _settings_hash(settings, weights)
        if not supporting:
            return ScoreBreakdown(risk_score=0, confidence_score=0, risk_band=risk_band(0, settings.bands),
                                  contributions=(), failed_sources=failed, not_queried=not_queried,
                                  settings_hash=settings_hash)
        values, value_caps = _category_values(supporting, effective, settings)
        risk_total, risk_contribs, risk_caps = _risk(values, supporting, context, effective, settings)
        conf_total, conf_contribs, conf_caps, reputation_only = _confidence(supporting, clean, context, settings)
        risk = _clamp(_round_half_up(risk_total))
        return ScoreBreakdown(
            risk_score=risk, confidence_score=_clamp(_round_half_up(conf_total)),
            risk_band=risk_band(risk, settings.bands),
            contributions=tuple(risk_contribs + conf_contribs),
            caps_applied=_dedupe(value_caps + risk_caps + conf_caps),
            failed_sources=failed, not_queried=not_queried, reputation_only=reputation_only,
            settings_hash=settings_hash)

    def package_scores(self, breakdowns: Sequence[ScoreBreakdown]) -> tuple[int, int]:
        """(max risk, round-half-up mean confidence); (0, 0) for none."""
        if not breakdowns:
            return 0, 0
        risk = max(b.risk_score for b in breakdowns)
        total = sum(b.confidence_score for b in breakdowns)
        count = len(breakdowns)
        return risk, (2 * total + count) // (2 * count)
