"""ScoringEngine (architecture 14.2.2, docs/threat-scoring.md sections 5, 9 and 10)."""
from __future__ import annotations

import inspect
import random

import pytest
from pydantic import ValidationError

from tests.unit.scoring._support import (
    CAT,
    DC,
    DOMAIN,
    HOST,
    ctx,
    engine,
    sig,
    worked_example_context,
    worked_example_signals,
)
from xdr_response.config.schema import ScoringSettings
from xdr_response.models.canonical import canonical_json, sha256_hex
from xdr_response.models.enums import CriticalAssetClass, HealthStatus, RiskBand, Verdict
from xdr_response.models.scoring import Contribution, ScoreBreakdown, ScoringContext, ScoringSignal
from xdr_response.scoring import ScoringEngine

FAILING = (HealthStatus.UNAVAILABLE, HealthStatus.AUTH_FAILED, HealthStatus.RATE_LIMITED)


def by(breakdown: ScoreBreakdown, applies_to: str, category: object) -> list[Contribution]:
    return [c for c in breakdown.contributions if c.applies_to == applies_to and c.category == category]


# ------------------------------------------------------- worked examples --
def test_worked_example_section_9():
    b = engine().score(worked_example_signals(), context=worked_example_context())
    assert (b.risk_score, b.risk_band, b.confidence_score) == (90, RiskBand.CRITICAL, 90)
    assert b.caps_applied == ("reputation capped at 50",)
    assert b.failed_sources == ("alienvault_otx (RATE_LIMITED)",)
    assert b.reputation_only is False
    assert b.explain() == (
        "risk 90 CRITICAL (endpoint_detection secure_endpoint 80; corroboration +10), "
        f"confidence 90 (base 85; independent sources +10; failed alienvault_otx -5), settings {b.settings_hash[:12]}")


def test_worked_example_contributions_cite_their_records():
    b = engine().score(worked_example_signals(), context=worked_example_context())
    [base] = [c for c in b.contributions if c.applies_to == "risk" and c.note == "base"]
    assert (base.category, base.integration, base.points, base.record_ids) == (
        CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, ("rec_se_2",))
    [corro] = by(b, "risk", "corroboration")
    assert corro.points == 10 and corro.record_ids == ("rec_um_5", "rec_vt_8")
    [rep] = by(b, "risk", CAT.REPUTATION)
    assert rep.points == 50 and rep.note == "corroborates"
    [conf_base] = [c for c in b.contributions if c.applies_to == "confidence" and c.note == "base"]
    assert (conf_base.integration, conf_base.points, conf_base.record_ids) == ("umbrella", 85, ("rec_um_5",))
    [indep] = by(b, "confidence", "independent_sources")
    assert indep.points == 10 and indep.note == "secure_endpoint, virustotal"
    [failed] = by(b, "confidence", "failed_sources")
    assert (failed.integration, failed.points, failed.note) == ("alienvault_otx", -5, "RATE_LIMITED")


def test_counter_example_reputation_only():
    b = engine().score([sig(CAT.REPUTATION, "virustotal", 90, 80, observable=DOMAIN)], context=ctx())
    assert (b.risk_score, b.risk_band, b.confidence_score, b.reputation_only) == (50, RiskBand.MEDIUM, 50, True)
    assert b.caps_applied == ("reputation capped at 50", "reputation-only confidence capped at 50")
    assert "reputation only" in b.explain()


def test_counter_example_with_clean_contradiction():
    signals = [sig(CAT.REPUTATION, "virustotal", 90, 80, observable=DOMAIN),
               sig(CAT.REPUTATION, "umbrella", 0, 90, verdict=Verdict.CLEAN, observable=DOMAIN)]
    b = engine().score(signals, context=ctx())
    assert (b.risk_score, b.confidence_score) == (50, 35)
    [contra] = by(b, "confidence", "contradiction")
    assert (contra.integration, contra.points, contra.record_ids) == ("umbrella", -15, ("rec_reputation_umbrella",))


# -------------------------------------------------------------------- risk --
def test_risk_is_highest_weighted_category_not_a_sum():
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 20, 80),
                        sig(CAT.PERSISTENCE, "defender_endpoint", 25, 80)], context=ctx())
    assert b.risk_score == 20  # 20 x 1.0 beats 25 x 0.8; neither reaches the corroboration minimum


def test_highest_severity_within_a_category_wins():
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 40, 80, "r1"),
                        sig(CAT.ENDPOINT_DETECTION, "defender_endpoint", 70, 60, "r2")], context=ctx())
    assert b.risk_score == 70
    [base] = by(b, "risk", CAT.ENDPOINT_DETECTION)
    assert base.integration == "defender_endpoint" and base.record_ids == ("r1", "r2")


@pytest.mark.parametrize("category,weight", [
    (CAT.ENDPOINT_DETECTION, 1.0), (CAT.SANDBOX_VERDICT, 0.9), (CAT.NETWORK_BEHAVIOUR, 0.9),
    (CAT.AUTHENTICATION_ANOMALY, 0.9), (CAT.EMAIL_VERDICT, 0.8), (CAT.PERSISTENCE, 0.8),
    (CAT.LATERAL_MOVEMENT, 1.0), (CAT.CAMPAIGN_ASSOCIATION, 0.7), (CAT.REPUTATION, 0.6),
])
def test_default_category_weights_apply(category, weight):
    b = engine().score([sig(category, "splunk", 70, 60)], context=ctx())
    expected = min(int(70 * weight + 0.5), 50) if category is CAT.REPUTATION else int(70 * weight + 0.5)
    assert b.risk_score == expected


def test_configured_weights_change_risk():
    b = engine(weights={"endpoint_detection": 0.5}).score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 80)],
                                                           context=ctx())
    assert b.risk_score == 40


def test_zero_weight_category_contributes_nothing_but_is_listed():
    b = engine(weights={"persistence": 0.0}).score(
        [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 60, 80), sig(CAT.PERSISTENCE, "secure_endpoint", 90, 80)],
        context=ctx())
    assert b.risk_score == 60
    [p] = by(b, "risk", CAT.PERSISTENCE)
    assert p.points == 0 and p.note == "below corroboration minimum 30"


def test_rounding_happens_once_half_up():
    # 35 x 0.9 = 31.5 -> 32 (half up), and 45 x 0.9 = 40.5 -> 41
    assert engine().score([sig(CAT.AUTHENTICATION_ANOMALY, "entra", 35, 50)], context=ctx()).risk_score == 32
    assert engine().score([sig(CAT.AUTHENTICATION_ANOMALY, "entra", 45, 50)], context=ctx()).risk_score == 41


@pytest.mark.parametrize("severity,weight,expected", [(45, 0.7, 32), (25, 0.58, 15), (75, 0.82, 62)])
def test_exact_halves_round_up_despite_float_noise(severity, weight, expected):
    # 45 x 0.7 is 31.499999999999996 in binary floating point; mathematically it is 31.5
    b = engine().score([sig(CAT.CAMPAIGN_ASSOCIATION, "cisco_xdr", severity, 50)], context=ctx(),
                       weights={CAT.CAMPAIGN_ASSOCIATION: weight})
    assert b.risk_score == expected


def test_fractional_base_is_rounded_once_at_the_end():
    # network 85 x 0.85 = 72.25 is kept unrounded, + corroboration 5 = 77.25 -> 77
    b = engine(weights={"network_behaviour": 0.85}).score(
        [sig(CAT.NETWORK_BEHAVIOUR, "umbrella", 85, 80), sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 40, 60)],
        context=ctx())
    assert b.risk_score == 77


@pytest.mark.parametrize("others,bonus", [(0, 0), (1, 5), (2, 10), (3, 15), (5, 15)])
def test_corroboration_bonus_and_cap(others, bonus):
    categories = [CAT.SANDBOX_VERDICT, CAT.NETWORK_BEHAVIOUR, CAT.AUTHENTICATION_ANOMALY, CAT.PERSISTENCE,
                  CAT.LATERAL_MOVEMENT]
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 70, 80)]
    signals += [sig(c, "splunk", 40, 60) for c in categories[:others]]
    b = engine().score(signals, context=ctx())
    assert b.risk_score == 70 + bonus
    assert ("corroboration capped at 15" in b.caps_applied) is (others > 3)


def test_corroboration_needs_the_minimum():
    # persistence 37 x 0.8 = 29.6 < 30: no bonus
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 70, 80),
                        sig(CAT.PERSISTENCE, "secure_endpoint", 37, 60)], context=ctx())
    assert b.risk_score == 70 and not by(b, "risk", "corroboration")


def test_risk_is_clamped_to_100():
    signals = [sig(c, "splunk", 100, 90) for c in (CAT.ENDPOINT_DETECTION, CAT.LATERAL_MOVEMENT, CAT.SANDBOX_VERDICT,
                                                   CAT.NETWORK_BEHAVIOUR)]
    b = engine().score(signals, context=ctx(critical=[DC]))
    assert b.risk_score == 100 and b.risk_band is RiskBand.CRITICAL


def test_configured_bands_are_used():
    b = engine(bands={"LOW": 0, "MEDIUM": 40, "HIGH": 70, "CRITICAL": 95}).score(
        [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 90, 80)], context=ctx())
    assert (b.risk_score, b.risk_band) == (90, RiskBand.HIGH)


# ------------------------------------------------- reputation never rules --
@pytest.mark.parametrize("weight", [0.0, 0.3, 0.6, 1.0])
@pytest.mark.parametrize("count", [1, 2, 4])
def test_reputation_only_never_exceeds_caps_whatever_the_weights(weight, count):
    names = ["virustotal", "alienvault_otx", "umbrella", "cisco_xdr"][:count]
    signals = [sig(CAT.REPUTATION, n, 100, 100, observable=DOMAIN) for n in names]
    for e, overrides in ((engine(weights={"reputation": weight}), None),
                         (engine(), {CAT.REPUTATION: weight})):
        b = e.score(signals, context=ctx(), weights=overrides)
        assert b.risk_score <= 50 and b.confidence_score <= 50
        assert b.reputation_only is True


def test_single_source_reaches_critical_only_with_a_behavioural_detection():
    rep = engine().score([sig(CAT.REPUTATION, "virustotal", 100, 100)], context=ctx())
    assert rep.risk_band is RiskBand.MEDIUM
    sandbox = engine().score([sig(CAT.SANDBOX_VERDICT, "secure_malware_analytics", 100, 100)], context=ctx())
    assert sandbox.risk_band is RiskBand.CRITICAL  # 90
    edr = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 95, 90)], context=ctx())
    assert edr.risk_band is RiskBand.CRITICAL


def test_custom_reputation_caps_apply():
    b = engine(caps={"reputation_max_contribution": 30, "reputation_only_confidence_cap": 40}).score(
        [sig(CAT.REPUTATION, "virustotal", 90, 80)], context=ctx())
    assert (b.risk_score, b.confidence_score) == (30, 40)
    assert b.caps_applied == ("reputation capped at 30", "reputation-only confidence capped at 40")


def test_reputation_below_cap_is_not_reported_as_capped():
    b = engine().score([sig(CAT.REPUTATION, "virustotal", 50, 40)], context=ctx())
    assert (b.risk_score, b.confidence_score, b.caps_applied) == (30, 40, ())


def test_reputation_only_independent_bonus_stays_under_the_cap():
    signals = [sig(CAT.REPUTATION, "virustotal", 60, 30, observable=DOMAIN),
               sig(CAT.REPUTATION, "alienvault_otx", 60, 40, observable=DOMAIN),
               sig(CAT.REPUTATION, "umbrella", 60, 45, observable=DOMAIN)]
    b = engine().score(signals, context=ctx())
    assert b.confidence_score == 50  # base 45, +10 limited to the headroom of 5
    [indep] = by(b, "confidence", "independent_sources")
    assert indep.points == 5


# ------------------------------------------------------- clean verdicts --
def test_clean_never_lowers_risk_below_the_strongest_behavioural_signal():
    behavioural = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 85, 80)]
    clean = [sig(CAT.REPUTATION, n, 0, 95, verdict=Verdict.CLEAN)
             for n in ("virustotal", "alienvault_otx", "umbrella")]
    clean.append(sig(CAT.ENDPOINT_DETECTION, "defender_endpoint", 90, 95, verdict=Verdict.CLEAN))
    alone = engine().score(behavioural, context=ctx())
    contradicted = engine().score(behavioural + clean, context=ctx())
    assert contradicted.risk_score == alone.risk_score == 85
    assert contradicted.confidence_score == max(0, 80 - 4 * 15)  # each clean integration costs confidence


def test_clean_on_another_observable_is_not_a_contradiction():
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 85, 80),
               sig(CAT.REPUTATION, "virustotal", 0, 90, verdict=Verdict.CLEAN, observable=DOMAIN)]
    b = engine().score(signals, context=ctx())
    assert b.confidence_score == 80 and not by(b, "confidence", "contradiction")


def test_contradiction_counts_each_integration_once():
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 85, 80),
               sig(CAT.REPUTATION, "virustotal", 0, 90, "c1", verdict=Verdict.CLEAN),
               sig(CAT.SANDBOX_VERDICT, "virustotal", 0, 90, "c2", verdict=Verdict.CLEAN)]
    b = engine().score(signals, context=ctx())
    assert b.confidence_score == 65
    [contra] = by(b, "confidence", "contradiction")
    assert contra.record_ids == ("c1", "c2")


def test_observable_match_ignores_case():
    upper = HOST.model_copy(update={"value": "th-lt-1047"})
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 85, 80),
               sig(CAT.REPUTATION, "virustotal", 0, 90, verdict=Verdict.CLEAN, observable=upper)]
    assert engine().score(signals, context=ctx()).confidence_score == 65


def test_clean_only_input_has_no_risk_and_no_confidence():
    b = engine().score([sig(CAT.REPUTATION, "virustotal", 0, 90, verdict=Verdict.CLEAN)], context=ctx())
    assert (b.risk_score, b.confidence_score, b.contributions) == (0, 0, ())


def test_unknown_signals_are_ignored():
    base = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 70, 70)]
    noise = [sig(CAT.LATERAL_MOVEMENT, "splunk", 100, 100, verdict=Verdict.UNKNOWN),
             sig(CAT.REPUTATION, "virustotal", 100, 100, verdict=Verdict.UNKNOWN)]
    a = engine().score(base, context=ctx())
    b = engine().score(base + noise, context=ctx())
    assert a == b


# ------------------------------------------------------------ confidence --
def test_suspicious_counts_as_supporting():
    b = engine().score([sig(CAT.AUTHENTICATION_ANOMALY, "entra", 60, 70, verdict=Verdict.SUSPICIOUS)], context=ctx())
    assert (b.risk_score, b.confidence_score) == (54, 70)


def test_base_confidence_ignores_reputation_when_behavioural_evidence_exists():
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 60, 40),
                        sig(CAT.REPUTATION, "virustotal", 90, 99)], context=ctx())
    assert b.confidence_score == 45 and b.reputation_only is False  # base 40, +5 for virustotal


@pytest.mark.parametrize("extra,bonus", [(0, 0), (1, 5), (3, 15), (4, 20), (6, 20)])
def test_independent_source_bonus_and_cap(extra, bonus):
    names = ["defender_endpoint", "splunk", "cisco_xdr", "umbrella", "meraki", "secure_cloud_analytics"][:extra]
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 70, 60)]
    signals += [sig(CAT.NETWORK_BEHAVIOUR, n, 50, 30) for n in names]
    b = engine().score(signals, context=ctx())
    assert b.confidence_score == 60 + bonus
    assert ("independent-source bonus capped at 20" in b.caps_applied) is (extra > 4)


def test_same_integration_in_two_categories_is_not_independent():
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 70, 60),
                        sig(CAT.PERSISTENCE, "secure_endpoint", 70, 50)], context=ctx())
    assert b.confidence_score == 60 and not by(b, "confidence", "independent_sources")


# ------------------------------------------------------ risk vs confidence --
def test_high_risk_low_confidence_stays_separate():
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 95, 20)], context=ctx())
    assert (b.risk_score, b.risk_band, b.confidence_score) == (95, RiskBand.CRITICAL, 20)


def test_low_risk_high_confidence_stays_separate():
    b = engine().score([sig(CAT.AUTHENTICATION_ANOMALY, "entra", 10, 95, verdict=Verdict.SUSPICIOUS),
                        sig(CAT.EMAIL_VERDICT, "secure_email", 10, 90, verdict=Verdict.SUSPICIOUS)], context=ctx())
    assert (b.risk_score, b.risk_band, b.confidence_score) == (9, RiskBand.LOW, 100)


def test_failures_move_confidence_only_and_critical_asset_moves_risk_only():
    signals = worked_example_signals()
    plain = engine().score(signals, context=ctx())
    failed = engine().score(signals, context=ctx(failed=[("alienvault_otx", HealthStatus.UNAVAILABLE)]))
    critical = engine().score(signals, context=ctx(critical=[DC]))
    assert failed.risk_score == plain.risk_score and failed.confidence_score == plain.confidence_score - 5
    assert critical.confidence_score == plain.confidence_score and critical.risk_score == min(100, plain.risk_score + 10)


# ------------------------------------------------ failed / missing sources --
@pytest.mark.parametrize("health", FAILING)
def test_failed_expected_source_lowers_confidence_and_is_listed(health):
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 80)]
    b = engine().score(signals, context=ctx(expected=("virustotal",), failed=[("virustotal", health)]))
    assert (b.risk_score, b.confidence_score) == (80, 75)
    assert b.failed_sources == (f"virustotal ({health.value})",)


@pytest.mark.parametrize("health", [HealthStatus.DEGRADED, HealthStatus.UNKNOWN, HealthStatus.CONNECTED])
def test_other_health_is_listed_but_costs_nothing(health):
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 80)],
                       context=ctx(failed=[("virustotal", health)]))
    assert b.confidence_score == 80 and b.failed_sources == (f"virustotal ({health.value})",)


def test_failed_source_that_was_not_expected_costs_nothing():
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 80)],
                       context=ctx(expected=("umbrella",), failed=[("virustotal", HealthStatus.UNAVAILABLE)]))
    assert b.confidence_score == 80 and b.failed_sources == ("virustotal (UNAVAILABLE)",)


def test_failed_source_penalty_is_capped():
    names = ["virustotal", "alienvault_otx", "umbrella", "hibp", "splunk", "cisco_xdr"]
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 80)],
                       context=ctx(failed=[(n, HealthStatus.UNAVAILABLE) for n in names]))
    assert b.confidence_score == 60
    failed = by(b, "confidence", "failed_sources")
    assert len(failed) == 6 and sum(c.points for c in failed) == -20
    assert "failed-source penalty capped at 20" in b.caps_applied
    assert len(b.failed_sources) == 6


def test_failed_source_never_empties_a_recommendation_backed_by_other_evidence():
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 85, 60)]
    every = [(n, HealthStatus.UNAVAILABLE) for n in ("virustotal", "alienvault_otx", "umbrella", "splunk",
                                                     "cisco_xdr", "hibp", "meraki")]
    b = engine().score(signals, context=ctx(failed=every))
    assert b.risk_score == 85 and b.confidence_score == 40 and b.contributions


def test_not_queried_source_costs_no_confidence():
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 80)]
    a = engine().score(signals, context=ctx(expected=("virustotal",)))
    b = engine().score(signals, context=ctx(expected=("virustotal",),
                                            not_queried=[("virustotal", "disclosure policy")]))
    assert (a.risk_score, a.confidence_score) == (b.risk_score, b.confidence_score)
    assert b.not_queried == ("virustotal (disclosure policy)",)


def test_no_signal_at_all_is_insufficient_evidence_with_failures_listed():
    b = engine().score([], context=ctx(failed=[("virustotal", HealthStatus.RATE_LIMITED),
                                               ("alienvault_otx", HealthStatus.UNAVAILABLE)],
                                       not_queried=[("hibp", "disclosure policy")], critical=[DC]))
    assert (b.risk_score, b.confidence_score, b.risk_band, b.contributions) == (0, 0, RiskBand.LOW, ())
    assert b.failed_sources == ("alienvault_otx (UNAVAILABLE)", "virustotal (RATE_LIMITED)")
    assert b.explain() == (
        "risk 0 LOW (insufficient evidence), confidence 0 (insufficient evidence; "
        "failed alienvault_otx (UNAVAILABLE); failed virustotal (RATE_LIMITED)), "
        f"settings {b.settings_hash[:12]}")


def test_degraded_signal_still_counts():
    b = engine().score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 70, health=HealthStatus.DEGRADED)],
                       context=ctx())
    assert (b.risk_score, b.confidence_score) == (80, 70)


# --------------------------------------------------------- critical asset --
def test_critical_asset_adds_the_bonus_once():
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 70, 70)]
    b = engine().score(signals, context=ctx(critical=[DC, CriticalAssetClass.IDENTITY_INFRASTRUCTURE]))
    assert (b.risk_score, b.risk_band) == (80, RiskBand.CRITICAL)
    [c] = by(b, "risk", "critical_asset")
    assert c.points == 10 and c.note == "domain_controller, identity_infrastructure"
    assert "critical asset +10" in b.explain()


def test_critical_asset_bonus_is_configurable():
    b = engine(context={"critical_asset_bonus": 25}).score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 50, 70)],
                                                           context=ctx(critical=[DC]))
    assert b.risk_score == 75
    zero = engine(context={"critical_asset_bonus": 0}).score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 50, 70)],
                                                             context=ctx(critical=[DC]))
    assert zero.risk_score == 50 and not by(zero, "risk", "critical_asset")


def test_critical_asset_without_evidence_invents_no_risk():
    b = engine().score([], context=ctx(critical=[DC]))
    assert (b.risk_score, b.confidence_score) == (0, 0)


def test_critical_asset_with_reputation_only_raises_impact_not_confidence():
    b = engine().score([sig(CAT.REPUTATION, "virustotal", 90, 80)], context=ctx(critical=[DC]))
    assert (b.risk_score, b.confidence_score, b.reputation_only) == (60, 50, True)


# ----------------------------------------------------------- determinism --
def test_input_order_never_changes_the_output():
    signals = worked_example_signals() + [
        sig(CAT.PERSISTENCE, "defender_endpoint", 60, 55, "p1"),
        sig(CAT.REPUTATION, "alienvault_otx", 70, 60, "o1"),
        sig(CAT.REPUTATION, "umbrella", 0, 70, "u1", verdict=Verdict.CLEAN),
        sig(CAT.ENDPOINT_DETECTION, "defender_endpoint", 80, 80, "d1"),
    ]
    failed = [("hibp", HealthStatus.UNAVAILABLE), ("alienvault_otx", HealthStatus.RATE_LIMITED)]
    reference = engine().score(signals, context=ctx(failed=failed))
    rng = random.Random(1047)
    for _ in range(25):
        shuffled = signals[:]
        rng.shuffle(shuffled)
        b = engine().score(shuffled, context=ctx(failed=list(reversed(failed))))
        assert b == reference and b.explain() == reference.explain()


def test_same_input_gives_identical_breakdown_and_hash_across_engines():
    a = ScoringEngine(ScoringSettings()).score(worked_example_signals(), context=worked_example_context())
    b = ScoringEngine(ScoringSettings()).score(worked_example_signals(), context=worked_example_context())
    assert a == b and a.model_dump_json() == b.model_dump_json()


def test_explain_is_stable():
    b = engine().score(worked_example_signals(), context=worked_example_context())
    assert b.explain() == b.explain() == ScoreBreakdown.model_validate(b.model_dump()).explain()
    assert b.settings_hash[:12] in b.explain()


# ------------------------------------------------------------ settings hash --
def test_settings_hash_is_sha256_of_canonical_settings():
    settings = ScoringSettings()
    e = ScoringEngine(settings)
    expected = sha256_hex(canonical_json(settings.model_dump(mode="python"), allow_floats=True))
    assert e.settings_hash == expected
    assert e.score([], context=ctx()).settings_hash == expected
    assert len(expected) == 64


def test_settings_hash_changes_with_settings_and_overrides():
    base = engine().settings_hash
    assert engine(weights={"reputation": 0.5}).settings_hash != base
    assert engine(caps={"reputation_max_contribution": 40}).settings_hash != base
    overridden = engine().score(worked_example_signals(), context=ctx(), weights={CAT.REPUTATION: 0.5})
    assert overridden.settings_hash != base
    assert overridden.settings_hash == engine(weights={"reputation": 0.5}).score([], context=ctx()).settings_hash


# ---------------------------------------------------------- weight overrides --
def test_workflow_weight_override_changes_only_that_category():
    signals = [sig(CAT.EMAIL_VERDICT, "secure_email", 80, 80)]
    assert engine().score(signals, context=ctx()).risk_score == 64
    assert engine().score(signals, context=ctx(), weights={CAT.EMAIL_VERDICT: 1.0}).risk_score == 80
    assert engine().score(signals, context=ctx(), weights={CAT.REPUTATION: 1.0}).risk_score == 64


def test_weight_override_cannot_change_caps():
    rep = [sig(CAT.REPUTATION, "virustotal", 100, 100)]
    b = engine().score(rep, context=ctx(), weights={CAT.REPUTATION: 1.0})
    assert (b.risk_score, b.confidence_score) == (50, 50)
    assert "reputation capped at 50" in b.caps_applied


@pytest.mark.parametrize("overrides", [
    {"caps": 1.0}, {"reputation_max_contribution": 1.0}, {"corroboration": 0.5}, {"made_up": 0.5},
    {CAT.REPUTATION: 1.5}, {CAT.REPUTATION: -0.1}, {CAT.REPUTATION: float("nan")}, {CAT.REPUTATION: True},
    {CAT.REPUTATION: "1.0"},
])
def test_bad_weight_overrides_are_refused(overrides):
    with pytest.raises(ValueError):
        engine().score(worked_example_signals(), context=ctx(), weights=overrides)


def test_engine_settings_are_not_mutated_by_overrides():
    settings = ScoringSettings()
    e = ScoringEngine(settings)
    e.score(worked_example_signals(), context=ctx(), weights={CAT.ENDPOINT_DETECTION: 0.1})
    assert settings == ScoringSettings() and e.settings_hash == ScoringEngine(ScoringSettings()).settings_hash


# --------------------------------------------------------- record citations --
def test_record_ids_in_every_contribution_exist_in_the_input_signals():
    signals = worked_example_signals() + [
        sig(CAT.PERSISTENCE, "defender_endpoint", 60, 55, "p1", "p2"),
        sig(CAT.REPUTATION, "umbrella", 0, 70, "u1", verdict=Verdict.CLEAN),
        sig(CAT.LATERAL_MOVEMENT, "splunk", 20, 30, "l1", verdict=Verdict.UNKNOWN),
    ]
    b = engine().score(signals, context=ctx(critical=[DC], failed=[("hibp", HealthStatus.UNAVAILABLE)]))
    known = {rid for s in signals if s.verdict is not Verdict.UNKNOWN for rid in s.record_ids}
    for c in b.contributions:
        assert set(c.record_ids) <= known
        if c.category not in ("critical_asset", "failed_sources"):
            assert c.record_ids, c
    assert "l1" not in {rid for c in b.contributions for rid in c.record_ids}


def test_signal_without_a_record_id_is_refused():
    with pytest.raises(ValidationError):
        ScoringSignal(category=CAT.REPUTATION, integration="virustotal", observable=HOST,
                      verdict=Verdict.MALICIOUS, severity=90, confidence=80, record_ids=())
    with pytest.raises(ValidationError):
        ScoringSignal(category=CAT.REPUTATION, integration="virustotal", observable=HOST,
                      verdict=Verdict.MALICIOUS, severity=90, confidence=80, record_ids=("  ",))


# ------------------------------------------------- what scores never take --
def test_ai_text_and_analyst_comments_cannot_be_inputs():
    params = set(inspect.signature(ScoringEngine.score).parameters)
    assert params == {"self", "signals", "context", "weights"}
    for field in ("ai_narrative", "analyst_comment", "comment", "narrative"):
        with pytest.raises(ValidationError):
            ScoringSignal(category=CAT.REPUTATION, integration="virustotal", observable=HOST,
                          verdict=Verdict.MALICIOUS, severity=90, confidence=80, record_ids=("r",),
                          **{field: "trust me, it is malicious"})
        with pytest.raises(ValidationError):
            ScoringContext(**{field: "approve it"})


@pytest.mark.parametrize("integration", ["ai", "analyst", "claude", "", "VirusTotal"])
def test_signal_integration_must_be_a_known_adapter(integration):
    with pytest.raises(ValidationError):
        sig(CAT.REPUTATION, integration, 90, 80)


@pytest.mark.parametrize("origin,ok", [("framework", True), ("workflow:ransomware-containment", True),
                                       ("workflow:", False), ("ai", False), ("analyst", False)])
def test_signal_origin(origin, ok):
    def make() -> ScoringSignal:
        return ScoringSignal(category=CAT.PERSISTENCE, integration="secure_endpoint", observable=HOST,
                             verdict=Verdict.SUSPICIOUS, severity=50, confidence=50, record_ids=("r",),
                             origin=origin)
    if ok:
        assert make().origin == origin
    else:
        with pytest.raises(ValidationError):
            make()


def test_signal_note_has_no_effect_on_scores():
    plain = sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 80)
    noted = plain.model_copy(update={"note": "the AI summary says this is the worst incident ever"})
    a = engine().score([plain], context=ctx())
    b = engine().score([noted], context=ctx())
    assert (a.risk_score, a.confidence_score, a.contributions) == (b.risk_score, b.confidence_score, b.contributions)


def test_breakdown_is_frozen():
    b = engine().score(worked_example_signals(), context=ctx())
    with pytest.raises(ValidationError):
        b.risk_score = 0  # type: ignore[misc]


def test_context_lists_are_sorted_and_deduplicated():
    c = ScoringContext(critical_asset_classes=(CriticalAssetClass.HYPERVISOR, DC, DC),
                       failed_sources=(("virustotal", HealthStatus.UNAVAILABLE), ("alienvault_otx", HealthStatus.AUTH_FAILED),
                                       ("virustotal", HealthStatus.UNAVAILABLE)),
                       not_queried=(("virustotal", "disclosure policy"), ("hibp", "disclosure policy")))
    assert c.critical_asset_classes == (DC, CriticalAssetClass.HYPERVISOR)
    assert c.failed_sources == (("alienvault_otx", HealthStatus.AUTH_FAILED), ("virustotal", HealthStatus.UNAVAILABLE))
    assert c.not_queried == (("hibp", "disclosure policy"), ("virustotal", "disclosure policy"))


# --------------------------------------------------------------- package --
def test_package_scores():
    e = engine()
    assert e.package_scores([]) == (0, 0)
    one = e.score(worked_example_signals(), context=ctx())
    low = e.score([sig(CAT.AUTHENTICATION_ANOMALY, "entra", 40, 41, verdict=Verdict.SUSPICIOUS)], context=ctx())
    assert e.package_scores([one]) == (one.risk_score, one.confidence_score)
    # confidences 95 and 41 -> mean 68.0; risks 90 and 36 -> max 90
    assert e.package_scores([one, low]) == (90, 68)


@pytest.mark.parametrize("confidences,mean", [((50, 51), 51), ((50, 50, 51), 50), ((1, 2), 2), ((0, 0, 1, 1), 1),
                                              ((99, 100), 100)])
def test_package_confidence_is_round_half_up_mean(confidences, mean):
    e = engine()
    breakdowns = [ScoreBreakdown(risk_score=10, confidence_score=c, risk_band=RiskBand.LOW, contributions=(),
                                 settings_hash=e.settings_hash) for c in confidences]
    assert e.package_scores(breakdowns) == (10, mean)


def test_dry_run_and_live_score_identically():
    # The engine has no dry-run input: the same call is made in both modes.
    assert "dry_run" not in inspect.signature(ScoringEngine.score).parameters
    assert "dry_run" not in inspect.signature(ScoringEngine.__init__).parameters
