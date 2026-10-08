"""aggregate_verdict (architecture 14.2.2): no single vendor's verdict is absolute truth."""
from __future__ import annotations

import pytest

from tests.unit.scoring._support import CAT, DOMAIN, ctx, engine, sig
from xdr_response.models.enums import HealthStatus, Verdict
from xdr_response.scoring import aggregate_verdict

M, S, C, U = Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.CLEAN, Verdict.UNKNOWN


def verdict_of(signals, *, failed=()):
    breakdown = engine().score(signals, context=ctx(failed=failed))
    return aggregate_verdict(signals, breakdown)


def test_behavioural_malicious_at_high_risk_is_malicious():
    assert verdict_of([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 80)]) is M


def test_behavioural_malicious_below_high_is_suspicious():
    assert verdict_of([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 59, 80)]) is S
    assert verdict_of([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 60, 80)]) is M


def test_one_reputation_vendor_alone_is_suspicious():
    assert verdict_of([sig(CAT.REPUTATION, "virustotal", 100, 100, observable=DOMAIN)]) is S


def test_two_reputation_vendors_agreeing_are_malicious():
    signals = [sig(CAT.REPUTATION, "virustotal", 90, 80, observable=DOMAIN),
               sig(CAT.REPUTATION, "alienvault_otx", 80, 70, observable=DOMAIN)]
    assert verdict_of(signals) is M


def test_two_reputation_signals_from_one_vendor_are_not_two_sources():
    signals = [sig(CAT.REPUTATION, "virustotal", 90, 80, "a", observable=DOMAIN),
               sig(CAT.REPUTATION, "virustotal", 85, 80, "b", observable=DOMAIN)]
    assert verdict_of(signals) is S


def test_reputation_agreement_with_a_clean_vote_is_suspicious():
    signals = [sig(CAT.REPUTATION, "virustotal", 90, 80, observable=DOMAIN),
               sig(CAT.REPUTATION, "alienvault_otx", 80, 70, observable=DOMAIN),
               sig(CAT.REPUTATION, "umbrella", 0, 90, verdict=C, observable=DOMAIN)]
    assert verdict_of(signals) is S


def test_clean_does_not_cancel_a_high_behavioural_detection():
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 90, 80),
               sig(CAT.REPUTATION, "virustotal", 0, 90, verdict=C)]
    assert verdict_of(signals) is M


def test_suspicious_only():
    assert verdict_of([sig(CAT.AUTHENTICATION_ANOMALY, "entra", 90, 80, verdict=S)]) is S


def test_clean_when_a_source_answered_clean_and_none_failed():
    assert verdict_of([sig(CAT.REPUTATION, "virustotal", 0, 90, verdict=C)]) is C


def test_clean_with_a_failed_source_is_unknown():
    signals = [sig(CAT.REPUTATION, "virustotal", 0, 90, verdict=C)]
    assert verdict_of(signals, failed=[("alienvault_otx", HealthStatus.UNAVAILABLE)]) is U


def test_nothing_known_is_unknown():
    assert verdict_of([]) is U
    assert verdict_of([sig(CAT.REPUTATION, "virustotal", 90, 90, verdict=U)]) is U


def test_unknown_signals_are_ignored():
    signals = [sig(CAT.REPUTATION, "virustotal", 0, 90, verdict=C),
               sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 90, 90, verdict=U)]
    assert verdict_of(signals) is C


@pytest.mark.parametrize("severity,expected", [(69, S), (70, M)])
def test_configured_high_band_is_used(severity, expected):
    bands = {"LOW": 0, "MEDIUM": 40, "HIGH": 70, "CRITICAL": 90}
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", severity, 80)]
    breakdown = engine(bands=bands).score(signals, context=ctx())
    assert aggregate_verdict(signals, breakdown, bands=bands) is expected


def test_default_bands_match_the_built_in_high_bound():
    signals = [sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 60, 80)]
    breakdown = engine().score(signals, context=ctx())
    assert aggregate_verdict(signals, breakdown) is aggregate_verdict(
        signals, breakdown, bands={"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 80}) is M


def test_input_order_does_not_matter():
    signals = [sig(CAT.REPUTATION, "virustotal", 90, 80, observable=DOMAIN),
               sig(CAT.REPUTATION, "umbrella", 0, 90, verdict=C, observable=DOMAIN),
               sig(CAT.NETWORK_BEHAVIOUR, "meraki", 70, 60, observable=DOMAIN)]
    breakdown = engine().score(signals, context=ctx())
    assert aggregate_verdict(signals, breakdown) is aggregate_verdict(list(reversed(signals)), breakdown)
