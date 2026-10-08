"""Signals from records (architecture 14.2.3).

The record models (``xdr_response.atomics.records``) belong to the investigation key and are built
in parallel; these tests use local fakes that carry exactly the documented fields. When the real
module is importable, ``test_real_records_*`` also run against it.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from tests.unit.scoring._support import DOMAIN, HOST, ctx, engine
from xdr_response.models.catalog import INTEGRATION_NAMES
from xdr_response.models.enums import ObservableType, Severity, Verdict
from xdr_response.models.observable import Observable
from xdr_response.models.scoring import SignalCategory as CAT
from xdr_response.scoring import (
    ENRICHMENT_CATEGORY,
    LEVEL_POINTS,
    RECORD_CONFIDENCE,
    SEVERITY_POINTS,
    signals_from_enrichment,
    signals_from_records,
)

USER = Observable(type=ObservableType.USER, value="jsmith@example.com")
_COUNTER = iter(range(1, 10_000))


def rec(kind: str, *, integration: str = "secure_endpoint", subject: Observable = HOST, **fields: Any) -> Any:
    """A fake record exposing the documented fields of its kind."""
    return SimpleNamespace(kind=kind, record_id=f"rec_{kind}_{next(_COUNTER):04d}", integration=integration,
                           atomic="test", subject=subject, **fields)


def enrichment(integration: str, verdict: Verdict, risk: int = 90, confidence: int = 80,
               subject: Observable = DOMAIN) -> Any:
    return rec("enrichment", integration=integration, subject=subject, verdict=verdict, risk_score=risk,
               confidence=confidence)


def one(records: list[Any], observable: Observable = HOST):
    signals = signals_from_records(records, observable=observable)
    assert len(signals) == 1, signals
    return signals[0]


# ------------------------------------------------------------- tables --
def test_enrichment_category_table():
    assert set(ENRICHMENT_CATEGORY) == set(INTEGRATION_NAMES)
    assert ENRICHMENT_CATEGORY["secure_malware_analytics"] is CAT.SANDBOX_VERDICT
    for name in ("secure_endpoint", "defender_endpoint", "intune"):
        assert ENRICHMENT_CATEGORY[name] is CAT.ENDPOINT_DETECTION
    assert ENRICHMENT_CATEGORY["entra"] is CAT.AUTHENTICATION_ANOMALY
    for name in ("secure_email", "defender_o365"):
        assert ENRICHMENT_CATEGORY[name] is CAT.EMAIL_VERDICT
    for name in ("cisco_xdr", "umbrella", "meraki", "virustotal", "alienvault_otx", "hibp", "splunk",
                 "secure_cloud_analytics", "microsoft_cloud"):
        assert ENRICHMENT_CATEGORY[name] is CAT.REPUTATION


def test_points_tables():
    assert dict(SEVERITY_POINTS) == {Severity.CRITICAL: 95, Severity.HIGH: 80, Severity.MEDIUM: 60,
                                     Severity.LOW: 30, Severity.INFO: 10}
    assert dict(LEVEL_POINTS) == {"high": 80, "medium": 60, "low": 40, "none": 0, "unknown": 0}
    assert dict(RECORD_CONFIDENCE) == {
        "detection": 80, "process_event": 70, "network_connection": 60, "dns_query": 60, "hash_prevalence": 70,
        "persistence_item": 60, "anomaly": 70, "mailbox_rule": 70, "role_change": 75, "email_message": 80,
        "cloud_app": 60, "user_profile": 70}
    with pytest.raises(TypeError):
        RECORD_CONFIDENCE["detection"] = 100  # type: ignore[index]


# --------------------------------------------------------- enrichment --
def test_signals_from_enrichment():
    records = [enrichment("virustotal", Verdict.MALICIOUS, 90, 80),
               enrichment("secure_malware_analytics", Verdict.SUSPICIOUS, 70, 60),
               enrichment("umbrella", Verdict.CLEAN, 0, 90),
               enrichment("alienvault_otx", Verdict.UNKNOWN, 0, 0)]
    signals = signals_from_enrichment(records)
    assert [(s.category, s.integration, s.verdict, s.severity, s.confidence) for s in signals] == [
        (CAT.REPUTATION, "virustotal", Verdict.MALICIOUS, 90, 80),
        (CAT.SANDBOX_VERDICT, "secure_malware_analytics", Verdict.SUSPICIOUS, 70, 60),
        (CAT.REPUTATION, "umbrella", Verdict.CLEAN, 0, 90),
    ]
    assert [s.record_ids for s in signals] == [(r.record_id,) for r in records[:3]]
    assert all(s.observable == DOMAIN and s.origin == "framework" for s in signals)


def test_signals_from_enrichment_refuses_other_kinds():
    with pytest.raises(ValueError):
        signals_from_enrichment([rec("detection", name="x", verdict=Verdict.MALICIOUS, severity=Severity.HIGH,
                                     category=None)])


def test_enrichment_record_through_signals_from_records_uses_the_target():
    s = one([enrichment("secure_endpoint", Verdict.MALICIOUS, 95, 90, subject=HOST)])
    assert (s.category, s.severity, s.confidence, s.observable) == (CAT.ENDPOINT_DETECTION, 95, 90, HOST)


# --------------------------------------------------------- detections --
@pytest.mark.parametrize("category,expected", [
    (None, CAT.ENDPOINT_DETECTION), ("Ransomware", CAT.ENDPOINT_DETECTION),
    ("Persistence", CAT.PERSISTENCE), ("persistence_mechanism", CAT.PERSISTENCE),
    ("Lateral Movement", CAT.LATERAL_MOVEMENT), ("lateral_movement", CAT.LATERAL_MOVEMENT),
    ("LateralMovement", CAT.LATERAL_MOVEMENT), ("CredentialAccess", CAT.ENDPOINT_DETECTION),
])
def test_detection_category(category, expected):
    s = one([rec("detection", name="Generic", verdict=Verdict.MALICIOUS, severity=Severity.HIGH, category=category)])
    assert (s.category, s.severity, s.confidence, s.verdict) == (expected, 80, 80, Verdict.MALICIOUS)


@pytest.mark.parametrize("severity,points", [(Severity.CRITICAL, 95), (Severity.HIGH, 80), (Severity.MEDIUM, 60),
                                             (Severity.LOW, 30), (Severity.INFO, 10)])
def test_detection_severity_points(severity, points):
    s = one([rec("detection", name="x", verdict=Verdict.SUSPICIOUS, severity=severity, category=None)])
    assert s.severity == points and s.verdict is Verdict.SUSPICIOUS


# -------------------------------------------------- verdict-gated kinds --
@pytest.mark.parametrize("verdict,severity", [(Verdict.MALICIOUS, 70), (Verdict.SUSPICIOUS, 50)])
def test_process_event(verdict, severity):
    s = one([rec("process_event", verdict=verdict)])
    assert (s.category, s.severity, s.confidence, s.verdict) == (CAT.ENDPOINT_DETECTION, severity, 70, verdict)


@pytest.mark.parametrize("verdict", [Verdict.CLEAN, Verdict.UNKNOWN])
def test_process_event_without_bad_verdict_is_context_only(verdict):
    assert signals_from_records([rec("process_event", verdict=verdict)], observable=HOST) == ()


@pytest.mark.parametrize("kind", ["network_connection", "dns_query"])
@pytest.mark.parametrize("verdict,severity", [(Verdict.MALICIOUS, 70), (Verdict.SUSPICIOUS, 50), (Verdict.CLEAN, 0)])
def test_network_kinds(kind, verdict, severity):
    s = one([rec(kind, integration="umbrella", verdict=verdict)])
    assert (s.category, s.severity, s.confidence, s.verdict) == (CAT.NETWORK_BEHAVIOUR, severity, 60, verdict)


@pytest.mark.parametrize("kind", ["network_connection", "dns_query"])
def test_network_unknown_is_context_only(kind):
    assert signals_from_records([rec(kind, verdict=Verdict.UNKNOWN)], observable=HOST) == ()


def test_hash_prevalence_only_when_malicious():
    s = one([rec("hash_prevalence", verdict=Verdict.MALICIOUS)])
    assert (s.category, s.severity, s.confidence, s.verdict) == (CAT.ENDPOINT_DETECTION, 70, 70, Verdict.MALICIOUS)
    for verdict in (Verdict.SUSPICIOUS, Verdict.CLEAN, Verdict.UNKNOWN):
        assert signals_from_records([rec("hash_prevalence", verdict=verdict)], observable=HOST) == ()


@pytest.mark.parametrize("verdict,severity", [(Verdict.MALICIOUS, 70), (Verdict.SUSPICIOUS, 50)])
def test_persistence_item(verdict, severity):
    s = one([rec("persistence_item", verdict=verdict)])
    assert (s.category, s.severity, s.confidence) == (CAT.PERSISTENCE, severity, 60)
    assert signals_from_records([rec("persistence_item", verdict=Verdict.CLEAN)], observable=HOST) == ()


@pytest.mark.parametrize("severity,points,verdict", [
    (Severity.CRITICAL, 95, Verdict.MALICIOUS), (Severity.HIGH, 80, Verdict.MALICIOUS),
    (Severity.MEDIUM, 60, Verdict.SUSPICIOUS), (Severity.LOW, 30, Verdict.SUSPICIOUS),
    (Severity.INFO, 10, Verdict.SUSPICIOUS),
])
def test_anomaly(severity, points, verdict):
    s = one([rec("anomaly", integration="entra", subject=USER, severity=severity)], USER)
    assert (s.category, s.severity, s.confidence, s.verdict) == (CAT.AUTHENTICATION_ANOMALY, points, 70, verdict)


@pytest.mark.parametrize("risk_state,risk_level,expected", [
    ("confirmed_compromised", "low", (85, Verdict.MALICIOUS)),
    ("confirmed_compromised", "high", (85, Verdict.MALICIOUS)),
    ("at_risk", "high", (80, Verdict.SUSPICIOUS)),
    ("unknown", "high", (80, Verdict.SUSPICIOUS)),
    ("at_risk", "medium", None),
    ("none", "none", None),
    ("remediated", "low", None),
])
def test_user_profile(risk_state, risk_level, expected):
    record = rec("user_profile", integration="entra", subject=USER, risk_state=risk_state, risk_level=risk_level)
    signals = signals_from_records([record], observable=USER)
    if expected is None:
        assert signals == ()
    else:
        [s] = signals
        assert (s.severity, s.verdict, s.category) == (*expected, CAT.AUTHENTICATION_ANOMALY)
        assert 0 < s.confidence <= 100


@pytest.mark.parametrize("external,delete,expected", [(True, False, True), (False, True, True),
                                                      (True, True, True), (False, False, False)])
def test_mailbox_rule(external, delete, expected):
    record = rec("mailbox_rule", integration="microsoft_cloud", subject=USER, external_forwarding=external,
                 delete=delete)
    signals = signals_from_records([record], observable=USER)
    if expected:
        [s] = signals
        assert (s.category, s.severity, s.confidence, s.verdict) == (CAT.PERSISTENCE, 70, 70, Verdict.SUSPICIOUS)
    else:
        assert signals == ()


@pytest.mark.parametrize("privileged,change,expected", [
    (True, "assigned", True), (True, "activated", True), (True, "removed", False),
    (True, "eligible_assigned", False), (False, "assigned", False), (True, "unknown", False),
])
def test_role_change(privileged, change, expected):
    record = rec("role_change", integration="entra", subject=USER, privileged=privileged, change=change)
    signals = signals_from_records([record], observable=USER)
    if expected:
        [s] = signals
        assert (s.category, s.severity, s.confidence, s.verdict) == (CAT.PERSISTENCE, 75, 75, Verdict.SUSPICIOUS)
    else:
        assert signals == ()


@pytest.mark.parametrize("verdict,severity", [(Verdict.MALICIOUS, 80), (Verdict.SUSPICIOUS, 50), (Verdict.CLEAN, 0)])
def test_email_message(verdict, severity):
    s = one([rec("email_message", integration="secure_email", verdict=verdict)])
    assert (s.category, s.severity, s.confidence, s.verdict) == (CAT.EMAIL_VERDICT, severity, 80, verdict)
    assert signals_from_records([rec("email_message", verdict=Verdict.UNKNOWN)], observable=HOST) == ()


@pytest.mark.parametrize("verdict", [Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.CLEAN])
def test_cloud_app(verdict):
    s = one([rec("cloud_app", integration="entra", verdict=verdict)])
    assert (s.category, s.severity, s.confidence, s.verdict) == (CAT.PERSISTENCE, 60, 60, verdict)
    assert signals_from_records([rec("cloud_app", verdict=Verdict.UNKNOWN)], observable=HOST) == ()


@pytest.mark.parametrize("kind", ["sign_in", "mfa_event", "endpoint", "generic"])
def test_context_only_kinds_produce_no_signal(kind):
    assert signals_from_records([rec(kind, verdict=Verdict.MALICIOUS, severity=Severity.CRITICAL)],
                                observable=HOST) == ()


# ------------------------------------------------------------ general --
def test_every_signal_cites_exactly_its_record_and_the_target():
    records = [rec("detection", name="x", verdict=Verdict.MALICIOUS, severity=Severity.HIGH, category=None),
               rec("process_event", verdict=Verdict.SUSPICIOUS),
               rec("network_connection", integration="umbrella", verdict=Verdict.MALICIOUS),
               rec("sign_in", integration="entra"),
               rec("persistence_item", verdict=Verdict.MALICIOUS)]
    signals = signals_from_records(records, observable=HOST)
    assert [s.record_ids for s in signals] == [(r.record_id,) for r in records if r.kind != "sign_in"]
    assert all(s.observable == HOST for s in signals)
    assert [s.integration for s in signals] == ["secure_endpoint", "secure_endpoint", "umbrella", "secure_endpoint"]


def test_records_from_an_unknown_integration_are_refused():
    with pytest.raises(ValueError):
        signals_from_records([rec("process_event", integration="ai", verdict=Verdict.MALICIOUS)], observable=HOST)


def test_signals_feed_the_engine():
    records = [rec("detection", name="Ransomware.Generic", verdict=Verdict.MALICIOUS, severity=Severity.CRITICAL,
                   category="Ransomware"),
               rec("network_connection", integration="umbrella", verdict=Verdict.MALICIOUS),
               rec("hash_prevalence", verdict=Verdict.MALICIOUS)]
    signals = signals_from_records(records, observable=HOST)
    b = engine().score(signals, context=ctx())
    # endpoint 95; network 70 x 0.9 = 63 corroborates (+5); confidence base 80, +5 (umbrella)
    assert (b.risk_score, b.confidence_score) == (100, 85)
    cited = {rid for c in b.contributions for rid in c.record_ids}
    assert cited == {r.record_id for r in records}


# ------------------------------------------------- real record models --
def _records_module():
    return pytest.importorskip("xdr_response.atomics.records")


def test_real_records_enrichment_and_detection():
    records = _records_module()
    kind = records.RecordKind
    subject = Observable(type=ObservableType.DOMAIN, value="c2.ransom-ops.example")
    vt = records.EnrichmentRecord(
        record_id=records.make_record_id("virustotal", kind.ENRICHMENT, subject, {}),
        integration="virustotal", atomic="enrich_domain", subject=subject, verdict=Verdict.MALICIOUS,
        risk_score=90, confidence=80)
    [s] = signals_from_enrichment([vt])
    assert (s.category, s.integration, s.record_ids) == (CAT.REPUTATION, "virustotal", (vt.record_id,))
    assert RECORD_CONFIDENCE[kind.DETECTION] == 80
    host = Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047")
    detection = records.DetectionRecord(
        record_id=records.make_record_id("secure_endpoint", kind.DETECTION, host, {"id": "det-0001"}),
        integration="secure_endpoint", atomic="investigate_endpoint", subject=host, detection_id="det-0001",
        name="Ransomware.Generic", verdict=Verdict.MALICIOUS, severity=Severity.CRITICAL, category="Ransomware")
    [d] = signals_from_records([detection], observable=host)
    assert (d.category, d.severity, d.confidence, d.record_ids) == (
        CAT.ENDPOINT_DETECTION, 95, 80, (detection.record_id,))
