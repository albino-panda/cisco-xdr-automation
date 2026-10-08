"""Enrichment atomics over simulated adapters (architecture 14.1.3).

Scoring goes through the local :class:`FakeScorer` (conftest); these tests check what the atomics
themselves own: subjects, source handling, privacy, records, the scoring context and the report.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta

import pytest
from pydantic import ValidationError

from tests.unit.atomics.enrichment._support import FAKE_MD5, FAKE_SHA256, FIXED_NOW, Lab, lab, statuses
from xdr_response.atomics.enrichment import ObservableReport
from xdr_response.atomics.enrichment._sources import DISCLOSURE_REASON
from xdr_response.atomics.enrichment.atomics import (
    ENRICHMENT_ATOMICS,
    ENRICHMENT_SUBJECT_TYPES,
    enrich,
    enrich_domain,
    enrich_email_address,
    enrich_endpoint,
    enrich_hash,
    enrich_ip,
    enrich_url,
    enrich_user,
)
from xdr_response.atomics.records import EnrichmentRecord, RecordKind, SourceOutcome, make_record_id
from xdr_response.config.schema import (
    AssetMatch,
    CriticalAssetClassConfig,
    CriticalAssetsConfig,
    ExclusionsConfig,
)
from xdr_response.integrations.simulated import (
    Fault,
    FaultKind,
    SimulatedEnvironment,
    register_simulated_adapters,
    simulated_adapter_class,
)
from xdr_response.models import (
    ActionType,
    CriticalAssetClass,
    EnrichmentResult,
    ErrorCode,
    ErrorInfo,
    EvidenceDraft,
    HealthStatus,
    Observable,
    ObservableType,
    OperationKind,
    Verdict,
)

_O = ObservableType
DOMAIN = "bad.example.test"
PUBLIC_IP = "203.0.113.10"
PRIVATE_IP = "10.20.30.40"

#: A small suite: one internal network source plus two public intel lookups.
INTEL_SUITE = {"umbrella": ("network",), "virustotal": ("intel",), "alienvault_otx": ("intel",)}
#: The same suite with HIBP (posing with the whole intel family, so it claims every intel type).
HIBP_SUITE = {**INTEL_SUITE, "hibp": ("intel",)}


def _lab(suite: dict[str, tuple[str, ...]] | None = None, **settings: object) -> tuple[Lab, SimulatedEnvironment]:
    the_lab = lab(**settings)
    env = SimulatedEnvironment(clock=the_lab.clock)
    register_simulated_adapters(the_lab.registry, env, suite=suite or INTEL_SUITE)
    return the_lab, env


def _called(env: SimulatedEnvironment) -> list[tuple[str, str, str | None]]:
    return [(c.integration, c.operation, c.target) for c in env.calls]


# ------------------------------------------------------------------ tables --
def test_tables_name_the_seven_atomics_after_their_catalog_types():
    assert set(ENRICHMENT_ATOMICS) == {"enrich_ip", "enrich_domain", "enrich_url", "enrich_hash",
                                       "enrich_email_address", "enrich_user", "enrich_endpoint"}
    assert set(ENRICHMENT_SUBJECT_TYPES) == set(ENRICHMENT_ATOMICS)
    for name in ENRICHMENT_ATOMICS:
        assert ActionType(name).value == name
    assert ENRICHMENT_SUBJECT_TYPES["enrich_hash"] == frozenset({_O.SHA256, _O.SHA1, _O.MD5})
    assert ENRICHMENT_SUBJECT_TYPES["enrich_endpoint"] == frozenset({_O.HOSTNAME, _O.ENDPOINT_ID})
    with pytest.raises(TypeError):
        ENRICHMENT_ATOMICS["enrich_ip"] = enrich_domain  # type: ignore[index]


def test_read_atomics_table_of_the_framework_includes_enrichment():
    atomics = pytest.importorskip("xdr_response.atomics")
    try:
        table = atomics.read_atomics()
    except ImportError:
        pytest.skip("investigation atomics not available yet")
    assert {name: table[name] for name in ENRICHMENT_ATOMICS} == dict(ENRICHMENT_ATOMICS)


@pytest.mark.parametrize(("observable", "atomic"), [
    (Observable(type=_O.IP, value=PUBLIC_IP), "enrich_ip"),
    (Observable(type=_O.IPV6, value="2001:db8::1"), "enrich_ip"),
    (Observable(type=_O.DOMAIN, value=DOMAIN), "enrich_domain"),
    (Observable(type=_O.URL, value=f"https://{DOMAIN}/x"), "enrich_url"),
    (Observable(type=_O.MD5, value=FAKE_MD5), "enrich_hash"),
    (Observable(type=_O.EMAIL_ADDRESS, value="jsmith@example.com"), "enrich_email_address"),
    (Observable(type=_O.USER, value="jsmith@example.com"), "enrich_user"),
    (Observable(type=_O.ENDPOINT_ID, value="mde-0001"), "enrich_endpoint"),
    (Observable(type=_O.HOSTNAME, value="TH-LT-1047"), "enrich_endpoint"),
])
def test_enrich_dispatches_by_observable_type(observable, atomic):
    the_lab, _ = _lab()
    report = enrich(the_lab.context(), observable)
    assert report.atomic == atomic and report.action_type is ActionType(atomic)
    assert report.subject.type is observable.type


@pytest.mark.parametrize("otype", [_O.MAC_ADDRESS, _O.EMAIL_MESSAGE_ID, _O.FILE_PATH])
def test_enrich_refuses_types_without_an_atomic(otype):
    the_lab, _ = _lab()
    with pytest.raises(ValueError, match="no enrichment atomic"):
        enrich(the_lab.context(), Observable(type=otype, value="x-0001"))


def test_enrich_needs_an_observable():
    the_lab, _ = _lab()
    with pytest.raises(ValueError):
        enrich(the_lab.context(), DOMAIN)  # type: ignore[arg-type]


def test_invalid_subjects_raise_before_any_source_is_asked():
    the_lab, env = _lab()
    with pytest.raises(ValueError):
        enrich_ip(the_lab.context(), "not-an-ip")
    with pytest.raises(ValueError):
        enrich_domain(the_lab.context(), Observable(type=_O.IP, value=PUBLIC_IP))
    assert env.calls == []


# ---------------------------------------------------------------- sources --
def test_every_enricher_gets_exactly_one_status_in_integration_order():
    the_lab, env = _lab()
    env.set_reputation(_O.DOMAIN, DOMAIN, Verdict.MALICIOUS, risk_score=80, confidence=70,
                       summary="listed as malware host", integrations=["umbrella", "virustotal"])
    report = enrich_domain(the_lab.context(), "BAD.example.test.")
    assert dict(statuses(report)) == {"umbrella": "answered", "virustotal": "answered", "alienvault_otx": "empty"}
    assert list(statuses(report)) == ["umbrella", "virustotal", "alienvault_otx"]
    assert report.answered == ("umbrella", "virustotal") and not report.degraded
    assert [r.integration for r in report.records] == ["umbrella", "virustotal"]
    assert all(s.health is HealthStatus.CONNECTED for s in report.sources)
    assert [s.records for s in report.sources] == [1, 1, 0]


def test_answered_sources_become_enrichment_records_with_deterministic_ids():
    the_lab, env = _lab()
    env.set_reputation(_O.DOMAIN, DOMAIN, Verdict.SUSPICIOUS, risk_score=55, confidence=60,
                       summary="newly registered domain", integrations=["virustotal"])
    report = enrich_domain(the_lab.context(), DOMAIN)
    (record,) = report.records
    assert isinstance(record, EnrichmentRecord) and record.kind is RecordKind.ENRICHMENT
    subject = Observable(type=_O.DOMAIN, value=DOMAIN)
    assert record.record_id == make_record_id("virustotal", RecordKind.ENRICHMENT, subject, {})
    assert (record.atomic, record.subject, record.integration) == ("enrich_domain", subject, "virustotal")
    assert (record.verdict, record.risk_score, record.confidence) == (Verdict.SUSPICIOUS, 55, 60)
    assert record.detail == "newly registered domain"
    assert record.observed_at == FIXED_NOW and record.reference == f"sim:virustotal:{DOMAIN}"
    again = enrich_domain(the_lab.context(), Observable(type=_O.DOMAIN, value="Bad.Example.Test", source="xdr"))
    assert again == report  # same input, same clock: identical report


def test_unknown_verdict_without_evidence_is_empty_not_a_record():
    the_lab, _ = _lab()
    report = enrich_url(the_lab.context(), f"https://{DOMAIN}/landing")
    assert set(statuses(report).values()) == {"empty"}
    assert report.records == () and not report.degraded


@pytest.mark.parametrize(("kind", "health", "code"), [
    (FaultKind.FAIL, HealthStatus.DEGRADED, ErrorCode.API_ERROR),
    (FaultKind.TIMEOUT, HealthStatus.DEGRADED, ErrorCode.TIMEOUT),
    (FaultKind.UNAVAILABLE, HealthStatus.UNAVAILABLE, ErrorCode.UNAVAILABLE),
    (FaultKind.AUTH_FAIL, HealthStatus.AUTH_FAILED, ErrorCode.AUTH_FAILED),
    (FaultKind.RATE_LIMIT, HealthStatus.RATE_LIMITED, ErrorCode.RATE_LIMITED),
])
def test_a_failing_source_is_failed_and_the_others_still_answer(kind, health, code):
    the_lab, env = _lab()
    env.set_reputation(_O.DOMAIN, DOMAIN, Verdict.MALICIOUS, risk_score=90, confidence=80, summary="c2 host")
    env.faults.append(Fault(kind, integration="virustotal", operation="enrich"))
    report = enrich_domain(the_lab.context(), DOMAIN)
    failed = next(s for s in report.sources if s.integration == "virustotal")
    assert failed.outcome is SourceOutcome.FAILED and failed.health is health
    assert failed.error is not None and failed.error.code is code and failed.reason == code.value
    assert report.degraded and report.failed == ("virustotal",)
    assert report.answered == ("umbrella", "alienvault_otx")
    assert report.risk_score == 90  # the other sources still back the report


def test_every_source_failing_still_returns_a_report_listing_the_failures(scorer):
    the_lab, env = _lab()
    env.faults.append(Fault(FaultKind.UNAVAILABLE, operation="enrich", remaining=None))
    report = enrich_domain(the_lab.context(), DOMAIN)
    assert report.failed == ("umbrella", "virustotal", "alienvault_otx") and report.records == ()
    assert (report.risk_score, report.confidence, report.verdict) == (0, 0, Verdict.UNKNOWN)
    assert scorer.last_context.failed_sources == (("alienvault_otx", HealthStatus.UNAVAILABLE),
                                                  ("umbrella", HealthStatus.UNAVAILABLE),
                                                  ("virustotal", HealthStatus.UNAVAILABLE))
    assert report.rule_item()["failed_sources"] == ["umbrella", "virustotal", "alienvault_otx"]


def test_failures_are_kept_as_raw_results_for_the_audit_trail():
    the_lab, env = _lab()
    env.faults.append(Fault(FaultKind.FAIL, integration="virustotal", operation="enrich"))
    report = enrich_domain(the_lab.context(), DOMAIN)
    assert [r.integration for r in report.raw] == ["umbrella", "virustotal", "alienvault_otx"]
    failed = report.raw[1]
    assert isinstance(failed, EnrichmentResult) and failed.verdict is Verdict.UNKNOWN
    assert failed.errors[0].code is ErrorCode.API_ERROR and failed.health is HealthStatus.DEGRADED


def _custom_adapter(the_lab: Lab, env: SimulatedEnvironment, name: str, enrich_impl) -> None:
    base = simulated_adapter_class(name, ("network",))
    cls = type(f"Custom{base.__name__}", (base,), {"enrich": enrich_impl})
    the_lab.registry.register(cls(environment=env, clock=the_lab.clock))


def test_unexpected_exceptions_fail_closed_with_a_redacted_internal_error():
    the_lab, env = _lab()

    def boom(self, observable):
        raise RuntimeError("parser crashed, api_key=fake-secret-value-123")

    _custom_adapter(the_lab, env, "umbrella", boom)
    report = enrich_domain(the_lab.context(), DOMAIN)
    status = report.sources[0]
    assert (status.integration, status.outcome, status.health) == ("umbrella", SourceOutcome.FAILED,
                                                                   HealthStatus.UNKNOWN)
    assert status.error.code is ErrorCode.INTERNAL and "fake-secret-value-123" not in status.error.message
    assert status.error.integration == "umbrella"


def test_an_adapter_returning_garbage_is_failed():
    the_lab, env = _lab()
    _custom_adapter(the_lab, env, "umbrella", lambda self, observable: {"verdict": "MALICIOUS"})
    report = enrich_domain(the_lab.context(), DOMAIN)
    assert report.sources[0].outcome is SourceOutcome.FAILED and report.records == ()


def test_a_result_with_errors_and_unknown_verdict_is_failed_with_its_health():
    the_lab, env = _lab()

    def degraded(self, observable):
        error = ErrorInfo(code=ErrorCode.API_ERROR, message="partial outage", integration=self.name)
        return EnrichmentResult(type=observable.type, value=observable.value, risk_score=0, confidence=0,
                                sources=(self.name,), verdict=Verdict.UNKNOWN, integration=self.name,
                                health=HealthStatus.DEGRADED, errors=(error,))

    _custom_adapter(the_lab, env, "umbrella", degraded)
    status = enrich_domain(the_lab.context(), DOMAIN).sources[0]
    assert (status.outcome, status.health, status.reason) == (SourceOutcome.FAILED, HealthStatus.DEGRADED,
                                                              "API_ERROR")


def test_a_verdict_with_errors_or_unknown_with_evidence_is_still_answered():
    the_lab, env = _lab()

    def partial(self, observable):
        error = ErrorInfo(code=ErrorCode.TIMEOUT, message="one module timed out", integration=self.name)
        evidence = EvidenceDraft(source=self.name, summary="status 0 (no verdict)",
                                 data={"security_categories": ["Newly Seen Domains"],
                                       "content_categories": ["Business", "Newly Seen Domains", 7],
                                       "first_seen": "2026-01-10T08:00:00+00:00"})
        return EnrichmentResult(type=observable.type, value=observable.value, risk_score=0, confidence=30,
                                sources=(self.name,), verdict=Verdict.UNKNOWN, integration=self.name,
                                evidence=(evidence,), errors=(error,) if observable.value.startswith("x") else ())

    _custom_adapter(the_lab, env, "umbrella", partial)
    report = enrich_domain(the_lab.context(), DOMAIN)
    (record,) = report.records
    assert report.sources[0].outcome is SourceOutcome.ANSWERED and record.verdict is Verdict.UNKNOWN
    assert record.categories == ("Newly Seen Domains", "Business")
    assert record.first_seen == FIXED_NOW - timedelta(days=5, hours=4)
    assert report.categories() == ("Business", "Newly Seen Domains")
    errored = enrich_domain(the_lab.context(), "x.example.test")
    assert errored.sources[0].outcome is SourceOutcome.FAILED  # UNKNOWN + errors


# ---------------------------------------------------------------- privacy --
def _third_party_calls(env: SimulatedEnvironment) -> list[tuple[str, str, str | None]]:
    return [c for c in _called(env) if c[0] in {"virustotal", "alienvault_otx", "hibp"}]


@pytest.mark.parametrize("value", [PRIVATE_IP, "127.0.0.1", "169.254.10.1", "fd00::1", PUBLIC_IP])
def test_non_public_ips_are_never_sent_to_public_intel(value):
    the_lab, env = _lab()
    report = enrich_ip(the_lab.context(), value)  # documentation ranges are not public by default
    third = {s.integration: s for s in report.sources if s.integration in {"virustotal", "alienvault_otx"}}
    assert {s.outcome for s in third.values()} == {SourceOutcome.NOT_QUERIED}
    assert {s.reason for s in third.values()} == {DISCLOSURE_REASON}
    assert {s.health for s in third.values()} == {HealthStatus.UNKNOWN}
    assert _third_party_calls(env) == []
    assert ("umbrella", "enrich", report.value) in _called(env)  # internal tools still answer


def test_public_ips_go_to_public_intel_when_the_policy_allows():
    the_lab, env = _lab()
    env.set_reputation(_O.IP, PUBLIC_IP, Verdict.MALICIOUS, risk_score=70, confidence=60, summary="scanner")
    report = enrich_ip(the_lab.context(public_documentation_ranges=True), PUBLIC_IP)
    assert report.answered == ("umbrella", "virustotal", "alienvault_otx")
    assert {c[0] for c in _third_party_calls(env)} == {"virustotal", "alienvault_otx"}


@pytest.mark.parametrize("value", ["fileserver.corp.example.com", "intranet.local", "printer01"])
def test_internal_domains_never_leave_the_organization(value):
    the_lab, env = _lab(exclusions=ExclusionsConfig(internal_domains=["corp.example.com"]))
    report = enrich_domain(the_lab.context(), value)
    assert statuses(report)["virustotal"] == "not_queried" and statuses(report)["alienvault_otx"] == "not_queried"
    assert _third_party_calls(env) == []


def test_urls_on_internal_hosts_are_withheld():
    the_lab, env = _lab(exclusions=ExclusionsConfig(internal_domains=["corp.example.com"]))
    report = enrich_url(the_lab.context(), "https://wiki.corp.example.com/page?id=42")
    assert report.not_queried == ("virustotal", "alienvault_otx")
    assert _third_party_calls(env) == []


def test_hashes_may_be_sent_to_public_intel():
    the_lab, env = _lab()
    env.set_reputation(_O.SHA256, FAKE_SHA256, Verdict.MALICIOUS, risk_score=95, confidence=90, summary="trojan")
    report = enrich_hash(the_lab.context(), FAKE_SHA256)
    assert report.answered == ("virustotal", "alienvault_otx") and report.not_queried == ()


@pytest.mark.parametrize(("atomic", "value"), [
    (enrich_ip, "198.51.100.7"), (enrich_domain, DOMAIN), (enrich_hash, FAKE_SHA256),
    (enrich_url, f"https://{DOMAIN}/x"),
])
def test_hibp_never_receives_anything_but_email_addresses(atomic, value):
    the_lab, env = _lab(HIBP_SUITE)
    report = atomic(the_lab.context(public_documentation_ranges=True), value)
    assert report.not_queried == ("hibp",)
    assert [c for c in _third_party_calls(env) if c[0] == "hibp"] == []


def test_email_addresses_only_ever_reach_hibp_and_only_for_external_domains():
    the_lab, env = _lab(HIBP_SUITE, exclusions=ExclusionsConfig(
        third_party_lookup={"user_domains": ["example.com"]}))
    internal = enrich_email_address(the_lab.context(), "jsmith@example.com")
    assert internal.not_queried == ("virustotal", "alienvault_otx", "hibp")
    assert _third_party_calls(env) == []
    external = enrich_email_address(the_lab.context(), "sender@partner.example.net")
    assert external.not_queried == ("virustotal", "alienvault_otx")
    assert _third_party_calls(env) == [("hibp", "enrich", "sender@partner.example.net")]


@pytest.mark.parametrize(("atomic", "value"), [
    (enrich_user, "jsmith@example.com"), (enrich_endpoint, "TH-LT-1047"),
    (enrich_endpoint, Observable(type=_O.ENDPOINT_ID, value="mde-0001")),
])
def test_users_and_endpoints_are_never_disclosed_even_if_a_third_party_claims_support(atomic, value):
    the_lab, env = _lab({"entra": ("identity",), "secure_endpoint": ("endpoint",)})
    for name in ("virustotal", "alienvault_otx", "hibp"):  # misconfigured lab adapters accepting everything
        cls = simulated_adapter_class(name, ("identity", "endpoint"))
        the_lab.registry.register(cls(environment=env, clock=the_lab.clock))
    report = atomic(the_lab.context(public_documentation_ranges=True), value)
    assert report.not_queried == ("virustotal", "alienvault_otx", "hibp")
    assert _third_party_calls(env) == []
    assert report.answered == () and len(report.sources) == 4


def test_a_disclosure_policy_error_withholds_the_observable():
    the_lab, env = _lab()

    class BrokenPolicy:
        def may_disclose(self, observable, integration):
            raise RuntimeError("policy file unreadable")

    report = enrich_hash(the_lab.context(disclosure=BrokenPolicy()), FAKE_SHA256)
    assert report.not_queried == ("virustotal", "alienvault_otx")
    assert _third_party_calls(env) == []


def test_not_queried_sources_are_passed_to_scoring_and_cost_no_failure(scorer):
    the_lab, _ = _lab()
    report = enrich_ip(the_lab.context(), PRIVATE_IP)
    context = scorer.last_context
    assert context.not_queried == (("alienvault_otx", DISCLOSURE_REASON), ("virustotal", DISCLOSURE_REASON))
    assert context.failed_sources == () and not report.degraded
    assert report.raw and all(r.integration == "umbrella" for r in report.raw)


# ---------------------------------------------------------------- scoring --
def test_scoring_context_lists_every_enricher_as_expected(scorer):
    the_lab, env = _lab()
    env.faults.append(Fault(FaultKind.RATE_LIMIT, integration="alienvault_otx", operation="enrich"))
    enrich_domain(the_lab.context(), DOMAIN)
    context = scorer.last_context
    assert context.expected_sources == ("umbrella", "virustotal", "alienvault_otx")
    assert context.failed_sources == (("alienvault_otx", HealthStatus.RATE_LIMITED),)
    assert context.critical_asset_classes == ()


def test_scoring_receives_only_the_answering_records_and_the_configured_settings(scorer):
    the_lab, env = _lab()
    env.set_reputation(_O.DOMAIN, DOMAIN, Verdict.MALICIOUS, risk_score=80, confidence=70, summary="x",
                       integrations=["virustotal"])
    report = enrich_domain(the_lab.context(), DOMAIN)
    settings, records, _ = scorer.calls[-1]
    assert settings is the_lab.settings.thresholds.scoring
    assert records == report.records


def test_critical_asset_classes_of_the_subject_reach_the_scoring_context(scorer):
    critical = CriticalAssetsConfig(classes={CriticalAssetClass.DOMAIN_CONTROLLER: CriticalAssetClassConfig(
        display_name="Domain controller", role="identity", potential_impact="authentication outage",
        match=AssetMatch(hostname_patterns=["th-dc-*"]))})
    the_lab, _ = _lab({"secure_endpoint": ("endpoint",)}, critical_assets=critical)
    enrich_endpoint(the_lab.context(), "th-dc-01")
    assert scorer.last_context.critical_asset_classes == (CriticalAssetClass.DOMAIN_CONTROLLER,)
    enrich_endpoint(the_lab.context(), "TH-LT-1047")
    assert scorer.last_context.critical_asset_classes == ()


def test_one_vendor_alone_never_decides_the_verdict():
    the_lab, env = _lab()
    env.set_reputation(_O.DOMAIN, DOMAIN, Verdict.MALICIOUS, risk_score=90, confidence=80, summary="x",
                       integrations=["virustotal"])
    report = enrich_domain(the_lab.context(), DOMAIN)
    assert report.source_verdicts() == {"virustotal": "MALICIOUS"}
    assert report.verdict is Verdict.SUSPICIOUS  # the aggregate (scorer), never the vendor's word


# ----------------------------------------------------------------- report --
def test_report_carries_the_normalized_observable():
    the_lab, env = _lab()
    env.set_reputation(_O.DOMAIN, DOMAIN, Verdict.MALICIOUS, risk_score=80, confidence=70, summary="x",
                       integrations=["umbrella", "virustotal"])
    report = enrich_domain(the_lab.context(), "Bad.Example.Test")
    assert isinstance(report, ObservableReport)
    assert report.normalized() == {"type": "domain", "value": DOMAIN, "risk_score": 80, "confidence": 70,
                                   "sources": ["umbrella", "virustotal"], "verdict": "MALICIOUS"}
    assert (report.type, report.value) == (_O.DOMAIN, DOMAIN)
    assert (report.risk_score, report.confidence) == (report.breakdown.risk_score,
                                                      report.breakdown.confidence_score)


def test_rule_item_has_the_common_and_enrichment_keys():
    the_lab, env = _lab()
    env.set_reputation(_O.IP, PRIVATE_IP, Verdict.SUSPICIOUS, risk_score=50, confidence=60, summary="x")
    env.faults.append(Fault(FaultKind.TIMEOUT, integration="umbrella", operation="enrich"))
    item = enrich_ip(the_lab.context(), PRIVATE_IP).rule_item()
    assert set(item) == {"atomic", "subject_type", "subject", "record_ids", "sources", "failed_sources",
                         "degraded", "type", "value", "risk_score", "confidence", "verdict", "not_queried",
                         "categories", "source_verdicts"}
    assert item["atomic"] == "enrich_ip" and item["subject_type"] == "ip" and item["subject"] == PRIVATE_IP
    assert item["failed_sources"] == ["umbrella"] and item["degraded"] is True
    assert item["not_queried"] == ["virustotal", "alienvault_otx"] and item["record_ids"] == []
    assert item["sources"] == [] and item["source_verdicts"] == {}


def test_report_timestamps_come_from_the_injected_clock():
    the_lab, _ = _lab()
    report = enrich_domain(the_lab.context(), DOMAIN)
    assert report.started_at == report.finished_at == FIXED_NOW


def _report(**changes: object) -> ObservableReport:
    the_lab, env = _lab()
    env.set_reputation(_O.DOMAIN, DOMAIN, Verdict.MALICIOUS, risk_score=80, confidence=70, summary="x")
    report = enrich_domain(the_lab.context(), DOMAIN)
    data = {name: getattr(report, name) for name in ObservableReport.model_fields}
    data.update(changes)
    return ObservableReport(**data)


@pytest.mark.parametrize("changes", [
    {"risk_score": 99}, {"confidence": 1}, {"value": "other.example.test"}, {"type": _O.URL},
    {"action_type": ActionType.INVESTIGATE_DOMAIN},
])
def test_report_refuses_scores_or_subjects_it_did_not_compute(changes):
    with pytest.raises(ValidationError):
        _report(**changes)


def test_report_round_trips():
    report = _report()
    assert ObservableReport.model_validate(report.model_dump()) == report


# -------------------------------------------------------------- read only --
def _all_operations(env: SimulatedEnvironment) -> Sequence[str]:
    return sorted({c.operation for c in env.calls})


def test_atomics_only_ever_read():
    the_lab, env = _lab({"umbrella": ("network",), "entra": ("identity",), "secure_endpoint": ("endpoint",),
                         "virustotal": ("intel",)})
    ctx = the_lab.context(public_documentation_ranges=True)
    for atomic, value in ((enrich_ip, PUBLIC_IP), (enrich_domain, DOMAIN), (enrich_url, f"https://{DOMAIN}/"),
                          (enrich_hash, FAKE_SHA256), (enrich_email_address, "sender@partner.example.net"),
                          (enrich_user, "jsmith@example.com"), (enrich_endpoint, "TH-LT-1047")):
        atomic(ctx, value)
    assert _all_operations(env) == ["enrich"]
    assert {c.kind for c in env.calls} == {OperationKind.READ}
    assert env.state == {}
