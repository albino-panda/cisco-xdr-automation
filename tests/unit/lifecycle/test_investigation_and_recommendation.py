"""Automatic investigation (failure isolation, audit) and the rule-based recommender."""
from __future__ import annotations

import pytest

from tests.fixtures.factories import FIXED_NOW
from xdr_response.audit import MemoryAuditTrail
from xdr_response.clock import FixedClock
from xdr_response.config import IntegrationConfig, Settings
from xdr_response.integrations.registry import AdapterRegistry
from xdr_response.integrations.simulated import FaultKind, SimulatedEnvironment, register_simulated_adapters
from xdr_response.lifecycle import InvestigationService, PlaybookRule, RuleBasedRecommender
from xdr_response.lifecycle.recommendation import combined_verdict
from xdr_response.models import (
    ActionType,
    AuditEventType,
    EnrichmentResult,
    HealthStatus,
    Incident,
    Observable,
    ObservableType,
    Severity,
    Verdict,
)
from xdr_response.secrets import StaticSecretProvider

SUITE = {"secure_endpoint": ("endpoint",), "entra": ("identity",), "umbrella": ("network",),
         "meraki": ("network",), "virustotal": ("intel",)}
DOMAIN = "c2.bad-actor.example"


def _registry(env: SimulatedEnvironment, audit: MemoryAuditTrail) -> AdapterRegistry:
    settings = Settings(integrations={n: IntegrationConfig(enabled=False) for n in SUITE})
    registry = AdapterRegistry(settings, StaticSecretProvider({}), clock=env.clock, audit=audit)
    register_simulated_adapters(registry, env, suite=SUITE, audit=audit)
    return registry


def _incident(*observables: Observable) -> Incident:
    return Incident(incident_id="XDR-INV-1", title="t", severity=Severity.HIGH, created_at=FIXED_NOW,
                    workflow_id="wf", workflow_version="1", observables=observables)


@pytest.fixture
def env():
    clock = FixedClock(FIXED_NOW)
    environment = SimulatedEnvironment(clock=clock)
    environment.set_reputation(ObservableType.DOMAIN, DOMAIN, Verdict.MALICIOUS, risk_score=90, confidence=80,
                               summary="umbrella says malicious", integrations=["umbrella", "virustotal"])
    environment.set_reputation(ObservableType.HOSTNAME, "TH-LT-1047", Verdict.SUSPICIOUS, risk_score=50,
                               confidence=60, integrations=["secure_endpoint"])
    environment.set_reputation(ObservableType.USER, "jsmith@example.com", Verdict.SUSPICIOUS, risk_score=75,
                               confidence=60, integrations=["entra"])
    return environment


def test_investigation_enriches_every_distinct_observable_and_audits(env):
    audit = MemoryAuditTrail(clock=env.clock)
    service = InvestigationService(_registry(env, audit), audit=audit, clock=env.clock)
    incident = _incident(Observable(type=ObservableType.DOMAIN, value=DOMAIN),
                         Observable(type=ObservableType.DOMAIN, value=DOMAIN.upper()),
                         Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047"))
    report = service.run(incident)
    domain_sources = sorted(r.integration for r in report.enrichments if r.type is ObservableType.DOMAIN)
    assert domain_sources == ["meraki", "umbrella", "virustotal"]  # duplicates collapsed, every enricher asked
    events = [r.event_type for r in audit.records()]
    assert events.count(AuditEventType.ENRICHMENT_RESULT) == len(report.enrichments)
    assert events[-1] is AuditEventType.INVESTIGATION_COMPLETED
    assert report.evidence and all(e.number >= 1 for e in report.evidence)


def test_one_failing_source_never_blocks_the_others(env):
    audit = MemoryAuditTrail(clock=env.clock)
    env.inject(FaultKind.UNAVAILABLE, integration="virustotal", operation="enrich", times=None)
    registry = _registry(env, audit)
    report = InvestigationService(registry, audit=audit, clock=env.clock).run(
        _incident(Observable(type=ObservableType.DOMAIN, value=DOMAIN)))
    vt = next(r for r in report.enrichments if r.integration == "virustotal")
    assert vt.verdict is Verdict.UNKNOWN and vt.health is HealthStatus.UNAVAILABLE and vt.errors
    assert report.health["virustotal"] is HealthStatus.UNAVAILABLE and "virustotal" in report.degraded_sources
    recommendation = RuleBasedRecommender(registry).recommend(
        _incident(Observable(type=ObservableType.DOMAIN, value=DOMAIN)), report)
    assert [p.action_type for p in recommendation.proposals] == [ActionType.BLOCK_DOMAIN]
    assert any("virustotal" in note for note in recommendation.notes)


def test_an_exception_of_any_type_is_contained():
    class Broken:
        name = "virustotal"

        def enrich(self, observable):
            raise RuntimeError("boom with secret=hunter2-long-value")

    class Registry:
        def for_observable(self, _t):
            return [Broken()]

        def for_action(self, _a):
            return []

    report = InvestigationService(Registry()).run(_incident(Observable(type=ObservableType.IP, value="198.51.100.9")))
    (result,) = report.enrichments
    assert result.verdict is Verdict.UNKNOWN and result.errors[0].code.value == "INTERNAL"
    assert "hunter2-long-value" not in result.errors[0].message


def test_recommender_thresholds_and_routing(env):
    audit = MemoryAuditTrail(clock=env.clock)
    registry = _registry(env, audit)
    incident = _incident(Observable(type=ObservableType.DOMAIN, value=DOMAIN),
                         Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047"),
                         Observable(type=ObservableType.USER, value="jsmith@example.com"))
    report = InvestigationService(registry, clock=env.clock).run(incident)
    recommendation = RuleBasedRecommender(registry).recommend(incident, report)
    by_type = {p.action_type: p for p in recommendation.proposals}
    # suspicious endpoint below the HIGH band: no isolation; suspicious user at 75: disable + revoke
    assert set(by_type) == {ActionType.BLOCK_DOMAIN, ActionType.DISABLE_USER, ActionType.REVOKE_SESSIONS}
    block = by_type[ActionType.BLOCK_DOMAIN]
    assert block.params == {"integration": "umbrella"}  # catalog preference among enabled adapters
    assert block.risk_score == 90 and block.confidence_score == 90  # 80 + 10 for one corroborating source
    assert {e.source for e in block.evidence} == {"umbrella", "virustotal"}
    assert recommendation.risk_score == 90
    assert by_type[ActionType.DISABLE_USER].target == "jsmith@example.com"


def test_unroutable_actions_are_reported_not_proposed(env):
    audit = MemoryAuditTrail(clock=env.clock)
    registry = _registry(env, audit)
    incident = _incident(Observable(type=ObservableType.DOMAIN, value=DOMAIN))
    report = InvestigationService(registry, clock=env.clock).run(incident)
    rules = (PlaybookRule(frozenset({ObservableType.DOMAIN}), (ActionType.BLOCK_DOMAIN,)),)
    recommender = RuleBasedRecommender(registry, playbook=rules,
                                       preferred_integrations={ActionType.BLOCK_DOMAIN: "cisco_xdr"})
    recommendation = recommender.recommend(incident, report)
    assert recommendation.empty and recommendation.unrouted[0].action_type is ActionType.BLOCK_DOMAIN


def test_params_hook_adds_adapter_parameters(env):
    audit = MemoryAuditTrail(clock=env.clock)
    registry = _registry(env, audit)
    incident = _incident(Observable(type=ObservableType.DOMAIN, value=DOMAIN))
    report = InvestigationService(registry, clock=env.clock).run(incident)
    recommender = RuleBasedRecommender(registry, params_for=lambda a, i, t: {"destination_list_id": "17",
                                                                               "integration": "evil"})
    (proposal,) = recommender.recommend(incident, report).proposals
    assert proposal.params == {"integration": "umbrella", "destination_list_id": "17"}


def test_combined_verdict_worst_wins_and_failed_sources_do_not_count():
    def result(verdict, risk, confidence, name, errors=()):
        return EnrichmentResult(type=ObservableType.IP, value="198.51.100.9", risk_score=risk,
                                confidence=confidence, sources=(name,), verdict=verdict, integration=name,
                                errors=errors)

    clean = result(Verdict.CLEAN, 5, 90, "umbrella")
    bad = result(Verdict.MALICIOUS, 80, 70, "virustotal")
    assert combined_verdict([clean, bad])[:3] == (Verdict.MALICIOUS, 80, 70)
    assert combined_verdict([])[0] is Verdict.UNKNOWN


def test_no_evidence_no_proposal():
    rule = PlaybookRule(frozenset({ObservableType.DOMAIN}), (ActionType.BLOCK_DOMAIN,))
    assert rule.fires(Verdict.MALICIOUS, 0) and not rule.fires(Verdict.SUSPICIOUS, 59)
    assert rule.fires(Verdict.SUSPICIOUS, 60) and not rule.fires(Verdict.CLEAN, 100)
