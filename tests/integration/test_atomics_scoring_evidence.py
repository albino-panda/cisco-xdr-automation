"""Phase 1 read zone end to end over real vendor adapters (no network; architecture 14.1-14.3).

Real ``UmbrellaAdapter``, ``VirusTotalAdapter`` and ``EntraAdapter`` (real ``GuardedHttpClient`` and
auth providers) answer through stateful fake vendor APIs (``_fake_vendors``). On top of them:

* the enrichment atomic asks every enricher through ``ReadOnlyAdapters`` and scores with the real
  ``ScoringEngine`` (risk and confidence separate, a single vendor never decides alone);
* the evidence builder cites only records of the run, and a fabricated record id is refused;
* correlation links and the blast-radius scope cite the same records;
* a containment builder routes to Umbrella and returns data only; ``PackageBuilder`` numbers the
  evidence and decides the approval level;
* a workflow (defined here, tests only) runs through the production lifecycle: automatic
  investigation and recommendation with zero vendor writes, then a human approval, execution,
  verification and a separately approved release.
"""
from __future__ import annotations

import httpx
import pytest

from tests.fixtures.principals import AI_ID, ANALYST_ID, AUTOMATION_ID, credential
from tests.integration.test_lifecycle_http_adapters import DOMAIN, LIST_ID, Lab
from xdr_response import guard
from xdr_response.atomics.containment import CONTAINMENT_BUILDERS
from xdr_response.atomics.context import build_context
from xdr_response.atomics.correlation import blast_radius, correlate
from xdr_response.atomics.enrichment.atomics import enrich_domain
from xdr_response.atomics.evidence import EvidenceBuilder, EvidenceError, RecordIndex
from xdr_response.atomics.records import EnrichmentRecord, SourceOutcome
from xdr_response.errors import ApprovalError
from xdr_response.lifecycle.workflow_adapter import WorkflowInvestigationReport
from xdr_response.models import (
    ActionType,
    ApprovalLevel,
    AuditEventType,
    ContainmentOverall,
    DecisionRequest,
    DecisionType,
    HealthStatus,
    Incident,
    IncidentState,
    ObservableType,
    Severity,
    Verdict,
)
from xdr_response.workflows.definition import (
    CorrelationSpec,
    IntegrationRequirement,
    InvestigationStep,
    MitreMapping,
    RecommendationRule,
    ScoringInputs,
    TriggerSpec,
    WorkflowDefinition,
)
from xdr_response.workflows.discovery import DiscoveredWorkflow, WorkflowCatalog

FAKE_RECORD_ID = "rec_" + "0" * 32

#: Tests-only workflow: block a command-and-control domain that reputation sources agree on.
C2_DOMAIN = WorkflowDefinition(
    id="integration-c2-domain",
    version="1.0.0",
    name="Integration C2 domain",
    description="Tests-only workflow: blocks a domain that DNS and intelligence sources rate malicious.",
    phase=4,
    default_severity=Severity.HIGH,
    triggers=(TriggerSpec(type="manual", description="Started by the integration test"),),
    input_observables=(ObservableType.DOMAIN, ObservableType.USER),
    required_integrations=(
        IntegrationRequirement(integration="umbrella", purpose="DNS reputation and the block list",
                               atomics=("enrich_domain",)),
    ),
    optional_integrations=(
        IntegrationRequirement(integration="virustotal", purpose="Second opinion on the domain",
                               atomics=("enrich_domain",)),
    ),
    investigation=(InvestigationStep(id="domain_reputation", atomic="enrich_domain"),),
    correlation=CorrelationSpec(description="Shared indicators across the run's records."),
    scoring=ScoringInputs(description="Reputation only: capped by the engine."),
    recommendations=(
        RecommendationRule(
            id="block_c2_domain",
            description="Block a domain rated malicious or suspicious",
            action=ActionType.BLOCK_DOMAIN,
            builder="block_domain_umbrella",
            for_each="[r for r in results.enrich_domain if r.verdict in ['MALICIOUS', 'SUSPICIOUS']]",
            target="item.value",
            evidence="item.record_ids",
            include_target_enrichment=False,
            rationale="'domain rated ' + item.verdict",
            min_risk=40,
            mitre=("T1071.004",),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0011", technique="T1071", technique_name="Application Layer Protocol",
                     sub_technique="T1071.004", sub_technique_name="DNS",
                     rationale="The domain is used as a command-and-control channel."),
    ),
    known_limitations=("Tests-only: never deployed.",),
)
CATALOG = WorkflowCatalog([DiscoveredWorkflow(C2_DOMAIN, None, "tests.integration")])


def _lab(*, dry_run: bool = False, workflows: WorkflowCatalog | None = None) -> Lab:
    """A fresh HTTP lab. The guard allows one runtime per process, so the harness resets it first."""
    guard._reset_for_test_harness()
    return Lab(dry_run=dry_run, workflows=workflows)


def _incident(lab: Lab, workflow_id: str = "c2-beacon") -> Incident:
    return lab.incident().model_copy(update={"workflow_id": workflow_id})


def _ctx(lab: Lab, *, dry_run: bool = False):
    return build_context(_incident(lab), lab.runtime.adapters, lab.runtime.settings, clock=lab.clock,
                         dry_run=dry_run)


def _get_paths(lab: Lab) -> list[str]:
    return [r.url.path for r in lab.umbrella.requests + lab.vt.requests if r.method == "GET"]


# --------------------------------------------------------------------------------- atomics --
def test_enrichment_over_real_http_is_scored_and_cites_its_records():
    lab = _lab()
    report = enrich_domain(_ctx(lab), DOMAIN)

    outcomes = {s.integration: s.outcome for s in report.sources}
    assert outcomes["umbrella"] is SourceOutcome.ANSWERED and outcomes["virustotal"] is SourceOutcome.ANSWERED
    assert report.verdict is Verdict.MALICIOUS  # two independent reputation sources agree
    assert (report.risk_score, report.confidence) == (report.breakdown.risk_score, report.breakdown.confidence_score)
    assert type(report.risk_score) is int and type(report.confidence) is int
    assert all(isinstance(r, EnrichmentRecord) for r in report.records)
    assert {r.integration for r in report.records} == {"umbrella", "virustotal"}

    record_ids = set(report.record_ids())
    for contribution in report.breakdown.contributions:
        assert set(contribution.record_ids) <= record_ids, "a score may only cite the run's records"

    builder = EvidenceBuilder(RecordIndex([report]))
    drafts = builder.cite(report.record_ids())
    builder.verify(drafts)
    assert [d.data["record_id"] for d in drafts] and {d.source for d in drafts} == {"umbrella", "virustotal"}
    with pytest.raises(EvidenceError):
        builder.cite([FAKE_RECORD_ID])  # evidence without a source record cannot exist

    assert lab.all_writes() == []
    assert any("categorization" in p for p in _get_paths(lab))


def test_a_failed_source_degrades_but_never_blocks_the_score():
    healthy = enrich_domain(_ctx(_lab()), DOMAIN)
    lab = _lab()
    lab.umbrella.fail("GET", "/investigate/v2/domains/categorization", httpx.Response(500))
    report = enrich_domain(_ctx(lab), DOMAIN)

    umbrella = next(s for s in report.sources if s.integration == "umbrella")
    assert umbrella.outcome is SourceOutcome.FAILED and umbrella.health is not HealthStatus.CONNECTED
    assert umbrella.error is not None
    assert report.degraded and "umbrella" in report.failed
    assert report.verdict is Verdict.SUSPICIOUS  # one vendor's MALICIOUS alone is only SUSPICIOUS
    assert report.confidence < healthy.confidence
    assert report.risk_score > 0, "the VirusTotal evidence still counts"
    assert any(f.startswith("umbrella (") for f in report.breakdown.failed_sources)
    EvidenceBuilder(RecordIndex([report])).verify(EvidenceBuilder(RecordIndex([report])).cite(report.record_ids()))
    assert lab.all_writes() == []


def test_correlation_and_blast_radius_cite_only_run_records():
    lab = _lab()
    ctx = _ctx(lab)
    report = enrich_domain(ctx, DOMAIN)
    correlation = correlate(ctx, [report])
    index = RecordIndex([report])
    for link in correlation.links:
        index.require(link.record_ids)
    scope = blast_radius(ctx, correlation, [report])
    assert set(scope.record_ids) <= set(index.ids())
    assert DOMAIN in scope.indicators
    assert scope.critical_assets == ()


def test_a_builder_routes_and_returns_data_then_package_builder_decides():
    lab = _lab()
    ctx = _ctx(lab)
    report = enrich_domain(ctx, DOMAIN)
    evidence = EvidenceBuilder(RecordIndex([report])).cite(report.record_ids())
    built = CONTAINMENT_BUILDERS["block_domain_umbrella"](
        ctx, DOMAIN, evidence=evidence, risk_score=report.risk_score, confidence_score=report.confidence,
        rationale=report.breakdown.explain())
    assert built.routed and built.route.integration == "umbrella" and not built.route.native
    assert built.proposal is not None and built.proposal.params["integration"] == "umbrella"
    assert "approval_level" not in built.proposal.model_dump()

    package = lab.runtime.packages.build(_incident(lab), [built.proposal], risk_score=report.risk_score,
                                         confidence_score=report.confidence, summary="integration", dry_run=False)
    action = package.actions[0]
    assert action.approval_level is ApprovalLevel.STANDARD
    assert [e.number for e in action.evidence] == list(range(1, len(evidence) + 1))
    EvidenceBuilder(RecordIndex([report])).verify(action.evidence)
    assert lab.all_writes() == [], "recommending never writes"


# ------------------------------------------------------------------------------- lifecycle --
def _workflow_lab(*, dry_run: bool = False) -> Lab:
    """The HTTP lab with the tests-only workflow catalog wired into the production runtime."""
    return _lab(dry_run=dry_run, workflows=CATALOG)


def test_a_workflow_runs_through_the_lifecycle_and_only_a_human_unlocks_execution():
    lab = _workflow_lab()
    detection = lab.orchestrator.handle_detection(_incident(lab, C2_DOMAIN.id))

    assert isinstance(detection.investigation, WorkflowInvestigationReport)
    run = detection.investigation.run
    assert run is not None and run.workflow.id == C2_DOMAIN.id
    package = detection.package
    assert package is not None and package.workflow_id == C2_DOMAIN.id and package.workflow_version == "1.0.0"
    assert [(a.action_type, a.target, a.integration) for a in package.actions] == [
        (ActionType.BLOCK_DOMAIN, DOMAIN, "umbrella")]
    assert (package.risk_score, package.confidence_score) == (run.risk_score, run.confidence_score)
    EvidenceBuilder(run.index).verify(package.actions[0].evidence)
    assert lab.all_writes() == [], "investigation and recommendation never write"
    assert lab.orchestrator.get_incident(package.incident_id).state is IncidentState.AWAITING_APPROVAL
    events = [r.event_type for r in lab.audit.records(package.incident_id)]
    assert AuditEventType.ENRICHMENT_RESULT in events and AuditEventType.INVESTIGATION_COMPLETED in events

    for principal in (AI_ID, AUTOMATION_ID):  # AI and automation can never approve
        with pytest.raises(ApprovalError):
            lab.orchestrator.submit_decision(
                DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL),
                [credential(principal)])
    assert lab.all_writes() == []

    result = lab.orchestrator.submit_decision(
        DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL), [credential(ANALYST_ID)])
    assert result.report is not None and result.report.overall is ContainmentOverall.CONTAINED
    assert lab.umbrella.blocked(LIST_ID, DOMAIN)

    release = lab.orchestrator.propose_release(package.incident_id)
    assert lab.umbrella.blocked(LIST_ID, DOMAIN), "proposing a release changes nothing"
    lab.orchestrator.submit_release_decision(
        DecisionRequest(package_id=release.package_id, decision=DecisionType.APPROVE_ALL), [credential(ANALYST_ID)])
    assert not lab.umbrella.blocked(LIST_ID, DOMAIN)
    assert lab.runtime.audit.verify().ok


def test_the_workflow_dry_run_scores_like_live_and_never_writes():
    live = _workflow_lab()
    live_detection = live.orchestrator.handle_detection(_incident(live, C2_DOMAIN.id))
    dry = _workflow_lab(dry_run=True)
    detection = dry.orchestrator.handle_detection(_incident(dry, C2_DOMAIN.id))

    assert detection.package is not None and detection.package.dry_run
    assert detection.dry_run_report is not None and detection.dry_run_report.dry_run
    assert (detection.package.risk_score, detection.package.confidence_score) == (
        live_detection.package.risk_score, live_detection.package.confidence_score)
    result = dry.orchestrator.submit_decision(
        DecisionRequest(package_id=detection.package.package_id, decision=DecisionType.APPROVE_ALL),
        [credential(ANALYST_ID)])
    assert result.dry_run
    assert dry.all_writes() == [] and not dry.umbrella.blocked(LIST_ID, DOMAIN)


def test_an_incident_without_a_workflow_takes_the_phase_0_path():
    lab = _workflow_lab()
    detection = lab.orchestrator.handle_detection(_incident(lab, "c2-beacon"))
    run = detection.investigation.run if isinstance(detection.investigation, WorkflowInvestigationReport) else None
    assert run is None
    assert detection.package is not None  # the Phase 0 generic recommender still proposes the block
    assert (ActionType.BLOCK_DOMAIN, DOMAIN) in {(a.action_type, a.target) for a in detection.package.actions}
    assert detection.package.workflow_id == "c2-beacon"
    assert lab.all_writes() == []


# ------------------------------------------------- investigation + scoring + critical asset --
def test_investigation_records_score_cite_and_a_critical_asset_is_elevated_whatever_the_score():
    """Typed investigation records -> scoring signals -> evidence -> builder -> PackageBuilder ELEVATED."""
    from tests.fixtures.sample_workflows.lab import make_incident, make_lab
    from xdr_response.approval import CriticalAssetPolicy, PackageBuilder
    from xdr_response.atomics.enrichment.atomics import enrich_hash
    from xdr_response.atomics.investigation.atomics import investigate_endpoint
    from xdr_response.atomics.records import RecordKind
    from xdr_response.config.policy import AllowlistPolicy
    from xdr_response.models import Asset, CriticalAssetClass, Observable, TargetKind
    from xdr_response.models.scoring import ScoringContext
    from xdr_response.scoring import ScoringEngine, signals_from_records

    host, sha = "TH-DC-02", "7e57da7a" * 8  # matches the "*-DC-*" domain-controller pattern
    lab = make_lab()
    lab.infected(host, sha)
    incident = make_incident((ObservableType.HOSTNAME, host), title="Sample malware detected on TH-DC-02")
    ctx = build_context(incident, lab.registry, lab.settings, clock=lab.clock, dry_run=False)

    bundle = investigate_endpoint(ctx, host)
    hash_report = enrich_hash(ctx, sha)
    index = RecordIndex([bundle, hash_report])
    detections = [r.record_id for r in bundle.records if r.kind is RecordKind.DETECTION]
    assert detections

    asset = Asset(name=host, kind=TargetKind.ENDPOINT, groups=("Domain Controllers",))
    classes = tuple(ctx.critical_assets.classify(host, TargetKind.ENDPOINT, asset))
    assert CriticalAssetClass.DOMAIN_CONTROLLER in classes
    signals = signals_from_records(bundle.records, observable=Observable(type=ObservableType.HOSTNAME, value=host))
    breakdown = ScoringEngine(lab.settings.thresholds.scoring).score(
        signals, context=ScoringContext(critical_asset_classes=classes, expected_sources=("secure_endpoint",)))
    assert breakdown.risk_score > 0 and breakdown.confidence_score > 0
    for contribution in breakdown.contributions:
        index.require(contribution.record_ids)

    builder = CONTAINMENT_BUILDERS["isolate_secure_endpoint"]
    evidence = EvidenceBuilder(index).cite(detections)
    packages = PackageBuilder(lab.settings, critical_assets=CriticalAssetPolicy(lab.settings.critical_assets),
                              allowlists=AllowlistPolicy(lab.settings.allowlists))
    for risk, confidence in ((breakdown.risk_score, breakdown.confidence_score), (1, 1)):
        built = builder(ctx, host, evidence=evidence, risk_score=risk, confidence_score=confidence,
                        rationale=breakdown.explain(), asset=asset)
        assert built.warnings and built.elevation_expected  # preview only
        package = packages.build(incident, [built.proposal], risk_score=risk, confidence_score=confidence,
                                 summary="integration", dry_run=True)
        action = package.actions[0]
        assert action.approval_level is ApprovalLevel.ELEVATED, "a low score never lowers the approval level"
        assert any(w.message.startswith("WARNING: ELEVATED APPROVAL REQUIRED") for w in action.warnings)
        EvidenceBuilder(index).verify(action.evidence)
    assert lab.environment.state_changing_calls() == []
