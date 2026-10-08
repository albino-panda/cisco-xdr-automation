"""Workflows plugged into the Phase 0 lifecycle (architecture 14.3.6): investigator, recommender,
incident assignment and lifecycle observers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from tests.fixtures.sample_workflows import SAMPLE_PACKAGE, SAMPLE_SCENARIO_DIR
from tests.fixtures.sample_workflows.lab import make_incident
from tools.simulator.scenario import ScenarioRun, load_scenario
from tools.simulator.workflow_scenario import WorkflowScenarioRun, load_workflow_scenario
from xdr_response.lifecycle import InvestigationService, RuleBasedRecommender
from xdr_response.lifecycle.investigation import InvestigationReport
from xdr_response.lifecycle.recommendation import Recommendation
from xdr_response.lifecycle.workflow_adapter import (
    WorkflowInvestigationReport,
    WorkflowInvestigator,
    WorkflowRecommender,
)
from xdr_response.models import AuditEventType, IncidentState
from xdr_response.workflows.discovery import discover_workflows

CATALOG = discover_workflows(SAMPLE_PACKAGE)


def _scenario_run(name: str = "tp-approve-all", *, live: bool = False) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SAMPLE_SCENARIO_DIR / "sample-malware" / f"{name}.yaml"),
                               live=live, catalog=CATALOG)


def test_without_a_catalog_the_runtime_is_phase_0():
    run = ScenarioRun(load_scenario("ransomware"))
    runtime = run.runtime
    assert runtime.workflows is None and runtime.observers == ()
    assert type(runtime.investigator) is InvestigationService
    assert type(runtime.recommender) is RuleBasedRecommender


def test_with_a_catalog_the_workflow_investigator_and_recommender_are_wired():
    runtime = _scenario_run().runtime
    assert runtime.workflows is CATALOG
    assert isinstance(runtime.investigator, WorkflowInvestigator) and runtime.investigator.catalog is CATALOG
    assert isinstance(runtime.recommender, WorkflowRecommender)


def test_open_incident_stores_the_resolved_workflow_id_and_version():
    run = _scenario_run()
    opened = run.orchestrator.open_incident(make_incident(workflow_id="xdr-generic", incident_id="XDR-SM-7001"))
    assert (opened.workflow_id, opened.workflow_version) == ("sample-malware", "1.0.0")
    stored = run.orchestrator.get_incident("XDR-SM-7001")
    assert stored.workflow_id == "sample-malware"
    received = [r for r in run.runtime.audit.records("XDR-SM-7001")
                if r.event_type is AuditEventType.INCIDENT_RECEIVED]
    assert received and (received[0].workflow_id, received[0].workflow_version) == ("sample-malware", "1.0.0")


def test_a_detection_runs_the_workflow_and_audits_its_reads():
    run = _scenario_run()
    detection = run.detect()
    report = detection.investigation
    assert isinstance(report, WorkflowInvestigationReport) and report.run is not None
    assert report.enrichments == report.run.raw_enrichments()
    assert detection.package is not None and detection.package.workflow_id == "sample-malware"
    assert detection.package.workflow_version == "1.0.0"
    assert detection.recommendation.summary.startswith("2 containment action(s) recommended by workflow "
                                                       "sample-malware 1.0.0")
    events = [r.event_type for r in run.runtime.audit.records(run.incident_id)]
    assert events.count(AuditEventType.ENRICHMENT_RESULT) == len(report.enrichments)
    assert events.count(AuditEventType.INVESTIGATION_COMPLETED) == 1
    assert detection.incident.state is IncidentState.AWAITING_APPROVAL
    assert run.environment.state_changing_calls() == []


def test_a_legacy_workflow_not_migrated_takes_the_generic_path_with_a_note():
    run = _scenario_run()
    incident = make_incident(workflow_id="ransomware", incident_id="XDR-SM-7002")
    detection = run.orchestrator.handle_detection(incident)
    assert isinstance(detection.investigation, WorkflowInvestigationReport)
    assert detection.investigation.run is None
    assert "workflow ransomware not migrated yet: Phase 0 generic investigation used" in detection.notes


def test_an_unrouted_incident_takes_the_generic_path_unchanged():
    run = _scenario_run()
    detection = run.orchestrator.handle_detection(
        make_incident(workflow_id="xdr-generic", title="Phishing reported", incident_id="XDR-SM-7003"))
    assert type(detection.investigation) is InvestigationReport


@dataclass
class _Fallback:
    calls: list[str] = field(default_factory=list)

    def run(self, incident: Any) -> InvestigationReport:
        self.calls.append(incident.incident_id)
        return InvestigationReport(incident_id=incident.incident_id)


class _ExplodingRunner:
    def run(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("framework bug with api_key=abcd1234efgh5678")


def test_a_runner_failure_falls_back_to_the_generic_path_with_a_redacted_note():
    fallback = _Fallback()
    investigator = WorkflowInvestigator(CATALOG, _ExplodingRunner(), fallback, audit=None,  # type: ignore[arg-type]
                                        dry_run=lambda: True)
    report = investigator.run(make_incident())
    assert fallback.calls == ["XDR-SM-9001"]
    assert isinstance(report, WorkflowInvestigationReport) and report.run is None
    assert report.notes[0].startswith("workflow sample-malware failed (RuntimeError")
    assert "abcd1234efgh5678" not in report.notes[0]


@dataclass
class _Recommender:
    calls: int = 0

    def recommend(self, incident: Any, investigation: Any) -> Recommendation:
        self.calls += 1
        return Recommendation(incident_id=incident.incident_id, proposals=(), risk_score=0, confidence_score=0,
                              summary="generic", notes=("generic note",))


def test_the_recommender_falls_back_without_a_run_and_keeps_routing_notes():
    fallback = _Recommender()
    recommender = WorkflowRecommender(fallback)
    incident = make_incident()
    plain = recommender.recommend(incident, InvestigationReport(incident_id=incident.incident_id))
    assert plain.summary == "generic" and plain.notes == ("generic note",)
    noted = recommender.recommend(incident, WorkflowInvestigationReport(incident_id=incident.incident_id,
                                                                        notes=("routing note",)))
    assert noted.notes == ("routing note", "generic note") and fallback.calls == 2


def test_the_recommender_maps_a_run():
    run = _scenario_run()
    detection = run.detect()
    recommendation = detection.recommendation
    workflow_run = detection.investigation.run  # type: ignore[attr-defined]
    assert recommendation.proposals == workflow_run.proposals
    assert (recommendation.risk_score, recommendation.confidence_score) == (workflow_run.risk_score,
                                                                            workflow_run.confidence_score)
    assert recommendation.notes == workflow_run.notes and recommendation.unrouted == ()


# -------------------------------------------------------------- observers --
@dataclass
class _Recorder:
    events: list[Any] = field(default_factory=list)

    def on_event(self, event: Any) -> None:
        self.events.append(event)


class _Exploding:
    def on_event(self, event: Any) -> None:
        raise RuntimeError("observer down")


def test_observers_see_every_lifecycle_moment_and_failures_are_swallowed():
    recorder = _Recorder()
    run = ScenarioRun(load_scenario("ransomware"), live=True, observers=(_Exploding(), recorder))
    run.detect()
    run.decide()
    run.propose_release()
    run.decide_release()
    run.orchestrator.close(run.incident_id, actor="analyst.one@example.com", reason="done")
    kinds = [e.kind.value for e in recorder.events]
    assert kinds == ["package_proposed", "decision_recorded", "containment_completed", "release_proposed",
                     "decision_recorded", "restoration_completed", "incident_closed"]
    assert all(e.incident.incident_id == run.incident_id for e in recorder.events)
    assert recorder.events[0].summary is None  # Phase 0 generic path: no workflow summary
    assert recorder.events[2].report is not None and not recorder.events[2].dry_run
    assert all("token" not in type(e).model_fields for e in recorder.events)


def test_a_detection_without_package_emits_detection_completed():
    recorder = _Recorder()
    run = _scenario_run("benign-no-action")
    run.runtime.observers = (*run.runtime.observers, recorder)
    run.detect()
    assert [e.kind.value for e in recorder.events] == ["detection_completed"]
    assert recorder.events[0].summary.workflow_id == "sample-malware" and recorder.events[0].dry_run


def test_dry_run_events_carry_the_workflow_summary():
    recorder = _Recorder()
    run = _scenario_run("tp-approve-all")
    run.runtime.observers = (*run.runtime.observers, recorder)
    run.detect()
    run.decide()
    assert [e.kind.value for e in recorder.events] == ["package_proposed", "decision_recorded"]
    assert all(e.dry_run for e in recorder.events)
    assert recorder.events[0].summary.risk_score == recorder.events[0].package.risk_score


def test_an_observer_without_on_event_is_refused():
    with pytest.raises(TypeError, match="has no on_event"):
        ScenarioRun(load_scenario("ransomware"), observers=(object(),))
