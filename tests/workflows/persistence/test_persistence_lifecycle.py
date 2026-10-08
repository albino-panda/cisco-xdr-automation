"""The persistence workflow through the production lifecycle (simulated lab): dry run and simulated live.

The workflow only investigates and recommends: nothing state-changing happens before a human
decision, AI and automation can never approve, approved containment executes and verifies
automatically, restoration needs its own human release approval, and removing a persistence item
is never automated (a manual step with records, outside the package).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.simulator.workflow_scenario import (
    WORKFLOW_SCENARIO_DIR,
    WorkflowScenarioRun,
    check_coverage,
    load_workflow_scenario,
)
from xdr_response import guard
from xdr_response.errors import ApprovalError, ApproverNotAllowedError
from xdr_response.models import ActionResultStatus, ActionType, ApprovalLevel, IncidentState
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.persistence import WORKFLOW
from xdr_response.workflows.runner import RuleOutcomeStatus

SCENARIOS = WORKFLOW_SCENARIO_DIR / "persistence"
SHA = "0dd5a1e5" * 8
LEGACY = ("01-malicious-run-key", "02-legit-updater-service", "03-allowlisted-hash-protected-host",
          "04-dormant-scheduled-task", "05-fleet-wide-service")


def _paths() -> list[Path]:
    return sorted(SCENARIOS.glob("*.yaml"))


def _run(name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SCENARIOS / f"{name}.yaml"), live=live)


@pytest.fixture(autouse=True)
def _fresh_guard():
    """One runtime per process: reset the guard around every test of this module."""
    guard._reset_for_test_harness()
    yield
    guard._reset_for_test_harness()


def test_the_scenario_set_meets_the_minimum_and_every_rule_is_proposed_somewhere():
    scenarios = [load_workflow_scenario(p) for p in _paths()]
    proposed: set[str] = set()
    for scenario in scenarios:
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        assert run.workflow_run is not None, scenario.name
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        assert not run.workflow_run.outcomes_with(RuleOutcomeStatus.ERROR), scenario.name
        assert all(p.action_type is not ActionType.REMOVE_PERSISTENCE for p in run.workflow_run.proposals)
        guard._reset_for_test_harness()  # one runtime per process: reset between the runs of this test
    assert proposed == {r.id for r in WORKFLOW.recommendations}
    assert check_coverage("persistence", scenarios, WORKFLOW, proposed_rules=proposed) == []


def test_every_legacy_scenario_is_migrated_with_its_source():
    sources = {load_workflow_scenario(p).legacy_source for p in _paths() if p.stem.startswith("legacy-")}
    assert sources == {f"workflows/persistence/scenarios/{name}.yaml" for name in LEGACY}
    assert not (SCENARIOS.parents[3] / "workflows" / "persistence" / "workflow.yaml").exists()


def test_dry_run_proposes_and_simulates_without_any_state_change():
    run = _run("dry-run", live=False).play()
    package = run.detection.package
    assert package is not None and package.dry_run
    assert package.workflow_id == "persistence" and package.workflow_version == WORKFLOW.version
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.check() == [] and run.implicit_problems() == []


def test_live_nothing_changes_before_the_human_decision_then_approved_actions_execute_and_verify():
    run = _run("tp-approve-all", live=True)
    detection = run.detect()
    assert run.environment.state_changing_calls() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL
    package = detection.package
    assert all(a.approval_level is ApprovalLevel.STANDARD for a in package.actions)
    assert all(a.evidence and a.rationale for a in package.actions)
    assert {a.action_type for a in package.actions} == {ActionType.ISOLATE_ENDPOINT, ActionType.TERMINATE_PROCESS,
                                                        ActionType.BLOCK_HASH}
    decision = run.decide()
    report = decision.report
    assert report is not None and not report.dry_run
    statuses = {f"{r.action_type.value}:{r.target}": r.status for r in report.results}
    assert set(statuses) == {f"{a.action_type.value}:{a.target}" for a in package.actions}
    assert set(statuses.values()) == {ActionResultStatus.SUCCESS}
    changed = {(c.operation, c.target) for c in run.environment.state_changing_calls()}
    assert {op for op, _ in changed} == {a.action_type.value for a in package.actions}
    assert "remove_persistence" not in {op for op, _ in changed}  # removal is a manual step, never executed
    assert all(r.verification is not None for r in report.results)
    assert len(run.runtime.registry.list(incident_id=run.incident_id)) == 2  # terminate registers no control


def test_the_manual_removal_step_reaches_the_notes_and_the_analyst_summary():
    run = _run("tp-approve-all", live=False)
    detection = run.detect()
    subject = "remove_persistence:TH-LT-1047/run-onedrivesync"
    assert any(n.startswith(f"manual step: {subject}") for n in detection.notes)
    summary = run.workflow_run.summary()
    assert any(step.startswith(subject) for step in summary.manual_steps)
    assert all(a.action_type is not ActionType.REMOVE_PERSISTENCE for a in detection.package.actions)


@pytest.mark.parametrize("alias", ["ai", "automation"])
def test_ai_and_automation_can_never_approve_containment(alias: str):
    run = _run("tp-approve-all", live=True)
    run.detect()
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=[alias])
    assert run.environment.state_changing_calls() == []


def test_a_critical_asset_needs_the_lead_and_an_analyst_alone_is_refused():
    run = _run("critical-asset-elevated", live=True)
    detection = run.detect()
    elevated = [a for a in detection.package.actions if a.approval_level is ApprovalLevel.ELEVATED]
    assert {a.action_type.value for a in elevated} == {"isolate_endpoint", "terminate_process"}
    assert all(a.warnings for a in elevated)
    with pytest.raises(ApproverNotAllowedError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert run.environment.state_changing_calls() == []
    decision = run.decide({"decision": "APPROVE_ALL"}, approvers=["lead"])
    assert decision.report is not None and decision.report.overall.value == "CONTAINED"


def test_a_fleet_wide_service_is_elevated_by_the_blast_radius():
    run = _run("legacy-05-fleet-wide-service", live=False)
    detection = run.detect()
    isolations = [a for a in detection.package.actions if a.action_type is ActionType.ISOLATE_ENDPOINT]
    assert len(isolations) == 6 and all(a.approval_level is ApprovalLevel.ELEVATED for a in isolations)
    block = next(a for a in detection.package.actions if a.action_type is ActionType.BLOCK_HASH)
    assert block.approval_level is ApprovalLevel.STANDARD


def test_restoration_needs_its_own_human_release_approval():
    run = _run("release-restoration", live=True)
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert len(controls) == 2
    calls = len(run.environment.state_changing_calls())
    run.propose_release()
    assert len(run.environment.state_changing_calls()) == calls  # proposing a release changes nothing
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["ai"])
    assert len(run.environment.state_changing_calls()) == calls
    result = run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert result.report is not None and result.report.overall.value == "RESTORED"
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.RESTORED


def test_rejected_package_closes_without_any_control():
    run = _run("tp-reject", live=True).play()
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CLOSED


def test_a_degraded_source_does_not_block_the_recommendation():
    run = _run("degraded-source", live=False).play()
    workflow_run = run.workflow_run
    assert workflow_run.degraded_sources() == ("virustotal",)
    assert any("degraded source: virustotal" in note for note in workflow_run.notes)
    assert run.detection.package is not None and len(run.detection.package.actions) == 3
    assert run.check() == []


def test_a_missing_required_integration_is_noted_and_does_not_block():
    run = _run("edge-defender-wmi-subscription", live=False)
    detection = run.detect()
    assert any("required integration secure_endpoint is not enabled" in n for n in run.workflow_run.notes)
    assert detection.package is not None and len(detection.package.actions) == 3


def test_dry_run_and_live_score_and_propose_identically():
    dry = _run("tp-approve-all", live=False)
    dry.detect()
    dry_view = [(p.action_type, p.target, p.risk_score, p.confidence_score) for p in dry.workflow_run.proposals]
    guard._reset_for_test_harness()
    live = _run("tp-approve-all", live=True)
    live.detect()
    live_view = [(p.action_type, p.target, p.risk_score, p.confidence_score) for p in live.workflow_run.proposals]
    assert dry_view == live_view


def test_package_evidence_is_numbered_and_cites_real_records():
    run = _run("tp-approve-all", live=False)
    detection = run.detect()
    index = run.workflow_run.index
    number_of: dict[str, int] = {}
    for action in detection.package.actions:
        assert action.evidence
        for item in action.evidence:
            assert item.number >= 1 and item.data["record_id"] in index
            assert number_of.setdefault(item.data["record_id"], item.number) == item.number
        assert type(action.risk_score) is int and type(action.confidence_score) is int
    assert type(detection.package.risk_score) is int and type(detection.package.confidence_score) is int


def test_the_catalog_runs_this_workflow_for_its_incidents():
    catalog = discover_workflows()
    run = _run("legacy-01-malicious-run-key", live=False)
    assert catalog.resolve(run.workflow_scenario.incident).definition.id == "persistence"
