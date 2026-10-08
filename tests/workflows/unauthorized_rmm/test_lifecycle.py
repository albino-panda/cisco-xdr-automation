"""The unauthorized-rmm workflow through the production lifecycle (simulated lab): dry run and simulated live.

The workflow only investigates and recommends: nothing state-changing happens before a human decision,
AI and automation can never approve, approved containment executes and verifies automatically,
restoration needs its own human release approval, and a sanctioned tool (allowlists.approved_rmm) is
never blocked or terminated.
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
from xdr_response.models import ActionResultStatus, ApprovalLevel, IncidentState
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.runner import RuleOutcomeStatus
from xdr_response.workflows.unauthorized_rmm import WORKFLOW

SCENARIOS = WORKFLOW_SCENARIO_DIR / "unauthorized-rmm"
HOST = "TH-LT-1047"
SHA = "a11d35c0" * 8
APPROVED_SHA = "1" * 64
LEGACY = ("01-unapproved-tool-fake-helpdesk", "02-sanctioned-examplermm", "03-guardrail-skips",
          "04-sanctioned-tool-unverified-operator", "05-helpdesk-campaign-blast-radius")


@pytest.fixture(autouse=True)
def _fresh_guard():
    """One runtime per process (the execution guard is sealed): reset around every test."""
    guard._reset_for_test_harness()
    yield
    guard._reset_for_test_harness()


def _paths() -> list[Path]:
    return sorted(SCENARIOS.glob("*.yaml"))


def _run(name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SCENARIOS / f"{name}.yaml"), live=live)


def test_the_scenario_set_meets_the_minimum_and_every_rule_is_proposed_somewhere():
    scenarios = [load_workflow_scenario(p) for p in _paths()]
    proposed: set[str] = set()
    for scenario in scenarios:
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        assert run.workflow_run is not None, scenario.name
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        assert not run.workflow_run.outcomes_with(RuleOutcomeStatus.ERROR), scenario.name
        guard._reset_for_test_harness()
    assert proposed == {r.id for r in WORKFLOW.recommendations}
    assert check_coverage("unauthorized-rmm", scenarios, WORKFLOW, proposed_rules=proposed) == []
    assert len([s for s in scenarios if s.name.startswith("edge-")]) >= 2


def test_every_legacy_scenario_is_migrated_with_its_source():
    sources = {load_workflow_scenario(p).legacy_source for p in _paths() if p.stem.startswith("legacy-")}
    assert sources == {f"workflows/unauthorized-rmm/scenarios/{name}.yaml" for name in LEGACY}
    legacy_dir = SCENARIOS.parents[3] / "workflows" / "unauthorized-rmm"
    assert not (legacy_dir / "workflow.yaml").exists() and not (legacy_dir / "scenarios").exists()
    for path in _paths():
        if path.stem.startswith("legacy-"):
            assert "requires_approval" not in path.read_text(encoding="utf-8")


def test_dry_run_proposes_and_simulates_without_any_state_change():
    run = _run("dry-run", live=False).play()
    package = run.detection.package
    assert package is not None and package.dry_run
    assert package.workflow_id == "unauthorized-rmm" and package.workflow_version == WORKFLOW.version
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
    decision = run.decide()
    report = decision.report
    assert report is not None and not report.dry_run
    statuses = {f"{r.action_type.value}:{r.target}": r.status for r in report.results}
    assert set(statuses) == {f"{a.action_type.value}:{a.target}" for a in package.actions}
    assert set(statuses.values()) == {ActionResultStatus.SUCCESS}
    changed = {c.operation for c in run.environment.state_changing_calls()}
    assert changed == {a.action_type.value for a in package.actions}
    assert all(r.verification is not None for r in report.results)
    assert len(run.runtime.registry.list(incident_id=run.incident_id)) == 5  # terminate registers no control


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


def test_a_help_desk_campaign_over_the_blast_radius_cap_is_elevated_not_split():
    run = _run("legacy-05-helpdesk-campaign-blast-radius", live=False)
    detection = run.detect()
    actions = detection.package.actions
    per_host = [a for a in actions if a.action_type.value in ("isolate_endpoint", "terminate_process")]
    assert len(per_host) == 12 and all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in per_host)
    assert run.environment.state_changing_calls() == []


def test_restoration_needs_its_own_human_release_approval():
    run = _run("release-restoration", live=True)
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert len(controls) == 5
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
    assert workflow_run.degraded_sources() == ("umbrella",)
    assert any("degraded source: umbrella" in note for note in workflow_run.notes)
    assert run.detection.package is not None and len(run.detection.package.actions) == 4
    # the isolation lost its only backing (Umbrella's rating of the peer): shown, never dropped silently
    assert {c.subject for c in workflow_run.considered} >= {f"isolate_endpoint:{HOST}"}
    assert run.check() == []


def test_an_approved_tool_is_never_blocked_or_terminated_but_its_session_is_isolated():
    run = _run("edge-approved-rmm-excluded", live=True).play()
    package = run.detection.package
    assert {f"{a.action_type.value}:{a.target}" for a in package.actions} == {"isolate_endpoint:TH-LT-3105"}
    assert {(e.action_type.value, e.target, e.reason) for e in package.excluded_targets} == {
        ("block_hash", APPROVED_SHA, "allowlists.approved_rmm: Example RMM"),
        ("block_domain", "rmm.example.net", "allowlists.approved_rmm: Example RMM")}
    targets = {c.target for c in run.environment.state_changing_calls()}
    assert APPROVED_SHA not in targets and "rmm.example.net" not in targets
    assert not any(t.startswith("TH-LT-3105/") for t in targets)  # the approved binary keeps running
    assert run.check() == []


def test_a_sanctioned_tool_with_nothing_flagging_it_proposes_nothing():
    for name in ("benign-no-action", "legacy-02-sanctioned-examplermm", "edge-approved-signer-new-build"):
        run = _run(name, live=True).play()
        assert run.detection.package is None, name
        assert run.environment.state_changing_calls() == [], name
        assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.NOT_STARTED, name
        assert run.check() == [], name
        guard._reset_for_test_harness()


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


def test_hand_offs_and_manual_steps_reach_the_run_notes_and_start_nothing():
    run = _run("edge-persistence-handoff", live=True).play()
    notes = run.workflow_run.notes
    assert any(n.startswith("hand-off: run persistence for TH-LT-5120") for n in notes)
    assert any(n.startswith("hand-off: run account-takeover for mlopez@example.com") for n in notes)
    assert any(n.startswith("manual step: uninstall Atera on TH-LT-5120") for n in notes)
    assert {c.operation for c in run.environment.state_changing_calls()} == {"terminate_process"}
    assert run.check() == []


def test_the_catalog_runs_this_workflow_for_its_incidents():
    catalog = discover_workflows()
    run = _run("legacy-01-unapproved-tool-fake-helpdesk", live=False)
    assert catalog.resolve(run.workflow_scenario.incident).definition.id == "unauthorized-rmm"
