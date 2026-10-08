"""mfa-fatigue through the production lifecycle on the simulated lab (dry run and simulated live).

Investigation and recommendation are automatic and read-only; every action waits for a human
approval; AI and automation can never approve; approved containment executes and verifies; release
needs its own human decision. All data is fake.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.simulator.workflow_scenario import WorkflowScenario, WorkflowScenarioRun, load_workflow_scenario
from xdr_response.atomics.evidence import EvidenceBuilder
from xdr_response.errors import ApprovalError
from xdr_response.models import ActionType, ApprovalLevel, IncidentState
from xdr_response.workflows.runner import RuleOutcomeStatus

SCENARIOS = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "workflows" / "mfa-fatigue"


def scenario(name: str, **update) -> WorkflowScenario:
    loaded = load_workflow_scenario(SCENARIOS / f"{name}.yaml")
    return loaded.model_copy(update=update) if update else loaded


def detect(name: str, *, live: bool = False, **update) -> WorkflowScenarioRun:
    run = WorkflowScenarioRun(scenario(name, **update), live=live)
    run.detect()
    return run


def test_detection_is_read_only_and_waits_for_a_human():
    run = detect("tp-approve-all", live=True)
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL
    package = run.detection.package
    assert {a.action_type for a in package.actions} == {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER,
                                                         ActionType.ISOLATE_ENDPOINT, ActionType.BLOCK_IP}
    assert all(a.approval_level in (ApprovalLevel.STANDARD, ApprovalLevel.ELEVATED) for a in package.actions)


def test_every_action_carries_numbered_evidence_from_the_run_and_separate_scores():
    run = detect("tp-approve-all")
    workflow_run = run.workflow_run
    EvidenceBuilder(workflow_run.index).verify([e for p in workflow_run.proposals for e in p.evidence])
    for action in run.detection.package.actions:
        numbers = [e.number for e in action.evidence]
        assert numbers == sorted(set(numbers)) and numbers[0] >= 1  # package-wide numbering
        assert all(e.data["record_id"] in workflow_run.index for e in action.evidence)
        assert isinstance(action.risk_score, int) and isinstance(action.confidence_score, int)
    revoke = next(a for a in run.detection.package.actions if a.action_type is ActionType.REVOKE_SESSIONS)
    kinds = {e.data["kind"] for e in revoke.evidence}
    assert {"mfa_event", "sign_in"} <= kinds
    assert "MFA fatigue against jsmith@example.com" in revoke.rationale


def test_revoke_sessions_needs_approval_like_every_other_action():
    run = detect("tp-reject", live=True)
    run.decide()
    assert run.environment.state_changing_calls() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CLOSED


@pytest.mark.parametrize("alias", ["ai", "automation"])
def test_ai_and_automation_can_never_approve(alias: str):
    run = detect("tp-approve-all", live=True)
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=[alias])
    assert run.environment.state_changing_calls() == []


def test_approved_containment_executes_and_verifies_automatically():
    run = WorkflowScenarioRun(scenario("tp-approve-all"), live=True).play()
    report = run.decision.report
    assert report.overall.value == "CONTAINED"
    assert {r.verification.status.value for r in report.results} == {"VERIFIED"}
    assert len(run.environment.state_changing_calls()) == 4


def test_release_needs_its_own_human_decision():
    run = detect("release-restoration", live=True)
    run.decide()
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CONTAINED
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert {c.action_type for c in controls} == {ActionType.DISABLE_USER, ActionType.BLOCK_IP}
    run.propose_release()
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["automation"])
    run.decide_release()
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.RESTORED


def test_a_privileged_target_is_elevated_and_an_analyst_alone_is_refused():
    run = detect("critical-asset-elevated", live=True)
    elevated = {a.action_type for a in run.detection.package.actions if a.approval_level is ApprovalLevel.ELEVATED}
    assert elevated == {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER}
    assert all(a.warnings for a in run.detection.package.actions if a.approval_level is ApprovalLevel.ELEVATED)
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    run.decide({"decision": "APPROVE_ALL"}, approvers=["lead"])
    assert run.decision.report.overall.value == "CONTAINED"


@pytest.mark.parametrize("live", [False, True])
def test_dry_run_and_live_score_identically(live: bool):
    # one runtime per process (the execution guard is sealed), so each mode is its own test
    run = detect("tp-approve-all", live=live)
    assert (run.workflow_run.risk_score, run.workflow_run.confidence_score) == (80, 75)
    assert run.detection.package.dry_run is (not live)


def test_dry_run_changes_nothing_even_after_approval():
    dry = detect("tp-approve-all")
    dry.decide()
    assert dry.environment.state_changing_calls() == []
    assert dry.runtime.registry.list() == []


def test_a_failed_identity_source_degrades_without_crashing():
    environment = scenario("tp-approve-all").environment.model_copy(update={"faults": (
        {"kind": "UNAVAILABLE", "integration": "entra", "operation": "investigate", "times": 20},)})
    run = WorkflowScenarioRun(scenario("tp-approve-all", environment=environment), live=False)
    run.detect()
    assert "entra" in run.workflow_run.degraded_sources()
    assert run.workflow_run.outcomes_with(RuleOutcomeStatus.ERROR) == ()
    assert run.environment.state_changing_calls() == []
    # without the identity evidence there is no compromise to act on: nothing is invented
    actions = {a.action_type for a in run.detection.package.actions} if run.detection.package else set()
    assert ActionType.REVOKE_SESSIONS not in actions


def test_prompts_only_is_considered_and_reported_never_hidden():
    run = detect("edge-prompts-only")
    assert run.detection.package is None
    below = run.workflow_run.outcomes_with(RuleOutcomeStatus.BELOW_THRESHOLD)
    assert [o.selector for o in below] == ["block_ip:203.0.113.81"]
    assert any("below threshold" in n for n in run.workflow_run.notes)
