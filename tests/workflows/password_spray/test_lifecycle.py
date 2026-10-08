"""The password-spray workflow through the production lifecycle (orchestrator) on the simulated lab.

Dry run and simulated live: investigation and recommendation are automatic and change nothing;
only a human approval lets the approved containment execute (then it verifies automatically);
restoration needs a separate human release approval; AI and automation never approve.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.simulator.workflow_scenario import (
    WORKFLOW_SCENARIO_DIR,
    WorkflowScenario,
    WorkflowScenarioRun,
    check_coverage,
    load_workflow_scenario,
)
from xdr_response import guard
from xdr_response.errors import ApprovalError
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    ApprovalLevel,
    AuditEventType,
    ContainmentOverall,
    IncidentState,
    RestorationOverall,
    VerificationStatus,
)
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.password_spray import WORKFLOW
from xdr_response.workflows.runner import RuleOutcomeStatus

SCENARIOS = WORKFLOW_SCENARIO_DIR / "password-spray"
SPRAY = "198.51.100.77"
USER = "jsmith@example.com"


def _scenario(name: str) -> WorkflowScenario:
    return load_workflow_scenario(SCENARIOS / f"{name}.yaml")


def _selectors(package) -> set[str]:
    return {f"{a.action_type.value}:{a.target}" for a in package.actions}


def test_dry_run_proposes_the_package_and_changes_nothing():
    run = WorkflowScenarioRun(_scenario("tp-approve-all"), live=False).play()
    package = run.detection.package
    assert package is not None and package.dry_run
    assert _selectors(package) == {f"block_ip:{SPRAY}", f"revoke_sessions:{USER}", f"disable_user:{USER}"}
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    lines = {r.dry_run_line for r in run.detection.dry_run_report.results}
    assert lines == {f"Would block: {SPRAY}", f"Would revoke sessions: {USER}", f"Would disable user: {USER}"}
    assert package.workflow_id == "password-spray" and package.workflow_version == WORKFLOW.version


def test_live_execution_needs_a_human_and_verifies_automatically():
    run = WorkflowScenarioRun(_scenario("tp-approve-all"), live=True)
    detection = run.detect()
    package = detection.package
    assert package is not None and not package.dry_run
    assert run.environment.state_changing_calls() == []  # investigation and recommendation never write
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.decide({"decision": "APPROVE_ALL"}, approvers=[alias])
    assert run.environment.state_changing_calls() == []
    decision = run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    report = decision.report
    assert report is not None and report.overall is ContainmentOverall.CONTAINED
    for result in report.results:
        assert result.status is ActionResultStatus.SUCCESS
        assert result.verification is not None and result.verification.status is VerificationStatus.VERIFIED
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    # session revocation is not reversible, so only the block and the disable are temporary controls
    assert sorted(c.action_type.value for c in controls) == ["block_ip", "disable_user"]
    events = [r.event_type for r in run.runtime.audit.records(run.incident_id)]
    assert events.index(AuditEventType.PACKAGE_PROPOSED) < events.index(AuditEventType.ACTION_STARTED)
    assert run.runtime.audit.verify().ok


def test_restoration_needs_its_own_release_approval():
    run = WorkflowScenarioRun(_scenario("release-restoration"), live=True)
    run.detect()
    run.decide()
    before = len(run.environment.state_changing_calls())
    release = run.propose_release()
    assert len(run.environment.state_changing_calls()) == before  # proposing a release changes nothing
    assert {a.action_type for a in release.actions} == {ActionType.UNBLOCK_IP, ActionType.ENABLE_USER}
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["automation"])
    result = run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert result.report is not None and result.report.overall is RestorationOverall.RESTORED


def test_privileged_account_actions_are_elevated_and_an_analyst_alone_cannot_approve():
    run = WorkflowScenarioRun(_scenario("critical-asset-elevated"), live=True)
    package = run.detect().package
    elevated = {f"{a.action_type.value}:{a.target}" for a in package.actions
                if a.approval_level is ApprovalLevel.ELEVATED}
    assert elevated == {"revoke_sessions:adm-tgreen@example.com", "disable_user:adm-tgreen@example.com"}
    assert all(a.warnings for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED)
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert run.environment.state_changing_calls() == []
    assert run.decide({"decision": "APPROVE_ALL"}, approvers=["lead"]).report.overall is ContainmentOverall.CONTAINED


def test_a_failed_identity_source_does_not_block_the_ip_block():
    scenario = _scenario("tp-approve-all")
    faults = ({"kind": "UNAVAILABLE", "integration": "entra", "operation": "investigate", "times": 50},)
    degraded = scenario.model_copy(update={
        "environment": scenario.environment.model_copy(update={"faults": faults}),
        "expect": scenario.expect.model_copy(update={"evidence_min": 1})})
    run = WorkflowScenarioRun(degraded, live=False).play()
    assert _selectors(run.detection.package) == {f"block_ip:{SPRAY}"}  # reputation still backs the block
    assert "entra" in run.workflow_run.degraded_sources()
    assert any("degraded source: entra" in note for note in run.workflow_run.notes)
    assert run.implicit_problems() == []


def test_dry_run_and_live_score_identically():
    scores = []
    for live in (False, True):
        guard._reset_for_test_harness()  # one runtime per process
        run = WorkflowScenarioRun(_scenario("tp-approve-all"), live=live)
        run.detect()
        scores.append((run.workflow_run.risk_score, run.workflow_run.confidence_score,
                       {(o.rule_id, o.target, o.risk_score, o.confidence_score) for o in run.workflow_run.outcomes}))
    assert scores[0] == scores[1]


def test_every_rule_is_proposed_somewhere_and_the_minimum_set_is_met():
    paths = sorted(Path(SCENARIOS).glob("*.yaml"))
    scenarios = [load_workflow_scenario(p) for p in paths]
    proposed: set[str] = set()
    for scenario in scenarios:
        guard._reset_for_test_harness()  # one runtime per process
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
    definition = discover_workflows().get("password-spray").definition
    assert check_coverage("password-spray", scenarios, definition, proposed_rules=proposed) == []
    assert proposed == {r.id for r in WORKFLOW.recommendations}
    assert sum(1 for s in scenarios if "legacy" in s.tags) == 6
