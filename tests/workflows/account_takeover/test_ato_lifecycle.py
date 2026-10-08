"""Account takeover through the production lifecycle (orchestrator, approval, execution, verification).

Dry run and simulated live, on the simulated lab: investigation and recommendation are automatic and
write nothing; only an authenticated human decision executes; verification is automatic; a release is
a separate human decision; AI and automation principals can never approve.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.simulator.workflow_scenario import WorkflowScenarioRun, load_workflow_scenario
from xdr_response.errors import ApprovalError, ApproverNotAllowedError
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    ApprovalLevel,
    AuditEventType,
    ContainmentOverall,
    IncidentState,
    VerificationStatus,
)
from xdr_response.workflows.account_takeover import WORKFLOW

SCENARIOS = Path(__file__).resolve().parents[2] / "fixtures" / "workflows" / "account-takeover"
USER = "jsmith@example.com"


def _run(name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SCENARIOS / f"{name}.yaml"), live=live)


def _approve_all(run: WorkflowScenarioRun, *approvers: str):
    package = run.orchestrator.latest_package(run.incident_id)
    return run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                            run.credentials(*approvers))


@pytest.mark.parametrize("live", [False, True])
def test_detection_is_automatic_and_writes_nothing(live):
    run = _run("tp-approve-all", live=live)
    detection = run.detect()
    package = detection.package
    assert package is not None
    assert package.workflow_id == WORKFLOW.id and package.workflow_version == WORKFLOW.version
    assert package.dry_run is (not live)
    assert {a.action_type for a in package.actions} == {ActionType.REVOKE_SESSIONS, ActionType.ISOLATE_ENDPOINT,
                                                       ActionType.BLOCK_IP}
    assert all(a.evidence for a in package.actions)
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL


@pytest.mark.parametrize("alias", ["ai", "automation"])
def test_ai_and_automation_can_never_approve(alias):
    run = _run("tp-approve-all", live=True)
    run.detect()
    with pytest.raises(ApprovalError):
        _approve_all(run, alias)
    assert run.environment.state_changing_calls() == []


def test_dry_run_approval_simulates_and_executes_nothing():
    run = _run("dry-run", live=False)
    run.detect()
    result = _approve_all(run, "analyst")
    assert result.report is not None and result.report.dry_run
    assert {r.status for r in result.report.results} == {ActionResultStatus.DRY_RUN}
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []


def test_live_approval_executes_and_verifies_automatically():
    run = _run("tp-approve-all", live=True)
    run.detect()
    result = _approve_all(run, "analyst")
    report = result.report
    assert report is not None and not report.dry_run and report.overall is ContainmentOverall.CONTAINED
    by_type = {r.action_type: r for r in report.results}
    assert by_type[ActionType.REVOKE_SESSIONS].status is ActionResultStatus.SUCCESS
    for result_ in report.results:
        assert result_.verification is not None
        assert result_.verification.status is VerificationStatus.VERIFIED
    assert not by_type[ActionType.REVOKE_SESSIONS].control_registered, "session revocation is not reversible"
    controls = {(c.action_type, c.target) for c in run.runtime.registry.list(incident_id=run.incident_id)}
    assert controls == {(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047"), (ActionType.BLOCK_IP, "203.0.113.145")}
    events = [r.event_type for r in run.runtime.audit.records(run.incident_id)]
    assert AuditEventType.GUARD_DENIED not in events
    assert run.runtime.audit.verify().ok


def test_restoration_needs_its_own_human_release_decision():
    run = _run("release-restoration", live=True)
    run.detect()
    _approve_all(run, "analyst")
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert {c.action_type for c in controls} == {ActionType.DISABLE_USER, ActionType.BLOCK_IP}
    calls_after_containment = len(run.environment.state_changing_calls())
    release = run.propose_release()
    assert {a.action_type for a in release.actions} == {ActionType.ENABLE_USER, ActionType.UNBLOCK_IP}
    assert len(run.environment.state_changing_calls()) == calls_after_containment, "proposing restores nothing"
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["automation"])
    run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.RESTORED


def test_a_privileged_account_needs_an_elevated_approver():
    run = _run("critical-asset-elevated", live=True)
    package = run.detect().package
    elevated = {a.action_type for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED}
    assert elevated == {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER}
    assert all(a.warnings for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED)
    with pytest.raises(ApproverNotAllowedError):
        _approve_all(run, "analyst")
    assert run.environment.state_changing_calls() == []
    result = _approve_all(run, "lead")
    assert result.report is not None and result.report.overall is ContainmentOverall.CONTAINED


def test_a_rejection_closes_the_incident_without_any_change():
    run = _run("tp-reject", live=True)
    run.play()
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CLOSED
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []


def test_a_benign_sign_in_proposes_no_package():
    run = _run("benign-no-action", live=True)
    detection = run.detect()
    assert detection.package is None
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.NOT_STARTED
    assert run.environment.state_changing_calls() == []
