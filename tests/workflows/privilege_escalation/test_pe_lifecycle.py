"""Privilege escalation through the production lifecycle (orchestrator, approval, execution, verification).

Dry run and simulated live, on the simulated lab: investigation and recommendation are automatic and
write nothing; only an authenticated human decision executes; verification is automatic; a release is
a separate human decision; AI and automation principals can never approve; role removal and its
restoration always need an ELEVATED approver; an account an anomalous change made privileged is never
shielded by that privilege (its actions stay proposed and ELEVATED); manual steps never reach the package.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.simulator.workflow_scenario import WorkflowScenarioRun, load_workflow_scenario
from xdr_response.integrations.simulated import production_manifest
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
from xdr_response.workflows.privilege_escalation import WORKFLOW

SCENARIOS = Path(__file__).resolve().parents[2] / "fixtures" / "workflows" / "privilege-escalation"
ACTOR = "jsmith@example.com"
STAGED = "svc-sync-temp@example.com"
ROLE_TARGET = f"{STAGED}/00000000-0000-4000-8000-0000000000a1"
HOST = "TH-LT-1047"
#: Action types with no VERIFIED write: never in a privilege-escalation package (manual steps instead).
MANUAL_ONLY = {ActionType.REVOKE_APP_CREDENTIALS, ActionType.REMOVE_APPLICATION, ActionType.RESET_PASSWORD,
               ActionType.REMOVE_PERSISTENCE, ActionType.CONFIRM_USER_COMPROMISED}


def _readback(result) -> VerificationStatus:
    """VERIFIED where the real adapter reads the action back, else UNABLE_TO_VERIFY (architecture 14.14.3:
    the simulated adapters do only what the real ones support and verify)."""
    real = production_manifest(result.integration)
    return (VerificationStatus.VERIFIED if real is not None and result.action_type in real.verifiable_actions
            else VerificationStatus.UNABLE_TO_VERIFY)


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
    assert {(a.action_type, a.target) for a in package.actions} == {
        (ActionType.ISOLATE_ENDPOINT, HOST), (ActionType.REVOKE_SESSIONS, ACTOR), (ActionType.REVOKE_SESSIONS, STAGED),
        (ActionType.DISABLE_USER, STAGED), (ActionType.REMOVE_PRIVILEGED_ROLE, ROLE_TARGET)}
    for action in package.actions:
        assert action.evidence and [e.number for e in action.evidence] == sorted(e.number for e in action.evidence)
        assert type(action.risk_score) is int and type(action.confidence_score) is int
    assert not {a.action_type for a in package.actions} & MANUAL_ONLY
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


def test_role_removal_and_the_staged_account_need_an_elevated_approver():
    run = _run("tp-approve-all", live=True)
    package = run.detect().package
    levels = {(a.action_type, a.target): a.approval_level for a in package.actions}
    assert levels[(ActionType.REMOVE_PRIVILEGED_ROLE, ROLE_TARGET)] is ApprovalLevel.ELEVATED
    assert levels[(ActionType.DISABLE_USER, STAGED)] is ApprovalLevel.ELEVATED
    assert levels[(ActionType.REVOKE_SESSIONS, STAGED)] is ApprovalLevel.ELEVATED
    assert levels[(ActionType.ISOLATE_ENDPOINT, HOST)] is ApprovalLevel.STANDARD
    assert all(a.warnings for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED)
    with pytest.raises(ApproverNotAllowedError):
        _approve_all(run, "analyst")
    assert run.environment.state_changing_calls() == []


def test_dry_run_approval_simulates_and_executes_nothing():
    run = _run("dry-run", live=False)
    run.detect()
    result = _approve_all(run, "lead")
    assert result.report is not None and result.report.dry_run
    assert {r.status for r in result.report.results} == {ActionResultStatus.DRY_RUN}
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []


def test_live_approval_executes_and_verifies_automatically():
    run = _run("tp-approve-all", live=True)
    run.detect()
    result = _approve_all(run, "lead")
    report = result.report
    assert report is not None and not report.dry_run and report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    for result_ in report.results:
        assert result_.status is ActionResultStatus.SUCCESS
        assert result_.verification is not None
        assert result_.verification.status is _readback(result_)
    by_key = {(r.action_type, r.target): r for r in report.results}
    assert not by_key[(ActionType.REVOKE_SESSIONS, ACTOR)].control_registered, "revocation is not reversible"
    controls = {(c.action_type, c.target) for c in run.runtime.registry.list(incident_id=run.incident_id)}
    assert controls == {(ActionType.ISOLATE_ENDPOINT, HOST), (ActionType.DISABLE_USER, STAGED),
                        (ActionType.REMOVE_PRIVILEGED_ROLE, ROLE_TARGET)}
    events = [r.event_type for r in run.runtime.audit.records(run.incident_id)]
    assert AuditEventType.GUARD_DENIED not in events
    assert run.runtime.audit.verify().ok


def test_restoration_needs_its_own_elevated_human_release_decision():
    run = _run("release-restoration", live=True)
    run.detect()
    _approve_all(run, "lead")
    calls_after_containment = len(run.environment.state_changing_calls())
    release = run.propose_release()
    assert {a.action_type for a in release.actions} == {ActionType.RELEASE_ENDPOINT, ActionType.ENABLE_USER,
                                                       ActionType.RESTORE_PRIVILEGED_ROLE}
    assert len(run.environment.state_changing_calls()) == calls_after_containment, "proposing restores nothing"
    restore = next(a for a in release.actions if a.action_type is ActionType.RESTORE_PRIVILEGED_ROLE)
    assert restore.approval_level is ApprovalLevel.ELEVATED
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["automation"])
    with pytest.raises(ApproverNotAllowedError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    run.decide_release({"decision": "APPROVE_ALL"}, approvers=["lead"])
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_RELEASE_APPROVAL


@pytest.mark.parametrize("name", ["edge-protected-group-self-add", "legacy-04-elevated-into-protected-group"])
def test_an_attacker_added_protected_group_member_is_never_shielded(name):
    """The protected group the attacker joined makes the account's actions ELEVATED; it never drops them."""
    run = _run(name, live=True)
    detection = run.detect()
    package = detection.package
    account = {a.action_type: a for a in package.actions if a.action_type in (ActionType.REVOKE_SESSIONS,
                                                                                ActionType.DISABLE_USER)}
    assert set(account) == {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER}
    assert all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in account.values())
    assert any("manual step: remove-group-membership:" in n for n in detection.notes)
    with pytest.raises(ApproverNotAllowedError):
        _approve_all(run, "analyst")
    result = _approve_all(run, "lead")
    assert result.report is not None and result.report.overall is ContainmentOverall.PARTIALLY_CONTAINED


def test_manual_steps_and_handoffs_are_notes_never_actions():
    run = _run("edge-service-principal-permissions", live=True)
    detection = run.detect()
    notes = "\n".join(detection.notes)
    assert "manual step: revoke-app-permissions:" in notes
    assert "hand-off: run account-takeover for opscloud@example.com" in notes
    assert "nothing is started" in notes
    targets = {a.target for a in detection.package.actions}
    assert not any(t.startswith("00000000-0000-4000-8000-0000000c") for t in targets), "no app is a target"


def test_a_rejection_closes_the_incident_without_any_change():
    run = _run("tp-reject", live=True)
    run.play()
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CLOSED
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []


def test_a_failed_removal_is_reported_and_the_rest_stands():
    run = _run("partial-failure", live=True)
    run.detect()
    report = _approve_all(run, "lead").report
    assert report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    statuses = {r.action_type: r.status for r in report.results if r.target in (ROLE_TARGET, HOST)}
    assert statuses == {ActionType.REMOVE_PRIVILEGED_ROLE: ActionResultStatus.FAILED,
                        ActionType.ISOLATE_ENDPOINT: ActionResultStatus.SUCCESS}


@pytest.mark.parametrize("name", ["benign-no-action", "edge-pim-activation-normal",
                                  "legacy-02-approved-change-window"])
def test_no_package_for_a_normal_change(name):
    run = _run(name, live=True)
    detection = run.detect()
    assert detection.package is None
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.NOT_STARTED
    assert run.environment.state_changing_calls() == []
    assert any("considered, not proposed: remove_privileged_role:" in n for n in detection.notes)


def test_a_degraded_endpoint_source_never_blocks_the_identity_package():
    run = _run("degraded-source", live=True)
    detection = run.detect()
    assert detection.package is not None
    assert {a.action_type for a in detection.package.actions} == {
        ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER, ActionType.REMOVE_PRIVILEGED_ROLE}
    assert run.workflow_run is not None and run.workflow_run.degraded_sources() == ("secure_endpoint",)
