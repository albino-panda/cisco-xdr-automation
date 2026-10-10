"""Business email compromise through the production lifecycle (orchestrator, approval, execution,
verification, release), dry run and simulated live, on the simulated lab (no network, fake data).

Investigation and recommendation are automatic and write nothing; only an authenticated human
decision executes; verification is automatic; restoration is a separate human release decision; AI
and automation principals can never approve; a critical mailbox needs the lead.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.simulator.workflow_scenario import WorkflowScenarioRun, check_coverage, load_workflow_scenario
from tools.simulator.workflow_scenario import executable_anywhere
from xdr_response.integrations.simulated import production_manifest
from xdr_response import guard
from xdr_response.errors import ApprovalError, ApproverNotAllowedError
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
from xdr_response.workflows.bec import WORKFLOW
from xdr_response.workflows.runner import RuleOutcomeStatus

SCENARIOS = Path(__file__).resolve().parents[2] / "fixtures" / "workflows" / "bec"
USER = "jsmith@example.com"


def _readback(result) -> VerificationStatus:
    """VERIFIED where the real adapter reads the action back, else UNABLE_TO_VERIFY (architecture 14.14.3:
    the simulated adapters do only what the real ones support and verify)."""
    real = production_manifest(result.integration)
    return (VerificationStatus.VERIFIED if real is not None and result.action_type in real.verifiable_actions
            else VerificationStatus.UNABLE_TO_VERIFY)


def _run(name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SCENARIOS / f"{name}.yaml"), live=live)


def _approve_all(run: WorkflowScenarioRun, *approvers: str):
    return run.decide({"decision": "APPROVE_ALL"}, approvers=list(approvers))


def test_minimum_scenario_set_and_every_rule_proposed_somewhere():
    scenarios = [load_workflow_scenario(p) for p in sorted(SCENARIOS.glob("*.yaml"))]
    proposed: set[str] = set()
    unrouted: set[str] = set()
    for scenario in scenarios:
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        assert run.workflow_run is not None, scenario.name
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        unrouted |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)}
        guard._reset_for_test_harness()  # one runtime per process: reset between the runs of this test
    assert check_coverage("bec", scenarios, WORKFLOW, proposed_rules=proposed, unrouted_rules=unrouted) == []
    assert proposed | (unrouted & {r.id for r in WORKFLOW.recommendations
                                if not executable_anywhere(r.action)}) == {r.id for r in WORKFLOW.recommendations}


@pytest.mark.parametrize("live", [False, True])
def test_detection_is_automatic_and_writes_nothing(live):
    run = _run("tp-approve-all", live=live)
    package = run.detect().package
    assert package is not None
    assert (package.workflow_id, package.workflow_version) == (WORKFLOW.id, WORKFLOW.version)
    assert package.dry_run is (not live)
    assert {a.action_type for a in package.actions} == {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER,
                                                       ActionType.QUARANTINE_EMAIL, ActionType.ISOLATE_ENDPOINT}
    for action in package.actions:
        assert action.evidence and all(e.data.get("record_id") in run.workflow_run.index for e in action.evidence)
        assert action.approval_level is ApprovalLevel.STANDARD
        assert type(action.risk_score) is int and type(action.confidence_score) is int
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
    assert run.runtime.registry.list() == []


def test_session_revocation_alone_still_needs_a_human():
    run = _run("edge-external-forwarding-rule", live=True)
    package = run.detect().package
    assert [a.action_type for a in package.actions] == [ActionType.REVOKE_SESSIONS]
    assert run.environment.state_changing_calls() == []
    with pytest.raises(ApprovalError):
        _approve_all(run, "automation")
    result = run.decide({"decision": "REJECT", "comment": "user confirmed the rule"}, approvers=["analyst"])
    assert result.report is None or not result.report.results
    assert run.environment.state_changing_calls() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CLOSED


def test_dry_run_approval_simulates_and_executes_nothing():
    run = _run("dry-run", live=False)
    run.detect()
    result = _approve_all(run, "analyst")
    assert result.report is not None and result.report.dry_run
    assert {r.status for r in result.report.results} == {ActionResultStatus.DRY_RUN}
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []


def test_live_approval_executes_verifies_and_release_needs_its_own_human_approval():
    run = _run("tp-approve-all", live=True)
    run.detect()
    assert run.environment.state_changing_calls() == []
    result = _approve_all(run, "analyst")
    report = result.report
    assert report is not None and not report.dry_run and report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    assert {r.status for r in report.results} == {ActionResultStatus.SUCCESS}
    assert all(r.verification is not None and r.verification.status is _readback(r) for r in report.results)
    assert len(run.environment.state_changing_calls()) == 4
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert {c.action_type for c in controls} == {ActionType.DISABLE_USER, ActionType.QUARANTINE_EMAIL,
                                                 ActionType.ISOLATE_ENDPOINT}  # revocation is not reversible
    events = [r.event_type for r in run.runtime.audit.records(run.incident_id)]
    assert events.index(AuditEventType.CONTAINMENT_COMPLETED) > events.index(AuditEventType.PACKAGE_PROPOSED)

    run.propose_release()
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["ai"])
    calls_before_release = len(run.environment.state_changing_calls())
    release = run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert release.report is not None and release.report.overall is RestorationOverall.PARTIALLY_RESTORED
    assert len(run.environment.state_changing_calls()) == calls_before_release + 3
    assert run.environment.state_for(ActionType.DISABLE_USER, USER) is False


def test_critical_mailbox_needs_the_lead():
    run = _run("critical-asset-elevated", live=True)
    package = run.detect().package
    elevated = {a.action_type for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED}
    assert elevated == {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER}
    assert all(a.warnings for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED)
    with pytest.raises(ApproverNotAllowedError):
        _approve_all(run, "analyst")
    assert run.environment.state_changing_calls() == []
    result = _approve_all(run, "lead")
    assert result.report.overall is ContainmentOverall.CONTAINED


def test_partial_failure_is_reported_never_hidden():
    run = _run("partial-failure", live=True)
    run.detect()
    report = _approve_all(run, "analyst").report
    assert report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    statuses = {r.action_type: r.status for r in report.results}
    assert statuses[ActionType.DISABLE_USER] is ActionResultStatus.FAILED
    assert statuses[ActionType.REVOKE_SESSIONS] is ActionResultStatus.SUCCESS


def test_degraded_required_source_does_not_block_mail_containment():
    run = _run("degraded-source", live=False)
    package = run.detect().package
    assert package is not None
    assert {a.action_type for a in package.actions} == {ActionType.QUARANTINE_EMAIL, ActionType.BLOCK_DOMAIN}
    assert "entra" in run.workflow_run.degraded_sources()
    assert any("degraded source: entra" in n for n in run.workflow_run.notes)


def test_dry_run_and_live_score_identically():
    scores = []
    for live in (False, True):
        run = _run("tp-approve-all", live=live)
        package = run.detect().package
        scores.append(sorted((a.action_type.value, a.target, a.risk_score, a.confidence_score)
                             for a in package.actions))
        guard._reset_for_test_harness()
    assert scores[0] == scores[1]
