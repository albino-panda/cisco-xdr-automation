"""``mail-bombing`` through the Phase 0 lifecycle: dry run and simulated live via the orchestrator.

Every scenario of the workflow is played here as well as in the framework scenario test, with
workflow-specific assertions: nothing changes state before the human decision, session revocation
is never executed without approval, dry run executes nothing, release needs its own human approval,
and every recommendation rule is proposed by at least one scenario.
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
from tools.simulator.workflow_scenario import executable_anywhere
from xdr_response import guard
from xdr_response.errors import ApprovalError
from xdr_response.models import ActionType, ApprovalLevel, IncidentState, OperationKind
from xdr_response.workflows.mail_bombing import WORKFLOW
from xdr_response.workflows.runner import RuleOutcomeStatus

SCENARIO_DIR = WORKFLOW_SCENARIO_DIR / "mail-bombing"
PATHS = sorted(SCENARIO_DIR.glob("*.yaml"))
CASES = [pytest.param(path, live, id=f"{path.stem}[{'live' if live else 'dry_run'}]")
         for path in PATHS for live in load_workflow_scenario(path).modes()]


def _play(name: str, *, live: bool, probe: bool = True) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SCENARIO_DIR / f"{name}.yaml"), live=live).play(probe=probe)


def _state_changing(run: WorkflowScenarioRun, operation: str | None = None) -> list:
    return [c for c in run.environment.calls if c.kind is OperationKind.STATE_CHANGING
            and (operation is None or c.operation == operation)]


@pytest.mark.parametrize("path, live", CASES)
def test_every_scenario_meets_its_expectations(path: Path, live: bool):
    run = WorkflowScenarioRun(load_workflow_scenario(path), live=live).play()
    assert run.workflow_run is not None and run.workflow_run.workflow.id == "mail-bombing"
    assert run.check() == []
    assert run.implicit_problems() == []
    assert run.probe.state_changes == 0 and run.probe.guard_denials == 0
    if not live:
        assert run.environment.state_changing_calls() == []
        assert run.runtime.registry.list() == []


def test_minimum_scenario_set_and_every_rule_proposed():
    scenarios = [load_workflow_scenario(p) for p in PATHS]
    proposed: set[str] = set()
    unrouted: set[str] = set()
    for scenario in scenarios:
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        unrouted |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)}
        guard._reset_for_test_harness()  # one runtime per process: reset between the runs of this test
    assert proposed | (unrouted & {r.id for r in WORKFLOW.recommendations
                                if not executable_anywhere(r.action)}) == {r.id for r in WORKFLOW.recommendations}
    assert check_coverage("mail-bombing", scenarios, WORKFLOW, proposed_rules=proposed, unrouted_rules=unrouted) == []
    assert len([s for s in scenarios if s.name.startswith("legacy-")]) == 5


def test_detection_only_proposes_and_waits_for_a_human():
    run = WorkflowScenarioRun(load_workflow_scenario(SCENARIO_DIR / "tp-approve-all.yaml"), live=True)
    detection = run.detect()
    assert detection.package is not None
    assert detection.incident.state is IncidentState.AWAITING_APPROVAL
    assert _state_changing(run) == []
    assert run.runtime.registry.list() == []
    assert all(a.approval_level in (ApprovalLevel.STANDARD, ApprovalLevel.ELEVATED) for a in detection.package.actions)


@pytest.mark.parametrize("alias", ["ai", "automation"])
def test_non_human_principals_can_never_approve(alias: str):
    run = WorkflowScenarioRun(load_workflow_scenario(SCENARIO_DIR / "tp-approve-all.yaml"), live=True)
    run.detect()
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=[alias])
    assert _state_changing(run) == []


def test_session_revocation_is_never_executed_without_approval():
    run = _play("tp-approve-selected", live=True)
    assert _state_changing(run, ActionType.REVOKE_SESSIONS.value) == []
    assert {c.target for c in _state_changing(run, ActionType.QUARANTINE_EMAIL.value)} == {
        "etd-mb-0002-001", "etd-mb-0002-002"}


def test_rejected_package_executes_nothing():
    run = _play("tp-reject", live=True)
    assert _state_changing(run) == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CLOSED


def test_approved_package_executes_and_verifies_automatically():
    run = _play("tp-approve-all", live=True)
    executed = {(c.operation, c.target) for c in _state_changing(run)}
    assert (ActionType.REVOKE_SESSIONS.value, "jsmith@example.com") in executed
    assert (ActionType.DISABLE_USER.value, "jsmith@example.com") in executed
    assert (ActionType.ISOLATE_ENDPOINT.value, "TH-LT-1047") in executed
    assert (ActionType.BLOCK_DOMAIN.value, "docs-sign.example") in executed
    assert (ActionType.QUARANTINE_EMAIL.value, "etd-mb-0001-004") not in executed  # buried notice stays
    report = run.decision.report
    assert report is not None and not report.dry_run
    assert all(r.verification is not None for r in report.results)


def test_release_needs_its_own_human_approval():
    run = WorkflowScenarioRun(load_workflow_scenario(SCENARIO_DIR / "release-restoration.yaml"), live=True)
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert len(controls) == 2
    release = run.propose_release()
    assert release is not None
    assert _state_changing(run, ActionType.RELEASE_EMAIL.value) == []  # proposing a release changes nothing
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["automation"])
    assert _state_changing(run, ActionType.RELEASE_EMAIL.value) == []
    run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert {c.target for c in _state_changing(run, ActionType.RELEASE_EMAIL.value)} == {
        "etd-mb-0009-001", "etd-mb-0009-002"}


def test_dry_run_notifications_are_marked_and_carry_no_secrets():
    run = _play("dry-run", live=False)
    drafts = run.outbox.drafts
    assert drafts and all(d.title.startswith("[DRY RUN] ") for d in drafts)
    for draft in drafts:
        assert "unlock code" not in draft.body.lower()
        assert "secret" not in draft.body.lower()


def test_over_the_cap_every_quarantine_is_elevated_and_an_analyst_alone_is_refused():
    run = WorkflowScenarioRun(load_workflow_scenario(SCENARIO_DIR / "edge-volume-over-cap.yaml"), live=True)
    detection = run.detect()
    actions = detection.package.actions
    assert len(actions) == 5 and all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in actions)
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert _state_changing(run) == []
