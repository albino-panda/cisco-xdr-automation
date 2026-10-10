"""The ransomware workflow through the real lifecycle orchestrator (simulated lab, fake data).

The workflow only investigates and recommends. These tests prove the owner rule for it end to end:
nothing changes before a human decision, AI and automation cannot approve, an analyst alone cannot
approve a critical asset, approved containment executes and verifies automatically, dry run changes
nothing, and restoration needs its own human release approval.
"""
from __future__ import annotations

import pytest

from tools.simulator.workflow_scenario import WORKFLOW_SCENARIO_DIR, WorkflowScenarioRun, load_workflow_scenario
from xdr_response import guard
from xdr_response.atomics.evidence import EvidenceBuilder
from xdr_response.errors import ApprovalError
from xdr_response.lifecycle.workflow_adapter import WorkflowInvestigationReport
from xdr_response.models import (
    ActionResultStatus,
    ApprovalLevel,
    AuditEventType,
    IncidentState,
    OperationKind,
)

SCENARIOS = WORKFLOW_SCENARIO_DIR / "ransomware"


def _run(name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SCENARIOS / f"{name}.yaml"), live=live)


def _writes(run: WorkflowScenarioRun) -> list:
    return [c for c in run.environment.calls if c.kind is OperationKind.STATE_CHANGING]


@pytest.mark.parametrize("live", [False, True])
def test_detection_investigates_and_recommends_without_any_write(live: bool):
    run = _run("tp-approve-all", live=live)
    detection = run.detect()
    assert isinstance(detection.investigation, WorkflowInvestigationReport)
    assert detection.investigation.run is not None and detection.investigation.run.workflow.id == "ransomware"
    assert _writes(run) == [] and run.runtime.registry.list() == []
    package = detection.package
    assert package is not None and package.dry_run is (not live)
    assert (package.workflow_id, package.workflow_version) == ("ransomware", "2.0.0")
    assert detection.incident.state is IncidentState.AWAITING_APPROVAL
    builder = EvidenceBuilder(detection.investigation.run.index)
    for action in package.actions:
        assert action.evidence and all(e.data["record_id"] in builder.index for e in action.evidence)
        assert isinstance(action.risk_score, int) and isinstance(action.confidence_score, int)
    events = [r.event_type for r in run.runtime.audit.records(run.incident_id)]
    assert AuditEventType.INVESTIGATION_COMPLETED in events


@pytest.mark.parametrize("alias", ["ai", "automation"])
def test_non_human_principals_can_never_approve(alias: str):
    run = _run("tp-approve-all", live=True)
    run.detect()
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=[alias])
    assert _writes(run) == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL


def test_an_analyst_alone_cannot_approve_a_domain_controller_isolation():
    run = _run("critical-asset-elevated", live=True)
    package = run.detect().package
    elevated = [a for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED]
    assert [a.target for a in elevated] == ["DC-02"] and elevated[0].warnings
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert _writes(run) == []
    decision = run.decide({"decision": "APPROVE_ALL"}, approvers=["lead"])
    assert decision.report is not None and decision.report.overall.value == "PARTIALLY_CONTAINED"


def test_approved_containment_executes_and_verifies_automatically():
    run = _run("tp-approve-all", live=True)
    run.detect()
    decision = run.decide()
    report = decision.report
    assert report is not None and not report.dry_run
    assert {r.status for r in report.results} == {ActionResultStatus.SUCCESS}
    assert len(_writes(run)) == len(report.results)
    events = [r.event_type for r in run.runtime.audit.records(run.incident_id)]
    assert events.count(AuditEventType.VERIFICATION_RESULT) == len(report.results)


def test_dry_run_simulates_and_changes_nothing():
    run = _run("dry-run", live=False).play()
    assert run.check() == [] and run.implicit_problems() == []
    assert _writes(run) == [] and run.runtime.registry.list() == []
    assert run.detection.package.dry_run is True


def test_restoration_needs_its_own_human_release_approval():
    run = _run("release-restoration", live=True)
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert len(controls) == 1  # the isolation; the hash block has no executor (UNROUTED)
    writes_after_containment = len(_writes(run))
    release = run.propose_release()
    assert _writes(run)[writes_after_containment:] == []  # proposing a release changes nothing
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["ai"])
    assert _writes(run)[writes_after_containment:] == []
    result = run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert release is not None and result.report is not None
    # only a Secure Endpoint release, not read back: the control waits for a human (never RESTORED)
    assert result.report.overall.value == "RESTORATION_FAILED"
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_RELEASE_APPROVAL


def test_live_and_dry_run_score_identically():
    dry = _run("tp-approve-all", live=False).detect()
    guard._reset_for_test_harness()  # one runtime per process: reset between the two runs
    live = _run("tp-approve-all", live=True).detect()
    key = lambda p: {(a.action_type, a.target): (a.risk_score, a.confidence_score) for a in p.actions}  # noqa: E731
    assert key(dry.package) == key(live.package)
    assert (dry.package.risk_score, dry.package.confidence_score) == (
        live.package.risk_score, live.package.confidence_score)
