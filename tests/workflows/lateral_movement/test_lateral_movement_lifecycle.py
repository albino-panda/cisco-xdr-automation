"""The lateral-movement workflow through the real lifecycle orchestrator (simulated lab, fake data).

The workflow only investigates and recommends. These tests prove the owner rule for it end to end:
nothing changes before a human decision (session revocation included), AI and automation cannot
approve, an analyst alone cannot approve a domain controller or a privileged account, approved
containment executes and verifies automatically, dry run changes nothing, and restoration needs its
own human release approval.
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
    ActionType,
    ApprovalLevel,
    AuditEventType,
    IncidentState,
    OperationKind,
)

SCENARIOS = WORKFLOW_SCENARIO_DIR / "lateral-movement"


def _run(name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SCENARIOS / f"{name}.yaml"), live=live)


def _writes(run: WorkflowScenarioRun) -> list:
    return [c for c in run.environment.calls if c.kind is OperationKind.STATE_CHANGING]


@pytest.mark.parametrize("live", [False, True])
def test_detection_investigates_and_recommends_without_any_write(live: bool):
    run = _run("tp-approve-all", live=live)
    detection = run.detect()
    assert isinstance(detection.investigation, WorkflowInvestigationReport)
    assert detection.investigation.run is not None and detection.investigation.run.workflow.id == "lateral-movement"
    assert _writes(run) == [] and run.runtime.registry.list() == []
    package = detection.package
    assert package is not None and package.dry_run is (not live)
    assert (package.workflow_id, package.workflow_version) == ("lateral-movement", "3.0.0")
    assert detection.incident.state is IncidentState.AWAITING_APPROVAL
    builder = EvidenceBuilder(detection.investigation.run.index)
    for action in package.actions:
        assert action.evidence and all(e.data["record_id"] in builder.index for e in action.evidence)
        numbers = [e.number for e in action.evidence]  # numbered package-wide (13.5)
        assert all(n >= 1 for n in numbers) and numbers == sorted(set(numbers))
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


def test_session_revocation_waits_for_the_human_decision_too():
    run = _run("tp-approve-all", live=True)
    package = run.detect().package
    assert any(a.action_type is ActionType.REVOKE_SESSIONS for a in package.actions)
    assert not any(c.operation == ActionType.REVOKE_SESSIONS.value for c in run.environment.calls)
    run.decide()
    revoked = [c for c in _writes(run) if c.operation == ActionType.REVOKE_SESSIONS.value]
    assert len(revoked) == 1


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


def test_a_privileged_movement_account_needs_elevated_approval():
    run = _run("legacy-03-domain-controller-destination", live=False)
    package = run.detect().package
    elevated = {(a.action_type, a.target) for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED}
    assert (ActionType.REVOKE_SESSIONS, "adm.r.lee@example.com") in elevated
    assert (ActionType.DISABLE_USER, "adm.r.lee@example.com") in elevated
    assert (ActionType.ISOLATE_ENDPOINT, "DC-01") in elevated
    assert (ActionType.ISOLATE_ENDPOINT, "WS-HR-03") not in elevated


def test_a_fan_out_over_the_blast_radius_cap_is_elevated_not_dropped():
    run = _run("legacy-04-admin-share-fan-out", live=False)
    package = run.detect().package
    isolations = [a for a in package.actions if a.action_type is ActionType.ISOLATE_ENDPOINT]
    assert len(isolations) == 7
    assert all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in isolations)


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
    assert len(controls) == 2  # both isolations; the tool hash block has no executor (UNROUTED)
    writes_after_containment = len(_writes(run))
    release = run.propose_release()
    assert _writes(run)[writes_after_containment:] == []  # proposing a release changes nothing
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["ai"])
    assert _writes(run)[writes_after_containment:] == []
    result = run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert release is not None and result.report is not None
    # only Secure Endpoint releases, none read back: every control waits for a human (never RESTORED)
    assert result.report.overall.value == "RESTORATION_FAILED"
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_RELEASE_APPROVAL


def test_a_degraded_identity_source_does_not_block_the_recommendation():
    run = _run("degraded-source", live=False)
    detection = run.detect()
    assert "entra" in run.workflow_run.degraded_sources()
    targets = {(a.action_type, a.target) for a in detection.package.actions}
    assert (ActionType.REVOKE_SESSIONS, "jsmith@example.com") in targets
    assert not any(t == ActionType.DISABLE_USER for t, _ in targets)
    assert any("degraded source: entra" in n for n in detection.notes)


def test_considered_items_and_hand_offs_reach_the_notes_but_never_the_package():
    run = _run("edge-admin-jump-host", live=False)
    detection = run.detect()
    assert "TH-JMP-0001" not in {a.target for a in detection.package.actions}
    assert any("considered, not proposed: isolate_endpoint:TH-JMP-0001" in n for n in detection.notes)
    guard._reset_for_test_harness()  # one runtime per process
    run = _run("tp-approve-all", live=False)
    detection = run.detect()
    assert any(n.startswith("hand-off: run account-takeover for jsmith@example.com") for n in detection.notes)
    assert _writes(run) == []


def test_live_and_dry_run_score_identically():
    dry = _run("tp-approve-all", live=False).detect()
    guard._reset_for_test_harness()  # one runtime per process: reset between the two runs
    live = _run("tp-approve-all", live=True).detect()
    key = lambda p: {(a.action_type, a.target): (a.risk_score, a.confidence_score) for a in p.actions}  # noqa: E731
    assert key(dry.package) == key(live.package)
    assert (dry.package.risk_score, dry.package.confidence_score) == (
        live.package.risk_score, live.package.confidence_score)
