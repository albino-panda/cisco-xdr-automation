"""The credential-dumping workflow through the production lifecycle (simulated lab): dry run and simulated live.

The workflow only investigates and recommends: nothing state-changing happens before a human
decision, AI and automation can never approve, approved containment (including session revocation)
executes and verifies automatically, a domain controller needs ELEVATED approval, and restoration
needs its own human release approval.
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
from xdr_response.errors import ApprovalError, ApproverNotAllowedError
from xdr_response.models import ActionResultStatus, ApprovalLevel, IncidentState
from xdr_response.workflows.credential_dumping import WORKFLOW
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.runner import RuleOutcomeStatus

SCENARIOS = WORKFLOW_SCENARIO_DIR / "credential-dumping"
LEGACY = ("01-workstation-lsass-access", "02-security-agent-memory-read", "03-domain-controller-ntds",
          "04-domain-admin-exposed", "05-shared-admin-server")
MINIMUM = ("tp-approve-all", "tp-approve-selected", "tp-reject", "benign-no-action", "degraded-source",
           "critical-asset-elevated", "partial-failure", "dry-run", "release-restoration")


def _paths() -> list[Path]:
    return sorted(SCENARIOS.glob("*.yaml"))


def _run(name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SCENARIOS / f"{name}.yaml"), live=live)


def test_the_scenario_set_meets_the_minimum_and_every_rule_is_proposed_somewhere():
    names = {p.stem for p in _paths()}
    assert set(MINIMUM) <= names
    assert len([n for n in names if n.startswith("edge-")]) >= 2
    scenarios = [load_workflow_scenario(p) for p in _paths()]
    proposed: set[str] = set()
    unrouted: set[str] = set()
    for scenario in scenarios:
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        assert run.workflow_run is not None, scenario.name
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        unrouted |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)}
        assert not run.workflow_run.outcomes_with(RuleOutcomeStatus.ERROR), scenario.name
        guard._reset_for_test_harness()  # one runtime per process: reset between the runs of this test
    assert proposed | (unrouted & {r.id for r in WORKFLOW.recommendations
                                if not executable_anywhere(r.action)}) == {r.id for r in WORKFLOW.recommendations}
    assert check_coverage("credential-dumping", scenarios, WORKFLOW, proposed_rules=proposed, unrouted_rules=unrouted) == []


def test_every_legacy_scenario_is_migrated_with_its_source():
    sources = {load_workflow_scenario(p).legacy_source for p in _paths() if p.stem.startswith("legacy-")}
    assert sources == {f"workflows/credential-dumping/scenarios/{name}.yaml" for name in LEGACY}
    assert not (SCENARIOS.parents[3] / "workflows" / "credential-dumping" / "workflow.yaml").exists()


def test_dry_run_proposes_and_simulates_without_any_state_change():
    run = _run("dry-run", live=False).play()
    package = run.detection.package
    assert package is not None and package.dry_run
    assert package.workflow_id == "credential-dumping" and package.workflow_version == WORKFLOW.version
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.check() == [] and run.implicit_problems() == []


def test_live_nothing_changes_before_the_human_decision_then_approved_actions_execute_and_verify():
    run = _run("tp-approve-all", live=True)
    detection = run.detect()
    assert run.environment.state_changing_calls() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL
    package = detection.package
    # the help-desk account the identity provider marks privileged is ELEVATED (privileged-account class)
    elevated = {f"{a.action_type.value}:{a.target}" for a in package.actions
                if a.approval_level is ApprovalLevel.ELEVATED}
    assert elevated == {"revoke_sessions:it.support@example.com", "disable_user:it.support@example.com"}
    assert all(a.warnings for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED)
    assert all(a.evidence and a.rationale for a in package.actions)
    with pytest.raises(ApproverNotAllowedError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert run.environment.state_changing_calls() == []
    decision = run.decide()
    report = decision.report
    assert report is not None and not report.dry_run
    statuses = {f"{r.action_type.value}:{r.target}": r.status for r in report.results}
    assert set(statuses) == {f"{a.action_type.value}:{a.target}" for a in package.actions}
    assert set(statuses.values()) == {ActionResultStatus.SUCCESS}
    changed = {c.operation for c in run.environment.state_changing_calls()}
    assert changed == {"isolate_endpoint", "revoke_sessions", "disable_user"}
    # the real Secure Endpoint adapter cannot block hashes: recommended, reported UNROUTED, never executed
    assert any(s.startswith("block_hash:") for s in {o.selector for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)})
    assert all(r.verification is not None for r in report.results)
    assert len(run.runtime.registry.list(incident_id=run.incident_id)) == 2  # revocation registers no control


@pytest.mark.parametrize("alias", ["ai", "automation"])
def test_ai_and_automation_can_never_approve_containment(alias: str):
    run = _run("tp-approve-all", live=True)
    run.detect()
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=[alias])
    assert run.environment.state_changing_calls() == []


def test_a_session_revocation_alone_still_needs_human_approval():
    run = _run("tp-approve-all", live=True)
    run.detect()
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_SELECTED", "select": ["revoke_sessions:jsmith@example.com"]},
                   approvers=["ai"])
    assert run.environment.state_changing_calls() == []


def test_a_domain_controller_needs_the_lead_and_an_analyst_alone_is_refused():
    run = _run("edge-domain-controller-ntds", live=True)
    detection = run.detect()
    levels = {f"{a.action_type.value}:{a.target}": a.approval_level for a in detection.package.actions}
    assert levels["isolate_endpoint:DC-02"] is ApprovalLevel.ELEVATED
    dc = next(a for a in detection.package.actions if a.target == "DC-02")
    assert any("Domain controller" in w.message for w in dc.warnings)
    with pytest.raises(ApproverNotAllowedError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert run.environment.state_changing_calls() == []
    decision = run.decide({"decision": "APPROVE_ALL"}, approvers=["lead"])
    # Secure Endpoint cannot read the isolation back (UNABLE_TO_VERIFY): partial, never CONTAINED
    assert decision.report is not None and decision.report.overall.value == "PARTIALLY_CONTAINED"
    manual = {c.subject for c in run.workflow_run.considered if c.manual}
    assert manual == {"domain-credential-reset:DC-02"}


def test_a_privileged_exposed_account_needs_the_lead():
    run = _run("critical-asset-elevated", live=True)
    detection = run.detect()
    elevated = {f"{a.action_type.value}:{a.target}" for a in detection.package.actions
                if a.approval_level is ApprovalLevel.ELEVATED}
    assert elevated == {"revoke_sessions:ops.lead@example.com", "disable_user:ops.lead@example.com"}
    with pytest.raises(ApproverNotAllowedError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert run.environment.state_changing_calls() == []


def test_restoration_needs_its_own_human_release_approval():
    run = _run("release-restoration", live=True)
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert {c.action_type.value for c in controls} == {"isolate_endpoint", "disable_user"}
    calls = len(run.environment.state_changing_calls())
    run.propose_release()
    assert len(run.environment.state_changing_calls()) == calls  # proposing a release changes nothing
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["ai"])
    assert len(run.environment.state_changing_calls()) == calls
    # the disabled account is privileged (ELEVATED), so its release needs the elevated approver too
    result = run.decide_release({"decision": "APPROVE_ALL"}, approvers=["lead"])
    assert result.report is not None and result.report.overall.value == "PARTIALLY_RESTORED"
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_RELEASE_APPROVAL


def test_rejected_package_closes_without_any_control():
    run = _run("tp-reject", live=True).play()
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CLOSED


def test_a_degraded_identity_source_does_not_block_the_recommendation():
    run = _run("degraded-source", live=False).play()
    workflow_run = run.workflow_run
    assert workflow_run.degraded_sources() == ("entra",)
    assert any("degraded source: entra" in note for note in workflow_run.notes)
    targets = {f"{a.action_type.value}:{a.target}" for a in run.detection.package.actions}
    assert "revoke_sessions:jsmith@example.com" in targets and "isolate_endpoint:TH-LT-1047" in targets
    assert not any(t.startswith("disable_user:") for t in targets)
    assert run.check() == []


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
    for name in ("legacy-01-workstation-lsass-access", "legacy-03-domain-controller-ntds", "tp-approve-all"):
        incident = load_workflow_scenario(SCENARIOS / f"{name}.yaml").incident
        assert catalog.resolve(incident.model_copy(update={"workflow_id": "unassigned"})).definition.id == \
            "credential-dumping"


def test_a_defender_managed_endpoint_is_isolated_through_defender():
    from tests.fixtures.sample_workflows.lab import make_incident, make_lab  # noqa: PLC0415
    from xdr_response.models import ObservableType  # noqa: PLC0415

    lab = make_lab({"defender_endpoint": ("endpoint",), "entra": ("identity",)})
    lab.typed("investigate_endpoint", "TH-LT-1047", "defender_endpoint", kind="endpoint", hostname="TH-LT-1047",
              mde_machine_id="mde-0000000000001047", users=["jsmith@example.com"], groups=["Workstations"],
              isolation_capable=True)
    lab.typed("investigate_endpoint", "TH-LT-1047", "defender_endpoint", kind="detection", detection_id="da-1",
              name="Suspicious access to LSASS service", verdict="MALICIOUS", severity="HIGH",
              endpoint="TH-LT-1047", mitre_techniques=["T1003.001"], status="active")
    incident = make_incident((ObservableType.HOSTNAME, "TH-LT-1047"), workflow_id="credential-dumping",
                             title="Credential theft behaviour on TH-LT-1047")
    run = lab.runner.run(WORKFLOW, discover_workflows().get("credential-dumping").hooks, incident, dry_run=True)
    outcomes = {o.rule_id: o.status for o in run.outcomes}
    assert outcomes["isolate_credential_host_defender_endpoint"] is RuleOutcomeStatus.PROPOSED
    isolation = next(b for b in run.built if b.action_type.value == "isolate_endpoint")
    assert isolation.route.integration == "defender_endpoint"
