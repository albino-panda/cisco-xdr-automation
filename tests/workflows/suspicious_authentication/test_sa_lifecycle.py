"""The suspicious-authentication workflow through the production lifecycle (orchestrator) on the simulated lab.

Dry run and simulated live: investigation and recommendation are automatic and change nothing; only a
human approval lets the approved containment execute (then it verifies automatically); restoration
needs a separate human release approval; AI and automation never approve. HIBP only ever receives an
address the disclosure policy allows.
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
from tools.simulator.workflow_scenario import executable_anywhere
from xdr_response import guard
from xdr_response.atomics.records import SourceOutcome
from xdr_response.errors import ApprovalError
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    ApprovalLevel,
    AuditEventType,
    ContainmentOverall,
    IncidentState,
    OperationKind,
    RestorationOverall,
    VerificationStatus,
)
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.runner import RuleOutcomeStatus
from xdr_response.workflows.suspicious_authentication import WORKFLOW

SCENARIOS = WORKFLOW_SCENARIO_DIR / "suspicious-authentication"
USER = "jsmith@example.com"
ATTACKER = "203.0.113.145"


def _scenario(name: str) -> WorkflowScenario:
    return load_workflow_scenario(SCENARIOS / f"{name}.yaml")


def _selectors(package) -> set[str]:
    return {f"{a.action_type.value}:{a.target}" for a in package.actions}


def _with(scenario: WorkflowScenario, **environment) -> WorkflowScenario:
    return scenario.model_copy(update={"environment": scenario.environment.model_copy(update=environment)})


@pytest.fixture(autouse=True)
def _one_runtime_per_test():
    guard._reset_for_test_harness()  # the execution guard allows one runtime per process
    yield
    guard._reset_for_test_harness()


def test_dry_run_proposes_the_package_and_changes_nothing():
    run = WorkflowScenarioRun(_scenario("tp-approve-all"), live=False).play()
    package = run.detection.package
    assert package is not None and package.dry_run
    assert _selectors(package) == {f"revoke_sessions:{USER}", f"disable_user:{USER}", f"block_ip:{ATTACKER}"}
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    lines = {r.dry_run_line for r in run.detection.dry_run_report.results}
    assert lines == {f"Would revoke sessions: {USER}", f"Would disable user: {USER}", f"Would block: {ATTACKER}"}
    assert package.workflow_id == "suspicious-authentication" and package.workflow_version == WORKFLOW.version


def test_every_action_carries_numbered_record_evidence_and_separate_scores():
    run = WorkflowScenarioRun(_scenario("tp-approve-all"), live=False)
    package = run.detect().package
    index = run.workflow_run.index
    for action in package.actions:
        assert action.evidence, action.target
        assert [e.number for e in action.evidence] == sorted(e.number for e in action.evidence)
        assert all(e.data["record_id"] in index for e in action.evidence)
        assert isinstance(action.risk_score, int) and isinstance(action.confidence_score, int)
    revoke = next(a for a in package.actions if a.action_type is ActionType.REVOKE_SESSIONS)
    sources = {e.source for e in revoke.evidence}
    assert {"entra", "cisco_xdr", "hibp"} <= sources  # sign-ins, the IP rating and the breach answer
    assert "indicator point" in revoke.rationale and "settings" in revoke.rationale


def test_live_execution_needs_a_human_and_verifies_automatically():
    run = WorkflowScenarioRun(_scenario("tp-approve-all"), live=True)
    package = run.detect().package
    assert package is not None and not package.dry_run
    assert run.environment.state_changing_calls() == []  # investigation and recommendation never write
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.decide({"decision": "APPROVE_ALL"}, approvers=[alias])
    assert run.environment.state_changing_calls() == []
    report = run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"]).report
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
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.decide_release({"decision": "APPROVE_ALL"}, approvers=[alias])
    assert len(run.environment.state_changing_calls()) == before
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
    degraded = _with(scenario, faults=faults).model_copy(update={
        "expect": scenario.expect.model_copy(update={"evidence_min": 1})})
    run = WorkflowScenarioRun(degraded, live=False).play()
    # the incident names the attacker IP and reputation still rates it: the block stands on that evidence
    assert _selectors(run.detection.package) == {f"block_ip:{ATTACKER}"}
    assert "entra" in run.workflow_run.degraded_sources()
    assert any("degraded source: entra" in note for note in run.workflow_run.notes)
    assert run.implicit_problems() == []


def test_a_failed_reputation_source_does_not_block_the_revocation():
    run = WorkflowScenarioRun(_scenario("degraded-source"), live=False).play()
    assert _selectors(run.detection.package) == {"revoke_sessions:akim@example.com"}
    assert run.workflow_run.degraded_sources() == ("cisco_xdr",)
    assert run.check() == [] and run.implicit_problems() == []


def test_hibp_never_receives_an_internal_address():
    scenario = _scenario("tp-approve-all")
    internal = "jsmith@corp.example.com"  # corp.example.com is an internal domain in config/exclusions.yaml
    incident = scenario.incident.model_copy(update={
        "users": (internal,),
        "observables": tuple(o for o in scenario.incident.observables if o.value != USER)})
    reputations = (*scenario.environment.reputations,
                   {"type": "email_address", "value": internal, "verdict": "SUSPICIOUS", "risk_score": 40,
                    "confidence": 90, "integrations": ["hibp"], "summary": "must never be asked"})
    run = WorkflowScenarioRun(_with(scenario, reputations=reputations).model_copy(update={"incident": incident}),
                              live=False)
    run.detect()
    exposure = [r for r in run.workflow_run.results if r.atomic == "enrich_email_address"]
    assert [r.subject.value for r in exposure] == [internal]
    hibp = next(s for s in exposure[0].sources if s.integration == "hibp")
    assert hibp.outcome is SourceOutcome.NOT_QUERIED and hibp.reason == "disclosure policy"
    assert [c for c in run.environment.calls if c.integration == "hibp"] == []
    assert all(c.kind is not OperationKind.STATE_CHANGING for c in run.environment.calls)


def test_hibp_is_asked_only_about_the_investigated_account():
    run = WorkflowScenarioRun(_scenario("tp-approve-all"), live=False)
    run.detect()
    asked = [c.target for c in run.environment.calls if c.integration == "hibp"]
    assert asked and set(asked) == {USER}


def test_the_corporate_vpn_egress_is_not_a_new_country():
    run = WorkflowScenarioRun(_scenario("edge-corporate-vpn-egress"), live=False).play()
    assert run.detection.package is None
    item = next(c for c in run.workflow_run.considered if c.subject == "revoke_sessions:lpark@example.com")
    assert "shared egress 198.51.100.20" in item.reason
    assert run.check() == [] and run.implicit_problems() == []


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
    unrouted: set[str] = set()
    for scenario in scenarios:
        guard._reset_for_test_harness()  # one runtime per process
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        unrouted |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)}
    definition = discover_workflows().get("suspicious-authentication").definition
    assert check_coverage("suspicious-authentication", scenarios, definition, proposed_rules=proposed, unrouted_rules=unrouted) == []
    assert proposed | (unrouted & {r.id for r in WORKFLOW.recommendations
                                if not executable_anywhere(r.action)}) == {r.id for r in WORKFLOW.recommendations}
    assert sum(1 for s in scenarios if "edge_case" in s.tags) >= 2
    assert not any("legacy" in s.tags for s in scenarios)  # new workflow: no legacy spec
