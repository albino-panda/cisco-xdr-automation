"""The phishing workflow through the production lifecycle (orchestrator, approval, execution, release).

Dry run and simulated live, on the phishing scenarios in ``tests/fixtures/workflows/phishing/``.
Every scenario is also played by ``tests/simulation/test_workflow_scenarios.py``; these tests add the
workflow-specific lifecycle facts: the package is bound to the workflow and version, nothing changes
before a human decision, non-human principals are refused, the approved actions run on the expected
products and verify, the non-reversible revocation has no control, and restoration needs its own
human release decision.
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
from xdr_response.integrations.simulated import production_manifest
from xdr_response import guard
from xdr_response.errors import ApprovalError
from xdr_response.models import ActionResultStatus, ActionType, ApprovalLevel, IncidentState, VerificationStatus
from xdr_response.workflows.phishing import WORKFLOW
from xdr_response.workflows.runner import RuleOutcomeStatus

SCENARIOS = WORKFLOW_SCENARIO_DIR / "phishing"


def _readback(result) -> VerificationStatus:
    """VERIFIED where the real adapter reads the action back, else UNABLE_TO_VERIFY (architecture 14.14.3:
    the simulated adapters do only what the real ones support and verify)."""
    real = production_manifest(result.integration)
    return (VerificationStatus.VERIFIED if real is not None and result.action_type in real.verifiable_actions
            else VerificationStatus.UNABLE_TO_VERIFY)


def _scenario(name: str):
    return load_workflow_scenario(SCENARIOS / f"{name}.yaml")


def _play(name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(_scenario(name), live=live).play()


def test_dry_run_proposes_a_bound_package_and_changes_nothing():
    run = _play("tp-approve-all", live=False)
    package = run.detection.package
    assert package is not None and package.dry_run
    assert (package.workflow_id, package.workflow_version) == ("phishing", WORKFLOW.version)
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    statuses = {r.status for r in run.decision.report.results}
    assert statuses == {ActionResultStatus.DRY_RUN}
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL


def test_live_run_needs_a_human_and_executes_on_the_expected_products():
    scenario = _scenario("tp-approve-all")
    run = WorkflowScenarioRun(scenario, live=True)
    run.detect()
    package = run.detection.package
    assert run.environment.state_changing_calls() == []  # investigation and recommendation only read
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                             run.credentials(alias))
    assert run.environment.state_changing_calls() == []
    decision = run.decide()
    report = decision.report
    assert report is not None and not report.dry_run
    by_type = {r.action_type: r for r in report.results}
    assert by_type[ActionType.QUARANTINE_EMAIL].integration == "secure_email"
    assert by_type[ActionType.BLOCK_DOMAIN].integration == "umbrella"
    assert by_type[ActionType.REVOKE_SESSIONS].integration == "entra"
    assert by_type[ActionType.DISABLE_USER].integration == "entra"
    assert by_type[ActionType.ISOLATE_ENDPOINT].integration == "secure_endpoint"
    assert all(r.status is ActionResultStatus.SUCCESS for r in report.results)
    assert all(r.verification is not None and r.verification.status is _readback(r) for r in report.results)
    revoke = by_type[ActionType.REVOKE_SESSIONS]
    assert revoke.control_registered is False  # not reversible: nothing to release
    assert len(run.runtime.registry.list(incident_id=run.incident_id)) == len(report.results) - 1


def test_restoration_needs_its_own_human_release_decision():
    scenario = _scenario("release-restoration")
    run = WorkflowScenarioRun(scenario, live=True)
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert controls
    calls_before = len(run.environment.state_changing_calls())
    release = run.propose_release()
    assert len(run.environment.state_changing_calls()) == calls_before  # proposing a release changes nothing
    with pytest.raises(ApprovalError):
        run.orchestrator.submit_release_decision(
            run._request(release, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"), run.credentials("automation"))
    assert len(run.environment.state_changing_calls()) == calls_before
    result = run.decide_release()
    assert result.report is not None and result.report.overall is not None
    assert result.report.overall.value == "PARTIALLY_RESTORED"


def test_privileged_user_actions_are_elevated_and_an_analyst_alone_is_refused():
    run = WorkflowScenarioRun(_scenario("critical-asset-elevated"), live=False)
    run.detect()
    package = run.detection.package
    elevated = {a.action_type for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED}
    assert elevated == {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER}
    assert all(a.warnings for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED)
    with pytest.raises(ApprovalError):
        run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                         run.credentials("analyst"))
    decision = run.decide(approvers=["lead"])
    assert decision.report is not None


def test_defender_managed_endpoint_is_isolated_through_defender():
    run = _play("edge-defender-managed-endpoint", live=True)
    isolate = next(r for r in run.decision.report.results if r.action_type is ActionType.ISOLATE_ENDPOINT)
    assert isolate.integration == "defender_endpoint" and isolate.status is ActionResultStatus.SUCCESS


def test_a_degraded_expected_source_lowers_confidence_but_keeps_the_package():
    healthy = _play("tp-approve-all", live=False)
    guard._reset_for_test_harness()  # one runtime per process
    degraded = _play("degraded-source", live=False)
    assert degraded.workflow_run.degraded_sources() == ("umbrella",)
    assert {a.action_type for a in degraded.detection.package.actions} == \
        {a.action_type for a in healthy.detection.package.actions}
    assert degraded.detection.package.confidence_score < healthy.detection.package.confidence_score


def test_every_rule_is_proposed_in_some_scenario_and_the_minimum_set_is_met():
    scenarios = [load_workflow_scenario(p) for p in sorted(Path(SCENARIOS).glob("*.yaml"))]
    proposed: set[str] = set()
    unrouted: set[str] = set()
    for scenario in scenarios:
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        unrouted |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)}
        assert run.workflow_run.outcomes_with(RuleOutcomeStatus.ERROR) == ()
        guard._reset_for_test_harness()  # one runtime per process: reset between runs of this test
    assert check_coverage("phishing", scenarios, WORKFLOW, proposed_rules=proposed, unrouted_rules=unrouted) == []
    assert proposed | (unrouted & {r.id for r in WORKFLOW.recommendations
                                if not executable_anywhere(r.action)}) == {r.id for r in WORKFLOW.recommendations}


def test_legacy_scenarios_are_all_migrated():
    legacy = sorted(p.name for p in SCENARIOS.glob("legacy-*.yaml"))
    assert legacy == [
        "legacy-01-credential-link-and-attachment.yaml", "legacy-02-benign-user-report.yaml",
        "legacy-03-allowlisted-partner-indicators.yaml", "legacy-04-campaign-over-indicator-cap.yaml",
        "legacy-05-malicious-url-on-legitimate-host.yaml"]
    for name in legacy:
        scenario = load_workflow_scenario(SCENARIOS / name)
        assert scenario.legacy_source == f"workflows/phishing/scenarios/{name.removeprefix('legacy-')}"
