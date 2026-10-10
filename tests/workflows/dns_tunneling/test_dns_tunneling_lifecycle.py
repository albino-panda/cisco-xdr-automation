"""The dns-tunneling workflow through the production lifecycle (simulated lab): dry run and simulated live.

The workflow only investigates and recommends: nothing state-changing happens before a human decision,
AI and automation can never approve, approved containment executes and verifies automatically,
restoration needs its own human release approval, and an approved DNS tool
(allowlists.approved_dns_tools), a clean-rated domain and a forwarding resolver are never contained.
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
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.dns_tunneling import WORKFLOW
from xdr_response.workflows.runner import RuleOutcomeStatus

SCENARIOS = WORKFLOW_SCENARIO_DIR / "dns-tunneling"
HOST = "TH-LT-1047"
PARENT = "cdn-update.test"
LEGACY = ("01-confirmed-tunnel", "02-security-product-lookups", "03-protected-host", "04-blast-radius",
          "05-internal-resolver-forwarding", "06-new-domain-without-reputation")


@pytest.fixture(autouse=True)
def _fresh_guard():
    """One runtime per process (the execution guard is sealed): reset around every test."""
    guard._reset_for_test_harness()
    yield
    guard._reset_for_test_harness()


def _paths() -> list[Path]:
    return sorted(SCENARIOS.glob("*.yaml"))


def _run(name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(SCENARIOS / f"{name}.yaml"), live=live)


def _selectors(actions) -> set[str]:
    return {f"{a.action_type.value}:{a.target}" for a in actions}


def test_the_scenario_set_meets_the_minimum_and_every_rule_is_proposed_somewhere():
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
        guard._reset_for_test_harness()
    assert proposed | (unrouted & {r.id for r in WORKFLOW.recommendations
                                if not executable_anywhere(r.action)}) == {r.id for r in WORKFLOW.recommendations}
    assert check_coverage("dns-tunneling", scenarios, WORKFLOW, proposed_rules=proposed, unrouted_rules=unrouted) == []
    assert len([s for s in scenarios if s.name.startswith("edge-")]) >= 2
    names = {s.name for s in scenarios}
    for required in ("tp-approve-all", "tp-approve-selected", "tp-reject", "benign-no-action", "degraded-source",
                     "critical-asset-elevated", "partial-failure", "dry-run", "release-restoration",
                     "edge-approved-dns-tool"):
        assert required in names


def test_every_legacy_scenario_is_migrated_with_its_source():
    sources = {load_workflow_scenario(p).legacy_source for p in _paths() if p.stem.startswith("legacy-")}
    assert sources == {f"workflows/dns-tunneling/scenarios/{name}.yaml" for name in LEGACY}
    legacy_dir = SCENARIOS.parents[3] / "workflows" / "dns-tunneling"
    assert not (legacy_dir / "workflow.yaml").exists() and not (legacy_dir / "scenarios").exists()
    for path in _paths():
        if path.stem.startswith("legacy-"):
            assert "requires_approval" not in path.read_text(encoding="utf-8")


def test_dry_run_proposes_and_simulates_without_any_state_change():
    run = _run("dry-run", live=False).play()
    package = run.detection.package
    assert package is not None and package.dry_run
    assert package.workflow_id == "dns-tunneling" and package.workflow_version == WORKFLOW.version
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.check() == [] and run.implicit_problems() == []


def test_live_nothing_changes_before_the_human_decision_then_approved_actions_execute_and_verify():
    run = _run("tp-approve-all", live=True)
    detection = run.detect()
    assert run.environment.state_changing_calls() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL
    package = detection.package
    assert _selectors(package.actions) == {f"block_domain:{PARENT}", f"isolate_endpoint:{HOST}"}
    # the termination has no VERIFIED write anywhere: recommended, reported UNROUTED, never executed
    assert f"terminate_process:{HOST}/4242" in {o.selector for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)}
    assert all(a.approval_level is ApprovalLevel.STANDARD for a in package.actions)
    assert all(a.evidence and a.rationale for a in package.actions)
    decision = run.decide()
    report = decision.report
    assert report is not None and not report.dry_run
    statuses = {f"{r.action_type.value}:{r.target}": r.status for r in report.results}
    assert set(statuses) == _selectors(package.actions)
    assert set(statuses.values()) == {ActionResultStatus.SUCCESS}
    changed = {c.operation for c in run.environment.state_changing_calls()}
    assert changed == {a.action_type.value for a in package.actions}
    assert all(r.verification is not None for r in report.results)
    assert len(run.runtime.registry.list(incident_id=run.incident_id)) == 2  # terminate registers no control


@pytest.mark.parametrize("alias", ["ai", "automation"])
def test_ai_and_automation_can_never_approve_containment(alias: str):
    run = _run("tp-approve-all", live=True)
    run.detect()
    with pytest.raises(ApprovalError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=[alias])
    assert run.environment.state_changing_calls() == []


def test_a_critical_asset_needs_the_lead_and_an_analyst_alone_is_refused():
    run = _run("critical-asset-elevated", live=True)
    detection = run.detect()
    elevated = [a for a in detection.package.actions if a.approval_level is ApprovalLevel.ELEVATED]
    assert {a.action_type.value for a in elevated} == {"isolate_endpoint"}
    assert any(s.startswith("terminate_process:") for s in {o.selector for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)})
    assert all(a.warnings for a in elevated)
    with pytest.raises(ApproverNotAllowedError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert run.environment.state_changing_calls() == []
    decision = run.decide({"decision": "APPROVE_ALL"}, approvers=["lead"])
    assert decision.report is not None and decision.report.overall.value == "PARTIALLY_CONTAINED"


def test_a_hypervisor_client_is_elevated_and_a_host_that_cannot_be_isolated_is_shown():
    run = _run("legacy-03-protected-host", live=False)
    detection = run.detect()
    levels = {f"{a.action_type.value}:{a.target}": a.approval_level for a in detection.package.actions}
    assert levels["isolate_endpoint:HV-03"] is ApprovalLevel.ELEVATED
    assert levels["isolate_endpoint:WS-0201"] is ApprovalLevel.STANDARD
    assert "isolate_endpoint:KIOSK-07" not in levels
    assert "isolate_endpoint:KIOSK-07" in {c.subject for c in run.workflow_run.considered}
    assert run.environment.state_changing_calls() == []


def test_tunnel_clients_over_the_blast_radius_cap_are_elevated_not_split():
    run = _run("legacy-04-blast-radius", live=False)
    detection = run.detect()
    isolations = [a for a in detection.package.actions if a.action_type.value == "isolate_endpoint"]
    assert len(isolations) == 6 and all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in isolations)
    [block] = [a for a in detection.package.actions if a.action_type.value == "block_domain"]
    assert block.target == "relay-ns.test" and block.approval_level is ApprovalLevel.STANDARD
    assert run.environment.state_changing_calls() == []


def test_restoration_needs_its_own_human_release_approval():
    run = _run("release-restoration", live=True)
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert len(controls) == 2
    calls = len(run.environment.state_changing_calls())
    run.propose_release()
    assert len(run.environment.state_changing_calls()) == calls  # proposing a release changes nothing
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["ai"])
    assert len(run.environment.state_changing_calls()) == calls
    result = run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    # the domain block is read back; the Secure Endpoint release is not, so its control waits for a human
    assert result.report is not None and result.report.overall.value == "PARTIALLY_RESTORED"
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_RELEASE_APPROVAL


def test_rejected_package_closes_without_any_control():
    run = _run("tp-reject", live=True).play()
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CLOSED


def test_a_degraded_source_does_not_block_the_recommendation():
    healthy = _run("tp-approve-all", live=False)
    healthy.detect()
    baseline = {(p.action_type, p.target): p.confidence_score for p in healthy.workflow_run.proposals}
    guard._reset_for_test_harness()
    run = _run("degraded-source", live=False).play()
    workflow_run = run.workflow_run
    assert workflow_run.degraded_sources() == ("umbrella",)
    assert any("degraded source: umbrella" in note for note in workflow_run.notes)
    assert run.detection.package is not None and len(run.detection.package.actions) == 2
    block = next(p for p in workflow_run.proposals if p.action_type.value == "block_domain")
    assert block.confidence_score < baseline[(block.action_type, block.target)]
    assert run.check() == []


def test_an_approved_dns_tool_is_never_contained_but_the_real_tunnel_is():
    run = _run("edge-approved-dns-tool", live=True).play()
    package = run.detection.package
    assert _selectors(package.actions) == {"block_domain:q9-relay.test", "isolate_endpoint:TH-LT-2051"}
    assert "terminate_process:TH-LT-2051/3301" in {o.selector for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)}
    assert {(e.action_type.value, e.target, e.reason) for e in package.excluded_targets} == {
        ("block_domain", "dnstools.example.net", "allowlists.approved_dns_tools: Example DNS diagnostics")}
    targets = {c.target for c in run.environment.state_changing_calls()}
    assert "dnstools.example.net" not in targets
    assert not any(t.startswith(("TH-LT-2050", "TH-LT-2052")) for t in targets)
    assert run.check() == []


def test_clean_rated_lookups_and_non_tunnels_propose_nothing():
    for name in ("benign-no-action", "legacy-02-security-product-lookups"):
        run = _run(name, live=True).play()
        assert run.detection.package is None, name
        assert run.environment.state_changing_calls() == [], name
        assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.NOT_STARTED, name
        assert run.check() == [], name
        guard._reset_for_test_harness()


def test_a_forwarding_resolver_is_never_isolated_and_the_client_is():
    run = _run("legacy-05-internal-resolver-forwarding", live=True).play()
    package = run.detection.package
    assert _selectors(package.actions) == {"block_domain:img-cache.test", "isolate_endpoint:WS-0217"}
    targets = {c.target for c in run.environment.state_changing_calls()}
    assert "NS-02" not in targets and not any(t.startswith("NS-02/") for t in targets)
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
        assert len(action.evidence) >= 3
        for item in action.evidence:
            assert item.number >= 1 and item.data["record_id"] in index
            assert number_of.setdefault(item.data["record_id"], item.number) == item.number
        assert type(action.risk_score) is int and type(action.confidence_score) is int
    assert type(detection.package.risk_score) is int and type(detection.package.confidence_score) is int


def test_manual_steps_reach_the_run_notes_and_change_nothing():
    run = _run("edge-internal-resolver-only", live=True).play()
    notes = run.workflow_run.notes
    assert any(n.startswith("manual step: find the client behind NS-02") for n in notes)
    assert any(n.startswith("manual step: assess data sent through img-relay.test") for n in notes)
    assert any(n.startswith("considered, not proposed: isolate_endpoint:NS-02") for n in notes)
    assert {c.operation for c in run.environment.state_changing_calls()} == {"block_domain"}
    assert run.check() == []


def test_the_catalog_runs_this_workflow_for_its_incidents():
    catalog = discover_workflows()
    for name in ("tp-approve-all", "critical-asset-elevated", "edge-defender-managed-endpoint"):
        run = _run(name, live=False)
        assert catalog.resolve(run.workflow_scenario.incident).definition.id == "dns-tunneling", name
        guard._reset_for_test_harness()
