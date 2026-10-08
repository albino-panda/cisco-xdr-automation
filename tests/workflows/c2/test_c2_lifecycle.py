"""The c2 workflow through the production lifecycle (simulated lab): dry run and simulated live.

The workflow only investigates and recommends: nothing state-changing happens before a human decision,
AI and automation can never approve, approved containment executes and verifies automatically,
restoration needs its own human release approval, a critical asset or an over-cap isolation is
ELEVATED with a warning, and a degraded source never blocks a recommendation other evidence backs.
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
from xdr_response import guard
from xdr_response.errors import ApprovalError, ApproverNotAllowedError
from xdr_response.models import ActionResultStatus, ApprovalLevel, IncidentState
from xdr_response.workflows.c2 import WORKFLOW
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.runner import RuleOutcomeStatus

SCENARIOS = WORKFLOW_SCENARIO_DIR / "c2"
HOST = "TH-LT-1047"
SHA = "c2be4c0d" * 8
LEGACY = ("01-confirmed-beaconing", "02-benign-saas-heartbeat", "03-guardrail-skips",
          "04-blast-radius-many-hosts", "05-suspicious-dga-domain", "06-shared-hosting-ip")


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
    for scenario in scenarios:
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        assert run.workflow_run is not None, scenario.name
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        assert not run.workflow_run.outcomes_with(RuleOutcomeStatus.ERROR), scenario.name
        guard._reset_for_test_harness()
    assert proposed == {r.id for r in WORKFLOW.recommendations}
    assert check_coverage("c2", scenarios, WORKFLOW, proposed_rules=proposed) == []
    assert len([s for s in scenarios if s.name.startswith("edge-")]) >= 2


def test_every_legacy_scenario_is_migrated_with_its_source():
    sources = {load_workflow_scenario(p).legacy_source for p in _paths() if p.stem.startswith("legacy-")}
    assert sources == {f"workflows/c2/scenarios/{name}.yaml" for name in LEGACY}
    legacy_dir = SCENARIOS.parents[3] / "workflows" / "c2"
    assert not (legacy_dir / "workflow.yaml").exists() and not (legacy_dir / "scenarios").exists()
    for path in _paths():
        text = path.read_text(encoding="utf-8")
        assert "requires_approval" not in text and "auto_approve" not in text


def test_dry_run_proposes_and_simulates_without_any_state_change():
    run = _run("dry-run", live=False).play()
    package = run.detection.package
    assert package is not None and package.dry_run
    assert package.workflow_id == "c2" and package.workflow_version == WORKFLOW.version
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.check() == [] and run.implicit_problems() == []


def test_live_nothing_changes_before_the_human_decision_then_approved_actions_execute_and_verify():
    run = _run("tp-approve-all", live=True)
    detection = run.detect()
    assert run.environment.state_changing_calls() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.AWAITING_APPROVAL
    package = detection.package
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
    assert len(run.runtime.registry.list(incident_id=run.incident_id)) == 4  # terminate registers no control


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
    assert _selectors(elevated) == {"isolate_endpoint:PRD-APP-03", "terminate_process:PRD-APP-03/3120"}
    assert all(a.warnings for a in elevated)
    with pytest.raises(ApproverNotAllowedError):
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert run.environment.state_changing_calls() == []
    decision = run.decide({"decision": "APPROVE_ALL"}, approvers=["lead"])
    assert decision.report is not None and decision.report.overall.value == "CONTAINED"


def test_a_protected_domain_controller_is_elevated_and_allow_listed_targets_are_shown_not_executed():
    run = _run("legacy-03-guardrail-skips", live=True).play()
    package = run.detection.package
    assert {(e.action_type.value, e.target) for e in package.excluded_targets} == {
        ("block_domain", "updates.example.com"), ("block_ip", "10.20.30.40")}
    dc = next(a for a in package.actions if a.target == "DC-02")
    assert dc.approval_level is ApprovalLevel.ELEVATED and dc.warnings
    targets = {c.target for c in run.environment.state_changing_calls()}
    assert "updates.example.com" not in targets and "10.20.30.40" not in targets
    assert run.check() == []


def test_six_beaconing_hosts_exceed_the_blast_radius_cap_and_every_isolation_is_elevated():
    run = _run("legacy-04-blast-radius-many-hosts", live=False)
    detection = run.detect()
    isolations = [a for a in detection.package.actions if a.action_type.value == "isolate_endpoint"]
    assert len(isolations) == 6 and all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in isolations)
    blocks = [a for a in detection.package.actions if a.action_type.value.startswith("block_")]
    assert blocks and all(a.approval_level is ApprovalLevel.STANDARD for a in blocks)
    assert run.environment.state_changing_calls() == []


def test_restoration_needs_its_own_human_release_approval():
    run = _run("release-restoration", live=True)
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert len(controls) == 4
    calls = len(run.environment.state_changing_calls())
    run.propose_release()
    assert len(run.environment.state_changing_calls()) == calls  # proposing a release changes nothing
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["ai"])
    assert len(run.environment.state_changing_calls()) == calls
    result = run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert result.report is not None and result.report.overall.value == "RESTORED"
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.RESTORED


def test_rejected_package_closes_without_any_control():
    run = _run("tp-reject", live=True).play()
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.CLOSED


def test_a_degraded_source_does_not_block_the_recommendation():
    run = _run("degraded-source", live=False).play()
    workflow_run = run.workflow_run
    assert workflow_run.degraded_sources() == ("umbrella",)
    assert any("degraded source: umbrella" in note for note in workflow_run.notes)
    assert run.detection.package is not None and len(run.detection.package.actions) == 5
    assert run.check() == []


def test_beaconing_alone_proposes_nothing_and_changes_nothing():
    for name in ("benign-no-action", "legacy-02-benign-saas-heartbeat", "edge-unrated-beacon"):
        run = _run(name, live=True).play()
        assert run.detection.package is None, name
        assert run.environment.state_changing_calls() == [], name
        assert run.orchestrator.get_incident(run.incident_id).state is IncidentState.NOT_STARTED, name
        assert run.check() == [], name
        guard._reset_for_test_harness()


def test_a_shared_cdn_address_is_never_blocked_and_an_unisolatable_kiosk_is_a_manual_step():
    run = _run("legacy-06-shared-hosting-ip", live=True).play()
    assert "198.51.100.80" not in {c.target for c in run.environment.state_changing_calls()}
    notes = run.workflow_run.notes
    assert any(n.startswith("considered, not proposed: block_ip:198.51.100.80") for n in notes)
    assert any(n.startswith("manual step: isolate_endpoint:KIOSK-0007") for n in notes)
    assert "KIOSK-0007" not in {c.target for c in run.environment.state_changing_calls()}
    assert run.check() == []


def test_the_malware_handoff_reaches_the_notes_and_starts_nothing():
    run = _run("tp-approve-all", live=False).play()
    assert any(n.startswith(f"hand-off: run malware for {SHA}") for n in run.workflow_run.notes)
    assert run.environment.state_changing_calls() == []
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


@pytest.mark.parametrize("name", ["tp-approve-all", "edge-second-host-from-sightings", "legacy-01-confirmed-beaconing"])
def test_the_catalog_runs_this_workflow_for_its_incidents(name: str):
    catalog = discover_workflows()
    run = _run(name, live=False)
    incident = run.workflow_scenario.incident.model_copy(update={"workflow_id": "unassigned"})
    assert catalog.resolve(incident).definition.id == "c2"  # routed by technique or title, not by workflow_id
