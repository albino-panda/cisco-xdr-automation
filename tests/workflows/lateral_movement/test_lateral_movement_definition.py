"""Lateral-movement workflow definition: validation, triggers, rules, MITRE, README and scenario coverage."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from tools.simulator.scenario import SIM_NOW
from tools.simulator.workflow_scenario import (
    WORKFLOW_SCENARIO_DIR,
    WorkflowScenarioRun,
    check_coverage,
    load_workflow_scenario,
)
from tools.validation import check_workflow_readmes as readme_checker
from tools.simulator.workflow_scenario import executable_anywhere
from xdr_response import guard
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity
from xdr_response.models.catalog import get_action_spec
from xdr_response.workflows.definition import WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.lateral_movement import HOOKS, WORKFLOW
from xdr_response.workflows.lateral_movement.hooks import LATERAL_PORTS, LateralMovementHooks
from xdr_response.workflows.lateral_movement.definition import _PORTS
from xdr_response.workflows.runner import RuleOutcomeStatus

REPO = Path(__file__).resolve().parents[3]
SCENARIOS = sorted((WORKFLOW_SCENARIO_DIR / "lateral-movement").glob("*.yaml"))


def _incident(title: str = "Alert", techniques: tuple[str, ...] = (), workflow_id: str = "xdr-generic") -> Incident:
    return Incident(incident_id="XDR-LM-9100", title=title, severity=Severity.HIGH, created_at=SIM_NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0",
                    observables=(Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047"),),
                    trigger={"mitre_techniques": list(techniques)})


def test_the_definition_validates_and_is_discovered_with_its_hooks():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("lateral-movement")
    assert found.definition == WORKFLOW and isinstance(found.hooks, LateralMovementHooks) and found.hooks is HOOKS
    assert (WORKFLOW.id, WORKFLOW.phase, WORKFLOW.legacy_id, WORKFLOW.default_severity) == (
        "lateral-movement", 3, "lateral-movement", Severity.HIGH)
    assert WORKFLOW.package_name == "lateral_movement"


@pytest.mark.parametrize("title, techniques, expected", [
    ("Alert", ("T1021.001",), True),  # a reported sub-technique matches its parent
    ("Alert", ("T1021.002",), True),
    ("Alert", ("T1021.006",), True),
    ("Alert", ("T1570",), True),
    ("Remote logons from ws-fin-07 to srv-app-02", (), True),
    ("Unusual WinRM sessions to web servers", (), True),
    ("Remote service created on dc-01 over admin share", (), True),
    ("PsExec-like service creation on TH-SRV-0310", (), True),
    ("Unexpected east-west SMB traffic", (), True),
    ("Third-party portal sign-in", (), False),  # contains "rdp" inside a word: never a title match
    ("Phishing reported by a user", ("T1566",), False),
])
def test_triggers(title: str, techniques: tuple[str, ...], expected: bool):
    assert (WORKFLOW.matches(_incident(title, techniques)) is not None) is expected


def test_routing_ransomware_wins_when_encryption_is_reported_and_an_explicit_id_routes_here():
    catalog = discover_workflows()
    assert catalog.resolve(_incident("Alert", ("T1021.002",))).definition.id == "lateral-movement"
    assert catalog.resolve(_incident("Alert", ("T1021.002", "T1486"))).definition.id == "ransomware"
    assert catalog.resolve(_incident("Unrelated", (), workflow_id="lateral-movement")).definition.id == \
        "lateral-movement"
    manual = [t for t in WORKFLOW.triggers if t.type == "manual"]
    assert manual and not manual[0].matches(_incident("Lateral movement", ("T1021",)))


def test_the_package_covers_the_brief():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.ISOLATE_ENDPOINT, ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER,
                       ActionType.BLOCK_HASH, ActionType.BLOCK_IP}
    builders = {r.builder for r in WORKFLOW.recommendations if r.action is ActionType.ISOLATE_ENDPOINT}
    assert builders == {"isolate_secure_endpoint", "isolate_defender_endpoint"}
    assert all(r.builder for r in WORKFLOW.recommendations)
    assert all(r.min_risk >= 50 for r in WORKFLOW.recommendations)
    # recommendations only: every action is a containment action that the lifecycle executes after approval
    assert all(get_action_spec(r.action).category.value in ("CONTAINMENT", "REMEDIATION")
               for r in WORKFLOW.recommendations)


def test_the_investigation_covers_source_targets_credential_tool_and_authentication():
    atomics = [s.atomic for s in WORKFLOW.investigation]
    assert set(atomics) == {"investigate_endpoint", "search_related_endpoints", "enrich_hash",
                            "search_hash_enterprise", "investigate_user", "investigate_authentication", "enrich_ip"}
    assert atomics.count("investigate_endpoint") == 3  # incident hosts, resolved peers, tool holders


def test_the_port_list_of_the_definition_matches_the_hooks():
    assert sorted(int(p) for p in _PORTS.strip("[]").split(",")) == sorted(LATERAL_PORTS)


def test_integrations_are_verified_sources_only():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_endpoint", "entra"]
    assert WORKFLOW.expected_sources() == ("secure_endpoint", "entra")
    optional = {r.integration for r in WORKFLOW.optional_integrations}
    assert {"defender_endpoint", "microsoft_cloud", "splunk", "meraki", "virustotal"} <= optional
    assert "secure_cloud_analytics" not in WORKFLOW.integrations()  # every operation is UNVERIFIED


def test_mitre_mapping_has_no_forced_or_legacy_only_ids():
    assert WORKFLOW.attack_ids() == {"T1021", "T1021.001", "T1021.002", "T1021.006", "T1570", "T1569",
                                     "T1569.002", "T1047", "T1078"}
    assert {m.tactic for m in WORKFLOW.mitre} == {"TA0008", "TA0002", "TA0001"}
    assert all(r.mitre for r in WORKFLOW.recommendations)
    assert all(m.rationale for m in WORKFLOW.mitre)


def test_shared_techniques_keep_the_tactic_other_workflows_use():
    catalog = discover_workflows()
    seen: dict[str, set[str]] = {}
    for workflow_id in catalog.ids():
        for mapping in catalog.get(workflow_id).definition.mitre:
            seen.setdefault(mapping.technique, set()).add(mapping.tactic)
    for mapping in WORKFLOW.mitre:
        assert seen[mapping.technique] == {mapping.tactic}, mapping.technique


def test_hand_offs_are_related_workflows():
    assert set(WORKFLOW.handoff_to) == {"account-takeover", "credential-dumping"}
    assert set(WORKFLOW.handoff_to) <= set(WORKFLOW.related_workflows)


def test_the_definition_cannot_carry_an_approval_switch():
    data = WORKFLOW.model_dump(mode="json")
    data["recommendations"][0]["params"] = {"approved": "True"}
    with pytest.raises(ValidationError):
        WorkflowDefinition.model_validate(data)
    data = WORKFLOW.model_dump(mode="json")
    data["triggers"][0]["auto_approve"] = True
    with pytest.raises(ValidationError):
        WorkflowDefinition.model_validate(data)


def test_the_readme_passes_the_validator():
    text = (REPO / "workflows" / "lateral-movement" / "README.md").read_text(encoding="utf-8")
    assert readme_checker.check_readme(WORKFLOW, text) == []


def test_the_legacy_spec_is_migrated():
    legacy = sorted(s for s in SCENARIOS if s.name.startswith("legacy-"))
    assert len(legacy) == 5
    sources = {load_workflow_scenario(p).legacy_source for p in legacy}
    assert sources == {f"workflows/lateral-movement/scenarios/{name}.yaml" for name in (
        "01-rdp-pivot-confirmed", "02-sanctioned-admin-winrm", "03-domain-controller-destination",
        "04-admin-share-fan-out", "05-tool-transfer-quiet-source")}
    assert not (REPO / "workflows" / "lateral-movement" / "workflow.yaml").exists()
    assert not (REPO / "workflows" / "lateral-movement" / "scenarios").exists()


def test_every_rule_is_proposed_in_some_scenario_and_the_minimum_set_is_met():
    scenarios = [load_workflow_scenario(p) for p in SCENARIOS]
    proposed: set[str] = set()
    unrouted: set[str] = set()
    for scenario in scenarios:
        run = WorkflowScenarioRun(scenario, live=False)
        run.detect()
        assert run.workflow_run is not None, scenario.name
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        unrouted |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)}
        guard._reset_for_test_harness()  # one runtime per process: reset between the runs of this test
    assert check_coverage("lateral-movement", scenarios, WORKFLOW, proposed_rules=proposed, unrouted_rules=unrouted) == []
    assert proposed | (unrouted & {r.id for r in WORKFLOW.recommendations
                                if not executable_anywhere(r.action)}) == {r.id for r in WORKFLOW.recommendations}
    names = {s.name for s in scenarios}
    assert {"tp-approve-all", "tp-approve-selected", "tp-reject", "benign-no-action", "degraded-source",
            "critical-asset-elevated", "partial-failure", "dry-run", "release-restoration",
            "edge-admin-jump-host"} <= names
    assert len([n for n in names if n.startswith("edge-")]) >= 2
