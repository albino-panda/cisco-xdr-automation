"""Ransomware workflow definition: validation, triggers, rules, MITRE, README and scenario coverage."""
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
from xdr_response.workflows.definition import WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.ransomware import HOOKS, WORKFLOW
from xdr_response.workflows.ransomware.hooks import RansomwareHooks
from xdr_response.workflows.runner import RuleOutcomeStatus

REPO = Path(__file__).resolve().parents[3]
SCENARIOS = sorted((WORKFLOW_SCENARIO_DIR / "ransomware").glob("*.yaml"))


def _incident(title: str = "Alert", techniques: tuple[str, ...] = (), workflow_id: str = "xdr-generic") -> Incident:
    return Incident(incident_id="XDR-RW-9100", title=title, severity=Severity.HIGH, created_at=SIM_NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0",
                    observables=(Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047"),),
                    trigger={"mitre_techniques": list(techniques)})


def test_the_definition_validates_and_is_discovered_with_its_hooks():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("ransomware")
    assert found.definition == WORKFLOW and isinstance(found.hooks, RansomwareHooks) and found.hooks is HOOKS
    assert (WORKFLOW.id, WORKFLOW.phase, WORKFLOW.legacy_id, WORKFLOW.default_severity) == (
        "ransomware", 2, "ransomware", Severity.CRITICAL)


@pytest.mark.parametrize("title, techniques, expected", [
    ("Alert", ("T1486",), True),
    ("Alert", ("T1490",), True),
    ("Alert", ("T1486.001",), True),  # a reported sub-technique matches its parent
    ("Ransomware detected on finance workstation", (), True),
    ("Mass file modification on SRV-BKP-02", (), True),
    ("File share encrypted from HR workstation", (), True),
    ("Files encrypted on TH-LT-1047", (), True),
    ("Mass encryption of documents on SRV-FS-01", (), True),
    # An encrypted network channel is command and control (c2, T1573), not ransomware (14.12.2).
    ("Encrypted beaconing from TH-LT-5520 to static-assets.test", (), False),
    ("Encrypted channel to a newly registered domain", (), False),
    ("Phishing reported by a user", ("T1566",), False),
])
def test_triggers(title: str, techniques: tuple[str, ...], expected: bool):
    assert (WORKFLOW.matches(_incident(title, techniques)) is not None) is expected


def test_the_manual_trigger_never_matches_automatically_but_an_explicit_workflow_id_routes():
    manual = [t for t in WORKFLOW.triggers if t.type == "manual"]
    assert manual and not manual[0].matches(_incident("Ransomware", ("T1486",)))
    catalog = discover_workflows()
    assert catalog.resolve(_incident("Unrelated title", (), workflow_id="ransomware")).definition.id == "ransomware"


def test_the_package_covers_the_brief():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.ISOLATE_ENDPOINT, ActionType.BLOCK_HASH, ActionType.BLOCK_DOMAIN,
                       ActionType.BLOCK_URL, ActionType.BLOCK_IP, ActionType.REVOKE_SESSIONS,
                       ActionType.DISABLE_USER, ActionType.QUARANTINE_EMAIL}
    builders = {r.builder for r in WORKFLOW.recommendations if r.action is ActionType.ISOLATE_ENDPOINT}
    assert builders == {"isolate_secure_endpoint", "isolate_defender_endpoint"}
    assert all(r.builder for r in WORKFLOW.recommendations)
    assert all(r.min_risk >= 50 for r in WORKFLOW.recommendations)


def test_the_investigation_covers_the_brief():
    atomics = {s.atomic for s in WORKFLOW.investigation}
    assert {"investigate_endpoint", "enrich_hash", "search_hash_enterprise", "search_related_endpoints",
            "investigate_user", "investigate_authentication", "investigate_email", "search_email_campaign",
            "enrich_domain", "enrich_url", "enrich_ip", "search_domain_enterprise"} == atomics


def test_integrations():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_endpoint", "entra"]
    assert WORKFLOW.expected_sources() == ("secure_endpoint", "entra")
    assert {"defender_endpoint", "umbrella", "meraki", "secure_email", "virustotal"} <= {
        r.integration for r in WORKFLOW.optional_integrations}


def test_mitre_mapping_has_no_forced_or_legacy_only_ids():
    assert WORKFLOW.attack_ids() == {"T1486", "T1490", "T1570", "T1071", "T1078", "T1566"}
    assert {m.tactic for m in WORKFLOW.mitre} == {"TA0040", "TA0008", "TA0011", "TA0001"}
    assert "T1489" not in WORKFLOW.attack_ids()  # no record kind carries service-stop evidence
    assert all(r.mitre for r in WORKFLOW.recommendations)


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
    text = (REPO / "workflows" / "ransomware" / "README.md").read_text(encoding="utf-8")
    assert readme_checker.check_readme(WORKFLOW, text) == []


def test_the_legacy_spec_is_migrated():
    legacy = sorted(s for s in SCENARIOS if s.name.startswith("legacy-"))
    assert len(legacy) == 6
    sources = {load_workflow_scenario(p).legacy_source for p in legacy}
    assert sources == {f"workflows/ransomware/scenarios/{name}.yaml" for name in (
        "01-workstation-encryption", "02-benign-backup-reencryption", "03-protected-hypervisor-and-admins",
        "04-outbreak-blast-radius", "05-fresh-build-remote-share-encryption", "06-widespread-hash-not-blocked")}
    assert not (REPO / "workflows" / "ransomware" / "workflow.yaml").exists()


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
    assert check_coverage("ransomware", scenarios, WORKFLOW, proposed_rules=proposed, unrouted_rules=unrouted) == []
    assert proposed | (unrouted & {r.id for r in WORKFLOW.recommendations
                                if not executable_anywhere(r.action)}) == {r.id for r in WORKFLOW.recommendations}
