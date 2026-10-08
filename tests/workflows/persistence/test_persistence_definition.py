"""Persistence definition: validation, triggers and routing, MITRE without forced mappings, rule shape."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from tools.simulator.workflow_scenario import WORKFLOW_SCENARIO_DIR, check_coverage, load_workflow_scenario
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.persistence import HOOKS, WORKFLOW
from xdr_response.workflows.persistence.definition import ATTACK_IDS, MAX_HASH_BLOCK_PREVALENCE
from xdr_response.workflows.persistence.hooks import PersistenceHooks

REPO = Path(__file__).resolve().parents[3]
CATALOG = discover_workflows()


def _incident(*observables: tuple[ObservableType, str], title: str = "Endpoint alert",
              techniques: tuple[str, ...] = ()) -> Incident:
    """An incident not yet assigned to a migrated workflow (routing by triggers)."""
    trigger: dict[str, Any] = {"source": "secure_endpoint", "mitre_techniques": list(techniques)}
    return Incident(incident_id="XDR-PER-ROUTE", title=title, severity=Severity.HIGH,
                    created_at=datetime(2026, 1, 15, 12, tzinfo=timezone.utc), source="secure_endpoint",
                    workflow_id="xdr-generic", workflow_version="0.0.0",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), trigger=trigger)


def _walk_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in _walk_keys(v)}
    if isinstance(value, (list, tuple)):
        return {k for v in value for k in _walk_keys(v)}
    return set()


def test_the_definition_validates_and_is_discovered():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = CATALOG.get("persistence")
    assert found.definition == WORKFLOW and isinstance(found.hooks, PersistenceHooks) and found.hooks is HOOKS
    assert WORKFLOW.package_name == "persistence" and WORKFLOW.legacy_id == "persistence" and WORKFLOW.phase == 3
    assert WORKFLOW.default_severity is Severity.MEDIUM


def test_no_approval_switch_anywhere_in_the_definition():
    assert not _walk_keys(WORKFLOW.model_dump(mode="json")) & APPROVAL_LIKE_KEYS


def test_integrations_are_the_endpoint_and_reputation_sources():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_endpoint", "virustotal"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {"defender_endpoint", "alienvault_otx",
                                                                       "cisco_xdr"}
    assert WORKFLOW.expected_sources() == ("secure_endpoint", "virustotal")


def test_recommendations_are_the_brief_package_and_never_remove_persistence_automatically():
    actions = {r.id: r.action for r in WORKFLOW.recommendations}
    assert actions == {
        "isolate_persistence_host_secure_endpoint": ActionType.ISOLATE_ENDPOINT,
        "isolate_persistence_host_defender_endpoint": ActionType.ISOLATE_ENDPOINT,
        "terminate_running_persisted_process": ActionType.TERMINATE_PROCESS,
        "block_malicious_persisted_binary": ActionType.BLOCK_HASH,
    }
    # removal has no VERIFIED write and no catalog integration: a manual step (hook), never a rule
    assert ActionType.REMOVE_PERSISTENCE not in actions.values()
    assert all(r.min_risk >= 50 for r in WORKFLOW.recommendations)
    block = next(r for r in WORKFLOW.recommendations if r.action is ActionType.BLOCK_HASH)
    assert str(MAX_HASH_BLOCK_PREVALENCE) in block.when


def test_mitre_mapping_is_persistence_only_without_forced_mappings():
    assert {m.tactic for m in WORKFLOW.mitre} == {"TA0003"}
    assert {m.attack_id for m in WORKFLOW.mitre} == set(ATTACK_IDS)
    assert WORKFLOW.attack_ids() == frozenset(ATTACK_IDS) | {"T1547", "T1053", "T1543", "T1546", "T1176"}
    assert "T1136" not in WORKFLOW.attack_ids()  # account creation is not handled (known limitation)
    assert all(m.rationale for m in WORKFLOW.mitre)
    assert any("T1136" in limitation for limitation in WORKFLOW.known_limitations)


@pytest.mark.parametrize("technique", ATTACK_IDS)
def test_a_persistence_technique_routes_here(technique: str):
    incident = _incident((ObservableType.HOSTNAME, "TH-LT-1047"), techniques=(technique,))
    assert CATALOG.resolve(incident).definition.id == "persistence"


@pytest.mark.parametrize("title", ["New Run key value launching unknown binary on TH-LT-1047",
                                   "Scheduled task created on DC-01 running unsigned binary",
                                   "New service installed on TH-LT-2201",
                                   "WMI event subscription created on TH-LT-2210",
                                   "Browser extension installed from outside the store on TH-LT-4402"])
def test_a_persistence_title_with_an_endpoint_routes_here(title: str):
    incident = _incident((ObservableType.HOSTNAME, "TH-LT-1047"), title=title)
    assert CATALOG.resolve(incident).definition.id == "persistence"


def test_a_title_without_an_endpoint_does_not_route_here():
    incident = _incident((ObservableType.SHA256, "0dd5a1e5" * 8), title="New service installed somewhere")
    resolved = CATALOG.resolve(incident)
    assert resolved is None or resolved.definition.id != "persistence"


def test_persistence_wins_over_malware_and_ransomware_wins_over_persistence():
    both = _incident((ObservableType.HOSTNAME, "TH-LT-1047"), (ObservableType.SHA256, "0dd5a1e5" * 8),
                     techniques=("T1204.002", "T1547.001"))
    assert CATALOG.resolve(both).definition.id == "persistence"
    if "ransomware" in CATALOG.ids():
        ransom = _incident((ObservableType.HOSTNAME, "TH-LT-1047"), techniques=("T1486", "T1053.005"))
        assert CATALOG.resolve(ransom).definition.id == "ransomware"


def test_the_static_scenario_coverage_is_complete():
    scenarios = [load_workflow_scenario(p) for p in sorted((WORKFLOW_SCENARIO_DIR / "persistence").glob("*.yaml"))]
    assert check_coverage("persistence", scenarios, WORKFLOW) == []


def test_the_legacy_spec_is_deleted_and_the_readme_stays():
    assert not (REPO / "workflows" / "persistence" / "workflow.yaml").exists()
    assert not (REPO / "workflows" / "persistence" / "scenarios").exists()
    assert (REPO / "workflows" / "persistence" / "README.md").is_file()


def test_related_workflows_exist_and_nothing_is_handed_off():
    assert WORKFLOW.handoff_to == ()
    for workflow_id in WORKFLOW.related_workflows:
        assert (REPO / "workflows" / workflow_id / "README.md").is_file(), workflow_id
