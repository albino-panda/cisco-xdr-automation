"""The mfa-fatigue definition: validation, discovery, triggers, rules and README (fake data only)."""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.simulator.workflow_scenario import check_coverage, load_workflow_scenario
from tools.validation.check_workflow_readmes import check_readme
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.models.catalog import ActionCategory
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.mfa_fatigue import HOOKS, WORKFLOW
from xdr_response.workflows.mfa_fatigue.hooks import MfaFatigueHooks

REPO = Path(__file__).resolve().parents[3]
SCENARIOS = REPO / "tests" / "fixtures" / "workflows" / "mfa-fatigue"
README = REPO / "workflows" / "mfa-fatigue" / "README.md"


def _incident(**fields) -> Incident:
    # "triage" is neither a workflow nor a legacy spec id, so routing falls through to the triggers
    base = {"incident_id": "XDR-MFA-9100", "title": "Suspicious sign-in", "severity": Severity.HIGH,
            "created_at": "2026-01-15T12:00:00Z", "workflow_id": "triage", "workflow_version": "0.0.0",
            "observables": (Observable(type=ObservableType.USER, value="jsmith@example.com"),)}
    return Incident.model_validate({**base, **fields})


def test_definition_validates_and_round_trips():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    assert WORKFLOW.id == "mfa-fatigue" and WORKFLOW.package_name == "mfa_fatigue"
    assert WORKFLOW.phase == 2 and WORKFLOW.legacy_id is None and WORKFLOW.default_severity is Severity.HIGH


def test_the_workflow_is_discovered_with_its_hooks():
    discovered = discover_workflows().get("mfa-fatigue")
    assert discovered.definition == WORKFLOW
    assert isinstance(discovered.hooks, MfaFatigueHooks) and discovered.hooks is HOOKS


def test_entra_is_the_required_source_and_every_other_integration_is_optional():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["entra"]
    assert WORKFLOW.expected_sources() == ("entra",)
    optional = {r.integration for r in WORKFLOW.optional_integrations}
    assert {"microsoft_cloud", "splunk", "secure_endpoint", "defender_endpoint", "meraki"} <= optional


def test_investigation_covers_user_ip_endpoint_and_post_authentication_activity():
    atomics = [s.atomic for s in WORKFLOW.investigation]
    assert atomics == ["investigate_authentication", "investigate_user", "search_user_activity", "enrich_ip",
                       "investigate_ip", "investigate_endpoint"]


def test_the_package_is_revoke_disable_isolate_and_block():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER, ActionType.ISOLATE_ENDPOINT,
                       ActionType.BLOCK_IP}
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).category is ActionCategory.CONTAINMENT
        assert rule.min_risk >= 60  # below: "considered, not proposed", reported in the notes
        assert rule.evidence.strip()


def test_no_approval_switch_anywhere_in_the_definition():
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                yield str(key).lower()
                yield from walk(value)
        elif isinstance(node, (list, tuple)):
            for value in node:
                yield from walk(value)
    assert not set(walk(WORKFLOW.model_dump(mode="json"))) & APPROVAL_LIKE_KEYS


def test_mitre_mapping_has_no_forced_ids():
    assert set(WORKFLOW.attack_ids()) == {"T1621", "T1078", "T1078.004", "T1114", "T1114.003", "T1098",
                                          "T1098.003"}
    assert {m.tactic for m in WORKFLOW.mitre} == {"TA0006", "TA0001", "TA0009", "TA0003"}
    assert all(m.rationale for m in WORKFLOW.mitre)


@pytest.mark.parametrize("fields", [
    {"trigger": {"source": "entra", "mitre_techniques": ["T1621"]}},
    {"title": "MFA fatigue pattern followed by successful sign-in"},
    {"title": "Push bombing against a finance user"},
])
def test_automatic_triggers_match_mfa_fatigue_incidents(fields):
    assert WORKFLOW.matches(_incident(**fields)) is not None


def test_t1621_without_a_user_observable_does_not_match_the_technique_trigger():
    incident = _incident(trigger={"mitre_techniques": ["T1621"]},
                         observables=(Observable(type=ObservableType.IP, value="203.0.113.80"),))
    assert WORKFLOW.matches(incident) is None


def test_an_unrelated_incident_does_not_match():
    assert WORKFLOW.matches(_incident(trigger={"mitre_techniques": ["T1486"]}, title="Ransomware")) is None


def test_a_t1621_incident_routes_to_this_workflow():
    incident = _incident(trigger={"source": "entra", "mitre_techniques": ["T1621"]})
    assert discover_workflows().resolve(incident).definition.id == "mfa-fatigue"


def test_readme_passes_the_validator():
    assert check_readme(WORKFLOW, README.read_text(encoding="utf-8")) == []


def test_scenarios_meet_the_minimum_set():
    scenarios = [load_workflow_scenario(p) for p in sorted(SCENARIOS.glob("*.yaml"))]
    assert check_coverage("mfa-fatigue", scenarios, WORKFLOW) == []
    legacy = [s for s in scenarios if "legacy" in s.tags]
    assert [s.legacy_source for s in legacy] == ["workflows/account-takeover/scenarios/05-mfa-fatigue-approved.yaml"]
