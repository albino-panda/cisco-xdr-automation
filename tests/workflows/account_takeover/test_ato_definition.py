"""The account-takeover WorkflowDefinition: validates, is discovered, carries no approval switch."""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.validation.check_workflow_readmes import check_workflow
from xdr_response.atomics import containment_builders, read_atomics
from xdr_response.models import (
    INTEGRATION_NAMES,
    ActionCategory,
    ActionType,
    Incident,
    Observable,
    ObservableType,
    Severity,
    get_action_spec,
)
from xdr_response.workflows.account_takeover import HOOKS, WORKFLOW
from xdr_response.workflows.account_takeover.hooks import AccountTakeoverHooks
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.expr import names_used

REPO = Path(__file__).resolve().parents[3]
NOW = "2026-01-15T12:00:00Z"


def _walk_keys(node) -> set[str]:
    keys: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            keys.add(str(key).lower())
            keys |= _walk_keys(value)
    elif isinstance(node, (list, tuple)):
        for value in node:
            keys |= _walk_keys(value)
    return keys


def _incident(**changes) -> Incident:
    data = {"incident_id": "XDR-ATO-T-1", "title": "Something happened", "severity": Severity.HIGH,
            "created_at": NOW, "workflow_id": "unassigned", "workflow_version": "0.0.0",
            "observables": [Observable(type=ObservableType.USER, value="jsmith@example.com")]}
    data.update(changes)
    return Incident.model_validate(data)


def test_the_definition_validates_and_round_trips():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    assert WORKFLOW.id == "account-takeover" and WORKFLOW.package_name == "account_takeover"
    assert WORKFLOW.legacy_id == "account-takeover"
    assert WORKFLOW.phase == 2 and WORKFLOW.default_severity is Severity.HIGH


def test_discovery_finds_the_workflow_and_its_hooks():
    found = discover_workflows().get("account-takeover")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, AccountTakeoverHooks) and found.hooks is HOOKS
    assert found.module == "xdr_response.workflows.account_takeover"


def test_no_approval_switch_anywhere_in_the_definition():
    assert not (_walk_keys(WORKFLOW.model_dump(mode="json")) & APPROVAL_LIKE_KEYS)


def test_every_rule_recommends_a_containment_action_through_a_known_builder():
    expected = {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER, ActionType.ISOLATE_ENDPOINT, ActionType.BLOCK_IP}
    assert {r.action for r in WORKFLOW.recommendations} == expected
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).category is ActionCategory.CONTAINMENT
        assert rule.builder is None or rule.builder in builders
        assert rule.min_risk >= 50, "a takeover action needs at least MEDIUM risk backed by records"
        assert not rule.params, "the rules pass no params: routing and approval are not workflow inputs"
        assert names_used(rule.for_each) == {"facts"}, "rules iterate over the hooks' record-backed facts"
        assert names_used(rule.evidence) == {"item"}


def test_investigation_steps_use_read_atomics_only():
    atomics = read_atomics()
    assert [s.atomic for s in WORKFLOW.investigation] == [
        "investigate_user", "investigate_authentication", "search_user_activity", "enrich_ip",
        "search_ip_enterprise", "investigate_endpoint"]
    for step in WORKFLOW.investigation:
        assert step.atomic in atomics
        assert get_action_spec(ActionType(step.atomic)).category in (ActionCategory.ENRICHMENT,
                                                                      ActionCategory.INVESTIGATION)


def test_integrations_are_known_and_entra_and_cisco_xdr_are_expected_sources():
    assert set(WORKFLOW.integrations()) <= set(INTEGRATION_NAMES)
    assert WORKFLOW.expected_sources() == ("entra", "cisco_xdr")
    assert "umbrella" not in WORKFLOW.integrations(), "direct Umbrella IP blocking is UNVERIFIED"


def test_mitre_mapping_is_the_responded_techniques_only():
    assert WORKFLOW.attack_ids() == {"T1078", "T1078.004", "T1539", "T1621"}
    assert {m.tactic for m in WORKFLOW.mitre} == {"TA0001", "TA0006"}
    for rule in WORKFLOW.recommendations:
        assert set(rule.mitre) <= WORKFLOW.attack_ids()
    assert all(m.rationale.strip() for m in WORKFLOW.mitre)


@pytest.mark.parametrize("changes, matches", [
    ({"trigger": {"mitre_techniques": ["T1078.004"]}}, True),
    ({"trigger": {"mitre_techniques": ["T1539"]}}, True),
    ({"title": "Entra risky sign-in for jsmith@example.com"}, True),
    ({"title": "Impossible travel for a sales user"}, True),
    ({"trigger": {"mitre_techniques": ["T1621"]}}, False),  # MFA prompt floods route to mfa-fatigue
    ({"title": "Entra risky sign-in", "observables": []}, False),  # no user: nothing to investigate
    ({"title": "Ransomware on a file server"}, False),
])
def test_triggers(changes, matches):
    assert (WORKFLOW.matches(_incident(**changes)) is not None) is matches


def test_the_readme_and_scenarios_pass_the_validator():
    found = discover_workflows().get("account-takeover")
    assert check_workflow(found, readme_root=REPO / "workflows",
                          scenario_root=REPO / "tests" / "fixtures" / "workflows") == []


def test_known_limitations_are_listed():
    assert len(WORKFLOW.known_limitations) >= 5
    assert any("UNVERIFIED" in text for text in WORKFLOW.known_limitations)
