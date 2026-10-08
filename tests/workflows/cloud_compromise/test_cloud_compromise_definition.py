"""The cloud-compromise WorkflowDefinition: validates, is discovered, carries no approval switch."""
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
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.cloud_compromise import HOOKS, WORKFLOW
from xdr_response.workflows.cloud_compromise.hooks import CloudCompromiseHooks
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.expr import names_used

REPO = Path(__file__).resolve().parents[3]
NOW = "2026-01-15T12:00:00Z"
CATALOG = discover_workflows()


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
    data = {"incident_id": "XDR-CC-T-1", "title": "Something happened", "severity": Severity.HIGH,
            "created_at": NOW, "workflow_id": "unassigned", "workflow_version": "0.0.0",
            "observables": [Observable(type=ObservableType.USER, value="jsmith@example.com")]}
    data.update(changes)
    return Incident.model_validate(data)


def test_the_definition_validates_and_round_trips():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    assert WORKFLOW.id == "cloud-compromise" and WORKFLOW.package_name == "cloud_compromise"
    assert WORKFLOW.legacy_id == "cloud-compromise"
    assert WORKFLOW.phase == 4 and WORKFLOW.default_severity is Severity.HIGH


def test_discovery_finds_the_workflow_and_its_hooks():
    found = CATALOG.get("cloud-compromise")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, CloudCompromiseHooks) and found.hooks is HOOKS
    assert found.module == "xdr_response.workflows.cloud_compromise"


def test_no_approval_switch_anywhere_in_the_definition():
    assert not (_walk_keys(WORKFLOW.model_dump(mode="json")) & APPROVAL_LIKE_KEYS)


def test_the_package_is_revoke_disable_remove_role_and_block_through_named_builders():
    expected = {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER, ActionType.REMOVE_PRIVILEGED_ROLE,
                ActionType.BLOCK_IP}
    assert {r.action for r in WORKFLOW.recommendations} == expected
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).category is ActionCategory.CONTAINMENT
        assert rule.builder in builders, "every rule uses a named builder (recommend, never execute)"
        assert rule.min_risk >= 50, "a cloud-compromise action needs at least MEDIUM risk backed by records"
        # Routing and approval are never workflow inputs; role removal only names the grant's scope (14.12.3).
        assert set(rule.params) <= ({"directory_scope_id"} if rule.action is ActionType.REMOVE_PRIVILEGED_ROLE
                                    else set()), rule.id
        assert names_used(rule.for_each) == {"facts"}, "rules iterate over the hooks' record-backed facts"
        assert names_used(rule.evidence) == {"item"}


def test_unverified_writes_are_never_recommended():
    """App credentials, consents and service principals have no VERIFIED write: manual steps only."""
    actions = {r.action for r in WORKFLOW.recommendations}
    assert ActionType.REVOKE_APP_CREDENTIALS not in actions
    assert ActionType.REMOVE_APPLICATION not in actions
    assert ActionType.CONFIRM_USER_COMPROMISED not in actions
    assert "umbrella" not in WORKFLOW.integrations(), "direct Umbrella IP blocking is UNVERIFIED"


def test_role_removal_is_always_elevated_by_the_catalog():
    assert get_action_spec(ActionType.REMOVE_PRIVILEGED_ROLE).always_elevated
    assert get_action_spec(ActionType.RESTORE_PRIVILEGED_ROLE).always_elevated


def test_investigation_steps_use_read_atomics_only():
    atomics = read_atomics()
    assert [s.atomic for s in WORKFLOW.investigation] == [
        "investigate_user", "investigate_authentication", "search_user_activity", "enrich_ip",
        "search_ip_enterprise"]
    for step in WORKFLOW.investigation:
        assert step.atomic in atomics
        assert get_action_spec(ActionType(step.atomic)).category in (ActionCategory.ENRICHMENT,
                                                                      ActionCategory.INVESTIGATION)


def test_integrations_and_expected_sources():
    assert set(WORKFLOW.integrations()) <= set(INTEGRATION_NAMES)
    assert WORKFLOW.expected_sources() == ("entra", "microsoft_cloud", "cisco_xdr")
    assert WORKFLOW.scoring.weights == {SignalCategory.PERSISTENCE: 1.0}


def test_mitre_mapping_is_the_responded_techniques_only():
    assert WORKFLOW.attack_ids() == {"T1078", "T1078.004", "T1098", "T1098.001", "T1098.003", "T1528"}
    assert {m.tactic for m in WORKFLOW.mitre} == {"TA0001", "TA0003", "TA0006"}
    assert "T1530" not in WORKFLOW.attack_ids(), "storage access is not investigated: no forced mapping"
    for rule in WORKFLOW.recommendations:
        assert set(rule.mitre) <= WORKFLOW.attack_ids()
    assert all(m.rationale.strip() for m in WORKFLOW.mitre)


def test_shared_techniques_keep_one_tactic_across_workflows():
    tactics: dict[str, set[str]] = {}
    for workflow_id in CATALOG.ids():
        for mapping in CATALOG.get(workflow_id).definition.mitre:
            tactics.setdefault(mapping.attack_id, set()).add(mapping.tactic)
    for mapping in WORKFLOW.mitre:
        assert tactics[mapping.attack_id] == {mapping.tactic}, mapping.attack_id


@pytest.mark.parametrize("changes, matches", [
    ({"trigger": {"mitre_techniques": ["T1098.001"]}}, True),
    ({"trigger": {"mitre_techniques": ["T1098.003"]}}, True),
    ({"trigger": {"mitre_techniques": ["T1528"]}}, True),
    ({"title": "New client secret on app registration Payroll Export"}, True),
    ({"title": "Risky OAuth consent grant by jsmith@example.com"}, True),
    ({"title": "Global Administrator directory role assigned to a new account"}, True),
    ({"trigger": {"mitre_techniques": ["T1078.004"]}}, False),  # a sign-in alone is account-takeover's
    ({"title": "Risky OAuth consent", "observables": []}, False),  # no user: nothing to investigate
    ({"title": "Ransomware on a file server"}, False),
])
def test_triggers(changes, matches):
    assert (WORKFLOW.matches(_incident(**changes)) is not None) is matches


@pytest.mark.parametrize("techniques, title, expected", [
    (("T1098.001", "T1078.004"), "Alert", "cloud-compromise"),
    (("T1528", "T1078.004"), "Alert", "cloud-compromise"),
    (("T1078.004",), "Alert", "account-takeover"),
    (("T1078.004",), "New client secret on app registration", "cloud-compromise"),
    (("T1621", "T1528"), "Alert", "mfa-fatigue"),
])
def test_routing_against_overlapping_workflows(techniques, title, expected):
    incident = _incident(trigger={"mitre_techniques": list(techniques)}, title=title)
    assert CATALOG.resolve(incident).id == expected


def test_the_workflow_outranks_the_workflow_it_hands_off_to():
    assert WORKFLOW.handoff_to == ("account-takeover",)

    def top(definition: WorkflowDefinition) -> int:
        return max(t.priority for t in definition.triggers if t.type != "manual")

    assert top(WORKFLOW) > top(CATALOG.get("account-takeover").definition)


def test_the_readme_and_scenarios_pass_the_validator():
    found = CATALOG.get("cloud-compromise")
    assert check_workflow(found, readme_root=REPO / "workflows",
                          scenario_root=REPO / "tests" / "fixtures" / "workflows") == []


def test_known_limitations_are_listed():
    assert len(WORKFLOW.known_limitations) >= 5
    assert any("UNVERIFIED" in text for text in WORKFLOW.known_limitations)
    assert any("manual step" in text for text in WORKFLOW.known_limitations)
