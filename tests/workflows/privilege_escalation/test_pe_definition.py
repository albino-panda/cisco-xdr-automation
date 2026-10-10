"""The privilege-escalation WorkflowDefinition: validates, is discovered, carries no approval switch."""
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
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.expr import names_used
from xdr_response.workflows.privilege_escalation import HOOKS, WORKFLOW
from xdr_response.workflows.privilege_escalation.hooks import PrivilegeEscalationHooks

REPO = Path(__file__).resolve().parents[3]
NOW = "2026-01-15T12:00:00Z"
CATALOG = discover_workflows()
O = ObservableType


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


def _incident(observables=((O.USER, "jsmith@example.com"),), **changes) -> Incident:
    data = {"incident_id": "XDR-PE-T-1", "title": "Something happened", "severity": Severity.HIGH,
            "created_at": NOW, "workflow_id": "unassigned", "workflow_version": "0.0.0",
            "observables": [Observable(type=t, value=v) for t, v in observables]}
    data.update(changes)
    return Incident.model_validate(data)


def test_the_definition_validates_and_round_trips():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    assert WORKFLOW.id == "privilege-escalation" and WORKFLOW.package_name == "privilege_escalation"
    assert WORKFLOW.legacy_id == "privilege-escalation"
    assert WORKFLOW.phase == 5 and WORKFLOW.default_severity is Severity.HIGH


def test_discovery_finds_the_workflow_and_its_hooks():
    found = CATALOG.get("privilege-escalation")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, PrivilegeEscalationHooks) and found.hooks is HOOKS
    assert found.module == "xdr_response.workflows.privilege_escalation"


def test_the_legacy_spec_is_gone_after_migration():
    legacy = REPO / "workflows" / "privilege-escalation"
    assert not (legacy / "workflow.yaml").exists()
    assert not (legacy / "scenarios").exists()
    migrated = sorted((REPO / "tests" / "fixtures" / "workflows" / "privilege-escalation").glob("legacy-*.yaml"))
    assert len(migrated) == 5


def test_no_approval_switch_anywhere_in_the_definition():
    assert not (_walk_keys(WORKFLOW.model_dump(mode="json")) & APPROVAL_LIKE_KEYS)


def test_the_package_is_remove_role_revoke_disable_and_isolate_through_named_builders():
    expected = {ActionType.REMOVE_PRIVILEGED_ROLE, ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER,
                ActionType.ISOLATE_ENDPOINT}
    assert {r.action for r in WORKFLOW.recommendations} == expected
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).category is ActionCategory.CONTAINMENT
        assert rule.builder in builders, "every rule uses a named builder (recommend, never execute)"
        assert rule.min_risk >= 50, "a privilege-escalation action needs at least MEDIUM risk backed by records"
        assert names_used(rule.for_each) == {"facts"}, "rules iterate over the hooks' record-backed facts"
        assert names_used(rule.evidence) == {"item"}
    params = {r.id: set(r.params) for r in WORKFLOW.recommendations}
    assert params["remove_unauthorized_role"] == {"directory_scope_id"}
    assert params["isolate_originating_endpoint_secure_endpoint"] == {"connector_guid"}
    assert not params["revoke_escalation_sessions"] and not params["disable_escalation_identity"]


def test_an_account_the_change_made_privileged_is_passed_as_privileged_context():
    """The workflow adds context (never removes it): the account an anomalous change elevated is privileged."""
    rules = {r.id: r for r in WORKFLOW.recommendations}
    assert "'privileged': True" in rules["remove_unauthorized_role"].asset
    for rule_id in ("revoke_escalation_sessions", "disable_escalation_identity"):
        assert "'privileged': item.privileged" in rules[rule_id].asset


def test_unverified_writes_are_never_recommended():
    """Group membership, app permissions and service principals have no VERIFIED write: manual steps only."""
    actions = {r.action for r in WORKFLOW.recommendations}
    for action in (ActionType.REVOKE_APP_CREDENTIALS, ActionType.REMOVE_APPLICATION,
                   ActionType.CONFIRM_USER_COMPROMISED, ActionType.RESET_PASSWORD, ActionType.REMOVE_PERSISTENCE):
        assert action not in actions


def test_role_removal_is_always_elevated_by_the_catalog():
    assert get_action_spec(ActionType.REMOVE_PRIVILEGED_ROLE).always_elevated
    assert get_action_spec(ActionType.RESTORE_PRIVILEGED_ROLE).always_elevated


def test_investigation_steps_use_read_atomics_only():
    atomics = read_atomics()
    assert [s.atomic for s in WORKFLOW.investigation] == [
        "investigate_endpoint", "enrich_hash", "investigate_user", "search_user_activity", "investigate_user",
        "search_user_activity", "investigate_authentication"]
    for step in WORKFLOW.investigation:
        assert step.atomic in atomics
        assert get_action_spec(ActionType(step.atomic)).category in (ActionCategory.ENRICHMENT,
                                                                      ActionCategory.INVESTIGATION)


def test_integrations_and_expected_sources():
    assert set(WORKFLOW.integrations()) <= set(INTEGRATION_NAMES)
    assert WORKFLOW.expected_sources() == ("entra", "secure_endpoint")
    assert WORKFLOW.scoring.weights == {SignalCategory.PERSISTENCE: 1.0}
    assert "umbrella" not in WORKFLOW.integrations() and "meraki" not in WORKFLOW.integrations()


def test_mitre_mapping_is_the_responded_techniques_only():
    assert WORKFLOW.attack_ids() == {"T1068", "T1548", "T1548.002", "T1098", "T1098.003", "T1098.007"}
    assert {m.tactic for m in WORKFLOW.mitre} == {"TA0003", "TA0004"}
    assert "T1136" not in WORKFLOW.attack_ids(), "account creation is not observed: no forced mapping"
    for rule in WORKFLOW.recommendations:
        assert set(rule.mitre) <= WORKFLOW.attack_ids()
    assert all(m.rationale.strip() for m in WORKFLOW.mitre)


def test_shared_techniques_keep_one_tactic_and_name_across_workflows():
    tactics: dict[str, set[str]] = {}
    names: dict[str, set[str]] = {}
    for workflow_id in CATALOG.ids():
        for mapping in CATALOG.get(workflow_id).definition.mitre:
            tactics.setdefault(mapping.attack_id, set()).add(mapping.tactic)
            names.setdefault(mapping.technique, set()).add(mapping.technique_name)
    for mapping in WORKFLOW.mitre:
        assert tactics[mapping.attack_id] == {mapping.tactic}, mapping.attack_id
        assert names[mapping.technique] == {mapping.technique_name}, mapping.technique


@pytest.mark.parametrize("observables, changes, matches", [
    (((O.HOSTNAME, "TH-LT-1047"),), {"trigger": {"mitre_techniques": ["T1068"]}}, True),
    (((O.HOSTNAME, "TH-LT-1047"),), {"trigger": {"mitre_techniques": ["T1548.002"]}}, True),
    (((O.USER, "jsmith@example.com"),), {"trigger": {"mitre_techniques": ["T1098"]}}, True),
    (((O.USER, "jsmith@example.com"),), {"trigger": {"mitre_techniques": ["T1098.007"]}}, True),
    (((O.USER, "jsmith@example.com"),), {"title": "Privileged role assigned to jsmith@example.com"}, True),
    (((O.HOSTNAME, "TH-LT-1047"),), {"title": "UAC bypass detected on TH-LT-1047"}, True),
    (((O.USER, "jsmith@example.com"),), {"title": "User added to Domain Admins"}, True),
    ((), {"title": "User added to Domain Admins"}, False),  # nothing to investigate
    (((O.USER, "jsmith@example.com"),), {"trigger": {"mitre_techniques": ["T1078.004"]}}, False),
    (((O.HOSTNAME, "TH-LT-1047"),), {"title": "Ransomware on a file server"}, False),
])
def test_triggers(observables, changes, matches):
    assert (WORKFLOW.matches(_incident(observables, **changes)) is not None) is matches


@pytest.mark.parametrize("observables, techniques, title, expected", [
    (((O.HOSTNAME, "TH-LT-1047"),), ("T1068",), "Alert", "privilege-escalation"),
    (((O.USER, "jsmith@example.com"),), ("T1098",), "Alert", "privilege-escalation"),
    (((O.USER, "jsmith@example.com"),), ("T1098.007",), "Alert", "privilege-escalation"),
    (((O.USER, "jsmith@example.com"),), ("T1098", "T1078.004"), "Alert", "privilege-escalation"),
    # cloud-compromise keeps its cloud sub-techniques and its directory-role titles
    (((O.USER, "jsmith@example.com"),), ("T1098.003",), "Alert", "cloud-compromise"),
    (((O.USER, "jsmith@example.com"),), ("T1098.001",), "Alert", "cloud-compromise"),
    (((O.USER, "jsmith@example.com"),), (), "Global Administrator directory role assigned", "cloud-compromise"),
    (((O.USER, "jsmith@example.com"),), (), "Privileged role assigned to jsmith@example.com", "privilege-escalation"),
    # higher-priority endpoint workflows keep their incidents
    (((O.HOSTNAME, "TH-LT-1047"),), ("T1068", "T1003.001"), "Alert", "credential-dumping"),
    (((O.HOSTNAME, "TH-LT-1047"),), ("T1548.002", "T1486"), "Alert", "ransomware"),
])
def test_routing_against_overlapping_workflows(observables, techniques, title, expected):
    incident = _incident(observables, trigger={"mitre_techniques": list(techniques)}, title=title)
    assert CATALOG.resolve(incident).id == expected


def test_the_workflow_outranks_the_workflow_it_hands_off_to():
    assert WORKFLOW.handoff_to == ("account-takeover",)

    def top(definition: WorkflowDefinition) -> int:
        return max(t.priority for t in definition.triggers if t.type != "manual")

    assert top(WORKFLOW) > top(CATALOG.get("account-takeover").definition)
    assert top(WORKFLOW) < top(CATALOG.get("cloud-compromise").definition)


def test_the_readme_and_scenarios_pass_the_validator():
    found = CATALOG.get("privilege-escalation")
    assert check_workflow(found, readme_root=REPO / "workflows",
                          scenario_root=REPO / "tests" / "fixtures" / "workflows") == []


def test_known_limitations_are_listed():
    assert len(WORKFLOW.known_limitations) >= 6
    assert any("UNVERIFIED" in text for text in WORKFLOW.known_limitations)
    assert any("manual step" in text for text in WORKFLOW.known_limitations)
    assert any("change reference" in text for text in WORKFLOW.known_limitations)
