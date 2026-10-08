"""The unauthorized-rmm workflow definition: validation, discovery, triggers, integrations, rules, MITRE."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_response.atomics import atomic_subject_types, containment_builders
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.unauthorized_rmm import HOOKS, WORKFLOW
from xdr_response.workflows.unauthorized_rmm.definition import (
    ENDPOINT_SOURCES,
    MAX_FLEET_BLOCK_PREVALENCE,
    RMM_PRODUCTS,
    RMM_TECHNIQUE,
)
from xdr_response.workflows.unauthorized_rmm.hooks import (
    UnauthorizedRmmHooks,
    names_rmm,
    product_of,
    public_ipv4,
)

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
SHA = "a11d35c0" * 8
HOST = (ObservableType.HOSTNAME, "TH-LT-1047")


def _incident(title: str = "Endpoint alert", *, trigger: dict | None = None,
              observables: tuple[tuple[ObservableType, str], ...] = (HOST,),
              workflow_id: str = "unassigned") -> Incident:
    return Incident(incident_id="XDR-RMM-T001", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), trigger=trigger or {})


def test_definition_revalidates_and_is_discovered():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("unauthorized-rmm")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, UnauthorizedRmmHooks) and found.hooks is HOOKS
    assert WORKFLOW.package_name == "unauthorized_rmm"
    assert (WORKFLOW.id, WORKFLOW.name, WORKFLOW.phase, WORKFLOW.legacy_id) == (
        "unauthorized-rmm", "Unauthorised remote access tool", 3, "unauthorized-rmm")
    assert WORKFLOW.default_severity is Severity.HIGH


def test_integrations_follow_the_brief():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_endpoint", "umbrella"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "defender_endpoint", "cisco_xdr", "virustotal", "alienvault_otx", "entra", "meraki"}
    assert WORKFLOW.expected_sources() == ("secure_endpoint", "umbrella")
    known = set(WORKFLOW.integrations())
    for step in WORKFLOW.investigation:
        assert set(step.integrations) <= known
    assert set(ENDPOINT_SOURCES) <= known


def test_every_step_uses_a_read_atomic_with_a_supported_subject_type():
    subject_types = atomic_subject_types()
    for step in WORKFLOW.investigation:
        assert step.atomic in subject_types
        if step.subject_type is not None:
            assert step.subject_type in subject_types[step.atomic]
    atomics = [s.atomic for s in WORKFLOW.investigation]
    # endpoint, execution, installer source, persistence and sessions (investigate_endpoint), the
    # binary (reputation and prevalence), destinations (domains and IPs) and the user
    for needed in ("investigate_endpoint", "enrich_hash", "search_hash_enterprise", "enrich_domain",
                   "enrich_ip", "investigate_user"):
        assert needed in atomics


def test_rules_build_the_brief_package_with_matching_builders():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.TERMINATE_PROCESS, ActionType.BLOCK_HASH, ActionType.BLOCK_DOMAIN,
                       ActionType.BLOCK_IP, ActionType.ISOLATE_ENDPOINT}
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).state_changing
        if rule.builder is not None:
            assert rule.builder in builders
        assert rule.min_risk >= 40, rule.id
        assert set(rule.mitre) <= WORKFLOW.attack_ids()


def test_isolation_rules_are_product_pinned_and_follow_the_session():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    secure = rules["isolate_untrusted_session_secure_endpoint"]
    defender = rules["isolate_untrusted_session_defender_endpoint"]
    assert (secure.builder, defender.builder) == ("isolate_secure_endpoint", "isolate_defender_endpoint")
    assert secure.params == {"connector_guid": "item.connector_guid"}
    for rule in (secure, defender):
        assert "facts.sessions" in rule.for_each and "s.untrusted" in rule.for_each
        assert rule.min_risk == 50


def test_fleet_wide_blocks_skip_widespread_tools_and_peer_ips_need_a_rating():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    assert "not t.widespread" in rules["block_rmm_binary"].for_each
    assert "not item.widespread_tool" in (rules["block_rmm_destination_domain"].when or "")
    assert rules["block_rmm_session_peer_ip"].when == "item.rated"
    assert MAX_FLEET_BLOCK_PREVALENCE == 50


def test_no_approval_switch_anywhere_in_the_definition():
    def keys(node):
        if isinstance(node, dict):
            for key, value in node.items():
                yield str(key).lower()
                yield from keys(value)
        elif isinstance(node, (list, tuple)):
            for value in node:
                yield from keys(value)
    assert not set(keys(WORKFLOW.model_dump(mode="json"))) & APPROVAL_LIKE_KEYS
    text = repr(WORKFLOW.model_dump(mode="json")).lower()
    for word in ("auto_approve", "skip_approval", "bypass_approval", "unlock_code"):
        assert word not in text


def test_mitre_mapping_is_not_forced():
    pairs = {(m.tactic, m.technique, m.sub_technique) for m in WORKFLOW.mitre}
    assert pairs == {("TA0011", "T1219", "T1219.002")}
    assert WORKFLOW.attack_ids() == frozenset({"T1219", "T1219.002"})
    [mapping] = WORKFLOW.mitre
    assert mapping.technique_name == "Remote Access Tools"  # one name per technique across workflows
    assert mapping.sub_technique_name == "Remote Desktop Software" and mapping.rationale.strip()
    assert RMM_TECHNIQUE == "T1219"


@pytest.mark.parametrize("trigger, observables, title", [
    ({"mitre_techniques": ["T1219"]}, (HOST,), "Endpoint alert"),
    ({"mitre_techniques": ["T1219.002"]}, (HOST,), "Endpoint alert"),
    ({"mitre_techniques": ["T1219.002"]}, ((ObservableType.SHA256, SHA),), "Endpoint alert"),
    ({}, (HOST,), "Unapproved RMM tool on a workstation"),
    ({}, (HOST,), "Remote access software detected"),
])
def test_automatic_triggers_match_rmm_incidents(trigger, observables, title):
    incident = _incident(title, trigger=trigger, observables=observables)
    assert WORKFLOW.matches(incident) is not None
    resolved = discover_workflows().resolve(incident)
    assert resolved is not None and resolved.definition.id == "unauthorized-rmm"


@pytest.mark.parametrize("trigger, observables, title", [
    ({"mitre_techniques": ["T1219"]}, ((ObservableType.USER, "jsmith@example.com"),), "Endpoint alert"),
    ({"mitre_techniques": ["T1204.002"]}, (HOST,), "Malicious file executed"),
    ({}, ((ObservableType.USER, "jsmith@example.com"),), "Remote access tool seen"),
    ({}, (HOST,), "Impossible travel for a user"),
])
def test_triggers_do_not_match_unrelated_incidents(trigger, observables, title):
    assert WORKFLOW.matches(_incident(title, trigger=trigger, observables=observables)) is None


def test_manual_trigger_never_matches_automatically_and_the_catalog_routes_by_workflow_id():
    manual = [t for t in WORKFLOW.triggers if t.type == "manual"]
    assert len(manual) == 1 and not manual[0].matches(_incident())
    resolved = discover_workflows().resolve(_incident("Unrelated title", workflow_id="unauthorized-rmm"))
    assert resolved is not None and resolved.definition.id == "unauthorized-rmm"


def test_handoffs_are_declared_and_related():
    assert set(WORKFLOW.handoff_to) == {"persistence", "account-takeover"}
    assert set(WORKFLOW.handoff_to) <= set(WORKFLOW.related_workflows)
    assert "mail-bombing" in WORKFLOW.related_workflows
    # mail-bombing hands the fake help-desk follow-up to this workflow
    assert "unauthorized-rmm" in discover_workflows().get("mail-bombing").definition.handoff_to


def test_known_limitations_document_the_unverified_manual_steps():
    text = " ".join(WORKFLOW.known_limitations)
    for phrase in ("approved_rmm", "UNROUTED", "UNVERIFIED", "manual steps", "service desk", "IPv6",
                   str(MAX_FLEET_BLOCK_PREVALENCE)):
        assert phrase in text


@pytest.mark.parametrize("product", ["AnyDesk", "RustDesk", "ScreenConnect", "TeamViewer", "Splashtop", "Atera",
                                     "ConnectWise Automate"])
def test_the_brief_tools_are_in_the_product_table(product: str):
    assert product in RMM_PRODUCTS


@pytest.mark.parametrize("name, expected", [
    ("AnyDesk.exe", "AnyDesk"), ("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe", "AnyDesk"),
    ("/usr/bin/rustdesk", "RustDesk"), ("ScreenConnect.ClientService.exe", "ScreenConnect"),
    ("TeamViewer_Service.exe", "TeamViewer"), ("AteraAgent.exe", "Atera"), ("LTSVC.exe", "ConnectWise Automate"),
    ("SRService.exe", "Splashtop"), ("notepad.exe", None), ("anydesk-notes.txt", None), ("", None), (None, None),
])
def test_product_of_matches_executable_names_only(name, expected):
    assert product_of(name) == expected


@pytest.mark.parametrize("text, expected", [
    ("PUA.RemoteAccess.AnyDesk", True), ("RemoteAccessTool", True), ("Remote Desktop tool", True),
    ("PUA.RMM.Generic", True), ("rmm", True), ("Firmmware.Update", False), ("Confirmmail", False),
    ("Sample.Trojan.Generic", False), ("", False), (None, False),
])
def test_names_rmm_uses_whole_words_for_short_keywords(text, expected):
    assert names_rmm(text) is expected


@pytest.mark.parametrize("value, expected", [
    ("198.51.100.45", "198.51.100.45"), ("203.0.113.145", "203.0.113.145"), ("10.20.0.15", None),
    ("192.168.1.10", None), ("100.64.0.1", None), ("2001:db8::1", None), ("not-an-ip", None), (None, None),
])
def test_public_ipv4_excludes_the_organisations_own_network(value, expected):
    assert public_ipv4(value) == expected
