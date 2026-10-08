"""The credential-dumping workflow definition: validation, discovery, triggers, integrations, rules, MITRE."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from tools.validation.check_workflow_readmes import check_workflow
from xdr_response.atomics import atomic_subject_types, containment_builders
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.credential_dumping import HOOKS, WORKFLOW
from xdr_response.workflows.credential_dumping.definition import (
    CREDENTIAL_TECHNIQUES,
    ENDPOINT_SOURCES,
    MAX_HASH_BLOCK_PREVALENCE,
)
from xdr_response.workflows.credential_dumping.hooks import CredentialDumpingHooks
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows

REPO = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
HOST = (ObservableType.HOSTNAME, "TH-LT-1047")


def _incident(title: str = "Endpoint alert", *, techniques: tuple[str, ...] = (),
              observables: tuple[tuple[ObservableType, str], ...] = (HOST,),
              workflow_id: str = "unassigned") -> Incident:
    return Incident(incident_id="XDR-CD-T001", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0", source="cisco_xdr",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables),
                    trigger={"mitre_techniques": list(techniques)})


def test_definition_revalidates_and_is_discovered_with_its_hooks():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("credential-dumping")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, CredentialDumpingHooks) and found.hooks is HOOKS
    assert WORKFLOW.package_name == "credential_dumping"
    assert (WORKFLOW.id, WORKFLOW.name, WORKFLOW.phase, WORKFLOW.legacy_id) == (
        "credential-dumping", "Credential dumping", 3, "credential-dumping")
    assert WORKFLOW.default_severity is Severity.CRITICAL


def test_the_legacy_spec_is_deleted_and_the_readme_validates():
    legacy = REPO / "workflows" / "credential-dumping"
    assert not (legacy / "workflow.yaml").exists()
    assert not (legacy / "scenarios").exists()
    assert check_workflow(discover_workflows().get("credential-dumping")) == []


def test_integrations_follow_the_brief():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_endpoint", "entra"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "defender_endpoint", "microsoft_cloud", "cisco_xdr", "virustotal", "alienvault_otx"}
    assert WORKFLOW.expected_sources() == ("secure_endpoint", "entra")
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
    assert [s.atomic for s in WORKFLOW.investigation] == [
        "investigate_endpoint", "enrich_hash", "search_hash_enterprise", "investigate_endpoint", "investigate_user"]


def test_rules_build_the_brief_package_with_matching_builders():
    assert {r.action for r in WORKFLOW.recommendations} == {
        ActionType.ISOLATE_ENDPOINT, ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER, ActionType.BLOCK_HASH}
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).state_changing
        assert rule.builder in builders, rule.id
        assert rule.min_risk >= 50, rule.id
        assert rule.mitre and set(rule.mitre) <= WORKFLOW.attack_ids()
        assert rule.evidence.startswith("item."), "evidence comes from record-backed hook facts only"


def test_isolation_rules_are_product_pinned_and_pass_the_connector_guid():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    secure = rules["isolate_credential_host_secure_endpoint"]
    defender = rules["isolate_credential_host_defender_endpoint"]
    assert (secure.builder, defender.builder) == ("isolate_secure_endpoint", "isolate_defender_endpoint")
    assert secure.params == {"connector_guid": "item.connector_guid"}
    assert "item.connector_guid" in (secure.when or "") and "item.mde_machine_id" in (defender.when or "")
    assert all("isolation_capable != False" in (r.when or "") for r in (secure, defender))


def test_account_rules_revoke_every_exposed_account_and_disable_only_when_justified():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    assert rules["revoke_exposed_sessions"].for_each == "facts.exposed_users"
    assert rules["revoke_exposed_sessions"].builder == "revoke_entra_sessions"
    assert rules["disable_exposed_account"].for_each == "[u for u in facts.exposed_users if u.disable]"
    assert rules["disable_exposed_account"].builder == "disable_entra_user"
    assert rules["block_credential_tool_hash"].for_each == "[h for h in facts.hashes if h.blockable]"
    assert MAX_HASH_BLOCK_PREVALENCE == 10


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
    for word in ("auto_approve", "skip_approval", "bypass_approval", "approval_required", "unlock_code"):
        assert word not in text


def test_mitre_mapping_is_the_credential_dumping_family_only():
    pairs = {(m.tactic, m.technique, m.sub_technique) for m in WORKFLOW.mitre}
    assert pairs == {("TA0006", "T1003", None), ("TA0006", "T1003", "T1003.001"),
                     ("TA0006", "T1003", "T1003.002"), ("TA0006", "T1003", "T1003.003")}
    assert WORKFLOW.attack_ids() == frozenset(CREDENTIAL_TECHNIQUES)
    assert {m.sub_technique_name for m in WORKFLOW.mitre if m.sub_technique} == {
        "LSASS Memory", "Security Account Manager", "NTDS"}
    for mapping in WORKFLOW.mitre:
        assert mapping.rationale.strip() and mapping.tactic_name == "Credential Access"


def test_hand_off_goes_to_account_takeover_only():
    assert WORKFLOW.handoff_to == ("account-takeover",)
    assert set(WORKFLOW.handoff_to) <= set(WORKFLOW.related_workflows)


@pytest.mark.parametrize("title, techniques, observables", [
    ("Endpoint alert", ("T1003.001",), (HOST,)),
    ("Endpoint alert", ("T1003.002",), (HOST,)),
    ("Endpoint alert", ("T1003.003",), (HOST,)),
    ("Endpoint alert", ("T1003",), (HOST,)),
    ("Credential theft behaviour on TH-LT-1047", (), (HOST,)),
    ("LSASS access on TH-LT-1047", (), (HOST,)),
    ("Directory database access on DC-02", (), ((ObservableType.HOSTNAME, "DC-02"),)),
    ("NTDS copy detected", (), ((ObservableType.ENDPOINT_ID, "00000000-0000-4000-8000-000000001047"),)),
])
def test_automatic_triggers_match_credential_dumping_incidents(title, techniques, observables):
    assert WORKFLOW.matches(_incident(title, techniques=techniques, observables=observables)) is not None


@pytest.mark.parametrize("title, techniques, observables", [
    ("Endpoint alert", ("T1486",), (HOST,)),
    ("Endpoint alert", ("T1204.002",), (HOST,)),
    ("LSASS access", (), ((ObservableType.USER, "jsmith@example.com"),)),  # no endpoint named
    ("Impossible travel for a user", (), (HOST,)),
])
def test_triggers_do_not_match_unrelated_incidents(title, techniques, observables):
    assert WORKFLOW.matches(_incident(title, techniques=techniques, observables=observables)) is None


def test_routing_against_the_other_migrated_workflows():
    catalog = discover_workflows()
    assert catalog.resolve(_incident(techniques=("T1003.001",))).definition.id == "credential-dumping"
    assert catalog.resolve(_incident(techniques=("T1003.001", "T1204.002"))).definition.id == "credential-dumping"
    assert catalog.resolve(_incident(techniques=("T1003.001", "T1486"))).definition.id == "ransomware"
    manual = [t for t in WORKFLOW.triggers if t.type == "manual"]
    assert len(manual) == 1 and not manual[0].matches(_incident())
    resolved = catalog.resolve(_incident("Unrelated title", workflow_id="credential-dumping"))
    assert resolved is not None and resolved.definition.id == "credential-dumping"


def test_known_limitations_document_the_manual_and_unverified_steps():
    text = " ".join(WORKFLOW.known_limitations)
    for phrase in ("UNVERIFIED", "manual", "Kerberos", "not reversible", str(MAX_HASH_BLOCK_PREVALENCE),
                   "generic records"):
        assert phrase in text
