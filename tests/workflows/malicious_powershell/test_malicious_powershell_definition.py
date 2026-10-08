"""The Suspicious PowerShell workflow definition: validation, discovery, triggers, integrations, rules, MITRE."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_response.atomics import atomic_subject_types, containment_builders
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.malicious_powershell import HOOKS, WORKFLOW
from xdr_response.workflows.malicious_powershell.definition import (
    LOLBIN_IMAGES,
    LOLBINS,
    MAX_HASH_BLOCK_PREVALENCE,
)
from xdr_response.workflows.malicious_powershell.hooks import MaliciousPowershellHooks

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
SHA = "c0ffee00" * 8


def _incident(title: str = "Endpoint alert on TH-LT-1047", *, trigger: dict | None = None,
              observables: tuple[tuple[ObservableType, str], ...] = ((ObservableType.HOSTNAME, "TH-LT-1047"),),
              workflow_id: str = "unassigned", source: str = "xdr") -> Incident:
    return Incident(incident_id="XDR-PS-T001", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0", source=source,
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), trigger=trigger or {})


def test_definition_revalidates_and_is_discovered():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("malicious-powershell")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, MaliciousPowershellHooks) and found.hooks is HOOKS
    assert WORKFLOW.package_name == "malicious_powershell"
    assert (WORKFLOW.id, WORKFLOW.name, WORKFLOW.phase, WORKFLOW.legacy_id) == (
        "malicious-powershell", "Suspicious PowerShell", 3, "malicious-powershell")
    assert WORKFLOW.default_severity is Severity.MEDIUM


def test_the_brief_binaries_are_evaluated():
    assert set(LOLBINS) == {"powershell", "pwsh", "mshta", "rundll32", "regsvr32", "certutil", "wmic", "wscript",
                            "cscript", "bitsadmin", "installutil"}
    assert set(LOLBIN_IMAGES) == set(LOLBINS) | {f"{n}.exe" for n in LOLBINS}


def test_integrations():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_endpoint", "virustotal"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "defender_endpoint", "cisco_xdr", "umbrella", "alienvault_otx", "splunk", "meraki"}
    assert WORKFLOW.expected_sources() == ("secure_endpoint", "virustotal")
    known = set(WORKFLOW.integrations())
    for step in WORKFLOW.investigation:
        assert set(step.integrations) <= known


def test_every_step_uses_a_read_atomic_with_a_supported_subject_type():
    subject_types = atomic_subject_types()
    for step in WORKFLOW.investigation:
        assert step.atomic in subject_types
        if step.subject_type is not None:
            assert step.subject_type in subject_types[step.atomic]
    atomics = [s.atomic for s in WORKFLOW.investigation]
    for needed in ("investigate_endpoint", "investigate_process", "enrich_hash", "search_hash_enterprise",
                   "enrich_domain", "enrich_ip", "enrich_url"):
        assert needed in atomics


def test_rules_build_the_brief_package_with_matching_builders():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.TERMINATE_PROCESS, ActionType.ISOLATE_ENDPOINT, ActionType.BLOCK_HASH,
                       ActionType.BLOCK_DOMAIN, ActionType.BLOCK_URL, ActionType.BLOCK_IP}
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).state_changing
        if rule.builder is not None:
            assert rule.builder in builders
        assert rule.min_risk >= 40, rule.id
        assert set(rule.mitre) <= WORKFLOW.attack_ids()
        assert rule.evidence.startswith("item.") or "facts." in rule.evidence


def test_isolation_rules_are_product_pinned_and_pass_the_connector_guid():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    secure, defender = rules["isolate_secure_endpoint"], rules["isolate_defender_endpoint"]
    assert (secure.builder, defender.builder) == ("isolate_secure_endpoint", "isolate_defender_endpoint")
    assert secure.params == {"connector_guid": "item.connector_guid"}
    assert "item.connector_guid" in (secure.when or "") and "item.mde_machine_id" in (defender.when or "")


def test_hash_rule_keeps_the_inclusive_prevalence_threshold():
    rule = next(r for r in WORKFLOW.recommendations if r.id == "block_payload_hash")
    assert MAX_HASH_BLOCK_PREVALENCE == 10
    assert f"item.prevalence <= {MAX_HASH_BLOCK_PREVALENCE}" in (rule.when or "")


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


def test_mitre_mapping_covers_the_evaluated_binaries_without_forced_ids():
    pairs = {(m.tactic, m.technique, m.sub_technique) for m in WORKFLOW.mitre}
    assert pairs == {
        ("TA0002", "T1059", "T1059.001"), ("TA0002", "T1059", None), ("TA0005", "T1027", None),
        ("TA0005", "T1218", None), ("TA0005", "T1218", "T1218.004"), ("TA0005", "T1218", "T1218.005"),
        ("TA0005", "T1218", "T1218.010"), ("TA0005", "T1218", "T1218.011"), ("TA0002", "T1047", None),
        ("TA0011", "T1105", None)}
    for mapping in WORKFLOW.mitre:
        assert mapping.rationale.strip()
    # one name per technique
    names: dict[str, str] = {}
    for mapping in WORKFLOW.mitre:
        assert names.setdefault(mapping.technique, mapping.technique_name) == mapping.technique_name


@pytest.mark.parametrize("trigger, title, source, observables", [
    ({"mitre_techniques": ["T1059.001"]}, "Endpoint alert", "xdr", ((ObservableType.HOSTNAME, "TH-LT-1047"),)),
    ({"mitre_techniques": ["T1027"]}, "Endpoint alert", "xdr", ((ObservableType.HOSTNAME, "TH-LT-1047"),)),
    ({"mitre_techniques": ["T1218.011"]}, "Endpoint alert", "xdr", ((ObservableType.HOSTNAME, "TH-LT-1047"),)),
    ({}, "Suspicious PowerShell on TH-LT-1047", "xdr", ((ObservableType.HOSTNAME, "TH-LT-1047"),)),
    ({}, "certutil download on a workstation", "xdr", ((ObservableType.HOSTNAME, "TH-LT-1047"),)),
    ({"source": "splunk", "mitre_techniques": ["T1059.001"]}, "Alert", "webhook", ((ObservableType.SHA256, SHA),)),
])
def test_automatic_triggers_match_powershell_incidents(trigger, title, source, observables):
    assert WORKFLOW.matches(_incident(title, trigger=trigger, observables=observables, source=source)) is not None


@pytest.mark.parametrize("trigger, title, observables", [
    ({"mitre_techniques": ["T1486"]}, "Files encrypted", ((ObservableType.HOSTNAME, "TH-LT-1047"),)),
    ({}, "PowerShell alert", ((ObservableType.USER, "jsmith@example.com"),)),
    ({}, "Impossible travel for a user", ((ObservableType.HOSTNAME, "TH-LT-1047"),)),
])
def test_triggers_do_not_match_unrelated_incidents(trigger, title, observables):
    assert WORKFLOW.matches(_incident(title, trigger=trigger, observables=observables)) is None


def test_routing_against_overlapping_workflows():
    catalog = discover_workflows()
    both = _incident(trigger={"mitre_techniques": ["T1059.001", "T1105"]})
    assert catalog.resolve(both).definition.id == "malicious-powershell"   # 125 beats malware's 100
    transfer_only = _incident(trigger={"mitre_techniques": ["T1105"]})
    assert catalog.resolve(transfer_only).definition.id == "malware"
    encrypted = _incident(trigger={"mitre_techniques": ["T1059.001", "T1486"]})
    assert catalog.resolve(encrypted).definition.id == "ransomware"        # ransomware (200) wins
    assert catalog.resolve(_incident("Unrelated", workflow_id="malicious-powershell")).definition == WORKFLOW


def test_handoffs_are_existing_related_workflows():
    assert set(WORKFLOW.handoff_to) == {"malware", "persistence"}
    assert set(WORKFLOW.handoff_to) <= set(WORKFLOW.related_workflows)


def test_known_limitations_document_the_manual_and_unverified_steps():
    text = " ".join(WORKFLOW.known_limitations)
    for phrase in ("UNROUTED", "UNVERIFIED", "command line", "process id", "IPv6", str(MAX_HASH_BLOCK_PREVALENCE),
                   "malware workflow"):
        assert phrase in text
