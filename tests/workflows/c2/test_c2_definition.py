"""The c2 workflow definition: validation, discovery, triggers, integrations, rules, MITRE."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_response.atomics import atomic_subject_types, containment_builders
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.c2 import HOOKS, WORKFLOW
from xdr_response.workflows.c2.definition import (
    ATTACK_IDS,
    DESTINATION_MIN_RISK,
    ENDPOINT_SOURCES,
    HUNT_SOURCES,
    MIN_BEACON_CONTACTS,
)
from xdr_response.workflows.c2.hooks import C2Hooks
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
HOST = (ObservableType.HOSTNAME, "TH-LT-1047")
DOMAIN = (ObservableType.DOMAIN, "beacon-gate.test")
IP = (ObservableType.IP, "198.51.100.45")


def _incident(title: str = "Endpoint alert", *, trigger: dict | None = None,
              observables: tuple[tuple[ObservableType, str], ...] = (HOST,), workflow_id: str = "unassigned",
              source: str = "cisco_xdr") -> Incident:
    return Incident(incident_id="XDR-C2-T001", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0", source=source,
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), trigger=trigger or {})


def test_definition_revalidates_and_is_discovered():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("c2")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, C2Hooks) and found.hooks is HOOKS
    assert WORKFLOW.package_name == "c2"
    assert (WORKFLOW.id, WORKFLOW.name, WORKFLOW.phase, WORKFLOW.legacy_id) == ("c2", "Command and control", 4, "c2")
    assert WORKFLOW.default_severity is Severity.HIGH


def test_integrations_follow_the_brief_and_only_verified_reads():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_endpoint", "umbrella"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "defender_endpoint", "cisco_xdr", "virustotal", "alienvault_otx", "microsoft_cloud", "splunk", "meraki"}
    assert WORKFLOW.expected_sources() == ("secure_endpoint", "umbrella")
    # Secure Cloud Analytics has no VERIFIED API: it is a trigger source only, never an integration
    assert "secure_cloud_analytics" not in WORKFLOW.integrations()
    meraki = next(r for r in WORKFLOW.optional_integrations if r.integration == "meraki")
    assert meraki.atomics == ()  # write landing product only: no VERIFIED read atomic
    umbrella = next(r for r in WORKFLOW.required_integrations if r.integration == "umbrella")
    assert umbrella.atomics == ("enrich_domain",)
    known = set(WORKFLOW.integrations())
    for step in WORKFLOW.investigation:
        assert set(step.integrations) <= known
    assert set(ENDPOINT_SOURCES) <= known and set(HUNT_SOURCES) <= known


def test_every_step_uses_a_read_atomic_with_a_supported_subject_type():
    subject_types = atomic_subject_types()
    for step in WORKFLOW.investigation:
        assert step.atomic in subject_types
        if step.subject_type is not None:
            assert step.subject_type in subject_types[step.atomic]
    assert [s.id for s in WORKFLOW.investigation] == [
        "endpoint_triage", "domain_reputation", "ip_reputation", "url_reputation", "domain_sightings",
        "ip_sightings", "related_endpoints", "beacon_process_reputation"]


def test_rules_build_the_brief_package_with_matching_builders():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.BLOCK_DOMAIN, ActionType.BLOCK_IP, ActionType.BLOCK_URL,
                       ActionType.ISOLATE_ENDPOINT, ActionType.TERMINATE_PROCESS}
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).state_changing
        if rule.builder is not None:
            assert rule.builder in builders
        assert set(rule.mitre) <= WORKFLOW.attack_ids()
        assert rule.min_risk >= DESTINATION_MIN_RISK, rule.id


def test_destination_blocks_need_a_rating_and_the_ip_block_skips_shared_infrastructure():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    for rule_id in ("block_c2_domain", "block_c2_ip", "block_c2_url"):
        assert "item.rated" in (rules[rule_id].when or ""), rule_id
        assert rules[rule_id].min_risk == DESTINATION_MIN_RISK == 30
    assert "not item.shared" in (rules["block_c2_ip"].when or "")
    assert MIN_BEACON_CONTACTS == 5


def test_isolation_rules_are_product_pinned_and_need_malicious_activity_on_the_endpoint():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    secure = rules["isolate_beaconing_endpoint_secure_endpoint"]
    defender = rules["isolate_beaconing_endpoint_defender_endpoint"]
    assert (secure.builder, defender.builder) == ("isolate_secure_endpoint", "isolate_defender_endpoint")
    assert secure.params == {"connector_guid": "item.connector_guid"}
    assert "item.connector_guid" in (secure.when or "") and "item.mde_machine_id" in (defender.when or "")
    for rule in (secure, defender):
        assert "h.isolate" in rule.for_each and "isolation_capable != False" in rule.for_each
        assert rule.min_risk == 60
    terminate = rules["terminate_beaconing_process"]
    assert terminate.for_each == "facts.processes" and terminate.include_target_enrichment is False


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
    triples = {(m.tactic, m.technique, m.sub_technique) for m in WORKFLOW.mitre}
    assert triples == {("TA0011", "T1071", "T1071.001"), ("TA0011", "T1573", None), ("TA0011", "T1568", "T1568.002")}
    assert WORKFLOW.attack_ids() == frozenset({"T1071", "T1071.001", "T1573", "T1568", "T1568.002"})
    names = {m.attack_id: (m.technique_name, m.sub_technique_name) for m in WORKFLOW.mitre}
    assert names["T1071.001"] == ("Application Layer Protocol", "Web Protocols")
    assert names["T1568.002"] == ("Dynamic Resolution", "Domain Generation Algorithms")
    for mapping in WORKFLOW.mitre:
        assert mapping.rationale.strip()
    assert set(ATTACK_IDS) <= WORKFLOW.attack_ids()


@pytest.mark.parametrize("trigger, observables, title, source", [
    ({"mitre_techniques": ["T1071.001"]}, (HOST,), "Endpoint alert", "cisco_xdr"),
    ({"mitre_techniques": ["T1573"]}, (HOST,), "Endpoint alert", "cisco_xdr"),
    ({"mitre_techniques": ["T1568.002"]}, (DOMAIN,), "Endpoint alert", "cisco_xdr"),
    ({}, (HOST, DOMAIN), "Periodic HTTPS beaconing from TH-LT-1047", "cisco_xdr"),
    ({}, (IP,), "Possible C2 traffic to an external host", "cisco_xdr"),
    ({}, (IP,), "Suspicious external connection from TH-LT-1047", "secure_cloud_analytics"),
    ({}, (DOMAIN,), "Malicious DNS lookup", "umbrella"),
])
def test_automatic_triggers_match_c2_incidents(trigger, observables, title, source):
    incident = _incident(title, trigger=trigger, observables=observables, source=source)
    assert WORKFLOW.matches(incident) is not None


@pytest.mark.parametrize("trigger, observables, title, source", [
    ({"mitre_techniques": ["T1071.004"]}, (DOMAIN,), "Endpoint alert", "cisco_xdr"),  # DNS tunnelling
    ({"mitre_techniques": ["T1486"]}, (HOST,), "Files encrypted", "cisco_xdr"),
    ({}, ((ObservableType.USER, "jsmith@example.com"),), "Beaconing detected", "cisco_xdr"),
    ({}, (DOMAIN,), "Suspicious external connection", "cisco_xdr"),  # not SCA or Umbrella
    ({}, (HOST,), "Malicious DNS lookup", "umbrella"),  # no domain or IP
    ({}, (HOST,), "Impossible travel for a user", "cisco_xdr"),
])
def test_triggers_do_not_match_unrelated_incidents(trigger, observables, title, source):
    assert WORKFLOW.matches(_incident(title, trigger=trigger, observables=observables, source=source)) is None


def test_manual_trigger_never_matches_and_the_catalog_routes_by_workflow_id_and_technique():
    manual = [t for t in WORKFLOW.triggers if t.type == "manual"]
    assert len(manual) == 1 and not manual[0].matches(_incident())
    catalog = discover_workflows()
    assert catalog.resolve(_incident("Unrelated title", workflow_id="c2")).definition.id == "c2"
    beacon = _incident(trigger={"mitre_techniques": ["T1071.001", "T1204.002"]}, observables=(HOST, DOMAIN))
    assert catalog.resolve(beacon).definition.id == "c2"  # c2 outranks malware, which it hands off to


def test_c2_outranks_the_workflow_it_hands_off_to():
    catalog = discover_workflows()
    assert WORKFLOW.handoff_to == ("malware",) and set(WORKFLOW.handoff_to) <= set(WORKFLOW.related_workflows)

    def top(definition: WorkflowDefinition) -> int:
        return max(t.priority for t in definition.triggers if t.type != "manual")
    assert top(WORKFLOW) > top(catalog.get("malware").definition)
    assert "c2" not in catalog.get("malware").definition.handoff_to  # no hand-off cycle


def test_known_limitations_document_the_unverified_manual_steps():
    text = " ".join(WORKFLOW.known_limitations)
    for phrase in ("Secure Cloud Analytics", "UNVERIFIED", "UNROUTED", "UNABLE_TO_VERIFY", "IPv6", "Beaconing",
                   "shared_infrastructure_ips", "by hand"):
        assert phrase in text, phrase
