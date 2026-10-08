"""The dns-tunneling workflow definition: validation, discovery, triggers, integrations, rules, MITRE."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_response.atomics import atomic_subject_types, containment_builders
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.dns_tunneling import HOOKS, WORKFLOW
from xdr_response.workflows.dns_tunneling.definition import (
    DNS_SERVER_PROCESSES,
    DNS_SOURCES,
    ENDPOINT_SOURCES,
    MIN_LABEL_ENTROPY,
    MIN_LONG_LABEL,
    MIN_PROFILE_INDICATORS,
    MIN_TUNNEL_QUERIES,
    MIN_UNIQUE_SUBDOMAINS,
    TUNNEL_RECORD_TYPES,
    TUNNEL_TECHNIQUES,
)
from xdr_response.workflows.dns_tunneling.hooks import DnsTunnelingHooks

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
DOMAIN = (ObservableType.DOMAIN, "cdn-update.test")
HOST = (ObservableType.HOSTNAME, "TH-LT-1047")
USER = (ObservableType.USER, "jsmith@example.com")


def _incident(title: str = "Network alert", *, trigger: dict | None = None,
              observables: tuple[tuple[ObservableType, str], ...] = (DOMAIN, HOST),
              workflow_id: str = "unassigned") -> Incident:
    return Incident(incident_id="XDR-DNS-T001", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), trigger=trigger or {})


def test_definition_revalidates_and_is_discovered():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("dns-tunneling")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, DnsTunnelingHooks) and found.hooks is HOOKS
    assert WORKFLOW.package_name == "dns_tunneling"
    assert (WORKFLOW.id, WORKFLOW.name, WORKFLOW.phase, WORKFLOW.legacy_id) == (
        "dns-tunneling", "DNS tunneling", 4, "dns-tunneling")
    assert WORKFLOW.default_severity is Severity.HIGH


def test_integrations_follow_the_brief():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["umbrella", "secure_endpoint"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "splunk", "defender_endpoint", "cisco_xdr", "virustotal", "alienvault_otx"}
    assert WORKFLOW.expected_sources() == ("umbrella", "secure_endpoint")
    known = set(WORKFLOW.integrations())
    for step in WORKFLOW.investigation:
        assert set(step.integrations) <= known
    assert set(ENDPOINT_SOURCES) <= known and set(DNS_SOURCES) <= known


def test_every_step_uses_a_read_atomic_with_a_supported_subject_type():
    subject_types = atomic_subject_types()
    for step in WORKFLOW.investigation:
        assert step.atomic in subject_types
        if step.subject_type is not None:
            assert step.subject_type in subject_types[step.atomic]
    atomics = [s.atomic for s in WORKFLOW.investigation]
    # endpoint and querying process, DNS activity (resolver logs), the parent's reputation, the binaries
    for needed in ("investigate_endpoint", "search_domain_enterprise", "enrich_domain", "enrich_hash",
                   "search_hash_enterprise"):
        assert needed in atomics


def test_reputation_is_asked_for_the_parent_domains_never_every_child_name():
    steps = {s.id: s for s in WORKFLOW.investigation}
    reputation = steps["parent_reputation"]
    assert reputation.subjects is not None and "unique_subdomains" in reputation.subjects
    assert "observables_by_type, 'domain'" in reputation.subjects
    assert steps["dns_activity"].subjects == reputation.subjects
    # the real client behind a forwarding resolver comes from the DNS records' endpoints
    assert "q.endpoint" in (steps["tunnel_clients"].subjects or "")


def test_rules_build_the_brief_package_with_matching_builders():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.BLOCK_DOMAIN, ActionType.TERMINATE_PROCESS, ActionType.ISOLATE_ENDPOINT}
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).state_changing
        if rule.builder is not None:
            assert rule.builder in builders
        assert rule.min_risk >= 40, rule.id
        assert set(rule.mitre) <= WORKFLOW.attack_ids()


def test_isolation_rules_are_product_pinned_and_rest_on_the_querying_binaries():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    secure = rules["isolate_tunnel_client_secure_endpoint"]
    defender = rules["isolate_tunnel_client_defender_endpoint"]
    assert (secure.builder, defender.builder) == ("isolate_secure_endpoint", "isolate_defender_endpoint")
    assert secure.params == {"connector_guid": "item.connector_guid"}
    for rule in (secure, defender):
        assert "facts.clients" in rule.for_each and "isolation_capable != False" in rule.for_each
        assert rule.binaries == "item.binaries"
        assert rule.min_risk == 50


def test_the_block_targets_confirmed_parents_and_an_unrated_one_rests_on_its_clients():
    rule = next(r for r in WORKFLOW.recommendations if r.id == "block_tunnel_parent_domain")
    assert rule.for_each == "[t for t in facts.tunnels if t.confirmed]"
    assert rule.target == "item.domain"
    assert rule.binaries == "[] if item.rated else item.client_hashes"
    assert rule.builder is None  # catalog order: native, Umbrella, Defender


def test_thresholds_keep_the_legacy_rule_and_the_profile():
    assert MIN_TUNNEL_QUERIES == 1000
    assert (MIN_UNIQUE_SUBDOMAINS, MIN_LONG_LABEL, MIN_LABEL_ENTROPY, MIN_PROFILE_INDICATORS) == (200, 40, 3.5, 3)
    assert set(TUNNEL_RECORD_TYPES) == {"TXT", "NULL"}
    assert {"dns.exe", "named", "unbound", "dnsmasq"} <= set(DNS_SERVER_PROCESSES)


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
    assert pairs == {("TA0011", "T1071", "T1071.004"), ("TA0011", "T1572", None)}
    assert WORKFLOW.attack_ids() == frozenset({"T1071", "T1071.004", "T1572"})
    names = {m.technique: m.technique_name for m in WORKFLOW.mitre}
    # one name per technique across workflows (ransomware also maps T1071)
    assert names == {"T1071": "Application Layer Protocol", "T1572": "Protocol Tunneling"}
    assert all(m.rationale.strip() for m in WORKFLOW.mitre)
    assert set(TUNNEL_TECHNIQUES) == {"T1071.004", "T1572"}
    ransomware = discover_workflows().get("ransomware").definition
    assert {m.technique_name for m in ransomware.mitre if m.technique == "T1071"} <= {"Application Layer Protocol"}


@pytest.mark.parametrize("trigger, observables, title", [
    ({"mitre_techniques": ["T1071.004"]}, (DOMAIN,), "Network alert"),
    ({"mitre_techniques": ["T1572"]}, (HOST,), "Network alert"),
    ({"mitre_techniques": ["T1071.004", "T1105"]}, (DOMAIN, HOST), "Network alert"),
    ({}, (DOMAIN,), "DNS Tunneling VPN category hit for cdn-update.test"),
    ({}, (HOST,), "Possible DNS tunnel from TH-LT-1047"),
])
def test_automatic_triggers_match_dns_tunneling_incidents(trigger, observables, title):
    incident = _incident(title, trigger=trigger, observables=observables)
    assert WORKFLOW.matches(incident) is not None
    resolved = discover_workflows().resolve(incident)
    assert resolved is not None and resolved.definition.id == "dns-tunneling"


@pytest.mark.parametrize("trigger, observables, title", [
    ({"mitre_techniques": ["T1071.004"]}, (USER,), "Network alert"),
    ({"mitre_techniques": ["T1071.001"]}, (DOMAIN,), "Web traffic alert"),
    ({}, (USER,), "DNS tunneling suspected"),
    ({}, (DOMAIN,), "Newly seen domain"),
])
def test_triggers_do_not_match_unrelated_incidents(trigger, observables, title):
    assert WORKFLOW.matches(_incident(title, trigger=trigger, observables=observables)) is None


def test_manual_trigger_never_matches_automatically_and_the_catalog_routes_by_workflow_id():
    manual = [t for t in WORKFLOW.triggers if t.type == "manual"]
    assert len(manual) == 1 and not manual[0].matches(_incident())
    resolved = discover_workflows().resolve(_incident("Unrelated title", workflow_id="dns-tunneling"))
    assert resolved is not None and resolved.definition.id == "dns-tunneling"


def test_no_handoffs_and_related_workflows_exist_or_are_planned():
    assert WORKFLOW.handoff_to == ()
    assert set(WORKFLOW.related_workflows) == {"c2", "exfiltration", "malware"}


def test_known_limitations_document_the_unverified_and_manual_parts():
    text = " ".join(WORKFLOW.known_limitations)
    for phrase in ("approved_dns_tools", "UNROUTED", "UNVERIFIED", "VERIFIED", "manual steps", "resolver",
                   "entropy", "generic records", "disclosure policy"):
        assert phrase in text, phrase
