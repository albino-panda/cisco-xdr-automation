"""The threat-intel-sweep workflow definition: validation, discovery, triggers, integrations, steps, rules,
MITRE mapping and known limitations."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_response.atomics import atomic_subject_types, containment_builders
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.threat_intel_sweep import HOOKS, WORKFLOW
from xdr_response.workflows.threat_intel_sweep.definition import (
    BLOCK_MIN_RISK,
    ENDPOINT_SOURCES,
    HASH_HUNT_SOURCES,
    IOC_TYPES,
    ISOLATE_MIN_RISK,
    MAIL_SOURCES,
    MAX_INDICATORS_PER_TYPE,
    NETWORK_HUNT_SOURCES,
    QUARANTINE_MIN_RISK,
    REVOKE_MIN_RISK,
    SENDER_SOURCES,
    SWEEP_LOOKBACK_HOURS,
    TRIGGER_PRIORITY,
)
from xdr_response.workflows.threat_intel_sweep.hooks import ThreatIntelSweepHooks

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
_O = ObservableType
HASH = (_O.SHA256, "7e3a91c5" * 8)
DOMAIN = (_O.DOMAIN, "update-relay.test")
IP = (_O.IP, "198.51.100.77")
HOST = (_O.HOSTNAME, "TH-LT-1047")


def _incident(title: str = "Alert", *, observables: tuple[tuple[ObservableType, str], ...] = (HASH,),
              source: str = "cisco_xdr", trigger: dict | None = None, workflow_id: str = "unassigned") -> Incident:
    return Incident(incident_id="XDR-TIS-T001", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0", source=source,
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), trigger=trigger or {})


def test_definition_revalidates_and_is_discovered_with_its_hooks():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("threat-intel-sweep")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, ThreatIntelSweepHooks) and found.hooks is HOOKS
    assert WORKFLOW.package_name == "threat_intel_sweep"
    assert (WORKFLOW.id, WORKFLOW.name, WORKFLOW.phase, WORKFLOW.legacy_id) == (
        "threat-intel-sweep", "Threat intelligence sweep", 5, None)
    assert WORKFLOW.default_severity is Severity.HIGH


def test_integrations_follow_the_brief_with_only_verified_reads():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["cisco_xdr", "secure_endpoint", "secure_email"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "defender_endpoint", "microsoft_cloud", "defender_o365", "umbrella", "entra", "virustotal", "alienvault_otx",
        "secure_malware_analytics", "hibp", "splunk", "meraki"}
    assert WORKFLOW.expected_sources() == ("cisco_xdr", "secure_endpoint", "secure_email")
    # Secure Cloud Analytics has no VERIFIED API: a trigger source only, never an integration
    assert "secure_cloud_analytics" not in WORKFLOW.integrations()
    optional = {r.integration: r for r in WORKFLOW.optional_integrations}
    assert optional["defender_o365"].atomics == () and optional["meraki"].atomics == ()  # executors only
    assert optional["umbrella"].atomics == ("enrich_domain",)  # DNS activity reports are UNVERIFIED
    known = set(WORKFLOW.integrations())
    for step in WORKFLOW.investigation:
        assert set(step.integrations) <= known, step.id
    for sources in (HASH_HUNT_SOURCES, NETWORK_HUNT_SOURCES, SENDER_SOURCES, MAIL_SOURCES, ENDPOINT_SOURCES):
        assert set(sources) <= known


def test_every_step_uses_a_read_atomic_with_a_supported_subject_type():
    subject_types = atomic_subject_types()
    for step in WORKFLOW.investigation:
        assert step.atomic in subject_types, step.id
        if step.subject_type is not None:
            assert step.subject_type in subject_types[step.atomic], step.id
    assert [s.id for s in WORKFLOW.investigation] == [
        "hash_reputation", "domain_reputation", "ip_reputation", "url_reputation", "sender_reputation",
        "hash_sightings", "domain_sightings", "ip_sightings", "sender_activity", "messages", "related_messages",
        "affected_endpoints", "affected_accounts"]


def test_the_sweep_is_retrospective_and_capped_per_indicator_type():
    steps = {s.id: s for s in WORKFLOW.investigation}
    for step_id in ("hash_sightings", "domain_sightings", "ip_sightings", "sender_activity", "messages",
                    "related_messages"):
        assert steps[step_id].lookback_hours == SWEEP_LOOKBACK_HOURS == 720, step_id
    for step_id in ("hash_reputation", "domain_reputation", "ip_reputation", "url_reputation", "sender_reputation",
                    "hash_sightings", "ip_sightings", "sender_activity"):
        assert steps[step_id].max_subjects == MAX_INDICATORS_PER_TYPE == 25, step_id
    # enrichment asks every enricher under the disclosure policy: no source restriction, no options
    for step in WORKFLOW.investigation:
        if step.atomic.startswith("enrich_"):
            assert step.integrations == () and step.options == {}, step.id
    assert steps["affected_accounts"].integrations == ("entra",)
    assert set(IOC_TYPES) == {_O.SHA256, _O.DOMAIN, _O.IP, _O.URL, _O.EMAIL_ADDRESS}
    assert set(IOC_TYPES) < set(WORKFLOW.input_observables)


def test_rules_build_containment_for_every_affected_asset_with_matching_builders():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.BLOCK_HASH, ActionType.BLOCK_DOMAIN, ActionType.BLOCK_IP, ActionType.BLOCK_URL,
                       ActionType.ISOLATE_ENDPOINT, ActionType.QUARANTINE_FILE, ActionType.QUARANTINE_EMAIL,
                       ActionType.REVOKE_SESSIONS}
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).state_changing
        if rule.builder is not None:
            assert rule.builder in builders
        assert set(rule.mitre) <= WORKFLOW.attack_ids()
        assert rule.min_risk >= BLOCK_MIN_RISK, rule.id
    rules = {r.id: r for r in WORKFLOW.recommendations}
    for rule_id in ("block_swept_hash", "block_swept_domain", "block_swept_ip", "block_swept_url"):
        assert "i.rated" in rules[rule_id].for_each and rules[rule_id].min_risk == BLOCK_MIN_RISK == 30
    assert rules["revoke_sessions_signed_in_from_indicator"].builder == "revoke_entra_sessions"
    assert rules["revoke_sessions_signed_in_from_indicator"].min_risk == REVOKE_MIN_RISK
    assert rules["quarantine_carrier_message"].params == {"recipient": "item.recipient"}
    assert rules["quarantine_swept_file"].min_risk == rules["quarantine_carrier_message"].min_risk == QUARANTINE_MIN_RISK


def test_isolation_rules_are_product_pinned_and_withhold_sanctioned_binaries():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    secure = rules["isolate_affected_endpoint_secure_endpoint"]
    defender = rules["isolate_affected_endpoint_defender_endpoint"]
    assert (secure.builder, defender.builder) == ("isolate_secure_endpoint", "isolate_defender_endpoint")
    assert secure.params == {"connector_guid": "item.connector_guid"}
    assert "item.connector_guid" in (secure.when or "") and "item.mde_machine_id" in (defender.when or "")
    for rule in (secure, defender):
        assert "item.isolate" in (rule.when or "") and "isolation_capable != False" in (rule.when or "")
        assert rule.binaries == "item.binaries" and rule.min_risk == ISOLATE_MIN_RISK == 50


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
    assert triples == {("TA0002", "T1204", "T1204.002"), ("TA0001", "T1566", "T1566.001"),
                       ("TA0001", "T1566", "T1566.002"), ("TA0001", "T1078", None)}
    names = {m.attack_id: (m.technique_name, m.sub_technique_name) for m in WORKFLOW.mitre}
    assert names["T1204.002"] == ("User Execution", "Malicious File")
    assert names["T1566.001"] == ("Phishing", "Spearphishing Attachment")
    assert names["T1078"] == ("Valid Accounts", None)
    for mapping in WORKFLOW.mitre:
        assert mapping.rationale.strip()
    rules = {r.id: r for r in WORKFLOW.recommendations}
    # an indicator names infrastructure, not a behaviour: the domain and IP blocks map to no technique
    assert rules["block_swept_domain"].mitre == () and rules["block_swept_ip"].mitre == ()


@pytest.mark.parametrize("title, observables, source", [
    ("IOC sweep: partner feed batch", (HASH, DOMAIN), "cisco_xdr"),
    ("Retro-hunt for campaign indicators", (IP,), "cisco_xdr"),
    ("High-confidence indicator match", ((_O.EMAIL_ADDRESS, "billing@invoice-notice.example"),), "cisco_xdr"),
    ("New indicator", (DOMAIN,), "threat_intel"),
    ("New indicator", ((_O.URL, "https://update-relay.test/dl/x"),), "threat-intel"),
])
def test_automatic_triggers_match_sweep_incidents(title, observables, source):
    assert WORKFLOW.matches(_incident(title, observables=observables, source=source)) is not None
    assert discover_workflows().resolve(_incident(title, observables=observables, source=source)).definition.id \
        == "threat-intel-sweep"


@pytest.mark.parametrize("title, observables, source, trigger", [
    ("IOC sweep", (HOST,), "cisco_xdr", {}),  # no indicator observable
    ("New indicator", (HASH,), "secure_endpoint", {}),  # not a threat-intelligence source
    ("Malware detected on TH-LT-1047", (HOST, HASH), "cisco_xdr", {}),
    ("Periodic HTTPS beaconing from TH-LT-1047", (HOST, DOMAIN), "cisco_xdr", {"mitre_techniques": ["T1071.001"]}),
])
def test_triggers_do_not_match_ordinary_detections(title, observables, source, trigger):
    assert WORKFLOW.matches(_incident(title, observables=observables, source=source, trigger=trigger)) is None


def test_manual_and_schedule_triggers_never_match_and_workflow_id_routes():
    for trigger in WORKFLOW.triggers:
        if trigger.type in ("manual", "schedule"):
            assert not trigger.matches(_incident("IOC sweep", observables=(HASH,), source="threat_intel"))
    assert {t.type for t in WORKFLOW.triggers} == {"manual", "schedule", "webhook", "xdr_incident_rule"}
    catalog = discover_workflows()
    assert catalog.resolve(_incident("Unrelated", workflow_id="threat-intel-sweep")).definition.id == \
        "threat-intel-sweep"


def test_the_sweep_outranks_every_workflow_it_hands_off_to_and_no_cycle():
    catalog = discover_workflows()
    assert WORKFLOW.handoff_to == ("malware", "c2", "phishing", "account-takeover")
    assert set(WORKFLOW.handoff_to) <= set(WORKFLOW.related_workflows)

    def top(definition: WorkflowDefinition) -> int:
        return max((t.priority for t in definition.triggers if t.type != "manual"), default=0)
    assert top(WORKFLOW) == TRIGGER_PRIORITY
    for target in WORKFLOW.handoff_to:
        assert top(WORKFLOW) > top(catalog.get(target).definition), target
        assert "threat-intel-sweep" not in catalog.get(target).definition.handoff_to


def test_known_limitations_document_the_unverified_and_manual_paths():
    text = " ".join(WORKFLOW.known_limitations)
    for phrase in ("never evidence", "Secure Cloud Analytics", "UNVERIFIED", "UNROUTED", "UNABLE_TO_VERIFY",
                   "manual step", "SHA-1", "IPv6", "720 hours", "considered", "ELEVATED"):
        assert phrase in text, phrase
    assert len(WORKFLOW.known_limitations) >= 10
