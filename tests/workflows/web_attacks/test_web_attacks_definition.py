"""The web-attacks workflow definition: validation, discovery, triggers, integrations, rules, MITRE."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_response.atomics import atomic_subject_types, containment_builders
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.web_attacks import HOOKS, WORKFLOW
from xdr_response.workflows.web_attacks.definition import (
    ATTACK_IDS,
    AUTHORIZED_SCANNERS_KEY,
    ENDPOINT_SOURCES,
    HUNT_SOURCES,
    ISOLATION_MIN_RISK,
    SOURCE_MIN_RISK,
    URL_MIN_RISK,
    WEB_SHELL_TECHNIQUE,
)
from xdr_response.workflows.web_attacks.hooks import WebAttacksHooks

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
HOST = (ObservableType.HOSTNAME, "WEB-SHOP-01")
IP = (ObservableType.IP, "203.0.113.145")
URL = (ObservableType.URL, "https://shop.example.net/upload")
USER = (ObservableType.USER, "jsmith@example.com")


def _incident(title: str = "Endpoint alert", *, trigger: dict | None = None,
              observables: tuple[tuple[ObservableType, str], ...] = (HOST,), workflow_id: str = "unassigned",
              source: str = "cisco_xdr") -> Incident:
    return Incident(incident_id="XDR-WEB-T001", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0", source=source,
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), trigger=trigger or {})


def test_definition_revalidates_and_is_discovered():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("web-attacks")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, WebAttacksHooks) and found.hooks is HOOKS
    assert WORKFLOW.package_name == "web_attacks"
    assert (WORKFLOW.id, WORKFLOW.name, WORKFLOW.phase, WORKFLOW.legacy_id) == (
        "web-attacks", "Web application attacks", 5, "web-attacks")
    assert WORKFLOW.default_severity is Severity.MEDIUM  # the legacy default severity


def test_integrations_are_known_and_only_verified_reads_are_used():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_endpoint", "cisco_xdr"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "defender_endpoint", "virustotal", "alienvault_otx", "microsoft_cloud", "splunk", "meraki", "umbrella"}
    assert WORKFLOW.expected_sources() == ("secure_endpoint", "cisco_xdr")
    for name in ("meraki", "umbrella"):  # write landing products only: no VERIFIED read atomic is used
        assert next(r for r in WORKFLOW.optional_integrations if r.integration == name).atomics == ()
    known = set(WORKFLOW.integrations())
    for step in WORKFLOW.investigation:
        assert set(step.integrations) <= known
    assert set(ENDPOINT_SOURCES) <= known and set(HUNT_SOURCES) <= known
    # the legacy Cloudflare edge and ServiceNow are not Phase 0 integrations
    text = repr(WORKFLOW.model_dump(mode="json")).lower()
    assert "servicenow" not in text


def test_every_step_uses_a_read_atomic_with_a_supported_subject_type():
    subject_types = atomic_subject_types()
    for step in WORKFLOW.investigation:
        assert step.atomic in subject_types
        if step.subject_type is not None:
            assert step.subject_type in subject_types[step.atomic]
    assert [s.id for s in WORKFLOW.investigation] == [
        "web_server_triage", "source_reputation", "source_sightings", "related_servers", "web_shell_reputation"]


def test_rules_build_the_brief_package_with_matching_builders():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.BLOCK_IP, ActionType.BLOCK_URL, ActionType.ISOLATE_ENDPOINT}
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).state_changing
        assert rule.builder in builders
        assert set(rule.mitre) <= WORKFLOW.attack_ids()
        assert rule.min_risk >= 30, rule.id
    assert (SOURCE_MIN_RISK, URL_MIN_RISK, ISOLATION_MIN_RISK) == (30, 30, 60)


def test_source_block_needs_a_rating_and_never_blocks_an_authorised_scanner():
    rule = next(r for r in WORKFLOW.recommendations if r.id == "block_attacking_source")
    assert rule.for_each == "facts.sources"
    assert rule.when == "item.rated and not item.authorized"
    assert AUTHORIZED_SCANNERS_KEY == "authorized_scanners"


def test_url_block_needs_exploitation_and_cites_no_target_enrichment():
    rule = next(r for r in WORKFLOW.recommendations if r.id == "block_exploited_url")
    assert rule.when == "item.exploited" and rule.include_target_enrichment is False
    assert rule.mitre == ("T1190",)


def test_isolation_rules_are_product_pinned_and_need_a_confirmed_web_shell():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    secure = rules["isolate_web_shell_server_secure_endpoint"]
    defender = rules["isolate_web_shell_server_defender_endpoint"]
    assert (secure.builder, defender.builder) == ("isolate_secure_endpoint", "isolate_defender_endpoint")
    assert secure.params == {"connector_guid": "item.connector_guid"}
    assert "item.connector_guid" in (secure.when or "") and "item.mde_machine_id" in (defender.when or "")
    for rule in (secure, defender):
        assert "s.isolate" in rule.for_each and "isolation_capable != False" in rule.for_each
        assert rule.min_risk == ISOLATION_MIN_RISK and rule.mitre == (WEB_SHELL_TECHNIQUE,)
        assert rule.binaries is None  # a web shell detection stands on its own


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
    assert triples == {("TA0001", "T1190", None), ("TA0043", "T1595", "T1595.002"),
                       ("TA0003", "T1505", "T1505.003")}
    assert WORKFLOW.attack_ids() == frozenset({"T1190", "T1595", "T1595.002", "T1505", "T1505.003"})
    names = {m.attack_id: (m.technique_name, m.sub_technique_name) for m in WORKFLOW.mitre}
    assert names["T1190"] == ("Exploit Public-Facing Application", None)
    assert names["T1595.002"] == ("Active Scanning", "Vulnerability Scanning")
    assert names["T1505.003"] == ("Server Software Component", "Web Shell")
    for mapping in WORKFLOW.mitre:
        assert mapping.rationale.strip()
    assert set(ATTACK_IDS) <= WORKFLOW.attack_ids()


@pytest.mark.parametrize("trigger, observables, title", [
    ({"mitre_techniques": ["T1505.003"]}, (HOST,), "Endpoint alert"),
    ({"mitre_techniques": ["T1505.003", "T1190"]}, (HOST, URL), "Endpoint alert"),
    ({"mitre_techniques": ["T1595.002"]}, (IP,), "Network alert"),
    ({}, (HOST,), "Web shell detected on WEB-SHOP-01"),
    ({}, (IP, URL), "SQL injection attempts against the shop"),
    ({}, (IP,), "WAF rule hits from scheduled external vulnerability scan"),
    ({}, (IP,), "Vulnerability scanning against shop application"),
    ({}, (URL,), "Path traversal on the customer portal"),
])
def test_automatic_triggers_match_web_attack_incidents(trigger, observables, title):
    assert WORKFLOW.matches(_incident(title, trigger=trigger, observables=observables)) is not None


@pytest.mark.parametrize("trigger, observables, title", [
    ({"mitre_techniques": ["T1190"]}, (HOST, URL), "Endpoint alert"),  # vulnerability-exploitation's trigger
    ({"mitre_techniques": ["T1203"]}, (HOST,), "Endpoint alert"),
    ({"mitre_techniques": ["T1071.001"]}, (HOST,), "Endpoint alert"),
    ({}, (USER,), "Web shell detected"),  # no IP, URL or hostname
    ({}, (HOST,), "Impossible travel for a user"),
])
def test_triggers_do_not_match_unrelated_incidents(trigger, observables, title):
    assert WORKFLOW.matches(_incident(title, trigger=trigger, observables=observables)) is None


def test_manual_trigger_never_matches_and_the_catalog_routes_by_workflow_id_and_technique():
    manual = [t for t in WORKFLOW.triggers if t.type == "manual"]
    assert len(manual) == 1 and not manual[0].matches(_incident())
    catalog = discover_workflows()
    assert catalog.resolve(_incident("Unrelated title", workflow_id="web-attacks")).definition.id == "web-attacks"
    shell = _incident(trigger={"mitre_techniques": ["T1505.003", "T1204.002"]}, observables=(HOST, IP))
    assert catalog.resolve(shell).definition.id == "web-attacks"  # outranks malware, which it hands off to
    exploited = _incident(trigger={"mitre_techniques": ["T1505.003", "T1190"]}, observables=(HOST, IP, URL))
    assert catalog.resolve(exploited).definition.id == "web-attacks"  # a web shell outranks the exploit trigger
    if "vulnerability-exploitation" in catalog:
        exploit = _incident(trigger={"mitre_techniques": ["T1190"]}, observables=(HOST, IP, URL))
        assert catalog.resolve(exploit).definition.id == "vulnerability-exploitation"
        scan = _incident(trigger={"mitre_techniques": ["T1595.002"]}, observables=(IP,))
        assert catalog.resolve(scan).definition.id == "web-attacks"


def test_web_attacks_outranks_the_workflow_it_hands_off_to():
    catalog = discover_workflows()
    assert WORKFLOW.handoff_to == ("malware",) and set(WORKFLOW.handoff_to) <= set(WORKFLOW.related_workflows)

    def top(definition: WorkflowDefinition) -> int:
        return max(t.priority for t in definition.triggers if t.type != "manual")
    assert top(WORKFLOW) > top(catalog.get("malware").definition)
    assert "web-attacks" not in catalog.get("malware").definition.handoff_to  # no hand-off cycle


def test_known_limitations_document_the_unverified_manual_steps():
    text = " ".join(WORKFLOW.known_limitations)
    for phrase in ("WAF", "Cloudflare", "manual step", "UNVERIFIED", "UNABLE_TO_VERIFY", "IPv6",
                   "authorized_scanners", "fix_pending", "by hand", "malware workflow"):
        assert phrase in text, phrase
