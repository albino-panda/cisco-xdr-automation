"""The phishing workflow definition: validation, discovery, triggers, integrations, rules and MITRE."""
from __future__ import annotations

import importlib
from datetime import datetime, timezone

import pytest

from xdr_response.atomics import atomic_subject_types, containment_builders, read_atomics
from xdr_response.integrations.base import EndpointStatus, OperationKind
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.expr import parse
from xdr_response.workflows.phishing import HOOKS, WORKFLOW
from xdr_response.workflows.phishing.hooks import PhishingHooks

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
MESSAGE = "<20260115.0900.4471@invoice-portal.example>"

#: rule id -> (action type, builder, pinned product or None for catalog order)
EXPECTED_RULES = {
    "quarantine_phishing_message": (ActionType.QUARANTINE_EMAIL, "quarantine_email", None),
    "block_phishing_url": (ActionType.BLOCK_URL, "block_url", None),
    "block_phishing_domain": (ActionType.BLOCK_DOMAIN, "block_domain_umbrella", "umbrella"),
    "block_malicious_attachment": (ActionType.BLOCK_HASH, "block_hash", None),
    "revoke_clicked_user_sessions": (ActionType.REVOKE_SESSIONS, "revoke_entra_sessions", "entra"),
    "disable_compromised_user": (ActionType.DISABLE_USER, "disable_entra_user", "entra"),
    "isolate_compromised_endpoint": (ActionType.ISOLATE_ENDPOINT, "isolate_secure_endpoint", "secure_endpoint"),
    "isolate_compromised_defender_endpoint": (ActionType.ISOLATE_ENDPOINT, "isolate_defender_endpoint",
                                              "defender_endpoint"),
}


def _incident(title: str = "Credential phishing delivered to finance", *, trigger: dict | None = None,
              observables: tuple[tuple[ObservableType, str], ...] = ((ObservableType.EMAIL_MESSAGE_ID, MESSAGE),),
              source: str = "xdr", workflow_id: str = "unassigned") -> Incident:
    return Incident(incident_id="XDR-PH-T001", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0", source=source,
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), trigger=trigger or {})


# ------------------------------------------------------------------ identity --
def test_definition_revalidates_and_is_discovered_with_its_hooks():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("phishing")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, PhishingHooks) and found.hooks is HOOKS
    assert (WORKFLOW.id, WORKFLOW.name, WORKFLOW.phase, WORKFLOW.legacy_id) == ("phishing", "Phishing", 2, "phishing")
    assert WORKFLOW.package_name == "phishing"
    assert WORKFLOW.default_severity is Severity.MEDIUM
    assert set(WORKFLOW.related_workflows) == {"account-takeover", "bec", "malware"}


def test_definition_carries_no_approval_switch():
    def keys(node):
        if isinstance(node, dict):
            for key, value in node.items():
                yield str(key).lower()
                yield from keys(value)
        elif isinstance(node, (list, tuple)):
            for value in node:
                yield from keys(value)

    assert not set(keys(WORKFLOW.model_dump(mode="json"))) & APPROVAL_LIKE_KEYS


# ------------------------------------------------------------------ triggers --
@pytest.mark.parametrize("techniques", [["T1566"], ["T1566.001"], ["T1566.002"]])
def test_phishing_techniques_trigger_the_workflow(techniques):
    assert WORKFLOW.matches(_incident(trigger={"mitre_techniques": techniques})) is not None


def test_secure_email_incident_with_a_message_triggers_the_workflow():
    incident = _incident("Verdict changed after delivery", source="secure_email")
    assert WORKFLOW.matches(incident) is not None
    without_message = _incident("Verdict changed after delivery", source="secure_email",
                                observables=((ObservableType.DOMAIN, "invoice-portal.example"),))
    assert WORKFLOW.matches(without_message) is None


def test_title_trigger_needs_a_message_id():
    assert WORKFLOW.matches(_incident("User-reported phish")) is not None
    assert WORKFLOW.matches(_incident("User-reported phish", observables=((ObservableType.HOSTNAME, "TH-LT-1047"),))) \
        is None


def test_unrelated_incidents_do_not_trigger_the_workflow():
    ransomware = _incident("Encryption activity on TH-LT-1047", trigger={"mitre_techniques": ["T1486"]},
                           observables=((ObservableType.HOSTNAME, "TH-LT-1047"),))
    assert WORKFLOW.matches(ransomware) is None
    manual = next(t for t in WORKFLOW.triggers if t.type == "manual")
    assert not manual.matches(_incident())


# -------------------------------------------------------------- integrations --
def test_integrations_follow_the_brief():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_email", "entra", "umbrella"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "defender_o365", "virustotal", "alienvault_otx", "secure_endpoint", "defender_endpoint", "cisco_xdr",
        "microsoft_cloud"}
    assert WORKFLOW.expected_sources() == ("secure_email", "entra", "umbrella")


def test_declared_atomics_are_served_by_the_real_adapter():
    """An integration is only declared for atomics its (VERIFIED-only) manifest serves."""
    subject_types = atomic_subject_types()
    for requirement in (*WORKFLOW.required_integrations, *WORKFLOW.optional_integrations):
        manifest = importlib.import_module(f"xdr_response.integrations.{requirement.integration}.manifest").MANIFEST
        for atomic in requirement.atomics:
            if atomic.startswith("enrich_"):  # enrichment is served by observable type
                assert subject_types[atomic] & set(manifest.enrichment_types), (requirement.integration, atomic)
            else:
                assert ActionType(atomic) in manifest.read_actions, (requirement.integration, atomic)


def test_defender_o365_contributes_no_read_because_its_read_api_is_unverified():
    requirement = next(r for r in WORKFLOW.optional_integrations if r.integration == "defender_o365")
    assert requirement.atomics == ()
    manifest = importlib.import_module("xdr_response.integrations.defender_o365.manifest").MANIFEST
    reads = [op for op in manifest.operations if op.kind is OperationKind.READ and op.name != "token"]
    assert reads and all(op.status is EndpointStatus.UNVERIFIED for op in reads)


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_RULES))
def test_pinned_products_execute_the_action_through_a_verified_operation(rule_id):
    action, _, product = EXPECTED_RULES[rule_id]
    candidates = [product] if product else list(get_action_spec(action).integrations)
    supported = []
    for name in candidates:
        manifest = importlib.import_module(f"xdr_response.integrations.{name}.manifest").MANIFEST
        if action in manifest.supported_actions:
            supported.append(name)
    assert supported, f"{rule_id}: no real adapter supports {action.value}"


# --------------------------------------------------------------------- steps --
def test_every_step_uses_a_read_atomic_with_a_supported_subject_type():
    subject_types = atomic_subject_types()
    for step in WORKFLOW.investigation:
        assert step.atomic in read_atomics()
        if step.subject_type is not None:
            assert step.subject_type in subject_types[step.atomic]
        for expression in (step.subjects, step.when):
            if expression is not None:
                parse(expression)


def test_the_investigation_covers_the_brief_in_order():
    atomics = [s.atomic for s in WORKFLOW.investigation]
    assert atomics == ["investigate_email", "search_email_campaign", "enrich_email_address", "enrich_url",
                       "enrich_domain", "enrich_ip", "enrich_hash", "search_domain_enterprise",
                       "search_hash_enterprise", "investigate_endpoint", "investigate_user",
                       "investigate_authentication"]
    # click activity runs before the endpoints and users it discovers are investigated
    assert atomics.index("search_domain_enterprise") < atomics.index("investigate_endpoint")
    assert atomics.index("investigate_endpoint") < atomics.index("investigate_authentication")


def test_correlation_window_covers_a_working_day():
    assert WORKFLOW.correlation.window_minutes == 1440


# --------------------------------------------------------------------- rules --
def test_rules_build_the_brief_containment_package():
    assert {r.id for r in WORKFLOW.recommendations} == set(EXPECTED_RULES)
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        action, builder, _ = EXPECTED_RULES[rule.id]
        assert (rule.action, rule.builder) == (action, builder)
        assert rule.builder in builders
        assert get_action_spec(rule.action).state_changing
        for expression in (rule.for_each, rule.when, rule.target, rule.evidence, rule.asset, rule.rationale,
                           *rule.params.values()):
            if expression is not None:
                parse(expression)


def test_every_rule_cites_records_from_the_hook_facts():
    for rule in WORKFLOW.recommendations:
        assert rule.for_each.startswith("get(facts, ")
        assert rule.evidence in ("item.record_ids", "item.disable_record_ids")


def test_thresholds_keep_reputation_alone_below_the_proposal_line():
    by_id = {r.id: r for r in WORKFLOW.recommendations}
    assert all(r.min_risk >= 60 for r in WORKFLOW.recommendations)
    assert by_id["disable_compromised_user"].min_risk > by_id["revoke_clicked_user_sessions"].min_risk
    assert by_id["disable_compromised_user"].when == "item.disable_justified"


def test_quarantine_params_carry_no_routing_or_approval_keys():
    rule = next(r for r in WORKFLOW.recommendations if r.id == "quarantine_phishing_message")
    # The Secure Email move verdict comes from integrations.secure_email.options (14.10.3), never the rule.
    assert set(rule.params) == {"recipient"}
    assert rule.when == "item.delivered"


def test_account_and_endpoint_rules_pass_asset_context_for_critical_asset_matching():
    for rule in WORKFLOW.recommendations:
        if rule.action in (ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER):
            assert "roles" in rule.asset and "groups" in rule.asset
        if rule.action is ActionType.ISOLATE_ENDPOINT:
            assert "groups" in rule.asset and "tags" in rule.asset


# --------------------------------------------------------------------- MITRE --
def test_mitre_mapping_has_no_forced_mappings():
    assert WORKFLOW.attack_ids() == {"T1566", "T1566.001", "T1566.002", "T1204", "T1204.001", "T1204.002",
                                     "T1078", "T1078.004"}
    assert {m.tactic for m in WORKFLOW.mitre} == {"TA0001", "TA0002"}
    used = {i for r in WORKFLOW.recommendations for i in r.mitre}
    assert {m.attack_id for m in WORKFLOW.mitre} <= used  # every mapping is answered by a rule
    for mapping in WORKFLOW.mitre:
        assert mapping.rationale.strip()


def test_known_limitations_name_the_unverified_paths():
    text = " ".join(WORKFLOW.known_limitations)
    assert "UNVERIFIED" in text and "UNABLE_TO_VERIFY" in text and "not reversible" in text
    assert len(WORKFLOW.known_limitations) >= 5
