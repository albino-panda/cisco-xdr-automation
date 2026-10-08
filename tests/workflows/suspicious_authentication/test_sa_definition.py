"""The suspicious-authentication WorkflowDefinition: validation, triggers and routing, rules, MITRE (14.3.1, 14.5)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_response.models import INTEGRATION_NAMES, ActionType, Incident, Observable, ObservableType, Severity
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.expr import evaluate, names_used
from xdr_response.workflows.suspicious_authentication import HOOKS, WORKFLOW
from xdr_response.workflows.suspicious_authentication.definition import EMAIL_SUBJECTS, MANAGED_DEVICE_SUBJECTS
from xdr_response.workflows.suspicious_authentication.hooks import SuspiciousAuthenticationHooks

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
CATALOG = discover_workflows()
_O = ObservableType
USER = (_O.USER, "jsmith@example.com")


def _incident(*observables: tuple[ObservableType, str], title: str = "Alert", techniques: tuple[str, ...] = (),
              workflow_id: str = "unassigned") -> Incident:
    return Incident(incident_id="XDR-SA-T-0001", title=title, severity=Severity.MEDIUM, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0", source="cisco_xdr",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables),
                    trigger={"mitre_techniques": list(techniques)})


def _walk_keys(node: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            keys.add(str(key).lower())
            keys |= _walk_keys(value)
    elif isinstance(node, (list, tuple)):
        for value in node:
            keys |= _walk_keys(value)
    return keys


def test_definition_is_discovered_with_its_hooks():
    discovered = CATALOG.get("suspicious-authentication")
    assert discovered.definition == WORKFLOW
    assert isinstance(discovered.hooks, SuspiciousAuthenticationHooks) and discovered.hooks is HOOKS
    assert discovered.module == "xdr_response.workflows.suspicious_authentication"
    assert WORKFLOW.package_name == "suspicious_authentication"


def test_definition_revalidates_and_is_a_new_phase_4_workflow():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    assert WORKFLOW.legacy_id is None
    assert WORKFLOW.phase == 4
    assert WORKFLOW.default_severity is Severity.MEDIUM


def test_definition_carries_no_approval_switch():
    assert not _walk_keys(WORKFLOW.model_dump(mode="json")) & APPROVAL_LIKE_KEYS
    text = repr(WORKFLOW.model_dump(mode="json")).lower()
    for word in ("auto_approve", "skip_approval", "bypass_approval", "approval_required", "unlock"):
        assert word not in text


def test_recommendations_are_the_brief_package_with_named_builders():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    assert {(r.action, r.builder) for r in rules.values()} == {
        (ActionType.REVOKE_SESSIONS, "revoke_entra_sessions"),
        (ActionType.DISABLE_USER, "disable_entra_user"),
        (ActionType.BLOCK_IP, "block_ip"),
    }
    for rule in rules.values():
        assert rule.min_risk >= 50, rule.id  # a weak finding is reported BELOW_THRESHOLD, never proposed
        assert set(rule.mitre) <= WORKFLOW.attack_ids()
    # the account rules pass the investigated asset context so PackageBuilder can decide ELEVATED
    assert "privileged" in rules["revoke_suspicious_sessions"].asset
    assert "privileged" in rules["disable_compromised_account"].asset


def test_rule_and_step_expressions_read_only_framework_names():
    allowed = {"incident", "results", "enrichment", "correlation", "blast", "facts", "item"}
    for rule in WORKFLOW.recommendations:
        for expression in (rule.for_each, rule.when, rule.target, rule.evidence, rule.asset, rule.rationale):
            if expression:
                assert names_used(expression) <= allowed, (rule.id, expression)
    for step in WORKFLOW.investigation:
        for expression in (step.subjects, step.when):
            if expression:
                assert names_used(expression) <= allowed, (step.id, expression)


def test_integrations_cover_the_brief_and_only_known_names():
    required = {r.integration for r in WORKFLOW.required_integrations}
    optional = {r.integration for r in WORKFLOW.optional_integrations}
    assert required == {"entra", "cisco_xdr"}
    assert {"intune", "microsoft_cloud", "defender_endpoint", "hibp", "virustotal", "alienvault_otx"} <= optional
    assert not required & optional
    assert (required | optional) <= set(INTEGRATION_NAMES)
    assert "umbrella" not in required | optional  # direct Umbrella IP blocking is UNVERIFIED


def test_investigation_plan():
    steps = {s.id: s for s in WORKFLOW.investigation}
    assert [s.atomic for s in WORKFLOW.investigation] == [
        "investigate_user", "investigate_authentication", "search_user_activity", "enrich_email_address",
        "enrich_ip", "search_ip_enterprise", "investigate_endpoint"]
    assert steps["authentication"].lookback_hours == 336  # the 14-day baseline
    assert steps["managed_device"].integrations == ("intune",)
    assert steps["managed_device"].subject_type is _O.ENDPOINT_ID
    assert steps["credential_exposure"].integrations == ()  # enrichment asks every enricher under the policy


def test_exposure_subjects_are_the_email_shaped_accounts_only():
    incident = _incident((_O.USER, "JSmith@Example.com"), (_O.USER, "svc-backup"),
                         (_O.EMAIL_ADDRESS, "jsmith.home@mailbox.test"))
    names = {"incident": {**incident.model_dump(mode="json"),
                          "observables_by_type": {"user": ["JSmith@Example.com", "svc-backup"],
                                                  "email_address": ["jsmith.home@mailbox.test"]}}}
    assert evaluate(EMAIL_SUBJECTS, names) == ["jsmith.home@mailbox.test", "jsmith@example.com"]
    names["incident"]["observables_by_type"]["endpoint_id"] = ["00000000-0000-4000-8000-0000000000c1"]
    assert evaluate(MANAGED_DEVICE_SUBJECTS, names) == ["00000000-0000-4000-8000-0000000000c1"]


def test_mitre_mapping_has_no_forced_techniques():
    assert {(m.tactic, m.technique, m.sub_technique) for m in WORKFLOW.mitre} == {
        ("TA0001", "T1078", "T1078.004"), ("TA0011", "T1090", "T1090.003")}
    assert all(m.rationale for m in WORKFLOW.mitre)
    names = {m.attack_id: m.sub_technique_name for m in WORKFLOW.mitre}
    assert names == {"T1078.004": "Cloud Accounts", "T1090.003": "Multi-hop Proxy"}


def test_shared_techniques_keep_one_name_and_tactic_across_workflows():
    for workflow_id in CATALOG.ids():
        for mapping in CATALOG.get(workflow_id).definition.mitre:
            for mine in WORKFLOW.mitre:
                if mapping.technique == mine.technique:
                    assert (mapping.tactic, mapping.technique_name) == (mine.tactic, mine.technique_name), workflow_id


# ---------------------------------------------------------------- routing --
ROUTES = [
    pytest.param(_incident(USER, title="Suspicious sign-in for jsmith@example.com"), "suspicious-authentication",
                 id="title"),
    pytest.param(_incident(USER, title="Sign-in from Tor exit node for jsmith@example.com"),
                 "suspicious-authentication", id="tor-title"),
    pytest.param(_incident(USER, title="Leaked credentials for jsmith@example.com"), "suspicious-authentication",
                 id="leaked-credentials-title"),
    pytest.param(_incident(USER, title="Suspicious sign-in: impossible travel"), "suspicious-authentication",
                 id="title-over-account-takeover-title"),
    pytest.param(_incident(USER, techniques=("T1078.002",)), "suspicious-authentication", id="T1078.002"),
    pytest.param(_incident(USER, techniques=("T1078",)), "suspicious-authentication", id="T1078"),
    # account-takeover keeps what it claimed before this workflow existed
    pytest.param(_incident(USER, techniques=("T1078.004",)), "account-takeover", id="T1078.004"),
    pytest.param(_incident(USER, title="Impossible travel for jsmith@example.com"), "account-takeover",
                 id="account-takeover-title"),
    pytest.param(_incident(USER, title="Suspicious sign-in", techniques=("T1621",)), "mfa-fatigue", id="mfa-fatigue"),
    pytest.param(_incident(USER, (_O.IP, "203.0.113.200"), title="Suspicious sign-in",
                           techniques=("T1110.003",)), "password-spray", id="password-spray"),
]


@pytest.mark.parametrize("incident, expected", ROUTES)
def test_routing_between_identity_workflows(incident: Incident, expected: str):
    resolved = CATALOG.resolve(incident)
    assert resolved is not None and resolved.definition.id == expected


def test_an_incident_without_an_account_does_not_match():
    incident = _incident((_O.IP, "203.0.113.200"), title="Suspicious sign-in from 203.0.113.200")
    assert WORKFLOW.matches(incident) is None


def test_hands_off_to_account_takeover_and_outranks_it():
    assert WORKFLOW.handoff_to == ("account-takeover",)
    top = max(t.priority for t in WORKFLOW.triggers if t.type != "manual")
    target = max(t.priority for t in CATALOG.get("account-takeover").definition.triggers if t.type != "manual")
    assert top > target


def test_known_limitations_document_the_gaps():
    text = " ".join(WORKFLOW.known_limitations)
    for needle in ("ASN", "HIBP", "Intune", "UNVERIFIED", "not reversible", "allowlists.never_block"):
        assert needle in text, needle
