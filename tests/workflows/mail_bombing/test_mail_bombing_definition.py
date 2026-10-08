"""The ``mail-bombing`` definition: validation, discovery, triggers, ownership rules and README (14.5)."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.sample_workflows.lab import make_incident
from tools.validation.check_workflow_readmes import check_readme
from xdr_response.atomics import containment_builders, read_atomics
from xdr_response.models import ActionCategory, ActionType, Observable, ObservableType, get_action_spec
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.mail_bombing import HOOKS, WORKFLOW
from xdr_response.workflows.mail_bombing.hooks import BURIED_KEYWORDS, MailBombingHooks, classify_subject

REPO = Path(__file__).resolve().parents[3]
RECIPIENT = (ObservableType.EMAIL_ADDRESS, "jsmith@example.com")


def _walk_keys(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield str(key).lower()
            yield from _walk_keys(value)
    elif isinstance(node, (list, tuple)):
        for value in node:
            yield from _walk_keys(value)


def test_definition_revalidates_and_is_discovered_with_its_hooks():
    again = WorkflowDefinition.model_validate(WORKFLOW.model_dump())
    assert again == WORKFLOW
    found = discover_workflows().get("mail-bombing")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, MailBombingHooks) and found.hooks is HOOKS
    assert found.module == "xdr_response.workflows.mail_bombing"


def test_identity_and_legacy_alignment():
    assert WORKFLOW.id == "mail-bombing" and WORKFLOW.package_name == "mail_bombing"
    assert WORKFLOW.legacy_id == "mail-bombing"
    assert WORKFLOW.phase == 2
    assert not (REPO / "workflows" / "mail-bombing" / "workflow.yaml").exists()
    assert not (REPO / "workflows" / "mail-bombing" / "scenarios").exists()


def test_required_and_optional_integrations():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_email", "entra"]
    assert WORKFLOW.expected_sources() == ("secure_email", "entra")
    optional = {r.integration for r in WORKFLOW.optional_integrations}
    assert {"cisco_xdr", "umbrella", "secure_endpoint", "microsoft_cloud", "splunk"} <= optional
    for requirement in (*WORKFLOW.required_integrations, *WORKFLOW.optional_integrations):
        assert set(requirement.atomics) <= set(read_atomics())


def test_investigation_plan_uses_only_read_atomics_in_order():
    atomics = [s.atomic for s in WORKFLOW.investigation]
    assert atomics == ["search_email_campaign", "investigate_user", "investigate_authentication",
                       "search_user_activity", "investigate_endpoint", "enrich_domain"]
    for step in WORKFLOW.investigation:
        spec = get_action_spec(ActionType(step.atomic))
        assert spec.category in (ActionCategory.INVESTIGATION, ActionCategory.ENRICHMENT)
        assert not spec.state_changing


def test_recommendations_produce_the_brief_package_and_only_containment_types():
    actions = {r.id: r.action for r in WORKFLOW.recommendations}
    assert actions == {
        "quarantine_flood_messages": ActionType.QUARANTINE_EMAIL,
        "revoke_sessions_buried_identity_event": ActionType.REVOKE_SESSIONS,
        "disable_account_on_takeover": ActionType.DISABLE_USER,
        "isolate_recipient_endpoint": ActionType.ISOLATE_ENDPOINT,
        "block_malicious_flood_domain": ActionType.BLOCK_DOMAIN,
    }
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).category in (ActionCategory.CONTAINMENT, ActionCategory.REMEDIATION)
        if rule.builder is not None:
            assert rule.builder in builders
        assert rule.evidence.strip(), "every rule cites records"
        assert set(rule.mitre) <= WORKFLOW.attack_ids()


def test_no_approval_switch_anywhere_in_the_definition():
    keys = set(_walk_keys(WORKFLOW.model_dump(mode="json")))
    assert not keys & APPROVAL_LIKE_KEYS
    assert "auto_approve" not in str(WORKFLOW.model_dump(mode="json")).lower()


def test_mitre_mapping_has_no_forced_legacy_technique():
    ids = WORKFLOW.attack_ids()
    assert {"T1667", "T1656", "T1621", "T1078", "T1078.004", "T1564", "T1564.008", "T1219", "T1566"} == ids
    assert "T1499" not in ids  # Endpoint Denial of Service was a loose legacy mapping
    assert all(m.rationale for m in WORKFLOW.mitre)


@pytest.mark.parametrize("kwargs, expected", [
    ({"source": "cisco-xdr-mailbomb-detector"}, "webhook"),
    ({"trigger": {"source": "cisco-xdr-mailbomb-detector"}}, "webhook"),
    ({"trigger": {"mitre_techniques": ["T1667"]}}, "xdr_incident_rule"),
    ({"title": "Possible email bombing of jsmith@example.com"}, "xdr_incident_rule"),
    ({"title": "Subscription bomb against the finance mailbox"}, "xdr_incident_rule"),
])
def test_triggers_match_detector_and_xdr_incidents(kwargs, expected):
    params = {"title": "Unrelated title", **kwargs}
    incident = make_incident(RECIPIENT, workflow_id="unassigned", **params)
    trigger = WORKFLOW.matches(incident)
    assert trigger is not None and trigger.type == expected


def test_triggers_do_not_match_unrelated_incidents():
    plain = make_incident(RECIPIENT, workflow_id="unassigned", title="Malware detected on TH-LT-1047")
    assert WORKFLOW.matches(plain) is None
    endpoint_dos = make_incident((ObservableType.HOSTNAME, "TH-LT-1047"), workflow_id="unassigned",
                                 title="Service flood", trigger={"mitre_techniques": ["T1499"]})
    assert WORKFLOW.matches(endpoint_dos) is None
    no_mailbox = make_incident((ObservableType.HOSTNAME, "TH-LT-1047"), workflow_id="unassigned",
                               title="Email bombing", trigger={"mitre_techniques": ["T1667"]})
    assert WORKFLOW.matches(no_mailbox) is None


def test_catalog_routes_an_assigned_incident_to_the_workflow():
    catalog = discover_workflows()
    incident = make_incident(RECIPIENT, workflow_id="mail-bombing", title="anything")
    assert catalog.resolve(incident).definition.id == "mail-bombing"


@pytest.mark.parametrize("subject, categories", [
    ("Your password was changed", ("credential",)),
    ("Password reset requested for your account", ("credential",)),
    ("New sign-in to your account", ("security_alert",)),
    ("Your verification code", ("mfa",)),
    ("Urgent wire transfer for supplier", ("financial",)),
    ("DocuSign: invoice awaiting your signature", ("financial", "lure")),
    ("Microsoft account security alert", ("lure", "security_alert")),
    ("Account recovery started", ("credential",)),
    ("Welcome to Signup Alerts", ()),
    (None, ()),
])
def test_buried_subject_classification(subject, categories):
    assert classify_subject(subject) == categories


def test_buried_keywords_cover_the_brief():
    words = " ".join(w for group in BURIED_KEYWORDS.values() for w in group)
    for topic in ("password reset", "password changed", "security alert", "new login", "new device", "mfa",
                  "authentication", "wire transfer", "invoice", "bank", "docusign", "microsoft", "account recovery"):
        assert topic in words, topic


def test_readme_passes_the_validator():
    text = (REPO / "workflows" / "mail-bombing" / "README.md").read_text(encoding="utf-8")
    assert check_readme(WORKFLOW, text) == []
    assert len([l for l in text.splitlines() if l.startswith("## ")]) == 17


def test_observable_inputs_are_declared():
    assert set(WORKFLOW.input_observables) >= {ObservableType.EMAIL_ADDRESS, ObservableType.EMAIL_MESSAGE_ID}
    Observable(type=ObservableType.EMAIL_MESSAGE_ID, value="etd-mb-0001-001")  # the seed format is valid
