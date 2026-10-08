"""The ``bec`` workflow definition: validation, discovery, triggers, rules and MITRE mapping (fake data)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_response.models import ActionCategory, ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.bec import HOOKS, WORKFLOW
from xdr_response.workflows.bec.definition import MANUAL_STEPS
from xdr_response.workflows.bec.hooks import BecHooks
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def _incident(title: str = "Something happened", *, techniques: tuple[str, ...] = (),
              observables: tuple[tuple[ObservableType, str], ...] = ((ObservableType.EMAIL_ADDRESS,
                                                                       "jsmith@example.com"),)) -> Incident:
    return Incident(incident_id="XDR-BEC-UNIT", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id="unassigned", workflow_version="0.0.0",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables),
                    trigger={"mitre_techniques": list(techniques)})


def _walk_keys(node: object) -> set[str]:
    if isinstance(node, dict):
        return {str(k).lower() for k in node} | {k for v in node.values() for k in _walk_keys(v)}
    if isinstance(node, (list, tuple)):
        return {k for v in node for k in _walk_keys(v)}
    return set()


def test_definition_revalidates_and_is_discovered_with_its_hooks():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("bec")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, BecHooks) and found.hooks is HOOKS
    assert (WORKFLOW.id, WORKFLOW.phase, WORKFLOW.legacy_id, WORKFLOW.package_name) == ("bec", 2, "bec", "bec")


def test_definition_carries_no_approval_switch():
    assert not _walk_keys(WORKFLOW.model_dump(mode="json")) & APPROVAL_LIKE_KEYS


def test_required_and_optional_integrations():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["entra", "secure_email"]
    assert WORKFLOW.expected_sources() == ("entra", "secure_email")
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "umbrella", "virustotal", "cisco_xdr", "microsoft_cloud", "defender_o365", "secure_endpoint", "splunk"}


def test_investigation_plan_covers_the_brief():
    atomics = [s.atomic for s in WORKFLOW.investigation]
    assert atomics == ["investigate_email", "search_email_campaign", "enrich_email_address", "enrich_domain",
                       "investigate_user", "investigate_authentication", "enrich_ip", "investigate_endpoint"]


def test_rules_only_recommend_containment_or_remediation_of_the_package():
    actions = {r.id: r.action for r in WORKFLOW.recommendations}
    assert actions == {
        "revoke_compromised_mailbox_sessions": ActionType.REVOKE_SESSIONS,
        "disable_abused_mailbox": ActionType.DISABLE_USER,
        "quarantine_fraud_messages": ActionType.QUARANTINE_EMAIL,
        "block_impersonation_domain": ActionType.BLOCK_DOMAIN,
        "isolate_infected_endpoint": ActionType.ISOLATE_ENDPOINT,
    }
    for rule in WORKFLOW.recommendations:
        assert get_action_spec(rule.action).category in (ActionCategory.CONTAINMENT, ActionCategory.REMEDIATION)
        assert rule.min_risk >= 40, "every rule needs real evidence of risk before it proposes"


def test_disable_needs_compromise_and_abuse_while_revoke_needs_either():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    assert rules["revoke_compromised_mailbox_sessions"].when == "item.identity_compromise or item.abuse"
    assert rules["disable_abused_mailbox"].when == "item.identity_compromise and item.abuse"


def test_mitre_mapping_has_no_forced_mappings():
    assert WORKFLOW.attack_ids() == {"T1078", "T1078.004", "T1114", "T1114.003", "T1564", "T1564.008", "T1534",
                                     "T1656"}
    used = {m for r in WORKFLOW.recommendations for m in r.mitre}
    assert {m.attack_id for m in WORKFLOW.mitre} <= used, "every mapped technique is answered by a rule"
    assert all(m.rationale for m in WORKFLOW.mitre)


@pytest.mark.parametrize("techniques", [("T1534",), ("T1114.003",), ("T1656",)])
def test_technique_trigger_matches(techniques):
    assert WORKFLOW.matches(_incident(techniques=techniques)) is not None


@pytest.mark.parametrize("title, expected", [
    ("BEC attempt against finance", True),
    ("Suspected business email compromise", True),
    ("Vendor bank detail change request", True),
    ("New inbox rule forwarding mail", True),
    ("Printer offline because of toner", False),  # "because" must not match the BEC pattern
    ("Malware detected on TH-LT-1047", False),
])
def test_title_trigger(title, expected):
    assert (WORKFLOW.matches(_incident(title)) is not None) is expected


def test_title_trigger_needs_a_mail_or_identity_observable():
    host_only = _incident("BEC attempt", observables=((ObservableType.HOSTNAME, "TH-LT-1047"),))
    assert WORKFLOW.matches(host_only) is None


def test_manual_steps_and_limitations_are_documented():
    assert any("inbox / forwarding rule" in s for s in MANUAL_STEPS)
    assert any("OAuth" in s for s in MANUAL_STEPS)
    assert any("mail gateway" in s for s in MANUAL_STEPS)
    assert len(WORKFLOW.known_limitations) >= 5
    assert any("VERIFIED" in limitation for limitation in WORKFLOW.known_limitations)
