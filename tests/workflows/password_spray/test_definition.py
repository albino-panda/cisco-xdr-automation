"""The password-spray WorkflowDefinition: validation, triggers, rules and MITRE mapping (architecture 14.3.1, 14.5)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.expr import names_used
from xdr_response.workflows.password_spray import HOOKS, WORKFLOW
from xdr_response.workflows.password_spray.definition import FOLLOW_ON_ANOMALIES, SPRAY_MIN_ACCOUNTS
from xdr_response.workflows.password_spray.hooks import PasswordSprayHooks

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def _incident(*observables: tuple[ObservableType, str], title: str = "Suspicious sign-ins",
              trigger: dict | None = None, workflow_id: str = "unassigned") -> Incident:
    return Incident(incident_id="XDR-PS-T-0001", title=title, severity=Severity.MEDIUM, created_at=NOW,
                    workflow_id=workflow_id, workflow_version="0.0.0",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), trigger=trigger or {})


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
    discovered = discover_workflows().get("password-spray")
    assert discovered.definition == WORKFLOW
    assert isinstance(discovered.hooks, PasswordSprayHooks) and discovered.hooks is HOOKS
    assert discovered.module == "xdr_response.workflows.password_spray"
    assert WORKFLOW.package_name == "password_spray"


def test_definition_revalidates_and_replaces_the_legacy_spec():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    assert WORKFLOW.legacy_id == "password-spray"
    assert WORKFLOW.phase == 2
    assert WORKFLOW.default_severity is Severity.MEDIUM


def test_definition_carries_no_approval_switch():
    assert not _walk_keys(WORKFLOW.model_dump(mode="json")) & APPROVAL_LIKE_KEYS
    text = repr(WORKFLOW.model_dump(mode="json")).lower()
    for word in ("auto_approve", "skip_approval", "bypass_approval", "approval_required", "unlock"):
        assert word not in text


def test_recommendations_are_the_brief_package_with_named_builders():
    rules = {r.id: r for r in WORKFLOW.recommendations}
    assert {(r.action, r.builder) for r in rules.values()} == {
        (ActionType.BLOCK_IP, "block_ip"),
        (ActionType.REVOKE_SESSIONS, "revoke_entra_sessions"),
        (ActionType.DISABLE_USER, "disable_entra_user"),
    }
    # rules only select hook facts: every recommendation cites records the hook collected
    for rule in rules.values():
        assert "facts" in names_used(rule.for_each)
        assert names_used(rule.evidence) <= {"item"}
    assert rules["disable_compromised_account"].min_risk >= rules["revoke_sprayed_sessions"].min_risk
    assert rules["revoke_sprayed_sessions"].asset is not None and rules["disable_compromised_account"].asset


def test_mitre_mapping_is_specific_and_used_by_the_rules():
    assert {(m.tactic, m.technique, m.sub_technique) for m in WORKFLOW.mitre} == {
        ("TA0006", "T1110", "T1110.003"), ("TA0001", "T1078", "T1078.004")}
    used = {mitre_id for rule in WORKFLOW.recommendations for mitre_id in rule.mitre}
    assert used == {"T1110.003", "T1078.004"}
    assert all("T1110.003" in rule.mitre for rule in WORKFLOW.recommendations)
    assert all(m.rationale for m in WORKFLOW.mitre)


def test_integrations_are_entra_and_xdr_first_and_only_verified_paths_are_relied_on():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["cisco_xdr", "entra"]
    optional = {r.integration for r in WORKFLOW.optional_integrations}
    assert {"virustotal", "alienvault_otx", "meraki", "defender_endpoint"} <= optional
    assert "umbrella" not in WORKFLOW.integrations()  # direct Umbrella IP blocking is UNVERIFIED
    assert WORKFLOW.expected_sources() == ("cisco_xdr", "entra")


def test_investigation_reads_accounts_sign_ins_reputation_and_sightings():
    atomics = [step.atomic for step in WORKFLOW.investigation]
    assert atomics[:2] == ["investigate_user", "investigate_authentication"]  # sign-ins feed the source list
    assert {"enrich_ip", "search_ip_enterprise"} <= set(atomics)
    assert all(not a.startswith(("block", "revoke", "disable")) for a in atomics)


@pytest.mark.parametrize("observables, title, trigger, expected", [
    (((ObservableType.IP, "198.51.100.77"),), "Unusual sign-ins", {"mitre_techniques": ["T1110.003"]}, True),
    (((ObservableType.IP, "198.51.100.77"),), "Password spray against Microsoft 365", {}, True),
    (((ObservableType.IPV6, "2001:db8::77"),), "Possible PASSWORD SPRAYING from a proxy", {}, True),
    (((ObservableType.USER, "jsmith@example.com"),), "Password spray against Microsoft 365", {}, False),
    (((ObservableType.IP, "198.51.100.77"),), "Malware on endpoint", {"mitre_techniques": ["T1204.002"]}, False),
])
def test_triggers(observables, title, trigger, expected):
    assert (WORKFLOW.matches(_incident(*observables, title=title, trigger=trigger)) is not None) is expected


def test_an_incident_assigned_to_the_workflow_resolves_here_and_manual_never_matches_alone():
    assigned = _incident((ObservableType.USER, "jsmith@example.com"), workflow_id="password-spray")
    assert discover_workflows().resolve(assigned).definition.id == "password-spray"
    manual = [t for t in WORKFLOW.triggers if t.type == "manual"]
    assert manual and not any(t.matches(_incident((ObservableType.IP, "198.51.100.77"))) for t in manual)
    hit = WORKFLOW.matches(_incident((ObservableType.IP, "198.51.100.77"), trigger={"mitre_techniques": ["T1110.003"]}))
    assert hit is not None and hit.priority > 100  # a spray-specific trigger outranks generic ones


def test_constants_are_conservative():
    assert SPRAY_MIN_ACCOUNTS >= 3
    assert "unfamiliar_location" not in FOLLOW_ON_ANOMALIES  # every external spray success has one
    assert set(FOLLOW_ON_ANOMALIES) <= {"impossible_travel", "unfamiliar_location", "new_device", "anonymous_ip",
                                        "malicious_ip", "mfa_fatigue", "password_spray", "brute_force",
                                        "token_replay", "atypical_volume", "leaked_credentials", "other"}


def test_known_limitations_name_the_manual_steps():
    text = " ".join(WORKFLOW.known_limitations)
    assert "UNVERIFIED" in text and "manual" in text
    assert len(WORKFLOW.known_limitations) >= 5
