"""The exfiltration workflow definition: validation, discovery, triggers, integrations, rules, MITRE, README."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from tools.validation.check_workflow_readmes import check_readme
from xdr_response.atomics import atomic_subject_types, containment_builders
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, get_action_spec
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.exfiltration import HOOKS, WORKFLOW
from xdr_response.workflows.exfiltration.definition import ENDPOINT_SOURCES, HUNT_SOURCES
from xdr_response.workflows.exfiltration.hooks import ExfiltrationHooks

REPO = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
HOST = (ObservableType.HOSTNAME, "TH-LT-1047")
USER = (ObservableType.USER, "jsmith@example.com")


def _incident(title: str = "Endpoint alert", *, techniques: tuple[str, ...] = (),
              observables: tuple[tuple[ObservableType, str], ...] = (HOST,)) -> Incident:
    return Incident(incident_id="XDR-EXF-T001", title=title, severity=Severity.HIGH, created_at=NOW,
                    workflow_id="unassigned", workflow_version="0.0.0",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables),
                    trigger={"mitre_techniques": list(techniques)})


def _keys(node: object) -> set[str]:
    if isinstance(node, dict):
        return {str(k).lower() for k in node} | {k for v in node.values() for k in _keys(v)}
    if isinstance(node, (list, tuple)):
        return {k for v in node for k in _keys(v)}
    return set()


def test_definition_revalidates_and_is_discovered():
    assert WorkflowDefinition.model_validate(WORKFLOW.model_dump()) == WORKFLOW
    found = discover_workflows().get("exfiltration")
    assert found.definition == WORKFLOW
    assert isinstance(found.hooks, ExfiltrationHooks) and found.hooks is HOOKS
    assert WORKFLOW.package_name == "exfiltration"
    assert (WORKFLOW.id, WORKFLOW.name, WORKFLOW.phase, WORKFLOW.legacy_id) == (
        "exfiltration", "Data exfiltration", 4, "exfiltration")
    assert WORKFLOW.default_severity is Severity.CRITICAL


def test_the_definition_carries_no_approval_switch():
    assert not _keys(WORKFLOW.model_dump(mode="json")) & APPROVAL_LIKE_KEYS


def test_integrations_follow_the_brief():
    assert [r.integration for r in WORKFLOW.required_integrations] == ["secure_endpoint", "umbrella", "entra"]
    assert {r.integration for r in WORKFLOW.optional_integrations} == {
        "defender_endpoint", "cisco_xdr", "microsoft_cloud", "splunk", "virustotal", "alienvault_otx", "meraki"}
    assert WORKFLOW.expected_sources() == ("secure_endpoint", "umbrella", "entra")
    known = set(WORKFLOW.integrations())
    for step in WORKFLOW.investigation:
        assert set(step.integrations) <= known
    assert set(ENDPOINT_SOURCES) <= known and set(HUNT_SOURCES) <= known
    # no integration whose reads are UNVERIFIED (Secure Cloud Analytics, Secure Malware Analytics search)
    assert "secure_cloud_analytics" not in known


def test_every_step_uses_a_read_atomic_with_a_supported_subject_type():
    subject_types = atomic_subject_types()
    for step in WORKFLOW.investigation:
        assert step.atomic in subject_types
        if step.subject_type is not None:
            assert step.subject_type in subject_types[step.atomic]
    atomics = [s.atomic for s in WORKFLOW.investigation]
    # endpoint (transfers, DNS, detections), destinations (reputation and reach) and the accounts
    for needed in ("investigate_endpoint", "enrich_domain", "enrich_ip", "search_domain_enterprise",
                   "search_ip_enterprise", "investigate_user"):
        assert needed in atomics


def test_rules_build_the_brief_package_with_matching_builders():
    actions = {r.action for r in WORKFLOW.recommendations}
    assert actions == {ActionType.BLOCK_DOMAIN, ActionType.BLOCK_IP, ActionType.ISOLATE_ENDPOINT,
                       ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER}
    builders = containment_builders()
    for rule in WORKFLOW.recommendations:
        spec = get_action_spec(rule.action)
        assert spec.state_changing and spec.purpose is not None
        if rule.builder is not None:
            assert rule.builder in builders
        assert rule.min_risk >= 40  # a low score is listed as considered, never proposed
        assert set(rule.mitre) <= WORKFLOW.attack_ids()
    by_id = {r.id: r for r in WORKFLOW.recommendations}
    assert by_id["isolate_source_secure_endpoint"].params == {"connector_guid": "item.connector_guid"}
    assert by_id["revoke_actor_sessions"].builder == "revoke_entra_sessions"
    assert by_id["disable_insider_actor"].for_each == "[a for a in facts.actors if a.insider]"


def test_mitre_mapping_is_exfiltration_only_and_not_forced():
    assert {m.tactic for m in WORKFLOW.mitre} == {"TA0010"}
    assert WORKFLOW.attack_ids() == {"T1041", "T1048", "T1567", "T1567.002"}
    for mapping in WORKFLOW.mitre:
        assert mapping.rationale and mapping.technique_name


@pytest.mark.parametrize("techniques", [("T1041",), ("T1048",), ("T1048.003",), ("T1567.002",), ("T1567",)])
def test_exfiltration_techniques_route_here(techniques: tuple[str, ...]):
    found = discover_workflows().resolve(_incident(techniques=techniques))
    assert found is not None and found.definition.id == "exfiltration"


@pytest.mark.parametrize("title", ["Large outbound transfer to an unknown file drop", "Possible data exfiltration",
                                   "Outbound volume anomaly from TH-SRV-0201", "Unusual upload volume to cloud storage"])
def test_exfiltration_titles_route_here(title: str):
    found = discover_workflows().resolve(_incident(title, observables=(USER,)))
    assert found is not None and found.definition.id == "exfiltration"


def test_routing_against_overlapping_workflows():
    catalog = discover_workflows()
    # ransomware wins a double-extortion incident; this workflow outranks account-takeover, which it hands off to
    assert catalog.resolve(_incident(techniques=("T1486", "T1567.002"))).definition.id == "ransomware"
    both = _incident(techniques=("T1567.002", "T1078.004"), observables=(HOST, USER))
    assert catalog.resolve(both).definition.id == "exfiltration"
    assert catalog.resolve(_incident("Generic endpoint alert")) is None or \
        catalog.resolve(_incident("Generic endpoint alert")).definition.id != "exfiltration"
    manual = [t for t in WORKFLOW.triggers if t.type == "manual"]
    assert manual and not manual[0].matches(_incident("Possible data exfiltration"))


def test_hand_off_only_to_account_takeover():
    assert WORKFLOW.handoff_to == ("account-takeover",)
    assert set(WORKFLOW.handoff_to) <= set(WORKFLOW.related_workflows)


def test_readme_matches_the_definition():
    text = (REPO / "workflows" / "exfiltration" / "README.md").read_text(encoding="utf-8")
    assert check_readme(WORKFLOW, text) == []
    assert text.count("\n- ", text.index("## Known limitations")) >= len(WORKFLOW.known_limitations)


def test_the_legacy_spec_is_gone():
    legacy = REPO / "workflows" / "exfiltration"
    assert not (legacy / "workflow.yaml").exists() and not (legacy / "scenarios").exists()
    assert (legacy / "README.md").exists()
