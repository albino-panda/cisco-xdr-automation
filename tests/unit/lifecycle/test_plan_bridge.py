"""Unit tests of ``xdr_response.lifecycle.plan_bridge`` (architecture 14.3.8).

The bridge only builds data: the runtime incident, citable legacy records, settings from legacy
guardrails and ``ProposedAction`` objects. It never decides an approval level (PackageBuilder does)
and every proposal's evidence cites a legacy record of the scenario.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from xdr_plan.planner import Action, Plan
from xdr_response.approval import CriticalAssetPolicy, PackageBuilder
from xdr_response.atomics.containment.models import RouteDecision
from xdr_response.atomics.evidence import EvidenceBuilder, RecordIndex
from xdr_response.config import Settings
from xdr_response.config.policy import AllowlistPolicy
from xdr_response.lifecycle.plan_bridge import (
    LEGACY_CONFIDENCE,
    LEGACY_CONTAINMENT,
    LEGACY_INCIDENT_ATOMIC,
    LEGACY_PROTECTED_HOST_TAG,
    LEGACY_PROTECTED_USER_TAG,
    LEGACY_SEVERITY_RISK,
    bridge_plan,
    guardrails_to_settings,
    legacy_incident,
    legacy_incident_record,
    legacy_records,
)
from xdr_response.models import (
    ActionType,
    ApprovalLevel,
    CriticalAssetClass,
    ObservableType,
    Severity,
    TargetKind,
)

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
HASH = "5ca1ab1e" * 8
GUID = "00000000-0000-4000-8000-000000000142"

INCIDENT = {
    "id": "INC-TEST-BRIDGE-1",
    "title": "Malicious file executed on wks-0142",
    "severity": "high",
    "source": "Cisco Secure Endpoint",
    "observables": [
        {"type": "sha256", "value": HASH},
        {"type": "domain", "value": "cdn-update.test"},
        {"type": "ip", "value": "203.0.113.50"},
        {"type": "host", "value": "wks-0142"},
        {"type": "email_subject", "value": "Invoice"},
    ],
    "targets": [{"type": "endpoint", "value": "wks-0142"}, {"type": "user", "value": "JSmith@example.com"}],
    "context": {"sender": "billing@invoice-portal.example"},
}
RESULTS = {
    "enrich-hash": [{"sha256": HASH, "disposition": "malicious", "prevalence": 1, "hosts": ["wks-0142"], "error": ""}],
    "enrich-domain": [{"domain": "cdn-update.test", "verdict": "malicious", "categories": ["Malware"], "error": ""}],
    "investigate-host": [{"host": "wks-0142", "connector_guid": GUID, "is_protected": True, "error": ""}],
    "investigate-user": [{"user": "jsmith@example.com", "profile": {"groups": ["Finance"]}, "is_protected": False,
                          "error": ""}],
}


def _incident():
    return legacy_incident(INCIDENT, workflow_id="malware", created_at=NOW)


def _route(action_type: ActionType, target: str) -> RouteDecision:
    return RouteDecision(action_type=action_type, integration="secure_endpoint", product="secure_endpoint",
                         params={"integration": "secure_endpoint"})


def _unrouted(action_type: ActionType, target: str) -> RouteDecision:
    return RouteDecision(action_type=action_type, integration=None, reason="no enabled adapter (test)")


def _plan(*actions: Action, escalate: bool = False, reasons: list[str] | None = None) -> Plan:
    return Plan("malware", list(actions), escalate, reasons or [])


def _action(atomic: str, target: str, *, status: str = "planned", source=None, elevated=False, reasons=()) -> Action:
    return Action(rule=f"rule_{atomic}", atomic=atomic, target=target, status=status, requires_approval=True,
                  elevated=elevated, reasons=list(reasons), source=source)


# ------------------------------------------------------------------------------------ incident --
def test_legacy_incident_maps_fields():
    incident = _incident()
    assert incident.incident_id == "INC-TEST-BRIDGE-1"
    assert incident.severity is Severity.HIGH
    assert incident.workflow_id == "malware" and incident.workflow_version == "legacy"
    types = {o.type for o in incident.observables}
    assert types == {ObservableType.SHA256, ObservableType.DOMAIN, ObservableType.IP, ObservableType.HOSTNAME}
    assert incident.trigger["legacy_unmapped_observables"] == [{"type": "email_subject", "value": "Invoice"}]
    assert [a.name for a in incident.assets] == ["WKS-0142"]
    assert incident.users == ("jsmith@example.com",)
    assert incident.trigger["legacy_context"] == {"sender": "billing@invoice-portal.example"}


def test_legacy_incident_needs_an_id():
    with pytest.raises(ValueError):
        legacy_incident({"title": "x", "severity": "low"}, workflow_id="malware", created_at=NOW)


def test_ipv6_observable_gets_the_ipv6_type():
    incident = legacy_incident({**INCIDENT, "observables": [{"type": "ip", "value": "2001:db8::5"}]},
                               workflow_id="malware", created_at=NOW)
    assert incident.observables[0].type is ObservableType.IPV6


# ------------------------------------------------------------------------------------- records --
def test_one_record_per_result_item_with_the_documented_source():
    records = legacy_records(RESULTS)
    assert len(records) == 4
    by_atomic = {r.atomic: r for r in records}
    assert by_atomic["legacy:enrich-hash"].integration == "cisco_xdr"
    assert by_atomic["legacy:enrich-domain"].integration == "umbrella"
    assert by_atomic["legacy:investigate-host"].integration == "secure_endpoint"
    assert by_atomic["legacy:investigate-user"].integration == "entra"
    assert by_atomic["legacy:investigate-host"].attributes["connector_guid"] == GUID
    assert all(r.name == r.atomic for r in records)


def test_records_are_deterministic_and_deduplicated():
    doubled = {"enrich-hash": RESULTS["enrich-hash"] * 2}
    assert legacy_records(doubled) == legacy_records({"enrich-hash": RESULTS["enrich-hash"]})
    assert [r.record_id for r in legacy_records(RESULTS)] == [r.record_id for r in legacy_records(RESULTS)]


def test_unknown_result_key_is_refused_and_unparseable_items_are_skipped():
    with pytest.raises(ValueError):
        legacy_records({"block-ip": [{"ip": "203.0.113.5"}]})
    assert legacy_records({"enrich-hash": [{"sha256": "not-a-hash"}]}) == ()


def test_incident_record():
    record = legacy_incident_record(INCIDENT)
    assert record is not None and record.atomic == LEGACY_INCIDENT_ATOMIC
    assert record.attributes["context"] == {"sender": "billing@invoice-portal.example"}
    assert legacy_incident_record({"id": "x", "observables": [{"type": "email_subject", "value": "y"}]}) is None


# ---------------------------------------------------------------------------------- guardrails --
GUARDRAILS = {
    "protected": {"hosts": ["dc-*", "10.0.10.0/24"], "users": ["breakglass-*@example.com"], "groups": ["Domain Admins"]},
    "allowlist": {"domains": ["example.com"], "ip_ranges": ["10.0.0.0/8"], "hashes": ["AB" * 32],
                  "url_block_allowed_domains": ["docs.example.com"], "approved_rmm": ["ExampleRMM"]},
    "blast_radius": {"max_hosts_isolated": 2, "max_users_disabled": 1, "max_indicators_blocked": 9,
                     "max_messages_quarantined": 7},
}


def test_guardrails_to_settings():
    settings = guardrails_to_settings(GUARDRAILS, Settings())
    classes = settings.critical_assets.classes
    host = classes[CriticalAssetClass.PRODUCTION_SERVER].match
    assert host.hostname_patterns == ["dc-*"] and host.ip_cidrs == ["10.0.10.0/24"]
    assert LEGACY_PROTECTED_HOST_TAG in host.tags
    user = classes[CriticalAssetClass.PRIVILEGED_ACCOUNT].match
    assert user.user_patterns == ["breakglass-*@example.com"] and user.groups == ["Domain Admins"]
    assert LEGACY_PROTECTED_USER_TAG in user.tags
    nb = settings.allowlists.never_block
    assert nb["domains"] == ["example.com"] and nb["cidrs"] == ["10.0.0.0/8"] and nb["hashes"] == ["ab" * 32]
    assert settings.allowlists.url_block_allowed_domains == ["docs.example.com"]
    assert settings.allowlists.approved_rmm == [{"name": "ExampleRMM"}]
    caps = settings.thresholds.blast_radius
    assert (caps.max_endpoints, caps.max_users, caps.max_indicators, caps.max_messages) == (2, 1, 9, 7)


def test_guardrails_replace_the_base_policies():
    base = Settings.model_validate({"allowlists": {"never_block": {"domains": ["other.test"]}}})
    settings = guardrails_to_settings({}, base)
    assert settings.allowlists.never_block["domains"] == []
    assert settings.thresholds.blast_radius == base.thresholds.blast_radius
    policy = CriticalAssetPolicy(guardrails_to_settings(GUARDRAILS, Settings()).critical_assets)
    assert policy.classify("DC-01", TargetKind.ENDPOINT) == [CriticalAssetClass.PRODUCTION_SERVER]
    assert policy.classify("breakglass-2@example.com", TargetKind.USER) == [CriticalAssetClass.PRIVILEGED_ACCOUNT]
    assert policy.classify("WKS-1", TargetKind.ENDPOINT) == []


# -------------------------------------------------------------------------------------- bridge --
def test_planned_actions_become_proposals_with_cited_evidence():
    plan = _plan(_action("block-hash", HASH, source=("enrich-hash", 0)),
                 _action("isolate-endpoint", GUID, source=("investigate-host", 0)))
    result = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_route, incident_data=INCIDENT)
    assert [p.action_type for p in result.proposals] == [ActionType.BLOCK_HASH, ActionType.ISOLATE_ENDPOINT]
    builder = EvidenceBuilder(RecordIndex(records=result.records))
    for proposal in result.proposals:
        builder.verify(proposal.evidence)
        assert proposal.risk_score == LEGACY_SEVERITY_RISK["high"]
        assert proposal.confidence_score == LEGACY_CONFIDENCE
        assert proposal.rationale.startswith("legacy plan rule ")
        assert proposal.params["integration"] == "secure_endpoint"
    hash_evidence = result.proposals[0].evidence
    assert [e.data["atomic"] for e in hash_evidence] == ["legacy:enrich-hash"]


def test_isolation_targets_the_host_name_and_keeps_the_guid_as_a_param():
    plan = _plan(_action("isolate-endpoint", GUID, source=("investigate-host", 0)))
    proposal = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_route).proposals[0]
    assert proposal.target == "WKS-0142" and proposal.target_kind is TargetKind.ENDPOINT
    assert proposal.params["connector_guid"] == GUID
    assert proposal.asset is not None and LEGACY_PROTECTED_HOST_TAG in proposal.asset.tags


def test_user_asset_context_carries_groups():
    plan = _plan(_action("disable-user", "jsmith@example.com", source=("investigate-user", 0)))
    proposal = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_route).proposals[0]
    assert proposal.asset is not None and proposal.asset.groups == ("Finance",)
    assert LEGACY_PROTECTED_USER_TAG not in proposal.asset.tags


def test_without_a_source_every_mentioning_record_is_cited():
    plan = _plan(_action("block-domain", "cdn-update.test"))
    proposal = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_route).proposals[0]
    assert [e.data["atomic"] for e in proposal.evidence] == ["legacy:enrich-domain"]


def test_a_target_from_the_incident_cites_the_incident_record():
    plan = _plan(_action("quarantine-email", "billing@invoice-portal.example"))
    result = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_route, incident_data=INCIDENT)
    assert [e.data["atomic"] for e in result.proposals[0].evidence] == [LEGACY_INCIDENT_ATOMIC]
    assert any(r.atomic == LEGACY_INCIDENT_ATOMIC for r in result.records)


def test_a_target_nobody_mentions_is_not_proposed():
    plan = _plan(_action("block-domain", "unmentioned.test"))
    result = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_route, incident_data=INCIDENT)
    assert result.proposals == () and len(result.unrouted) == 1
    assert "no evidence" in result.unrouted[0].note
    assert any("unmentioned.test" in n for n in result.notes)


def test_skipped_actions_are_reported_not_proposed():
    plan = _plan(_action("block-domain", "example.com", status="skipped_allowlisted"),
                 _action("block-ip", "10.1.2.3", status="skipped_internal"))
    result = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_route)
    assert result.proposals == () and result.unrouted == ()
    assert [a.status for a in result.actions] == ["skipped_allowlisted", "skipped_internal"]


def test_unrouted_actions_are_reported_with_the_reason():
    plan = _plan(_action("block-hash", HASH, source=("enrich-hash", 0)))
    result = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_unrouted)
    assert result.proposals == ()
    assert result.unrouted[0].note == "no enabled adapter (test)"


def test_escalation_and_reasons_are_carried_but_never_an_approval_level():
    reason = "max_indicators_blocked: 2 planned > limit 1: ELEVATED approval required"
    plan = _plan(_action("block-hash", HASH, source=("enrich-hash", 0), elevated=True, reasons=[reason]),
                 escalate=True, reasons=[reason])
    result = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_route)
    assert result.escalate and reason in result.notes
    proposal = result.proposals[0]
    assert "approval_level" not in proposal.model_dump()
    assert reason in proposal.rationale
    assert result.actions[0].elevated is True


def test_package_builder_decides_elevated_from_the_bridged_context():
    settings = guardrails_to_settings(GUARDRAILS, Settings())
    plan = _plan(_action("isolate-endpoint", GUID, source=("investigate-host", 0)),
                 _action("block-hash", HASH, source=("enrich-hash", 0)))
    result = bridge_plan(plan, incident=_incident(), results=RESULTS, route=_route)
    builder = PackageBuilder(settings, critical_assets=CriticalAssetPolicy(settings.critical_assets),
                             allowlists=AllowlistPolicy(settings.allowlists))
    package = builder.build(_incident(), result.proposals, risk_score=75, confidence_score=50,
                            summary="legacy replay", dry_run=True)
    levels = {a.action_type: a.approval_level for a in package.actions}
    assert levels == {ActionType.ISOLATE_ENDPOINT: ApprovalLevel.ELEVATED, ActionType.BLOCK_HASH: ApprovalLevel.STANDARD}
    isolate = next(a for a in package.actions if a.action_type is ActionType.ISOLATE_ENDPOINT)
    assert isolate.warnings and isolate.warnings[0].message.startswith("WARNING: ELEVATED APPROVAL REQUIRED")


def test_the_mapping_covers_every_legacy_containment_atomic():
    from xdr_plan.guardrails import CHECKS

    assert set(LEGACY_CONTAINMENT) == set(CHECKS)
