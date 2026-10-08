"""CriticalAssetPolicy and PackageBuilder against the repository's example config."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from tests.fixtures.factories import FAKE_SHA256, FIXED_NOW, make_incident
from xdr_response.approval import CriticalAssetPolicy, PackageBuilder
from xdr_response.clock import FixedClock
from xdr_response.config import AllowlistPolicy, CriticalAssetsConfig, Settings, load_settings
from xdr_response.models import (
    ActionType,
    ApprovalLevel,
    Asset,
    CriticalAssetClass,
    EvidenceDraft,
    ProposedAction,
    TargetKind,
    evidence_snapshot_hash,
    get_action_spec,
)

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"
DC = CriticalAssetClass.DOMAIN_CONTROLLER
ANALYST = "analyst.one@example.com"


@pytest.fixture(scope="module")
def settings() -> Settings:
    return load_settings(CONFIG_DIR, env={})


@pytest.fixture(scope="module")
def policy(settings) -> CriticalAssetPolicy:
    return CriticalAssetPolicy(settings.critical_assets)


@pytest.fixture
def builder(settings, policy) -> PackageBuilder:
    ids = iter(f"pkg-{n}" for n in range(1, 100))
    return PackageBuilder(settings, critical_assets=policy, allowlists=AllowlistPolicy(settings.allowlists),
                          clock=FixedClock(FIXED_NOW), id_factory=lambda: next(ids))


def ev(summary: str = "EDR alert: encoded PowerShell", source: str = "secure_endpoint", minute: int = 0):
    return EvidenceDraft(source=source, summary=summary, observed_at=FIXED_NOW - timedelta(minutes=60 - minute))


def proposal(action_type=ActionType.ISOLATE_ENDPOINT, target="TH-LT-1047", integration="secure_endpoint",
             evidence=None, risk=80, confidence=70, **kw) -> ProposedAction:
    spec = get_action_spec(action_type)
    return ProposedAction(action_type=action_type, target=target, target_kind=kw.pop("target_kind", spec.target_kind),
                          params={"integration": integration, **kw.pop("params", {})},
                          evidence=tuple(evidence or (ev(),)), risk_score=risk, confidence_score=confidence,
                          rationale=f"contain {target}", **kw)


def build(builder, *proposals, incident=None, **kw):
    return builder.build(incident or make_incident(), list(proposals), risk_score=kw.pop("risk_score", 85),
                         confidence_score=kw.pop("confidence_score", 75), summary="Contain the PowerShell host", **kw)


# --------------------------------------------------------- critical assets --
@pytest.mark.parametrize("target,kind,expected", [
    ("DC-01", TargetKind.ENDPOINT, [DC]),
    ("dc-01", TargetKind.ENDPOINT, [DC]),
    ("PRD-WEB-01", TargetKind.ENDPOINT, [CriticalAssetClass.PRODUCTION_SERVER]),
    ("svc-backup@example.com", TargetKind.USER, [CriticalAssetClass.SERVICE_ACCOUNT]),
    ("ceo@example.com", TargetKind.USER, [CriticalAssetClass.EXECUTIVE_ENDPOINT]),
    ("adm-j.doe@example.com/62e90394-69f5-4237-9190-012177145e10", TargetKind.ROLE_ASSIGNMENT,
     [CriticalAssetClass.PRIVILEGED_ACCOUNT]),
    ("203.0.113.5", TargetKind.IP, [CriticalAssetClass.PRODUCTION_SERVER]),
    ("DC-01/" + FAKE_SHA256, TargetKind.FILE, [DC]),
    ("TH-LT-1047", TargetKind.ENDPOINT, []),
    ("bad.example.test", TargetKind.DOMAIN, []),
    ("j.doe@example.com", TargetKind.USER, []),
])
def test_classify(policy, target, kind, expected):
    assert policy.classify(target, kind) == expected


def test_classify_uses_asset_groups_tags_and_ip(policy):
    asset = Asset(name="TH-SRV-7", kind=TargetKind.ENDPOINT, groups=("domain controllers",), tags=("Production",),
                  ip="203.0.113.9")
    assert policy.classify("TH-SRV-7", TargetKind.ENDPOINT, asset) == [DC, CriticalAssetClass.PRODUCTION_SERVER]


def test_classify_with_empty_config_is_never_critical():
    assert CriticalAssetPolicy(CriticalAssetsConfig()).classify("DC-01", TargetKind.ENDPOINT) == []


def test_evaluate_builds_full_warning(policy, settings):
    [w] = policy.evaluate(ActionType.ISOLATE_ENDPOINT, "DC-01", TargetKind.ENDPOINT)
    cfg = settings.critical_assets.classes[DC]
    assert (w.asset, w.asset_class, w.role, w.action_type, w.potential_impact) == (
        "DC-01", DC, cfg.role, ActionType.ISOLATE_ENDPOINT, cfg.potential_impact)
    assert w.message.startswith("WARNING: ELEVATED APPROVAL REQUIRED - isolate_endpoint on Domain controller DC-01")
    assert cfg.potential_impact in w.message


# ----------------------------------------------------------- package builder --
def test_build_basic_package(builder):
    pkg = build(builder, proposal(), proposal(ActionType.BLOCK_DOMAIN, "Bad.Example.TEST.", "umbrella"))
    assert pkg.package_id == "pkg-1" and pkg.incident_id == "XDR-83921" and pkg.purpose.value == "containment"
    assert pkg.keys == ("XDR-83921:isolate_endpoint:TH-LT-1047", "XDR-83921:block_domain:bad.example.test")
    assert all(a.approval_level is ApprovalLevel.STANDARD and not a.warnings for a in pkg.actions)
    assert (pkg.created_at, pkg.expires_at) == (FIXED_NOW, FIXED_NOW + timedelta(minutes=240))
    assert (pkg.workflow_id, pkg.workflow_version, pkg.requested_by) == ("malicious-powershell", "1.0.0",
                                                                         "automation:package_builder")
    assert (pkg.risk_score, pkg.confidence_score, pkg.dry_run) == (85, 75, False)
    assert pkg.endpoints == ("TH-LT-1047",) and pkg.blast_radius.indicators == ("bad.example.test",)
    assert pkg.evidence_snapshot_hash == evidence_snapshot_hash(pkg.evidence)


def test_evidence_is_numbered_and_shared_between_package_and_actions(builder):
    shared = ev("Umbrella: host resolved bad.example.test", source="umbrella", minute=5)
    pkg = build(builder, proposal(evidence=[ev(), shared]),
                proposal(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella", evidence=[shared]),
                extra_evidence=[ev("Analyst note", source="analyst")])
    assert [e.number for e in pkg.evidence] == [1, 2, 3]
    by_number = {e.number: e for e in pkg.evidence}
    for action in pkg.actions:
        for e in action.evidence:
            assert by_number[e.number] == e
    assert [e.number for e in pkg.actions[1].evidence] == [3]  # sorted by source: analyst, secure_endpoint, umbrella


def test_build_is_deterministic(settings, policy):
    def fresh():
        return PackageBuilder(settings, critical_assets=policy, allowlists=AllowlistPolicy(settings.allowlists),
                              clock=FixedClock(FIXED_NOW), id_factory=lambda: "pkg-x")
    props = [proposal(), proposal(ActionType.BLOCK_IP, "203.0.113.77", "meraki")]
    assert build(fresh(), *props) == build(fresh(), *props)


def test_dry_run_and_requester_pass_through(builder):
    pkg = build(builder, proposal(), dry_run=True, requested_by=ANALYST)
    assert pkg.dry_run is True and pkg.requested_by == ANALYST



@pytest.mark.parametrize("action_type", [ActionType.ENRICH_IP, ActionType.INVESTIGATE_ENDPOINT,
                                         ActionType.ADD_INCIDENT_NOTE])
def test_read_only_proposals_are_refused(builder, action_type):
    spec = get_action_spec(action_type)
    target = {"IP": "203.0.113.10", "ENDPOINT": "TH-LT-1047", "INCIDENT": "XDR-83921"}[spec.target_kind.value]
    with pytest.raises(ValueError, match="read-only"):
        build(builder, proposal(action_type, target, "cisco_xdr"))


def test_restoration_proposals_are_refused(builder):
    with pytest.raises(ValueError, match="release package"):
        build(builder, proposal(ActionType.RELEASE_ENDPOINT))


def test_wrong_target_kind_is_refused(builder):
    with pytest.raises(ValueError, match="targets"):
        build(builder, proposal(target_kind=TargetKind.USER))


def test_duplicates_are_merged_keeping_higher_risk_and_all_evidence(builder):
    low = proposal(target="th-lt-1047", risk=40, evidence=[ev("first", minute=1)])
    high = proposal(target="TH-LT-1047 ", risk=90, integration="defender_endpoint", evidence=[ev("second", minute=2)])
    pkg = build(builder, low, high)
    [action] = pkg.actions
    assert action.risk_score == 90 and action.integration == "defender_endpoint"
    assert sorted(e.summary for e in action.evidence) == ["first", "second"]


def test_allowlisted_targets_are_excluded_with_reason(builder):
    pkg = build(builder, proposal(), proposal(ActionType.BLOCK_DOMAIN, "login.microsoft.com", "umbrella"))
    assert pkg.keys == ("XDR-83921:isolate_endpoint:TH-LT-1047",)
    [excluded] = pkg.excluded_targets
    assert (excluded.action_type, excluded.target) == (ActionType.BLOCK_DOMAIN, "login.microsoft.com")
    assert excluded.reason == "allowlists.never_block.domains: microsoft.com"


def test_all_targets_allowlisted_raises(builder):
    with pytest.raises(ValueError, match="no containment action"):
        build(builder, proposal(target="TH-DC-01"))


def test_critical_asset_is_elevated_with_warning_not_blocked(builder):
    pkg = build(builder, proposal(target="DC-02"))
    [action] = pkg.actions
    assert action.approval_level is ApprovalLevel.ELEVATED
    assert [w.asset_class for w in action.warnings] == [DC]
    assert pkg.has_elevated


def test_incident_asset_context_is_used(builder):
    incident = make_incident(assets=(Asset(name="TH-LT-1047", kind=TargetKind.ENDPOINT, groups=("Executives",)),))
    [action] = build(builder, proposal(), incident=incident).actions
    assert action.approval_level is ApprovalLevel.ELEVATED
    assert action.warnings[0].asset_class is CriticalAssetClass.EXECUTIVE_ENDPOINT


def test_always_elevated_action_type(builder):
    target = "j.doe@example.com/62e90394-69f5-4237-9190-012177145e10"
    [action] = build(builder, proposal(ActionType.REMOVE_PRIVILEGED_ROLE, target, "entra")).actions
    assert action.approval_level is ApprovalLevel.ELEVATED and action.warnings == ()


def test_blast_radius_over_cap_elevates_every_action_of_that_kind(builder):
    hosts = [proposal(target=f"TH-LT-{n}") for n in range(1000, 1006)]  # 6 > max_endpoints 5
    pkg = build(builder, *hosts, proposal(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella"))
    assert len(pkg.blast_radius.endpoints) == 6
    endpoint_actions = [a for a in pkg.actions if a.target_kind is TargetKind.ENDPOINT]
    assert all(a.approval_level is ApprovalLevel.ELEVATED for a in endpoint_actions)
    w = endpoint_actions[0].warnings[0]
    assert w.asset_class is None and w.role == "blast radius" and "max_endpoints" in w.potential_impact
    assert w.message.startswith("WARNING: ELEVATED APPROVAL REQUIRED")
    domain = pkg.action("XDR-83921:block_domain:bad.example.test")
    assert domain.approval_level is ApprovalLevel.STANDARD
    assert len(pkg.actions) == 7  # nothing removed


def test_blast_radius_counts_users_and_messages(builder):
    pkg = build(builder, proposal(ActionType.DISABLE_USER, "a@example.org", "entra"),
                proposal(ActionType.QUARANTINE_EMAIL, "<msg-1@example.test>", "secure_email"),
                proposal(ActionType.QUARANTINE_EMAIL, "<msg-2@example.test>", "secure_email"))
    assert pkg.blast_radius.users == ("a@example.org",) and pkg.blast_radius.messages == 2
    assert pkg.users == ("a@example.org",)
