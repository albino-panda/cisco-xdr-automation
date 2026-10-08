"""Containment recommendation builders: validation, normalization, previews, rollback (14.1.7)."""
from __future__ import annotations

import pytest

from tests.fixtures.factories import make_incident
from tests.unit.atomics.containment._support import (
    FAKE_SHA256,
    FIXED_NOW,
    FakeAdapters,
    NativeAction,
    evidence,
    make_context,
    make_settings,
    record_id,
)
from xdr_response.approval.critical_assets import WARNING_PREFIX, CriticalAssetPolicy
from xdr_response.approval.package import PackageBuilder
from xdr_response.atomics import containment_builders
from xdr_response.atomics.containment import (
    CONTAINMENT_BUILDERS,
    RESERVED_PARAM_KEYS,
    BuiltRecommendation,
    build_containment,
    intune_device_action,
)
from xdr_response.clock import FixedClock
from xdr_response.config import FORBIDDEN_KEYS
from xdr_response.config.policy import AllowlistPolicy
from xdr_response.errors import UnverifiedEndpointError
from xdr_response.models import (
    ActionType,
    ApprovalLevel,
    Asset,
    CriticalAssetClass,
    EvidenceDraft,
    ProposedAction,
    TargetKind,
    get_action_spec,
)

ALL_ENABLED = ("cisco_xdr", "secure_endpoint", "secure_email", "umbrella", "meraki", "entra", "defender_endpoint",
               "defender_o365", "intune")

#: builder -> (action type, pinned product or None, valid raw target, normalized target)
TABLE: dict[str, tuple[ActionType, str | None, str, str]] = {
    "isolate_secure_endpoint": (ActionType.ISOLATE_ENDPOINT, "secure_endpoint", "th-lt-1047", "TH-LT-1047"),
    "isolate_defender_endpoint": (ActionType.ISOLATE_ENDPOINT, "defender_endpoint", "th-lt-1047", "TH-LT-1047"),
    "block_domain_umbrella": (ActionType.BLOCK_DOMAIN, "umbrella", "Bad.Example.Test.", "bad.example.test"),
    "block_url": (ActionType.BLOCK_URL, None, " https://bad.example.test/payload ", "https://bad.example.test/payload"),
    "block_ip": (ActionType.BLOCK_IP, None, "203.0.113.10", "203.0.113.10"),
    "block_hash": (ActionType.BLOCK_HASH, None, FAKE_SHA256.upper(), FAKE_SHA256),
    "revoke_entra_sessions": (ActionType.REVOKE_SESSIONS, "entra", "J.Doe@Example.com", "j.doe@example.com"),
    "disable_entra_user": (ActionType.DISABLE_USER, "entra", "J.Doe@Example.com", "j.doe@example.com"),
    "quarantine_email": (ActionType.QUARANTINE_EMAIL, None, "msg-0001@example.test", "msg-0001@example.test"),
    "delete_malicious_email": (ActionType.DELETE_EMAIL, None, "msg-0001@example.test", "msg-0001@example.test"),
    "intune_device_action": (ActionType.LOCK_DEVICE, "intune", "th-lt-1047", "TH-LT-1047"),
    "terminate_process": (ActionType.TERMINATE_PROCESS, None, "th-lt-1047/4242", "TH-LT-1047/4242"),
    "quarantine_file": (ActionType.QUARANTINE_FILE, None, f"th-lt-1047/{FAKE_SHA256.upper()}",
                        f"TH-LT-1047/{FAKE_SHA256}"),
    "remove_persistence": (ActionType.REMOVE_PERSISTENCE, None, "th-lt-1047/run-key-0001", "TH-LT-1047/run-key-0001"),
    "remove_privileged_role": (ActionType.REMOVE_PRIVILEGED_ROLE, "entra", "J.Doe@Example.com/role-def-0001",
                               "j.doe@example.com/role-def-0001"),
}

ROLLBACK: dict[str, ActionType | None] = {
    "isolate_secure_endpoint": ActionType.RELEASE_ENDPOINT, "isolate_defender_endpoint": ActionType.RELEASE_ENDPOINT,
    "block_domain_umbrella": ActionType.UNBLOCK_DOMAIN, "block_url": ActionType.UNBLOCK_URL,
    "block_ip": ActionType.UNBLOCK_IP, "block_hash": ActionType.UNBLOCK_HASH, "revoke_entra_sessions": None,
    "disable_entra_user": ActionType.ENABLE_USER, "quarantine_email": ActionType.RELEASE_EMAIL,
    "delete_malicious_email": None, "intune_device_action": None, "terminate_process": None,
    "quarantine_file": ActionType.RESTORE_FILE, "remove_persistence": None,
    "remove_privileged_role": ActionType.RESTORE_PRIVILEGED_ROLE,
}


def _kwargs(**overrides):
    base = {"evidence": evidence(2), "risk_score": 85, "confidence_score": 70,
            "rationale": "rule matched: malicious verdict corroborated by two sources"}
    base.update(overrides)
    return base


def _ctx(enabled=ALL_ENABLED, **kwargs):
    return make_context(FakeAdapters(enabled_names=enabled), **kwargs)


# ------------------------------------------------------------------ table --
def test_builder_table_has_the_fifteen_contract_names():
    assert set(CONTAINMENT_BUILDERS) == set(TABLE) and len(CONTAINMENT_BUILDERS) == 15
    assert dict(containment_builders()) == dict(CONTAINMENT_BUILDERS)


@pytest.mark.parametrize("name", sorted(TABLE))
def test_each_builder_fixes_action_type_product_and_normalizes(name):
    action, product, raw, normalized = TABLE[name]
    built = CONTAINMENT_BUILDERS[name](_ctx(), raw, **_kwargs())
    assert isinstance(built, BuiltRecommendation)
    assert built.action_type is action and built.target == normalized
    spec = get_action_spec(action)
    if not spec.integrations:  # remove_persistence: no adapter anywhere
        assert built.proposal is None and built.unrouted_reason == built.route.reason
        return
    expected = product or next(n for n in spec.integrations if n != "cisco_xdr")
    assert built.route.integration == expected and not built.route.native
    proposal = built.proposal
    assert isinstance(proposal, ProposedAction)
    assert (proposal.action_type, proposal.target, proposal.target_kind) == (action, normalized, spec.target_kind)
    assert proposal.params == {"integration": expected}
    assert (proposal.risk_score, proposal.confidence_score) == (85, 70)
    assert proposal.evidence == evidence(2) and built.unrouted_reason is None


@pytest.mark.parametrize("name", sorted(TABLE))
def test_rollback_mapping_comes_from_the_catalog(name):
    action, _, raw, _ = TABLE[name]
    built = CONTAINMENT_BUILDERS[name](_ctx(), raw, **_kwargs())
    assert built.rollback_action_type is ROLLBACK[name]
    assert built.reversible is (ROLLBACK[name] is not None)
    assert get_action_spec(action).rollback_action_type is ROLLBACK[name]


@pytest.mark.parametrize("name", ["isolate_secure_endpoint", "block_domain_umbrella", "disable_entra_user"])
def test_named_builders_route_native_first(name):
    action, product, raw, normalized = TABLE[name]
    native = {action.value: {product: {"module": "M", "action_id": f"{name}-act"}}}
    adapters = FakeAdapters(enabled_names=ALL_ENABLED, native=[NativeAction("mi-1", f"{name}-act")])
    built = CONTAINMENT_BUILDERS[name](make_context(adapters, make_settings(native_actions=native)), raw, **_kwargs())
    assert built.route.native and built.proposal.params["integration"] == "cisco_xdr"
    assert built.proposal.params["verify_integration"] == product
    assert built.proposal.params["observable_value"] == normalized


def test_caller_params_are_kept_and_route_params_added():
    built = build_containment(_ctx(), ActionType.BLOCK_DOMAIN, "bad.example.test", product="umbrella",
                              params={"destination_list_id": 17, "rule_comment": "XDR-83921", "tags": ["a", "b"]},
                              **_kwargs())
    assert built.proposal.params == {"destination_list_id": 17, "rule_comment": "XDR-83921", "tags": ["a", "b"],
                                     "integration": "umbrella"}


def test_other_catalog_containment_types_are_reachable():
    for action, target in [(ActionType.CONFIRM_USER_COMPROMISED, "j.doe@example.com"),
                           (ActionType.RESET_PASSWORD, "j.doe@example.com"), (ActionType.RESET_MFA, "j.doe@example.com"),
                           (ActionType.BLOCK_NETWORK_CLIENT, "N_0001/k74272e"),
                           (ActionType.REVOKE_APP_CREDENTIALS, "cred-0001"),
                           (ActionType.REMOVE_APPLICATION, "app-0001")]:
        built = build_containment(_ctx(), action, target, **_kwargs())
        assert built.proposal is not None and built.action_type is action


# ------------------------------------------------------------- validation --
@pytest.mark.parametrize("action", [ActionType.RELEASE_ENDPOINT, ActionType.UNBLOCK_IP, ActionType.ENABLE_USER,
                                    ActionType.ENRICH_HASH, ActionType.INVESTIGATE_ENDPOINT, ActionType.NOTIFY_SOC])
def test_non_containment_types_raise(action):
    with pytest.raises(ValueError, match="not a containment"):
        build_containment(_ctx(), action, "TH-LT-1047", **_kwargs())


@pytest.mark.parametrize("bad", [(), [], (EvidenceDraft(source="secure_endpoint", summary="no record"),),
                                 (EvidenceDraft(source="secure_endpoint", summary="x", data={"record_id": "rec_1"}),),
                                 ("not a draft",)])
def test_evidence_must_cite_records(bad):
    with pytest.raises(ValueError):
        build_containment(_ctx(), ActionType.BLOCK_IP, "203.0.113.10", **_kwargs(evidence=bad))


@pytest.mark.parametrize("key", sorted(RESERVED_PARAM_KEYS) + ["Integration", " approval_level "])
def test_reserved_param_keys_raise(key):
    with pytest.raises(ValueError):
        build_containment(_ctx(), ActionType.BLOCK_IP, "203.0.113.10", params={key: "x"}, **_kwargs())


@pytest.mark.parametrize("params", [
    {"api_key": "x"}, {"nested": {"client_secret": "x"}}, {"list": [{"accessToken": "x"}]},
    {"nested": {"auto_approve": True}}, {"rate": 1.5}, {"nested": [1, 2.0]}, {"when": FIXED_NOW},
    {"": 1}, {3: "x"}, ["not", "a", "mapping"],
])
def test_unsafe_params_raise(params):
    with pytest.raises(ValueError):
        build_containment(_ctx(), ActionType.BLOCK_IP, "203.0.113.10", params=params, **_kwargs())


def test_forbidden_keys_are_reserved():
    assert FORBIDDEN_KEYS <= RESERVED_PARAM_KEYS


@pytest.mark.parametrize("overrides", [{"risk_score": 101}, {"risk_score": -1}, {"risk_score": True},
                                       {"confidence_score": 50.0}, {"rationale": ""}, {"rationale": "   "},
                                       {"rationale": None}, {"asset": {"name": "TH-LT-1047"}}])
def test_scores_rationale_and_asset_are_checked(overrides):
    with pytest.raises(ValueError):
        build_containment(_ctx(), ActionType.BLOCK_IP, "203.0.113.10", **_kwargs(**overrides))


@pytest.mark.parametrize(("action", "target"), [
    (ActionType.BLOCK_IP, "not-an-ip"), (ActionType.BLOCK_IP, "   "), (ActionType.BLOCK_HASH, "xyz"),
    (ActionType.BLOCK_HASH, "a" * 63), (ActionType.BLOCK_DOMAIN, "bad example.test"),
    (ActionType.BLOCK_DOMAIN, "https://bad.example.test"), (ActionType.ISOLATE_ENDPOINT, "TH LT 1047"),
    (ActionType.BLOCK_URL, "nodots"), (ActionType.TERMINATE_PROCESS, "TH-LT-1047"),
    (ActionType.TERMINATE_PROCESS, "TH-LT-1047/notapid"), (ActionType.QUARANTINE_FILE, "TH-LT-1047/" + "a" * 40),
    (ActionType.REMOVE_PERSISTENCE, "/run-key"), (ActionType.REMOVE_PRIVILEGED_ROLE, "j.doe@example.com"),
])
def test_targets_that_cannot_be_normalized_raise(action, target):
    with pytest.raises(ValueError):
        build_containment(_ctx(), action, target, **_kwargs())


def test_ipv6_and_process_hash_targets_normalize():
    assert build_containment(_ctx(), ActionType.BLOCK_IP, "2001:DB8:0:0::10", **_kwargs()).target == "2001:db8::10"
    built = build_containment(_ctx(), ActionType.TERMINATE_PROCESS, f"th-lt-1047/{FAKE_SHA256.upper()}", **_kwargs())
    assert built.target == f"TH-LT-1047/{FAKE_SHA256}"


def test_rationale_is_redacted():
    built = build_containment(_ctx(), ActionType.BLOCK_IP, "203.0.113.10",
                              **_kwargs(rationale="matched rule; password=hunter2-fake"))
    assert "hunter2-fake" not in built.proposal.rationale


# -------------------------------------------------------- action specifics --
def test_intune_only_lock_is_verified():
    built = intune_device_action(_ctx(), "TH-LT-1047", params={"managed_device_id": "dev-0001"}, **_kwargs())
    assert built.action_type is ActionType.LOCK_DEVICE and built.proposal.params["integration"] == "intune"
    for action in ("wipe", "retire", "Lock"):
        with pytest.raises(ValueError) as info:
            intune_device_action(_ctx(), "TH-LT-1047", action=action, **_kwargs())
        assert isinstance(info.value, UnverifiedEndpointError)


def test_email_delete_is_never_hard():
    builder = CONTAINMENT_BUILDERS["delete_malicious_email"]
    for choice in ("softDelete", "moveToDeletedItems"):
        assert builder(_ctx(), "msg-0001@example.test", params={"delete_action": choice}, **_kwargs()).proposal
    for choice in ("hardDelete", "purge", 1):
        with pytest.raises(ValueError):
            builder(_ctx(), "msg-0001@example.test", params={"delete_action": choice}, **_kwargs())


def test_unrouted_action_is_reported_not_dropped():
    built = CONTAINMENT_BUILDERS["isolate_secure_endpoint"](_ctx(enabled=("defender_endpoint",)), "TH-DC-01",
                                                            **_kwargs())
    assert built.proposal is None and not built.routed
    assert built.unrouted_reason == "no enabled adapter has a VERIFIED write for isolate_endpoint"
    assert built.warnings and built.elevation_expected  # warnings are still previewed


# ------------------------------------------------- critical assets / allow --
def test_critical_endpoint_gets_a_visible_elevated_warning():
    built = CONTAINMENT_BUILDERS["isolate_defender_endpoint"](_ctx(), "th-dc-01", **_kwargs())
    assert built.proposal is not None  # never silently skipped
    [warning] = built.warnings
    assert warning.asset_class is CriticalAssetClass.DOMAIN_CONTROLLER
    assert warning.message.startswith(WARNING_PREFIX) and "TH-DC-01" in warning.message
    assert built.elevation_expected


def test_incident_asset_context_and_caller_asset_are_both_considered():
    incident = make_incident(assets=(Asset(name="TH-LT-2001", kind=TargetKind.ENDPOINT, groups=("Executives",)),))
    built = CONTAINMENT_BUILDERS["isolate_secure_endpoint"](_ctx(incident=incident), "th-lt-2001", **_kwargs())
    assert [w.asset_class for w in built.warnings] == [CriticalAssetClass.EXECUTIVE_ENDPOINT]
    caller = Asset(name="TH-LT-3001", kind=TargetKind.ENDPOINT, groups=("Executives",))
    built = CONTAINMENT_BUILDERS["isolate_secure_endpoint"](_ctx(), "TH-LT-3001", asset=caller, **_kwargs())
    assert [w.asset_class for w in built.warnings] == [CriticalAssetClass.EXECUTIVE_ENDPOINT]
    assert built.proposal.asset == caller


def test_privileged_role_holder_composite_target_is_matched():
    built = CONTAINMENT_BUILDERS["remove_privileged_role"](_ctx(), "admin.ops@example.com/role-def-0001", **_kwargs())
    assert [w.asset_class for w in built.warnings] == [CriticalAssetClass.PRIVILEGED_ACCOUNT]


def test_always_elevated_type_expects_elevation_without_warnings():
    built = CONTAINMENT_BUILDERS["remove_privileged_role"](_ctx(), "j.doe@example.com/role-def-0001", **_kwargs())
    assert built.warnings == () and built.elevation_expected


def test_ordinary_target_has_no_warning():
    built = CONTAINMENT_BUILDERS["block_ip"](_ctx(), "203.0.113.10", **_kwargs())
    assert built.warnings == () and not built.elevation_expected and built.excluded_reason is None


def test_allowlisted_target_is_previewed_and_still_built():
    built = CONTAINMENT_BUILDERS["block_domain_umbrella"](_ctx(), "login.example.com", **_kwargs())
    assert built.excluded_reason == "allowlists.never_block.domains: example.com"
    assert built.proposal is not None


def test_dry_run_flag_does_not_change_the_recommendation():
    for name, (_, _, raw, _) in TABLE.items():
        wet = CONTAINMENT_BUILDERS[name](_ctx(dry_run=False), raw, **_kwargs())
        dry = CONTAINMENT_BUILDERS[name](_ctx(dry_run=True), raw, **_kwargs())
        assert wet == dry


# ------------------------------------------------------- package builder --
def test_proposals_package_with_elevation_and_exclusion_decided_by_package_builder():
    settings = make_settings()
    ctx = make_context(FakeAdapters(enabled_names=ALL_ENABLED), settings)
    built = [
        CONTAINMENT_BUILDERS["isolate_defender_endpoint"](ctx, "TH-DC-01", **_kwargs()),
        CONTAINMENT_BUILDERS["block_ip"](ctx, "203.0.113.10", **_kwargs(evidence=evidence(1, "defender_endpoint"))),
        CONTAINMENT_BUILDERS["remove_privileged_role"](ctx, "j.doe@example.com/role-def-0001", **_kwargs()),
        CONTAINMENT_BUILDERS["block_domain_umbrella"](ctx, "login.example.com", **_kwargs()),
    ]
    builder = PackageBuilder(settings, critical_assets=CriticalAssetPolicy(settings.critical_assets),
                             allowlists=AllowlistPolicy(settings.allowlists), clock=FixedClock(FIXED_NOW),
                             id_factory=lambda: "pkg-0001")
    package = builder.build(ctx.incident, [b.proposal for b in built], risk_score=85, confidence_score=70,
                            summary="test package")
    levels = {a.action_type: a.approval_level for a in package.actions}
    assert levels == {ActionType.ISOLATE_ENDPOINT: ApprovalLevel.ELEVATED, ActionType.BLOCK_IP: ApprovalLevel.STANDARD,
                      ActionType.REMOVE_PRIVILEGED_ROLE: ApprovalLevel.ELEVATED}
    assert [(e.action_type, e.target) for e in package.excluded_targets] == [
        (ActionType.BLOCK_DOMAIN, "login.example.com")]
    isolate = package.action("XDR-83921:isolate_endpoint:TH-DC-01")
    assert [w.message for w in isolate.warnings] == [w.message for w in built[0].warnings]
    assert {e.data["record_id"] for e in package.evidence} == {record_id(1), record_id(2)}
    assert package.evidence[0].number == 1
