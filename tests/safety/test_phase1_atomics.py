"""Adversarial safety tests of the Phase 1 read zone (lens: atomics and approval).

Owner rule under test: investigation and recommendation are automatic, but every state-changing
action (including session revocation, release and restoration) needs a human approval; critical
assets always come out ELEVATED with a visible warning; dry run has no side effect.

Every test asserts the SAFE behaviour, so a failing test is a real defect. Attack surface:

* containment builders, routing, notifications, enrichment / investigation atomics and the
  workflow runner never reach a state-changing call, never enter a guard context, never create or
  sign a token and never mark an action as not needing approval;
* ``revoke_sessions`` and every restoration action always need approval;
* a critical-asset target always comes out ELEVATED with a warning, whatever path it takes
  (builder, runner duplicate merge, IP-named endpoint);
* dry run stays side-effect free through the Phase 1 runtime (workflow catalog + observers).

The legacy plan-bridge section was retired with the plan engine at the end of Phase 5 (architecture 14.4.3).

Fake data only: example.com / *.example / *.test, documentation IP ranges, fake hashes.
"""
from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

import pytest

from tests.fixtures.sample_workflows import SAMPLE_PACKAGE, SAMPLE_SCENARIO_DIR
from tests.fixtures.sample_workflows.lab import HASH, HOST, make_incident, make_lab
from tests.fixtures.sample_workflows.sample_malware import HOOKS as SAMPLE_HOOKS
from tests.fixtures.sample_workflows.sample_malware import WORKFLOW as SAMPLE_WORKFLOW
from tools.simulator.scenario import SIM_NOW, Scenario, ScenarioRun
from tools.simulator.workflow_scenario import WorkflowScenarioRun, load_workflow_scenario
from xdr_response import guard
from xdr_response.approval import CriticalAssetPolicy, PackageBuilder
from xdr_response.approval.critical_assets import WARNING_PREFIX
from xdr_response.approval.tokens import ApprovalTokenService
from xdr_response.atomics import containment_builders, read_atomics
from xdr_response.atomics.containment import CONTAINMENT_BUILDERS
from xdr_response.atomics.containment.builders import RESERVED_PARAM_KEYS, build_containment
from xdr_response.atomics.containment.models import BuiltRecommendation
from xdr_response.atomics.context import AtomicContext, build_context
from xdr_response.atomics.evidence import EvidenceBuilder
from xdr_response.atomics.investigation.normalize.typed import TYPED_INTEGRATION_KEY, TYPED_RECORD_KEY
from xdr_response.atomics.notifications.models import (
    DeliveryStatus,
    LifecycleEvent,
    LifecycleEventKind,
    NotificationDraft,
)
from xdr_response.atomics.notifications.render import (
    render_analyst_summary,
    render_incident_note,
    render_soc_notification,
)
from xdr_response.atomics.notifications.service import NotificationService
from xdr_response.atomics.notifications.sinks import MemoryNotificationSink, XdrIncidentNoteSink
from xdr_response.atomics.records import AtomicResult
from xdr_response.clock import FixedClock
from xdr_response.config import FORBIDDEN_KEYS, Settings
from xdr_response.config.policy import AllowlistPolicy
from xdr_response.errors import ApprovalError, ApprovalRequiredError
from xdr_response.integrations.simulated import SIMULATED_SUITE
from xdr_response.lifecycle.workflow_adapter import WorkflowInvestigationReport, WorkflowRecommender
from xdr_response.models import (
    ActionCategory,
    ActionType,
    ApprovalLevel,
    ApprovalPurpose,
    Asset,
    ContainmentPackage,
    DecisionRequest,
    DecisionType,
    EvidenceDraft,
    Incident,
    IncidentState,
    Observable,
    ObservableType,
    ProposedAction,
    RecommendedAction,
    Severity,
    TargetKind,
    Verdict,
    get_action_spec,
)
from xdr_response.models.canonical import sha256_hex
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.definition import RecommendationRule, WorkflowDefinition
from xdr_response.workflows.discovery import DiscoveredWorkflow, WorkflowCatalog, discover_workflows
from xdr_response.workflows.hooks import RunView, WorkflowHooks
from xdr_response.workflows.runner import RuleOutcomeStatus

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
GUID = "00000000-0000-4000-8000-000000000142"
ROLE_ID = "00000000-0000-4000-8000-0000000000aa"
MESSAGE_ID = "AAMkAD-fake-message-0001"

STATE_CHANGING = frozenset(a for a in ActionType if get_action_spec(a).state_changing)
RESTORATION = frozenset(a for a in ActionType if get_action_spec(a).category is ActionCategory.RESTORATION)
READ_ONLY = frozenset(a for a in ActionType if not get_action_spec(a).state_changing)
APPROVAL_MARKERS = frozenset(FORBIDDEN_KEYS) | {"approval_level", "requires_approval", "approve", "approved"}

#: A target for every named builder (non-critical by the repository's critical-assets.yaml).
BUILDER_TARGETS: dict[str, str] = {
    "isolate_secure_endpoint": HOST,
    "isolate_defender_endpoint": HOST,
    "block_domain_umbrella": "bad-cdn.test",
    "block_url": "https://bad-cdn.test/payload",
    "block_ip": "198.51.100.77",
    "block_hash": HASH,
    "revoke_entra_sessions": "jsmith@example.com",
    "disable_entra_user": "jsmith@example.com",
    "quarantine_email": MESSAGE_ID,
    "delete_malicious_email": MESSAGE_ID,
    "intune_device_action": HOST,
    "terminate_process": f"{HOST}/4242",
    "quarantine_file": f"{HOST}/{HASH}",
    "remove_persistence": f"{HOST}/run-key-0001",
    "remove_privileged_role": f"jsmith@example.com/{ROLE_ID}",
}


# ------------------------------------------------------------------------------------ helpers --
def _record_id(n: int) -> str:
    return "rec_" + sha256_hex(f"phase1-safety-record-{n}".encode())[:32]


def _drafts(n: int = 1) -> tuple[EvidenceDraft, ...]:
    return tuple(EvidenceDraft(source="secure_endpoint", summary=f"secure_endpoint: fake detection {i}",
                               observed_at=NOW, data={"record_id": _record_id(i), "kind": "detection"})
                 for i in range(1, n + 1))


def _builder_kwargs(**extra: Any) -> dict[str, Any]:
    return {"evidence": _drafts(), "risk_score": 80, "confidence_score": 70,
            "rationale": "fake detection on the target", **extra}


def _incident(*, assets: tuple[Asset, ...] = (), observables=((ObservableType.HOSTNAME, HOST),),
              incident_id: str = "XDR-P1-SAFE-0001") -> Incident:
    return Incident(incident_id=incident_id, title="Phase 1 safety probe", severity=Severity.HIGH, created_at=SIM_NOW,
                    workflow_id="sample-malware", workflow_version="1.0.0",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables), assets=assets)


def _full_lab(*, dry_run: bool = True):
    return make_lab(SIMULATED_SUITE, dry_run=dry_run)


def _ctx(lab, incident: Incident | None = None) -> AtomicContext:
    return build_context(incident or _incident(), lab.registry, lab.settings, clock=lab.clock, dry_run=True)


def _package_builder(settings: Settings, clock=None) -> PackageBuilder:
    return PackageBuilder(settings, critical_assets=CriticalAssetPolicy(settings.critical_assets),
                          allowlists=AllowlistPolicy(settings.allowlists), clock=clock or FixedClock(NOW))


def _package(settings: Settings, incident: Incident, proposals, *, dry_run: bool = True) -> ContainmentPackage:
    proposals = tuple(proposals)
    return _package_builder(settings).build(
        incident, proposals, risk_score=max(p.risk_score for p in proposals),
        confidence_score=max(p.confidence_score for p in proposals), summary="phase 1 safety probe",
        dry_run=dry_run)


def _proposal_or_unrouted_probe(built: BuiltRecommendation, risk_score: int = 1,
                                confidence_score: int = 1) -> ProposedAction:
    """The built proposal, or, for an action no adapter can execute, the same proposal built by hand.

    terminate_process and quarantine_file have no VERIFIED write on any real adapter, and the simulated
    adapters mirror the real ones (production parity, architecture 14.14.3 and 15.2): they are reported
    as unrouted for manual handling and never proposed. The package layer must still elevate their
    critical targets if a route is ever added, so the probe goes through the PackageBuilder anyway.
    """
    if built.proposal is not None:
        return built.proposal
    assert built.unrouted_reason, "an unroutable action must be reported for manual handling, never dropped"
    spec = get_action_spec(built.action_type)
    return ProposedAction(action_type=built.action_type, target=built.target, target_kind=spec.target_kind,
                          params={"integration": spec.integrations[0]},  # hypothetical future route
                          evidence=_drafts(), risk_score=risk_score, confidence_score=confidence_score,
                          rationale="fake detection on the target")


def _keys_anywhere(value: Any) -> set[str]:
    """Every mapping key at any depth, folded."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key, inner in value.items():
            found.add(str(key).strip().lower())
            found |= _keys_anywhere(inner)
    elif isinstance(value, (list, tuple)):
        for inner in value:
            found |= _keys_anywhere(inner)
    return found


@pytest.fixture
def write_tripwires(monkeypatch) -> Iterator[list[str]]:
    """Fail loudly if read-zone code enters a guard context, checks or signs or issues a token."""
    hits: list[str] = []

    def trip(name: str):
        def _tripped(*args: Any, **kwargs: Any) -> Any:
            hits.append(name)
            raise AssertionError(f"read-zone code reached {name}")
        return _tripped

    monkeypatch.setattr(guard, "authorized", trip("guard.authorized"))
    monkeypatch.setattr(guard, "check_token", trip("guard.check_token"))
    monkeypatch.setattr(guard, "require_authorization", trip("guard.require_authorization"))
    monkeypatch.setattr(ApprovalTokenService, "sign", trip("ApprovalTokenService.sign"))
    monkeypatch.setattr(ApprovalTokenService, "issue", trip("ApprovalTokenService.issue"))
    monkeypatch.setattr(ApprovalTokenService, "bind_issuer", trip("ApprovalTokenService.bind_issuer"))
    yield hits
    assert hits == [], f"read-zone code reached write paths: {hits}"


# ================================================================ containment builders ====
@pytest.mark.parametrize("name", sorted(CONTAINMENT_BUILDERS))
def test_every_named_builder_returns_data_and_never_writes(name, write_tripwires):
    lab = _full_lab()
    ctx = _ctx(lab)
    built = CONTAINMENT_BUILDERS[name](ctx, BUILDER_TARGETS[name], **_builder_kwargs())
    assert isinstance(built, BuiltRecommendation)
    assert built.proposal is None or type(built.proposal) is ProposedAction
    assert not isinstance(built.proposal, RecommendedAction)
    assert lab.environment.state_changing_calls() == []
    assert guard.current() is None
    if built.proposal is not None:
        assert not (_keys_anywhere(built.proposal.params) & APPROVAL_MARKERS)
        assert get_action_spec(built.action_type).state_changing  # it will need a human decision
    else:
        assert built.unrouted_reason, "an unrouted action is reported, never silently dropped"


def test_builder_table_is_the_contract_table_and_has_no_restoration_entry():
    assert dict(containment_builders()) == dict(CONTAINMENT_BUILDERS)
    for fn in CONTAINMENT_BUILDERS.values():
        assert not guard.is_state_changing_method(fn)


@pytest.mark.parametrize("action_type", sorted(RESTORATION | READ_ONLY, key=lambda a: a.value))
def test_build_containment_refuses_restoration_and_read_only_types(action_type):
    lab = _full_lab()
    with pytest.raises(ValueError):
        build_containment(_ctx(lab), action_type, "anything-at-all", **_builder_kwargs())


@pytest.mark.parametrize("params", [
    {"auto_approve": True},
    {"AUTO_APPROVE": True},
    {" skip_approval ": True},
    {"bypass_approval": "yes"},
    {"approval_required": False},
    {"approval_level": "STANDARD"},
    {"Approval_Level": "NONE"},
    {"integration": "meraki"},
    {"Integration": "meraki"},
    {"verify_integration": "secure_endpoint"},
    {"restores": "ctl-1"},
    {"action_id": "native-guess"},
    {"wrapper": {"auto_approve": True}},
    {"wrapper": [{"skip_approval": True}]},
    {"api_key": "SECRET_NAME"},
    {"ratio": 0.5},
])
def test_builder_refuses_approval_bypass_reserved_secret_and_float_params(params):
    lab = _full_lab()
    with pytest.raises(ValueError):
        CONTAINMENT_BUILDERS["isolate_secure_endpoint"](_ctx(lab), HOST, **_builder_kwargs(params=params))


@pytest.mark.parametrize("params", [
    {"requires_approval": False},
    {"approve": True},
    {"approved": True},
    {"options": {"requires_approval": False}},
    {"options": {"approval_level": "NONE"}},
])
def test_builder_never_lets_params_mark_an_action_as_not_needing_approval(params):
    """The workflow definition refuses APPROVAL_LIKE_KEYS; the builder must not be weaker."""
    lab = _full_lab()
    try:
        built = CONTAINMENT_BUILDERS["isolate_secure_endpoint"](_ctx(lab), HOST, **_builder_kwargs(params=params))
    except ValueError:
        return  # refused: safe
    assert built.proposal is not None
    leaked = _keys_anywhere(built.proposal.params) & APPROVAL_MARKERS
    assert not leaked, f"approval marker params {sorted(leaked)} reached the proposal"


def test_route_params_always_win_and_caller_cannot_redirect_execution():
    lab = _full_lab()
    built = CONTAINMENT_BUILDERS["isolate_secure_endpoint"](_ctx(lab), HOST, **_builder_kwargs(
        params={"comment": "fake"}))
    assert built.proposal is not None
    assert built.proposal.params["integration"] == built.route.integration == "secure_endpoint"


def test_hard_delete_is_never_recommended():
    lab = _full_lab()
    for choice in ("hardDelete", "HardDelete", "purge"):
        with pytest.raises(ValueError):
            CONTAINMENT_BUILDERS["delete_malicious_email"](_ctx(lab), MESSAGE_ID,
                                                           **_builder_kwargs(params={"delete_action": choice}))


def test_builder_needs_record_backed_evidence():
    lab = _full_lab()
    ctx = _ctx(lab)
    with pytest.raises(ValueError):
        CONTAINMENT_BUILDERS["block_hash"](ctx, HASH, **_builder_kwargs(evidence=()))
    hand_made = EvidenceDraft(source="secure_endpoint", summary="secure_endpoint: trust me", observed_at=NOW)
    with pytest.raises(ValueError):
        CONTAINMENT_BUILDERS["block_hash"](ctx, HASH, **_builder_kwargs(evidence=(hand_made,)))
    with pytest.raises(ValueError):  # AI output can never be evidence
        EvidenceDraft(source="ai", summary="the model thinks so", data={"record_id": _record_id(9)})


def test_revoke_sessions_is_state_changing_irreversible_and_packaged_for_approval():
    spec = get_action_spec(ActionType.REVOKE_SESSIONS)
    assert spec.state_changing and spec.purpose is ApprovalPurpose.CONTAINMENT
    lab = _full_lab()
    incident = _incident(observables=((ObservableType.USER, "jsmith@example.com"),))
    built = CONTAINMENT_BUILDERS["revoke_entra_sessions"](_ctx(lab, incident), "jsmith@example.com",
                                                          **_builder_kwargs())
    assert built.proposal is not None and not built.reversible
    package = _package(lab.settings, incident, [built.proposal])
    (action,) = package.actions
    assert action.action_type is ActionType.REVOKE_SESSIONS
    assert action.approval_level in (ApprovalLevel.STANDARD, ApprovalLevel.ELEVATED)
    assert lab.environment.state_changing_calls() == []


# ================================================================ critical assets ====
#: Builders whose action no real adapter can execute (architecture 15.2): always unrouted, never proposed.
_NO_VERIFIED_WRITE = frozenset({"terminate_process", "quarantine_file"})


@pytest.mark.parametrize(("name", "target"), [
    ("isolate_secure_endpoint", "DC-01"),
    ("isolate_defender_endpoint", "prd-db-07"),
    ("isolate_secure_endpoint", "  exec-ceo-laptop  "),
    ("intune_device_action", "VIP-0001"),
    ("terminate_process", "DC-01/4242"),
    ("quarantine_file", f"PRD-DB-07/{HASH}"),
    ("disable_entra_user", "ADM-JDOE@EXAMPLE.COM"),
    ("revoke_entra_sessions", "svc-backup@example.com"),
    ("remove_privileged_role", f"breakglass-01@example.com/{ROLE_ID}"),
    ("block_ip", "203.0.113.10"),
])
def test_critical_asset_targets_are_elevated_with_a_visible_warning(name, target):
    lab = _full_lab()
    incident = _incident()
    built = CONTAINMENT_BUILDERS[name](_ctx(lab, incident), target, **_builder_kwargs(risk_score=1,
                                                                                       confidence_score=1))
    assert built.warnings, "the builder preview must show the critical-asset warning"
    assert built.elevation_expected
    if name not in _NO_VERIFIED_WRITE:
        assert built.proposal is not None
    (action,) = _package(lab.settings, incident, [_proposal_or_unrouted_probe(built)]).actions
    assert action.approval_level is ApprovalLevel.ELEVATED
    assert action.warnings and all(w.message.startswith(WARNING_PREFIX) for w in action.warnings)


def test_incident_asset_context_cannot_be_shrunk_by_the_caller():
    lab = _full_lab()
    incident = _incident(assets=(Asset(name="TH-SRV-2000", kind=TargetKind.ENDPOINT, groups=("Domain Controllers",)),))
    built = CONTAINMENT_BUILDERS["isolate_secure_endpoint"](
        _ctx(lab, incident), "th-srv-2000",
        **_builder_kwargs(asset=Asset(name="TH-SRV-2000", kind=TargetKind.ENDPOINT, groups=(), tags=())))
    assert built.warnings
    (action,) = _package(lab.settings, incident, [built.proposal]).actions
    assert action.approval_level is ApprovalLevel.ELEVATED and action.warnings


def test_remove_privileged_role_is_always_elevated():
    lab = _full_lab()
    built = CONTAINMENT_BUILDERS["remove_privileged_role"](_ctx(lab), f"jsmith@example.com/{ROLE_ID}",
                                                           **_builder_kwargs())
    assert built.elevation_expected
    (action,) = _package(lab.settings, _incident(), [built.proposal]).actions
    assert action.approval_level is ApprovalLevel.ELEVATED


@pytest.mark.parametrize(("name", "target"), [
    ("isolate_secure_endpoint", "203.0.113.10"),          # production_server ip_cidrs 203.0.113.0/26
    ("isolate_defender_endpoint", "192.0.2.5"),           # network_infrastructure ip_cidrs 192.0.2.0/28
    ("quarantine_file", f"203.0.113.10/{HASH}"),
])
def test_an_endpoint_named_by_its_ip_inside_a_critical_cidr_is_elevated(name, target):
    """Endpoints are often reported by IP; the critical-asset CIDR must still apply."""
    lab = _full_lab()
    incident = _incident()
    built = CONTAINMENT_BUILDERS[name](_ctx(lab, incident), target, **_builder_kwargs())
    if name not in _NO_VERIFIED_WRITE:
        assert built.proposal is not None
    assert built.warnings, "the builder preview must show the critical-asset warning"
    (action,) = _package(lab.settings, incident, [_proposal_or_unrouted_probe(built, 80, 70)]).actions
    assert action.approval_level is ApprovalLevel.ELEVATED, (
        f"{name} on {target} (inside a critical CIDR) came out {action.approval_level.value} with no warning")
    assert action.warnings


# ================================================================ workflow runner ====
def _rule(base: RecommendationRule, **update: Any) -> dict[str, Any]:
    data = base.model_dump(mode="json")
    data.update(update)
    return data


def _workflow(*rules: dict[str, Any], workflow_id: str = "sample-malware") -> WorkflowDefinition:
    data = SAMPLE_WORKFLOW.model_dump(mode="json")
    data["id"] = workflow_id
    data["recommendations"] = list(rules)
    return WorkflowDefinition.model_validate(data)


def _exec_lab(groups=("Executives",), tags=()):
    lab = make_lab({"secure_endpoint": ("endpoint",), "virustotal": ("intel",)})  # Defender not enabled
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST,
              groups=list(groups), tags=list(tags), isolation_state="not_isolated")
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="detection", detection_id=f"det-{HOST}",
              name="Sample.Trojan.Generic", verdict="MALICIOUS", severity="HIGH", endpoint=HOST, sha256=HASH)
    lab.environment.set_reputation(ObservableType.SHA256, HASH, Verdict.MALICIOUS, risk_score=90, confidence=85,
                                   integrations=["secure_endpoint", "virustotal"])
    return lab


def _isolate_rule() -> RecommendationRule:
    return next(r for r in SAMPLE_WORKFLOW.recommendations if r.action is ActionType.ISOLATE_ENDPOINT)


def test_control_rule_asset_context_makes_the_isolation_elevated():
    lab = _exec_lab()
    workflow = _workflow(_rule(_isolate_rule(), id="isolate_with_context"))
    incident = make_incident()
    run = lab.runner.run(workflow, SAMPLE_HOOKS, incident, dry_run=True)
    (proposal,) = run.proposals
    (action,) = _package(lab.settings, incident, run.proposals).actions
    assert action.approval_level is ApprovalLevel.ELEVATED and action.warnings


def test_duplicate_rule_merge_keeps_the_critical_asset_context_of_every_rule():
    """Two rules recommend the same isolation; only the second carries the investigated asset context.

    The run notes say ELEVATED is needed, so the package must be ELEVATED too.
    """
    lab = _exec_lab()
    workflow = _workflow(_rule(_isolate_rule(), id="isolate_plain", asset=None),
                         _rule(_isolate_rule(), id="isolate_with_context"))
    incident = make_incident()
    run = lab.runner.run(workflow, SAMPLE_HOOKS, incident, dry_run=True)
    statuses = [o.status for o in run.outcomes]
    assert statuses == [RuleOutcomeStatus.PROPOSED, RuleOutcomeStatus.DUPLICATE]
    assert any("needs ELEVATED approval" in n for n in run.notes), "the run itself saw the critical asset"
    (action,) = _package(lab.settings, incident, run.proposals).actions
    assert action.approval_level is ApprovalLevel.ELEVATED, (
        "duplicate merge dropped the second rule's asset context: the critical endpoint is STANDARD")
    assert action.warnings


class _ForgingHooks(WorkflowHooks):
    """A hostile hook: cites a fabricated record and tries to smuggle actions through facts."""

    def derive_signals(self, view: RunView):
        return [ScoringSignal(category=SignalCategory.ENDPOINT_DETECTION, integration="secure_endpoint",
                              observable=Observable(type=ObservableType.HOSTNAME, value=HOST),
                              verdict=Verdict.MALICIOUS, severity=100, confidence=100,
                              record_ids=(_record_id(404),), origin="workflow:sample-malware")]

    def facts(self, view: RunView):
        return {"malicious_detections": 1, "auto_approve": True,
                "proposal": {"action_type": "release_endpoint", "target": HOST}}


def test_hooks_cannot_fabricate_evidence_or_bypass_approval(write_tripwires):
    lab = _exec_lab(groups=("Workstations",))
    run = lab.runner.run(SAMPLE_WORKFLOW, _ForgingHooks(), make_incident(), dry_run=True)
    assert run.signals == (), "a signal citing a fabricated record must be dropped"
    for proposal in run.proposals:
        assert _record_id(404) not in EvidenceBuilder.record_ids(proposal.evidence)
        EvidenceBuilder(run.index).verify(proposal.evidence)
        assert get_action_spec(proposal.action_type).purpose is ApprovalPurpose.CONTAINMENT
        assert not (_keys_anywhere(proposal.params) & APPROVAL_MARKERS)
    assert lab.environment.state_changing_calls() == []


def test_runner_with_every_adapter_enabled_never_writes_and_cites_only_run_records(write_tripwires):
    lab = make_lab(SIMULATED_SUITE)
    lab.infected()
    run = lab.runner.run(SAMPLE_WORKFLOW, SAMPLE_HOOKS, make_incident(
        (ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, HASH)), dry_run=True)
    assert run.proposals, "the lab should recommend something"
    for proposal in run.proposals:
        assert type(proposal) is ProposedAction
        EvidenceBuilder(run.index).verify(proposal.evidence)
        assert 0 <= proposal.risk_score <= 100 and 0 <= proposal.confidence_score <= 100
    assert lab.environment.state_changing_calls() == []
    assert guard.current() is None


def test_rule_params_cannot_carry_approval_markers_into_a_proposal():
    """A rule param *value* that is a mapping is not walked by the definition's key check."""
    lab = _exec_lab(groups=("Workstations",))
    rule = _rule(_isolate_rule(), id="isolate_with_options",
                 params={"options": "{'requires_approval': False, 'approved': True}"})
    run = lab.runner.run(_workflow(rule), SAMPLE_HOOKS, make_incident(), dry_run=True)
    for proposal in run.proposals:
        leaked = _keys_anywhere(proposal.params) & APPROVAL_MARKERS
        assert not leaked, f"approval marker params {sorted(leaked)} reached a workflow proposal"


@pytest.mark.parametrize("action_type", sorted(RESTORATION | READ_ONLY, key=lambda a: a.value))
def test_a_rule_can_never_recommend_restoration_or_read_only_actions(action_type):
    with pytest.raises(ValueError):
        RecommendationRule(id="probe", description="probe", action=action_type, for_each="[]",
                           target="'x'", evidence="[]", rationale="'x'")


@pytest.mark.parametrize("key", ["auto_approve", "AUTO_APPROVE", "approval_level", "requires_approval",
                                 "integration", "restores", "verify_integration"])
def test_a_rule_cannot_declare_approval_or_routing_params(key):
    with pytest.raises(ValueError):
        RecommendationRule(id="probe", description="probe", action=ActionType.BLOCK_HASH, for_each="[]",
                           target="'x'", evidence="[]", rationale="'x'", params={key: "'x'"})


def test_workflow_recommender_hands_only_proposals_to_the_package_builder():
    lab = make_lab()
    lab.infected()
    incident = make_incident((ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, HASH))
    run = lab.runner.run(SAMPLE_WORKFLOW, SAMPLE_HOOKS, incident, dry_run=True)
    report = WorkflowInvestigationReport(incident_id=incident.incident_id, enrichments=run.raw_enrichments(),
                                         investigations=run.raw_investigations(), health=dict(run.health), run=run)

    class _NeverCalled:
        def recommend(self, *a, **k):  # pragma: no cover - a run is present
            raise AssertionError("fallback must not be used when a run exists")

    rec = WorkflowRecommender(_NeverCalled()).recommend(incident, report)
    assert all(type(p) is ProposedAction for p in rec.proposals)
    assert rec.proposals == run.proposals


def test_read_atomics_table_contains_no_state_changing_entry():
    for name in read_atomics():
        assert not name.startswith(tuple(a.value for a in STATE_CHANGING)), name


def test_a_degraded_source_does_not_block_a_backed_recommendation():
    lab = make_lab()
    lab.infected()
    from xdr_response.integrations.simulated import FaultKind
    lab.environment.inject(FaultKind.UNAVAILABLE, integration="virustotal", times=100)
    run = lab.runner.run(SAMPLE_WORKFLOW, SAMPLE_HOOKS, make_incident(
        (ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, HASH)), dry_run=True)
    assert "virustotal" in run.degraded_sources()
    assert any(p.action_type is ActionType.ISOLATE_ENDPOINT for p in run.proposals)


# ================================================================ lifecycle: revoke + release ====
def _revoke_workflow() -> WorkflowDefinition:
    rule = {
        "id": "revoke_user_sessions", "description": "Revoke sessions of the user behind a malicious detection",
        "action": "revoke_sessions", "builder": "revoke_entra_sessions",
        "for_each": "[d for d in results.investigate_endpoint[0].detections if d.verdict == 'MALICIOUS']",
        "target": "item.user", "evidence": "ids([item])", "rationale": "'malicious detection by ' + item.user",
    }
    return _workflow(rule)


def test_revoke_sessions_from_a_workflow_needs_a_human_approval():
    catalog = WorkflowCatalog([DiscoveredWorkflow(definition=_revoke_workflow(), hooks=SAMPLE_HOOKS,
                                                  module="tests.safety.phase1_probe")])
    incident = _incident(incident_id="XDR-P1-REVOKE-1")
    scenario = Scenario(name="revoke-probe", description="", incident=incident, suite=dict(SIMULATED_SUITE))
    run = ScenarioRun(scenario, live=True, workflows=catalog)
    run.environment.add_findings(ActionType.INVESTIGATE_ENDPOINT, HOST, {TYPED_RECORD_KEY: {
        "kind": "detection", "detection_id": "det-r1", "name": "Sample.Trojan.Generic", "verdict": "MALICIOUS",
        "severity": "HIGH", "endpoint": HOST, "sha256": HASH, "user": "jsmith@example.com"},
        TYPED_INTEGRATION_KEY: "secure_endpoint"})
    detection = run.detect()
    package = detection.package
    assert package is not None, detection.notes
    assert [a.action_type for a in package.actions] == [ActionType.REVOKE_SESSIONS]
    assert run.environment.state_changing_calls() == [], "recommending a revocation never revokes"
    assert run.orchestrator.get_incident(incident.incident_id).state is IncidentState.AWAITING_APPROVAL

    with pytest.raises(ApprovalRequiredError):  # execution without a token fails closed
        run.runtime.executor.execute(package, None)
    for who in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_decision(
                DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL),
                run.credentials(who))
    assert run.environment.state_changing_calls() == []

    run.orchestrator.submit_decision(DecisionRequest(package_id=package.package_id,
                                                     decision=DecisionType.APPROVE_ALL), run.credentials("analyst"))
    calls = run.environment.state_changing_calls()
    assert [c.operation for c in calls] == ["revoke_sessions"]


def test_release_needs_its_own_human_approval_through_the_workflow_runtime():
    scenario = load_workflow_scenario(SAMPLE_SCENARIO_DIR / "sample-malware" / "release-restoration.yaml")
    run = WorkflowScenarioRun(scenario, live=True, catalog=discover_workflows(SAMPLE_PACKAGE))
    run.detect()
    run.decide()
    contained = len(run.environment.state_changing_calls())
    assert contained > 0
    release = run.propose_release()
    assert len(run.environment.state_changing_calls()) == contained, "proposing a release changes nothing"
    assert all(get_action_spec(a.action_type).category is ActionCategory.RESTORATION for a in release.actions)
    with pytest.raises(ApprovalRequiredError):
        run.runtime.restoration.execute(release, None)
    for who in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_release_decision(
                DecisionRequest(package_id=release.package_id, decision=DecisionType.APPROVE_ALL),
                run.credentials(who))
    assert len(run.environment.state_changing_calls()) == contained
    run.decide_release()
    assert len(run.environment.state_changing_calls()) > contained


# ================================================================ dry run through the runtime ====
@pytest.mark.parametrize("name", ["dry-run.yaml", "critical-asset-elevated.yaml", "tp-approve-all.yaml"])
def test_dry_run_through_the_phase1_runtime_has_no_side_effect(name):
    scenario = load_workflow_scenario(SAMPLE_SCENARIO_DIR / "sample-malware" / name)
    run = WorkflowScenarioRun(scenario, live=False, catalog=discover_workflows(SAMPLE_PACKAGE))
    run.detect()
    package = run.detection.package
    assert package is not None and package.dry_run
    if run.workflow_scenario.analyst is not None:
        result = run.decide()
        assert result.dry_run
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == [], "dry run never registers a temporary control"
    assert run.outbox.drafts, "dry run still writes [DRY RUN] notification drafts"
    for draft in run.outbox.drafts:
        assert draft.title.startswith("[DRY RUN] "), draft.title
        assert draft.event not in (LifecycleEventKind.CONTAINMENT_COMPLETED,
                                   LifecycleEventKind.RESTORATION_COMPLETED)
    if name == "critical-asset-elevated.yaml":
        assert package.has_elevated
        assert any(WARNING_PREFIX in d.body for d in run.outbox.drafts)


# ================================================================ notifications ====
PARAM_MARKER = "param-marker-7f3a9c"


def _notification_package(*, critical: bool = False, dry_run: bool = False) -> tuple[Incident, ContainmentPackage]:
    lab = _full_lab()
    incident = _incident()
    target = "DC-01" if critical else HOST
    built = CONTAINMENT_BUILDERS["isolate_secure_endpoint"](
        _ctx(lab, incident), target, **_builder_kwargs(params={"comment": PARAM_MARKER}))
    return incident, _package(lab.settings, incident, [built.proposal], dry_run=dry_run)


@pytest.mark.parametrize("render", [render_incident_note, render_soc_notification, render_analyst_summary])
def test_notifications_never_show_params_and_always_show_elevated_warnings(render):
    incident, package = _notification_package(critical=True)
    draft = render(LifecycleEvent(kind=LifecycleEventKind.PACKAGE_PROPOSED, at=NOW, incident=incident,
                                  package=package))
    assert isinstance(draft, NotificationDraft)
    assert PARAM_MARKER not in draft.body and PARAM_MARKER not in draft.title
    assert "ELEVATED" in draft.title and WARNING_PREFIX in draft.body
    assert "cannot approve, execute or release anything" in draft.body
    lowered = draft.body.lower()
    assert "http://" not in lowered and "https://" not in lowered


@pytest.mark.parametrize("render", [render_incident_note, render_soc_notification, render_analyst_summary])
def test_dry_run_notifications_are_always_labelled(render):
    incident, package = _notification_package(dry_run=True)
    draft = render(LifecycleEvent(kind=LifecycleEventKind.PACKAGE_PROPOSED, at=NOW, incident=incident,
                                  package=package, dry_run=False))
    assert draft.title.startswith("[DRY RUN] ")


def test_xdr_note_sink_never_delivers_and_never_touches_an_adapter():
    lab = _full_lab()
    incident, package = _notification_package()
    service = NotificationService([XdrIncidentNoteSink(clock=lab.clock), MemoryNotificationSink(clock=lab.clock)],
                                  clock=lab.clock)
    records = service.on_event(LifecycleEvent(kind=LifecycleEventKind.PACKAGE_PROPOSED, at=NOW, incident=incident,
                                              package=package))
    assert records
    assert {r.status for r in records if r.sink == "cisco_xdr_note"} == {DeliveryStatus.NOT_DELIVERED_UNVERIFIED}
    assert lab.environment.state_changing_calls() == []
    assert service.on_event("not an event") == ()  # never raises


def test_live_notifications_show_only_a_token_id_prefix():
    scenario = load_workflow_scenario(SAMPLE_SCENARIO_DIR / "sample-malware" / "tp-approve-all.yaml")
    run = WorkflowScenarioRun(scenario, live=True, catalog=discover_workflows(SAMPLE_PACKAGE))
    run.play(probe=False)
    token_id = run.decision.outcome.decision.token_id
    assert token_id and len(token_id) > 8
    assert run.outbox.drafts
    for draft in run.outbox.drafts:
        assert token_id not in draft.body and token_id not in draft.title


# ================================================================ read atomics and the facade ====
_SAMPLE_SUBJECTS: dict[ObservableType, str] = {
    ObservableType.IP: "198.51.100.77", ObservableType.IPV6: "2001:db8::77", ObservableType.DOMAIN: "bad-cdn.test",
    ObservableType.URL: "https://bad-cdn.test/payload", ObservableType.SHA256: HASH, ObservableType.SHA1: "ab" * 20,
    ObservableType.MD5: "cd" * 16, ObservableType.EMAIL_ADDRESS: "jsmith@example.com",
    ObservableType.USER: "jsmith@example.com", ObservableType.HOSTNAME: HOST, ObservableType.ENDPOINT_ID: GUID,
    ObservableType.EMAIL_MESSAGE_ID: MESSAGE_ID, ObservableType.PROCESS: f"{HOST}/4242",
}


def _atomic_cases() -> list[tuple[str, ObservableType]]:
    from xdr_response.atomics import atomic_subject_types
    return [(name, otype) for name, types in sorted(atomic_subject_types().items())
            for otype in sorted(types, key=lambda t: t.value)]


@pytest.mark.parametrize(("atomic", "otype"), _atomic_cases())
def test_every_read_atomic_reads_only(atomic, otype, write_tripwires):
    lab = _full_lab()
    lab.infected()
    ctx = _ctx(lab, _incident(observables=((ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, HASH))))
    result = read_atomics()[atomic](ctx, Observable(type=otype, value=_SAMPLE_SUBJECTS[otype]))
    assert isinstance(result, AtomicResult)
    assert lab.environment.state_changing_calls() == []
    assert guard.current() is None


def test_read_only_facade_exposes_only_the_contract_surface():
    from xdr_response.atomics.context import ReadOnlyAdapters
    from xdr_response.integrations.base import IntegrationAdapter
    from xdr_response.models import InvestigationQuery

    public = {n for n in dir(ReadOnlyAdapters) if not n.startswith("_")}
    assert public == {"enabled", "is_simulated", "manifest", "health", "enrichers", "enrich", "investigators",
                      "investigate", "executors", "native_response_actions"}
    lab = _full_lab()
    facade = lab.adapters
    for value in (facade.enabled(), facade.executors(ActionType.ISOLATE_ENDPOINT),
                  facade.enrichers(ObservableType.SHA256), facade.investigators(ActionType.INVESTIGATE_ENDPOINT)):
        assert all(type(v) is str for v in value)
        assert not any(isinstance(v, IntegrationAdapter) for v in value)
    with pytest.raises(ValueError):
        facade.investigators(ActionType.ISOLATE_ENDPOINT)
    with pytest.raises(ValueError):
        facade.executors(ActionType.RELEASE_ENDPOINT)
    forged = InvestigationQuery.model_construct(action_type=ActionType.ISOLATE_ENDPOINT,
                                                subject=Observable(type=ObservableType.HOSTNAME, value=HOST),
                                                time_from=None, time_to=None, limit=1, options={})
    with pytest.raises(ValueError):  # a query skipping validation still cannot reach a write
        facade.investigate("secure_endpoint", forged)
    assert lab.environment.state_changing_calls() == []


def test_a_product_pinned_builder_never_silently_switches_product():
    lab = make_lab({"secure_endpoint": ("endpoint",)})
    built = CONTAINMENT_BUILDERS["isolate_defender_endpoint"](_ctx(lab), HOST, **_builder_kwargs())
    assert built.proposal is None and built.unrouted_reason
    assert built.route.integration is None


def test_an_unverified_intune_device_action_is_refused():
    from xdr_response.errors import UnverifiedEndpointError
    lab = _full_lab()
    for action in ("wipe", "retire", "restart"):
        with pytest.raises(UnverifiedEndpointError):
            CONTAINMENT_BUILDERS["intune_device_action"](_ctx(lab), HOST, action=action, **_builder_kwargs())


# ======================================================================= round 2 ====
# Phase 1, round 2 (lens: atomics and approval). Each test asserts the SAFE behaviour.

@pytest.mark.parametrize("target", [
    "::ffff:203.0.113.10",       # IPv4-mapped form of a production_server address (203.0.113.0/26)
    "64:ff9b::cb00:710a",        # NAT64 (RFC 6052) form of 203.0.113.10
])
def test_block_ip_on_an_ipv6_form_of_a_critical_ipv4_is_elevated(target):
    """The disclosure policy judges an IPv6 address that embeds an IPv4 address by the embedded address
    too (14.9.6); the critical-asset policy must not be weaker. Blocking the mapped / NAT64 form of a
    critical server's address cuts that server off just like blocking the IPv4 form (which is ELEVATED)."""
    lab = _full_lab()
    incident = _incident()
    built = CONTAINMENT_BUILDERS["block_ip"](_ctx(lab, incident), target, **_builder_kwargs())
    assert built.proposal is not None
    (action,) = _package(lab.settings, incident, [built.proposal]).actions
    assert action.approval_level is ApprovalLevel.ELEVATED, (
        f"block_ip {target} embeds a critical IPv4 address but came out {action.approval_level.value}")
    assert action.warnings and all(w.message.startswith(WARNING_PREFIX) for w in action.warnings)


def test_block_ip_on_an_ipv6_form_of_an_allowlisted_critical_ipv4_is_excluded_visibly():
    """192.0.2.5 is both critical (network_infrastructure) and allow-listed in the repository config.

    Since 14.10.7 the mapped spelling is the IPv4 host, and the allow-list wins over the critical-asset class
    (as for 192.0.2.5 itself): the block is shown as excluded and never becomes an action."""
    lab = _full_lab()
    incident = _incident()
    built = CONTAINMENT_BUILDERS["block_ip"](_ctx(lab, incident), "::ffff:192.0.2.5", **_builder_kwargs())
    other = CONTAINMENT_BUILDERS["block_ip"](_ctx(lab, incident), "198.51.100.77", **_builder_kwargs())
    assert built.proposal is not None and other.proposal is not None
    package = _package(lab.settings, incident, [built.proposal, other.proposal])
    excluded = {(e.action_type, e.target) for e in package.excluded_targets}
    assert (ActionType.BLOCK_IP, "192.0.2.5") in excluded
    assert all(a.target != "192.0.2.5" for a in package.actions)


def test_an_endpoint_named_by_the_ip_of_a_critical_incident_asset_is_elevated():
    """The incident's own asset record says 198.51.100.20 is a domain controller (group context).

    Detections often name a host by its IP (14.9.6), so isolating the endpoint "198.51.100.20" acts on
    that domain controller and must be ELEVATED with a warning, in the builder preview and the package.
    """
    lab = _full_lab()
    dc = Asset(name="TH-SRV-2000", kind=TargetKind.ENDPOINT, groups=("Domain Controllers",), ip="198.51.100.20")
    incident = _incident(assets=(dc,))
    built = CONTAINMENT_BUILDERS["isolate_secure_endpoint"](_ctx(lab, incident), "198.51.100.20",
                                                            **_builder_kwargs())
    assert built.proposal is not None
    (action,) = _package(lab.settings, incident, [built.proposal]).actions
    assert action.approval_level is ApprovalLevel.ELEVATED, (
        "isolating a domain controller by its IP came out STANDARD: the incident asset is looked up by name only")
    assert action.warnings
    assert built.warnings, "the builder preview must show the critical-asset warning too"


@pytest.mark.parametrize("role", ["Global Administrator", "Privileged Role Administrator"])
def test_a_user_holding_a_privileged_directory_role_is_elevated(role):
    """``UserProfileRecord`` marks a user ``privileged`` from its directory roles (PRIVILEGED_ROLE_NAMES)
    and a rule passes them as asset ``roles``. Disabling (or revoking) such an account is acting on a
    privileged account, so it must be ELEVATED with a warning, never STANDARD."""
    from xdr_response.atomics.records import PRIVILEGED_ROLE_NAMES
    assert role.lower() in PRIVILEGED_ROLE_NAMES
    lab = _full_lab()
    incident = _incident(observables=((ObservableType.USER, "jdoe@example.com"),))
    asset = Asset(name="jdoe@example.com", kind=TargetKind.USER, roles=(role,))
    for name in ("disable_entra_user", "revoke_entra_sessions"):
        built = CONTAINMENT_BUILDERS[name](_ctx(lab, incident), "jdoe@example.com",
                                           **_builder_kwargs(asset=asset))
        assert built.proposal is not None
        (action,) = _package(lab.settings, incident, [built.proposal]).actions
        assert action.approval_level is ApprovalLevel.ELEVATED, (
            f"{name} on a {role} came out {action.approval_level.value}: asset roles are never evaluated")
        assert action.warnings


def _defender_isolate_rule(**update: Any) -> dict[str, Any]:
    """The sample isolation rule pinned to Defender (not enabled in the lab: always unrouted)."""
    return _rule(_isolate_rule(), builder="isolate_defender_endpoint", **update)


def test_duplicate_merge_keeps_the_asset_context_of_an_unrouted_duplicate():
    """Rule 1 isolates through Secure Endpoint without asset context; rule 2 (pinned to Defender, which is
    not enabled) carries the investigated Executives context. The run notes the critical asset, so the
    routed proposal must keep that context and the package must be ELEVATED."""
    lab = _exec_lab()
    workflow = _workflow(_rule(_isolate_rule(), id="isolate_plain", asset=None),
                         _defender_isolate_rule(id="isolate_defender_with_context"))
    incident = make_incident()
    run = lab.runner.run(workflow, SAMPLE_HOOKS, incident, dry_run=True)
    assert [o.status for o in run.outcomes] == [RuleOutcomeStatus.PROPOSED, RuleOutcomeStatus.DUPLICATE]
    assert any("needs ELEVATED approval" in n for n in run.notes), "the run itself saw the critical asset"
    (action,) = _package(lab.settings, incident, run.proposals).actions
    assert action.approval_level is ApprovalLevel.ELEVATED, (
        "an unrouted duplicate's asset context was dropped: the Executives endpoint is STANDARD")
    assert action.warnings


def test_an_unrouted_rule_never_suppresses_a_routable_duplicate():
    """Rule 1 is pinned to Defender (not enabled: unrouted); rule 2 isolates the same host through Secure
    Endpoint, which is enabled. A missing product must not block a recommendation another rule can route
    and back with evidence: the routable isolation is still proposed for a human decision."""
    lab = _exec_lab(groups=("Workstations",))
    workflow = _workflow(_defender_isolate_rule(id="isolate_via_defender"),
                         _rule(_isolate_rule(), id="isolate_via_secure_endpoint"))
    incident = make_incident()
    run = lab.runner.run(workflow, SAMPLE_HOOKS, incident, dry_run=True)
    statuses = [o.status for o in run.outcomes]
    assert RuleOutcomeStatus.UNROUTED in statuses
    assert any(p.action_type is ActionType.ISOLATE_ENDPOINT and p.target == HOST for p in run.proposals), (
        f"outcomes {[(o.rule_id, o.status.value) for o in run.outcomes]}: the routable isolation was merged "
        "into the unrouted one and never proposed")
    assert lab.environment.state_changing_calls() == []


@pytest.mark.parametrize("render", [render_incident_note, render_soc_notification, render_analyst_summary])
def test_a_long_incident_title_never_pushes_the_elevated_warning_or_dry_run_notice_out(render):
    """Incident titles come from the detection (they can quote attacker-chosen strings such as an email
    subject or file name) and have no length limit. The body is capped at 16 KiB, so the ELEVATED warning
    and the DRY RUN notice must survive whatever the title length."""
    incident, package = _notification_package(critical=True, dry_run=True)
    incident = incident.model_copy(update={"title": "Suspicious attachment " + "A" * 20000})
    draft = render(LifecycleEvent(kind=LifecycleEventKind.PACKAGE_PROPOSED, at=NOW, incident=incident,
                                  package=package))
    assert draft.title.startswith("[DRY RUN] ")
    assert WARNING_PREFIX in draft.body, "the critical-asset warning was truncated out of the body"
    assert "DRY RUN: simulation only" in draft.body, "the dry-run notice was truncated out of the body"
    assert "cannot approve, execute or release anything" in draft.body


def test_a_constructed_workflow_cannot_recommend_restoration_through_the_runner(write_tripwires):
    """A definition built with ``model_construct`` (skipping the rule validator) and handed straight to the
    runner still cannot produce a restoration or read-only proposal: the builder refuses it."""
    base = _isolate_rule()
    forged = tuple(RecommendationRule.model_construct(**{**dict(base), "id": f"forged_{a.value}", "action": a,
                                                         "builder": None})
                   for a in (ActionType.RELEASE_ENDPOINT, ActionType.ENABLE_USER, ActionType.INVESTIGATE_ENDPOINT))
    workflow = SAMPLE_WORKFLOW.model_copy(update={"recommendations": forged})
    lab = _exec_lab(groups=("Workstations",))
    run = lab.runner.run(workflow, SAMPLE_HOOKS, make_incident(), dry_run=True)
    assert run.proposals == ()
    assert all(o.status is not RuleOutcomeStatus.PROPOSED for o in run.outcomes)
    assert lab.environment.state_changing_calls() == []
