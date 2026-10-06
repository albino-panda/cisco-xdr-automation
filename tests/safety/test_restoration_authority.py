"""Adversarial safety tests, round 1, lens: restoration authority.

Every test asserts the SAFE behaviour. A failing test is evidence of a real weakness in the
restoration path (architecture sections 5.8, 8, 11.1 T11/T12, 13.17).

Attack surface covered:

* restoration only for controls created by automation and recorded in the registry;
* never removing manual controls or controls that belong to a different incident;
* release without a release approval (or with a containment / foreign / expired / minted token);
* closing an incident never removes controls;
* critical-asset release needs elevated approval;
* restoration is audited and verified;
* integrity of the temporary control registry itself.

The real production stack is used wherever possible (``tools.simulator.scenario.ScenarioRun``:
real approval engine, real HMAC tokens, real guard, real runner, simulated vendors). Fake data
only, no network.
"""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from tools.simulator.scenario import LAB_PRINCIPALS, SIM_NOW, ScenarioRun, load_scenario
from xdr_response import guard
from xdr_response.errors import (
    ApprovalError,
    ApprovalRequiredError,
    ApproverNotAllowedError,
    DecisionError,
    RegistryError,
    TokenExpiredError,
    TokenMismatchError,
)
from xdr_response.integrations.simulated import FaultKind
from xdr_response.models import (
    ActionRequest,
    ActionType,
    ApprovalLevel,
    ApprovalPurpose,
    ApprovalTokenClaims,
    ApproverClaim,
    AuditEventType,
    ControlStatus,
    DecisionRequest,
    DecisionType,
    IncidentState,
    OperationKind,
    PrincipalKind,
    ReleasePackage,
    RestorationOverall,
    TargetKind,
    TemporaryControl,
    TokenActionGrant,
    VerificationStatus,
    make_idempotency_key,
)
from xdr_response.restoration import JsonlControlRegistry

S = IncidentState
ANALYST = LAB_PRINCIPALS["analyst"][0]
LEAD = LAB_PRINCIPALS["lead"][0]

RW = "XDR-RW-1047"  # ransomware scenario incident
DC = "XDR-RW-2002"  # ransomware_domain_controller scenario incident
HOST = "TH-LT-1047"
DOMAIN = "c2.ransom-ops.example"
IP = "198.51.100.23"
ENDPOINT_KEY = f"{RW}:isolate_endpoint:{HOST}"
DOMAIN_KEY = f"{RW}:block_domain:{DOMAIN}"
IP_KEY = f"{RW}:block_ip:{IP}"
DC_KEY = f"{DC}:isolate_endpoint:TH-DC-02"

# Errors a refused release may legitimately raise.
REFUSALS = (ApprovalError, RegistryError)


# ------------------------------------------------------------------ helpers --
def _run(name: str = "ransomware") -> ScenarioRun:
    return ScenarioRun(load_scenario(name), live=True)


def _contained(name: str = "ransomware", **decide_kwargs) -> ScenarioRun:
    run = _run(name)
    run.detect()
    result = run.decide(**decide_kwargs)
    assert result.incident.state in (S.CONTAINED, S.PARTIALLY_CONTAINED)
    return run


def _writes(run: ScenarioRun, operation: str | None = None, integration: str | None = None) -> list:
    return [c for c in run.environment.state_changing_calls()
            if (operation is None or c.operation == operation)
            and (integration is None or c.integration == integration)]


def _status(run: ScenarioRun, key: str) -> ControlStatus | None:
    control = run.runtime.registry.get(key)
    return control.status if control else None


def _tampered(release: ReleasePackage, package_id: str, mutate) -> ReleasePackage:
    """A release package derived from ``release`` with every action dict passed through ``mutate``."""
    data = release.model_dump(mode="python")
    data["package_id"] = package_id
    data["actions"] = [mutate(dict(a)) for a in data["actions"]]
    return ReleasePackage.model_validate(data)


def _approve_release(run: ScenarioRun, package: ReleasePackage, *approvers: str):
    request = DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL)
    return run.orchestrator.submit_release_decision(request, run.credentials(*(approvers or ("analyst",))))


def _release_token(run: ScenarioRun, package: ReleasePackage, *approvers: str):
    """A genuine release token from the real approval engine (no execution)."""
    request = DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL)
    outcome = run.runtime.approval.decide(package, request, run.credentials(*(approvers or ("analyst",))))
    assert outcome.token is not None
    return outcome.token


def _control(*, incident_id: str = RW, target: str = HOST, level: ApprovalLevel = ApprovalLevel.STANDARD,
             control_key: str | None = None) -> TemporaryControl:
    return TemporaryControl(
        control_key=control_key or make_idempotency_key(incident_id, ActionType.ISOLATE_ENDPOINT, target),
        incident_id=incident_id, action_type=ActionType.ISOLATE_ENDPOINT, target=target,
        target_kind=TargetKind.ENDPOINT, integration="secure_endpoint", workflow_id="ransomware-containment",
        workflow_version="1.0.0", package_id="pkg-test-0001", token_id="tok-test-0001",
        decision_id="dec-test-0001", approval_level=level, created_at=SIM_NOW,
        rollback_action_type=ActionType.RELEASE_ENDPOINT,
        rollback_params={"integration": "secure_endpoint", "previous_state": False},
    )


def _denials(run: ScenarioRun, incident_id: str) -> int:
    return sum(1 for r in run.runtime.audit.records(incident_id)
               if r.event_type in (AuditEventType.GUARD_DENIED, AuditEventType.APPROVAL_DENIED))


# ================================================ scope: registry-only release --
def test_release_package_contains_only_registered_controls_of_the_incident():
    run = _contained()
    other = _control(incident_id="XDR-OTHER-0001", target="TH-LT-2001")
    run.runtime.registry.register(other)
    release = run.propose_release()
    assert set(release.control_keys) == {c.control_key for c in run.runtime.registry.list(incident_id=RW)}
    assert other.control_key not in release.control_keys
    assert all(a.params["restores"] in release.control_keys for a in release.actions)


def test_planner_refuses_unregistered_manual_control_key():
    run = _contained()
    manual = f"{RW}:block_domain:manual-block.example"
    with pytest.raises(RegistryError):
        run.propose_release([manual])
    assert run.orchestrator.get_incident(RW).state is S.CONTAINED


def test_planner_refuses_control_key_of_another_incident():
    run = _contained()
    other = run.runtime.registry.register(_control(incident_id="XDR-OTHER-0001", target="TH-LT-2001"))
    with pytest.raises(RegistryError):
        run.propose_release([other.control_key])
    assert _status(run, other.control_key) is ControlStatus.ACTIVE


def test_already_contained_manual_block_is_never_registered_nor_released():
    run = _run()
    run.environment.force_desired_state(ActionType.BLOCK_DOMAIN, DOMAIN)  # a pre-existing manual block
    run.detect()
    run.decide()
    assert run.runtime.registry.get(DOMAIN_KEY) is None
    with pytest.raises(RegistryError):
        run.propose_release([DOMAIN_KEY])
    release = run.propose_release()
    assert ActionType.UNBLOCK_DOMAIN not in {a.action_type for a in release.actions}
    run.decide_release()
    assert run.environment.in_desired_state(ActionType.BLOCK_DOMAIN, DOMAIN)  # manual block kept
    assert _writes(run, "unblock_domain") == []


def test_fabricated_release_of_unregistered_target_is_refused_even_with_a_human_token():
    run = _contained()
    release = run.propose_release([ENDPOINT_KEY])
    run.environment.force_desired_state(ActionType.BLOCK_DOMAIN, "manual-block.example")
    data = release.model_dump(mode="python")
    extra = dict(data["actions"][0])
    manual_key = f"{RW}:block_domain:manual-block.example"
    extra.update(idempotency_key=f"{RW}:unblock_domain:manual-block.example", action_type=ActionType.UNBLOCK_DOMAIN,
                 target="manual-block.example", target_kind=TargetKind.DOMAIN,
                 params={"integration": "umbrella", "restores": manual_key})
    data.update(package_id="forged-release-0001", actions=[*data["actions"], extra],
                control_keys=[*data["control_keys"], manual_key])
    forged = ReleasePackage.model_validate(data)
    run.runtime.package_store.save(forged)
    try:
        _approve_release(run, forged)
    except REFUSALS:
        pass
    assert run.environment.in_desired_state(ActionType.BLOCK_DOMAIN, "manual-block.example")
    assert _writes(run, "unblock_domain") == []


def test_fabricated_release_pointing_at_another_incidents_control_is_refused():
    run = _contained()
    other = run.runtime.registry.register(_control(incident_id="XDR-OTHER-0001", target="TH-LT-2001"))
    run.environment.force_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-2001")
    release = run.propose_release([ENDPOINT_KEY])
    data = release.model_dump(mode="python")
    extra = dict(data["actions"][0])
    extra.update(idempotency_key=f"{RW}:release_endpoint:TH-LT-2001", target="TH-LT-2001",
                 params={"integration": "secure_endpoint", "restores": other.control_key})
    data.update(package_id="forged-release-0002", actions=[*data["actions"], extra],
                control_keys=[*data["control_keys"], other.control_key])
    forged = ReleasePackage.model_validate(data)
    run.runtime.package_store.save(forged)
    try:
        _approve_release(run, forged)
    except REFUSALS:
        pass
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-2001")
    assert _status(run, other.control_key) is ControlStatus.ACTIVE
    assert [c for c in _writes(run, "release_endpoint") if c.target == "TH-LT-2001"] == []


def test_release_must_use_the_rollback_params_recorded_in_the_registry():
    """A release action whose params differ from the registry's rollback_params must not run.

    Attack: the release package (built outside the planner, or altered in the package store) keeps
    the same restores key, target and rollback type but carries different vendor parameters (for
    example another Umbrella destination id, i.e. a manual block). A human approves what the card
    shows; the engine must still bind the action to what automation recorded.
    """
    run = _contained()
    run.propose_release([DOMAIN_KEY])
    original = run.orchestrator.latest_package(RW, ApprovalPurpose.RELEASE)

    def mutate(a):
        a["params"] = {**a["params"], "destination_list_id": 9001, "destination_id": "manual-dest-0042"}
        return a

    forged = _tampered(original, "forged-release-0003", mutate)
    run.runtime.package_store.save(forged)
    try:
        _approve_release(run, forged)
    except REFUSALS:
        pass
    assert _writes(run, "unblock_domain") == [], "release ran with params not recorded in the registry"
    assert _status(run, DOMAIN_KEY) is not ControlStatus.RELEASED


def test_release_must_run_on_the_integration_that_created_the_control():
    """Integration substitution: the control was created in Meraki; the release must not run elsewhere."""
    run = _contained()
    run.propose_release([IP_KEY])
    original = run.orchestrator.latest_package(RW, ApprovalPurpose.RELEASE)
    assert original.actions[0].params["integration"] == "meraki"

    def mutate(a):
        a["params"] = {**a["params"], "integration": "umbrella"}
        return a

    forged = _tampered(original, "forged-release-0004", mutate)
    run.runtime.package_store.save(forged)
    try:
        _approve_release(run, forged)
    except REFUSALS:
        pass
    assert _writes(run, "unblock_ip", integration="umbrella") == [], \
        "release was executed by an integration that never created the control"
    assert _status(run, IP_KEY) is not ControlStatus.RELEASED


def test_release_of_shared_target_does_not_silently_remove_another_incidents_containment():
    """Two incidents contain the same host. The second one got ALREADY_CONTAINED (no control of its
    own). Releasing the first incident's control silently lifts the containment the second incident's
    analyst approved. The release must at least surface the other incident (warning) or be refused."""
    run = _contained()
    second = run.scenario.incident.model_copy(update={"incident_id": "XDR-RW-1048"})
    detection = run.orchestrator.handle_detection(second)
    assert detection.package is not None
    run.orchestrator.submit_decision(
        DecisionRequest(package_id=detection.package.package_id, decision=DecisionType.APPROVE_ALL),
        run.credentials("analyst"))
    assert run.runtime.registry.list(incident_id="XDR-RW-1048") == []  # all ALREADY_CONTAINED
    try:
        release = run.orchestrator.propose_release(RW, [ENDPOINT_KEY])
    except RegistryError:
        return
    action = release.actions[0]
    surfaced = any("XDR-RW-1048" in (w.message + w.potential_impact) for w in action.warnings)
    assert surfaced, "release lifts XDR-RW-1048's approved containment of TH-LT-1047 without any warning"


# ======================================================== release needs approval --
def test_release_without_token_or_with_containment_token_is_refused():
    run = _run()
    run.detect()
    containment = run.decide()
    release = run.propose_release()
    with pytest.raises(ApprovalRequiredError):
        run.runtime.restoration.execute(release, None)
    with pytest.raises(TokenMismatchError):
        run.runtime.restoration.execute(release, containment.outcome.token)
    assert {c.status for c in run.runtime.registry.list()} == {ControlStatus.ACTIVE}
    assert _writes(run, "release_endpoint") == []


def test_release_token_of_another_release_package_is_refused():
    run = _contained()
    first = run.propose_release([ENDPOINT_KEY])
    token = _release_token(run, first)
    second = run.propose_release([DOMAIN_KEY])
    with pytest.raises(TokenMismatchError):
        run.runtime.restoration.execute(second, token)
    assert _status(run, DOMAIN_KEY) is ControlStatus.ACTIVE
    assert run.environment.in_desired_state(ActionType.BLOCK_DOMAIN, DOMAIN)


def test_expired_release_token_is_refused():
    run = _contained()
    release = run.propose_release([ENDPOINT_KEY])
    token = _release_token(run, release)
    run.advance(31)
    with pytest.raises(TokenExpiredError):
        run.runtime.restoration.execute(release, token)
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST)


@pytest.mark.parametrize("aliases", [["ai"], ["automation"], ["analyst", "ai"]])
def test_non_human_principals_cannot_approve_a_release(aliases):
    run = _contained()
    run.propose_release()
    with pytest.raises(ApproverNotAllowedError):
        run.decide_release(approvers=aliases)
    assert run.orchestrator.get_incident(RW).state is S.AWAITING_RELEASE_APPROVAL
    assert {c.status for c in run.runtime.registry.list()} == {ControlStatus.ACTIVE}
    assert _writes(run, "release_endpoint") == []


def test_release_requester_cannot_self_approve():
    run = _contained()
    package = run.orchestrator.propose_release(RW, requested_by=LEAD)
    with pytest.raises(ApproverNotAllowedError):
        _approve_release(run, package, "lead")
    assert {c.status for c in run.runtime.registry.list()} == {ControlStatus.ACTIVE}


def test_minted_release_token_without_a_recorded_human_decision_cannot_release():
    """Any component holding ``runtime.tokens`` can call the public ``sign()`` (documented as
    "performs no policy checks") and mint a release token naming a HUMAN approver that never
    decided anything. Restoration must not accept authority that no recorded decision created."""
    run = _contained()
    release = run.propose_release([ENDPOINT_KEY])
    now = run.clock.now()
    claims = ApprovalTokenClaims(
        token_id="minted-token-0001", purpose=ApprovalPurpose.RELEASE, package_id=release.package_id,
        incident_id=RW, evidence_snapshot_hash=release.evidence_snapshot_hash,
        workflow_id=release.workflow_id, workflow_version=release.workflow_version,
        decision_id="decision-that-was-never-recorded",
        actions=tuple(TokenActionGrant(idempotency_key=a.idempotency_key, action_type=a.action_type,
                                       target=a.target, params_hash=a.params_hash,
                                       approval_level=a.approval_level) for a in release.actions),
        approvers=(ApproverClaim(principal_id=LEAD, kind=PrincipalKind.HUMAN,
                                 roles=("xdr-approver", "xdr-elevated-approver")),),
        issued_at=now, expires_at=now + timedelta(minutes=10),
    )
    minted = run.runtime.tokens.sign(claims)
    try:
        run.runtime.restoration.execute(release, minted)
    except REFUSALS:
        pass
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST), \
        "a self-minted release token released the endpoint without any human decision"
    assert _status(run, ENDPOINT_KEY) is ControlStatus.ACTIVE


def test_release_token_cannot_be_replayed_after_the_target_was_contained_again():
    """Release, re-contain the same host under a new approval, then replay the old release package
    and token through the engine. The new control must not be marked RELEASED (and the host must not
    be released) on the strength of the consumed release approval."""
    run = _contained()
    run.propose_release([ENDPOINT_KEY])
    first = run.decide_release()
    assert first.report.overall is RestorationOverall.RESTORED
    old_package, old_token = run.release_package, first.outcome.token
    run.orchestrator.close(RW, actor=ANALYST, reason="resolved")
    run.orchestrator.reinvestigate(RW, actor=ANALYST, reason="re-infection observed")
    run.release_package = None
    run.decide()
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST)
    assert _status(run, ENDPOINT_KEY) is ControlStatus.ACTIVE
    writes_before = len(_writes(run, "release_endpoint"))
    try:
        run.runtime.restoration.execute(old_package, old_token)
    except REFUSALS:
        pass
    assert len(_writes(run, "release_endpoint")) == writes_before
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST)
    assert _status(run, ENDPOINT_KEY) is not ControlStatus.RELEASED, \
        "replayed release marked the new, still-enforced isolation RELEASED without any vendor call"


def test_direct_rollback_adapter_call_outside_the_guard_is_refused():
    run = _contained()
    release = run.propose_release([ENDPOINT_KEY])
    adapter = run.runtime.adapters.get("secure_endpoint")
    with pytest.raises(ApprovalRequiredError):
        adapter.release_endpoint(ActionRequest.from_recommendation(release.actions[0]))
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST)


def test_containment_token_cannot_authorize_a_rollback_in_the_guard():
    run = _run()
    run.detect()
    containment = run.decide()
    release = run.propose_release([ENDPOINT_KEY])
    request = ActionRequest.from_recommendation(release.actions[0])
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(containment.outcome.token, request):
            pass
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST)


def test_dry_run_release_never_touches_registry_or_vendor():
    run = _contained()
    run.propose_release()
    with guard.dry_run():
        result = run.decide_release()
    assert result.report.dry_run is True
    assert {c.status for c in run.runtime.registry.list()} == {ControlStatus.ACTIVE}
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST)
    assert _writes(run, "release_endpoint") == []


def test_approve_selected_release_only_releases_the_selected_controls():
    run = _contained()
    release = run.propose_release()
    key = next(a.idempotency_key for a in release.actions if a.action_type is ActionType.RELEASE_ENDPOINT)
    request = DecisionRequest(package_id=release.package_id, decision=DecisionType.APPROVE_SELECTED,
                              approved_keys=(key,))
    run.orchestrator.submit_release_decision(request, run.credentials("analyst"))
    assert _status(run, ENDPOINT_KEY) is ControlStatus.RELEASED
    assert _status(run, DOMAIN_KEY) is ControlStatus.ACTIVE and _status(run, IP_KEY) is ControlStatus.ACTIVE
    assert run.environment.in_desired_state(ActionType.BLOCK_DOMAIN, DOMAIN)
    assert run.environment.in_desired_state(ActionType.BLOCK_IP, IP)


# ============================================================ closing an incident --
def test_closing_never_removes_controls():
    run = _contained()
    writes = len(run.environment.state_changing_calls())
    closed = run.orchestrator.close(RW, actor=ANALYST, reason="handover to IT")
    assert closed.state is S.CLOSED and "remain in force" in closed.history[-1].reason
    assert {c.status for c in run.runtime.registry.list(incident_id=RW)} == {ControlStatus.ACTIVE}
    assert len(run.environment.state_changing_calls()) == writes
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST)
    run.runtime.close()  # process shutdown also never touches the registry
    assert {c.status for c in run.runtime.registry.list(incident_id=RW)} == {ControlStatus.ACTIVE}


def test_pending_release_package_cannot_be_approved_after_close():
    run = _contained()
    release = run.propose_release()
    run.orchestrator.close(RW, actor=ANALYST, reason="closed while release pending")
    with pytest.raises(DecisionError):
        _approve_release(run, release)
    assert {c.status for c in run.runtime.registry.list(incident_id=RW)} == {ControlStatus.ACTIVE}
    assert _writes(run, "release_endpoint") == []


def test_registry_exposes_no_delete_or_close_api_and_review_only_reminds():
    run = _contained()
    registry = run.runtime.registry
    for name in ("delete", "remove", "clear", "close_incident", "purge", "release_all", "expire"):
        assert not hasattr(registry, name), f"registry exposes {name}()"
    due = registry.due_for_review(SIM_NOW + timedelta(days=365))
    assert {c.status for c in due} <= {ControlStatus.ACTIVE, ControlStatus.RELEASE_FAILED}
    assert {c.status for c in registry.list(incident_id=RW)} == {ControlStatus.ACTIVE}


# ================================================ critical-asset release authority --
def test_elevated_control_release_needs_elevated_approver():
    run = _contained("ransomware_domain_controller", approvers=["lead"])
    release = run.propose_release()
    assert release.action(f"{DC}:release_endpoint:TH-DC-02").approval_level is ApprovalLevel.ELEVATED
    with pytest.raises(ApproverNotAllowedError):
        run.decide_release(approvers=["analyst"])
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-DC-02")


def test_release_approval_level_cannot_be_downgraded_below_the_registry_record():
    """The registry recorded TH-DC-02 isolation as ELEVATED. A release package that labels the
    rollback STANDARD (altered in the package store or built outside the planner) must not let a
    standard analyst release the domain controller: the engine must bind the level to the registry."""
    run = _contained("ransomware_domain_controller", approvers=["lead"])
    assert run.runtime.registry.get(DC_KEY).approval_level is ApprovalLevel.ELEVATED
    run.propose_release([DC_KEY])
    original = run.orchestrator.latest_package(DC, ApprovalPurpose.RELEASE)

    def downgrade(a):
        a.update(approval_level=ApprovalLevel.STANDARD, warnings=())
        return a

    forged = _tampered(original, "forged-release-0005", downgrade)
    run.runtime.package_store.save(forged)
    try:
        _approve_release(run, forged, "analyst")
    except REFUSALS:
        pass
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-DC-02"), \
        "a standard analyst released an ELEVATED domain-controller isolation"
    assert _status(run, DC_KEY) is not ControlStatus.RELEASED


def test_release_of_a_currently_critical_asset_requires_elevated_approval():
    """critical-assets.yaml classifies TH-DC-02 (hostname pattern *-DC-*) as a domain controller.
    A control recorded STANDARD (for example before the asset was classified) must still get an
    ELEVATED release with a warning: the planner has to apply the critical-asset policy."""
    run = _run("ransomware_domain_controller")
    control = run.runtime.registry.register(_control(incident_id=DC, target="TH-DC-02",
                                                     level=ApprovalLevel.STANDARD))
    release = run.runtime.planner.build_release_package(run.scenario.incident, [control.control_key])
    action = release.actions[0]
    assert action.approval_level is ApprovalLevel.ELEVATED, \
        "release of a configured critical asset (domain controller) is only STANDARD"
    assert action.warnings


# ===================================================== restoration audit/verify --
def test_successful_release_is_fully_audited_and_chain_verifies():
    run = _contained()
    release = run.propose_release()
    result = run.decide_release()
    records = list(run.runtime.audit.records(RW))
    results = [r for r in records if r.event_type is AuditEventType.RESTORATION_RESULT]
    assert {r.payload["control_key"] for r in results} == set(release.control_keys)
    completed = [r for r in records if r.event_type is AuditEventType.RESTORATION_COMPLETED]
    assert completed and completed[-1].payload["token_id"] == result.outcome.token.token_id
    assert set(completed[-1].payload["released"]) == set(release.control_keys)
    decisions = [r for r in records if r.event_type is AuditEventType.DECISION_RECORDED
                 and r.payload.get("purpose") == "release"]
    assert decisions and decisions[-1].payload["analyst_identity"] == ANALYST
    assert run.runtime.audit.verify().ok
    blob = "\n".join(r.model_dump_json() for r in records)
    assert result.outcome.token.signature not in blob


def test_refused_release_attempt_is_audited():
    """A release attempt with the wrong (containment) token is refused; like the containment
    executor's GUARD_DENIED, the refusal must leave a record in the audit trail."""
    run = _run()
    run.detect()
    containment = run.decide()
    release = run.propose_release()
    before = _denials(run, RW)
    with pytest.raises(ApprovalRequiredError):
        run.runtime.restoration.execute(release, containment.outcome.token)
    with pytest.raises(ApprovalRequiredError):
        run.runtime.restoration.execute(release, None)
    assert _denials(run, RW) >= before + 2, "refused release attempts left no audit record"


def test_unverified_release_keeps_control_in_force():
    run = _contained()
    run.environment.inject(FaultKind.NO_EFFECT, integration="secure_endpoint", operation="release_endpoint",
                           times=None)
    run.propose_release([ENDPOINT_KEY])
    result = run.decide_release()
    endpoint = next(r for r in result.report.results if r.action_type is ActionType.RELEASE_ENDPOINT)
    assert endpoint.verification is not None
    assert endpoint.verification.status is not VerificationStatus.VERIFIED
    assert _status(run, ENDPOINT_KEY) is ControlStatus.RELEASE_FAILED
    assert result.report.overall is not RestorationOverall.RESTORED
    assert result.incident.state is S.AWAITING_RELEASE_APPROVAL


def test_release_runner_refuses_when_audit_is_unavailable():
    run = _contained()
    release = run.propose_release([ENDPOINT_KEY])
    token = _release_token(run, release)
    audit = run.runtime.audit
    original = audit.append

    def broken(*args, **kwargs):
        raise OSError("audit disk full (test)")

    audit.append = broken  # type: ignore[method-assign]
    try:
        try:
            run.runtime.restoration.execute(release, token)
        except Exception:  # noqa: BLE001 - any refusal is acceptable
            pass
    finally:
        audit.append = original  # type: ignore[method-assign]
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST), \
        "endpoint released while nothing could be written to the audit trail"


# ======================================================== registry integrity --
def test_control_key_must_match_its_incident_action_and_target():
    """A registry entry whose control_key names another incident (or target) must be invalid, or it
    can be released under the wrong incident's approval."""
    with pytest.raises((ValueError, RegistryError)):
        _control(incident_id=RW, target=HOST, control_key=f"XDR-OTHER-0001:isolate_endpoint:{HOST}")


def test_jsonl_registry_detects_an_in_place_approval_level_downgrade(tmp_path):
    """Editing an existing event (ELEVATED -> STANDARD) would let a standard analyst release a
    critical-asset control; replay must fail closed like the audit trail does."""
    path = tmp_path / "controls.jsonl"
    registry = JsonlControlRegistry(path)
    registry.register(_control(incident_id=DC, target="TH-DC-02", level=ApprovalLevel.ELEVATED))
    line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    line["control"]["approval_level"] = "STANDARD"
    path.write_text(json.dumps(line) + "\n", encoding="utf-8")
    try:
        reopened = JsonlControlRegistry(path)
    except RegistryError:
        return
    assert reopened.get(DC_KEY).approval_level is ApprovalLevel.ELEVATED, \
        "tampered registry silently downgraded an ELEVATED control to STANDARD"


def test_jsonl_registry_rejects_reassigning_a_control_to_another_incident(tmp_path):
    path = tmp_path / "controls.jsonl"
    registry = JsonlControlRegistry(path)
    control = registry.register(_control())
    forged = {"seq": 1, "event": "RELEASE_FAILED", "control_key": control.control_key,
              "at": SIM_NOW.isoformat(),
              "control": {**control.model_dump(mode="json"), "incident_id": "XDR-OTHER-0001",
                          "status": "RELEASE_FAILED",
                          "last_error": {"code": "API_ERROR", "message": "forged"}}}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(forged) + "\n")
    try:
        reopened = JsonlControlRegistry(path)
    except RegistryError:
        return
    assert reopened.get(control.control_key).incident_id == RW, \
        "registry replay moved a control to another incident (identity fields changed between events)"


def test_sqlite_registry_is_append_only(tmp_path):
    from xdr_response.restoration import SqliteControlRegistry

    with SqliteControlRegistry(tmp_path / "controls.db") as registry:
        registry.register(_control())
        import sqlite3

        with pytest.raises(sqlite3.DatabaseError):
            registry._conn.execute("DELETE FROM control_events")
        with pytest.raises(sqlite3.DatabaseError):
            registry._conn.execute("UPDATE control_events SET incident_id = 'x'")
        assert registry.get(ENDPOINT_KEY).status is ControlStatus.ACTIVE


def test_released_control_cannot_be_released_again_by_a_second_run():
    run = _contained()
    run.propose_release([ENDPOINT_KEY])
    first = run.decide_release()
    assert _status(run, ENDPOINT_KEY) is ControlStatus.RELEASED
    writes = len(_writes(run, "release_endpoint"))
    with pytest.raises(REFUSALS):
        run.propose_release([ENDPOINT_KEY])
    try:
        run.runtime.restoration.execute(run.release_package, first.outcome.token)
    except REFUSALS:
        pass
    assert len(_writes(run, "release_endpoint")) == writes


def test_operation_kind_is_state_changing_for_releases():
    """Sanity: rollbacks are recorded as STATE_CHANGING calls (so the checks above are meaningful)."""
    run = _contained()
    run.propose_release([ENDPOINT_KEY])
    run.decide_release()
    calls = _writes(run, "release_endpoint")
    assert calls and all(c.kind is OperationKind.STATE_CHANGING for c in calls)


# =============================================================================
# Round 2 (adversarial, lens: restoration authority). Each test asserts the SAFE behaviour.
# =============================================================================
from pydantic import SecretStr  # noqa: E402

from tools.simulator.scenario import simulation_settings  # noqa: E402
from xdr_response.config import Settings  # noqa: E402
from xdr_response.models import ApproverCredential, Asset, ContainmentPackage  # noqa: E402

MANUAL_DOMAIN = "manual-block.example"


def _fields(model) -> dict:
    """Field values of a pydantic model (``dict(model)`` is shadowed by a ``keys`` property)."""
    return {name: getattr(model, name) for name in type(model).model_fields}
MANUAL_DOMAIN_KEY = f"{RW}:block_domain:{MANUAL_DOMAIN}"


def _forged_registry_entry(run: ScenarioRun, provenance: str) -> TemporaryControl:
    """A registry entry for a block that an administrator created by hand (not by automation).

    ``provenance="fake"`` uses invented package / token / decision ids; ``"borrowed"`` copies the
    ids of a genuine control of the same incident (a real approval that never covered this target).
    """
    genuine = run.runtime.registry.get(DOMAIN_KEY)
    data = genuine.model_dump(mode="python")
    data.update(control_key=MANUAL_DOMAIN_KEY, target=MANUAL_DOMAIN, external_ref=None,
                review_due_at=None)
    if provenance == "fake":
        data.update(package_id="pkg-forged-0001", token_id="tok-forged-0001", decision_id="dec-forged-0001")
    return TemporaryControl.model_validate(data)


@pytest.mark.parametrize("provenance", ["fake", "borrowed"])
def test_r2_registry_entry_without_automation_provenance_cannot_release_a_manual_block(provenance):
    """``registry.register`` accepts any well-formed TemporaryControl. An entry for a manual block
    (no containment decision, package or token ever covered this target) must not become releasable:
    the planner / engine must tie every control to the approved containment action that created it
    (package actions, token grant, SUCCESS execution), or the release removes a manual control
    while the decision card claims it was "created by automation"."""
    run = _contained()
    run.environment.force_desired_state(ActionType.BLOCK_DOMAIN, MANUAL_DOMAIN)  # manual admin block
    try:
        run.runtime.registry.register(_forged_registry_entry(run, provenance))
    except REFUSALS:
        return
    try:
        release = run.propose_release()
        if MANUAL_DOMAIN_KEY not in release.control_keys:
            return
        run.decide_release()
    except REFUSALS:
        pass
    assert run.environment.in_desired_state(ActionType.BLOCK_DOMAIN, MANUAL_DOMAIN), \
        f"a manual block with {provenance} provenance was released as if automation had created it"
    assert [c for c in _writes(run, "unblock_domain") if c.target == MANUAL_DOMAIN] == []


def _shared_target_release(run: ScenarioRun) -> ReleasePackage:
    second = run.scenario.incident.model_copy(update={"incident_id": "XDR-RW-1048"})
    detection = run.orchestrator.handle_detection(second)
    run.orchestrator.submit_decision(
        DecisionRequest(package_id=detection.package.package_id, decision=DecisionType.APPROVE_ALL),
        run.credentials("analyst"))
    return run.orchestrator.propose_release(RW, [ENDPOINT_KEY])


def test_r2_engine_reapplies_dependent_incident_elevation():
    """The planner elevates a release that also lifts another incident's approved containment, but
    ``required_release_level`` (the rule the engine re-applies) ignores dependent incidents. A
    release package relabelled STANDARD without the warning must not let a standard analyst lift
    XDR-RW-1048's containment of TH-LT-1047."""
    run = _contained()
    original = _shared_target_release(run)
    assert original.actions[0].approval_level is ApprovalLevel.ELEVATED  # planner is right

    def downgrade(a):
        a.update(approval_level=ApprovalLevel.STANDARD, warnings=())
        return a

    forged = _tampered(original, "forged-release-r2-0001", downgrade)
    run.runtime.package_store.save(forged)
    try:
        _approve_release(run, forged, "analyst")
    except REFUSALS:
        pass
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST), \
        "a STANDARD-labelled release lifted another incident's containment (dependent elevation not re-checked)"
    assert _status(run, ENDPOINT_KEY) is not ControlStatus.RELEASED


def test_r2_rejected_release_package_cannot_be_approved_and_executed_later():
    """An analyst REJECTs the release (controls stay in force). The same package must never be
    executed afterwards: neither the approval engine nor the restoration engine may accept a later
    approval of a package whose recorded decision is REJECT (analyst override)."""
    run = _contained()
    release = run.propose_release([ENDPOINT_KEY])
    rejected = run.orchestrator.submit_release_decision(
        DecisionRequest(package_id=release.package_id, decision=DecisionType.REJECT,
                        comment="user still reports encryption activity"),
        run.credentials("analyst"))
    assert rejected.incident.state is S.REMEDIATION_REQUIRED
    try:
        outcome = run.runtime.approval.decide(
            release, DecisionRequest(package_id=release.package_id, decision=DecisionType.APPROVE_ALL),
            run.credentials("lead"))
        run.runtime.restoration.execute(release, outcome.token)
    except REFUSALS:
        pass
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST), \
        "a release package the analyst rejected was approved again and executed"
    assert _status(run, ENDPOINT_KEY) is ControlStatus.ACTIVE


def test_r2_closing_voids_an_unexecuted_release_approval():
    """Closing never removes controls. A release approval that was issued but not executed before
    the incident was closed must not remove controls of the CLOSED incident afterwards (the
    restoration engine does not look at the incident lifecycle at all)."""
    run = _contained()
    release = run.propose_release([ENDPOINT_KEY])
    token = _release_token(run, release)
    run.orchestrator.close(RW, actor=ANALYST, reason="closed; release deferred to IT")
    try:
        run.runtime.restoration.execute(release, token)
    except REFUSALS:
        pass
    assert run.orchestrator.get_incident(RW).state is S.CLOSED
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST), \
        "controls of a CLOSED incident were removed by a release approval issued before closing"
    assert _status(run, ENDPOINT_KEY) is ControlStatus.ACTIVE


def test_r2_selective_release_does_not_report_restored_while_controls_remain_in_force():
    """Section 8.2 step 4: RESTORED only when everything is released; otherwise the incident
    returns to AWAITING_RELEASE_APPROVAL. compute_overall only looks at the approved subset."""
    run = _contained()
    release = run.propose_release()
    key = next(a.idempotency_key for a in release.actions if a.action_type is ActionType.RELEASE_ENDPOINT)
    result = run.orchestrator.submit_release_decision(
        DecisionRequest(package_id=release.package_id, decision=DecisionType.APPROVE_SELECTED,
                        approved_keys=(key,)), run.credentials("analyst"))
    still = {c.control_key for c in run.runtime.planner.outstanding(RW)}
    assert still == set(release.control_keys) - {ENDPOINT_KEY} and {DOMAIN_KEY, IP_KEY} <= still
    assert result.incident.state is not S.RESTORED, \
        f"incident reported RESTORED while {len(still)} temporary controls of the release package remain in force"


def test_r2_release_of_asset_critical_by_group_or_tag_requires_elevated_approval():
    """critical-assets.yaml classifies hosts by group/tag too (``Domain Controllers``,
    ``domain-controller``). The planner evaluates the policy at release time with the bare target
    only (no asset context from ``incident.assets``), so a domain controller with a non-DC hostname
    and a STANDARD registry record gets a STANDARD release."""
    run = _run("ransomware_domain_controller")
    host = run.target(ActionType.ISOLATE_ENDPOINT, "SRV-AUTH-07")
    asset = Asset(name=host, kind=TargetKind.ENDPOINT, groups=("Domain Controllers",), tags=("domain-controller",))
    incident = run.scenario.incident.model_copy(update={"assets": (*run.scenario.incident.assets, asset)})
    control = run.runtime.registry.register(_control(incident_id=DC, target=host, level=ApprovalLevel.STANDARD))
    release = run.runtime.planner.build_release_package(incident, [control.control_key])
    assert release.actions[0].approval_level is ApprovalLevel.ELEVATED, \
        "release of a domain controller classified by group/tag is only STANDARD"


def test_r2_rollback_smuggled_into_a_containment_package_cannot_release():
    """A ContainmentPackage built with ``model_construct`` (validators skipped) carrying a
    release_endpoint action gets a *containment* token; the guard derives the purpose from the
    catalog, so the rollback must still be refused."""
    run = _contained()
    rollback = run.propose_release([ENDPOINT_KEY]).actions[0]
    containment = run.orchestrator.latest_package(RW)
    run.orchestrator.mark_remediation_required(RW, actor=ANALYST, reason="re-scope")
    forged = ContainmentPackage.model_construct(
        **{**_fields(containment), "package_id": "forged-containment-r2-0001", "actions": (rollback,),
           "expires_at": run.clock.now() + timedelta(minutes=30), "created_at": run.clock.now()})
    try:
        run.orchestrator.propose(RW, forged)
        run.orchestrator.submit_decision(
            DecisionRequest(package_id=forged.package_id, decision=DecisionType.APPROVE_ALL),
            run.credentials("lead"))
    except (*REFUSALS, ValueError, TypeError):
        pass
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST)
    assert _writes(run, "release_endpoint") == []
    assert _status(run, ENDPOINT_KEY) is ControlStatus.ACTIVE


def _two_elevated_quorum_run() -> tuple[ScenarioRun, list[ApproverCredential]]:
    scenario = load_scenario("ransomware_domain_controller")
    data = simulation_settings(dry_run=False, suite=scenario.suite).model_dump()
    data["thresholds"]["approval"]["elevated_min_approvers"] = 2
    run = ScenarioRun(scenario, live=True, settings=Settings.model_validate(data))
    run.authenticator.add_principal("lead.three@example.com", display_name="Lead3", kind=PrincipalKind.HUMAN,
                                    roles=frozenset({"xdr-approver", "xdr-elevated-approver"}),
                                    secret="lab-only-secret-lead-three")
    third = ApproverCredential(principal_id="lead.three@example.com", scheme="static",
                               secret=SecretStr("lab-only-secret-lead-three"))
    return run, [*run.credentials("lead"), third]


def test_r2_configured_elevated_quorum_applies_to_critical_asset_release():
    run, both = _two_elevated_quorum_run()
    run.detect()
    package = run.orchestrator.latest_package(DC)
    run.orchestrator.submit_decision(
        DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL), both)
    assert run.runtime.registry.get(DC_KEY).status is ControlStatus.ACTIVE
    release = run.propose_release([DC_KEY])
    with pytest.raises(ApproverNotAllowedError):
        _approve_release(run, release, "lead")  # one elevated approver, quorum is two
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-DC-02")
    run.orchestrator.submit_release_decision(
        DecisionRequest(package_id=release.package_id, decision=DecisionType.APPROVE_ALL), both)
    assert run.runtime.registry.get(DC_KEY).status is ControlStatus.RELEASED


def test_r2_rejected_release_is_audited_and_keeps_every_control():
    run = _contained()
    release = run.propose_release()
    writes = len(run.environment.state_changing_calls())
    result = run.orchestrator.submit_release_decision(
        DecisionRequest(package_id=release.package_id, decision=DecisionType.REJECT, comment="not yet"),
        run.credentials("analyst"))
    assert result.outcome.token is None and result.incident.state is S.REMEDIATION_REQUIRED
    assert {c.status for c in run.runtime.registry.list(incident_id=RW)} == {ControlStatus.ACTIVE}
    assert len(run.environment.state_changing_calls()) == writes
    decisions = [r for r in run.runtime.audit.records(RW) if r.event_type is AuditEventType.DECISION_RECORDED
                 and r.payload.get("purpose") == "release"]
    assert decisions and decisions[-1].payload["decision"] == "REJECT"
    assert decisions[-1].payload["analyst_identity"] == ANALYST
    assert run.runtime.audit.verify().ok


def test_r2_control_stuck_in_release_pending_is_still_reported_when_closing():
    """The engine marks RELEASE_PENDING before calling the vendor. If the process dies in that
    window the control may still be in force, yet ``outstanding()`` (close note) and
    ``due_for_review()`` only look at ACTIVE / RELEASE_FAILED, and the planner refuses it: the
    control silently disappears from every view while possibly still isolating the host."""
    run = _contained()
    run.runtime.registry.mark_release_pending(ENDPOINT_KEY, release_package_id="pkg-crashed-r2",
                                              token_id="tok-crashed-r2")  # what the engine does first
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, HOST)  # vendor never called
    closed = run.orchestrator.close(RW, actor=ANALYST, reason="handover")
    visible = (ENDPOINT_KEY in closed.history[-1].reason
               or any(c.control_key == ENDPOINT_KEY
                      for c in run.runtime.registry.due_for_review(SIM_NOW + timedelta(days=365))))
    assert visible, "a control still in force (RELEASE_PENDING after a crash) is invisible on close and review"


def test_r2_release_token_cannot_authorize_a_different_control_in_the_guard():
    run = _contained()
    endpoint_release = run.propose_release([ENDPOINT_KEY])
    token = _release_token(run, endpoint_release)
    domain_release = run.propose_release([DOMAIN_KEY])
    request = ActionRequest.from_recommendation(domain_release.actions[0])
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(token, request):
            pass
    assert run.environment.in_desired_state(ActionType.BLOCK_DOMAIN, DOMAIN)


def test_r2_release_engine_with_mismatched_control_keys_releases_only_approved_and_audits_truth():
    """``ReleasePackage.model_construct`` skips the control_keys/restores validator. The engine must
    still only release what the approved actions name, and the audit must report what really
    happened (not the forged control_keys list)."""
    run = _contained()
    real = run.propose_release([ENDPOINT_KEY])
    token = _release_token(run, real)
    forged = ReleasePackage.model_construct(**{**_fields(real), "control_keys": (DOMAIN_KEY,)})
    try:
        run.runtime.restoration.execute(forged, token)
    except REFUSALS:
        pass
    assert _status(run, DOMAIN_KEY) is ControlStatus.ACTIVE
    assert run.environment.in_desired_state(ActionType.BLOCK_DOMAIN, DOMAIN)
    completed = [r for r in run.runtime.audit.records(RW) if r.event_type is AuditEventType.RESTORATION_COMPLETED]
    if completed and _status(run, ENDPOINT_KEY) is ControlStatus.RELEASED:
        assert ENDPOINT_KEY in completed[-1].payload["released"], \
            "audit RESTORATION_COMPLETED omits the control that was actually released"
