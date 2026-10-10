"""End-to-end lifecycle against the simulated vendor environment (real engines, no network).

Each test plays a fixture incident from ``tests/fixtures/incidents`` through
``xdr_response.lifecycle``: automatic investigation and recommendation, human approval (HMAC tokens
for authenticated HUMAN lab principals), automatic execution and verification, and the separate
release approval and automatic restoration.

The simulated adapters do exactly what the real ones support and verify (architecture 14.14.3): the
Secure Endpoint isolation and release cannot be read back (UNABLE_TO_VERIFY), so a run that isolates
an endpoint is PARTIALLY_CONTAINED and its release keeps the control RELEASE_FAILED until a human
verifies it; a hash block has no enabled executor in the default lab and is reported, never executed.
The fully verified happy path is played with the account-takeover and phishing incidents (Entra,
Meraki, Secure Email and Umbrella read their writes back).
"""
from __future__ import annotations

import pytest

from tools.simulator.scenario import LAB_PRINCIPALS, ScenarioRun, load_scenario
from xdr_response import guard
from xdr_response.errors import (
    ApprovalRequiredError,
    ApproverNotAllowedError,
    DecisionError,
    InvalidTransitionError,
)
from xdr_response.integrations.simulated import FaultKind
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    AuditEventType,
    ContainmentOverall,
    ControlStatus,
    DecisionRequest,
    DecisionType,
    IncidentState,
    RestorationOverall,
    SkipReason,
    VerificationStatus,
)

S = IncidentState


def _run(name: str, *, live: bool = True) -> ScenarioRun:
    return ScenarioRun(load_scenario(name), live=live)


def _states(run: ScenarioRun) -> list[IncidentState]:
    incident = run.orchestrator.get_incident(run.incident_id)
    return [t.to_state for t in incident.history]


def _events(run: ScenarioRun) -> list[AuditEventType]:
    return [r.event_type for r in run.runtime.audit.records(run.incident_id)]


def _result(report, action: ActionType):
    return next(r for r in report.results if r.action_type is action)


# --------------------------------------------------------------- approve all --
RANSOMWARE_ACTIONS = {"isolate_endpoint:TH-LT-1047", "block_domain:c2.ransom-ops.example", "block_ip:198.51.100.23"}
RANSOMWARE_HASH = "5c1d7e0b9a8f6e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d"


def test_ransomware_full_approve_all_lifecycle():
    """Production outcome: the hash block is reported (no executor), the isolation cannot be read back."""
    run = _run("ransomware")
    detection = run.detect()
    package = detection.package
    assert detection.incident.state is S.AWAITING_APPROVAL
    assert set(package.keys) == set(run.keys(package, RANSOMWARE_ACTIONS))
    assert any("block_hash" in n and RANSOMWARE_HASH in n for n in detection.notes)  # shown, never dropped
    assert all(a.evidence and a.risk_score and a.confidence_score for a in package.actions)
    assert run.environment.state_changing_calls() == []  # nothing executed before the human decision

    decision = run.decide()
    assert decision.outcome.token is not None and decision.outcome.decision.analyst_identity == \
        LAB_PRINCIPALS["analyst"][0]
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    assert decision.incident.state is S.PARTIALLY_CONTAINED
    assert all(r.status is ActionResultStatus.SUCCESS for r in decision.report.results)
    isolation = _result(decision.report, ActionType.ISOLATE_ENDPOINT)
    assert isolation.verification.status is VerificationStatus.UNABLE_TO_VERIFY and isolation.requires_attention
    assert all(r.verification.status is VerificationStatus.VERIFIED for r in decision.report.results
               if r.action_type is not ActionType.ISOLATE_ENDPOINT)
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert len(controls) == 3 and {c.status for c in controls} == {ControlStatus.ACTIVE}

    release = run.propose_release()
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_RELEASE_APPROVAL
    assert {a.action_type for a in release.actions} == {ActionType.RELEASE_ENDPOINT, ActionType.UNBLOCK_DOMAIN,
                                                        ActionType.UNBLOCK_IP}
    restored = run.decide_release()
    assert restored.report.overall is RestorationOverall.PARTIALLY_RESTORED
    assert restored.incident.state is S.AWAITING_RELEASE_APPROVAL  # a human verifies the release first
    assert not run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")
    statuses = {c.action_type: c.status for c in run.runtime.registry.list(incident_id=run.incident_id)}
    assert statuses == {ActionType.ISOLATE_ENDPOINT: ControlStatus.RELEASE_FAILED,
                        ActionType.BLOCK_DOMAIN: ControlStatus.RELEASED, ActionType.BLOCK_IP: ControlStatus.RELEASED}
    assert _states(run) == [S.AWAITING_APPROVAL, S.APPROVED, S.CONTAINMENT_RUNNING, S.PARTIALLY_CONTAINED,
                            S.AWAITING_RELEASE_APPROVAL, S.RESTORATION_RUNNING, S.AWAITING_RELEASE_APPROVAL]
    approved = [t for t in run.orchestrator.get_incident(run.incident_id).history
                if t.to_state in (S.APPROVED, S.RESTORATION_RUNNING)]
    assert all(t.token_id and t.actor == LAB_PRINCIPALS["analyst"][0] for t in approved)


def test_verified_full_lifecycle_contains_restores_and_closes():
    """Every routed action of the account-takeover incident is read back: CONTAINED, RESTORED, CLOSED."""
    run = _run("account_takeover")
    package = run.detect().package
    assert run.environment.state_changing_calls() == []
    decision = run.decide()
    assert decision.report.overall is ContainmentOverall.CONTAINED and decision.incident.state is S.CONTAINED
    assert all(r.verification.status is VerificationStatus.VERIFIED for r in decision.report.results)
    assert len(package.actions) == 3
    release = run.propose_release()
    assert {a.action_type for a in release.actions} == {ActionType.ENABLE_USER}
    restored = run.decide_release()
    assert restored.report.overall is RestorationOverall.RESTORED and restored.incident.state is S.RESTORED
    assert {c.status for c in run.runtime.registry.list(incident_id=run.incident_id)} == {ControlStatus.RELEASED}
    closed = run.orchestrator.close(run.incident_id, actor=LAB_PRINCIPALS["analyst"][0], reason="resolved")
    assert closed.state is S.CLOSED
    assert _states(run) == [S.AWAITING_APPROVAL, S.APPROVED, S.CONTAINMENT_RUNNING, S.CONTAINED,
                            S.AWAITING_RELEASE_APPROVAL, S.RESTORATION_RUNNING, S.RESTORED, S.CLOSED]


def test_every_lifecycle_step_is_audited_in_order_and_the_chain_verifies():
    run = _run("ransomware")
    run.detect()
    run.decide()
    run.propose_release()
    run.decide_release()
    events = _events(run)
    order = [AuditEventType.INCIDENT_RECEIVED, AuditEventType.ENRICHMENT_RESULT,
             AuditEventType.INVESTIGATION_COMPLETED, AuditEventType.PACKAGE_PROPOSED,
             AuditEventType.DECISION_RECORDED, AuditEventType.TOKEN_ISSUED, AuditEventType.ACTION_STARTED,
             AuditEventType.CONTROL_REGISTERED, AuditEventType.ACTION_RESULT, AuditEventType.VERIFICATION_RESULT,
             AuditEventType.CONTAINMENT_COMPLETED, AuditEventType.RELEASE_PACKAGE_PROPOSED,
             AuditEventType.RESTORATION_RESULT, AuditEventType.RESTORATION_COMPLETED]
    positions = [events.index(e) for e in order]
    assert positions == sorted(positions)
    assert AuditEventType.STATE_TRANSITION in events and AuditEventType.API_CALL in events
    assert run.runtime.audit.verify().ok
    summary = run.orchestrator.audit_summary(run.incident_id)
    assert summary.analyst_identity == LAB_PRINCIPALS["analyst"][0]
    assert len(summary.approved_actions) == len(RANSOMWARE_ACTIONS)
    assert summary.containment_results and summary.restoration_results


def test_audit_never_contains_credentials_or_token_signatures():
    run = _run("account_takeover")
    run.detect()
    decision = run.decide()
    blob = "\n".join(r.model_dump_json() for r in run.runtime.audit.records())
    assert decision.outcome.token.signature not in blob
    assert decision.outcome.token.encode() not in blob
    for alias in LAB_PRINCIPALS:
        assert run._secrets[alias] not in blob
    assert run.runtime.secrets.get("APPROVAL_SIGNING_KEY").reveal() not in blob


# ----------------------------------------------------------- approve selected --
def test_phishing_approve_selected_skips_rejected_actions():
    run = _run("phishing")
    run.detect()
    decision = run.decide()
    report = decision.report
    disable = _result(report, ActionType.DISABLE_USER)
    assert disable.status is ActionResultStatus.SKIPPED and disable.skip_reason is SkipReason.REJECTED_BY_ANALYST
    assert decision.outcome.decision.rejected_action_keys == run.keys(run.detection.package,
                                                                       run.scenario.expect["rejected"])
    assert report.overall is ContainmentOverall.CONTAINED  # rejected actions do not count
    assert not run.environment.in_desired_state(ActionType.DISABLE_USER, "jsmith@example.com")
    assert run.environment.in_desired_state(ActionType.QUARANTINE_EMAIL,
                                            "<20260115.7781@mail.contoso-payroll.example>")
    assert len(run.runtime.registry.list(incident_id=run.incident_id)) == 3  # revoke_sessions is irreversible
    assert decision.outcome.token.claims.grant(disable.idempotency_key) is None


# -------------------------------------------------------------------- reject --
def test_reject_closes_the_incident_without_any_state_change():
    run = _run("ransomware")
    run.detect()
    decision = run.decide({"decision": "REJECT", "comment": "false positive: authorised encryption test"})
    assert decision.outcome.token is None and decision.report is None
    assert decision.incident.state is S.CLOSED
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    assert AuditEventType.TOKEN_ISSUED not in _events(run)


def test_request_more_investigation_returns_to_not_started_and_reproposes():
    run = _run("ransomware")
    first = run.detect().package
    decision = run.decide({"decision": "REQUEST_MORE_INVESTIGATION", "comment": "check the backup server too"})
    assert decision.incident.state is S.NOT_STARTED and decision.outcome.token is None
    assert run.environment.state_changing_calls() == []
    with pytest.raises(DecisionError):  # the old package can no longer be decided
        run.orchestrator.submit_decision(DecisionRequest(package_id=first.package_id,
                                                         decision=DecisionType.APPROVE_ALL),
                                         run.credentials("analyst"))
    again = run.orchestrator.investigate_and_propose(run.incident_id)
    assert again.incident.state is S.AWAITING_APPROVAL and again.package.package_id != first.package_id
    assert run.decide().incident.state is S.PARTIALLY_CONTAINED  # the isolation cannot be read back


# ----------------------------------------------------------- partial failure --
def test_partial_failure_gives_partially_contained_and_other_actions_still_run():
    run = _run("ransomware")
    run.environment.inject(FaultKind.UNAVAILABLE, integration="umbrella", operation="block_domain", times=None)
    run.detect()
    decision = run.decide()
    report = decision.report
    failed = _result(report, ActionType.BLOCK_DOMAIN)
    assert failed.status is ActionResultStatus.FAILED and failed.requires_attention
    assert report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    assert decision.incident.state is S.PARTIALLY_CONTAINED
    assert sum(r.status is ActionResultStatus.SUCCESS for r in report.results) == 2
    assert any("block_domain" in line for line in report.attention)
    # transient failure: the recommendation is a new package for a new human approval, never a silent retry
    assert decision.recommended_next_state is S.AWAITING_APPROVAL
    run.environment.clear_faults()
    retry = run.orchestrator.propose_retry(run.incident_id)
    assert [a.action_type for a in retry.actions] == [ActionType.BLOCK_DOMAIN]
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL
    second = run.decide()
    assert second.report.overall is ContainmentOverall.CONTAINED  # the retried block is read back
    assert len(run.runtime.registry.list(incident_id=run.incident_id)) == 3


def test_control_not_in_effect_requires_remediation():
    run = _run("account_takeover")
    run.environment.inject(FaultKind.NO_EFFECT, integration="entra", operation="disable_user")
    run.detect()
    decision = run.decide()
    disable = _result(decision.report, ActionType.DISABLE_USER)
    assert disable.verification.status is VerificationStatus.NOT_VERIFIED
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    assert decision.incident.state is S.REMEDIATION_REQUIRED
    assert _states(run)[-2:] == [S.PARTIALLY_CONTAINED, S.REMEDIATION_REQUIRED]


def test_all_actions_failing_gives_containment_failed():
    run = _run("ransomware")
    run.detect()
    run.environment.inject(FaultKind.AUTH_FAIL, times=None)  # every vendor call is refused from now on
    decision = run.decide()
    assert all(r.status is ActionResultStatus.FAILED for r in decision.report.results)
    assert {r.error.code.value for r in decision.report.results} == {"AUTH_FAILED"}
    assert decision.report.overall is ContainmentOverall.CONTAINMENT_FAILED
    assert decision.incident.state is S.REMEDIATION_REQUIRED  # auth failures need a human
    assert run.runtime.registry.list() == []


# -------------------------------------------------------------- idempotency --
def test_already_contained_target_reports_already_contained_and_creates_no_control():
    run = _run("account_takeover")
    run.detect()
    decision = run.decide()
    block = _result(decision.report, ActionType.BLOCK_IP)
    assert block.status is ActionResultStatus.ALREADY_CONTAINED and not block.control_registered
    assert decision.report.overall is ContainmentOverall.CONTAINED
    keys = [c.control_key for c in run.runtime.registry.list(incident_id=run.incident_id)]
    assert keys == [f"{run.incident_id}:disable_user:jsmith@example.com"]
    writes = [c for c in run.environment.state_changing_calls() if c.operation == "block_ip"]
    assert writes == []  # the read-only pre-check avoided the vendor write


def test_an_approved_package_never_executes_twice():
    run = _run("ransomware")
    package = run.detect().package
    decision = run.decide()
    calls = len(run.environment.state_changing_calls())
    with pytest.raises(DecisionError):
        run.orchestrator.submit_decision(DecisionRequest(package_id=package.package_id,
                                                         decision=DecisionType.APPROVE_ALL),
                                         run.credentials("analyst"))
    replay = run.runtime.executor.execute(package, decision.outcome.token)  # direct replay of the token
    assert all(r.status is not ActionResultStatus.SUCCESS or "replayed" in r.message for r in replay.results)
    assert len(run.environment.state_changing_calls()) == calls


# ------------------------------------------------------------ elevated (DC) --
def test_domain_controller_needs_elevated_approval_and_is_never_silently_blocked():
    run = _run("ransomware_domain_controller")
    package = run.detect().package
    dc = package.action(f"{run.incident_id}:isolate_endpoint:TH-DC-02")
    assert dc.approval_level.value == "ELEVATED"
    assert dc.warnings and dc.warnings[0].asset_class.value == "domain_controller"
    assert "Active Directory domain controller" in dc.warnings[0].role
    assert [e.target for e in package.excluded_targets] == ["TH-DC-01"]

    with pytest.raises(ApproverNotAllowedError):
        run.decide(approvers=["analyst"])
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL
    assert AuditEventType.APPROVAL_DENIED in _events(run)
    assert run.environment.state_changing_calls() == []

    decision = run.decide(approvers=["lead"])
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED  # isolation is not read back
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-DC-02")
    assert not run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-DC-01")

    release = run.propose_release()
    assert any(a.approval_level.value == "ELEVATED" for a in release.actions)
    with pytest.raises(ApproverNotAllowedError):
        run.decide_release(approvers=["analyst"])
    released = run.decide_release(approvers=["lead"])
    assert not run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-DC-02")
    # neither release can be read back: the controls stay for a human to verify
    assert released.incident.state is S.AWAITING_RELEASE_APPROVAL
    assert {c.status for c in run.runtime.registry.list(incident_id=run.incident_id)} == {ControlStatus.RELEASE_FAILED}


def test_analyst_may_approve_only_the_standard_action_selected():
    run = _run("ransomware_domain_controller")
    run.detect()
    decision = run.decide({"decision": "APPROVE_SELECTED", "select": ["isolate_endpoint:TH-LT-1047"]},
                          approvers=["analyst"])
    assert decision.incident.state is S.PARTIALLY_CONTAINED  # executed, not read back
    assert run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")
    assert not run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-DC-02")


@pytest.mark.parametrize("alias", ["automation", "ai"])
def test_non_human_principals_can_never_approve(alias):
    run = _run("ransomware")
    run.detect()
    with pytest.raises(ApproverNotAllowedError):
        run.decide(approvers=[alias])
    with pytest.raises(ApproverNotAllowedError):
        run.decide(approvers=["analyst", alias])
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL
    assert run.environment.state_changing_calls() == []


# ------------------------------------------------------ release / restoration --
def test_release_needs_a_separate_release_approval():
    run = _run("ransomware")
    run.detect()
    containment = run.decide()
    release = run.propose_release()
    with pytest.raises(ApprovalRequiredError):  # the containment token can never release
        run.runtime.restoration.execute(release, containment.outcome.token)
    assert {c.status for c in run.runtime.registry.list()} == {ControlStatus.ACTIVE}
    with pytest.raises(ApprovalRequiredError):
        run.runtime.restoration.execute(release, None)


def test_rejected_release_keeps_controls_active_and_requires_remediation():
    run = _run("phishing")
    run.detect()
    run.decide()
    run.propose_release()
    rejected = run.decide_release({"decision": "REJECT", "comment": "campaign still active"})
    assert rejected.incident.state is S.REMEDIATION_REQUIRED and rejected.report is None
    assert {c.status for c in run.runtime.registry.list()} == {ControlStatus.ACTIVE}
    closed = run.orchestrator.close(run.incident_id, actor=LAB_PRINCIPALS["analyst"][0], reason="handed over")
    assert closed.state is S.CLOSED and "remain in force" in closed.history[-1].reason
    assert {c.status for c in run.runtime.registry.list()} == {ControlStatus.ACTIVE}  # closing never releases
    package = run.propose_release()  # a closed incident can still release its controls later
    assert run.decide_release().incident.state is S.RESTORED
    assert package.purpose.value == "release"


def test_partial_release_then_second_approval_restores_the_rest():
    run = _run("phishing")
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    domain_key = next(c.control_key for c in controls if c.action_type is ActionType.BLOCK_DOMAIN)
    run.propose_release([domain_key])
    first = run.decide_release()
    assert first.report.overall is RestorationOverall.RESTORED and first.incident.state is S.RESTORED
    assert len(run.orchestrator.outstanding_controls(run.incident_id)) == 2
    run.release_package = None
    run.propose_release()
    assert run.decide_release().incident.state is S.RESTORED
    assert run.orchestrator.outstanding_controls(run.incident_id) == []


def test_an_unverifiable_release_keeps_the_control_for_a_human():
    """Secure Endpoint cannot read a release back: the control is RELEASE_FAILED (still listed), never RELEASED."""
    run = _run("ransomware")
    run.detect()
    run.decide()
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    endpoint_key = next(c.control_key for c in controls if c.action_type is ActionType.ISOLATE_ENDPOINT)
    run.propose_release([endpoint_key])
    result = run.decide_release()
    assert result.report.overall is not RestorationOverall.RESTORED
    assert result.incident.state is S.AWAITING_RELEASE_APPROVAL
    assert not run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")  # it did run
    statuses = {c.action_type: c.status for c in run.runtime.registry.list(incident_id=run.incident_id)}
    assert statuses[ActionType.ISOLATE_ENDPOINT] is ControlStatus.RELEASE_FAILED
    assert endpoint_key in {c.control_key for c in run.orchestrator.outstanding_controls(run.incident_id)}


def test_failed_release_goes_back_to_awaiting_release_approval():
    run = _run("phishing")
    run.detect()
    run.decide()
    run.environment.inject(FaultKind.UNAVAILABLE, integration="umbrella", operation="unblock_domain", times=None)
    run.propose_release()
    result = run.decide_release()
    assert result.report.overall is RestorationOverall.PARTIALLY_RESTORED
    assert result.incident.state is S.AWAITING_RELEASE_APPROVAL
    statuses = {c.action_type: c.status for c in run.runtime.registry.list(incident_id=run.incident_id)}
    assert statuses[ActionType.BLOCK_DOMAIN] is ControlStatus.RELEASE_FAILED
    run.environment.clear_faults()
    run.release_package = None
    run.propose_release()  # RELEASE_FAILED controls are still in force and can be released again
    assert run.decide_release().incident.state is S.RESTORED


# ------------------------------------------------------------- state machine --
def test_state_machine_refuses_approval_states_without_a_human_token():
    run = _run("ransomware")
    package = run.detect().package
    with pytest.raises(ApprovalRequiredError):
        run.runtime.machine.transition(run.incident_id, S.APPROVED, actor="automation:anything",
                                       package_id=package.package_id)
    with pytest.raises(InvalidTransitionError):
        run.runtime.machine.transition(run.incident_id, S.CONTAINED, actor="automation:anything")
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL


def test_guard_refuses_direct_adapter_calls_even_in_live_mode():
    run = _run("ransomware")
    package = run.detect().package
    action = package.action(f"{run.incident_id}:isolate_endpoint:TH-LT-1047")
    from xdr_response.models import ActionRequest

    adapter = run.runtime.adapters.get("secure_endpoint")
    with pytest.raises(ApprovalRequiredError):
        adapter.isolate_endpoint(ActionRequest.from_recommendation(action))
    assert run.environment.state_changing_calls() == []
    assert guard.is_dry_run() is False
