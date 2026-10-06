"""Adversarial review, round 1, lens: execution integrity (architecture sections 5-8, 11, 13).

Every test asserts the SAFE behaviour. A failing test is evidence of a real weakness in the
Phase 0 code under ``src/xdr_response``; a passing test is an attack that was refused.

Attack surface covered: double execution (same key twice, concurrent runs, crash/restart, retry
after partial failure), already-contained targets, partial failures never reported as success,
CONTAINED only when verified, unapproved or rejected actions never execute, dry run never changes
simulated state and cannot be turned into live authority, and the incident state machine refusing
illegal transitions or approvals it cannot prove.

Fake data only (example.com / *.example domains, documentation IP ranges, TH-LT-1047 hosts).
"""
from __future__ import annotations

import contextvars
import threading
import types
from datetime import timedelta

import httpx
import pytest

from tests.fixtures.guard_helpers import install_fake_verifier, make_token
from tests.unit.execution.execution_harness import (
    bind_token,
    make_harness,
    make_package,
    make_recommendation,
)
from tools.simulator.scenario import LAB_PRINCIPALS, ScenarioRun, load_scenario
from xdr_response import guard
from xdr_response.approval.ledger import JsonlTokenUseLedger
from xdr_response.errors import (
    ApprovalRequiredError,
    DecisionError,
    DryRunViolationError,
    IntegrationError,
    IntegrationTimeoutError,
    InvalidTransitionError,
    TokenReplayError,
)
from xdr_response.execution import ActionRunner, InMemoryExecutionStateStore
from xdr_response.integrations.http import GuardedHttpClient, RetryPolicy
from xdr_response.integrations.simulated import FaultKind
from xdr_response.models import (
    ALLOWED_TRANSITIONS,
    TOKEN_REQUIRED,
    ActionRequest,
    ActionResultStatus,
    ActionType,
    ApprovalPurpose,
    ContainmentOverall,
    DecisionRequest,
    DecisionType,
    IncidentState,
    OperationKind,
    SkipReason,
    TargetState,
    VerificationStatus,
    can_transition,
)

S = IncidentState
ANALYST = LAB_PRINCIPALS["analyst"][0]
ISOLATE_KEY = "XDR-RW-1047:isolate_endpoint:TH-LT-1047"


# ------------------------------------------------------------------ helpers --
def _run(name: str = "ransomware", *, live: bool = True) -> ScenarioRun:
    return ScenarioRun(load_scenario(name), live=live)


def _writes(run: ScenarioRun, operation: str | None = None) -> list:
    calls = run.environment.state_changing_calls()
    return [c for c in calls if operation is None or c.operation == operation]


def _approve(run: ScenarioRun, package, decision: DecisionType = DecisionType.APPROVE_ALL, keys=()):
    """Obtain a genuine human approval token WITHOUT going through the orchestrator (no execution)."""
    request = DecisionRequest(package_id=package.package_id, decision=decision, approved_keys=tuple(keys))
    return run.runtime.approval.decide(package, request, run.credentials("analyst"))


def _forged(package, **claim_updates):
    """Unsigned token whose claims bind ``package`` exactly (zero signature, unknown key id)."""
    token = make_token(*package.actions, incident_id=package.incident_id)
    updates = {"package_id": package.package_id, "evidence_snapshot_hash": package.evidence_snapshot_hash,
               "workflow_id": package.workflow_id, "workflow_version": package.workflow_version}
    updates.update(claim_updates)
    return token.model_copy(update={"claims": token.claims.model_copy(update=updates)})


# =============================================================================
# 1. Double execution
# =============================================================================
def test_same_package_executed_twice_calls_the_vendor_once():
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    token = h.approve(package)
    executor = h.executor()
    first = executor.execute(package, token)
    second = executor.execute(package, token)
    assert h.se.calls == [action.idempotency_key]
    assert first.overall is ContainmentOverall.CONTAINED
    assert "replayed" in second.results[0].message


def test_concurrent_execution_of_one_package_writes_once():
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    token = h.approve(package)
    executor = h.executor()
    start = threading.Barrier(4)
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            start.wait(timeout=5)
            executor.execute(package, token)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert not errors
    assert h.se.calls == [action.idempotency_key]


def test_crash_restart_with_fresh_execution_store_cannot_replay_the_token():
    """A worker restart loses the in-memory execution store; the token ledger must still stop it."""
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    token = h.approve(package)
    h.runner.run(action, token, package=package, decision_id="d-1")
    restarted = ActionRunner(h.adapters, h.verification, registry=h.registry, audit=h.audit, clock=h.clock,
                             state_store=InMemoryExecutionStateStore(), redactor=h.redactor)
    second = restarted.run(action, token, package=package, decision_id="d-1")
    assert h.se.calls == [action.idempotency_key]
    assert second.status is ActionResultStatus.FAILED


def test_concurrent_workers_with_separate_stores_share_one_token_use():
    """Two workers (separate execution stores) racing on one approved action: one vendor write."""
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    token = h.approve(package)
    runners = [ActionRunner(h.adapters, h.verification, registry=h.registry, audit=h.audit, clock=h.clock,
                            state_store=InMemoryExecutionStateStore(), redactor=h.redactor) for _ in range(4)]
    start = threading.Barrier(len(runners))
    results = []

    def worker(r: ActionRunner) -> None:
        start.wait(timeout=5)
        results.append(r.run(action, token, package=package, decision_id="d-1"))

    threads = [threading.Thread(target=worker, args=(r,)) for r in runners]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert h.se.calls == [action.idempotency_key]
    assert sum(r.status is ActionResultStatus.SUCCESS for r in results) == 1


def test_orchestrator_concurrent_decisions_execute_the_package_once():
    run = _run()
    package = run.detect().package
    request = DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL)
    start = threading.Barrier(3)
    outcomes: list[object] = []

    def worker() -> None:
        start.wait(timeout=5)
        try:
            outcomes.append(run.orchestrator.submit_decision(request, run.credentials("analyst")))
        except DecisionError as exc:
            outcomes.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sum(isinstance(o, DecisionError) for o in outcomes) == 2
    assert len(_writes(run)) == len(package.actions)


def test_retry_after_partial_failure_never_resends_actions_that_succeeded():
    run = _run()
    run.environment.inject(FaultKind.UNAVAILABLE, integration="umbrella", operation="block_domain", times=None)
    run.detect()
    first = run.decide()
    assert first.report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    run.environment.clear_faults()
    retry = run.orchestrator.propose_retry(run.incident_id)
    assert [a.action_type for a in retry.actions] == [ActionType.BLOCK_DOMAIN]
    run.decide()
    for op in ("isolate_endpoint", "block_hash", "block_ip"):
        assert len(_writes(run, op)) == 1, op
    # the failed attempt plus exactly one successful retry
    assert [c.result for c in _writes(run, "block_domain")][-1] == ActionResultStatus.SUCCESS.value


def test_failed_action_is_never_retried_with_the_same_token():
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    token = h.approve(package)
    h.se.errors[action.idempotency_key] = IntegrationTimeoutError("read timeout", integration="secure_endpoint")
    first = h.executor().execute(package, token)
    assert first.results[0].status is ActionResultStatus.FAILED
    h.se.errors.clear()
    second = h.executor().execute(package, token)
    assert second.results[0].status is ActionResultStatus.FAILED
    assert h.se.calls == [action.idempotency_key]


def test_timed_out_write_later_seen_as_applied_is_tracked_as_an_automation_control():
    """Retry after a timed-out write whose outcome was unknown.

    Run 1: the write times out and the re-check still reads NOT_IN_DESIRED_STATE (eventual
    consistency), so the result is FAILED and no control is registered. The vendor did apply it.
    Run 2 (retry package, new human approval): the pre-check reads IN_DESIRED_STATE ->
    ALREADY_CONTAINED -> no control is registered either. The control the automation created is now
    invisible to the TemporaryControlRegistry and can never be released through a release package.
    """
    h = make_harness()
    action = make_recommendation()
    key = action.idempotency_key
    first_pkg = make_package(action)
    h.se.errors[key] = IntegrationTimeoutError("read timeout after send", integration="secure_endpoint")
    h.se.states[key] = [TargetState.NOT_IN_DESIRED_STATE]
    r1 = h.runner.run(action, h.approve(first_pkg), package=first_pkg, decision_id="d-1")
    assert r1.status is ActionResultStatus.FAILED and h.se.calls == [key]  # the write WAS sent
    h.se.errors.clear()
    h.se.states[key] = [TargetState.IN_DESIRED_STATE]  # the timed-out write did take effect
    retry_pkg = make_package(action)
    r2 = h.runner.run(action, h.approve(retry_pkg), package=retry_pkg, decision_id="d-2")
    assert r2.status is ActionResultStatus.ALREADY_CONTAINED
    assert h.registry.get(key) is not None, (
        "control created by the automation's own (timed out) write is not in the registry: "
        "it can never be released")


def test_jsonl_ledger_instances_on_one_file_do_not_double_consume(tmp_path):
    """Two ledger instances (two orchestrator workers) sharing the durable ledger file."""
    path = tmp_path / "ledger.jsonl"
    a = JsonlTokenUseLedger(path, fsync=False)
    b = JsonlTokenUseLedger(path, fsync=False)
    gate = threading.Barrier(2)

    def interleave(ledger: JsonlTokenUseLedger) -> None:
        original = ledger._refresh

        def refresh(self: JsonlTokenUseLedger) -> None:
            original()
            try:
                gate.wait(timeout=1)  # both have read the file before either appends
            except threading.BrokenBarrierError:
                pass
        ledger._refresh = types.MethodType(refresh, ledger)  # type: ignore[method-assign]

    interleave(a)
    interleave(b)
    wins: list[str] = []

    def consume(ledger: JsonlTokenUseLedger, name: str) -> None:
        try:
            ledger.consume("token-1", ISOLATE_KEY)
            wins.append(name)
        except TokenReplayError:
            pass

    threads = [threading.Thread(target=consume, args=(a, "a")), threading.Thread(target=consume, args=(b, "b"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(wins) == 1, f"the same (token, action) pair was consumed {len(wins)} times"


# =============================================================================
# 2. Guard scope: one authorization = one write, never outliving its block
# =============================================================================
def test_authorization_captured_in_a_copied_context_does_not_outlive_the_block():
    run = _run()
    package = run.detect().package
    token = _approve(run, package).token
    action = package.action(ISOLATE_KEY)
    request = ActionRequest.from_recommendation(action)
    adapter = run.runtime.adapters.get(request.integration)
    with guard.authorized(token, request):
        captured = contextvars.copy_context()  # e.g. a callback or thread spawned inside the block
    assert guard.current() is None
    with pytest.raises(ApprovalRequiredError):
        captured.run(adapter.execute, request)
    assert _writes(run) == [], "a vendor write ran after the authorization context had been exited"


def test_one_authorization_allows_only_one_vendor_write():
    run = _run()
    package = run.detect().package
    token = _approve(run, package).token
    request = ActionRequest.from_recommendation(package.action(ISOLATE_KEY))
    adapter = run.runtime.adapters.get(request.integration)
    sent = 0
    with guard.authorized(token, request):
        adapter.execute(request)
        sent += 1
        try:
            adapter.execute(request)
            sent += 1
        except ApprovalRequiredError:
            pass
    assert sent == 1 and len(_writes(run)) == 1, (
        "the single-use token was consumed once but the guarded write ran twice")


def test_authorized_write_cannot_be_redirected_to_another_target_or_integration():
    run = _run()
    package = run.detect().package
    token = _approve(run, package).token
    isolate = ActionRequest.from_recommendation(package.action(ISOLATE_KEY))
    other = next(a for a in package.actions if a.action_type is ActionType.BLOCK_DOMAIN)
    with guard.authorized(token, isolate):
        with pytest.raises(ApprovalRequiredError):
            run.runtime.adapters.get(other.integration).execute(ActionRequest.from_recommendation(other))
        wrong_adapter = next(n for n in ("umbrella", "secure_malware_analytics", "cisco_xdr")
                             if n != isolate.integration and n in run.runtime.adapters.names())
        with pytest.raises((ApprovalRequiredError, IntegrationError, ValueError)):
            run.runtime.adapters.get(wrong_adapter).isolate_endpoint(isolate)
    assert _writes(run) == []


@pytest.mark.parametrize("failure", ["read_timeout", 500, 502, 504, 503])
def test_http_client_never_blindly_resends_a_write(failure):
    install_fake_verifier()
    action = make_recommendation(ActionType.BLOCK_DOMAIN, target="c2.ransom-ops.example", integration="umbrella")
    request = ActionRequest.from_recommendation(action)
    sent: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        sent.append(req)
        if failure == "read_timeout":
            raise httpx.ReadTimeout("read timed out", request=req)
        return httpx.Response(int(failure), json={"error": "server"})

    client = GuardedHttpClient("umbrella", "https://api.example.com", transport=httpx.MockTransport(handler),
                               retry=RetryPolicy(max_retries=3), sleep=lambda _s: None)
    with guard.authorized(make_token(request), request):
        with pytest.raises(IntegrationError):
            client.post("/v1/destinationlists/1/destinations", kind=OperationKind.STATE_CHANGING,
                        operation="add_destination", json=[{"destination": request.target}])
    assert len(sent) == 1


def test_http_write_outside_authorization_is_never_sent():
    install_fake_verifier()
    sent: list[httpx.Request] = []
    client = GuardedHttpClient("umbrella", "https://api.example.com",
                               transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200)))
    with pytest.raises(ApprovalRequiredError):
        client.post("/v1/destinationlists/1/destinations", kind=OperationKind.STATE_CHANGING,
                    operation="add_destination", json=[])
    assert sent == []


# =============================================================================
# 3. Already-contained targets
# =============================================================================
def test_target_contained_by_someone_else_is_not_written_and_never_registered():
    run = _run()
    run.environment.force_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")
    run.detect()
    decision = run.decide()
    iso = next(r for r in decision.report.results if r.idempotency_key == ISOLATE_KEY)
    assert iso.status is ActionResultStatus.ALREADY_CONTAINED and not iso.control_registered
    assert _writes(run, "isolate_endpoint") == []
    assert run.runtime.registry.get(ISOLATE_KEY) is None
    release = run.propose_release()
    assert all(a.target != "TH-LT-1047" for a in release.actions)  # never releases someone else's control


def test_write_reporting_already_contained_registers_no_control():
    run = _run()
    run.environment.inject(FaultKind.ALREADY_CONTAINED, integration="secure_endpoint",
                           operation="isolate_endpoint")
    run.detect()
    decision = run.decide()
    iso = next(r for r in decision.report.results if r.idempotency_key == ISOLATE_KEY)
    assert iso.status is ActionResultStatus.ALREADY_CONTAINED
    assert run.runtime.registry.get(ISOLATE_KEY) is None


# =============================================================================
# 4. Partial failures and verification-gated CONTAINED
# =============================================================================
def test_one_failure_is_partial_never_contained_and_never_stops_the_others():
    run = _run()
    run.environment.inject(FaultKind.AUTH_FAIL, integration="secure_endpoint", operation="isolate_endpoint",
                           times=None)
    run.detect()
    decision = run.decide()
    report = decision.report
    assert report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    assert decision.incident.state is not S.CONTAINED
    assert [r.status for r in report.results].count(ActionResultStatus.SUCCESS) == len(report.results) - 1
    failed = next(r for r in report.results if r.idempotency_key == ISOLATE_KEY)
    assert failed.requires_attention and any("isolate_endpoint" in line for line in report.attention)


def test_executed_but_not_in_effect_is_never_contained():
    run = _run()
    run.environment.inject(FaultKind.NO_EFFECT, operation=None, times=None)  # every write "succeeds", no effect
    run.detect()
    decision = run.decide()
    assert all(r.status is ActionResultStatus.SUCCESS for r in decision.report.results)
    assert all(r.verification.status is VerificationStatus.NOT_VERIFIED for r in decision.report.results)
    assert decision.report.overall is ContainmentOverall.CONTAINMENT_FAILED
    assert S.CONTAINED not in [t.to_state for t in decision.incident.history]


def test_unverifiable_success_is_partial_by_default():
    run = _run()
    run.environment.inject(FaultKind.FAIL, integration="secure_endpoint", operation="verify", times=None)
    run.detect()
    decision = run.decide()
    iso = next(r for r in decision.report.results if r.idempotency_key == ISOLATE_KEY)
    assert iso.status is ActionResultStatus.SUCCESS
    assert iso.verification.status is VerificationStatus.UNABLE_TO_VERIFY and iso.requires_attention
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED
    assert decision.incident.state is not S.CONTAINED


def test_replayed_results_never_upgrade_a_failed_run_to_contained():
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    token = h.approve(package)
    h.verification.statuses[action.idempotency_key] = VerificationStatus.NOT_VERIFIED
    first = h.executor().execute(package, token)
    h.verification.statuses.clear()  # a later verification would succeed, but nothing re-runs
    second = h.executor().execute(package, token)
    assert first.overall is ContainmentOverall.CONTAINMENT_FAILED
    assert second.overall is ContainmentOverall.CONTAINMENT_FAILED


def test_disabled_integration_counts_as_failed_not_as_success():
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    h.adapters.by_name.pop("secure_endpoint")
    report = h.executor().execute(package, h.approve(package))
    assert report.results[0].status is ActionResultStatus.SKIPPED
    assert report.results[0].skip_reason is SkipReason.NO_CAPABLE_ADAPTER
    assert report.overall is ContainmentOverall.CONTAINMENT_FAILED


# =============================================================================
# 5. Unapproved or rejected actions never execute
# =============================================================================
def test_rejected_actions_in_approve_selected_never_reach_the_vendor():
    run = _run()
    package = run.detect().package
    others = [a.idempotency_key for a in package.actions if a.idempotency_key != ISOLATE_KEY]
    request = DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_SELECTED,
                              approved_keys=(ISOLATE_KEY,))
    decision = run.orchestrator.submit_decision(request, run.credentials("analyst"))
    assert [c.operation for c in _writes(run)] == ["isolate_endpoint"]
    for key in others:
        r = next(x for x in decision.report.results if x.idempotency_key == key)
        assert r.status is ActionResultStatus.SKIPPED and r.skip_reason is SkipReason.REJECTED_BY_ANALYST
    # a second direct executor call with the same selective token still cannot reach the rejected ones
    run.runtime.executor.execute(package, decision.outcome.token)
    assert [c.operation for c in _writes(run)] == ["isolate_endpoint"]


def test_rejected_package_cannot_be_executed_afterwards():
    run = _run()
    package = run.detect().package
    run.decide({"decision": "REJECT", "comment": "authorised test"})
    with pytest.raises(ApprovalRequiredError):
        run.runtime.executor.execute(package, None)
    with pytest.raises(ApprovalRequiredError):
        run.runtime.executor.execute(package, _forged(package))
    with pytest.raises(DecisionError):
        run.orchestrator.submit_decision(DecisionRequest(package_id=package.package_id,
                                                         decision=DecisionType.APPROVE_ALL),
                                         run.credentials("analyst"))
    assert _writes(run) == []


def test_token_of_one_package_cannot_execute_a_sibling_package_of_the_same_incident():
    run = _run()
    first = run.detect().package
    token = _approve(run, first, DecisionType.APPROVE_SELECTED, keys=(ISOLATE_KEY,)).token
    run.orchestrator.reinvestigate(run.incident_id, actor=ANALYST, reason="re-check")
    second = run.orchestrator.latest_package(run.incident_id)
    assert second.package_id != first.package_id
    with pytest.raises(ApprovalRequiredError):
        run.runtime.executor.execute(second, token)
    rebound = token.model_copy(update={"claims": token.claims.model_copy(
        update={"package_id": second.package_id})})
    with pytest.raises(ApprovalRequiredError):
        run.runtime.executor.execute(second, rebound)
    assert _writes(run) == []


def test_unsigned_token_never_executes_even_when_it_binds_the_package():
    run = _run()
    package = run.detect().package
    with pytest.raises(ApprovalRequiredError):
        run.runtime.executor.execute(package, _forged(package))
    assert _writes(run) == []


def test_direct_adapter_call_without_approval_is_refused_for_every_package_action():
    run = _run()
    package = run.detect().package
    for action in package.actions:
        request = ActionRequest.from_recommendation(action)
        with pytest.raises(ApprovalRequiredError):
            run.runtime.adapters.get(request.integration).execute(request)
    assert _writes(run) == []


# =============================================================================
# 6. Dry run never changes simulated state and never becomes live authority
# =============================================================================
def test_dry_run_full_lifecycle_changes_nothing():
    run = _run(live=False)
    before = dict(run.environment.state)
    detection = run.detect()
    assert detection.dry_run_report is not None and detection.dry_run_report.dry_run
    decision = run.decide()
    assert decision.dry_run and decision.report.overall is None
    assert _writes(run) == []
    assert run.environment.state == before
    assert run.runtime.registry.list() == []
    assert run.runtime.runner.state_store.list() == []
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL


def test_live_runtime_dry_run_simulation_writes_nothing_and_consumes_nothing():
    run = _run()
    package = run.detect().package
    token = _approve(run, package).token
    report = run.runtime.executor.execute(package, token, dry_run=True)
    with guard.dry_run():
        report2 = run.runtime.executor.execute(package, token)
    assert report.dry_run and report2.dry_run and _writes(run) == []
    assert run.runtime.runner.state_store.list() == []
    real = run.runtime.executor.execute(package, token)  # the simulation consumed no token use
    assert real.overall is ContainmentOverall.CONTAINED


def test_dry_run_inside_an_authorization_still_refuses_the_write():
    install_fake_verifier()
    h = make_harness()
    action = make_recommendation()
    request = ActionRequest.from_recommendation(action)
    with guard.authorized(make_token(request), request):
        with guard.dry_run():
            with pytest.raises(DryRunViolationError):
                h.se.isolate_endpoint(request)
    with guard.dry_run():
        with pytest.raises(DryRunViolationError):
            with guard.authorized(make_token(request), request):
                pass
    assert h.se.calls == []


def test_dry_run_does_not_poison_the_execution_store():
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    token = h.approve(package)
    with guard.dry_run():
        simulated = h.runner.run(action, token, package=package, decision_id="d-1")
    assert simulated.status is ActionResultStatus.FAILED and h.se.calls == []
    real = h.runner.run(action, token, package=package, decision_id="d-1")
    assert real.status is ActionResultStatus.SUCCESS and h.se.calls == [action.idempotency_key]


def test_token_issued_for_a_dry_run_approval_cannot_authorize_live_execution():
    """The analyst approved a SIMULATION. That approval must never become live authority.

    The token claims do not bind ``package.dry_run``, and neither ``check_token_binds_package`` nor
    ``ApprovalTokenService.verify_package`` look at it, so once dry run is switched off (within the
    token TTL) the same token executes the package for real.
    """
    run = _run(live=False)
    package = run.detect().package
    decision = run.decide()
    token = decision.outcome.token
    assert decision.dry_run and token is not None  # a real, signed token was issued for a simulation
    guard.configure(dry_run=False)  # operator later switches the deployment live
    live_copy = package.model_copy(update={"dry_run": False})
    try:
        run.runtime.executor.execute(live_copy, token)
    except ApprovalRequiredError:
        pass
    assert _writes(run) == [], "a dry-run approval token executed real containment"


# =============================================================================
# 7. State machine
# =============================================================================
ALL_STATES = list(IncidentState)


@pytest.mark.parametrize("src", ALL_STATES, ids=lambda s: s.value)
@pytest.mark.parametrize("dst", ALL_STATES, ids=lambda s: s.value)
def test_transition_table_only_allows_listed_moves(src, dst):
    assert can_transition(src, dst) is (dst in ALLOWED_TRANSITIONS[src])


def test_running_states_are_only_reachable_through_their_approval_states():
    into_running = {s for s, targets in ALLOWED_TRANSITIONS.items() if S.CONTAINMENT_RUNNING in targets}
    into_restoring = {s for s, targets in ALLOWED_TRANSITIONS.items() if S.RESTORATION_RUNNING in targets}
    into_approved = {s for s, targets in ALLOWED_TRANSITIONS.items() if S.APPROVED in targets}
    assert into_running == {S.APPROVED}
    assert into_restoring == {S.AWAITING_RELEASE_APPROVAL}
    assert into_approved == {S.AWAITING_APPROVAL}
    assert TOKEN_REQUIRED[S.APPROVED] is ApprovalPurpose.CONTAINMENT
    assert TOKEN_REQUIRED[S.RESTORATION_RUNNING] is ApprovalPurpose.RELEASE
    assert not any(t in ALLOWED_TRANSITIONS[S.CLOSED] for t in (S.APPROVED, S.CONTAINMENT_RUNNING,
                                                                S.RESTORATION_RUNNING))


@pytest.mark.parametrize("target", [S.CONTAINMENT_RUNNING, S.CONTAINED, S.PARTIALLY_CONTAINED,
                                    S.RESTORATION_RUNNING, S.RESTORED])
def test_machine_refuses_skipping_approval(target):
    run = _run()
    package = run.detect().package
    token = _approve(run, package).token
    with pytest.raises(InvalidTransitionError):
        run.runtime.machine.transition(run.incident_id, target, actor=ANALYST, package_id=package.package_id,
                                       token=token)
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL


def test_machine_refuses_approved_with_wrong_purpose_package_or_actor():
    run = _run()
    package = run.detect().package
    token = _approve(run, package).token
    m = run.runtime.machine
    release_like = token.model_copy(update={"claims": token.claims.model_copy(
        update={"purpose": ApprovalPurpose.RELEASE})})
    with pytest.raises(ApprovalRequiredError):
        m.transition(run.incident_id, S.APPROVED, actor=ANALYST, package_id=package.package_id, token=release_like)
    with pytest.raises(ApprovalRequiredError):
        m.transition(run.incident_id, S.APPROVED, actor=ANALYST, package_id="other-package", token=token)
    with pytest.raises(ApprovalRequiredError):
        m.transition(run.incident_id, S.APPROVED, actor="automation:lifecycle", package_id=package.package_id,
                     token=token)
    with pytest.raises(ApprovalRequiredError):
        m.transition(run.incident_id, S.APPROVED, actor=ANALYST, package_id=package.package_id, token=None)
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL


@pytest.mark.parametrize("kind", ["unsigned", "expired"])
def test_machine_refuses_approved_with_a_token_the_token_service_rejects(kind):
    """Entering APPROVED records a human approval in the incident history and audit trail.

    The machine only checks presence and binding (13.9), not the signature, expiry or approver
    roles, so a forged or expired token produces an APPROVED transition (and then
    CONTAINMENT_RUNNING) that no valid human approval backs.
    """
    run = _run()
    package = run.detect().package
    if kind == "unsigned":
        token = _forged(package)
    else:
        token = _approve(run, package).token
        run.advance(24 * 60)  # far past the 30 minute token TTL
    with pytest.raises(ApprovalRequiredError):
        run.runtime.machine.transition(run.incident_id, S.APPROVED, actor=ANALYST,
                                       package_id=package.package_id, token=token)
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL


def test_machine_refuses_a_second_approved_transition_with_an_already_used_token():
    run = _run()
    package = run.detect().package
    run.environment.inject(FaultKind.AUTH_FAIL, times=None)
    decision = run.decide()
    token = decision.outcome.token
    assert decision.report.overall is ContainmentOverall.CONTAINMENT_FAILED
    m = run.runtime.machine
    if run.orchestrator.get_incident(run.incident_id).state is not S.AWAITING_APPROVAL:
        m.transition(run.incident_id, S.AWAITING_APPROVAL, actor=ANALYST, reason="retry")
    with pytest.raises(ApprovalRequiredError):
        m.transition(run.incident_id, S.APPROVED, actor=ANALYST, package_id=package.package_id, token=token)
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL


def test_executed_package_cannot_be_decided_again_after_returning_to_awaiting_approval():
    run = _run()
    package = run.detect().package
    run.environment.inject(FaultKind.AUTH_FAIL, times=None)
    run.decide()
    run.environment.clear_faults()
    if run.orchestrator.get_incident(run.incident_id).state is not S.AWAITING_APPROVAL:
        run.runtime.machine.transition(run.incident_id, S.AWAITING_APPROVAL, actor=ANALYST, reason="retry")
    with pytest.raises(DecisionError):
        run.orchestrator.submit_decision(DecisionRequest(package_id=package.package_id,
                                                         decision=DecisionType.APPROVE_ALL),
                                         run.credentials("analyst"))
    assert all(c.result != ActionResultStatus.SUCCESS.value for c in _writes(run))


def test_executor_token_check_cannot_be_skipped_by_a_machine_only_approval():
    """Even if the machine is driven to CONTAINMENT_RUNNING by hand, execution still needs a real token."""
    run = _run()
    package = run.detect().package
    forged = _forged(package)
    try:
        run.runtime.machine.transition(run.incident_id, S.APPROVED, actor=ANALYST,
                                       package_id=package.package_id, token=forged)
        run.runtime.machine.transition(run.incident_id, S.CONTAINMENT_RUNNING, actor="automation:execution")
    except ApprovalRequiredError:
        pass
    with pytest.raises(ApprovalRequiredError):
        run.runtime.executor.execute(package, forged)
    assert _writes(run) == []


def test_harness_token_with_extra_grant_outside_the_package_is_refused():
    h = make_harness()
    action = make_recommendation()
    stranger = make_recommendation(target="TH-LT-2001")
    package = make_package(action)
    token = bind_token(make_token(action, stranger), package)
    with pytest.raises(ApprovalRequiredError):
        h.executor().execute(package, token)
    assert h.se.calls == []


def test_expired_token_executes_nothing():
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    token = h.approve(package)
    h.clock.advance(timedelta(minutes=31))
    report = h.executor().execute(package, token)
    assert report.results[0].status is ActionResultStatus.FAILED
    assert h.se.calls == []



# =============================================================================
# Round 2 (adversarial review, lens: execution integrity)
# =============================================================================
from tests.unit.execution.execution_harness import (  # noqa: E402
    FakeSecureEndpoint,
    settings_with_unable_to_verify_counting,
)
from xdr_response.execution import ContainmentExecutor  # noqa: E402


def _http_sink(sent: list) -> httpx.MockTransport:
    return httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={"id": "obj-1"}))


def _fresh_executor(h, store=None) -> ContainmentExecutor:
    """A second worker / restarted process: same adapters, ledger and registry, new execution store."""
    runner = h.new_runner(store=store or InMemoryExecutionStateStore())
    return ContainmentExecutor(runner, h.verifier, h.settings, audit=h.audit, clock=h.clock,
                               id_factory=lambda: "report-2", redactor=h.redactor)


# ---------------------------------------------------------- R2.1 double execution --
def test_r2_unauthorized_runner_call_cannot_poison_the_approved_execution():
    """An unauthorized (forged-token) runner call must not consume the slot of the approved action.

    The runner claims (package_id, key) in the execution store BEFORE the guard verifies the token.
    A forged token whose grant merely names the key gets FAILED and that FAILED result is stored as
    COMPLETED; the genuine human approval of the same package then only replays the forged failure.
    """
    run = _run()
    package = run.detect().package
    action = package.action(ISOLATE_KEY)
    poisoned = run.runtime.runner.run(action, _forged(package), package=package, decision_id="forged")
    assert poisoned.status is ActionResultStatus.FAILED and _writes(run) == []
    decision = run.decide()  # the real analyst approves the (latest, never executed) package
    iso = next(r for r in decision.report.results if r.idempotency_key == ISOLATE_KEY)
    assert iso.status is ActionResultStatus.SUCCESS, (
        f"genuinely approved isolation never ran; it replayed the forged attempt: {iso.message!r}")
    assert len(_writes(run, "isolate_endpoint")) == 1


def test_r2_second_token_for_the_same_package_after_restart_does_not_execute_again():
    """Two approvals of one package (the ApprovalEngine does not refuse a re-decision) + a restart.

    The execution store is per process and the token ledger is per token, so after a worker restart
    the second token executes the already executed package again. The target has no readable state
    (Secure Endpoint isolation status has no VERIFIED read, architecture 11.2), so the adapter
    pre-check cannot save it.
    """
    h = make_harness()
    action = make_recommendation()
    h.se.states[action.idempotency_key] = [TargetState.UNKNOWN]
    package = make_package(action)
    first, second = h.approve(package), h.approve(package)
    assert first.token_id != second.token_id
    assert h.executor().execute(package, first).overall is ContainmentOverall.CONTAINED
    _fresh_executor(h).execute(package, second)
    assert h.se.calls == [action.idempotency_key], (
        f"package {package.package_id} executed {len(h.se.calls)} times")


def test_r2_concurrent_packages_with_the_same_idempotency_key_write_once():
    """Two approved packages of one incident share a key and run concurrently (two workers).

    Section 6.3 makes ``<incident>:<action>:<target>`` THE idempotency key, but the claim is keyed by
    (package_id, key) and the token ledger by (token_id, key): both pre-checks read 'not contained'
    and both send the write.
    """
    h = make_harness()
    action = make_recommendation()
    key = action.idempotency_key
    gate = threading.Barrier(2, timeout=1)
    original_state = h.se.current_state

    def racing_current_state(request):
        observed = original_state(request)  # read first, then wait for the other worker's read
        try:
            gate.wait()
        except threading.BrokenBarrierError:
            pass  # a serialized implementation simply proceeds after the timeout
        return observed

    original_do = h.se._do

    def applying_do(request):
        outcome = original_do(request)
        h.se.states[key] = [TargetState.IN_DESIRED_STATE]  # the vendor now reports it contained
        return outcome

    h.se.current_state = racing_current_state  # type: ignore[method-assign]
    h.se._do = applying_do  # type: ignore[method-assign]
    pkg_a, pkg_b = make_package(action), make_package(action)
    jobs = [(h.executor(), pkg_a, h.approve(pkg_a)), (_fresh_executor(h), pkg_b, h.approve(pkg_b))]
    errors: list[BaseException] = []

    def worker(executor, package, token):
        try:
            executor.execute(package, token)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=job) for job in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert not errors
    assert h.se.calls == [key], f"{len(h.se.calls)} vendor writes for idempotency key {key}"


def test_r2_earlier_approval_token_cannot_execute_after_the_analyst_rejected_the_package():
    """A token issued for the package earlier (second analyst, double submit) must die with REJECT.

    Neither the ApprovalEngine (no 'already decided' check) nor the executor (no package-store /
    incident-state check) knows the package was rejected and the incident CLOSED.
    """
    run = _run()
    package = run.detect().package
    early = _approve(run, package).token  # genuine human approval, not routed through the orchestrator
    rejected = run.decide({"decision": "REJECT", "comment": "false positive, do not contain"})
    assert rejected.incident.state is S.CLOSED
    try:
        run.runtime.executor.execute(package, early)
    except (ApprovalRequiredError, DecisionError):
        pass
    assert _writes(run) == [], "containment ran after the analyst's recorded REJECT closed the incident"


def test_r2_retry_after_unverified_write_tracks_the_control_the_retry_created():
    """Run 1: the write 'succeeds' but has no effect (NOT_VERIFIED); a control is registered with its
    rollback parameters. Retry (new package, new approval): a second write creates the control that is
    really in force. ``register`` returns the old ACTIVE entry unchanged, so the registry keeps the
    rollback data (external ref / vendor object id) of the ineffective first write while the result
    of the retry claims ``control_registered=True``. A release would delete the wrong vendor object.
    """
    run = _run()
    run.environment.inject(FaultKind.NO_EFFECT, integration="secure_endpoint", operation="isolate_endpoint")
    run.detect()
    first = run.decide()
    iso1 = next(r for r in first.report.results if r.idempotency_key == ISOLATE_KEY)
    assert iso1.status is ActionResultStatus.SUCCESS
    assert iso1.verification.status is VerificationStatus.NOT_VERIFIED
    retry_pkg = run.orchestrator.propose_retry(run.incident_id)
    assert ISOLATE_KEY in retry_pkg.keys
    second = run.decide()
    iso2 = next(r for r in second.report.results if r.idempotency_key == ISOLATE_KEY)
    assert iso2.status is ActionResultStatus.SUCCESS and iso2.control_registered
    control = run.runtime.registry.get(ISOLATE_KEY)
    assert control is not None
    assert control.package_id == retry_pkg.package_id and control.external_ref in iso2.message, (
        f"registry still points at the first, ineffective write ({control.external_ref}, package "
        f"{control.package_id}); the retry's control is untracked")


# ------------------------------------------------- R2.2 guard: one approval = one write --
def test_r2_unguarded_http_write_inside_an_authorization_window_is_refused():
    """5.7: 'a vendor write cannot be sent from an unguarded method either'.

    ``require_active_authorization`` allows a STATE_CHANGING request from ANY code running inside the
    ``authorized`` block as long as no ``@state_changing`` call consumed it yet. That unguarded write
    plus the guarded write make two vendor writes under one single-use approval.
    """
    install_fake_verifier()
    h = make_harness()
    action = make_recommendation(ActionType.BLOCK_DOMAIN, target="c2.ransom-ops.example", integration="umbrella")
    request = ActionRequest.from_recommendation(action)
    sent: list[httpx.Request] = []
    client = GuardedHttpClient("umbrella", "https://api.example.com", transport=_http_sink(sent),
                               sleep=lambda _s: None)
    with guard.authorized(make_token(request), request):
        try:
            client.post("/v1/destinationlists/1/destinations", kind=OperationKind.STATE_CHANGING,
                        operation="add_destination", json=[{"destination": "other.example.com"}])
        except ApprovalRequiredError:
            pass
        h.umbrella.block_domain(request)
    assert len(sent) + len(h.umbrella.calls) <= 1, (
        f"{len(sent)} unguarded + {len(h.umbrella.calls)} guarded writes under one approval")


def test_r2_read_only_precheck_cannot_send_a_vendor_write():
    """The runner calls ``adapter.current_state`` (read-only, unguarded) INSIDE ``guard.authorized``.

    An adapter whose pre-check issues a STATE_CHANGING request (bug, or a vendor 'action' endpoint
    used for a status probe) gets it sent, then ``execute`` writes again.
    """
    sent: list[httpx.Request] = []

    class WritingPrecheck(FakeSecureEndpoint):
        def __init__(self) -> None:
            super().__init__()
            self.http = GuardedHttpClient("secure_endpoint", "https://api.example.com",
                                          transport=_http_sink(sent), sleep=lambda _s: None)

        def current_state(self, request):
            # the adapter's own manifest write operation (see the harness manifest), sent from a read
            self.http.post("/fake/isolate_endpoint", kind=OperationKind.STATE_CHANGING,
                           operation="op_isolate_endpoint", json={"hostname": request.target})
            return super().current_state(request)

    h = make_harness()
    adapter = WritingPrecheck()
    h.adapters.by_name["secure_endpoint"] = adapter
    action = make_recommendation()
    package = make_package(action)
    h.runner.run(action, h.approve(package), package=package, decision_id="d-1")
    assert sent == [], "the read-only state pre-check sent a vendor write inside the authorization window"
    assert adapter.calls == [action.idempotency_key]


# -------------------------------------------------------- R2.3 already-contained targets --
def test_r2_someone_elses_control_is_not_adopted_after_failed_precheck_and_write_timeout():
    """The host was isolated by the SOC by hand. The pre-check read fails, the write times out (never
    applied), the re-check reads 'isolated' -> SUCCESS and the SOC's isolation is registered as an
    automation control, so the next release package un-isolates a host the automation never touched.
    """
    run = _run()
    run.environment.force_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")  # someone else's
    run.environment.inject(FaultKind.UNAVAILABLE, integration="secure_endpoint", operation="current_state",
                           target="TH-LT-1047")
    run.environment.inject(FaultKind.TIMEOUT, integration="secure_endpoint", operation="isolate_endpoint",
                           target="TH-LT-1047")
    run.detect()
    decision = run.decide()
    iso = next(r for r in decision.report.results if r.idempotency_key == ISOLATE_KEY)
    assert iso.status is not ActionResultStatus.SUCCESS or not iso.control_registered, (
        f"someone else's isolation adopted as an automation control: {iso.message!r}")
    try:
        release = run.propose_release()
    except Exception:  # noqa: BLE001 - nothing to release is also safe
        return
    assert all(a.target != "TH-LT-1047" for a in release.actions)


def test_r2_already_contained_but_independent_read_disagrees_is_never_contained():
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    h.se.states[action.idempotency_key] = [TargetState.IN_DESIRED_STATE]
    h.verification.statuses[action.idempotency_key] = VerificationStatus.NOT_VERIFIED
    report = h.executor().execute(package, h.approve(package))
    assert report.results[0].status is ActionResultStatus.ALREADY_CONTAINED
    assert report.overall is ContainmentOverall.CONTAINMENT_FAILED
    assert h.se.calls == [] and h.registry.get(action.idempotency_key) is None


# ------------------------------------------------- R2.4 verification-gated CONTAINED --
@pytest.mark.parametrize("actor", ["ai:assistant", "automation:verification"])
def test_r2_contained_cannot_be_recorded_without_an_executed_and_verified_run(actor):
    """'CONTAINED only when verified': the machine accepts CONTAINED from any actor string (an AI
    component included) right after CONTAINMENT_RUNNING, with no execution report at all.
    """
    run = _run()
    package = run.detect().package
    token = _approve(run, package).token
    m = run.runtime.machine
    m.transition(run.incident_id, S.APPROVED, actor=ANALYST, package_id=package.package_id, token=token)
    m.transition(run.incident_id, S.CONTAINMENT_RUNNING, actor="automation:execution",
                 package_id=package.package_id, token=token)
    with pytest.raises((ApprovalRequiredError, InvalidTransitionError, ValueError)):
        m.transition(run.incident_id, S.CONTAINED, actor=actor, reason="looks contained",
                     package_id=package.package_id)
    assert _writes(run) == []
    assert run.orchestrator.get_incident(run.incident_id).state is not S.CONTAINED


def test_r2_unable_to_verify_counted_as_contained_still_requires_attention():
    h = make_harness()
    action = make_recommendation()
    package = make_package(action)
    h.verification.statuses[action.idempotency_key] = VerificationStatus.UNABLE_TO_VERIFY
    report = h.executor(settings=settings_with_unable_to_verify_counting()).execute(package, h.approve(package))
    assert report.overall is ContainmentOverall.CONTAINED  # operator opted in
    assert report.results[0].requires_attention
    assert any("TH-LT-1047" in line for line in report.attention)


# --------------------------------------------------------------- R2.5 dry run fidelity --
def test_r2_dry_run_of_a_selective_approval_never_shows_rejected_actions_as_executed():
    """Dry run of APPROVE_SELECTED: the analyst rejected everything except isolation, yet the
    simulation (built from the whole package, ignoring the token) prints 'Would block ...' for the
    rejected actions, i.e. it misreports what the live run would do.
    """
    run = _run(live=False)
    before = dict(run.environment.state)
    package = run.detect().package
    decision = run.decide({"decision": "APPROVE_SELECTED", "select": ["isolate_endpoint"]})
    assert decision.dry_run and _writes(run) == [] and run.environment.state == before
    rejected = [r for r in decision.report.results if r.idempotency_key != ISOLATE_KEY]
    assert rejected and len(package.actions) > 1
    shown_as_executed = [r.dry_run_line for r in rejected
                         if r.status is ActionResultStatus.DRY_RUN and r.dry_run_line
                         and not r.dry_run_line.startswith("Would skip")]
    assert shown_as_executed == [], f"rejected actions simulated as executed: {shown_as_executed}"
