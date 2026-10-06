"""ContainmentExecutor: automatic execution of approved packages (architecture 6.1, 6.4, 13.16)."""
from __future__ import annotations

import threading

import pytest

from tests.unit.execution.execution_harness import (
    bind_token,
    expired_by,
    make_harness,
    make_package,
    make_recommendation,
    make_release_package,
    make_token,
    settings_with_unable_to_verify_counting,
)
from xdr_response import guard
from xdr_response.errors import (
    ApprovalRequiredError,
    AuthFailedError,
    TokenExpiredError,
    TokenInvalidError,
    TokenMismatchError,
)
from xdr_response.execution import ContainmentExecutor, check_token_binds_package
from xdr_response.models import (
    ActionResultStatus as S,
    ActionType,
    AuditEventType as E,
    ContainmentOverall as C,
    ErrorCode,
    SkipReason,
    VerificationStatus as V,
)

ISOLATE = make_recommendation()
BLOCK = make_recommendation(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella")
REVOKE = make_recommendation(ActionType.REVOKE_SESSIONS, "j.doe@example.com", "entra")


@pytest.fixture
def h():
    return make_harness()


def _calls(h) -> list[str]:
    return h.se.calls + h.umbrella.calls + h.entra.calls


# ------------------------------------------------------------- happy paths --
def test_all_actions_verified_is_contained(h):
    package = make_package(ISOLATE, BLOCK, REVOKE)
    report = h.executor().execute(package, h.approve(package))
    assert report.overall is C.CONTAINED
    assert report.dry_run is False
    assert [r.idempotency_key for r in report.results] == list(package.keys)
    assert all(r.status is S.SUCCESS for r in report.results)
    assert report.attention == ()
    assert h.audit.types()[-1] is E.CONTAINMENT_COMPLETED
    assert h.audit.of(E.CONTAINMENT_COMPLETED)[0]["overall"] == "CONTAINED"


def test_one_failure_gives_partial_with_attention_and_escalation(h):
    h.entra.errors[REVOKE.idempotency_key] = AuthFailedError("forbidden", integration="entra", http_status=403)
    package = make_package(ISOLATE, BLOCK, REVOKE)
    report = h.executor().execute(package, h.approve(package))
    assert report.overall is C.PARTIALLY_CONTAINED
    assert [r.status for r in report.results] == [S.SUCCESS, S.SUCCESS, S.FAILED]
    assert h.se.calls and h.umbrella.calls  # the failure did not stop the other actions
    assert "Requires attention: revoke_sessions j.doe@example.com - HTTP 403 (AUTH_FAILED)" in report.attention
    assert "Recommended escalation: Microsoft 365 administrator" in report.attention


def test_failure_of_first_action_does_not_stop_later_ones(h):
    h.se.errors[ISOLATE.idempotency_key] = RuntimeError("adapter bug")
    package = make_package(ISOLATE, BLOCK)
    report = h.executor().execute(package, h.approve(package))
    assert [r.status for r in report.results] == [S.FAILED, S.SUCCESS]
    assert report.overall is C.PARTIALLY_CONTAINED


def test_every_action_failing_is_containment_failed(h):
    h.se.errors[ISOLATE.idempotency_key] = RuntimeError("x")
    h.umbrella.errors[BLOCK.idempotency_key] = RuntimeError("y")
    package = make_package(ISOLATE, BLOCK)
    report = h.executor().execute(package, h.approve(package))
    assert report.overall is C.CONTAINMENT_FAILED


def test_approve_selected_runs_only_granted_actions(h):
    package = make_package(ISOLATE, BLOCK, REVOKE)
    token = h.approve(package, ISOLATE.idempotency_key, REVOKE.idempotency_key)
    report = h.executor().execute(package, token)
    by_key = {r.idempotency_key: r for r in report.results}
    assert by_key[BLOCK.idempotency_key].status is S.SKIPPED
    assert by_key[BLOCK.idempotency_key].skip_reason is SkipReason.REJECTED_BY_ANALYST
    assert h.umbrella.calls == [] and h.umbrella.state_calls == []
    assert report.overall is C.CONTAINED  # rejected actions are excluded from the overall


def test_unable_to_verify_respects_threshold_flag(h):
    h.verification.statuses[ISOLATE.idempotency_key] = V.UNABLE_TO_VERIFY
    package = make_package(ISOLATE, BLOCK)
    report = h.executor().execute(package, h.approve(package))
    assert report.overall is C.PARTIALLY_CONTAINED
    assert any("verify manually" in line for line in report.attention)

    h2 = make_harness()
    h2.verification.statuses[ISOLATE.idempotency_key] = V.UNABLE_TO_VERIFY
    report2 = h2.executor(settings=settings_with_unable_to_verify_counting()).execute(
        package, h2.approve(package))
    assert report2.overall is C.CONTAINED


def test_not_verified_counts_as_failed(h):
    h.verification.statuses[ISOLATE.idempotency_key] = V.NOT_VERIFIED
    package = make_package(ISOLATE)
    report = h.executor().execute(package, h.approve(package))
    assert report.overall is C.CONTAINMENT_FAILED


def test_reexecuting_the_same_package_never_calls_the_vendor_twice(h):
    package = make_package(ISOLATE, BLOCK)
    token = h.approve(package)
    executor = h.executor()
    first = executor.execute(package, token)
    second = executor.execute(package, token)
    assert first.overall is second.overall is C.CONTAINED
    assert h.se.calls == [ISOLATE.idempotency_key]
    assert h.umbrella.calls == [BLOCK.idempotency_key]


def test_completed_audit_failure_is_reported_not_raised(h):
    h.audit.fail_on.add(E.CONTAINMENT_COMPLETED)
    package = make_package(ISOLATE)
    report = h.executor().execute(package, h.approve(package))
    assert report.overall is C.CONTAINED
    assert any("CONTAINMENT_COMPLETED" in line for line in report.attention)


# ------------------------------------------------------------ token checks --
def test_missing_token_raises_and_is_audited(h):
    package = make_package(ISOLATE)
    with pytest.raises(ApprovalRequiredError):
        h.executor().execute(package, None)
    assert _calls(h) == []
    assert h.audit.types() == [E.GUARD_DENIED]


@pytest.mark.parametrize("update", [
    {"package_id": "another-package"},
    {"evidence_snapshot_hash": "b" * 64},
    {"incident_id": "XDR-00001"},
    {"workflow_version": "9.9.9"},
])
def test_token_bound_to_something_else_is_refused(h, update):
    package = make_package(ISOLATE)
    token = bind_token(make_token(ISOLATE), package, **update)
    with pytest.raises(TokenMismatchError):
        h.executor().execute(package, token)
    assert _calls(h) == []
    assert h.verifier.mark_used_calls == 0


def test_token_with_grant_outside_package_is_refused(h):
    package = make_package(ISOLATE)
    token = bind_token(make_token(ISOLATE, BLOCK), package)
    with pytest.raises(TokenMismatchError):
        h.executor().execute(package, token)
    assert _calls(h) == []


def test_release_token_cannot_execute_containment(h):
    release = make_recommendation(ActionType.RELEASE_ENDPOINT, restores=ISOLATE.idempotency_key)
    release_token = h.approve(make_release_package(release))
    package = make_package(ISOLATE)
    with pytest.raises(TokenMismatchError):
        h.executor().execute(package, bind_token(release_token, package))
    assert _calls(h) == []


def test_tampered_package_evidence_is_refused(h):
    package = make_package(ISOLATE)
    token = h.approve(package)
    tampered = package.model_copy(update={"evidence": package.evidence[:1]})
    with pytest.raises(TokenMismatchError):
        check_token_binds_package(token, tampered)


def test_verify_package_of_the_token_service_is_called_and_enforced(h):
    class Service:
        def __init__(self, inner, fail):
            self.inner, self.fail, self.calls = inner, fail, 0

        def verify(self, token, *, purpose, binding):
            return self.inner.verify(token, purpose=purpose, binding=binding)

        def mark_used(self, token, key):
            return self.inner.mark_used(token, key)

        def verify_package(self, token, package):
            self.calls += 1
            if self.fail:
                raise TokenExpiredError("token expired")

    package = make_package(ISOLATE)
    ok = Service(h.verifier, fail=False)
    assert h.executor(tokens=ok).execute(package, h.approve(package)).overall is C.CONTAINED
    assert ok.calls == 1

    h2 = make_harness()
    bad = Service(h2.verifier, fail=True)
    with pytest.raises(TokenExpiredError):
        h2.executor(tokens=bad).execute(package, h2.approve(package))
    assert _calls(h2) == []


def test_unexpected_verify_package_error_fails_closed(h):
    class Broken:
        def verify(self, token, *, purpose, binding):  # pragma: no cover - never reached
            raise AssertionError

        def mark_used(self, token, key):  # pragma: no cover
            raise AssertionError

        def verify_package(self, token, package):
            raise KeyError("ledger")

    package = make_package(ISOLATE)
    with pytest.raises(TokenInvalidError):
        h.executor(tokens=Broken()).execute(package, h.approve(package))


def test_expired_token_fails_every_action_without_vendor_calls(h):
    package = make_package(ISOLATE, BLOCK)
    token = h.approve(package)
    expired_by(h)
    report = h.executor().execute(package, token)
    assert report.overall is C.CONTAINMENT_FAILED
    assert all(r.error is not None and r.error.code is ErrorCode.APPROVAL_DENIED for r in report.results)
    assert _calls(h) == []


# ----------------------------------------------------------------- dry run --
@pytest.mark.parametrize("mode", ["global", "argument", "package", "context"])
def test_dry_run_simulates_and_never_reaches_adapters(h, mode):
    package = make_package(ISOLATE, BLOCK)
    token = h.approve(package)
    executor = h.executor()
    if mode == "global":
        guard.configure(dry_run=True)
        report = executor.execute(package, token)
    elif mode == "argument":
        report = executor.execute(package, token, dry_run=True)
    elif mode == "package":
        report = executor.execute(package.model_copy(update={"dry_run": True}), token)
    else:
        with guard.dry_run():
            report = executor.execute(package, token)
    assert report.dry_run is True and report.overall is None
    assert h.simulator.calls == 1 and h.simulator.saw_dry_run == [True]
    assert _calls(h) == [] and h.se.state_calls == []
    assert h.verifier.mark_used_calls == 0
    assert h.registry.controls == {}


def test_dry_run_without_token_is_allowed(h):
    guard.configure(dry_run=True)
    report = h.executor().execute(make_package(ISOLATE), None)
    assert report.overall is None


def test_fallback_simulation_without_simulator(h):
    package = make_package(ISOLATE, BLOCK)
    report = h.executor(simulator=None).execute(package, None, dry_run=True)
    assert [r.dry_run_line for r in report.results] == ["Would isolate: TH-LT-1047",
                                                         "Would block: bad.example.test"]
    assert all(r.status is S.DRY_RUN for r in report.results)
    assert h.audit.types() == [E.DRY_RUN_SIMULATION]
    assert _calls(h) == []


def test_simulator_returning_a_real_report_is_rejected(h):
    class Liar:
        def simulate(self, package):
            report = h.simulator.simulate(package)
            return report.model_copy(update={"dry_run": False, "overall": C.CONTAINED})

    with pytest.raises(RuntimeError):
        h.executor(simulator=Liar()).execute(make_package(ISOLATE), None, dry_run=True)


# ------------------------------------------------------------- concurrency --
def test_actions_on_different_integrations_run_concurrently(h):
    barrier = threading.Barrier(2, timeout=5)
    h.se.barrier = barrier
    h.umbrella.barrier = barrier
    package = make_package(ISOLATE, BLOCK)
    report = h.executor(max_concurrency=2).execute(package, h.approve(package))
    assert [r.status for r in report.results] == [S.SUCCESS, S.SUCCESS]
    assert [r.idempotency_key for r in report.results] == list(package.keys)


def test_per_integration_limit_serializes_calls(h):
    blocks = [make_recommendation(ActionType.BLOCK_DOMAIN, f"bad{i}.example.test", "umbrella") for i in range(4)]
    package = make_package(*blocks, ISOLATE)
    report = h.executor(max_concurrency=4, integration_concurrency={"umbrella": 1}).execute(
        package, h.approve(package))
    assert report.overall is C.CONTAINED
    assert h.umbrella.max_active == 1
    assert len(h.umbrella.calls) == 4


def test_concurrent_run_keeps_guard_context_per_action(h):
    package = make_package(ISOLATE, BLOCK, REVOKE)
    report = h.executor(max_concurrency=3).execute(package, h.approve(package))
    assert report.overall is C.CONTAINED
    assert h.verifier.mark_used_calls == 3
    assert guard.current() is None


@pytest.mark.parametrize("kwargs", [{"max_concurrency": 0}, {"integration_concurrency": {"umbrella": 0}}])
def test_invalid_concurrency_settings(h, kwargs):
    with pytest.raises(ValueError):
        h.executor(**kwargs)


def test_only_containment_packages_are_accepted(h):
    release = make_recommendation(ActionType.RELEASE_ENDPOINT, restores=ISOLATE.idempotency_key)
    with pytest.raises(TypeError):
        h.executor().execute(make_release_package(release), None)  # type: ignore[arg-type]


def test_runner_crash_is_contained_by_executor(h):
    class Exploding:
        def run(self, *a, **kw):
            raise RuntimeError("runner bug")

    executor = ContainmentExecutor(Exploding(), h.verifier, h.settings, audit=h.audit,  # type: ignore[arg-type]
                                   simulator=h.simulator, clock=h.clock)
    package = make_package(ISOLATE)
    report = executor.execute(package, h.approve(package))
    assert report.results[0].status is S.FAILED
    assert report.overall is C.CONTAINMENT_FAILED
