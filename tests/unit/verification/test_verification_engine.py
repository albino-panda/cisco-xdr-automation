"""VerificationEngine: read-only polling with backoff, never raises, evidence recorded."""
from __future__ import annotations

import json

import pytest

from tests.fixtures.factories import FIXED_NOW
from tests.unit.verification.verification_fakes import (
    FakeEntraVerify,
    FakeRegistry,
    FakeSleep,
    ScriptedVerifyAdapter,
    make_outcome,
    make_request,
)
from xdr_response import guard
from xdr_response.clock import FixedClock
from xdr_response.config.schema import VerificationSettings
from xdr_response.errors import (
    ApprovalRequiredError,
    AuthFailedError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    InvalidTargetError,
    RateLimitedError,
)
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    ErrorCode,
    VerificationResult,
    VerificationStatus,
)
from xdr_response.verification import NO_VERIFY_METHOD, PollPolicy, VerificationEngine

V = VerificationStatus


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(FIXED_NOW)


def _engine(adapter, clock, *, policy: PollPolicy | None = None, sleep: FakeSleep | None = None,
            settings: VerificationSettings | None = None):
    sleep = sleep if sleep is not None else FakeSleep(clock)
    engine = VerificationEngine(FakeRegistry(adapter), settings or VerificationSettings(),
                                clock=clock, sleep=sleep,
                                policy=policy or PollPolicy(interval_seconds=10, timeout_seconds=300,
                                                            backoff_factor=1.5, max_interval_seconds=60))
    return engine, sleep


def test_verified_on_first_read_needs_no_sleep(clock):
    adapter = ScriptedVerifyAdapter([V.VERIFIED], clock=clock)
    engine, sleep = _engine(adapter, clock)
    request = make_request()
    result = engine.verify(request, make_outcome())
    assert result.status is V.VERIFIED
    assert result.idempotency_key == request.idempotency_key
    assert result.integration == "secure_endpoint"
    assert result.method == "read_state"
    assert len(result.api_calls) == 1
    assert len(adapter.calls) == 1
    assert sleep.calls == []


def test_eventual_consistency_polls_with_backoff_until_verified(clock):
    adapter = ScriptedVerifyAdapter([V.NOT_VERIFIED, V.NOT_VERIFIED, V.VERIFIED], clock=clock)
    engine, sleep = _engine(adapter, clock)
    trace = engine.verify_with_trace(make_request(), make_outcome())
    assert trace.result.status is V.VERIFIED
    assert sleep.calls == [10.0, 15.0]
    assert [a.status for a in trace.attempts] == [V.NOT_VERIFIED, V.NOT_VERIFIED, V.VERIFIED]
    assert len(trace.result.api_calls) == 3  # every read is evidence
    assert "(3 read(s))" in trace.result.details
    assert trace.timed_out is False


def test_persistent_not_verified_stops_at_timeout(clock):
    adapter = ScriptedVerifyAdapter([V.NOT_VERIFIED], clock=clock)
    policy = PollPolicy(interval_seconds=10, timeout_seconds=60, backoff_factor=2.0,
                        max_interval_seconds=60)
    engine, sleep = _engine(adapter, clock, policy=policy)
    trace = engine.verify_with_trace(make_request(), make_outcome())
    assert trace.result.status is V.NOT_VERIFIED
    assert trace.timed_out is True
    assert sum(sleep.calls) == pytest.approx(60.0)
    assert sleep.calls == [10.0, 20.0, 30.0]  # last delay capped by the remaining time
    assert len(adapter.calls) == 4


def test_pending_unable_to_verify_is_polled_then_times_out(clock):
    adapter = ScriptedVerifyAdapter([V.UNABLE_TO_VERIFY], clock=clock)  # unknown/pending status
    policy = PollPolicy(interval_seconds=5, timeout_seconds=12, backoff_factor=1.0, max_interval_seconds=5)
    engine, sleep = _engine(adapter, clock, policy=policy)
    trace = engine.verify_with_trace(make_request(), make_outcome())
    assert trace.result.status is V.UNABLE_TO_VERIFY
    assert trace.timed_out is True
    assert "no terminal state" in trace.result.details
    assert "verify manually" in trace.result.details
    assert sleep.calls == [5.0, 5.0, 2.0]


def test_pending_then_verified(clock):
    adapter = ScriptedVerifyAdapter([V.UNABLE_TO_VERIFY, V.VERIFIED], clock=clock)
    engine, _ = _engine(adapter, clock)
    assert engine.verify(make_request(), make_outcome()).status is V.VERIFIED


def test_no_read_back_method_is_terminal_immediately(clock):
    adapter = ScriptedVerifyAdapter([V.UNABLE_TO_VERIFY], clock=clock, method=NO_VERIFY_METHOD)
    engine, sleep = _engine(adapter, clock)
    result = engine.verify(make_request(), make_outcome())
    assert result.status is V.UNABLE_TO_VERIFY
    assert len(adapter.calls) == 1
    assert sleep.calls == []


@pytest.mark.parametrize("exc", [
    IntegrationUnavailableError("503 from vendor", integration="secure_endpoint"),
    IntegrationTimeoutError("read timed out", integration="secure_endpoint"),
])
def test_transient_errors_are_retried(clock, exc):
    adapter = ScriptedVerifyAdapter([exc, V.VERIFIED], clock=clock)
    engine, sleep = _engine(adapter, clock)
    trace = engine.verify_with_trace(make_request(), make_outcome())
    assert trace.result.status is V.VERIFIED
    assert trace.attempts[0].error is not None
    assert trace.attempts[0].status is None
    assert sleep.calls == [10.0]


def test_rate_limit_honours_retry_after(clock):
    exc = RateLimitedError("429", integration="secure_endpoint", retry_after=30)
    adapter = ScriptedVerifyAdapter([exc, V.VERIFIED], clock=clock)
    engine, sleep = _engine(adapter, clock)
    assert engine.verify(make_request(), make_outcome()).status is V.VERIFIED
    assert sleep.calls == [30.0]


@pytest.mark.parametrize("exc, code", [
    (AuthFailedError("forbidden", integration="secure_endpoint", http_status=403), ErrorCode.AUTH_FAILED),
    (InvalidTargetError("no such computer", integration="secure_endpoint", http_status=404),
     ErrorCode.INVALID_TARGET),
])
def test_non_retryable_errors_stop_with_unable_to_verify(clock, exc, code):
    adapter = ScriptedVerifyAdapter([exc, V.VERIFIED], clock=clock)
    engine, sleep = _engine(adapter, clock)
    trace = engine.verify_with_trace(make_request(), make_outcome())
    assert trace.result.status is V.UNABLE_TO_VERIFY
    assert len(adapter.calls) == 1
    assert sleep.calls == []
    assert trace.last_error is not None and trace.last_error.code is code
    assert code.value in trace.result.details


def test_unexpected_exception_never_raises_and_is_redacted(clock):
    adapter = ScriptedVerifyAdapter([RuntimeError("boom Authorization: Bearer faketoken0123456789")],
                                    clock=clock)
    engine, _ = _engine(adapter, clock)
    trace = engine.verify_with_trace(make_request(), make_outcome())
    assert trace.result.status is V.UNABLE_TO_VERIFY
    assert trace.last_error is not None and trace.last_error.code is ErrorCode.INTERNAL
    assert "faketoken0123456789" not in json.dumps(trace.to_audit_payload())


def test_verify_attempting_a_guarded_call_is_unable_to_verify(clock):
    adapter = ScriptedVerifyAdapter([ApprovalRequiredError("no authorization context")], clock=clock)
    engine, _ = _engine(adapter, clock)
    trace = engine.verify_with_trace(make_request(), make_outcome())
    assert trace.result.status is V.UNABLE_TO_VERIFY
    assert trace.last_error is not None and trace.last_error.code is ErrorCode.APPROVAL_DENIED


def test_result_for_another_action_is_rejected(clock):
    other = make_request(target="TH-LT-2000")
    foreign = VerificationResult(idempotency_key=other.idempotency_key, status=V.VERIFIED,
                                 integration="secure_endpoint", method="read_state", checked_at=FIXED_NOW)
    adapter = ScriptedVerifyAdapter([foreign], clock=clock)
    engine, _ = _engine(adapter, clock)
    result = engine.verify(make_request(), make_outcome())
    assert result.status is V.UNABLE_TO_VERIFY


def test_adapter_returning_wrong_type_is_unable_to_verify(clock):
    adapter = ScriptedVerifyAdapter([V.VERIFIED], clock=clock)
    adapter.verify = lambda request, outcome: {"status": "VERIFIED"}  # type: ignore[method-assign]
    engine, _ = _engine(adapter, clock)
    assert engine.verify(make_request(), make_outcome()).status is V.UNABLE_TO_VERIFY


def test_undeclared_verify_capability_returns_immediately(clock):
    adapter = ScriptedVerifyAdapter([V.VERIFIED], clock=clock)
    engine, _ = _engine(adapter, clock)
    request = make_request(ActionType.RELEASE_ENDPOINT)  # not in verifiable_actions
    result = engine.verify(request, make_outcome())
    assert result.status is V.UNABLE_TO_VERIFY
    assert result.method == NO_VERIFY_METHOD
    assert "verify manually" in result.details
    assert adapter.calls == []


def test_missing_adapter_is_unable_to_verify(clock):
    adapter = ScriptedVerifyAdapter([V.VERIFIED], clock=clock)
    engine, _ = _engine(adapter, clock)
    request = make_request(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella")
    result = engine.verify(request, make_outcome("umbrella"))
    assert result.status is V.UNABLE_TO_VERIFY
    assert result.integration == "umbrella"


def test_disabled_adapter_is_unable_to_verify(clock):
    adapter = ScriptedVerifyAdapter([V.VERIFIED], clock=clock, enabled=False)
    engine, _ = _engine(adapter, clock)
    result = engine.verify(make_request(), make_outcome())
    assert result.status is V.UNABLE_TO_VERIFY
    assert "disabled" in result.details
    assert adapter.calls == []


def test_verify_integration_param_routes_native_xdr_actions(clock):
    entra = FakeEntraVerify([V.VERIFIED], clock=clock)
    engine = VerificationEngine(FakeRegistry(entra), VerificationSettings(), clock=clock,
                                sleep=FakeSleep(clock))
    request = make_request(ActionType.DISABLE_USER, "j.doe@example.com", "cisco_xdr",
                           verify_integration="entra")
    result = engine.verify(request, make_outcome("cisco_xdr"))
    assert result.status is V.VERIFIED
    assert result.integration == "entra"
    assert len(entra.calls) == 1


def test_already_contained_and_missing_outcome_are_passed_through(clock):
    adapter = ScriptedVerifyAdapter([V.VERIFIED], clock=clock)
    engine, _ = _engine(adapter, clock)
    already = make_outcome(status=ActionResultStatus.ALREADY_CONTAINED)
    engine.verify(make_request(), already)
    engine.verify(make_request(), None)
    assert [outcome for _, outcome in adapter.calls] == [already, None]


def test_bounded_even_if_clock_never_advances(clock):
    adapter = ScriptedVerifyAdapter([V.NOT_VERIFIED], clock=clock)
    policy = PollPolicy(interval_seconds=10, timeout_seconds=30, backoff_factor=1.0, max_interval_seconds=10)
    sleep = FakeSleep(None)  # does not advance the clock
    engine, _ = _engine(adapter, clock, policy=policy, sleep=sleep)
    result = engine.verify(make_request(), make_outcome())
    assert result.status is V.NOT_VERIFIED
    assert sum(sleep.calls) == pytest.approx(30.0)


def test_max_attempts_bound(clock):
    adapter = ScriptedVerifyAdapter([V.NOT_VERIFIED], clock=clock)
    policy = PollPolicy(interval_seconds=0, timeout_seconds=300, backoff_factor=1.0,
                        max_interval_seconds=0, max_attempts=3)
    engine, _ = _engine(adapter, clock, policy=policy)
    assert engine.verify(make_request(), make_outcome()).status is V.NOT_VERIFIED
    assert len(adapter.calls) == 3


def test_policy_comes_from_settings(clock):
    adapter = ScriptedVerifyAdapter([V.NOT_VERIFIED], clock=clock)
    sleep = FakeSleep(clock)
    engine = VerificationEngine(FakeRegistry(adapter),
                                VerificationSettings(poll_interval_seconds=2, timeout_seconds=5),
                                clock=clock, sleep=sleep)
    assert engine.policy.interval_seconds == 2
    assert engine.policy.timeout_seconds == 5
    engine.verify(make_request(), make_outcome())
    assert sum(sleep.calls) == pytest.approx(5.0)


def test_verification_works_in_dry_run_without_guard(clock):
    assert guard.is_dry_run()  # conftest default: fail-closed global dry run
    adapter = ScriptedVerifyAdapter([V.VERIFIED], clock=clock)
    engine, _ = _engine(adapter, clock)
    assert engine.verify(make_request(), make_outcome()).status is V.VERIFIED


def test_audit_payload_is_json_serializable(clock):
    adapter = ScriptedVerifyAdapter(
        [IntegrationUnavailableError("down", integration="secure_endpoint"), V.VERIFIED], clock=clock)
    engine, _ = _engine(adapter, clock)
    payload = engine.verify_with_trace(make_request(), make_outcome()).to_audit_payload()
    decoded = json.loads(json.dumps(payload))
    assert decoded["result"]["status"] == "VERIFIED"
    assert [a["attempt"] for a in decoded["attempts"]] == [1, 2]
    assert decoded["attempts"][0]["error"]["code"] == "UNAVAILABLE"
