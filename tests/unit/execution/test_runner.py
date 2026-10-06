"""ActionRunner: the guarded per-action pipeline (architecture section 6.2)."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from tests.unit.execution.execution_harness import (
    FAKE_SECRET,
    FIXED_NOW,
    expired_by,
    make_harness,
    make_package,
    make_recommendation,
    make_release_package,
    make_token,
)
from xdr_response import guard
from xdr_response.errors import (
    ApiError,
    ApprovalRequiredError,
    AuthFailedError,
    CapabilityNotSupportedError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    InvalidTargetError,
    RateLimitedError,
    UnverifiedEndpointError,
)
from xdr_response.execution import ExecutionPhase, SqliteExecutionStateStore
from xdr_response.models import (
    ActionRequest,
    ActionResultStatus as S,
    ActionType,
    AuditEventType as E,
    ErrorCode,
    SkipReason,
    TargetState,
    VerificationStatus as V,
)

ISOLATE = make_recommendation()  # XDR-83921:isolate_endpoint:TH-LT-1047 via secure_endpoint


@pytest.fixture
def h():
    return make_harness()


def _run(h, action=ISOLATE, package=None, token=None):
    package = package or make_package(action)
    token = token or h.approve(package)
    return h.runner.run(action, token, package=package, decision_id="decision-1")


def _dump(h) -> str:
    return json.dumps([p for _, p in h.audit.events], default=str)


# ------------------------------------------------------------------- success --
def test_success_executes_verifies_registers_and_audits(h):
    result = _run(h)
    assert result.status is S.SUCCESS
    assert result.verification is not None and result.verification.status is V.VERIFIED
    assert result.control_registered is True
    assert result.requires_attention is False
    assert h.se.calls == [ISOLATE.idempotency_key]
    assert h.se.state_calls == [ISOLATE.idempotency_key]
    assert h.verifier.mark_used_calls == 1
    assert h.audit.types() == [E.ACTION_STARTED, E.CONTROL_REGISTERED, E.ACTION_RESULT, E.VERIFICATION_RESULT]


def test_registered_control_carries_rollback_and_approval_data(h):
    package = make_package(ISOLATE)
    token = h.approve(package)
    h.runner.run(ISOLATE, token, package=package, decision_id="decision-1")
    control = h.registry.get(ISOLATE.idempotency_key)
    assert control is not None
    assert control.rollback_action_type is ActionType.RELEASE_ENDPOINT
    assert control.rollback_params == {"integration": "secure_endpoint", "vendor_object_id": "obj-1"}
    assert control.package_id == package.package_id
    assert control.token_id == token.token_id
    assert control.decision_id == "decision-1"
    assert control.external_ref == "ref-1"
    assert control.review_due_at == FIXED_NOW + timedelta(hours=24)


def test_already_in_desired_state_skips_the_write_and_registers_nothing(h):
    h.se.states[ISOLATE.idempotency_key] = [TargetState.IN_DESIRED_STATE]
    result = _run(h)
    assert result.status is S.ALREADY_CONTAINED
    assert h.se.calls == []
    assert h.registry.controls == {}
    assert result.control_registered is False
    assert h.verification.calls == [(ISOLATE.idempotency_key, S.ALREADY_CONTAINED)]


def test_adapter_reported_already_contained_registers_nothing(h):
    h.se.outcome_status[ISOLATE.idempotency_key] = S.ALREADY_CONTAINED
    result = _run(h)
    assert result.status is S.ALREADY_CONTAINED
    assert h.registry.controls == {}


def test_non_reversible_action_creates_no_control(h):
    revoke = make_recommendation(ActionType.REVOKE_SESSIONS, "j.doe@example.com", "entra")
    result = _run(h, revoke)
    assert result.status is S.SUCCESS
    assert h.registry.controls == {}


def test_release_action_runs_through_same_pipeline_without_registering(h):
    release = make_recommendation(ActionType.RELEASE_ENDPOINT, restores=ISOLATE.idempotency_key)
    package = make_release_package(release)
    token = h.approve(package)
    result = h.runner.run(release, token, package=package, decision_id="decision-r")
    assert result.status is S.SUCCESS
    assert h.registry.controls == {}


# ------------------------------------------------------------ not executed --
def test_action_without_grant_is_skipped_as_rejected(h):
    block = make_recommendation(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella")
    package = make_package(ISOLATE, block)
    token = h.approve(package, ISOLATE.idempotency_key)
    result = h.runner.run(block, token, package=package, decision_id="d")
    assert result.status is S.SKIPPED and result.skip_reason is SkipReason.REJECTED_BY_ANALYST
    assert result.requires_attention is False
    assert h.umbrella.calls == [] and h.umbrella.state_calls == []
    assert h.store.get(package.package_id, block.idempotency_key) is None


@pytest.mark.parametrize("enabled, reason", [(None, SkipReason.NO_CAPABLE_ADAPTER),
                                             (False, SkipReason.INTEGRATION_DISABLED)])
def test_missing_or_disabled_integration_is_skipped(h, enabled, reason):
    if enabled is None:
        del h.adapters.by_name["secure_endpoint"]
    else:
        h.se.config = h.se.config.model_copy(update={"enabled": False})
    result = _run(h)
    assert result.status is S.SKIPPED and result.skip_reason is reason
    assert result.requires_attention is True
    assert h.se.calls == []
    assert h.verifier.mark_used_calls == 0


def test_audit_failure_before_execution_blocks_the_action(h):
    h.audit.fail_on.add(E.ACTION_STARTED)
    result = _run(h)
    assert result.status is S.FAILED
    assert result.error is not None and result.error.code is ErrorCode.AUDIT_UNAVAILABLE
    assert h.se.calls == []
    assert h.verifier.mark_used_calls == 0


def test_dry_run_refuses_before_claiming(h):
    guard.configure(dry_run=True)
    package = make_package(ISOLATE)
    result = _run(h, package=package)
    assert result.status is S.FAILED and result.error.code is ErrorCode.DRY_RUN
    assert h.se.calls == []
    assert h.store.get(package.package_id, ISOLATE.idempotency_key) is None


def test_per_run_dry_run_context_also_refuses(h):
    with guard.dry_run():
        result = _run(h)
    assert result.error is not None and result.error.code is ErrorCode.DRY_RUN
    assert h.se.calls == []


def test_expired_token_is_denied_by_the_guard(h):
    package = make_package(ISOLATE)
    token = h.approve(package)
    expired_by(h)
    result = h.runner.run(ISOLATE, token, package=package, decision_id="d")
    assert result.status is S.FAILED and result.error.code is ErrorCode.APPROVAL_DENIED
    assert h.se.calls == [] and h.se.state_calls == []


def test_token_for_different_params_is_denied(h):
    package = make_package(ISOLATE)
    other = make_recommendation(connector_guid="fake-guid-0001")  # same key, different params hash
    token = make_token(other)
    token = token.model_copy(update={"claims": token.claims.model_copy(
        update={"package_id": package.package_id})})
    result = h.runner.run(ISOLATE, token, package=package, decision_id="d")
    assert result.status is S.FAILED and result.error.code is ErrorCode.APPROVAL_DENIED
    assert h.se.calls == []


def test_no_verifier_registered_denies(h):
    guard.unregister_verifier()
    result = _run(h)
    assert result.status is S.FAILED and result.error.code is ErrorCode.APPROVAL_DENIED
    assert h.se.calls == []


def test_action_outside_package_fails_without_execution(h):
    other = make_recommendation(target="TH-LT-2001")
    package = make_package(ISOLATE)
    token = make_token(other)
    result = h.runner.run(other, token, package=package, decision_id="d")
    assert result.status is S.FAILED and result.error.code is ErrorCode.INTERNAL
    assert h.se.calls == []


def test_state_store_failure_fails_closed(h):
    class Broken:
        def begin(self, **kw):
            raise OSError("disk full")

    runner = h.new_runner(store=Broken())  # type: ignore[arg-type]
    package = make_package(ISOLATE)
    result = runner.run(ISOLATE, h.approve(package), package=package, decision_id="d")
    assert result.status is S.FAILED and result.error.code is ErrorCode.INTERNAL
    assert h.se.calls == []


# ------------------------------------------------------------ error mapping --
@pytest.mark.parametrize("exc, code", [
    (RateLimitedError("slow down", integration="secure_endpoint", retry_after=30), ErrorCode.RATE_LIMITED),
    (AuthFailedError("forbidden", integration="secure_endpoint", http_status=403), ErrorCode.AUTH_FAILED),
    (IntegrationUnavailableError("503", integration="secure_endpoint"), ErrorCode.UNAVAILABLE),
    (InvalidTargetError("no such host", integration="secure_endpoint", http_status=404),
     ErrorCode.INVALID_TARGET),
    (ApiError("bad request", integration="secure_endpoint", http_status=409), ErrorCode.API_ERROR),
    (UnverifiedEndpointError("secure_endpoint", "isolate_endpoint"), ErrorCode.UNVERIFIED_ENDPOINT),
    (CapabilityNotSupportedError("nope", integration="secure_endpoint"), ErrorCode.NOT_SUPPORTED),
    (RuntimeError("boom"), ErrorCode.INTERNAL),
])
def test_adapter_errors_map_to_failed_results(h, exc, code):
    h.se.errors[ISOLATE.idempotency_key] = exc
    result = _run(h)
    assert result.status is S.FAILED
    assert result.error is not None and result.error.code is code
    assert result.requires_attention is True
    assert result.verification is None
    assert h.registry.controls == {}
    assert h.audit.types()[-1] is E.ACTION_RESULT


def test_failure_carries_the_manifest_escalation_hint(h):
    revoke = make_recommendation(ActionType.REVOKE_SESSIONS, "j.doe@example.com", "entra")
    h.entra.errors[revoke.idempotency_key] = AuthFailedError("forbidden", integration="entra", http_status=403)
    result = _run(h, revoke)
    assert result.error.http_status == 403
    assert result.recommended_escalation == "Microsoft 365 administrator"


def test_write_timeout_with_unknown_state_is_failed_not_retried(h):
    h.se.errors[ISOLATE.idempotency_key] = IntegrationTimeoutError("read timeout", integration="secure_endpoint")
    h.se.states[ISOLATE.idempotency_key] = [TargetState.NOT_IN_DESIRED_STATE, TargetState.UNKNOWN]
    result = _run(h)
    assert result.status is S.FAILED and result.error.code is ErrorCode.TIMEOUT
    assert h.se.calls == [ISOLATE.idempotency_key]  # exactly one write attempt
    assert len(h.se.state_calls) == 2  # pre-check + re-check
    assert "verify manually" in result.message


def test_write_timeout_confirmed_by_recheck_is_success_needing_review(h):
    h.se.errors[ISOLATE.idempotency_key] = IntegrationTimeoutError("read timeout", integration="secure_endpoint")
    h.se.states[ISOLATE.idempotency_key] = [TargetState.NOT_IN_DESIRED_STATE, TargetState.IN_DESIRED_STATE]
    result = _run(h)
    assert result.status is S.SUCCESS
    assert result.requires_attention is True
    control = h.registry.get(ISOLATE.idempotency_key)
    assert control is not None and control.rollback_params == {"integration": "secure_endpoint"}


def test_failing_state_precheck_does_not_block_execution(h):
    h.se.state_errors[ISOLATE.idempotency_key] = IntegrationUnavailableError("down", integration="secure_endpoint")
    result = _run(h)
    assert result.status is S.SUCCESS
    assert h.se.calls == [ISOLATE.idempotency_key]
    assert result.requires_attention is True


# ------------------------------------------------------------- verification --
@pytest.mark.parametrize("status", [V.NOT_VERIFIED, V.UNABLE_TO_VERIFY])
def test_unconfirmed_verification_requires_attention(h, status):
    h.verification.statuses[ISOLATE.idempotency_key] = status
    result = _run(h)
    assert result.status is S.SUCCESS
    assert result.verification.status is status
    assert result.requires_attention is True
    assert result.control_registered is True  # the control exists at the vendor either way


def test_verifier_exception_becomes_unable_to_verify(h):
    h.verification.raise_for.add(ISOLATE.idempotency_key)
    result = _run(h)
    assert result.verification.status is V.UNABLE_TO_VERIFY
    assert FAKE_SECRET not in result.verification.details


def test_registry_failure_is_flagged_and_audited(h):
    h.registry.fail = True
    result = _run(h)
    assert result.status is S.SUCCESS
    assert result.control_registered is False
    assert result.requires_attention is True
    assert "record it manually" in result.message
    assert E.ERROR in h.audit.types()


def test_result_audit_failure_marks_attention(h):
    h.audit.fail_on.add(E.ACTION_RESULT)
    result = _run(h)
    assert result.status is S.SUCCESS
    assert result.requires_attention is True


# ---------------------------------------------------------- double execution --
def test_second_run_of_same_package_replays_without_vendor_call(h):
    package = make_package(ISOLATE)
    token = h.approve(package)
    first = h.runner.run(ISOLATE, token, package=package, decision_id="d")
    second = h.runner.run(ISOLATE, token, package=package, decision_id="d")
    assert first.status is second.status is S.SUCCESS
    assert "replayed" in second.message
    assert h.se.calls == [ISOLATE.idempotency_key]
    assert h.verifier.mark_used_calls == 1
    assert h.audit.of(E.ACTION_RESULT)[-1]["replayed"] is True


def test_unfinished_previous_attempt_is_never_resent(h):
    package = make_package(ISOLATE)
    token = h.approve(package)
    h.store.begin(package_id=package.package_id, idempotency_key=ISOLATE.idempotency_key,
                  incident_id=ISOLATE.incident_id, token_id=token.token_id, at=FIXED_NOW)
    result = h.runner.run(ISOLATE, token, package=package, decision_id="d")
    assert result.status is S.FAILED and result.error.code is ErrorCode.INTERNAL
    assert "outcome unknown" in result.message
    assert h.se.calls == []


def test_sqlite_store_prevents_reexecution_after_restart(h, tmp_path):
    path = tmp_path / "exec.db"
    package = make_package(ISOLATE)
    token = h.approve(package)
    first_store = SqliteExecutionStateStore(path)
    h.new_runner(store=first_store).run(ISOLATE, token, package=package, decision_id="d")
    first_store.close()
    second_store = SqliteExecutionStateStore(path)
    try:
        result = h.new_runner(store=second_store).run(ISOLATE, token, package=package, decision_id="d")
        assert result.status is S.SUCCESS and "replayed" in result.message
        assert h.se.calls == [ISOLATE.idempotency_key]
        record = second_store.get(package.package_id, ISOLATE.idempotency_key)
        assert record is not None and record.phase is ExecutionPhase.COMPLETED
    finally:
        second_store.close()


# ------------------------------------------------------------------ secrets --
def test_results_and_audit_never_contain_secrets_or_token_signature(h):
    package = make_package(ISOLATE)
    token = h.approve(package)
    signed = token.model_copy(update={"signature": "f" * 64})
    result = h.runner.run(ISOLATE, signed, package=package, decision_id="d")
    dumped = result.model_dump_json() + _dump(h)
    assert FAKE_SECRET not in dumped
    assert "abcdefghijklmnop0123456789" not in dumped  # bearer value in the adapter message
    assert "f" * 64 not in dumped
    assert result.api_calls and result.api_calls[0].request_summary["api_key"] == "[REDACTED]"
    assert token.token_id in dumped  # the token id is fine to audit


def test_adapter_write_method_is_unreachable_outside_the_guard(h):
    request = ActionRequest.from_recommendation(ISOLATE)
    with pytest.raises(ApprovalRequiredError):
        h.se.isolate_endpoint(request)
    with pytest.raises(ApprovalRequiredError):
        h.se.execute(request)
    assert h.se.calls == []


def test_unexpected_pipeline_error_still_closes_the_claim(h):
    class ExplodingAdapters:
        def get(self, name):
            raise ValueError("adapter construction failed")

    runner = h.new_runner()
    runner._adapters = ExplodingAdapters()  # type: ignore[attr-defined]
    package = make_package(ISOLATE)
    result = runner.run(ISOLATE, h.approve(package), package=package, decision_id="d")
    assert result.status is S.FAILED and result.error.code is ErrorCode.INTERNAL
    record = h.store.get(package.package_id, ISOLATE.idempotency_key)
    assert record is not None and record.phase is ExecutionPhase.COMPLETED
