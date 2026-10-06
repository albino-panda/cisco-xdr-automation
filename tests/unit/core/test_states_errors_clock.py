"""Lifecycle transition table, typed errors and the injectable clock."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from xdr_response import FRAMEWORK_VERSION, __version__
from xdr_response.clock import DEFAULT_CLOCK, Clock, FixedClock, SystemClock, utc
from xdr_response.errors import (
    ApiError,
    ApprovalError,
    ApprovalRequiredError,
    ApproverNotAllowedError,
    AuthFailedError,
    CapabilityNotSupportedError,
    DryRunViolationError,
    IntegrationError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    InvalidTargetError,
    InvalidTransitionError,
    RateLimitedError,
    SecretNotFoundError,
    TokenExpiredError,
    TokenInvalidError,
    TokenMismatchError,
    TokenReplayError,
    UnverifiedEndpointError,
    XdrResponseError,
    unverified,
)
from xdr_response.lifecycle import states as lifecycle_states
from xdr_response.logs import get_redactor
from xdr_response.models import (
    ALLOWED_TRANSITIONS,
    TOKEN_REQUIRED,
    ApprovalPurpose,
    ErrorCode,
    IncidentState,
    can_transition,
)

S = IncidentState


def test_version():
    assert __version__ == "0.1.0" and FRAMEWORK_VERSION == __version__


# ------------------------------------------------------------------- states --
def test_transition_table_covers_every_state_with_exact_names():
    assert set(ALLOWED_TRANSITIONS) == set(IncidentState)
    assert [s.value for s in IncidentState] == [
        "NOT_STARTED", "AWAITING_APPROVAL", "APPROVED", "CONTAINMENT_RUNNING", "CONTAINED",
        "PARTIALLY_CONTAINED", "CONTAINMENT_FAILED", "REMEDIATION_REQUIRED", "AWAITING_RELEASE_APPROVAL",
        "RESTORATION_RUNNING", "RESTORED", "CLOSED"]
    for targets in ALLOWED_TRANSITIONS.values():
        assert isinstance(targets, frozenset)
    with pytest.raises(TypeError):
        ALLOWED_TRANSITIONS[S.CLOSED] = frozenset()  # type: ignore[index]


@pytest.mark.parametrize(("a", "b"), [
    (S.NOT_STARTED, S.AWAITING_APPROVAL), (S.AWAITING_APPROVAL, S.APPROVED),
    (S.APPROVED, S.CONTAINMENT_RUNNING), (S.CONTAINMENT_RUNNING, S.PARTIALLY_CONTAINED),
    (S.CONTAINED, S.AWAITING_RELEASE_APPROVAL), (S.AWAITING_RELEASE_APPROVAL, S.RESTORATION_RUNNING),
    (S.RESTORATION_RUNNING, S.RESTORED), (S.RESTORED, S.CLOSED), (S.CLOSED, S.AWAITING_RELEASE_APPROVAL),
    (S.AWAITING_APPROVAL, S.NOT_STARTED), (S.AWAITING_RELEASE_APPROVAL, S.REMEDIATION_REQUIRED),
])
def test_allowed_transitions(a, b):
    assert can_transition(a, b)


@pytest.mark.parametrize(("a", "b"), [
    (S.NOT_STARTED, S.APPROVED),                 # approval cannot be skipped
    (S.NOT_STARTED, S.CONTAINMENT_RUNNING),      # containment cannot start unapproved
    (S.AWAITING_APPROVAL, S.CONTAINMENT_RUNNING),
    (S.CONTAINED, S.RESTORATION_RUNNING),        # release needs its own approval
    (S.CONTAINED, S.RESTORED),
    (S.CLOSED, S.RESTORATION_RUNNING),
    (S.CLOSED, S.CONTAINED),
    (S.RESTORATION_RUNNING, S.CLOSED),
])
def test_forbidden_transitions(a, b):
    assert not can_transition(a, b)


def test_state_changing_states_require_tokens():
    assert dict(TOKEN_REQUIRED) == {S.APPROVED: ApprovalPurpose.CONTAINMENT,
                                    S.RESTORATION_RUNNING: ApprovalPurpose.RELEASE}
    # the only way into a running state is through the token-gated state
    for src, targets in ALLOWED_TRANSITIONS.items():
        if S.CONTAINMENT_RUNNING in targets:
            assert src is S.APPROVED
        if S.APPROVED in targets:
            assert src is S.AWAITING_APPROVAL
        if S.RESTORATION_RUNNING in targets:
            assert src is S.AWAITING_RELEASE_APPROVAL


def test_lifecycle_states_reexport():
    assert lifecycle_states.ALLOWED_TRANSITIONS is ALLOWED_TRANSITIONS
    assert lifecycle_states.can_transition is can_transition
    assert not can_transition("BOGUS", S.CLOSED)  # type: ignore[arg-type]


# ------------------------------------------------------------------- errors --
def test_error_hierarchy():
    assert issubclass(DryRunViolationError, ApprovalRequiredError)
    for cls in (TokenInvalidError, TokenExpiredError, TokenMismatchError, TokenReplayError):
        assert issubclass(cls, ApprovalRequiredError)
    assert issubclass(TokenExpiredError, TokenInvalidError)
    assert issubclass(ApproverNotAllowedError, ApprovalError)
    assert not issubclass(ApproverNotAllowedError, ApprovalRequiredError)
    assert issubclass(UnverifiedEndpointError, NotImplementedError)
    assert issubclass(UnverifiedEndpointError, IntegrationError)
    for cls in (ApprovalError, IntegrationError, InvalidTransitionError, SecretNotFoundError):
        assert issubclass(cls, XdrResponseError)


def test_error_codes():
    expected = {
        IntegrationTimeoutError: ErrorCode.TIMEOUT, RateLimitedError: ErrorCode.RATE_LIMITED,
        AuthFailedError: ErrorCode.AUTH_FAILED, IntegrationUnavailableError: ErrorCode.UNAVAILABLE,
        InvalidTargetError: ErrorCode.INVALID_TARGET, ApiError: ErrorCode.API_ERROR,
        CapabilityNotSupportedError: ErrorCode.NOT_SUPPORTED,
    }
    for cls, code in expected.items():
        err = cls("boom", integration="umbrella")
        assert err.code is code and err.integration == "umbrella"
        assert err.to_error_info().code is code
    rl = RateLimitedError("slow down", integration="virustotal", retry_after=15.0)
    assert rl.retry_after == 15.0 and rl.retryable and rl.http_status == 429


def test_unverified_message_exact():
    with pytest.raises(UnverifiedEndpointError) as exc:
        unverified("secure_endpoint", "block_hash")
    assert str(exc.value) == "unverified endpoint: secure_endpoint.block_hash - see docs/integrations.md"
    assert exc.value.code is ErrorCode.UNVERIFIED_ENDPOINT
    with pytest.raises(NotImplementedError):
        unverified("umbrella", "block_ip")


def test_error_info_is_redacted():
    get_redactor().register_secret("sekrit-value-123456")
    err = AuthFailedError("token sekrit-value-123456 rejected; Authorization: Bearer abcdefghijkl",
                          integration="cisco_xdr", http_status=403)
    info = err.to_error_info()
    assert "sekrit-value-123456" not in info.message and "abcdefghijkl" not in info.message
    assert info.http_status == 403 and info.integration == "cisco_xdr"


def test_secret_not_found_and_invalid_transition_messages():
    assert "XDR_CLIENT_SECRET" in str(SecretNotFoundError("XDR_CLIENT_SECRET"))
    err = InvalidTransitionError(S.NOT_STARTED, S.APPROVED, "approval required")
    assert str(err) == "invalid incident state transition NOT_STARTED -> APPROVED: approval required"
    assert err.from_state is S.NOT_STARTED


# -------------------------------------------------------------------- clock --
def test_fixed_clock():
    start = datetime(2026, 1, 15, 13, 0, tzinfo=timezone(timedelta(hours=1)))
    clock = FixedClock(start)
    assert clock.now() == datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
    assert clock.now().tzinfo == timezone.utc
    clock.advance(timedelta(minutes=5))
    assert clock.now().minute == 5
    clock.set(datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert clock.now().month == 2
    with pytest.raises(ValueError):
        FixedClock(datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        clock.set(datetime(2026, 1, 1))
    assert isinstance(clock, Clock) and isinstance(DEFAULT_CLOCK, SystemClock)


def test_system_clock_and_utc():
    now = SystemClock().now()
    assert now.tzinfo is not None and now.utcoffset() == timedelta(0)
    with pytest.raises(ValueError):
        utc(datetime(2026, 1, 1))
