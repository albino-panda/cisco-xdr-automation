"""Post-action verification engine (architecture sections 7 and 13.16).

``VerificationEngine.verify`` runs after every ``SUCCESS`` and ``ALREADY_CONTAINED`` action (and
after every restoration action). It only calls the adapter's read-only ``verify`` method, never
needs the execution guard, polls for eventual consistency and never raises: every problem becomes
``UNABLE_TO_VERIFY`` with the reason recorded as evidence.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.config.schema import VerificationSettings
from xdr_response.errors import ApprovalRequiredError, IntegrationError, RateLimitedError
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ApiCallSummary,
    ErrorCode,
    ErrorInfo,
    VerificationResult,
    VerificationStatus,
)
from xdr_response.verification.policy import PollPolicy

__all__ = [
    "AdapterLookup",
    "VerificationAttempt",
    "VerificationTrace",
    "VerificationEngine",
    "NO_VERIFY_METHOD",
    "resolve_verify_integration",
]

#: ``VerificationResult.method`` value meaning "no read-back call exists" (terminal, never polled).
NO_VERIFY_METHOD = "none"


class AdapterLookup(Protocol):
    """The part of ``AdapterRegistry`` the engine needs (``get`` raises ``KeyError`` if unknown)."""

    def get(self, name: str) -> Any:
        ...


@dataclass(frozen=True)
class VerificationAttempt:
    """One read-back attempt, kept as evidence for the audit trail (number 0 = no read made)."""

    number: int
    at: datetime
    status: VerificationStatus | None
    details: str = ""
    error: ErrorInfo | None = None

    def to_payload(self) -> dict[str, Any]:
        """JSON-safe dict for audit payloads (already redacted)."""
        return {
            "attempt": self.number,
            "at": self.at.isoformat(),
            "status": self.status.value if self.status else None,
            "details": self.details,
            "error": self.error.model_dump(mode="json") if self.error else None,
        }


@dataclass(frozen=True)
class VerificationTrace:
    """Final verification result plus every attempt that led to it."""

    result: VerificationResult
    attempts: tuple[VerificationAttempt, ...] = field(default_factory=tuple)
    timed_out: bool = False

    @property
    def last_error(self) -> ErrorInfo | None:
        """The most recent error seen while verifying, if any."""
        for attempt in reversed(self.attempts):
            if attempt.error is not None:
                return attempt.error
        return None

    def to_audit_payload(self) -> dict[str, Any]:
        """Payload for a ``VERIFICATION_RESULT`` audit record."""
        return {
            "result": self.result.model_dump(mode="json"),
            "attempts": [a.to_payload() for a in self.attempts],
            "timed_out": self.timed_out,
        }


def resolve_verify_integration(request: ActionRequest) -> str:
    """``params["verify_integration"]`` for native XDR actions, else ``params["integration"]``."""
    value = request.params.get("verify_integration")
    if isinstance(value, str) and value:
        return value
    return request.integration


def _redact(text: str) -> str:
    return get_redactor().redact_text(text)


def _error_info(exc: Exception, integration: str) -> ErrorInfo:
    if isinstance(exc, IntegrationError):
        return exc.to_error_info()
    if isinstance(exc, ApprovalRequiredError):
        return ErrorInfo(code=ErrorCode.APPROVAL_DENIED, integration=integration,
                         message=_redact(f"verify attempted a guarded call: {exc}"))
    return ErrorInfo(code=ErrorCode.INTERNAL, integration=integration,
                     message=_redact(f"{type(exc).__name__}: {exc}"))


class _Deadline:
    """Tracks elapsed time from both the injected clock and the injected sleep.

    Using the larger of the two keeps polling bounded even when a test clock never advances.
    """

    def __init__(self, clock: Clock, timeout: float) -> None:
        self._clock = clock
        self._start = clock.now()
        self._slept = 0.0
        self.timeout = timeout

    def elapsed(self) -> float:
        by_clock = (self._clock.now() - self._start).total_seconds()
        return max(by_clock, self._slept)

    def remaining(self) -> float:
        return max(0.0, self.timeout - self.elapsed())

    def add_sleep(self, seconds: float) -> None:
        self._slept += seconds


@dataclass(frozen=True)
class _Read:
    """Outcome of one read attempt (internal)."""

    result: VerificationResult | None
    attempt: VerificationAttempt
    terminal: bool
    retry_after: float | None = None


class VerificationEngine:
    """Verify that an executed action is in effect, by an independent read-only call."""

    def __init__(
        self,
        adapters: AdapterLookup,
        settings: VerificationSettings | None = None,
        *,
        clock: Clock | None = None,
        sleep: Callable[[float], None] | None = None,
        policy: PollPolicy | None = None,
    ) -> None:
        self._adapters = adapters
        self._settings = settings or VerificationSettings()
        self._clock: Clock = clock or DEFAULT_CLOCK
        self._sleep: Callable[[float], None] = sleep or time.sleep
        self.policy = policy or PollPolicy.from_settings(self._settings)

    # ----------------------------------------------------------------- public --
    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """Return VERIFIED / NOT_VERIFIED / UNABLE_TO_VERIFY for ``request``. Never raises."""
        return self.verify_with_trace(request, outcome).result

    def verify_with_trace(self, request: ActionRequest,
                          outcome: ActionOutcome | None) -> VerificationTrace:
        """Like :meth:`verify`, but also return every attempt as evidence. Never raises."""
        integration = "unknown"
        try:
            integration = resolve_verify_integration(request)
            adapter, reason = self._resolve_adapter(request, integration)
            if adapter is None:
                return self._immediate(request, integration, reason)
            return self._poll(adapter, request, outcome, integration)
        except Exception as exc:  # never raise out of the engine
            error = _error_info(exc, integration)
            return self._immediate(request, integration,
                                   f"verification error: {error.message}; verify manually", error=error)

    # ------------------------------------------------------------ resolution --
    def _resolve_adapter(self, request: ActionRequest, integration: str) -> tuple[Any | None, str]:
        try:
            adapter = self._adapters.get(integration)
        except KeyError:
            return None, f"no adapter registered for {integration}; verify manually"
        if not getattr(adapter, "enabled", False):
            return None, f"{integration} is disabled; verify manually"
        manifest = getattr(adapter, "manifest", None)
        verifiable = getattr(manifest, "verifiable_actions", frozenset())
        if request.action_type not in verifiable:
            return None, (f"{integration} has no verified read-back for "
                          f"{request.action_type.value}; verify manually")
        return adapter, ""

    def _immediate(self, request: ActionRequest, integration: str, details: str, *,
                   error: ErrorInfo | None = None) -> VerificationTrace:
        now = self._clock.now()
        result = VerificationResult(
            idempotency_key=request.idempotency_key,
            status=VerificationStatus.UNABLE_TO_VERIFY,
            integration=integration,
            method=NO_VERIFY_METHOD,
            checked_at=now,
            details=details,
        )
        attempt = VerificationAttempt(number=0, at=now, status=VerificationStatus.UNABLE_TO_VERIFY,
                                      details=details, error=error)
        return VerificationTrace(result=result, attempts=(attempt,))

    # --------------------------------------------------------------- polling --
    def _poll(self, adapter: Any, request: ActionRequest, outcome: ActionOutcome | None,
              integration: str) -> VerificationTrace:
        deadline = _Deadline(self._clock, self.policy.timeout_seconds)
        attempts: list[VerificationAttempt] = []
        api_calls: list[ApiCallSummary] = []
        number = 0
        while True:
            number += 1
            read = self._read(adapter, request, outcome, integration, number)
            attempts.append(read.attempt)
            if read.result is not None:
                api_calls.extend(read.result.api_calls)
            if read.terminal:
                return self._final(request, integration, read.result, attempts, api_calls,
                                   timed_out=False)
            if number >= self.policy.max_attempts or not self._wait(deadline, number, read.retry_after):
                return self._final(request, integration, read.result, attempts, api_calls,
                                   timed_out=True)

    def _read(self, adapter: Any, request: ActionRequest, outcome: ActionOutcome | None,
              integration: str, number: int) -> _Read:
        """One read-only verify call, converted into evidence."""
        try:
            result = adapter.verify(request, outcome)
            self._check_result(result, request)
        except Exception as exc:
            error = _error_info(exc, integration)
            retryable = isinstance(exc, IntegrationError) and exc.retryable
            retry_after = exc.retry_after if isinstance(exc, RateLimitedError) else None
            attempt = VerificationAttempt(number=number, at=self._clock.now(), status=None,
                                          details=error.message, error=error)
            return _Read(result=None, attempt=attempt, terminal=not retryable, retry_after=retry_after)
        attempt = VerificationAttempt(number=number, at=result.checked_at, status=result.status,
                                      details=_redact(result.details))
        return _Read(result=result, attempt=attempt, terminal=self._is_terminal(result))

    @staticmethod
    def _check_result(result: Any, request: ActionRequest) -> None:
        if not isinstance(result, VerificationResult):
            raise TypeError(f"adapter verify returned {type(result).__name__}, not VerificationResult")
        if result.idempotency_key != request.idempotency_key:
            raise ValueError("adapter verify returned a result for a different action")

    @staticmethod
    def _is_terminal(result: VerificationResult) -> bool:
        """VERIFIED is final; so is UNABLE_TO_VERIFY with no read-back method.

        NOT_VERIFIED and pending UNABLE_TO_VERIFY reads are retried until the deadline, because
        vendor state is eventually consistent. An adapter that knows better sets
        ``VerificationResult.terminal`` (for example a vendor action in a final ``Failed`` state).
        """
        if result.terminal is not None:
            return result.terminal
        if result.status is VerificationStatus.VERIFIED:
            return True
        return result.status is VerificationStatus.UNABLE_TO_VERIFY and result.method == NO_VERIFY_METHOD

    def _wait(self, deadline: _Deadline, number: int, retry_after: float | None) -> bool:
        """Sleep before the next read. False when the deadline does not allow another read."""
        remaining = deadline.remaining()
        if remaining <= 0:
            return False
        delay = self.policy.delay_after(number)
        if retry_after is not None:
            delay = max(delay, float(retry_after))
        delay = min(delay, remaining)
        if delay > 0:
            self._sleep(delay)
            deadline.add_sleep(delay)
        return True

    def _final(self, request: ActionRequest, integration: str, last: VerificationResult | None,
               attempts: list[VerificationAttempt], api_calls: list[ApiCallSummary], *,
               timed_out: bool) -> VerificationTrace:
        reads = len(attempts)
        if last is not None and last.status is not VerificationStatus.UNABLE_TO_VERIFY:
            status, method = last.status, last.method
            details = f"{_redact(last.details)} ({reads} read(s))".strip()
        else:
            status = VerificationStatus.UNABLE_TO_VERIFY
            method = last.method if last is not None else NO_VERIFY_METHOD
            details = self._unable_details(last, attempts, timed_out)
        result = VerificationResult(
            idempotency_key=request.idempotency_key,
            status=status,
            integration=integration,
            method=method,
            checked_at=self._clock.now(),
            details=details,
            api_calls=tuple(api_calls),
        )
        return VerificationTrace(result=result, attempts=tuple(attempts),
                                 timed_out=timed_out and status is not VerificationStatus.VERIFIED)

    @staticmethod
    def _unable_details(last: VerificationResult | None, attempts: list[VerificationAttempt],
                        timed_out: bool) -> str:
        reads = len(attempts)
        error = next((a.error for a in reversed(attempts) if a.error is not None), None)
        parts = []
        if timed_out:
            parts.append(f"no terminal state after {reads} read(s)")
        if error is not None:
            parts.append(f"last error {error.code.value}: {error.message}")
        elif last is not None and last.details:
            parts.append(_redact(last.details))
        parts.append("verify manually")
        return "; ".join(parts)
