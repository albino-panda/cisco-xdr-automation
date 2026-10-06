"""Guarded HTTP client used by every adapter (architecture sections 6.6 and 13.13).

* Timeouts, retry with exponential backoff and jitter, token-bucket rate limiting. ``sleep``,
  the clock and the jitter source are injectable so tests are deterministic.
* HTTP failures are mapped to the typed errors of :mod:`xdr_response.errors`.
* The mutating path is guarded: a request of kind ``STATE_CHANGING`` calls
  :func:`xdr_response.guard.require_active_authorization` before *every* attempt, so it is
  refused outside an approved authorization context and while dry run is active, even when an
  adapter calls the client directly. ``PUT``/``PATCH``/``DELETE`` are always ``STATE_CHANGING``
  (never ``READ``, ``VERIFY`` or ``BOOKKEEPING``), and ``BOOKKEEPING`` requests are ``POST`` only
  and limited to ``BOOKKEEPING_OPERATIONS``.
* The declared kind is not trusted on its own: a client owned by an adapter carries the adapter's
  capability ``manifest`` (attached by ``IntegrationAdapter``), and every request is checked
  against it (the operation must exist, the HTTP method and the kind must match the manifest
  row). A manifest STATE_CHANGING operation can therefore never be sent as READ to dodge the guard.
* The URL is checked too: the request path (and the host, for an absolute URL) must match the
  manifest row's documented path template (``{name}`` matches one path segment), relative to the
  host or to the base URL. An operation without a documented path cannot be sent. So a VERIFIED
  vendor write URL can never be sent under a READ / VERIFY / BOOKKEEPING operation name.
* A client without a manifest (not owned by an adapter) still knows the integration's registered
  manifest: a non-STATE_CHANGING request whose method and URL match one of that manifest's
  STATE_CHANGING operations is refused, so building a fresh client cannot dodge the guard either.
* Error excerpts from vendor bodies are redacted *before* they are truncated, so a secret that
  straddles the excerpt boundary can never leak a partial value.
* State-changing requests are never retried blindly: only when the request provably did not
  reach the server (connect error), on ``429``, and on ``503`` with ``Retry-After``.
* Every attempt produces a redacted :class:`ApiCallSummary`; with an audit sink it is appended as
  ``API_CALL``. Raised :class:`IntegrationError` instances carry ``api_calls`` (all attempts).
"""
from __future__ import annotations

import importlib
import json as _json
import random
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
from functools import lru_cache
from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic import Field

from xdr_response import guard
from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.errors import (
    ApiError,
    AuditError,
    AuthFailedError,
    IntegrationError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    InvalidTargetError,
    RateLimitedError,
)
from xdr_response.interfaces import AuditSink
from xdr_response.logs.redaction import Redactor, get_redactor
from xdr_response.logs.setup import get_logger, protect_third_party_loggers
from xdr_response.models import (
    BOOKKEEPING_OPERATIONS,
    INTEGRATION_NAMES,
    ApiCallSummary,
    AuditEventType,
    FrozenModel,
    OperationKind,
)

__all__ = [
    "RetryPolicy",
    "RateLimiter",
    "HttpResult",
    "GuardedHttpClient",
    "SupportsAuth",
    "parse_retry_after",
    "MUTATING_METHODS",
    "READ_ONLY_KINDS",
]

_log = get_logger("integrations.http")
protect_third_party_loggers()  # httpx logs every request URL at INFO outside the xdr_response tree

#: HTTP methods that may never be declared as a READ or VERIFY operation.
MUTATING_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
#: Operation kinds that must not change vendor state.
READ_ONLY_KINDS = frozenset({OperationKind.READ, OperationKind.VERIFY})
_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"})
_ERROR_EXCERPT = 200
#: Bytes of a vendor error body that are redacted before the excerpt is cut (bounds the work).
_ERROR_REDACT_WINDOW = 64 * 1024


@runtime_checkable
class SupportsAuth(Protocol):
    """Structural type of ``integrations.auth.AuthProvider`` (kept local to avoid a hard import)."""

    def apply(self, request: httpx.Request) -> None:
        ...

    def invalidate(self) -> None:
        ...


class ManifestLike(Protocol):
    """Structural type of ``integrations.base.CapabilityManifest`` (only ``operation`` is used)."""

    def operation(self, name: str) -> Any:  # KeyError when unknown
        ...


# ------------------------------------------------------------------ retry --
class RetryPolicy(FrozenModel):
    """Retry and backoff settings. ``max_retries`` counts retries after the first attempt."""

    max_retries: int = Field(default=3, ge=0, le=10)
    backoff_base: float = Field(default=1.0, ge=0)
    backoff_max: float = Field(default=30.0, ge=0)
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504)
    jitter: bool = True

    def backoff(self, retry_number: int, rand: Callable[[], float] = random.random) -> float:
        """Delay before retry ``retry_number`` (1-based): exponential, capped, "equal jitter"."""
        if retry_number < 1:
            raise ValueError("retry_number starts at 1")
        delay = min(self.backoff_max, self.backoff_base * (2 ** (retry_number - 1)))
        if not self.jitter or delay <= 0:
            return delay
        return delay / 2 + rand() * delay / 2


def parse_retry_after(value: str | None, now: datetime) -> float | None:
    """Seconds from a ``Retry-After`` header (delta seconds or HTTP date); None if absent/invalid."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None or when.tzinfo is None:
            return None
        seconds = (when - now).total_seconds()
    if seconds != seconds:  # NaN
        return None
    return max(0.0, seconds)


# ------------------------------------------------------------- rate limit --
class RateLimiter:
    """Thread-safe token bucket: ``rate_per_minute`` tokens per minute, burst of the same size.

    Time is read from the injected clock and waiting goes through the injected ``sleep``. After a
    wait the bucket is advanced by the waited time even if the clock did not move, so a fixed
    clock with a recording ``sleep`` gives deterministic tests.
    """

    def __init__(self, rate_per_minute: int | None, *, clock: Clock | None = None,
                 sleep: Callable[[float], None] | None = None) -> None:
        if rate_per_minute is not None and rate_per_minute < 1:
            raise ValueError("rate_per_minute must be >= 1 or None")
        self.rate_per_minute = rate_per_minute
        self._clock = clock or DEFAULT_CLOCK
        self._sleep = sleep or time.sleep
        self._capacity = float(rate_per_minute or 0)
        self._tokens = self._capacity
        self._updated: datetime | None = None
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.rate_per_minute is not None

    def acquire(self) -> float:
        """Take one token, sleeping if needed. Returns the seconds waited (0 when no limit)."""
        if self.rate_per_minute is None:
            return 0.0
        with self._lock:
            self._refill()
            if self._tokens >= 1:
                self._tokens -= 1
                return 0.0
            per_second = self.rate_per_minute / 60.0
            wait = (1 - self._tokens) / per_second
            self._sleep(wait)
            assert self._updated is not None
            self._updated = max(self._clock.now(), self._updated + timedelta(seconds=wait))
            self._tokens = 0.0
            return wait

    def _refill(self) -> None:
        now = self._clock.now()
        if self._updated is None:
            self._updated = now
            return
        elapsed = (now - self._updated).total_seconds()
        if elapsed <= 0:
            return
        assert self.rate_per_minute is not None
        self._tokens = min(self._capacity, self._tokens + elapsed * self.rate_per_minute / 60.0)
        self._updated = now


# ----------------------------------------------------------------- result --
class HttpResult(FrozenModel):
    """Successful response. ``headers`` are redacted; ``body`` and ``text`` are raw vendor data,
    never logged or audited and hidden from ``repr`` (tracebacks, debug output)."""

    status_code: int
    headers: dict[str, str]
    body: Any = Field(default=None, repr=False)
    text: str = Field(default="", repr=False)
    summary: ApiCallSummary
    attempts: tuple[ApiCallSummary, ...] = ()


@dataclass(frozen=True)
class _Verdict:
    """What to do after one attempt."""

    error: IntegrationError | None = None
    retry: bool = False
    delay: float = 0.0
    reauth: bool = False


# ----------------------------------------------------------------- client --
class GuardedHttpClient:
    """httpx-based client with guard enforcement, retries, rate limiting and audit summaries."""

    def __init__(
        self,
        integration: str,
        base_url: str,
        *,
        timeout: float = 15.0,
        retry: RetryPolicy | None = None,
        rate_limiter: RateLimiter | None = None,
        auth: SupportsAuth | None = None,
        default_headers: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        redactor: Redactor | None = None,
        clock: Clock | None = None,
        sleep: Callable[[float], None] | None = None,
        audit: AuditSink | None = None,
        rand: Callable[[], float] | None = None,
        monotonic: Callable[[], float] | None = None,
        manifest: ManifestLike | None = None,
    ) -> None:
        if not integration:
            raise ValueError("integration is required")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.integration = integration
        self.base_url = base_url
        self.timeout = timeout
        self.retry = retry or RetryPolicy()
        self.rate_limiter = rate_limiter
        self.auth = auth
        self.default_headers = dict(default_headers or {})
        self.redactor = redactor or get_redactor()
        self.clock = clock or DEFAULT_CLOCK
        self.sleep = sleep or time.sleep
        self.audit = audit
        #: Capability manifest of the owning adapter; when set, every request is checked against it.
        self.manifest: ManifestLike | None = manifest
        self._rand = rand or random.random
        self._monotonic = monotonic or time.monotonic
        self._client = httpx.Client(base_url=base_url, timeout=httpx.Timeout(timeout),
                                    transport=transport, follow_redirects=False)

    # ---------------------------------------------------------- shortcuts --
    def get(self, url: str, *, kind: OperationKind = OperationKind.READ, operation: str,
            **kw: Any) -> HttpResult:
        return self.request("GET", url, kind=kind, operation=operation, **kw)

    def post(self, url: str, *, kind: OperationKind, operation: str, **kw: Any) -> HttpResult:
        """POST. ``kind`` is mandatory: a search POST is READ, a write is STATE_CHANGING."""
        return self.request("POST", url, kind=kind, operation=operation, **kw)

    def put(self, url: str, *, operation: str, kind: OperationKind = OperationKind.STATE_CHANGING,
            **kw: Any) -> HttpResult:
        return self.request("PUT", url, kind=kind, operation=operation, **kw)

    def patch(self, url: str, *, operation: str, kind: OperationKind = OperationKind.STATE_CHANGING,
              **kw: Any) -> HttpResult:
        return self.request("PATCH", url, kind=kind, operation=operation, **kw)

    def delete(self, url: str, *, operation: str, kind: OperationKind = OperationKind.STATE_CHANGING,
               **kw: Any) -> HttpResult:
        return self.request("DELETE", url, kind=kind, operation=operation, **kw)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GuardedHttpClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------ request --
    def _check_url(self, method: str, target: httpx.URL, kind: OperationKind, operation: str) -> None:
        """The URL must be the documented path of the declared operation (see the module docstring)."""
        base = self._client.base_url
        manifest = self.manifest
        if manifest is not None:
            spec = manifest.operation(operation)  # existence already checked by _check_manifest
            template = getattr(spec, "path", None)
            if not template:
                raise ValueError(f"{self.integration}.{operation} has no documented path in the manifest; "
                                 "it cannot be sent")
            if not url_matches_template(str(template), target, base):
                raise ValueError(f"{self.integration}.{operation}: URL path {target.path!r} is not the "
                                 f"manifest path of this operation ({template})")
            return
        if kind is OperationKind.STATE_CHANGING:
            return  # guarded by require_active_authorization
        registered = _registered_manifest(self.integration)
        if registered is None:
            return
        for spec in getattr(registered, "operations", ()):
            if OperationKind(spec.kind) is not OperationKind.STATE_CHANGING or not spec.path:
                continue
            if spec.method and str(spec.method).upper() != method:
                continue
            if url_matches_template(str(spec.path), target, base):
                raise ValueError(f"{self.integration}.{operation}: {method} {target.path!r} is the "
                                 f"state-changing operation {spec.name!r} of the {self.integration} "
                                 f"manifest; it cannot be sent as {kind.value}")

    def request(
        self,
        method: str,
        url: str,
        *,
        kind: OperationKind,
        operation: str,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        data: Mapping[str, Any] | str | None = None,
        headers: Mapping[str, str] | None = None,
        expected: tuple[int, ...] = (200, 201, 202, 204),
    ) -> HttpResult:
        """Send one logical request (with retries). Raises a typed :class:`IntegrationError`."""
        method = self._check_call(method, kind, operation)
        probe = self._probe(method, url, params=params, json=json, data=data)
        self._check_url(method, probe.url, kind, operation)
        if kind is not OperationKind.STATE_CHANGING:
            return self._send_logical(method, url, kind=kind, operation=operation, params=params,
                                      json=json, data=data, headers=headers, expected=expected)
        with guard.write_window(self.integration, lambda req: _carries_target(probe, req.target),
                                self._action_types(operation)):
            return self._send_logical(method, url, kind=kind, operation=operation, params=params,
                                      json=json, data=data, headers=headers, expected=expected)

    def _probe(self, method: str, url: str, *, params: Mapping[str, Any] | None, json: Any,
               data: Mapping[str, Any] | str | None) -> httpx.Request:
        """The request as it would be sent (no auth applied, nothing sent): used by the checks."""
        kwargs: dict[str, Any] = {"params": dict(params) if params else None}
        if json is not None:
            kwargs["json"] = json
        if isinstance(data, str):
            kwargs["content"] = data
        elif data is not None:
            kwargs["data"] = dict(data)
        return self._client.build_request(method, url, **kwargs)

    def _action_types(self, operation: str) -> tuple[Any, ...]:
        manifest = self.manifest
        if manifest is None:
            return ()
        try:
            return tuple(getattr(manifest.operation(operation), "action_types", ()) or ())
        except KeyError:
            return ()

    def _send_logical(self, method: str, url: str, *, kind: OperationKind, operation: str,
                      params: Mapping[str, Any] | None, json: Any, data: Mapping[str, Any] | str | None,
                      headers: Mapping[str, str] | None, expected: tuple[int, ...]) -> HttpResult:
        summaries: list[ApiCallSummary] = []
        retries = 0
        reauthed = False
        while True:
            self._preflight(kind)
            if self.rate_limiter is not None:
                self.rate_limiter.acquire()
            request = self._build(method, url, params=params, json=json, data=data, headers=headers)
            response, verdict = self._attempt(request, kind, operation, expected, retries, reauthed)
            summary = self._summarize(request, response, kind, operation, len(summaries) + 1,
                                      verdict.error, params=params, json=json, data=data)
            summaries.append(summary)
            self._audit(summary, kind)
            if verdict.error is None and response is not None:
                return self._result(response, summary, summaries)
            if verdict.reauth:
                assert self.auth is not None
                self.auth.invalidate()
                reauthed = True
                continue
            if verdict.retry:
                retries += 1
                _log.info("retrying %s.%s (retry %d) after %.2fs: %s", self.integration, operation,
                          retries, verdict.delay, type(verdict.error).__name__)
                if verdict.delay > 0:
                    self.sleep(verdict.delay)
                continue
            assert verdict.error is not None
            verdict.error.api_calls = tuple(summaries)  # type: ignore[attr-defined]
            raise verdict.error

    # ----------------------------------------------------------- checks --
    def _check_call(self, method: str, kind: OperationKind, operation: str) -> str:
        method = str(method).upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"unsupported HTTP method {method!r}")
        kind = OperationKind(kind)
        if not operation:
            raise ValueError("operation name is required")
        if method in MUTATING_METHODS and kind is not OperationKind.STATE_CHANGING:
            raise ValueError(f"{self.integration}.{operation}: {method} cannot be a {kind.value} operation "
                             "(PUT, PATCH and DELETE are always STATE_CHANGING and guarded)")
        if kind is OperationKind.BOOKKEEPING:
            if operation not in BOOKKEEPING_OPERATIONS:
                raise ValueError(f"{self.integration}.{operation} is not an allow-listed bookkeeping "
                                 f"operation ({sorted(BOOKKEEPING_OPERATIONS)})")
            if method != "POST":
                raise ValueError(f"{self.integration}.{operation}: bookkeeping requests are POST only")
        self._check_manifest(method, kind, operation)
        return method

    def _check_manifest(self, method: str, kind: OperationKind, operation: str) -> None:
        """With an adapter manifest attached, the call must match its manifest row exactly."""
        manifest = self.manifest
        if manifest is None:
            return
        try:
            spec = manifest.operation(operation)
        except KeyError:
            raise ValueError(f"{self.integration}.{operation} is not an operation of the "
                             f"{self.integration} manifest") from None
        spec_kind = OperationKind(spec.kind)
        same_kind = spec_kind is kind or (spec_kind in READ_ONLY_KINDS and kind in READ_ONLY_KINDS)
        if not same_kind:
            raise ValueError(f"{self.integration}.{operation}: declared kind {kind.value} does not match "
                             f"the manifest ({spec_kind.value})")
        spec_method = getattr(spec, "method", None)
        if spec_method and str(spec_method).upper() != method:
            raise ValueError(f"{self.integration}.{operation}: method {method} does not match the "
                             f"manifest ({spec_method})")

    def _preflight(self, kind: OperationKind) -> None:
        """Run before every attempt: a STATE_CHANGING request needs an active authorization."""
        if kind is OperationKind.STATE_CHANGING:
            guard.require_active_authorization(self.integration)

    def _build(self, method: str, url: str, *, params: Mapping[str, Any] | None, json: Any,
               data: Mapping[str, Any] | str | None, headers: Mapping[str, str] | None) -> httpx.Request:
        merged = {**self.default_headers, **dict(headers or {})}
        kwargs: dict[str, Any] = {"params": dict(params) if params else None, "headers": merged}
        if json is not None:
            kwargs["json"] = json
        if isinstance(data, str):
            kwargs["content"] = data
        elif data is not None:
            kwargs["data"] = dict(data)
        request = self._client.build_request(method, url, **kwargs)
        if self.auth is not None:
            self.auth.apply(request)
        return request

    # ----------------------------------------------------------- attempt --
    def _attempt(self, request: httpx.Request, kind: OperationKind, operation: str,
                 expected: tuple[int, ...], retries: int,
                 reauthed: bool) -> tuple[httpx.Response | None, _Verdict]:
        try:
            response = self._client.send(request)
        except httpx.TransportError as exc:
            return None, self._transport_verdict(exc, kind, operation, retries)
        response.read()
        if response.status_code in expected:
            return response, _Verdict()
        return response, self._status_verdict(response, kind, operation, retries, reauthed)

    def _can_retry(self, retries: int) -> bool:
        return retries < self.retry.max_retries

    def _transport_verdict(self, exc: httpx.TransportError, kind: OperationKind, operation: str,
                           retries: int) -> _Verdict:
        where = f"{self.integration}.{operation}"
        not_sent = isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
        error: IntegrationError
        if isinstance(exc, httpx.TimeoutException):
            suffix = "" if not_sent or kind is not OperationKind.STATE_CHANGING else (
                " (outcome unknown; state-changing request not retried)")
            error = IntegrationTimeoutError(f"{where}: timed out ({type(exc).__name__}){suffix}",
                                            integration=self.integration)
        else:
            error = IntegrationUnavailableError(f"{where}: connection failed ({type(exc).__name__})",
                                                integration=self.integration)
        retry_allowed = not_sent if kind is OperationKind.STATE_CHANGING else True
        if retry_allowed and self._can_retry(retries):
            return _Verdict(error=error, retry=True, delay=self.retry.backoff(retries + 1, self._rand))
        return _Verdict(error=error)

    def _status_verdict(self, response: httpx.Response, kind: OperationKind, operation: str,
                        retries: int, reauthed: bool) -> _Verdict:
        status = response.status_code
        message = self._error_message(response, operation)
        integration = self.integration
        if status == 401:
            if self.auth is not None and not reauthed:
                return _Verdict(error=AuthFailedError(message, integration=integration, http_status=401),
                                reauth=True)
            return _Verdict(error=AuthFailedError(message, integration=integration, http_status=401))
        if status == 403:
            return _Verdict(error=AuthFailedError(message, integration=integration, http_status=403))
        if status in (400, 404):
            return _Verdict(error=InvalidTargetError(message, integration=integration, http_status=status))
        retry_after = parse_retry_after(response.headers.get("Retry-After"), self.clock.now())
        if status == 429:
            error: IntegrationError = RateLimitedError(message, integration=integration,
                                                       retry_after=retry_after)
            return self._maybe_retry(error, retries, retry_after)
        if status >= 500:
            error = IntegrationUnavailableError(message, integration=integration, http_status=status)
            if status not in self.retry.retry_on_status:
                return _Verdict(error=error)
            if kind is OperationKind.STATE_CHANGING and not (status == 503 and retry_after is not None):
                return _Verdict(error=error)
            return self._maybe_retry(error, retries, retry_after)
        return _Verdict(error=ApiError(message, integration=integration, http_status=status))

    def _maybe_retry(self, error: IntegrationError, retries: int, retry_after: float | None) -> _Verdict:
        if not self._can_retry(retries):
            return _Verdict(error=error)
        if retry_after is not None:
            if retry_after > self.retry.backoff_max:
                return _Verdict(error=error)  # server asks for longer than we may wait: give up now
            return _Verdict(error=error, retry=True, delay=retry_after)
        return _Verdict(error=error, retry=True, delay=self.retry.backoff(retries + 1, self._rand))

    def _error_message(self, response: httpx.Response, operation: str) -> str:
        excerpt = ""
        if response.text:
            # Redact first, cut afterwards: a secret straddling the cut can never leak a prefix.
            redacted = self.redactor.redact_body(response.text[:_ERROR_REDACT_WINDOW])
            excerpt = redacted[:_ERROR_EXCERPT]
        base = f"{self.integration}.{operation}: HTTP {response.status_code}"
        return f"{base}: {excerpt}" if excerpt else base

    # ------------------------------------------------------- summaries --
    def _summarize(self, request: httpx.Request, response: httpx.Response | None, kind: OperationKind,
                   operation: str, attempt: int, error: IntegrationError | None, *,
                   params: Mapping[str, Any] | None, json: Any,
                   data: Mapping[str, Any] | str | None) -> ApiCallSummary:
        duration_ms = 0
        if response is not None:
            try:
                duration_ms = max(0, int(response.elapsed.total_seconds() * 1000))
            except RuntimeError:
                duration_ms = 0
        return ApiCallSummary(
            integration=self.integration,
            operation=operation,
            method=request.method,
            url=self.redactor.redact_url(str(request.url)),
            kind=kind,
            status_code=response.status_code if response is not None else None,
            duration_ms=duration_ms,
            attempt=attempt,
            request_summary=self._request_summary(params, json, data),
            response_summary=self._response_summary(response),
            error=error.to_error_info() if error is not None else None,
        )

    def _request_summary(self, params: Mapping[str, Any] | None, json: Any,
                         data: Mapping[str, Any] | str | None) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if params:
            out["params"] = self.redactor.redact(dict(params))
        if json is not None:
            out["json"] = self.redactor.redact(json)
        if isinstance(data, str):
            out["data_bytes"] = len(data.encode("utf-8"))
        elif data is not None:
            out["data"] = self.redactor.redact(dict(data))
        return out

    def _response_summary(self, response: httpx.Response | None) -> dict[str, Any]:
        if response is None:
            return {}
        body = _parse_body(response)
        if isinstance(body, dict):
            return self.redactor.redact(body)
        if isinstance(body, list):
            return {"items": len(body)}
        return {}

    def _audit(self, summary: ApiCallSummary, kind: OperationKind) -> None:
        if self.audit is None:
            return
        context = guard.current()
        incident_id = context.request.incident_id if context is not None else None
        try:
            self.audit.append(AuditEventType.API_CALL, incident_id=incident_id,
                              actor=f"integration:{self.integration}",
                              payload=summary.model_dump(mode="json"))
        except Exception as exc:  # noqa: BLE001
            if kind in READ_ONLY_KINDS:
                _log.warning("audit append failed for read call %s.%s: %s", self.integration,
                             summary.operation, type(exc).__name__)
                return
            if isinstance(exc, AuditError):
                raise
            raise AuditError(f"audit append failed: {type(exc).__name__}") from exc

    def _result(self, response: httpx.Response, summary: ApiCallSummary,
                summaries: list[ApiCallSummary]) -> HttpResult:
        return HttpResult(
            status_code=response.status_code,
            headers=self.redactor.redact_headers(dict(response.headers)),
            body=_parse_body(response),
            text=response.text,
            summary=summary,
            attempts=tuple(summaries),
        )


@lru_cache(maxsize=None)
def _registered_manifest(integration: str) -> Any:
    """The capability manifest registered for ``integration`` (None for unknown names)."""
    if integration not in INTEGRATION_NAMES:
        return None
    try:
        module = importlib.import_module(f"xdr_response.integrations.{integration}.manifest")
    except ImportError:
        return None
    return getattr(module, "MANIFEST", None)


_PLACEHOLDER = re.compile(r"\{[^{}/]*\}")


#: Region labels of vendor hosts (``automate.us.security.cisco.com`` -> ``automate.eu...``).
_REGION_LABELS = frozenset({"us", "eu", "apjc", "au", "in", "ae", "de", "uk", "ca", "jp", "sg"})


@lru_cache(maxsize=512)
def _template_regex(template: str, allow_dots: bool) -> re.Pattern[str]:
    parts = _PLACEHOLDER.split(template)
    wildcard = "[^/:]+" if allow_dots else "[^/]+"
    return re.compile(wildcard.join(re.escape(p) for p in parts))


@lru_cache(maxsize=256)
def _host_regex(template_netloc: str) -> re.Pattern[str]:
    """Host template: ``{x}`` matches any host part, a region label matches any one label."""
    labels = []
    for label in template_netloc.split("."):
        if label in _REGION_LABELS:
            labels.append("[a-z0-9-]+")
        else:
            labels.append(_template_regex(label, True).pattern)
    return re.compile(r"\.".join(labels))


def _norm_path(path: str) -> str:
    path = path if path.startswith("/") else "/" + path
    return path.rstrip("/") or "/"


def url_matches_template(template: str, url: httpx.URL, base_url: httpx.URL) -> bool:
    """True when ``url`` is the documented ``template`` (absolute URL or path, ``{x}`` = one segment).

    A relative template matches the path relative to the host or to the base URL path, on the
    base URL's host. An absolute template also matches its own host (``{x}`` = any host label).
    """
    template = template.split("?", 1)[0].strip()
    host = (url.host or "").lower()
    netloc = host if url.port is None else f"{host}:{url.port}"
    hosts_ok = {(base_url.host or "").lower()}
    path_template = template
    if "://" in template:
        rest = template.split("://", 1)[1]
        tpl_netloc, _, tpl_path = rest.partition("/")
        path_template = "/" + tpl_path
        host_rx = _host_regex(tpl_netloc.lower())
        if not (host_rx.fullmatch(netloc) or host_rx.fullmatch(host) or host in hosts_ok):
            return False
    elif host not in hosts_ok:
        return False
    path = _norm_path(url.path)
    tpl = _norm_path(path_template)
    base_path = _norm_path(base_url.path).rstrip("/")
    candidates = {tpl, _norm_path(base_path + tpl)}
    return any(_template_regex(c, False).fullmatch(path) for c in candidates)


def _carries_target(request: httpx.Request, target: str) -> bool:
    """True when the approved ``target`` appears in the request URL or body (case-insensitive)."""
    needle = (target or "").strip().lower()
    if not needle:
        return False
    try:
        body = request.content.decode("utf-8", "replace")
    except (httpx.RequestNotRead, RuntimeError):
        body = ""
    query = request.url.query.decode("utf-8", "replace")
    haystack = f"{request.url.path}?{query}\n{body}".lower()
    return needle in haystack


def _parse_body(response: httpx.Response) -> Any:
    """Parsed JSON body, or None for empty / non-JSON bodies."""
    if not response.content:
        return None
    content_type = response.headers.get("content-type", "")
    if "json" not in content_type.lower():
        stripped = response.content.lstrip()[:1]
        if stripped not in (b"{", b"["):
            return None
    try:
        return _json.loads(response.content)
    except ValueError:
        return None
