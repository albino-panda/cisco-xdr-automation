"""Integration health checks (architecture sections 6.6 and 13.13).

:func:`classify_exception` maps any failure to a :class:`HealthStatus`;
:class:`HealthMonitor` checks every known integration and never raises: disabled integrations
report ``UNKNOWN`` without being loaded, an adapter that cannot be loaded or whose health check
raises is reported with the classified status, so one broken source never hides the others.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.errors import (
    ApiError,
    AuthenticationError,
    AuthFailedError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    InvalidTargetError,
    RateLimitedError,
    SecretNotFoundError,
)
from xdr_response.interfaces import AuditSink
from xdr_response.logs.redaction import get_redactor
from xdr_response.logs.setup import get_logger
from xdr_response.models import AuditEventType, HealthStatus, IntegrationHealth

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.integrations.registry import AdapterRegistry

__all__ = ["classify_exception", "HealthMonitor", "health_from_exception"]

_log = get_logger("integrations.health")

# Order matters: subclasses before their bases.
_EXCEPTION_STATUS: tuple[tuple[type[BaseException], HealthStatus], ...] = (
    (AuthFailedError, HealthStatus.AUTH_FAILED),
    (AuthenticationError, HealthStatus.AUTH_FAILED),
    (SecretNotFoundError, HealthStatus.AUTH_FAILED),
    (RateLimitedError, HealthStatus.RATE_LIMITED),
    (IntegrationTimeoutError, HealthStatus.DEGRADED),
    (httpx.TimeoutException, HealthStatus.DEGRADED),
    (IntegrationUnavailableError, HealthStatus.UNAVAILABLE),
    (httpx.TransportError, HealthStatus.UNAVAILABLE),
    (ImportError, HealthStatus.UNAVAILABLE),
    (InvalidTargetError, HealthStatus.DEGRADED),
    (ApiError, HealthStatus.DEGRADED),
)


def classify_exception(exc: BaseException) -> HealthStatus:
    """Health status implied by ``exc`` (``UNKNOWN`` for anything unrecognized)."""
    for exc_type, status in _EXCEPTION_STATUS:
        if isinstance(exc, exc_type):
            return status
    return HealthStatus.UNKNOWN


def health_from_exception(integration: str, exc: BaseException, *, clock: Clock | None = None,
                          prefix: str = "health check failed") -> IntegrationHealth:
    """Build an :class:`IntegrationHealth` for a failure (detail redacted, never the raw secret)."""
    detail = get_redactor().redact_text(f"{prefix}: {type(exc).__name__}: {exc}")
    return IntegrationHealth(integration=integration, status=classify_exception(exc),
                             checked_at=(clock or DEFAULT_CLOCK).now(), detail=detail[:500])


class HealthMonitor:
    """Checks the health of every integration known to an :class:`AdapterRegistry`."""

    def __init__(self, registry: "AdapterRegistry", *, audit: AuditSink | None = None,
                 clock: Clock | None = None) -> None:
        self.registry = registry
        self.audit = audit
        self.clock = clock or getattr(registry, "clock", None) or DEFAULT_CLOCK
        self._last: dict[str, IntegrationHealth] = {}

    @property
    def last_results(self) -> dict[str, IntegrationHealth]:
        """Most recent result per integration (copy)."""
        return dict(self._last)

    def check(self, name: str) -> IntegrationHealth:
        """Health of one integration. Never raises (unknown names report ``UNKNOWN``)."""
        result = self._check(name)
        self._last[name] = result
        self._audit(result)
        return result

    def check_all(self) -> dict[str, IntegrationHealth]:
        """Health of every known integration, in registry order. Never raises."""
        return {name: self.check(name) for name in self.registry.names()}

    def usable(self) -> list[str]:
        """Integrations whose last result is CONNECTED or DEGRADED (enrichment may still try them)."""
        ok = (HealthStatus.CONNECTED, HealthStatus.DEGRADED)
        return [name for name, h in self._last.items() if h.status in ok]

    # ------------------------------------------------------------- private --
    def _status(self, name: str, status: HealthStatus, detail: str) -> IntegrationHealth:
        return IntegrationHealth(integration=name, status=status, checked_at=self.clock.now(), detail=detail)

    def _check(self, name: str) -> IntegrationHealth:
        try:
            if not self.registry.is_enabled(name):
                return self._status(name, HealthStatus.UNKNOWN, "integration disabled")
        except KeyError:
            return self._status(name, HealthStatus.UNKNOWN, "unknown integration")
        try:
            adapter = self.registry.get(name)
        except Exception as exc:  # noqa: BLE001 - never raise from a health check
            return health_from_exception(name, exc, clock=self.clock, prefix="adapter could not be loaded")
        try:
            result = adapter.health_check()
        except Exception as exc:  # noqa: BLE001
            return health_from_exception(name, exc, clock=self.clock)
        if not isinstance(result, IntegrationHealth) or result.integration != name:
            return self._status(name, HealthStatus.UNKNOWN, "adapter returned an invalid health result")
        return result

    def _audit(self, result: IntegrationHealth) -> None:
        if self.audit is None:
            return
        try:
            self.audit.append(AuditEventType.HEALTH_CHECK, incident_id=None, actor="integrations:health",
                              payload=result.model_dump(mode="json"))
        except Exception as exc:  # noqa: BLE001 - a health check never raises
            _log.warning("audit append failed for health check of %s: %s", result.integration,
                         type(exc).__name__)
