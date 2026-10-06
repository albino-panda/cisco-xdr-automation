"""Health classification and HealthMonitor (never raises; disabled -> UNKNOWN)."""
from __future__ import annotations

from typing import ClassVar

import httpx
import pytest

from tests.fixtures.principals import make_test_secrets
from tests.unit.integrations._support import FakeAudit, MockRouter, SleepRecorder, fixed_clock, json_response
from xdr_response.config import IntegrationConfig
from xdr_response.config.schema import Settings
from xdr_response.errors import (
    ApiError,
    AuthenticationError,
    AuthFailedError,
    CapabilityNotSupportedError,
    ConfigError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    InvalidTargetError,
    RateLimitedError,
    SecretNotFoundError,
)
from xdr_response.integrations.base import CapabilityManifest, IntegrationAdapter, OperationSpec
from xdr_response.integrations.health import HealthMonitor, classify_exception, health_from_exception
from xdr_response.integrations.registry import AdapterRegistry
from xdr_response.integrations.simulated import FaultKind, SimulatedEnvironment, simulated_adapter_class
from xdr_response.models import (
    AuditEventType,
    EndpointStatus,
    HealthStatus,
    IntegrationHealth,
    OperationKind,
)

SECRET = "health-secret-value-not-real"


@pytest.mark.parametrize(("exc", "status"), [
    (AuthFailedError("x", integration="a", http_status=401), HealthStatus.AUTH_FAILED),
    (AuthFailedError("x", integration="a", http_status=403), HealthStatus.AUTH_FAILED),
    (AuthenticationError("x"), HealthStatus.AUTH_FAILED),
    (SecretNotFoundError("SOME_SECRET"), HealthStatus.AUTH_FAILED),
    (RateLimitedError("x", integration="a"), HealthStatus.RATE_LIMITED),
    (IntegrationTimeoutError("x", integration="a"), HealthStatus.DEGRADED),
    (httpx.ReadTimeout("x"), HealthStatus.DEGRADED),
    (IntegrationUnavailableError("x", integration="a"), HealthStatus.UNAVAILABLE),
    (httpx.ConnectError("x"), HealthStatus.UNAVAILABLE),
    (ImportError("x"), HealthStatus.UNAVAILABLE),
    (InvalidTargetError("x", integration="a"), HealthStatus.DEGRADED),
    (ApiError("x", integration="a"), HealthStatus.DEGRADED),
    (CapabilityNotSupportedError("x", integration="a"), HealthStatus.UNKNOWN),
    (ConfigError("x"), HealthStatus.UNKNOWN),
    (RuntimeError("x"), HealthStatus.UNKNOWN),
])
def test_classify_exception(exc: BaseException, status: HealthStatus) -> None:
    assert classify_exception(exc) is status


def test_health_from_exception_redacts_detail() -> None:
    health = health_from_exception("umbrella", RuntimeError(f"failed with client_secret={SECRET}"),
                                   clock=fixed_clock())
    assert SECRET not in health.detail
    assert health.status is HealthStatus.UNKNOWN
    assert health.integration == "umbrella"


# ------------------------------------------------------------- HTTP adapter --
class HttpHealthAdapter(IntegrationAdapter):
    """Test adapter whose health check is a real GuardedHttpClient GET against a MockTransport."""

    name: ClassVar[str] = "virustotal"
    manifest: ClassVar[CapabilityManifest] = CapabilityManifest(
        integration="virustotal", display_name="Test VT",
        operations=(OperationSpec(name="health", kind=OperationKind.READ, status=EndpointStatus.VERIFIED,
                                  method="GET", path="/health", source="https://docs.example.com/health"),),
    )
    default_base_url = "https://vt.example.com"

    def health_check(self) -> IntegrationHealth:
        if not self.enabled:
            return self.disabled_health()
        try:
            self.http.get("/health", operation="health")
        except Exception as exc:  # noqa: BLE001
            return health_from_exception(self.name, exc, clock=self.clock)
        return IntegrationHealth(integration=self.name, status=HealthStatus.CONNECTED, checked_at=self.clock.now())


@pytest.mark.parametrize(("responses", "status"), [
    ([json_response(200, {})], HealthStatus.CONNECTED),
    ([json_response(401)], HealthStatus.AUTH_FAILED),
    ([json_response(403)], HealthStatus.AUTH_FAILED),
    ([json_response(429, headers={"Retry-After": "1"})], HealthStatus.RATE_LIMITED),
    ([json_response(503)], HealthStatus.UNAVAILABLE),
])
def test_http_backed_health_statuses(responses: list[httpx.Response], status: HealthStatus) -> None:
    router = MockRouter()
    router.add("GET", "/health", *responses)
    config = IntegrationConfig(enabled=True, max_retries=1, backoff_base_seconds=0.0)
    reg = AdapterRegistry(Settings(), make_test_secrets(), clock=fixed_clock(), sleep=SleepRecorder())
    reg.register(HttpHealthAdapter(config, make_test_secrets(), transport=router.transport(), clock=reg.clock,
                                   sleep=SleepRecorder()))
    assert HealthMonitor(reg).check("virustotal").status is status


def test_http_backed_health_timeout_is_degraded() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    router = MockRouter()
    router.add("GET", "/health", timeout)
    reg = AdapterRegistry(Settings(), make_test_secrets(), clock=fixed_clock())
    reg.register(HttpHealthAdapter(IntegrationConfig(enabled=True, max_retries=0), make_test_secrets(),
                                   transport=router.transport(), clock=reg.clock))
    assert HealthMonitor(reg).check("virustotal").status is HealthStatus.DEGRADED


# ------------------------------------------------------------------ monitor --
def simulated_registry(env: SimulatedEnvironment, *names: str, broken: set[str] = frozenset(),
                       audit: FakeAudit | None = None) -> AdapterRegistry:
    settings = Settings(integrations={n: IntegrationConfig(enabled=True) for n in (*names, *broken)})

    def loader(name: str):
        if name in broken:
            raise ImportError(f"adapter module for {name} missing")
        return simulated_adapter_class(name, ("intel",))

    reg = AdapterRegistry(settings, make_test_secrets(), clock=env.clock, class_loader=loader, audit=audit)
    for name in names:
        adapter = reg.get(name)
        adapter.environment = env  # type: ignore[attr-defined]
    return reg


def test_check_all_never_raises_and_reports_every_integration() -> None:
    env = SimulatedEnvironment(clock=fixed_clock())
    env.inject(FaultKind.AUTH_FAIL, integration="virustotal", operation="health_check")
    env.inject(FaultKind.RATE_LIMIT, integration="alienvault_otx", operation="health_check")
    env.inject(FaultKind.TIMEOUT, integration="hibp", operation="health_check")
    env.set_health("umbrella", HealthStatus.DEGRADED)
    reg = simulated_registry(env, "virustotal", "alienvault_otx", "hibp", "umbrella", "entra", broken={"meraki"})
    monitor = HealthMonitor(reg)
    results = monitor.check_all()
    assert list(results) == reg.names()
    assert results["virustotal"].status is HealthStatus.AUTH_FAILED
    assert results["alienvault_otx"].status is HealthStatus.RATE_LIMITED
    assert results["hibp"].status is HealthStatus.DEGRADED
    assert results["umbrella"].status is HealthStatus.DEGRADED
    assert results["entra"].status is HealthStatus.CONNECTED
    assert results["meraki"].status is HealthStatus.UNAVAILABLE
    assert "could not be loaded" in results["meraki"].detail
    assert results["splunk"].status is HealthStatus.UNKNOWN
    assert results["splunk"].detail == "integration disabled"
    assert set(monitor.usable()) == {"hibp", "umbrella", "entra"}
    assert monitor.last_results["entra"].status is HealthStatus.CONNECTED


def test_disabled_integrations_are_not_loaded() -> None:
    loaded: list[str] = []

    def loader(name: str):
        loaded.append(name)
        return simulated_adapter_class(name, ("intel",))

    reg = AdapterRegistry(Settings(), make_test_secrets(), clock=fixed_clock(), class_loader=loader)
    results = HealthMonitor(reg).check_all()
    assert loaded == []
    assert {h.status for h in results.values()} == {HealthStatus.UNKNOWN}


def test_adapter_exceptions_and_bad_results_are_contained() -> None:
    env = SimulatedEnvironment(clock=fixed_clock())
    reg = simulated_registry(env, "virustotal", "hibp")

    def explode() -> IntegrationHealth:
        raise IntegrationUnavailableError("down", integration="virustotal")

    reg.get("virustotal").health_check = explode  # type: ignore[method-assign]
    reg.get("hibp").health_check = lambda: "fine"  # type: ignore[method-assign]
    monitor = HealthMonitor(reg)
    assert monitor.check("virustotal").status is HealthStatus.UNAVAILABLE
    assert monitor.check("hibp").status is HealthStatus.UNKNOWN
    assert monitor.check("not_an_integration").status is HealthStatus.UNKNOWN


def test_health_checks_are_audited_and_audit_failure_is_swallowed() -> None:
    env = SimulatedEnvironment(clock=fixed_clock())
    audit = FakeAudit()
    reg = simulated_registry(env, "virustotal")
    HealthMonitor(reg, audit=audit).check("virustotal")
    assert audit.events[0]["event_type"] is AuditEventType.HEALTH_CHECK
    assert audit.events[0]["payload"]["status"] == "CONNECTED"
    assert HealthMonitor(reg, audit=FakeAudit(fail=True)).check("virustotal").status is HealthStatus.CONNECTED
