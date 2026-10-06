"""Shared building blocks for the shipped vendor adapters (``integrations/<vendor>/``).

Every vendor adapter subclasses :class:`VendorAdapter`, which adds to
:class:`~xdr_response.integrations.base.IntegrationAdapter`:

* :class:`ApiRequest`: a pure, inspectable description of one HTTP call. Request builders in
  ``<vendor>/builders.py`` return these and never perform I/O, so tests can check method, path and
  body without a network.
* :meth:`VendorAdapter._send`: sends an :class:`ApiRequest` through the guarded HTTP client after a
  manifest check. An operation that is not VERIFIED in its manifest is refused with
  :class:`~xdr_response.errors.UnverifiedEndpointError` even if a builder exists, and the method and
  kind must match the manifest row. STATE_CHANGING requests are additionally checked by the HTTP
  client against the active guard context.
* helpers that build :class:`ActionOutcome`, :class:`VerificationResult`, :class:`EnrichmentResult`
  and :class:`IntegrationHealth` consistently, and a never-raising :meth:`health_check`.

Relative request paths have no leading slash: they are resolved against the adapter's base URL
(httpx ``base_url`` semantics, which keep a base path such as ``/api/v1``). Absolute URLs are used
only for hosts that docs/integrations.md documents separately from the base URL.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NoReturn, Protocol
from urllib.parse import quote

from xdr_response.errors import (
    AuthFailedError,
    ConfigError,
    IntegrationError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    InvalidTargetError,
    RateLimitedError,
    SecretNotFoundError,
    UnverifiedEndpointError,
)
from xdr_response.integrations.base import IntegrationAdapter
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    ApiCallSummary,
    EndpointStatus,
    EnrichmentResult,
    ErrorCode,
    ErrorInfo,
    EvidenceDraft,
    HealthStatus,
    IntegrationHealth,
    Observable,
    OperationKind,
    Verdict,
    VerificationResult,
    VerificationStatus,
)

if TYPE_CHECKING:  # pragma: no cover
    import httpx

    from xdr_response.config.policy import DisclosurePolicy

__all__ = [
    "DEFAULT_EXPECTED",
    "ApiRequest",
    "HttpResultLike",
    "CompositeAuth",
    "VendorAdapter",
    "ThirdPartyLookupMixin",
    "segment",
    "require_param",
    "body_dict",
    "body_list",
    "classify_health",
]

DEFAULT_EXPECTED: tuple[int, ...] = (200, 201, 202, 204)
_READ_KINDS = frozenset({OperationKind.READ, OperationKind.VERIFY})


@dataclass(frozen=True)
class ApiRequest:
    """One HTTP call, described without performing it.

    ``operation`` is the :class:`~xdr_response.integrations.base.OperationSpec` name in the
    adapter's manifest; ``path`` is relative to the base URL (no leading slash) or absolute.
    """

    operation: str
    method: str
    path: str
    kind: OperationKind = OperationKind.READ
    params: Mapping[str, Any] | None = None
    json: Any = None
    data: Mapping[str, Any] | str | None = None
    headers: Mapping[str, str] | None = None
    expected: tuple[int, ...] = DEFAULT_EXPECTED


class HttpResultLike(Protocol):
    """The parts of ``integrations.http.HttpResult`` the adapters read."""

    status_code: int
    headers: Mapping[str, str]
    body: Any
    summary: ApiCallSummary


class CompositeAuth:
    """Apply several auth providers to one request (for example OAuth2 plus an API-key header)."""

    def __init__(self, *providers: Any) -> None:
        self._providers = tuple(p for p in providers if p is not None)

    def apply(self, request: "httpx.Request") -> None:
        for provider in self._providers:
            provider.apply(request)

    def invalidate(self) -> None:
        for provider in self._providers:
            provider.invalidate()


# ------------------------------------------------------------------ helpers --
def segment(value: object, *, safe: str = "") -> str:
    """Percent-encode one URL path segment so a target can never inject path elements."""
    return quote(str(value), safe=safe)


def require_param(request: ActionRequest, key: str, *, integration: str) -> Any:
    """Return ``request.params[key]`` or raise :class:`InvalidTargetError` (recorded as FAILED)."""
    value = request.params.get(key)
    if value is None or value == "" or value == []:
        raise InvalidTargetError(
            f"{integration}: {request.action_type.value} needs params.{key} (set at plan time and "
            "covered by the approval)",
            integration=integration,
        )
    return value


def identity_matches(target: str, values: Iterable[str]) -> bool:
    """True when one of ``values`` names ``target`` (case-insensitive, hostname vs FQDN aware)."""
    wanted = str(target or "").strip().lower()
    if not wanted:
        return False
    for value in values:
        got = str(value or "").strip().lower()
        if not got:
            continue
        if got == wanted or got.split(".", 1)[0] == wanted or wanted.split(".", 1)[0] == got:
            return True
    return False


def body_dict(body: Any) -> dict[str, Any]:
    """The response body when it is a JSON object, else an empty dict."""
    return body if isinstance(body, dict) else {}


def body_list(body: Any, key: str = "data") -> list[Any]:
    """A list response, either the body itself or ``body[key]`` (empty when absent)."""
    if isinstance(body, list):
        return body
    value = body_dict(body).get(key)
    return value if isinstance(value, list) else []


def classify_health(exc: BaseException) -> HealthStatus:
    """Map an exception from a probe call to an integration health status."""
    if isinstance(exc, AuthFailedError):
        return HealthStatus.AUTH_FAILED
    if isinstance(exc, RateLimitedError):
        return HealthStatus.RATE_LIMITED
    if isinstance(exc, (IntegrationTimeoutError, IntegrationUnavailableError)):
        return HealthStatus.UNAVAILABLE
    if isinstance(exc, (ConfigError, SecretNotFoundError, UnverifiedEndpointError)):
        return HealthStatus.UNKNOWN
    if isinstance(exc, IntegrationError):
        return HealthStatus.DEGRADED
    return HealthStatus.UNKNOWN


def _safe_detail(exc: BaseException) -> str:
    if isinstance(exc, IntegrationError):
        return f"{type(exc).__name__}: {exc.to_error_info().message}"
    return type(exc).__name__  # never echo arbitrary exception text (could carry secrets)


# ------------------------------------------------------------- base class --
class VendorAdapter(IntegrationAdapter):
    """Common plumbing for the shipped adapters. Subclasses define ``name`` and ``manifest``."""

    # ----------------------------------------------------------- sending --
    def _check_operation(self, req: ApiRequest) -> None:
        try:
            spec = self.manifest.operation(req.operation)
        except KeyError:
            raise ValueError(f"{self.name}: operation {req.operation!r} is not in the manifest") from None
        if spec.status is not EndpointStatus.VERIFIED:
            raise UnverifiedEndpointError(self.name, req.operation)
        if spec.method and spec.method.upper() != req.method.upper():
            raise ValueError(f"{self.name}.{req.operation}: method {req.method} does not match the "
                             f"manifest ({spec.method})")
        same_kind = spec.kind is req.kind or (spec.kind in _READ_KINDS and req.kind in _READ_KINDS)
        if not same_kind:
            raise ValueError(f"{self.name}.{req.operation}: kind {req.kind.value} does not match the "
                             f"manifest ({spec.kind.value})")

    def _send(self, req: ApiRequest, *, client: Any = None) -> HttpResultLike:
        """Send a manifest-checked request through the guarded HTTP client (``client`` defaults to ``http``)."""
        self._check_operation(req)
        return (client or self.http).request(
            req.method, req.path, kind=req.kind, operation=req.operation, params=req.params,
            json=req.json, data=req.data, headers=req.headers, expected=req.expected,
        )

    def _require_identity(self, request: ActionRequest, ref: str, record: Mapping[str, Any],
                          fields: Sequence[str], *, what: str) -> None:
        """The vendor object ``ref`` named in params must be the approved target.

        The analyst, the idempotency key and the critical-asset policy only ever see
        ``request.target``; a write to an object named in params is allowed only when the
        verified lookup ``record`` of that object names the target in one of ``fields``
        (case-insensitive; a hostname also matches the first label of an FQDN). Anything else,
        including a lookup that names nothing, is refused (fail closed).
        """
        values = [str(record.get(f)) for f in fields if record.get(f)]
        if identity_matches(request.target, values):
            return
        shown = ", ".join(values) if values else "no identifying field"
        raise InvalidTargetError(
            f"{self.name}: {what} {ref!r} named in params is not the approved target "
            f"{request.target!r} (lookup returned {shown}); refusing to act on another object",
            integration=self.name)

    def _unverified(self, operation: str) -> NoReturn:
        """Raise the standard ``unverified endpoint`` error for ``operation``."""
        raise UnverifiedEndpointError(self.name, operation)

    def _param(self, request: ActionRequest, key: str) -> Any:
        return require_param(request, key, integration=self.name)

    def _option(self, key: str, default: Any = None) -> Any:
        return self.config.options.get(key, default)

    # ---------------------------------------------------------- results --
    @staticmethod
    def _calls(results: Iterable[Any]) -> tuple[ApiCallSummary, ...]:
        return tuple(r.summary for r in results if isinstance(getattr(r, "summary", None), ApiCallSummary))

    def _outcome(
        self,
        status: ActionResultStatus,
        *,
        message: str = "",
        results: Iterable[Any] = (),
        external_ref: str | None = None,
        rollback: Mapping[str, Any] | None = None,
    ) -> ActionOutcome:
        """Build an :class:`ActionOutcome`; ``rollback`` always carries this integration's name."""
        rollback_params = {"integration": self.name, **rollback} if rollback is not None else {}
        return ActionOutcome(
            status=status, integration=self.name, message=message, external_ref=external_ref,
            rollback_params=rollback_params, api_calls=self._calls(results), executed_at=self.clock.now(),
        )

    def _verification(
        self,
        request: ActionRequest,
        status: VerificationStatus,
        *,
        method: str,
        details: str = "",
        results: Iterable[Any] = (),
    ) -> VerificationResult:
        return VerificationResult(
            idempotency_key=request.idempotency_key, status=status, integration=self.name,
            method=method, checked_at=self.clock.now(), details=details, api_calls=self._calls(results),
        )

    def _evidence(self, summary: str, *, reference: str | None = None,
                  data: Mapping[str, Any] | None = None) -> EvidenceDraft:
        return EvidenceDraft(source=self.name, summary=summary, observed_at=self.clock.now(),
                             reference=reference, data=dict(data or {}))

    def _enrichment(
        self,
        observable: Observable,
        verdict: Verdict,
        *,
        risk: int,
        confidence: int,
        evidence: Iterable[EvidenceDraft] = (),
        errors: Iterable[ErrorInfo] = (),
        health: HealthStatus = HealthStatus.CONNECTED,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            type=observable.type, value=observable.value, risk_score=risk, confidence=confidence,
            sources=(self.name,), verdict=verdict, integration=self.name, health=health,
            evidence=tuple(evidence), errors=tuple(errors),
        )

    # ----------------------------------------------------------- health --
    def _health_probe(self) -> ApiRequest | None:
        """A side-effect-free VERIFIED READ request, or None when no such probe exists."""
        return None

    def health_check(self) -> IntegrationHealth:
        """Probe the integration once. Never raises; disabled adapters report UNKNOWN."""
        if not self.enabled:
            return self.disabled_health()
        try:
            probe = self._health_probe()
        except Exception as exc:  # noqa: BLE001 - misconfiguration must not escape a health check
            return IntegrationHealth(integration=self.name, status=classify_health(exc),
                                     checked_at=self.clock.now(), detail=_safe_detail(exc))
        if probe is None:
            return IntegrationHealth(
                integration=self.name, status=HealthStatus.UNKNOWN, checked_at=self.clock.now(),
                detail="no VERIFIED side-effect-free probe; health is derived from call results",
            )
        started = self.clock.now()
        try:
            self._send(probe)
        except Exception as exc:  # noqa: BLE001 - health_check never raises
            return IntegrationHealth(integration=self.name, status=classify_health(exc),
                                     checked_at=self.clock.now(), detail=_safe_detail(exc))
        finished = self.clock.now()
        latency = max(0, int((finished - started).total_seconds() * 1000))
        return IntegrationHealth(integration=self.name, status=HealthStatus.CONNECTED, checked_at=finished,
                                 detail=f"probe {probe.operation} succeeded", latency_ms=latency)


class ThirdPartyLookupMixin:
    """Disclosure-policy gate for third-party lookups (VirusTotal, OTX, HIBP).

    The policy is built from ``settings.exclusions`` when settings are given, else from an empty
    :class:`ExclusionsConfig` (built-in internal suffixes and non-public ranges still apply).
    Tests and labs may assign ``adapter.disclosure`` directly.
    """

    _disclosure: "DisclosurePolicy | None" = None

    @property
    def disclosure(self) -> "DisclosurePolicy":
        if self._disclosure is None:
            from xdr_response.config.policy import DisclosurePolicy
            from xdr_response.config.schema import ExclusionsConfig

            settings = getattr(self, "settings", None)
            exclusions = settings.exclusions if settings is not None else ExclusionsConfig()
            self._disclosure = DisclosurePolicy(exclusions)
        return self._disclosure

    @disclosure.setter
    def disclosure(self, policy: "DisclosurePolicy") -> None:
        self._disclosure = policy

    def _withheld(self, observable: Observable) -> EnrichmentResult:
        """Result for an observable the policy forbids sending (no HTTP call is made)."""
        adapter: VendorAdapter = self  # type: ignore[assignment]
        error = ErrorInfo(code=ErrorCode.NOT_SUPPORTED, integration=adapter.name,
                          message=f"{observable.type.value} withheld by the disclosure policy")
        return adapter._enrichment(observable, Verdict.UNKNOWN, risk=0, confidence=0, errors=(error,))
