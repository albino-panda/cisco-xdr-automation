"""Adapter base classes and capability manifests (architecture section 13.13).

Read methods (``health_check``, ``enrich``, ``investigate``, ``current_state``, ``verify``) never
change vendor state. Every state-changing method is named exactly after its ``ActionType`` value
and MUST be decorated with :func:`xdr_response.guard.state_changing`; this is enforced when the
subclass is created (``TypeError``), so an unguarded write method cannot exist.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import model_validator

from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.errors import (
    CapabilityNotSupportedError,
    ConfigError,
    IntegrationUnavailableError,
    UnverifiedEndpointError,
)
from xdr_response.guard import is_state_changing_method, state_changing
from xdr_response.interfaces import AuditSink, SecretProvider
from xdr_response.models import (
    INTEGRATION_NAMES,
    ActionCategory,
    ActionOutcome,
    ActionRequest,
    ActionType,
    EndpointStatus,
    EnrichmentResult,
    FrozenModel,
    HealthStatus,
    IntegrationHealth,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    ObservableType,
    OperationKind,
    TargetState,
    TargetStateCheck,
    VerificationResult,
    VerificationStatus,
    get_action_spec,
)

if TYPE_CHECKING:  # pragma: no cover
    import httpx

    from xdr_response.config.schema import IntegrationConfig, Settings
    from xdr_response.integrations.auth import AuthProvider
    from xdr_response.integrations.http import GuardedHttpClient
    from xdr_response.secrets.provider import SecretValue

__all__ = [
    "OperationSpec",
    "CapabilityManifest",
    "IntegrationAdapter",
    "HealthStatus",
    "STATE_CHANGING_ACTION_NAMES",
]

#: Method names reserved for guarded state-changing implementations.
STATE_CHANGING_ACTION_NAMES = frozenset(a.value for a in ActionType if get_action_spec(a).state_changing)


class OperationSpec(FrozenModel):
    name: str
    kind: OperationKind
    status: EndpointStatus
    method: str | None = None
    path: str | None = None  # as written in docs/integrations.md
    source: str | None = None  # required when status == VERIFIED
    action_types: tuple[ActionType, ...] = ()

    @model_validator(mode="after")
    def _validate(self) -> "OperationSpec":
        if self.status is EndpointStatus.VERIFIED and not self.source:
            raise ValueError(f"operation {self.name}: VERIFIED endpoints need a documentation source")
        if self.method and self.method.upper() in ("PUT", "PATCH", "DELETE") and self.kind in (
                OperationKind.READ, OperationKind.VERIFY):
            raise ValueError(f"operation {self.name}: {self.method} cannot be a {self.kind.value} operation")
        return self


class CapabilityManifest(FrozenModel):
    integration: str
    display_name: str
    optional: bool = False  # True only for splunk
    enabled_by_default: bool = True  # False for splunk
    native_xdr: bool = False  # True for cisco_xdr
    supported_actions: frozenset[ActionType] = frozenset()  # state-changing types with a VERIFIED write
    verifiable_actions: frozenset[ActionType] = frozenset()
    read_actions: frozenset[ActionType] = frozenset()  # ENRICHMENT/INVESTIGATION types served
    enrichment_types: frozenset[ObservableType] = frozenset()
    operations: tuple[OperationSpec, ...]
    escalation_hint: str = ""
    rate_limit_note: str = ""

    @model_validator(mode="after")
    def _validate(self) -> "CapabilityManifest":
        if self.integration not in INTEGRATION_NAMES:
            raise ValueError(f"unknown integration {self.integration!r}")
        names = [o.name for o in self.operations]
        if len(set(names)) != len(names):
            raise ValueError("duplicate operation names in manifest")
        for a in self.supported_actions:
            if not get_action_spec(a).state_changing:
                raise ValueError(f"supported_actions may only list state-changing types, not {a.value}")
            if not any(o.status is EndpointStatus.VERIFIED and o.kind is OperationKind.STATE_CHANGING
                       and a in o.action_types for o in self.operations):
                raise ValueError(
                    f"{self.integration}: {a.value} is listed as supported but no VERIFIED "
                    "STATE_CHANGING operation serves it (see docs/integrations.md)"
                )
        for a in self.verifiable_actions:
            if not get_action_spec(a).state_changing:
                raise ValueError(f"verifiable_actions may only list state-changing types, not {a.value}")
        for a in self.read_actions:
            if get_action_spec(a).category not in (ActionCategory.ENRICHMENT, ActionCategory.INVESTIGATION,
                                                   ActionCategory.BOOKKEEPING):
                raise ValueError(f"read_actions may not list {a.value}")
        return self

    def operation(self, name: str) -> OperationSpec:
        for o in self.operations:
            if o.name == name:
                return o
        raise KeyError(name)

    def unverified_operation_for(self, action_type: ActionType) -> OperationSpec | None:
        for o in self.operations:
            if action_type in o.action_types and o.status is EndpointStatus.UNVERIFIED:
                return o
        return None


class IntegrationAdapter(ABC):
    """Base class of every vendor adapter. Vendor-specific logic stays behind this interface."""

    name: ClassVar[str]
    manifest: ClassVar[CapabilityManifest]
    #: Default base URL when the config gives none (must come from docs/integrations.md).
    default_base_url: ClassVar[str | None] = None
    #: Logical secret name -> default secret NAME (overridable by ``config.secrets``).
    secret_names: ClassVar[Mapping[str, str]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        for attr, value in cls.__dict__.items():
            fn = value.__func__ if isinstance(value, (staticmethod, classmethod)) else value
            if attr in STATE_CHANGING_ACTION_NAMES or attr == "execute":
                if not callable(fn) or not is_state_changing_method(fn):
                    raise TypeError(
                        f"{cls.__qualname__}.{attr} changes vendor state and must be decorated "
                        "with @xdr_response.guard.state_changing"
                    )
        manifest = cls.__dict__.get("manifest")
        if isinstance(manifest, CapabilityManifest):
            name = cls.__dict__.get("name", getattr(cls, "name", None))
            if name != manifest.integration:
                raise TypeError(f"{cls.__qualname__}.name must equal manifest.integration")
            for action in manifest.supported_actions:
                method = getattr(cls, action.value, None)
                if method is None or not is_state_changing_method(method):
                    raise TypeError(
                        f"{cls.__qualname__} declares {action.value} as supported but has no "
                        "@state_changing method with that name"
                    )

    def __init__(
        self,
        config: "IntegrationConfig",
        secrets: SecretProvider,
        *,
        transport: "httpx.BaseTransport | None" = None,
        clock: Clock | None = None,
        audit: AuditSink | None = None,
        settings: "Settings | None" = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.config = config
        self.secrets = secrets
        self.transport = transport
        self.clock: Clock = clock or DEFAULT_CLOCK
        self.audit = audit
        self.settings = settings
        self.sleep = sleep
        self._http: GuardedHttpClient | None = None

    # ------------------------------------------------------------- plumbing --
    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled)

    @property
    def base_url(self) -> str:
        url = self.config.base_url or self.default_base_url
        if not url:
            raise ConfigError(f"{self.name}: no base_url configured")
        return url

    def secret(self, logical: str) -> "SecretValue":
        """Resolve a logical secret (``client_secret``) to its value via the configured NAME."""
        name = self.config.secrets.get(logical) or self.secret_names.get(logical)
        if not name:
            raise ConfigError(f"{self.name}: no secret name configured for {logical!r}")
        return self.secrets.get(name)

    def build_auth(self) -> "AuthProvider | None":
        """Override to supply the integration's auth provider."""
        return None

    def default_headers(self) -> Mapping[str, str]:
        """Override to add mandatory headers (for example HIBP's user-agent)."""
        return {}

    def build_http_client(self) -> "GuardedHttpClient":
        """Build the guarded HTTP client from config (imported lazily; owned by integrations-core)."""
        from xdr_response.integrations.http import GuardedHttpClient, RateLimiter, RetryPolicy

        cfg = self.config
        return GuardedHttpClient(
            self.name,
            self.base_url,
            timeout=cfg.timeout_seconds,
            retry=RetryPolicy(max_retries=cfg.max_retries, backoff_base=cfg.backoff_base_seconds,
                              backoff_max=cfg.backoff_max_seconds),
            rate_limiter=RateLimiter(cfg.rate_limit_per_minute, clock=self.clock, sleep=self.sleep),
            auth=self.build_auth(),
            default_headers=self.default_headers(),
            transport=self.transport,
            clock=self.clock,
            sleep=self.sleep,
            audit=self.audit,
            manifest=self.manifest,
        )

    def _bind_manifest(self, client: Any) -> Any:
        """Attach this adapter's manifest to ``client`` so every call is checked against it."""
        if client is not None and hasattr(client, "manifest"):
            client.manifest = self.manifest
        return client

    @property
    def http(self) -> "GuardedHttpClient":
        """The adapter's guarded HTTP client, built on first use (always manifest-checked)."""
        if self._http is None:
            self._http = self._bind_manifest(self.build_http_client())
        return self._http

    @http.setter
    def http(self, client: "GuardedHttpClient") -> None:
        self._http = self._bind_manifest(client)

    def close(self) -> None:
        if self._http is not None:
            self._http.close()

    # ---------------------------------------------------------- read paths --
    @abstractmethod
    def health_check(self) -> IntegrationHealth:
        """Never raises; disabled adapters report UNKNOWN."""

    def _unsupported(self, what: str) -> CapabilityNotSupportedError:
        return CapabilityNotSupportedError(f"{self.name} does not support {what}", integration=self.name)

    def enrich(self, observable: Observable) -> EnrichmentResult:
        raise self._unsupported(f"enrichment of {observable.type.value}")

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        raise self._unsupported(f"investigation {query.action_type.value}")

    def current_state(self, request: ActionRequest) -> TargetStateCheck:
        """Read-only check of the target's current state (idempotency). Default UNKNOWN."""
        return TargetStateCheck(state=TargetState.UNKNOWN, detail=f"{self.name}: state check not available")

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """Read-only verification. Default UNABLE_TO_VERIFY. Must not assume this adapter executed."""
        return VerificationResult(
            idempotency_key=request.idempotency_key,
            status=VerificationStatus.UNABLE_TO_VERIFY,
            integration=self.name,
            method="none",
            checked_at=self.clock.now(),
            details=f"{self.name}: no verified read-back for {request.action_type.value}",
        )

    def disabled_health(self) -> IntegrationHealth:
        return IntegrationHealth(integration=self.name, status=HealthStatus.UNKNOWN,
                                 checked_at=self.clock.now(), detail="integration disabled")

    # --------------------------------------------------------- write paths --
    @state_changing
    def execute(self, request: ActionRequest) -> ActionOutcome:
        """Dispatch to the ``@state_changing`` method named after ``request.action_type``."""
        action = request.action_type
        if not self.enabled:
            raise IntegrationUnavailableError(f"{self.name} is disabled", integration=self.name,
                                              retryable=False)
        if action not in self.manifest.supported_actions:
            if self.manifest.unverified_operation_for(action) is not None:
                raise UnverifiedEndpointError(self.name, action.value)
            raise self._unsupported(action.value)
        method = getattr(self, action.value, None)
        if method is None or not is_state_changing_method(method):
            raise self._unsupported(action.value)
        outcome = method(request)
        if not isinstance(outcome, ActionOutcome):
            raise TypeError(f"{self.name}.{action.value} must return an ActionOutcome")
        return outcome
