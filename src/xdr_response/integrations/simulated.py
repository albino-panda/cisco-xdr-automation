"""Simulated adapters backed by an in-memory environment (tests, lab and the simulator).

A :class:`SimulatedEnvironment` holds vendor-side state ("is TH-LT-1047 isolated?"), indicator
reputations, investigation findings, health overrides and injected faults. The
:class:`SimulatedAdapter` family (endpoint, identity, email, DNS/network, intel) implements
every state-changing :class:`ActionType` across its families, ``current_state`` (idempotency),
``verify`` (read-back), the rollback action types, enrichment and investigation.

Safety is identical to a real adapter: every state-changing method is ``@state_changing``, so it
is refused outside an approved authorization context and while dry run is active. Simulated
adapters never make HTTP calls (``build_http_client`` raises).

Fault injection (:class:`FaultKind`): ``FAIL``, ``UNAVAILABLE``, ``AUTH_FAIL``, ``RATE_LIMIT``,
``TIMEOUT``, ``INVALID_TARGET`` raise the matching typed error; ``ALREADY_CONTAINED`` puts the
target in the desired state first (the action then reports ``ALREADY_CONTAINED``);
``NO_EFFECT`` reports success without changing state (verification then says ``NOT_VERIFIED``).
"""
from __future__ import annotations

from xdr_response import guard as _guard

import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar

from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.config.schema import IntegrationConfig
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
from xdr_response.guard import state_changing
from xdr_response.integrations.base import CapabilityManifest, IntegrationAdapter, OperationSpec
from xdr_response.integrations.health import health_from_exception
from xdr_response.interfaces import AuditSink, SecretProvider
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    ActionType,
    ApiCallSummary,
    AuditEventType,
    EndpointStatus,
    EnrichmentResult,
    EvidenceDraft,
    HealthStatus,
    IntegrationHealth,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    ObservableType,
    OperationKind,
    TargetState,
    TargetStateCheck,
    Verdict,
    VerificationResult,
    VerificationStatus,
    get_action_spec,
)
from xdr_response.secrets.provider import StaticSecretProvider

if TYPE_CHECKING:  # pragma: no cover
    import httpx

    from xdr_response.config.schema import Settings
    from xdr_response.integrations.http import GuardedHttpClient
    from xdr_response.integrations.registry import AdapterRegistry

__all__ = [
    "SIMULATOR_SOURCE",
    "FaultKind",
    "Fault",
    "Reputation",
    "SimulatedCall",
    "SimulatedEnvironment",
    "ACTION_EFFECTS",
    "FAMILIES",
    "SimulatedAdapter",
    "SimulatedEndpointAdapter",
    "SimulatedIdentityAdapter",
    "SimulatedEmailAdapter",
    "SimulatedNetworkAdapter",
    "SimulatedIntelAdapter",
    "SIMULATED_SUITE",
    "build_simulated_manifest",
    "simulated_adapter_class",
    "build_simulated_adapters",
    "register_simulated_adapters",
]

#: ``OperationSpec.source`` of every simulated operation: no vendor endpoint is involved.
SIMULATOR_SOURCE = "simulator:in-memory (no network; xdr_response.integrations.simulated)"

#: Read operations that can carry an injected fault.
READ_OPERATIONS = frozenset({"health_check", "enrich", "investigate", "current_state", "verify"})


# ------------------------------------------------------------------ faults --
class FaultKind(StrEnum):
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"
    AUTH_FAIL = "AUTH_FAIL"
    RATE_LIMIT = "RATE_LIMIT"
    TIMEOUT = "TIMEOUT"
    INVALID_TARGET = "INVALID_TARGET"
    ALREADY_CONTAINED = "ALREADY_CONTAINED"
    NO_EFFECT = "NO_EFFECT"


#: Fault kinds that only make sense for state-changing operations.
_STATE_FAULTS = frozenset({FaultKind.ALREADY_CONTAINED, FaultKind.NO_EFFECT})


@dataclass
class Fault:
    """An injected fault. ``None`` selectors match anything; ``remaining=None`` never expires."""

    kind: FaultKind
    integration: str | None = None
    operation: str | None = None  # an ActionType value or one of READ_OPERATIONS
    target: str | None = None
    remaining: int | None = 1
    retry_after: float | None = None

    def matches(self, integration: str, operation: str, target: str | None) -> bool:
        if self.integration is not None and self.integration != integration:
            return False
        if self.operation is not None and self.operation != operation:
            return False
        if self.target is not None and target is not None and self.target.lower() != target.lower():
            return False
        if self.target is not None and target is None:
            return False
        if self.kind in _STATE_FAULTS and operation in READ_OPERATIONS:
            return False
        return self.remaining is None or self.remaining > 0

    def to_error(self, integration: str, operation: str) -> IntegrationError:
        """The typed error this fault raises (``ALREADY_CONTAINED``/``NO_EFFECT`` raise nothing)."""
        where = f"{integration}.{operation}: simulated"
        if self.kind is FaultKind.FAIL:
            return ApiError(f"{where} API failure", integration=integration, http_status=500)
        if self.kind is FaultKind.UNAVAILABLE:
            return IntegrationUnavailableError(f"{where} outage", integration=integration, http_status=503)
        if self.kind is FaultKind.AUTH_FAIL:
            return AuthFailedError(f"{where} authentication failure", integration=integration,
                                   http_status=401)
        if self.kind is FaultKind.RATE_LIMIT:
            return RateLimitedError(f"{where} rate limit", integration=integration,
                                    retry_after=self.retry_after)
        if self.kind is FaultKind.TIMEOUT:
            return IntegrationTimeoutError(f"{where} timeout", integration=integration)
        if self.kind is FaultKind.INVALID_TARGET:
            return InvalidTargetError(f"{where} unknown target", integration=integration, http_status=404)
        raise ValueError(f"{self.kind.value} does not map to an error")


# ---------------------------------------------------------------- effects --
@dataclass(frozen=True)
class _Effect:
    facet: str
    value: Any
    default: Any


_A = ActionType


def _pair(contain: ActionType, restore: ActionType | None, facet: str, on: Any, off: Any,
          default: Any) -> list[tuple[ActionType, _Effect]]:
    rows = [(contain, _Effect(facet, on, default))]
    if restore is not None:
        rows.append((restore, _Effect(facet, off, default)))
    return rows


def _build_effects() -> Mapping[ActionType, _Effect]:
    rows: list[tuple[ActionType, _Effect]] = [
        *_pair(_A.ISOLATE_ENDPOINT, _A.RELEASE_ENDPOINT, "endpoint.isolated", True, False, False),
        *_pair(_A.BLOCK_DOMAIN, _A.UNBLOCK_DOMAIN, "domain.blocked", True, False, False),
        *_pair(_A.BLOCK_URL, _A.UNBLOCK_URL, "url.blocked", True, False, False),
        *_pair(_A.BLOCK_IP, _A.UNBLOCK_IP, "ip.blocked", True, False, False),
        *_pair(_A.BLOCK_HASH, _A.UNBLOCK_HASH, "hash.blocked", True, False, False),
        *_pair(_A.DISABLE_USER, _A.ENABLE_USER, "user.disabled", True, False, False),
        *_pair(_A.REVOKE_SESSIONS, None, "user.sessions_revoked", True, None, False),
        *_pair(_A.CONFIRM_USER_COMPROMISED, None, "user.compromised", True, None, False),
        *_pair(_A.QUARANTINE_EMAIL, _A.RELEASE_EMAIL, "email.location", "quarantine", "inbox", "inbox"),
        *_pair(_A.DELETE_EMAIL, None, "email.location", "deleted", None, "inbox"),
        *_pair(_A.BLOCK_NETWORK_CLIENT, _A.RESTORE_NETWORK_CLIENT, "client.blocked", True, False, False),
        *_pair(_A.LOCK_DEVICE, None, "device.locked", True, None, False),
        *_pair(_A.REMOVE_PRIVILEGED_ROLE, _A.RESTORE_PRIVILEGED_ROLE, "role.assigned", False, True, True),
        *_pair(_A.TERMINATE_PROCESS, None, "process.running", False, None, True),
        *_pair(_A.QUARANTINE_FILE, _A.RESTORE_FILE, "file.quarantined", True, False, False),
        *_pair(_A.REMOVE_PERSISTENCE, None, "persistence.present", False, None, True),
        *_pair(_A.RESET_PASSWORD, None, "user.password_reset", True, None, False),
        *_pair(_A.RESET_MFA, None, "user.mfa_reset", True, None, False),
        *_pair(_A.REVOKE_APP_CREDENTIALS, None, "credential.revoked", True, None, False),
        *_pair(_A.REMOVE_APPLICATION, None, "application.installed", False, None, True),
    ]
    effects = dict(rows)
    missing = {a for a in ActionType if get_action_spec(a).state_changing} - set(effects)
    if missing:  # pragma: no cover - guarded by unit tests
        raise RuntimeError(f"simulated effects missing for {sorted(m.value for m in missing)}")
    return effects


#: State-changing action type -> (facet, desired value, default value of the facet).
ACTION_EFFECTS: Mapping[ActionType, _Effect] = _build_effects()


# ------------------------------------------------------------ environment --
@dataclass(frozen=True)
class Reputation:
    verdict: Verdict
    risk_score: int = 0
    confidence: int = 0
    summary: str = ""
    #: Integrations that "know" this reputation; ``None`` means every enriching adapter does.
    integrations: frozenset[str] | None = None

    def known_by(self, integration: str) -> bool:
        return self.integrations is None or integration in self.integrations


@dataclass(frozen=True)
class SimulatedCall:
    """One call that reached the simulated vendor (state-changing or read)."""

    integration: str
    operation: str
    kind: OperationKind
    target: str | None
    result: str
    at: datetime


@dataclass
class SimulatedEnvironment:
    """In-memory vendor state shared by every simulated adapter of one run."""

    clock: Clock = field(default_factory=lambda: DEFAULT_CLOCK)
    state: dict[tuple[str, str], Any] = field(default_factory=dict)
    reputations: dict[tuple[ObservableType, str], Reputation] = field(default_factory=dict)
    findings: dict[tuple[ActionType, str], list[dict[str, Any]]] = field(default_factory=dict)
    health: dict[str, HealthStatus] = field(default_factory=dict)
    invalid_targets: set[str] = field(default_factory=set)
    faults: list[Fault] = field(default_factory=list)
    calls: list[SimulatedCall] = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _ref_counter: int = field(default=0, repr=False)

    # ---------------------------------------------------------- state --
    @staticmethod
    def _key(facet: str, target: str) -> tuple[str, str]:
        return facet, target.lower()

    def get(self, facet: str, target: str, default: Any = None) -> Any:
        with self._lock:
            return self.state.get(self._key(facet, target), default)

    def set(self, facet: str, target: str, value: Any) -> None:
        with self._lock:
            self.state[self._key(facet, target)] = value

    def state_for(self, action_type: ActionType, target: str) -> Any:
        """Current value of the facet ``action_type`` changes on ``target``."""
        effect = ACTION_EFFECTS[ActionType(action_type)]
        return self.get(effect.facet, target, effect.default)

    def in_desired_state(self, action_type: ActionType, target: str) -> bool:
        effect = ACTION_EFFECTS[ActionType(action_type)]
        return self.state_for(action_type, target) == effect.value

    def force_desired_state(self, action_type: ActionType, target: str) -> None:
        """Put ``target`` in the state ``action_type`` would produce (scenario setup)."""
        effect = ACTION_EFFECTS[ActionType(action_type)]
        self.set(effect.facet, target, effect.value)

    def apply(self, action_type: ActionType, target: str) -> tuple[bool, Any]:
        """Apply ``action_type``. Returns ``(changed, previous value)``; idempotent."""
        effect = ACTION_EFFECTS[ActionType(action_type)]
        with self._lock:
            previous = self.get(effect.facet, target, effect.default)
            if previous == effect.value:
                return False, previous
            self.set(effect.facet, target, effect.value)
            return True, previous

    def next_ref(self, integration: str) -> str:
        with self._lock:
            self._ref_counter += 1
            return f"sim-{integration}-{self._ref_counter:06d}"

    # ---------------------------------------------------- scenario data --
    def set_reputation(self, observable_type: ObservableType, value: str, verdict: Verdict, *,
                       risk_score: int = 0, confidence: int = 0, summary: str = "",
                       integrations: Sequence[str] | None = None) -> None:
        """Reputation of one observable; ``integrations`` limits which adapters report it."""
        self.reputations[(ObservableType(observable_type), value.strip().lower())] = Reputation(
            verdict=Verdict(verdict), risk_score=risk_score, confidence=confidence, summary=summary,
            integrations=frozenset(integrations) if integrations is not None else None)

    def reputation(self, observable: Observable) -> Reputation | None:
        return self.reputations.get((observable.type, observable.value.strip().lower()))

    def add_findings(self, action_type: ActionType, subject: str, *findings: Mapping[str, Any]) -> None:
        bucket = self.findings.setdefault((ActionType(action_type), subject.strip().lower()), [])
        bucket.extend(dict(f) for f in findings)

    def findings_for(self, action_type: ActionType, subject: str) -> list[dict[str, Any]]:
        return list(self.findings.get((action_type, subject.strip().lower()), []))

    def set_health(self, integration: str, status: HealthStatus) -> None:
        self.health[integration] = HealthStatus(status)

    def mark_invalid_target(self, target: str) -> None:
        self.invalid_targets.add(target.lower())

    def is_invalid_target(self, target: str) -> bool:
        return target.lower() in self.invalid_targets

    # ---------------------------------------------------------- faults --
    def inject(self, kind: FaultKind, *, integration: str | None = None, operation: str | ActionType | None = None,
               target: str | None = None, times: int | None = 1, retry_after: float | None = None) -> Fault:
        """Inject a fault; ``times=None`` keeps it until :meth:`clear_faults`."""
        if times is not None and times < 1:
            raise ValueError("times must be >= 1 or None")
        op = operation.value if isinstance(operation, ActionType) else operation
        fault = Fault(kind=FaultKind(kind), integration=integration, operation=op, target=target,
                      remaining=times, retry_after=retry_after)
        with self._lock:
            self.faults.append(fault)
        return fault

    def clear_faults(self) -> None:
        with self._lock:
            self.faults.clear()

    def take_fault(self, integration: str, operation: str, target: str | None) -> Fault | None:
        """First matching fault, consuming one use."""
        with self._lock:
            for fault in self.faults:
                if fault.matches(integration, operation, target):
                    if fault.remaining is not None:
                        fault.remaining -= 1
                    self.faults[:] = [f for f in self.faults if f.remaining is None or f.remaining > 0]
                    return fault
        return None

    # ----------------------------------------------------------- calls --
    def record(self, integration: str, operation: str, kind: OperationKind, target: str | None,
               result: str) -> SimulatedCall:
        call = SimulatedCall(integration=integration, operation=operation, kind=kind, target=target,
                             result=result, at=self.clock.now())
        with self._lock:
            self.calls.append(call)
        return call

    def state_changing_calls(self) -> list[SimulatedCall]:
        """Every state-changing call that reached the simulated vendor (dry-run proofs)."""
        return [c for c in self.calls if c.kind is OperationKind.STATE_CHANGING]


# ---------------------------------------------------------------- families --
_O = ObservableType
_HASHES = (_O.SHA256, _O.SHA1, _O.MD5)


@dataclass(frozen=True)
class _Family:
    actions: frozenset[ActionType]
    enrichment_types: frozenset[ObservableType]
    investigations: frozenset[ActionType]
    display: str


FAMILIES: Mapping[str, _Family] = {
    "endpoint": _Family(
        actions=frozenset({_A.ISOLATE_ENDPOINT, _A.RELEASE_ENDPOINT, _A.BLOCK_HASH, _A.UNBLOCK_HASH,
                           _A.TERMINATE_PROCESS, _A.QUARANTINE_FILE, _A.RESTORE_FILE,
                           _A.REMOVE_PERSISTENCE, _A.LOCK_DEVICE, _A.REMOVE_APPLICATION}),
        enrichment_types=frozenset({_O.HOSTNAME, _O.ENDPOINT_ID, *_HASHES}),
        investigations=frozenset({_A.INVESTIGATE_ENDPOINT, _A.INVESTIGATE_HASH, _A.INVESTIGATE_PROCESS,
                                  _A.SEARCH_HASH_ENTERPRISE, _A.SEARCH_RELATED_ENDPOINTS}),
        display="endpoint",
    ),
    "identity": _Family(
        actions=frozenset({_A.DISABLE_USER, _A.ENABLE_USER, _A.REVOKE_SESSIONS, _A.CONFIRM_USER_COMPROMISED,
                           _A.REMOVE_PRIVILEGED_ROLE, _A.RESTORE_PRIVILEGED_ROLE, _A.RESET_PASSWORD,
                           _A.RESET_MFA, _A.REVOKE_APP_CREDENTIALS}),
        enrichment_types=frozenset({_O.USER, _O.EMAIL_ADDRESS}),
        investigations=frozenset({_A.INVESTIGATE_USER, _A.INVESTIGATE_AUTHENTICATION,
                                  _A.SEARCH_USER_ACTIVITY, _A.SEARCH_RELATED_USERS}),
        display="identity",
    ),
    "email": _Family(
        actions=frozenset({_A.QUARANTINE_EMAIL, _A.RELEASE_EMAIL, _A.DELETE_EMAIL}),
        enrichment_types=frozenset({_O.EMAIL_ADDRESS, _O.EMAIL_MESSAGE_ID}),
        investigations=frozenset({_A.INVESTIGATE_EMAIL, _A.SEARCH_EMAIL_CAMPAIGN}),
        display="email",
    ),
    "network": _Family(
        actions=frozenset({_A.BLOCK_DOMAIN, _A.UNBLOCK_DOMAIN, _A.BLOCK_URL, _A.UNBLOCK_URL, _A.BLOCK_IP,
                           _A.UNBLOCK_IP, _A.BLOCK_NETWORK_CLIENT, _A.RESTORE_NETWORK_CLIENT}),
        enrichment_types=frozenset({_O.DOMAIN, _O.URL, _O.IP, _O.IPV6}),
        investigations=frozenset({_A.INVESTIGATE_IP, _A.INVESTIGATE_DOMAIN, _A.INVESTIGATE_NETWORK_CONNECTION,
                                  _A.SEARCH_DOMAIN_ENTERPRISE, _A.SEARCH_IP_ENTERPRISE}),
        display="DNS/network",
    ),
    "intel": _Family(
        actions=frozenset(),
        enrichment_types=frozenset({_O.IP, _O.IPV6, _O.DOMAIN, _O.URL, *_HASHES, _O.EMAIL_ADDRESS}),
        investigations=frozenset(),
        display="threat intelligence",
    ),
}

_ENRICH_ACTION: Mapping[ObservableType, ActionType] = {
    _O.IP: _A.ENRICH_IP, _O.IPV6: _A.ENRICH_IP, _O.DOMAIN: _A.ENRICH_DOMAIN, _O.URL: _A.ENRICH_URL,
    _O.SHA256: _A.ENRICH_HASH, _O.SHA1: _A.ENRICH_HASH, _O.MD5: _A.ENRICH_HASH,
    _O.EMAIL_ADDRESS: _A.ENRICH_EMAIL_ADDRESS, _O.USER: _A.ENRICH_USER,
    _O.HOSTNAME: _A.ENRICH_ENDPOINT, _O.ENDPOINT_ID: _A.ENRICH_ENDPOINT,
}


def _family_union(families: Sequence[str]) -> _Family:
    unknown = [f for f in families if f not in FAMILIES]
    if unknown or not families:
        raise ValueError(f"unknown simulated families {unknown}; known: {sorted(FAMILIES)}")
    picked = [FAMILIES[f] for f in families]
    return _Family(
        actions=frozenset().union(*(f.actions for f in picked)),
        enrichment_types=frozenset().union(*(f.enrichment_types for f in picked)),
        investigations=frozenset().union(*(f.investigations for f in picked)),
        display=" + ".join(f.display for f in picked),
    )


def build_simulated_manifest(integration: str, families: Sequence[str]) -> CapabilityManifest:
    """Manifest of a simulated adapter posing as ``integration`` with the given families."""
    fam = _family_union(families)
    ordered = sorted(fam.actions, key=lambda a: a.value)
    ops = [OperationSpec(name=a.value, kind=OperationKind.STATE_CHANGING, status=EndpointStatus.VERIFIED,
                         source=SIMULATOR_SOURCE, action_types=(a,)) for a in ordered]
    ops.append(OperationSpec(name="verify_state", kind=OperationKind.VERIFY, status=EndpointStatus.VERIFIED,
                             source=SIMULATOR_SOURCE, action_types=tuple(ordered)))
    read_actions = {_ENRICH_ACTION[t] for t in fam.enrichment_types if t in _ENRICH_ACTION}
    read_actions |= fam.investigations
    ops.append(OperationSpec(name="enrich", kind=OperationKind.READ, status=EndpointStatus.VERIFIED,
                             source=SIMULATOR_SOURCE,
                             action_types=tuple(sorted(read_actions, key=lambda a: a.value))))
    ops.append(OperationSpec(name="health", kind=OperationKind.READ, status=EndpointStatus.VERIFIED,
                             source=SIMULATOR_SOURCE))
    return CapabilityManifest(
        integration=integration,
        display_name=f"Simulated {fam.display} ({integration})",
        optional=integration == "splunk",
        enabled_by_default=integration != "splunk",
        native_xdr=integration == "cisco_xdr",
        supported_actions=frozenset(fam.actions),
        verifiable_actions=frozenset(fam.actions),
        read_actions=frozenset(read_actions),
        enrichment_types=fam.enrichment_types,
        operations=tuple(ops),
        escalation_hint="simulated environment: no vendor console",
        rate_limit_note="none (in-memory)",
    )


# ----------------------------------------------------------------- adapter --
def _simulated_action(action_type: ActionType) -> Callable[..., ActionOutcome]:
    """A guarded method named after ``action_type`` that applies it to the environment."""

    def method(self: "SimulatedAdapter", request: ActionRequest) -> ActionOutcome:
        return self._apply(action_type, request)

    method.__name__ = action_type.value
    method.__qualname__ = f"SimulatedAdapter.{action_type.value}"
    method.__doc__ = f"Simulated, guarded ``{action_type.value}``."
    return state_changing(method)


class SimulatedAdapter(IntegrationAdapter):
    """Base of the simulated family. Use a family subclass or :func:`simulated_adapter_class`."""

    name: ClassVar[str]
    manifest: ClassVar[CapabilityManifest]
    families: ClassVar[tuple[str, ...]] = ()

    def __init__(self, config: IntegrationConfig | None = None, secrets: SecretProvider | None = None, *,
                 environment: SimulatedEnvironment | None = None,
                 transport: "httpx.BaseTransport | None" = None, clock: Clock | None = None,
                 audit: AuditSink | None = None, settings: "Settings | None" = None,
                 sleep: Callable[[float], None] | None = None) -> None:
        super().__init__(config or IntegrationConfig(enabled=True), secrets or StaticSecretProvider({}),
                         transport=transport, clock=clock, audit=audit, settings=settings, sleep=sleep)
        self.environment = environment or SimulatedEnvironment(clock=self.clock)

    def build_http_client(self) -> "GuardedHttpClient":
        raise RuntimeError(f"simulated adapter {self.name} makes no HTTP calls")

    # ----------------------------------------------------------- reads --
    def health_check(self) -> IntegrationHealth:
        """Never raises: disabled -> UNKNOWN; injected fault -> classified; else override or CONNECTED."""
        if not self.enabled:
            return self.disabled_health()
        fault = self.environment.take_fault(self.name, "health_check", None)
        if fault is not None:
            return health_from_exception(self.name, fault.to_error(self.name, "health_check"), clock=self.clock)
        status = self.environment.health.get(self.name, HealthStatus.CONNECTED)
        return IntegrationHealth(integration=self.name, status=status, checked_at=self.clock.now(),
                                 detail="simulated", latency_ms=0)

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Reputation from the environment (``UNKNOWN`` verdict when nothing is known)."""
        if observable.type not in self.manifest.enrichment_types:
            raise self._unsupported(f"enrichment of {observable.type.value}")
        self._read_preflight("enrich", observable.value)
        rep = self.environment.reputation(observable)
        self.environment.record(self.name, "enrich", OperationKind.READ, observable.value, "OK")
        if rep is None or not rep.known_by(self.name):
            return EnrichmentResult(type=observable.type, value=observable.value, risk_score=0, confidence=0,
                                    sources=(self.name,), verdict=Verdict.UNKNOWN, integration=self.name)
        evidence = EvidenceDraft(
            source=self.name, observed_at=self.clock.now(), reference=f"sim:{self.name}:{observable.value}",
            summary=rep.summary or f"{self.name} rates {observable.value} {rep.verdict.value}",
            data={"verdict": rep.verdict.value, "risk_score": rep.risk_score, "confidence": rep.confidence},
        )
        return EnrichmentResult(type=observable.type, value=observable.value, risk_score=rep.risk_score,
                                confidence=rep.confidence, sources=(self.name,), verdict=rep.verdict,
                                integration=self.name, evidence=(evidence,))

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        """Findings registered with :meth:`SimulatedEnvironment.add_findings`."""
        if query.action_type not in self.manifest.read_actions:
            raise self._unsupported(f"investigation {query.action_type.value}")
        self._read_preflight("investigate", query.subject.value)
        findings = self.environment.findings_for(query.action_type, query.subject.value)[: query.limit]
        self.environment.record(self.name, "investigate", OperationKind.READ, query.subject.value, "OK")
        evidence = tuple(
            EvidenceDraft(source=self.name, observed_at=self.clock.now(),
                          summary=str(f.get("summary") or f"{query.action_type.value} finding {i}"),
                          reference=f"sim:{self.name}:{query.action_type.value}:{i}", data=f)
            for i, f in enumerate(findings, start=1)
        )
        return InvestigationResult(integration=self.name, action_type=query.action_type, subject=query.subject,
                                   findings=tuple(findings), evidence=evidence)

    def current_state(self, request: ActionRequest) -> TargetStateCheck:
        """Read-only idempotency check against the environment."""
        if request.action_type not in self.manifest.supported_actions:
            return TargetStateCheck(state=TargetState.UNKNOWN,
                                    detail=f"{self.name}: {request.action_type.value} not simulated here")
        self._read_preflight("current_state", request.target)
        if self.environment.is_invalid_target(request.target):
            raise InvalidTargetError(f"{self.name}: unknown target {request.target}", integration=self.name,
                                     http_status=404)
        desired = self.environment.in_desired_state(request.action_type, request.target)
        value = self.environment.state_for(request.action_type, request.target)
        state = TargetState.IN_DESIRED_STATE if desired else TargetState.NOT_IN_DESIRED_STATE
        return TargetStateCheck(state=state, detail=f"{ACTION_EFFECTS[request.action_type].facet}={value!r}",
                                api_calls=(self._summary("current_state", OperationKind.VERIFY, request.target),))

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """Read-back of the environment. Never raises."""
        def result(status: VerificationStatus, details: str, method: str = "verify_state",
                   terminal: bool | None = None) -> VerificationResult:
            return VerificationResult(idempotency_key=request.idempotency_key, status=status,
                                      integration=self.name, method=method, checked_at=self.clock.now(),
                                      details=details, terminal=terminal)

        if request.action_type not in self.manifest.verifiable_actions:
            return result(VerificationStatus.UNABLE_TO_VERIFY,
                          f"{self.name}: no read-back for {request.action_type.value}", "none")
        fault = self.environment.take_fault(self.name, "verify", request.target)
        if fault is not None:
            return result(VerificationStatus.UNABLE_TO_VERIFY,
                          f"{self.name}: verification call failed ({fault.kind.value})")
        value = self.environment.state_for(request.action_type, request.target)
        facet = ACTION_EFFECTS[request.action_type].facet
        if self.environment.in_desired_state(request.action_type, request.target):
            return result(VerificationStatus.VERIFIED, f"{facet}={value!r} on {request.target}", terminal=True)
        # the in-memory state is authoritative (no eventual consistency): NOT_VERIFIED is final
        return result(VerificationStatus.NOT_VERIFIED, f"{facet}={value!r} on {request.target} (not applied)",
                      terminal=True)

    # ---------------------------------------------------------- writes --
    isolate_endpoint = _simulated_action(_A.ISOLATE_ENDPOINT)
    block_domain = _simulated_action(_A.BLOCK_DOMAIN)
    block_url = _simulated_action(_A.BLOCK_URL)
    block_ip = _simulated_action(_A.BLOCK_IP)
    block_hash = _simulated_action(_A.BLOCK_HASH)
    disable_user = _simulated_action(_A.DISABLE_USER)
    revoke_sessions = _simulated_action(_A.REVOKE_SESSIONS)
    confirm_user_compromised = _simulated_action(_A.CONFIRM_USER_COMPROMISED)
    quarantine_email = _simulated_action(_A.QUARANTINE_EMAIL)
    block_network_client = _simulated_action(_A.BLOCK_NETWORK_CLIENT)
    lock_device = _simulated_action(_A.LOCK_DEVICE)
    remove_privileged_role = _simulated_action(_A.REMOVE_PRIVILEGED_ROLE)
    delete_email = _simulated_action(_A.DELETE_EMAIL)
    terminate_process = _simulated_action(_A.TERMINATE_PROCESS)
    quarantine_file = _simulated_action(_A.QUARANTINE_FILE)
    remove_persistence = _simulated_action(_A.REMOVE_PERSISTENCE)
    reset_password = _simulated_action(_A.RESET_PASSWORD)
    reset_mfa = _simulated_action(_A.RESET_MFA)
    revoke_app_credentials = _simulated_action(_A.REVOKE_APP_CREDENTIALS)
    remove_application = _simulated_action(_A.REMOVE_APPLICATION)
    release_endpoint = _simulated_action(_A.RELEASE_ENDPOINT)
    unblock_domain = _simulated_action(_A.UNBLOCK_DOMAIN)
    unblock_url = _simulated_action(_A.UNBLOCK_URL)
    unblock_ip = _simulated_action(_A.UNBLOCK_IP)
    unblock_hash = _simulated_action(_A.UNBLOCK_HASH)
    enable_user = _simulated_action(_A.ENABLE_USER)
    release_email = _simulated_action(_A.RELEASE_EMAIL)
    restore_network_client = _simulated_action(_A.RESTORE_NETWORK_CLIENT)
    restore_privileged_role = _simulated_action(_A.RESTORE_PRIVILEGED_ROLE)
    restore_file = _simulated_action(_A.RESTORE_FILE)

    # --------------------------------------------------------- private --
    def _apply(self, action_type: ActionType, request: ActionRequest) -> ActionOutcome:
        """Body of every guarded write.

        Re-checks the guard itself (defence in depth, like the HTTP client's write path), so calling
        the undecorated method (for example via ``__wrapped__``) can never change simulated state.
        """
        if request.action_type is not action_type:
            raise ValueError(f"{action_type.value} called with a {request.action_type.value} request")
        _guard.require_authorization(request, integration=self.name)
        _guard.require_active_authorization(self.name)
        if not self.enabled:
            raise IntegrationUnavailableError(f"{self.name} is disabled", integration=self.name, retryable=False)
        if action_type not in self.manifest.supported_actions:
            raise self._unsupported(action_type.value)
        target, op = request.target, action_type.value
        no_effect = self._write_faults(op, action_type, target)
        if self.environment.is_invalid_target(target):
            self.environment.record(self.name, op, OperationKind.STATE_CHANGING, target, "INVALID_TARGET")
            raise InvalidTargetError(f"{self.name}: unknown target {target}", integration=self.name,
                                     http_status=404)
        if no_effect:
            changed, previous = True, self.environment.state_for(action_type, target)
        else:
            changed, previous = self.environment.apply(action_type, target)
        status = ActionResultStatus.SUCCESS if changed else ActionResultStatus.ALREADY_CONTAINED
        self.environment.record(self.name, op, OperationKind.STATE_CHANGING, target, status.value)
        summary = self._summary(op, OperationKind.STATE_CHANGING, target, incident_id=request.incident_id)
        verb = get_action_spec(action_type).dry_run_verb.removeprefix("Would ").strip()
        return ActionOutcome(
            status=status, integration=self.name,
            message=f"simulated: {verb}: {target}" if changed else f"simulated: already in desired state: {target}",
            external_ref=self.environment.next_ref(self.name) if changed else None,
            rollback_params=self._rollback_params(action_type, previous) if changed else {},
            api_calls=(summary,), executed_at=self.clock.now(),
        )

    def _write_faults(self, op: str, action_type: ActionType, target: str) -> bool:
        """Apply an injected fault to a write. Returns True for ``NO_EFFECT``."""
        fault = self.environment.take_fault(self.name, op, target)
        if fault is None:
            return False
        if fault.kind is FaultKind.ALREADY_CONTAINED:
            self.environment.force_desired_state(action_type, target)
            return False
        if fault.kind is FaultKind.NO_EFFECT:
            return True
        self.environment.record(self.name, op, OperationKind.STATE_CHANGING, target, fault.kind.value)
        raise fault.to_error(self.name, op)

    @staticmethod
    def _rollback_params(action_type: ActionType, previous: Any) -> dict[str, Any]:
        rollback = get_action_spec(action_type).rollback_action_type
        if rollback is None:
            return {}
        return {"rollback_action_type": rollback.value, "previous_state": previous}

    def _read_preflight(self, operation: str, target: str | None) -> None:
        if not self.enabled:
            raise IntegrationUnavailableError(f"{self.name} is disabled", integration=self.name, retryable=False)
        fault = self.environment.take_fault(self.name, operation, target)
        if fault is not None:
            self.environment.record(self.name, operation, OperationKind.READ, target, fault.kind.value)
            raise fault.to_error(self.name, operation)

    def _summary(self, operation: str, kind: OperationKind, target: str, *,
                 incident_id: str | None = None) -> ApiCallSummary:
        summary = ApiCallSummary(integration=self.name, operation=operation, method="SIM",
                                 url=f"sim://{self.name}/{operation}", kind=kind, status_code=200,
                                 duration_ms=0, attempt=1, request_summary={"target": target})
        self._audit(summary, incident_id)
        return summary

    def _audit(self, summary: ApiCallSummary, incident_id: str | None) -> None:
        if self.audit is None:
            return
        try:
            self.audit.append(AuditEventType.API_CALL, incident_id=incident_id, actor=f"integration:{self.name}",
                              payload=summary.model_dump(mode="json"))
        except Exception as exc:  # noqa: BLE001
            if summary.kind is OperationKind.STATE_CHANGING:
                raise AuditError(f"audit append failed: {type(exc).__name__}") from exc


# ---------------------------------------------------------------- factories --
_CLASS_CACHE: dict[tuple[str, tuple[str, ...]], type[SimulatedAdapter]] = {}
_CLASS_LOCK = threading.Lock()


def simulated_adapter_class(integration: str, families: Sequence[str]) -> type[SimulatedAdapter]:
    """A :class:`SimulatedAdapter` subclass posing as ``integration`` (cached per combination)."""
    key = (integration, tuple(sorted(set(families))))
    with _CLASS_LOCK:
        cls = _CLASS_CACHE.get(key)
        if cls is None:
            title = "".join(p.title() for p in (*key[1], *integration.split("_")))
            cls = type(f"Simulated{title}Adapter", (SimulatedAdapter,), {
                "name": integration,
                "families": key[1],
                "manifest": build_simulated_manifest(integration, key[1]),
                "__module__": __name__,
            })
            _CLASS_CACHE[key] = cls
    return cls


class SimulatedEndpointAdapter(SimulatedAdapter):
    """EDR/MDM family: isolation, hash blocks, process/file/persistence/app remediation, device lock."""

    name = "secure_endpoint"
    families = ("endpoint",)
    manifest = build_simulated_manifest("secure_endpoint", ("endpoint",))


class SimulatedIdentityAdapter(SimulatedAdapter):
    """Identity family: disable/enable user, sessions, compromise, roles, password/MFA/app credentials."""

    name = "entra"
    families = ("identity",)
    manifest = build_simulated_manifest("entra", ("identity",))


class SimulatedEmailAdapter(SimulatedAdapter):
    """Email family: quarantine, release, delete."""

    name = "secure_email"
    families = ("email",)
    manifest = build_simulated_manifest("secure_email", ("email",))


class SimulatedNetworkAdapter(SimulatedAdapter):
    """DNS/network family: domain, URL, IP and network-client blocks and their removal."""

    name = "umbrella"
    families = ("network",)
    manifest = build_simulated_manifest("umbrella", ("network",))


class SimulatedIntelAdapter(SimulatedAdapter):
    """Threat-intelligence family: enrichment only (no state-changing actions)."""

    name = "virustotal"
    families = ("intel",)
    manifest = build_simulated_manifest("virustotal", ("intel",))


#: Integration name -> families. Covers every catalog-routable state-changing action type
#: (``remove_persistence`` has no catalog integration and is therefore never routed).
SIMULATED_SUITE: Mapping[str, tuple[str, ...]] = {
    "secure_endpoint": ("endpoint",),
    "defender_endpoint": ("endpoint", "network"),
    "intune": ("endpoint",),
    "entra": ("identity",),
    "secure_email": ("email",),
    "defender_o365": ("email",),
    "umbrella": ("network",),
    "meraki": ("network",),
    "virustotal": ("intel",),
    "alienvault_otx": ("intel",),
}


def build_simulated_adapters(environment: SimulatedEnvironment, *,
                             suite: Mapping[str, Sequence[str]] = SIMULATED_SUITE,
                             clock: Clock | None = None, audit: AuditSink | None = None) -> list[SimulatedAdapter]:
    """One enabled simulated adapter per ``suite`` entry, all sharing ``environment``."""
    return [simulated_adapter_class(name, fams)(environment=environment, clock=clock or environment.clock,
                                                audit=audit)
            for name, fams in suite.items()]


def register_simulated_adapters(registry: "AdapterRegistry", environment: SimulatedEnvironment, *,
                                suite: Mapping[str, Sequence[str]] = SIMULATED_SUITE,
                                audit: AuditSink | None = None) -> list[SimulatedAdapter]:
    """Build the simulated suite and install it in ``registry`` (replacing real adapters)."""
    adapters = build_simulated_adapters(environment, suite=suite, clock=registry.clock,
                                        audit=audit if audit is not None else registry.audit)
    for adapter in adapters:
        registry.register(adapter)
    return adapters
