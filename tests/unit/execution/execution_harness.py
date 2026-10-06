"""Fakes and builders for the execution engine tests (no network, no other Phase 0 components).

Import as ``tests.unit.execution.execution_harness``. Fake values only.
"""
from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from tests.fixtures.factories import FIXED_NOW, make_evidence, make_package, make_recommendation
from tests.fixtures.guard_helpers import FakeVerifier, install_fake_verifier, make_token
from tests.fixtures.principals import make_test_secrets
from xdr_response import guard
from xdr_response.clock import FixedClock
from xdr_response.config import IntegrationConfig
from xdr_response.config.schema import RuntimeSettings, Settings, Thresholds, VerificationSettings
from xdr_response.errors import RegistryError
from xdr_response.execution import ActionRunner, ContainmentExecutor, InMemoryExecutionStateStore
from xdr_response.execution.state_store import ExecutionStateStore
from xdr_response.integrations import CapabilityManifest, IntegrationAdapter, OperationSpec
from xdr_response.logs.redaction import Redactor
from xdr_response.models import (
    GENESIS_HASH,
    ActionOutcome,
    ActionPackage,
    ActionRequest,
    ActionResult,
    ActionResultStatus,
    ActionType,
    ApiCallSummary,
    ApprovalToken,
    AuditEventType,
    AuditRecord,
    ContainmentPackage,
    ContainmentReport,
    ControlStatus,
    EndpointStatus,
    ErrorInfo,
    HealthStatus,
    IntegrationHealth,
    OperationKind,
    RecommendedAction,
    ReleasePackage,
    TargetState,
    TargetStateCheck,
    TemporaryControl,
    VerificationResult,
    VerificationStatus,
    get_action_spec,
)

DOC = "https://docs.example.com/verified-page"
FAKE_SECRET = "s3cr3t-api-key-value-0001"
FAKE_BEARER = "Bearer abcdefghijklmnop0123456789"

__all__ = [
    "FIXED_NOW", "FAKE_SECRET", "FAKE_BEARER", "Harness", "FakeAudit", "FakeRegistry",
    "FakeVerification", "FakeAdapters", "FakeSimulator", "FakeSecureEndpoint", "FakeUmbrella",
    "FakeEntra", "bind_token", "make_harness", "make_release_package", "make_result",
    "make_package", "make_recommendation", "make_token",
]


# ------------------------------------------------------------------ adapters --
def _manifest(name: str, actions: tuple[ActionType, ...], escalation: str = "") -> CapabilityManifest:
    ops = tuple(
        OperationSpec(name=f"op_{a.value}", kind=OperationKind.STATE_CHANGING,
                      status=EndpointStatus.VERIFIED, method="POST", path=f"/fake/{a.value}",
                      source=DOC, action_types=(a,))
        for a in actions
    )
    return CapabilityManifest(integration=name, display_name=f"Fake {name}",
                              supported_actions=frozenset(actions), operations=ops,
                              escalation_hint=escalation)


class _Scripted:
    """Scriptable behaviour shared by the fake adapters (keyed by idempotency key)."""

    def _setup(self) -> None:
        self.calls: list[str] = []
        self.state_calls: list[str] = []
        self.errors: dict[str, BaseException] = {}
        self.states: dict[str, list[TargetState]] = {}
        self.state_errors: dict[str, BaseException] = {}
        self.outcome_status: dict[str, ActionResultStatus] = {}
        self.barrier: threading.Barrier | None = None
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def health_check(self) -> IntegrationHealth:
        return IntegrationHealth(integration=self.name, status=HealthStatus.CONNECTED,  # type: ignore[attr-defined]
                                 checked_at=FIXED_NOW)

    def current_state(self, request: ActionRequest) -> TargetStateCheck:
        key = request.idempotency_key
        self.state_calls.append(key)
        if key in self.state_errors:
            raise self.state_errors[key]
        sequence = self.states.get(key)
        state = TargetState.NOT_IN_DESIRED_STATE
        if sequence:
            state = sequence.pop(0) if len(sequence) > 1 else sequence[0]
        return TargetStateCheck(state=state, detail=f"fake state {state.value}")

    def _do(self, request: ActionRequest) -> ActionOutcome:
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.barrier is not None:
                self.barrier.wait()
            key = request.idempotency_key
            self.calls.append(key)
            if key in self.errors:
                raise self.errors[key]
            call = ApiCallSummary(
                integration=self.name, operation=f"op_{request.action_type.value}",  # type: ignore[attr-defined]
                method="POST", url=f"https://api.example.com/fake?api_key={FAKE_SECRET}",
                kind=OperationKind.STATE_CHANGING, status_code=200, duration_ms=5, attempt=1,
                request_summary={"target": request.target, "api_key": FAKE_SECRET},
                response_summary={"id": "ref-1", "access_token": FAKE_SECRET},
            )
            return ActionOutcome(
                status=self.outcome_status.get(key, ActionResultStatus.SUCCESS),
                integration=self.name,  # type: ignore[attr-defined]
                message=f"done ({FAKE_BEARER})", external_ref=f"ref-{len(self.calls)}",
                rollback_params={"vendor_object_id": f"obj-{len(self.calls)}"},
                api_calls=(call,), executed_at=FIXED_NOW,
            )
        finally:
            with self._lock:
                self.active -= 1


class FakeSecureEndpoint(_Scripted, IntegrationAdapter):
    name = "secure_endpoint"
    manifest = _manifest("secure_endpoint", (ActionType.ISOLATE_ENDPOINT, ActionType.RELEASE_ENDPOINT))

    def __init__(self, *, enabled: bool = True) -> None:
        IntegrationAdapter.__init__(self, IntegrationConfig(enabled=enabled), make_test_secrets(),
                                    clock=FixedClock(FIXED_NOW))
        self._setup()

    @guard.state_changing
    def isolate_endpoint(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)

    @guard.state_changing
    def release_endpoint(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)


class FakeUmbrella(_Scripted, IntegrationAdapter):
    name = "umbrella"
    manifest = _manifest("umbrella", (ActionType.BLOCK_DOMAIN, ActionType.UNBLOCK_DOMAIN))

    def __init__(self, *, enabled: bool = True) -> None:
        IntegrationAdapter.__init__(self, IntegrationConfig(enabled=enabled), make_test_secrets(),
                                    clock=FixedClock(FIXED_NOW))
        self._setup()

    @guard.state_changing
    def block_domain(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)

    @guard.state_changing
    def unblock_domain(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)


class FakeEntra(_Scripted, IntegrationAdapter):
    name = "entra"
    manifest = _manifest("entra", (ActionType.DISABLE_USER, ActionType.REVOKE_SESSIONS),
                         escalation="Microsoft 365 administrator")

    def __init__(self, *, enabled: bool = True) -> None:
        IntegrationAdapter.__init__(self, IntegrationConfig(enabled=enabled), make_test_secrets(),
                                    clock=FixedClock(FIXED_NOW))
        self._setup()

    @guard.state_changing
    def disable_user(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)

    @guard.state_changing
    def revoke_sessions(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)


class FakeAdapters:
    """AdapterProvider fake: ``get`` raises KeyError for unknown names."""

    def __init__(self, *adapters: IntegrationAdapter) -> None:
        self.by_name = {a.name: a for a in adapters}

    def get(self, name: str) -> IntegrationAdapter:
        return self.by_name[name]


# ----------------------------------------------------------------- services --
class FakeAudit:
    """AuditSink fake with an optional failure per event type."""

    def __init__(self) -> None:
        self.events: list[tuple[AuditEventType, dict[str, Any]]] = []
        self.fail_on: set[AuditEventType] = set()
        self._lock = threading.Lock()

    def append(self, event_type: AuditEventType, *, incident_id: str | None, actor: str,
               payload: Mapping[str, Any], workflow_id: str | None = None,
               workflow_version: str | None = None) -> AuditRecord:
        if event_type in self.fail_on:
            from xdr_response.errors import AuditError
            raise AuditError(f"audit sink down for {event_type.value}")
        with self._lock:
            self.events.append((event_type, dict(payload)))
            seq = len(self.events) - 1
        return AuditRecord(seq=seq, record_id=uuid.uuid4().hex, timestamp=FIXED_NOW, event_type=event_type,
                           incident_id=incident_id, workflow_id=workflow_id, workflow_version=workflow_version,
                           actor=actor, payload=dict(payload), prev_hash=GENESIS_HASH, hash="1" * 64)

    def records(self, incident_id: str | None = None) -> Iterator[AuditRecord]:
        return iter(())

    @property
    def head_hash(self) -> str:
        return GENESIS_HASH

    def types(self) -> list[AuditEventType]:
        return [e for e, _ in self.events]

    def of(self, event_type: AuditEventType) -> list[dict[str, Any]]:
        return [p for e, p in self.events if e is event_type]


class FakeRegistry:
    """ControlRegistry fake (idempotent register, no delete method)."""

    def __init__(self) -> None:
        self.controls: dict[str, TemporaryControl] = {}
        self.fail = False

    def register(self, control: TemporaryControl) -> TemporaryControl:
        if self.fail:
            raise RegistryError("registry unavailable")
        existing = self.controls.get(control.control_key)
        if existing is not None and existing.status is ControlStatus.ACTIVE:
            return existing
        self.controls[control.control_key] = control
        return control

    def get(self, control_key: str) -> TemporaryControl | None:
        return self.controls.get(control_key)

    def list(self, *, incident_id: str | None = None,
             status: ControlStatus | None = None) -> list[TemporaryControl]:
        return [c for c in self.controls.values()
                if (incident_id is None or c.incident_id == incident_id)
                and (status is None or c.status is status)]

    def list_active(self, incident_id: str | None = None) -> list[TemporaryControl]:
        return self.list(incident_id=incident_id, status=ControlStatus.ACTIVE)

    def mark_release_pending(self, control_key: str, *, release_package_id: str,
                             token_id: str) -> TemporaryControl:  # pragma: no cover - unused here
        raise NotImplementedError

    def mark_released(self, control_key: str, *, at: datetime) -> TemporaryControl:  # pragma: no cover
        raise NotImplementedError

    def mark_release_failed(self, control_key: str, *, error: ErrorInfo) -> TemporaryControl:  # pragma: no cover
        raise NotImplementedError


class FakeVerification:
    """VerificationEngine fake: status per idempotency key (default VERIFIED)."""

    def __init__(self) -> None:
        self.statuses: dict[str, VerificationStatus] = {}
        self.raise_for: set[str] = set()
        self.calls: list[tuple[str, ActionResultStatus | None]] = []

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        self.calls.append((request.idempotency_key, outcome.status if outcome else None))
        if request.idempotency_key in self.raise_for:
            raise RuntimeError(f"verify exploded with {FAKE_SECRET}")
        return VerificationResult(
            idempotency_key=request.idempotency_key,
            status=self.statuses.get(request.idempotency_key, VerificationStatus.VERIFIED),
            integration=request.integration, method="fake_read", checked_at=FIXED_NOW,
        )


class FakeSimulator:
    """DryRunSimulator fake: records whether it ran inside guard.dry_run()."""

    def __init__(self) -> None:
        self.calls = 0
        self.saw_dry_run: list[bool] = []

    def simulate(self, package: ActionPackage) -> ContainmentReport:
        self.calls += 1
        self.saw_dry_run.append(guard.is_dry_run())
        results = tuple(
            ActionResult(idempotency_key=a.idempotency_key, action_type=a.action_type, target=a.target,
                         integration=a.integration, approval_level=a.approval_level,
                         status=ActionResultStatus.DRY_RUN, started_at=FIXED_NOW, finished_at=FIXED_NOW,
                         dry_run_line=f"{get_action_spec(a.action_type).dry_run_verb}: {a.target}")
            for a in package.actions
        )
        return ContainmentReport(report_id="sim", incident_id=package.incident_id,
                                 package_id=package.package_id, token_id=None, dry_run=True,
                                 started_at=FIXED_NOW, finished_at=FIXED_NOW, results=results, overall=None)


# ------------------------------------------------------------------ builders --
def bind_token(token: ApprovalToken, package: ActionPackage, **claim_updates: Any) -> ApprovalToken:
    """Re-bind a ``make_token`` token to ``package`` (package id and evidence hash)."""
    updates: dict[str, Any] = {"package_id": package.package_id,
                               "evidence_snapshot_hash": package.evidence_snapshot_hash}
    updates.update(claim_updates)
    return token.model_copy(update={"claims": token.claims.model_copy(update=updates)})


def make_release_package(*actions: RecommendedAction) -> ReleasePackage:
    base = make_package()
    data = base.model_dump(exclude={"purpose", "actions", "endpoints", "users"})
    data.update(actions=actions, control_keys=tuple(a.params["restores"] for a in actions))
    return ReleasePackage(**data)


def make_result(status: ActionResultStatus = ActionResultStatus.SUCCESS,
                verification: VerificationStatus | None = VerificationStatus.VERIFIED, *,
                skip_reason: Any = None, key_suffix: str = "1") -> ActionResult:
    target = f"TH-LT-{key_suffix}"
    key = f"XDR-83921:isolate_endpoint:{target}"
    ver = None
    if verification is not None and status in (ActionResultStatus.SUCCESS, ActionResultStatus.ALREADY_CONTAINED):
        ver = VerificationResult(idempotency_key=key, status=verification, integration="secure_endpoint",
                                 method="fake", checked_at=FIXED_NOW)
    return ActionResult(
        idempotency_key=key, action_type=ActionType.ISOLATE_ENDPOINT, target=target,
        integration="secure_endpoint", approval_level="STANDARD", status=status, skip_reason=skip_reason,
        started_at=FIXED_NOW, finished_at=FIXED_NOW, verification=ver,
        dry_run_line="Would isolate: x" if status is ActionResultStatus.DRY_RUN else None,
    )


@dataclass
class Harness:
    clock: FixedClock
    verifier: FakeVerifier
    audit: FakeAudit
    registry: FakeRegistry
    verification: FakeVerification
    simulator: FakeSimulator
    se: FakeSecureEndpoint
    umbrella: FakeUmbrella
    entra: FakeEntra
    adapters: FakeAdapters
    store: ExecutionStateStore
    runner: ActionRunner
    redactor: Redactor
    settings: Settings = field(default_factory=lambda: live_settings())

    def executor(self, *, settings: Settings | None = None, simulator: Any = "default",
                 tokens: Any = None, **kwargs: Any) -> ContainmentExecutor:
        return ContainmentExecutor(
            self.runner, tokens or self.verifier, settings or self.settings, audit=self.audit,
            simulator=self.simulator if simulator == "default" else simulator, clock=self.clock,
            id_factory=lambda: "report-1", redactor=self.redactor, **kwargs,
        )

    def new_runner(self, store: ExecutionStateStore | None = None,
                   review_after_hours: Mapping[str, int] | None = None) -> ActionRunner:
        return ActionRunner(self.adapters, self.verification, registry=self.registry, audit=self.audit,
                            clock=self.clock, state_store=store or self.store,
                            review_after_hours=review_after_hours, redactor=self.redactor)

    def approve(self, package: ContainmentPackage | ReleasePackage, *keys: str) -> ApprovalToken:
        """Token granting ``keys`` (default: every package action), bound to the package."""
        actions = [a for a in package.actions if not keys or a.idempotency_key in keys]
        return bind_token(make_token(*actions), package)


def make_harness(store: ExecutionStateStore | None = None) -> Harness:
    clock = FixedClock(FIXED_NOW)
    verifier = install_fake_verifier(clock)
    audit, registry, verification = FakeAudit(), FakeRegistry(), FakeVerification()
    se, umbrella, entra = FakeSecureEndpoint(), FakeUmbrella(), FakeEntra()
    adapters = FakeAdapters(se, umbrella, entra)
    store = store or InMemoryExecutionStateStore()
    redactor = Redactor()
    redactor.register_secret(FAKE_SECRET)  # as a SecretProvider would on first use
    runner = ActionRunner(adapters, verification, registry=registry, audit=audit, clock=clock,
                          state_store=store, review_after_hours={"isolate_endpoint": 24},
                          redactor=redactor)
    return Harness(clock=clock, verifier=verifier, audit=audit, registry=registry, verification=verification,
                   simulator=FakeSimulator(), se=se, umbrella=umbrella, entra=entra, adapters=adapters,
                   store=store, runner=runner, redactor=redactor)


def live_settings(**kwargs: Any) -> Settings:
    """Settings of a live deployment (``runtime.dry_run`` false): the executor honours DRY_RUN=true."""
    return Settings(runtime=RuntimeSettings(dry_run=False), **kwargs)


def settings_with_unable_to_verify_counting() -> Settings:
    return live_settings(thresholds=Thresholds(
        verification=VerificationSettings(unable_to_verify_counts_as_contained=True)))


def expired_by(h: Harness, minutes: int = 31) -> None:
    """Advance the verifier clock past the 30 minute token TTL."""
    h.clock.advance(timedelta(minutes=minutes))


__all__ += ["settings_with_unable_to_verify_counting", "expired_by", "make_evidence", "live_settings"]
