"""Shared doubles for restoration tests. Fake data only; no network, deterministic clock.

``FakeRunner`` mirrors the ``ActionRunner`` pipeline of section 6.2 closely enough to prove the
safety properties: it enters ``guard.authorized(token, request)`` and calls a ``@state_changing``
adapter method, so the real execution guard re-verifies the release token for every rollback.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import pytest

from tests.fixtures.factories import FIXED_NOW, make_incident, make_package, make_recommendation
from tests.fixtures.guard_helpers import FakeVerifier, install_fake_verifier, make_token
from xdr_response import guard
from xdr_response.clock import FixedClock
from xdr_response.config.schema import RuntimeSettings, Settings
from xdr_response.errors import (
    ApprovalRequiredError,
    AuditError,
    IntegrationError,
    IntegrationUnavailableError,
)
from xdr_response.models import (
    GENESIS_HASH,
    ActionOutcome,
    ActionPackage,
    ActionRequest,
    ActionResult,
    ActionResultStatus,
    ActionType,
    ApprovalLevel,
    ApprovalPurpose,
    ApprovalToken,
    ApprovalTokenClaims,
    ApproverClaim,
    AuditEventType,
    AuditRecord,
    ErrorCode,
    ErrorInfo,
    Incident,
    PrincipalKind,
    RecommendedAction,
    ReleasePackage,
    TemporaryControl,
    TokenActionGrant,
    VerificationResult,
    VerificationStatus,
)
from xdr_response.restoration import (
    InMemoryControlRegistry,
    RestorationEngine,
    RestorationPlanner,
    control_from_result,
)

DEFAULT_ROLLBACK_PARAMS: dict[ActionType, dict[str, Any]] = {
    ActionType.ISOLATE_ENDPOINT: {"connector_guid": "00000000-0000-4000-8000-000000001047"},
    ActionType.BLOCK_DOMAIN: {"destination_list_id": 101, "destination_id": "dest-0001"},
    ActionType.DISABLE_USER: {"user_object_id": "00000000-0000-4000-8000-0000000000aa"},
    ActionType.REMOVE_PRIVILEGED_ROLE: {"roleDefinitionId": "role-def-0001", "principalId": "principal-0001",
                                        "directoryScopeId": "/"},
}


# ------------------------------------------------------------------ audit --
class FakeAudit:
    """In-memory AuditSink double (no hash chain; the audit component owns that)."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self._records: list[AuditRecord] = []

    def append(self, event_type: AuditEventType, *, incident_id: str | None, actor: str,
               payload: Mapping[str, Any], workflow_id: str | None = None,
               workflow_version: str | None = None) -> AuditRecord:
        if self.fail:
            raise AuditError("audit sink unavailable (test)")
        record = AuditRecord(
            seq=len(self._records), record_id=f"rec-{len(self._records)}", timestamp=FIXED_NOW,
            event_type=event_type, incident_id=incident_id, workflow_id=workflow_id,
            workflow_version=workflow_version, actor=actor, payload=dict(payload),
            prev_hash=GENESIS_HASH, hash=GENESIS_HASH,
        )
        self._records.append(record)
        return record

    def records(self, incident_id: str | None = None) -> Iterator[AuditRecord]:
        return iter([r for r in self._records if incident_id is None or r.incident_id == incident_id])

    @property
    def head_hash(self) -> str:
        return GENESIS_HASH

    def of(self, event_type: AuditEventType) -> list[AuditRecord]:
        return [r for r in self._records if r.event_type is event_type]


# ---------------------------------------------------------------- adapter --
class FakeAdapter:
    """Vendor adapter double whose rollback methods are guarded by ``@state_changing``."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[ActionRequest] = []
        self.fail_targets: set[str] = set()
        self.already_released: set[str] = set()
        self.verification: dict[str, VerificationStatus] = {}

    def is_already_released(self, request: ActionRequest) -> bool:
        return request.target in self.already_released

    def execute(self, request: ActionRequest) -> ActionOutcome:
        return getattr(self, request.action_type.value)(request)

    def _do(self, request: ActionRequest) -> ActionOutcome:
        self.calls.append(request)
        if request.target in self.fail_targets:
            raise IntegrationUnavailableError("HTTP 503 from fake vendor", integration=self.name,
                                              http_status=503)
        return ActionOutcome(status=ActionResultStatus.SUCCESS, integration=self.name,
                             message="released", executed_at=FIXED_NOW)

    @guard.state_changing
    def release_endpoint(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)

    @guard.state_changing
    def unblock_domain(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)

    @guard.state_changing
    def enable_user(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)

    @guard.state_changing
    def restore_privileged_role(self, request: ActionRequest) -> ActionOutcome:
        return self._do(request)


# ----------------------------------------------------------------- runner --
class FakeRunner:
    """ActionRunner double: guard.authorized -> state pre-check -> adapter -> verification."""

    def __init__(self, adapters: Mapping[str, FakeAdapter], clock: FixedClock) -> None:
        self.adapters = dict(adapters)
        self.clock = clock
        self.runs: list[str] = []
        self.raise_for: set[str] = set()

    def run(self, action: RecommendedAction, token: ApprovalToken, *, package: ActionPackage,
            decision_id: str) -> ActionResult:
        self.runs.append(action.idempotency_key)
        if action.target in self.raise_for:
            raise RuntimeError("unexpected runner bug (test)")
        request = ActionRequest.from_recommendation(action)
        adapter = self.adapters[request.integration]
        started = self.clock.now()
        try:
            with guard.authorized(token, request):
                if adapter.is_already_released(request):
                    status = ActionResultStatus.ALREADY_CONTAINED
                else:
                    adapter.execute(request)
                    status = ActionResultStatus.SUCCESS
        except ApprovalRequiredError as exc:
            return self._failed(action, started, ErrorInfo(code=ErrorCode.APPROVAL_DENIED, message=str(exc)))
        except IntegrationError as exc:
            return self._failed(action, started, exc.to_error_info())
        verification = VerificationResult(
            idempotency_key=action.idempotency_key,
            status=adapter.verification.get(action.target, VerificationStatus.VERIFIED),
            integration=adapter.name, method="fake_read_back", checked_at=self.clock.now(),
        )
        return ActionResult(
            idempotency_key=action.idempotency_key, action_type=action.action_type, target=action.target,
            integration=adapter.name, approval_level=action.approval_level, status=status,
            started_at=started, finished_at=self.clock.now(), verification=verification,
        )

    def _failed(self, action: RecommendedAction, started: Any, error: ErrorInfo) -> ActionResult:
        return ActionResult(
            idempotency_key=action.idempotency_key, action_type=action.action_type, target=action.target,
            integration=action.integration, approval_level=action.approval_level,
            status=ActionResultStatus.FAILED, started_at=started, finished_at=self.clock.now(),
            message=error.message, error=error, requires_attention=True,
        )


# ---------------------------------------------------------------- helpers --
def build_control(*, incident_id: str = "XDR-83921", action_type: ActionType = ActionType.ISOLATE_ENDPOINT,
                  target: str = "TH-LT-1047", integration: str = "secure_endpoint",
                  rollback_params: Mapping[str, Any] | None = None,
                  approval_level: ApprovalLevel = ApprovalLevel.STANDARD,
                  review_after_hours: Mapping[str, int] | None = None,
                  clock: FixedClock | None = None) -> TemporaryControl:
    """A control exactly as the containment pipeline would register it (via control_from_result)."""
    action = make_recommendation(action_type, target, integration, incident_id, approval_level)
    package = make_package(action, incident_id=incident_id, package_id="pkg-test")
    token = make_token(action, purpose=ApprovalPurpose.CONTAINMENT)
    result = ActionResult(
        idempotency_key=action.idempotency_key, action_type=action.action_type, target=action.target,
        integration=integration, approval_level=action.approval_level, status=ActionResultStatus.SUCCESS,
        started_at=FIXED_NOW, finished_at=FIXED_NOW, control_registered=True,
    )
    params = dict(DEFAULT_ROLLBACK_PARAMS.get(action_type, {}) if rollback_params is None else rollback_params)
    outcome = ActionOutcome(status=ActionResultStatus.SUCCESS, integration=integration,
                            external_ref=f"ext-{action.target}", rollback_params=params, executed_at=FIXED_NOW)
    return control_from_result(action, result, outcome, package=package, token=token,
                               decision_id="decision-containment",
                               review_after_hours=review_after_hours or {}, clock=clock or FixedClock(FIXED_NOW))


def release_token(package: ReleasePackage, *, keys: tuple[str, ...] | None = None,
                  purpose: ApprovalPurpose = ApprovalPurpose.RELEASE, incident_id: str | None = None,
                  ttl: timedelta = timedelta(minutes=30)) -> ApprovalToken:
    """Unsigned release token (FakeVerifier does not check signatures) bound to ``package``."""
    actions = [package.action(k) for k in keys] if keys is not None else list(package.actions)
    claims = ApprovalTokenClaims(
        token_id=uuid.uuid4().hex, purpose=purpose, package_id=package.package_id,
        incident_id=incident_id or package.incident_id, evidence_snapshot_hash=package.evidence_snapshot_hash,
        workflow_id=package.workflow_id, workflow_version=package.workflow_version,
        decision_id="decision-release",
        actions=tuple(
            TokenActionGrant(idempotency_key=a.idempotency_key, action_type=a.action_type, target=a.target,
                             params_hash=a.params_hash, approval_level=a.approval_level)
            for a in actions
        ),
        approvers=(ApproverClaim(principal_id="lead.two@example.com", kind=PrincipalKind.HUMAN,
                                 roles=("xdr-approver", "xdr-elevated-approver")),),
        issued_at=FIXED_NOW, expires_at=FIXED_NOW + ttl,
    )
    return ApprovalToken(claims=claims, key_id="test", signature="0" * 64)


@dataclass
class Env:
    """Wired restoration components around fakes."""

    clock: FixedClock
    registry: InMemoryControlRegistry
    audit: FakeAudit
    adapters: dict[str, FakeAdapter]
    runner: FakeRunner
    verifier: FakeVerifier
    settings: Settings
    planner: RestorationPlanner
    incident: Incident
    ids: list[str] = field(default_factory=list)

    def engine(self, settings: Settings | None = None, tokens: Any = None,
               simulator: Any = None) -> RestorationEngine:
        return RestorationEngine(self.runner, self.registry, tokens or self.verifier, settings or self.settings,
                                 audit=self.audit, simulator=simulator, clock=self.clock,
                                 id_factory=self._next_id)

    def _next_id(self) -> str:
        self.ids.append(f"id-{len(self.ids) + 1:04d}")
        return self.ids[-1]

    def contain(self, **kwargs: Any) -> TemporaryControl:
        kwargs.setdefault("clock", self.clock)
        return self.registry.register(build_control(**kwargs))

    def adapter_calls(self) -> int:
        return sum(len(a.calls) for a in self.adapters.values())


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(FIXED_NOW)


@pytest.fixture
def env(clock: FixedClock) -> Env:
    """Guard ON (verifier registered, dry run off), in-memory registry, fake runner and adapters."""
    verifier = install_fake_verifier(clock)
    registry = InMemoryControlRegistry(clock=clock)
    adapters = {name: FakeAdapter(name) for name in ("secure_endpoint", "umbrella", "entra")}
    settings = Settings(runtime=RuntimeSettings(dry_run=False))  # a live deployment
    counter = iter(range(1, 10_000))
    planner = RestorationPlanner(registry, settings, clock=clock, id_factory=lambda: f"rel-{next(counter):03d}")
    return Env(clock=clock, registry=registry, audit=FakeAudit(), adapters=adapters,
               runner=FakeRunner(adapters, clock), verifier=verifier, settings=settings, planner=planner,
               incident=make_incident())


@pytest.fixture
def control_factory() -> Callable[..., TemporaryControl]:
    return build_control


@pytest.fixture
def token_factory() -> Callable[..., ApprovalToken]:
    return release_token
