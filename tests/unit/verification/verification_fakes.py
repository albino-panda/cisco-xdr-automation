"""Local fakes for verification tests: a scripted read-only adapter, a registry and a fake sleep."""
from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from tests.fixtures.factories import FIXED_NOW, make_recommendation
from tests.fixtures.principals import make_test_secrets
from xdr_response.clock import FixedClock
from xdr_response.config import IntegrationConfig
from xdr_response.integrations import CapabilityManifest, IntegrationAdapter, OperationSpec
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResult,
    ActionResultStatus,
    ActionType,
    ApiCallSummary,
    ApprovalLevel,
    EndpointStatus,
    ErrorCode,
    ErrorInfo,
    HealthStatus,
    IntegrationHealth,
    OperationKind,
    SkipReason,
    VerificationResult,
    VerificationStatus,
)

DOC = "https://docs.example.com/verified-read"

VERIFIABLE = frozenset({
    ActionType.ISOLATE_ENDPOINT,
    ActionType.QUARANTINE_EMAIL,
    ActionType.BLOCK_DOMAIN,
    ActionType.DISABLE_USER,
})


def _manifest(integration: str, verifiable: frozenset[ActionType]) -> CapabilityManifest:
    return CapabilityManifest(
        integration=integration,
        display_name=f"Fake {integration}",
        verifiable_actions=verifiable,
        operations=(OperationSpec(name="read_state", kind=OperationKind.VERIFY,
                                  status=EndpointStatus.VERIFIED, method="GET",
                                  path="/state/{id}", source=DOC),),
        escalation_hint="",
    )


class ScriptedVerifyAdapter(IntegrationAdapter):
    """Read-only adapter whose ``verify`` returns (or raises) the scripted items in order.

    Script items: a ``VerificationStatus`` (turned into a result), a ``VerificationResult``, or an
    exception instance (raised). The last item repeats when the script runs out.
    """

    name = "secure_endpoint"
    manifest = _manifest("secure_endpoint", VERIFIABLE)

    def __init__(self, script: Iterable[Any], *, clock: FixedClock, enabled: bool = True,
                 method: str = "read_state") -> None:
        super().__init__(IntegrationConfig(enabled=enabled), make_test_secrets(), clock=clock)
        self.script = list(script)
        self.method = method
        self.calls: list[tuple[str, ActionOutcome | None]] = []

    def health_check(self) -> IntegrationHealth:
        return IntegrationHealth(integration=self.name, status=HealthStatus.CONNECTED,
                                 checked_at=self.clock.now())

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        self.calls.append((request.idempotency_key, outcome))
        index = min(len(self.calls), len(self.script)) - 1
        item = self.script[index]
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, VerificationResult):
            return item
        return VerificationResult(
            idempotency_key=request.idempotency_key,
            status=item,
            integration=self.name,
            method=self.method,
            checked_at=self.clock.now(),
            details=f"read {len(self.calls)}: {item.value}",
            api_calls=(api_call(self.name),),
        )


class FakeEntraVerify(ScriptedVerifyAdapter):
    name = "entra"
    manifest = _manifest("entra", frozenset({ActionType.DISABLE_USER, ActionType.REVOKE_SESSIONS}))


class FakeRegistry:
    """Minimal ``AdapterRegistry.get`` stand-in."""

    def __init__(self, *adapters: IntegrationAdapter) -> None:
        self._adapters = {a.name: a for a in adapters}

    def get(self, name: str) -> IntegrationAdapter:
        return self._adapters[name]


class FakeSleep:
    """Records sleeps and advances the shared fake clock."""

    def __init__(self, clock: FixedClock | None = None) -> None:
        self.clock = clock
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        if self.clock is not None:
            self.clock.advance(timedelta(seconds=seconds))


def api_call(integration: str, status_code: int = 200) -> ApiCallSummary:
    return ApiCallSummary(integration=integration, operation="read_state", method="GET",
                          url="https://api.example.com/state/1", kind=OperationKind.VERIFY,
                          status_code=status_code, duration_ms=5, attempt=1)


def make_request(action_type: ActionType = ActionType.ISOLATE_ENDPOINT, target: str = "TH-LT-1047",
                 integration: str = "secure_endpoint", **params: Any) -> ActionRequest:
    return ActionRequest.from_recommendation(
        make_recommendation(action_type, target, integration, **params))


def make_outcome(integration: str = "secure_endpoint",
                 status: ActionResultStatus = ActionResultStatus.SUCCESS) -> ActionOutcome:
    return ActionOutcome(status=status, integration=integration, executed_at=FIXED_NOW,
                         external_ref="ref-0001")


def verification(request_key: str, status: VerificationStatus | None,
                 integration: str = "secure_endpoint", details: str = "") -> VerificationResult | None:
    if status is None:
        return None
    return VerificationResult(idempotency_key=request_key, status=status, integration=integration,
                              method="read_state", checked_at=FIXED_NOW, details=details)


def make_result(action_type: ActionType = ActionType.ISOLATE_ENDPOINT, target: str = "TH-LT-1047",
                integration: str = "secure_endpoint", *,
                status: ActionResultStatus = ActionResultStatus.SUCCESS,
                verified: VerificationStatus | None = VerificationStatus.VERIFIED,
                error: ErrorInfo | None = None, skip_reason: SkipReason | None = None,
                escalation: str | None = None, details: str = "",
                dry_run_line: str | None = None) -> ActionResult:
    request = make_request(action_type, target, integration)
    return ActionResult(
        idempotency_key=request.idempotency_key,
        action_type=action_type,
        target=request.target,
        integration=integration,
        approval_level=ApprovalLevel.STANDARD,
        status=status,
        skip_reason=skip_reason,
        started_at=FIXED_NOW,
        finished_at=FIXED_NOW,
        error=error,
        verification=verification(request.idempotency_key, verified, integration, details),
        recommended_escalation=escalation,
        dry_run_line=dry_run_line,
    )


def error(code: ErrorCode, *, http_status: int | None = None, integration: str = "secure_endpoint",
          message: str = "", retryable: bool = False) -> ErrorInfo:
    return ErrorInfo(code=code, message=message or code.value.lower(), integration=integration,
                     http_status=http_status, retryable=retryable)
