"""Private helpers shared by the runner and the executor: redaction, error mapping, result builders."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from xdr_response.errors import (
    ApprovalRequiredError,
    DryRunViolationError,
    IntegrationError,
)
from xdr_response.interfaces import AuditSink
from xdr_response.logs.redaction import Redactor
from xdr_response.models import (
    ActionPackage,
    ActionResult,
    ActionResultStatus,
    ApiCallSummary,
    AuditEventType,
    ErrorCode,
    ErrorInfo,
    RecommendedAction,
    SkipReason,
    VerificationStatus,
)

ACTOR = "automation:execution"


def redact_payload(redactor: Redactor, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Deep-redacted copy of an audit payload (secrets, tokens, keys, signatures removed)."""
    redacted = redactor.redact(dict(payload))
    return redacted if isinstance(redacted, dict) else {"payload": redacted}


def sanitize_calls(calls: Iterable[ApiCallSummary], redactor: Redactor) -> tuple[ApiCallSummary, ...]:
    """Re-redact API call summaries (defense in depth; the HTTP client already redacts)."""
    clean: list[ApiCallSummary] = []
    for call in calls:
        error = call.error
        if error is not None:
            error = error.model_copy(update={"message": redactor.redact_text(error.message)})
        clean.append(call.model_copy(update={
            "url": redactor.redact_url(call.url),
            "request_summary": redact_payload(redactor, call.request_summary),
            "response_summary": redact_payload(redactor, call.response_summary),
            "error": error,
        }))
    return tuple(clean)


def error_info_for(exc: BaseException, integration: str | None, redactor: Redactor) -> ErrorInfo:
    """Map any exception raised while executing one action to a redacted :class:`ErrorInfo`."""
    if isinstance(exc, IntegrationError):
        info = exc.to_error_info()
        return info.model_copy(update={"message": redactor.redact_text(info.message)})
    if isinstance(exc, DryRunViolationError):
        code = ErrorCode.DRY_RUN
    elif isinstance(exc, ApprovalRequiredError):
        code = ErrorCode.APPROVAL_DENIED
    else:
        code = ErrorCode.INTERNAL
    message = redactor.redact_text(f"{type(exc).__name__}: {exc}")
    return ErrorInfo(code=code, message=message, integration=integration)


def failed_result(action: RecommendedAction, *, started_at: datetime, finished_at: datetime,
                  error: ErrorInfo, message: str = "", integration: str | None = None) -> ActionResult:
    """A FAILED result that requires attention (nothing was executed by this path)."""
    return ActionResult(
        idempotency_key=action.idempotency_key, action_type=action.action_type, target=action.target,
        integration=integration if integration is not None else action.integration,
        approval_level=action.approval_level, status=ActionResultStatus.FAILED,
        started_at=started_at, finished_at=max(started_at, finished_at),
        message=message or error.message, error=error, requires_attention=True,
    )


def skipped_result(action: RecommendedAction, reason: SkipReason, *, started_at: datetime,
                   finished_at: datetime, message: str) -> ActionResult:
    """A SKIPPED result; anything but REJECTED_BY_ANALYST requires attention."""
    return ActionResult(
        idempotency_key=action.idempotency_key, action_type=action.action_type, target=action.target,
        integration=action.integration, approval_level=action.approval_level,
        status=ActionResultStatus.SKIPPED, skip_reason=reason, started_at=started_at,
        finished_at=max(started_at, finished_at), message=message,
        requires_attention=reason is not SkipReason.REJECTED_BY_ANALYST,
    )


def attention_reason(result: ActionResult) -> str:
    """Short human reason why a result needs attention."""
    if result.status is ActionResultStatus.FAILED and result.error is not None:
        status = f"HTTP {result.error.http_status} " if result.error.http_status else ""
        return f"{status}({result.error.code.value})".strip()
    if result.status is ActionResultStatus.SKIPPED and result.skip_reason is not None:
        return f"skipped ({result.skip_reason.value})"
    verification = result.verification
    if verification is not None and verification.status is VerificationStatus.UNABLE_TO_VERIFY:
        return "verify manually (UNABLE_TO_VERIFY)"
    if verification is not None and verification.status is VerificationStatus.NOT_VERIFIED:
        return "verification failed (NOT_VERIFIED)"
    return result.message or result.status.value


def attention_lines(results: Iterable[ActionResult]) -> tuple[str, ...]:
    """Report lines for results that need a human: one per action, then distinct escalations."""
    lines: list[str] = []
    escalations: list[str] = []
    for result in results:
        if not result.requires_attention:
            continue
        lines.append(f"Requires attention: {result.action_type.value} {result.target} - "
                     f"{attention_reason(result)}")
        hint = result.recommended_escalation
        if hint and hint not in escalations:
            escalations.append(hint)
    lines.extend(f"Recommended escalation: {hint}" for hint in escalations)
    return tuple(lines)


def safe_audit(audit: AuditSink, event_type: AuditEventType, *, package: ActionPackage,
               payload: Mapping[str, Any], redactor: Redactor, actor: str = ACTOR) -> bool:
    """Append one redacted audit record. Returns False (never raises) when the sink fails."""
    try:
        audit.append(
            event_type, incident_id=package.incident_id, actor=actor,
            payload=redact_payload(redactor, payload), workflow_id=package.workflow_id,
            workflow_version=package.workflow_version,
        )
    except Exception:  # noqa: BLE001 - audit failure is reported by the caller, never raised
        return False
    return True
