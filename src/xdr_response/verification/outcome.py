"""Combine execution and verification into the overall containment / restoration state.

Rules (architecture section 6.4):

* Only approved actions count. ``SKIPPED`` with ``REJECTED_BY_ANALYST`` and ``DRY_RUN`` results are
  excluded (restoration also excludes ``CONTROL_NOT_ACTIVE``: nothing was left to release).
* An action is **confirmed** when its status is ``SUCCESS`` or ``ALREADY_CONTAINED`` and its
  verification is ``VERIFIED`` (or ``UNABLE_TO_VERIFY`` when
  ``verification.unable_to_verify_counts_as_contained`` is true; default false).
* An action **failed** when its status is ``FAILED``, it was ``SKIPPED`` for any other reason, or its
  verification is ``NOT_VERIFIED``.
* Anything else (executed but unverifiable, or never verified) is **unconfirmed**.
* All confirmed: ``CONTAINED``. All failed: ``CONTAINMENT_FAILED``. Otherwise ``PARTIALLY_CONTAINED``.

Follow-up recommendation (never applied automatically; the lifecycle and a human decide):

* ``REMEDIATION_REQUIRED`` when a control is reported applied but the read-back shows it is not in
  effect, an action failed with a non-retryable error (permissions, invalid target, unsupported or
  unverified endpoint, platform fault), or an action was skipped because no adapter could run it.
  These need work outside this automation.
* ``AWAITING_APPROVAL`` when the only failures are transient (timeout, rate limit, unavailable): a
  new package for the remaining actions, which needs a new human approval.
* No recommendation when everything was confirmed.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from xdr_response.logs.redaction import get_redactor
from xdr_response.models import (
    ActionResult,
    ActionResultStatus,
    ContainmentOverall,
    ErrorCode,
    ErrorInfo,
    IncidentState,
    RestorationOverall,
    SkipReason,
    VerificationResult,
    VerificationStatus,
    can_transition,
)
from xdr_response.execution import outcome as _rules
from xdr_response.execution.outcome import ActionVerdict, classify_action, is_effective, to_incident_state
from xdr_response.verification.escalation import SOC_ANALYST, integration_owner, recommend_escalation

__all__ = [
    "ActionVerdict",
    "ActionAssessment",
    "ContainmentAssessment",
    "TRANSIENT_ERROR_CODES",
    "classify_action",
    "is_effective",
    "compute_containment_overall",
    "compute_restoration_overall",
    "to_incident_state",
    "assess_action",
    "assess_containment",
    "assess_restoration",
    "apply_verification",
]

_EXECUTED = frozenset({ActionResultStatus.SUCCESS, ActionResultStatus.ALREADY_CONTAINED})

#: Failures a new approval and a re-run may fix; everything else needs remediation by a human.
TRANSIENT_ERROR_CODES = frozenset({ErrorCode.TIMEOUT, ErrorCode.RATE_LIMITED, ErrorCode.UNAVAILABLE})

_MANUAL_SKIPS = frozenset({SkipReason.NO_CAPABLE_ADAPTER, SkipReason.INTEGRATION_DISABLED})


@dataclass(frozen=True)
class ActionAssessment:
    """Per-action verdict plus what a human needs to know about it."""

    idempotency_key: str
    action_type: str
    target: str
    integration: str | None
    status: ActionResultStatus
    verification: VerificationStatus | None
    verdict: ActionVerdict
    requires_attention: bool
    reason: str = ""
    error: ErrorInfo | None = None
    escalation: str | None = None
    needs_remediation: bool = False
    retry_may_help: bool = False

    @property
    def label(self) -> str:
        """``"<action_type> <target>"`` as shown on the result table."""
        return f"{self.action_type} {self.target}"


@dataclass(frozen=True)
class ContainmentAssessment:
    """Overall state of a containment (or restoration) run and the actions needing attention."""

    incident_id: str
    results: tuple[ActionResult, ...]
    actions: tuple[ActionAssessment, ...]
    overall: ContainmentOverall | RestorationOverall | None
    incident_state: IncidentState | None
    recommended_next_state: IncidentState | None
    remediation_reasons: tuple[str, ...] = ()
    restoration: bool = False

    @property
    def attention(self) -> tuple[ActionAssessment, ...]:
        """Actions that require a human (failed, skipped, not verified, unable to verify)."""
        return tuple(a for a in self.actions if a.requires_attention)

    @property
    def remediation_required(self) -> bool:
        return self.recommended_next_state is IncidentState.REMEDIATION_REQUIRED

    def attention_lines(self) -> tuple[str, ...]:
        """One line per attention item, suitable for ``ContainmentReport.attention``."""
        return tuple(f"{a.label}: {a.reason}" if a.reason else a.label for a in self.attention)


# ------------------------------------------------------------ overall rules --
# The per-action rules and the overall calculation live in ``xdr_response.execution.outcome`` (one
# rule set for execution, verification, reporting and lifecycle). This module adds the dry-run view
# (``None``) and the per-action assessment used for attention lines and next-state recommendations.
def _only_dry_run(results: Sequence[ActionResult]) -> bool:
    return bool(results) and all(r.status is ActionResultStatus.DRY_RUN for r in results)


def _real(results: Sequence[ActionResult]) -> list[ActionResult]:
    return [r for r in results if r.status is not ActionResultStatus.DRY_RUN]


def compute_containment_overall(results: Sequence[ActionResult], *,
                                unable_to_verify_counts_as_contained: bool = False
                                ) -> ContainmentOverall | None:
    """Overall containment state; ``None`` for a dry run. Nothing executed is ``CONTAINMENT_FAILED``."""
    if _only_dry_run(results):
        return None
    return _rules.compute_containment_overall(
        _real(results), unable_to_verify_counts_as_contained=unable_to_verify_counts_as_contained)


def compute_restoration_overall(results: Sequence[ActionResult], *,
                                unable_to_verify_counts_as_contained: bool = False
                                ) -> RestorationOverall | None:
    """Overall restoration state; ``None`` for a dry run. Nothing executed is ``RESTORATION_FAILED``."""
    if _only_dry_run(results):
        return None
    return _rules.compute_restoration_overall(
        _real(results), unable_to_verify_counts_as_contained=unable_to_verify_counts_as_contained)


# ------------------------------------------------------------- per action --
def _redact(text: str) -> str:
    return get_redactor().redact_text(text)


def _http_note(error: ErrorInfo) -> str:
    prefix = f"HTTP {error.http_status} " if error.http_status else ""
    return f"{prefix}({error.code.value})"


def _error_reason(error: ErrorInfo | None) -> str:
    if error is None:
        return "failed (no error recorded)"
    message = f": {_redact(error.message)}" if error.message else ""
    return f"{_http_note(error)}{message}"


def _is_transient(error: ErrorInfo | None) -> bool:
    return error is not None and (error.code in TRANSIENT_ERROR_CODES or error.retryable)


def _verification_reason(verification: VerificationResult | None) -> str:
    if verification is None:
        return "not verified: verify manually"
    if verification.status is VerificationStatus.NOT_VERIFIED:
        return f"control not in effect: {_redact(verification.details)}".rstrip(": ")
    return f"unable to verify: {_redact(verification.details)}".rstrip(": ")


def _verification_escalation(result: ActionResult, verification: VerificationResult | None,
                             hints: Mapping[str, str] | None) -> str:
    if verification is not None and verification.status is VerificationStatus.NOT_VERIFIED:
        return result.recommended_escalation or integration_owner(
            verification.integration or result.integration, hints)
    return result.recommended_escalation or SOC_ANALYST


def assess_action(result: ActionResult, *, unable_to_verify_counts: bool = False,
                  restoration: bool = False,
                  escalation_hints: Mapping[str, str] | None = None) -> ActionAssessment:
    """Verdict, attention flag, reason and escalation owner for one action."""
    verdict = classify_action(result, unable_to_verify_counts=unable_to_verify_counts,
                              restoration=restoration)
    verification = result.verification
    base = {
        "idempotency_key": result.idempotency_key,
        "action_type": result.action_type.value,
        "target": result.target,
        "integration": result.integration,
        "status": result.status,
        "verification": verification.status if verification else None,
        "verdict": verdict,
        "error": result.error,
    }
    if verdict is ActionVerdict.EXCLUDED:
        reason = result.skip_reason.value if result.skip_reason else ""
        return ActionAssessment(**base, requires_attention=False, reason=reason)
    if result.status is ActionResultStatus.FAILED:
        transient = _is_transient(result.error)
        return ActionAssessment(**base, requires_attention=True, reason=_error_reason(result.error),
                                escalation=recommend_escalation(result, hints=escalation_hints),
                                needs_remediation=not transient, retry_may_help=transient)
    if result.status is ActionResultStatus.SKIPPED:
        manual = result.skip_reason in _MANUAL_SKIPS
        reason = f"skipped ({result.skip_reason.value if result.skip_reason else 'unknown'})"
        return ActionAssessment(**base, requires_attention=True, reason=reason,
                                escalation=recommend_escalation(result, hints=escalation_hints),
                                needs_remediation=manual, retry_may_help=not manual)
    status = verification.status if verification else None
    if status is VerificationStatus.VERIFIED:
        return ActionAssessment(**base, requires_attention=bool(result.requires_attention),
                                escalation=result.recommended_escalation)
    not_in_effect = status is VerificationStatus.NOT_VERIFIED
    return ActionAssessment(**base, requires_attention=True, reason=_verification_reason(verification),
                            escalation=_verification_escalation(result, verification, escalation_hints),
                            needs_remediation=not_in_effect)


# ---------------------------------------------------------------- overall --
def _recommend_next(state: IncidentState | None, actions: Sequence[ActionAssessment],
                    restoration: bool) -> tuple[IncidentState | None, tuple[str, ...]]:
    if state is None:
        return None, ()
    reasons = tuple(f"{a.label}: {a.reason}" for a in actions if a.needs_remediation)
    if reasons:
        candidate: IncidentState | None = IncidentState.REMEDIATION_REQUIRED
    elif any(a.retry_may_help for a in actions) and not restoration:
        candidate = IncidentState.AWAITING_APPROVAL
    else:
        candidate = None
    if candidate is not None and not can_transition(state, candidate):
        candidate = None
    return candidate, reasons


def _assess(incident_id: str, results: Sequence[ActionResult], *, restoration: bool,
            unable_to_verify_counts: bool,
            escalation_hints: Mapping[str, str] | None) -> ContainmentAssessment:
    actions = tuple(assess_action(r, unable_to_verify_counts=unable_to_verify_counts,
                                  restoration=restoration, escalation_hints=escalation_hints)
                    for r in results)
    overall: ContainmentOverall | RestorationOverall | None
    if restoration:
        overall = compute_restoration_overall(
            results, unable_to_verify_counts_as_contained=unable_to_verify_counts)
    else:
        overall = compute_containment_overall(
            results, unable_to_verify_counts_as_contained=unable_to_verify_counts)
    state = to_incident_state(overall) if overall is not None else None
    next_state, reasons = _recommend_next(state, actions, restoration)
    return ContainmentAssessment(incident_id=incident_id, results=tuple(results), actions=actions,
                                 overall=overall, incident_state=state,
                                 recommended_next_state=next_state, remediation_reasons=reasons,
                                 restoration=restoration)


def assess_containment(incident_id: str, results: Sequence[ActionResult], *,
                       unable_to_verify_counts_as_contained: bool = False,
                       escalation_hints: Mapping[str, str] | None = None) -> ContainmentAssessment:
    """Combine execution and verification results of a containment run."""
    return _assess(incident_id, results, restoration=False,
                   unable_to_verify_counts=unable_to_verify_counts_as_contained,
                   escalation_hints=escalation_hints)


def assess_restoration(incident_id: str, results: Sequence[ActionResult], *,
                       unable_to_verify_counts_as_contained: bool = False,
                       escalation_hints: Mapping[str, str] | None = None) -> ContainmentAssessment:
    """Combine execution and verification results of a release (restoration) run."""
    return _assess(incident_id, results, restoration=True,
                   unable_to_verify_counts=unable_to_verify_counts_as_contained,
                   escalation_hints=escalation_hints)


def apply_verification(result: ActionResult, verification: VerificationResult | None, *,
                       unable_to_verify_counts: bool = False,
                       escalation_hints: Mapping[str, str] | None = None) -> ActionResult:
    """Return ``result`` with ``verification``, ``requires_attention`` and escalation filled in."""
    if verification is not None and verification.idempotency_key != result.idempotency_key:
        raise ValueError("verification result belongs to a different action")
    staged = result.model_copy(update={"verification": verification})
    assessment = assess_action(staged, unable_to_verify_counts=unable_to_verify_counts,
                               escalation_hints=escalation_hints)
    attention = assessment.requires_attention or result.requires_attention
    escalation = result.recommended_escalation or (assessment.escalation if attention else None)
    return ActionResult.model_validate({
        **staged.model_dump(),
        "requires_attention": attention,
        "recommended_escalation": escalation,
    })
