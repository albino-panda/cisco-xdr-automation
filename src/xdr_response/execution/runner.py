"""Per-action execution pipeline (architecture section 6.2).

``ActionRunner.run`` executes exactly one approved action and never raises for it:

1. Approval and binding pre-checks: the token must hold a grant for the action key (otherwise
   ``SKIPPED`` / ``REJECTED_BY_ANALYST``), the action must belong to the package, its idempotency
   key is recomputed, and dry run refuses execution before anything is claimed. The token is then
   verified with the guard's verifier (``guard.check_token``, nothing consumed): a forged or foreign
   token gets ``FAILED`` and is never recorded, so it cannot poison the slot of the approved run.
2. The action is claimed in the :class:`ExecutionStateStore`; an existing claim is never re-sent
   (completed results are replayed, unfinished ones are reported as unknown outcome). A control
   this package already registered (durable registry) is never re-sent either, even after a
   restart with an empty execution store.
3. Adapter selection by ``params["integration"]`` (missing: ``NO_CAPABLE_ADAPTER``; disabled:
   ``INTEGRATION_DISABLED``).
4. Audit ``ACTION_STARTED``; if that write fails the action is not executed (``AUDIT_UNAVAILABLE``).
5. Under a process-wide lock per idempotency key (so two packages sharing the key never both write):
   the read-only ``current_state`` pre-check runs OUTSIDE the authorization (no write can pass the
   guard there), then ``guard.authorized(token, request)`` consumes the approval and either records
   ``ALREADY_CONTAINED`` (no vendor write) or calls ``adapter.execute``. A timed-out write is never
   retried blindly: the target state is re-read. When the pre-check failed, a positive re-check
   after a timeout is NOT turned into SUCCESS: the control in force may be someone else's.
6. Outside the guard: verification for ``SUCCESS`` / ``ALREADY_CONTAINED``.
7. ``SUCCESS`` of a control-creating action type registers a :class:`TemporaryControl`.
   ``ALREADY_CONTAINED`` is normally never registered (someone else's control). Exception: an
   earlier attempt for the same key (another package of the same incident) sent the write and its
   outcome stayed unknown (write timeout, or a claim that never completed). Then the control in
   force is most likely the automation's own write, so it is registered flagged "reconstructed"
   (requires attention) instead of becoming an orphan no release package can ever remove.
8. Audit ``ACTION_RESULT`` and ``VERIFICATION_RESULT`` with redacted API summaries.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from xdr_response import guard
from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.errors import IntegrationError, IntegrationTimeoutError
from xdr_response.execution._support import (
    ACTOR,
    error_info_for,
    failed_result,
    safe_audit,
    sanitize_calls,
    skipped_result,
)
from xdr_response.execution.protocols import ActionVerifier, AdapterProvider
from xdr_response.execution.state_store import (
    ExecutionPhase,
    ExecutionRecord,
    ExecutionStateStore,
    InMemoryExecutionStateStore,
)
from xdr_response.interfaces import AuditSink, ControlRegistry
from xdr_response.logs.redaction import Redactor, get_redactor
from xdr_response.models import (
    ActionOutcome,
    ActionPackage,
    ActionRequest,
    ActionResult,
    ActionResultStatus,
    ApiCallSummary,
    ApprovalToken,
    AuditEventType,
    ErrorCode,
    ErrorInfo,
    RecommendedAction,
    SkipReason,
    TargetState,
    TargetStateCheck,
    TemporaryControl,
    VerificationResult,
    VerificationStatus,
    ControlStatus,
    get_action_spec,
    make_idempotency_key,
)

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.integrations.base import IntegrationAdapter

__all__ = ["ActionRunner", "ControlFactory"]

#: Signature of ``xdr_response.restoration.control_from_result`` (architecture 13.17). The lifecycle
#: runtime injects it so the registry entry is built by the restoration component's single rule;
#: without one the runner uses an equivalent private builder.
ControlFactory = Callable[..., TemporaryControl]

_EXECUTED = (ActionResultStatus.SUCCESS, ActionResultStatus.ALREADY_CONTAINED)
#: Controls of the registry that are still in force.
_IN_FORCE = frozenset({ControlStatus.ACTIVE, ControlStatus.RELEASE_FAILED, ControlStatus.RELEASE_PENDING})

_KEY_LOCKS: dict[str, threading.Lock] = {}
_KEY_LOCKS_GUARD = threading.Lock()


def _key_lock(idempotency_key: str) -> threading.Lock:
    """Process-wide lock serializing pre-check + write per idempotency key (across packages)."""
    with _KEY_LOCKS_GUARD:
        return _KEY_LOCKS.setdefault(idempotency_key, threading.Lock())
#: Stable marker in the message of a FAILED result whose write was sent but timed out.
UNKNOWN_OUTCOME_MARKER = "write timed out; outcome unknown"


@dataclass
class _Draft:
    """Mutable accumulator for one action; frozen into an :class:`ActionResult` at the end."""

    action: RecommendedAction
    request: ActionRequest
    started_at: datetime
    integration: str | None
    status: ActionResultStatus = ActionResultStatus.FAILED
    skip_reason: SkipReason | None = None
    error: ErrorInfo | None = None
    message: str = ""
    outcome: ActionOutcome | None = None
    verification: VerificationResult | None = None
    control_registered: bool = False
    escalation: str | None = None
    api_calls: list[ApiCallSummary] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def skip(self, reason: SkipReason, message: str) -> None:
        self.status = ActionResultStatus.SKIPPED
        self.skip_reason = reason
        self.message = message

    def fail(self, error: ErrorInfo, message: str = "") -> None:
        self.status = ActionResultStatus.FAILED
        self.error = error
        self.message = message or error.message
        self.outcome = None


class ActionRunner:
    """Runs one approved action through the guarded pipeline. Shared by containment and release."""

    def __init__(self, adapters: AdapterProvider, verifier: ActionVerifier, *,
                 registry: ControlRegistry, audit: AuditSink, clock: Clock | None = None,
                 state_store: ExecutionStateStore | None = None,
                 review_after_hours: Mapping[str, int] | None = None,
                 redactor: Redactor | None = None, actor: str = ACTOR,
                 control_factory: ControlFactory | None = None) -> None:
        self._adapters = adapters
        self._control_factory = control_factory
        self._verifier = verifier
        self._registry = registry
        self._audit = audit
        self._clock: Clock = clock or DEFAULT_CLOCK
        self._store: ExecutionStateStore = state_store or InMemoryExecutionStateStore()
        self._review_after_hours = dict(review_after_hours or {})
        self._redactor = redactor or get_redactor()
        self._actor = actor

    @property
    def state_store(self) -> ExecutionStateStore:
        """The store consulted to prevent double execution."""
        return self._store

    # ------------------------------------------------------------------ API --
    def run(self, action: RecommendedAction, token: ApprovalToken, *, package: ActionPackage,
            decision_id: str) -> ActionResult:
        """Execute one approved action (section 6.2). Never raises for a single action."""
        started = self._clock.now()
        try:
            return self._run(action, token, package, decision_id, started)
        except Exception as exc:  # noqa: BLE001 - last resort: one action never stops the others
            error = error_info_for(exc, action.integration, self._redactor)
            return failed_result(action, started_at=started, finished_at=self._clock.now(), error=error)

    # ---------------------------------------------------------- pre-checks --
    def _run(self, action: RecommendedAction, token: ApprovalToken, package: ActionPackage,
             decision_id: str, started: datetime) -> ActionResult:
        early = self._precheck(action, token, package, started)
        if early is None:
            early = self._preverify(action, token, started)
        if early is not None:
            self._audit_result(early, package, token, decision_id)
            return early
        try:
            existing = self._store.begin(package_id=package.package_id,
                                         idempotency_key=action.idempotency_key,
                                         incident_id=action.incident_id, token_id=token.token_id,
                                         at=started)
        except Exception as exc:  # noqa: BLE001 - fail closed: no claim, no execution
            error = ErrorInfo(code=ErrorCode.INTERNAL, integration=action.integration,
                              message=self._redactor.redact_text(
                                  f"execution state store unavailable ({type(exc).__name__}); "
                                  "action not executed"))
            result = failed_result(action, started_at=started, finished_at=self._clock.now(), error=error)
            self._audit_result(result, package, token, decision_id)
            return result
        if existing is not None:
            return self._from_existing(existing, action, package, token, decision_id, started)
        try:
            result = self._pipeline(action, token, package, decision_id, started)
        except Exception as exc:  # noqa: BLE001 - still close the claim with a FAILED result
            error = error_info_for(exc, action.integration, self._redactor)
            result = failed_result(action, started_at=started, finished_at=self._clock.now(), error=error)
            self._audit_result(result, package, token, decision_id)
        return self._complete(result, package)

    def _precheck(self, action: RecommendedAction, token: ApprovalToken, package: ActionPackage,
                  started: datetime) -> ActionResult | None:
        """Checks that need no claim. Returns a terminal result, or None to continue."""
        now = self._clock.now()
        if not isinstance(token, ApprovalToken) or token.claims.grant(action.idempotency_key) is None:
            return skipped_result(action, SkipReason.REJECTED_BY_ANALYST, started_at=started,
                                  finished_at=now, message="not approved by the analyst")
        binding_error = self._binding_error(action, package)
        if binding_error is not None:
            error = ErrorInfo(code=ErrorCode.INTERNAL, message=binding_error,
                              integration=action.integration)
            return failed_result(action, started_at=started, finished_at=now, error=error)
        if guard.is_dry_run():
            error = ErrorInfo(code=ErrorCode.DRY_RUN, integration=action.integration,
                              message="dry run is active: state-changing actions are refused")
            return failed_result(action, started_at=started, finished_at=now, error=error)
        return None

    def _preverify(self, action: RecommendedAction, token: ApprovalToken, started: datetime) -> ActionResult | None:
        """Verify the token (nothing consumed) before anything is claimed or recorded."""
        try:
            guard.check_token(token, ActionRequest.from_recommendation(action))
        except Exception as exc:  # noqa: BLE001 - any verification problem: not executed, not recorded
            error = error_info_for(exc, action.integration, self._redactor)
            return failed_result(action, started_at=started, finished_at=self._clock.now(), error=error,
                                 message=f"approval refused before execution: {error.message}")
        return None

    @staticmethod
    def _binding_error(action: RecommendedAction, package: ActionPackage) -> str | None:
        if action.incident_id != package.incident_id:
            return "action incident does not match the package incident"
        try:
            in_package = package.action(action.idempotency_key)
        except KeyError:
            return "action is not part of the approved package"
        if in_package != action:
            return "action differs from the package action with the same key"
        expected = make_idempotency_key(action.incident_id, action.action_type, action.target)
        if expected != action.idempotency_key:
            return f"idempotency key mismatch (expected {expected})"
        return None

    def _from_existing(self, record: ExecutionRecord, action: RecommendedAction,
                       package: ActionPackage, token: ApprovalToken, decision_id: str,
                       started: datetime) -> ActionResult:
        """Never re-send an action that was already claimed for this package."""
        if record.phase is ExecutionPhase.COMPLETED and record.result is not None:
            prior = record.result
            note = "already executed for this package; result replayed (no new vendor call)"
            result = prior.model_copy(update={"message": f"{note}. {prior.message}".strip()})
        else:
            error = ErrorInfo(code=ErrorCode.INTERNAL, integration=action.integration,
                              message="a previous execution attempt did not complete; outcome unknown. "
                                      "Not re-executed: verify the target state manually")
            result = failed_result(action, started_at=started, finished_at=self._clock.now(), error=error)
        self._audit_result(result, package, token, decision_id, replayed=True)
        return result

    def _complete(self, result: ActionResult, package: ActionPackage) -> ActionResult:
        try:
            self._store.complete(package_id=package.package_id, idempotency_key=result.idempotency_key,
                                 result=result, at=self._clock.now())
        except Exception:  # noqa: BLE001 - the action already ran; flag it instead of raising
            note = "execution state could not be recorded (a re-run would report unknown outcome)"
            return result.model_copy(update={"requires_attention": True,
                                             "message": f"{result.message}; {note}".strip("; ")})
        return result

    # ------------------------------------------------------------ pipeline --
    def _pipeline(self, action: RecommendedAction, token: ApprovalToken, package: ActionPackage,
                  decision_id: str, started: datetime) -> ActionResult:
        request = ActionRequest.from_recommendation(action)
        draft = _Draft(action=action, request=request, started_at=started,
                       integration=request.integration)
        adapter = self._resolve_adapter(draft)
        if adapter is None:
            return self._finish(draft, package, token, decision_id)
        if not self._audit_started(draft, package, token, decision_id):
            draft.fail(ErrorInfo(code=ErrorCode.AUDIT_UNAVAILABLE, integration=draft.integration,
                                 message="audit trail unavailable: action not executed"))
            return self._finish(draft, package, token, decision_id)
        if self._already_registered_by(action, package, draft):
            try:
                with guard.authorized(token, draft.request):  # the approval is still consumed (no write)
                    pass
            except Exception as exc:  # noqa: BLE001 - replayed or invalid approval: FAILED, nothing sent
                draft.fail(error_info_for(exc, draft.integration, self._redactor))
                return self._finish(draft, package, token, decision_id)
            draft.verification = self._verify(draft)
            return self._finish(draft, package, token, decision_id)
        self._execute_guarded(adapter, token, draft)
        if draft.status in _EXECUTED:
            draft.verification = self._verify(draft)
        creates_control = get_action_spec(action.action_type).creates_control
        if draft.status is ActionResultStatus.SUCCESS and creates_control:
            self._register_control(draft, package, token, decision_id)
        elif (draft.status is ActionResultStatus.ALREADY_CONTAINED and creates_control
              and self._earlier_unknown_outcome(action, package)):
            self._register_reconstructed(draft, package, token, decision_id)
        return self._finish(draft, package, token, decision_id)

    def _already_registered_by(self, action: RecommendedAction, package: ActionPackage, draft: _Draft) -> bool:
        """A package executes once: a control this package registered is never re-sent (durable check)."""
        if not get_action_spec(action.action_type).creates_control:
            return False
        try:
            control = self._registry.get(action.idempotency_key)
        except Exception:  # noqa: BLE001 - the execution store claim still protects this process
            return False
        if control is None or control.package_id != package.package_id or control.status not in _IN_FORCE:
            return False
        draft.outcome = ActionOutcome(
            status=ActionResultStatus.ALREADY_CONTAINED, integration=draft.request.integration,
            message=(f"package {package.package_id} already executed this action (registered control "
                     f"{control.control_key} is {control.status.value}); not re-sent"),
            external_ref=control.external_ref, executed_at=self._clock.now())
        draft.status = ActionResultStatus.ALREADY_CONTAINED
        draft.message = draft.outcome.message
        return True

    def _earlier_unknown_outcome(self, action: RecommendedAction, package: ActionPackage) -> bool:
        """True when another package's attempt at this key sent a write whose outcome is unknown."""
        try:
            records = self._store.list(incident_id=action.incident_id)
        except Exception:  # noqa: BLE001 - advisory only
            return False
        for record in records:
            if record.idempotency_key != action.idempotency_key or record.package_id == package.package_id:
                continue
            if record.phase is ExecutionPhase.IN_PROGRESS:
                return True
            result = record.result
            if (result is not None and result.status is ActionResultStatus.FAILED and result.error is not None
                    and result.error.code is ErrorCode.TIMEOUT and UNKNOWN_OUTCOME_MARKER in result.message):
                return True
        return False

    def _register_reconstructed(self, draft: _Draft, package: ActionPackage, token: ApprovalToken,
                                decision_id: str) -> None:
        """Register the control an earlier timed-out write of the automation most likely created."""
        note = ("target already in the desired state after an earlier timed-out write of this action: "
                "registered as an automation control (reconstructed rollback parameters, review before "
                "release)")
        saved_status, saved_outcome = draft.status, draft.outcome
        draft.status = ActionResultStatus.SUCCESS
        draft.outcome = ActionOutcome(
            status=ActionResultStatus.SUCCESS, integration=draft.request.integration,
            message="reconstructed after an earlier write with unknown outcome",
            rollback_params=dict(draft.request.params), executed_at=self._clock.now())
        try:
            self._register_control(draft, package, token, decision_id)
        finally:
            draft.status, draft.outcome = saved_status, saved_outcome
        draft.notes.append(note)

    def _resolve_adapter(self, draft: _Draft) -> "IntegrationAdapter | None":
        name = draft.request.integration
        try:
            adapter = self._adapters.get(name)
        except KeyError:
            adapter = None
        if adapter is None:
            draft.skip(SkipReason.NO_CAPABLE_ADAPTER, f"no adapter available for integration {name!r}")
            return None
        if not getattr(adapter, "enabled", False):
            draft.skip(SkipReason.INTEGRATION_DISABLED, f"integration {name!r} is disabled")
            return None
        manifest = getattr(adapter, "manifest", None)
        draft.escalation = (getattr(manifest, "escalation_hint", "") or None)
        return adapter

    def _execute_guarded(self, adapter: "IntegrationAdapter", token: ApprovalToken, draft: _Draft) -> None:
        request = draft.request
        try:
            with _key_lock(request.idempotency_key):
                # Read-only pre-check OUTSIDE the authorization: no write can pass the guard here.
                check = self._current_state(adapter, draft)
                timed_out: IntegrationTimeoutError | None = None
                with guard.authorized(token, request):  # verifies and consumes the single use
                    if check is not None and check.state is TargetState.IN_DESIRED_STATE:
                        draft.outcome = ActionOutcome(
                            status=ActionResultStatus.ALREADY_CONTAINED, integration=adapter.name,
                            message=check.detail or "target already in the desired state",
                            executed_at=self._clock.now())
                    else:
                        try:
                            draft.outcome = adapter.execute(request)
                        except IntegrationTimeoutError as exc:
                            timed_out = exc
                if timed_out is not None:
                    self._recheck_after_timeout(adapter, draft, timed_out, precheck_failed=check is None)
        except Exception as exc:  # noqa: BLE001 - mapped to a FAILED result
            draft.fail(error_info_for(exc, draft.integration, self._redactor))
            if not isinstance(exc, IntegrationError):
                draft.escalation = None
            return
        if draft.outcome is None:
            return
        draft.status = draft.outcome.status
        draft.message = self._redactor.redact_text(draft.outcome.message)
        draft.escalation = None
        draft.api_calls.extend(draft.outcome.api_calls)

    def _current_state(self, adapter: "IntegrationAdapter", draft: _Draft) -> TargetStateCheck | None:
        """Read-only pre-check. A failing read is noted and treated as UNKNOWN (execution proceeds)."""
        try:
            check = adapter.current_state(draft.request)
        except Exception as exc:  # noqa: BLE001 - the pre-check is advisory
            draft.notes.append(self._redactor.redact_text(
                f"state pre-check failed ({type(exc).__name__}); executed without it"))
            return None
        draft.api_calls.extend(check.api_calls)
        return check

    def _recheck_after_timeout(self, adapter: "IntegrationAdapter", draft: _Draft,
                               exc: IntegrationTimeoutError, *, precheck_failed: bool = False) -> None:
        """A write timed out: re-read the target instead of retrying the write blindly."""
        check = self._current_state(adapter, draft)
        if check is None or check.state is not TargetState.IN_DESIRED_STATE:
            state = check.state.value if check is not None else TargetState.UNKNOWN.value
            draft.fail(exc.to_error_info(),
                       f"{UNKNOWN_OUTCOME_MARKER}; target state after re-check: {state}. "
                       "The write may have been applied: verify manually")
            return
        if precheck_failed:
            # The state before the write is unknown: the control in force may be someone else's
            # (for example a manual isolation). Never adopt it as an automation control.
            draft.fail(exc.to_error_info(),
                       "write timed out; the target is in the desired state but its state before the write "
                       "is unknown (pre-check failed), so it may be someone else's control: NOT registered "
                       "as an automation control and never releasable by automation. Verify manually")
            return
        draft.notes.append("write timed out but the re-check shows the target in the desired state; "
                           "rollback parameters were reconstructed from the request: review before release")
        draft.outcome = ActionOutcome(
            status=ActionResultStatus.SUCCESS, integration=adapter.name,
            message="confirmed by state re-check after a write timeout",
            rollback_params=dict(draft.request.params), executed_at=self._clock.now())

    def _verify(self, draft: _Draft) -> VerificationResult:
        """Verification never raises; any failure becomes UNABLE_TO_VERIFY."""
        try:
            result = self._verifier.verify(draft.request, draft.outcome)
            if not isinstance(result, VerificationResult):
                raise TypeError("verifier returned no VerificationResult")
        except Exception as exc:  # noqa: BLE001
            return VerificationResult(
                idempotency_key=draft.action.idempotency_key, status=VerificationStatus.UNABLE_TO_VERIFY,
                integration=draft.integration, method="none", checked_at=self._clock.now(),
                details=self._redactor.redact_text(f"verification error: {type(exc).__name__}: {exc}"))
        return result.model_copy(update={"api_calls": sanitize_calls(result.api_calls, self._redactor)})

    # ------------------------------------------------------------- registry --
    def _register_control(self, draft: _Draft, package: ActionPackage, token: ApprovalToken,
                          decision_id: str) -> None:
        try:
            control = self._build_control(draft, package, token, decision_id)
            stored = self._registry.register(control)
            if stored.package_id != control.package_id:
                stored = self._supersede(draft, stored, control)
        except Exception as exc:  # noqa: BLE001 - the control exists at the vendor; flag it loudly
            note = (f"temporary control could not be registered ({type(exc).__name__}): "
                    "record it manually before any release")
            draft.notes.append(note)
            safe_audit(self._audit, AuditEventType.ERROR, package=package, redactor=self._redactor,
                       actor=self._actor, payload={"idempotency_key": draft.action.idempotency_key,
                                                   "error": note})
            return
        draft.control_registered = True
        if not safe_audit(self._audit, AuditEventType.CONTROL_REGISTERED, package=package,
                          redactor=self._redactor, actor=self._actor,
                          payload=stored.model_dump(mode="json")):
            draft.notes.append("CONTROL_REGISTERED audit record could not be written")

    def _supersede(self, draft: _Draft, stored: TemporaryControl, control: TemporaryControl) -> TemporaryControl:
        """A later package's write is the control in force: the registry must point at it."""
        supersede = getattr(self._registry, "supersede", None)
        if not callable(supersede):
            raise RuntimeError(f"the registry still holds the registration of package {stored.package_id} "
                               "and cannot record the newer write")
        updated = supersede(control)
        if updated.package_id != control.package_id:
            raise RuntimeError(f"the registry kept the registration of package {stored.package_id}")
        draft.notes.append(f"registry entry of package {stored.package_id} (external_ref "
                           f"{stored.external_ref}) superseded by this write")
        return updated

    def _build_control(self, draft: _Draft, package: ActionPackage, token: ApprovalToken,
                       decision_id: str) -> TemporaryControl:
        action = draft.action
        outcome = draft.outcome
        spec = get_action_spec(action.action_type)
        if outcome is None or spec.rollback_action_type is None:
            raise ValueError("no outcome or rollback action for a control-creating action")
        if self._control_factory is not None:
            return self._control_factory(action, self._to_result(draft), outcome, package=package,
                                         token=token, decision_id=decision_id,
                                         review_after_hours=self._review_after_hours, clock=self._clock)
        now = self._clock.now()
        hours = self._review_after_hours.get(action.action_type.value)
        return TemporaryControl(
            control_key=action.idempotency_key, incident_id=action.incident_id,
            action_type=action.action_type, target=action.target, target_kind=action.target_kind,
            integration=draft.request.integration, workflow_id=package.workflow_id,
            workflow_version=package.workflow_version, package_id=package.package_id,
            token_id=token.token_id, decision_id=decision_id, approval_level=action.approval_level,
            created_at=now, rollback_action_type=spec.rollback_action_type,
            rollback_params={"integration": draft.request.integration, **outcome.rollback_params},
            external_ref=outcome.external_ref,
            review_due_at=now + timedelta(hours=hours) if hours else None,
        )

    # ---------------------------------------------------------------- audit --
    def _base_payload(self, action: RecommendedAction, package: ActionPackage, token: ApprovalToken,
                      decision_id: str) -> dict[str, object]:
        return {
            "idempotency_key": action.idempotency_key, "action_type": action.action_type.value,
            "target": action.target, "integration": action.integration,
            "approval_level": action.approval_level.value, "package_id": package.package_id,
            "token_id": token.token_id if isinstance(token, ApprovalToken) else None,
            "decision_id": decision_id,
        }

    def _audit_started(self, draft: _Draft, package: ActionPackage, token: ApprovalToken,
                       decision_id: str) -> bool:
        payload = self._base_payload(draft.action, package, token, decision_id)
        payload.update({"params": draft.request.params, "params_hash": draft.request.params_hash,
                        "risk_score": draft.action.risk_score,
                        "confidence_score": draft.action.confidence_score,
                        "evidence_numbers": [e.number for e in draft.action.evidence]})
        return safe_audit(self._audit, AuditEventType.ACTION_STARTED, package=package,
                          payload=payload, redactor=self._redactor, actor=self._actor)

    def _audit_result(self, result: ActionResult, package: ActionPackage, token: ApprovalToken,
                      decision_id: str, *, replayed: bool = False) -> bool:
        action = package.action(result.idempotency_key) if result.idempotency_key in package.keys else None
        payload: dict[str, object] = (self._base_payload(action, package, token, decision_id)
                                      if action is not None else {"idempotency_key": result.idempotency_key})
        payload.update(result.model_dump(mode="json", exclude={"verification"}))
        payload["replayed"] = replayed
        ok = safe_audit(self._audit, AuditEventType.ACTION_RESULT, package=package, payload=payload,
                        redactor=self._redactor, actor=self._actor)
        if result.verification is not None and not replayed:
            verification = result.verification.model_dump(mode="json")
            ok = safe_audit(self._audit, AuditEventType.VERIFICATION_RESULT, package=package,
                            payload=verification, redactor=self._redactor, actor=self._actor) and ok
        return ok

    def _finish(self, draft: _Draft, package: ActionPackage, token: ApprovalToken,
                decision_id: str) -> ActionResult:
        result = self._to_result(draft)
        if not self._audit_result(result, package, token, decision_id):
            note = "result audit record could not be written"
            result = result.model_copy(update={"requires_attention": True,
                                               "message": f"{result.message}; {note}".strip("; ")})
        return result

    def _to_result(self, draft: _Draft) -> ActionResult:
        notes = draft.notes
        message = "; ".join(m for m in [draft.message, *notes] if m)
        verification = draft.verification
        needs_attention = (
            draft.status is ActionResultStatus.FAILED
            or draft.status is ActionResultStatus.SKIPPED
            or bool(notes)
            or (verification is not None and verification.status is not VerificationStatus.VERIFIED)
        )
        external_ref = draft.outcome.external_ref if draft.outcome is not None else None
        if external_ref and external_ref not in message:
            message = f"{message}; external_ref={external_ref}".strip("; ")
        return ActionResult(
            idempotency_key=draft.action.idempotency_key, action_type=draft.action.action_type,
            target=draft.action.target, integration=draft.integration,
            approval_level=draft.action.approval_level, status=draft.status, skip_reason=draft.skip_reason,
            started_at=draft.started_at, finished_at=max(draft.started_at, self._clock.now()),
            message=self._redactor.redact_text(message), error=draft.error,
            api_calls=sanitize_calls(draft.api_calls, self._redactor), verification=verification,
            control_registered=draft.control_registered, requires_attention=needs_attention,
            recommended_escalation=draft.escalation if draft.status is ActionResultStatus.FAILED else None,
        )
