"""Restoration engine (architecture sections 8.2 and 13.17).

:meth:`RestorationEngine.execute` runs an approved :class:`ReleasePackage`:

1. Dry run (global, per run or package flag): simulated only, no token needed, registry untouched.
2. Otherwise the package is re-validated (``control_keys`` must be exactly the controls the
   actions restore; a package built with ``model_construct`` cannot smuggle a mismatch) and a
   release-purpose token is mandatory (:class:`ApprovalRequiredError`) and must bind
   this package (purpose, package, incident, evidence snapshot, workflow version and every grant).
   An engine whose own ``settings.runtime.dry_run`` is true still checks the token, then simulates.
   The token service's ``verify_package`` (signature, expiry, approvers, issuance proof) runs when
   available. Every refusal is audited (``GUARD_DENIED``) before it is raised.
3. Per approved action, in package order: re-read the registry entry; it must exist, belong to
   the package incident and still be in force, and the action must be bound to exactly what the
   registry recorded: rollback type, target, params equal to the recorded ``rollback_params`` plus
   ``restores`` (so also the integration that created the control), an approval level at least
   :func:`~xdr_response.restoration.planner.required_release_level` (registry level, always-elevated
   rollbacks, current critical-asset config with the incident's asset context, other incidents
   depending on the same control: the same rule the planner applies), confirmed automation
   provenance (the control's token was consumed for exactly this control key and the execution,
   when recorded, succeeded), and the registry evidence in the package must name the
   current registration (containment package, token and created_at), so a release approval can
   never be replayed against a later re-registration of the same key. Otherwise the action is not
   executed. Then ``RELEASE_PENDING``, run the rollback through the runner (which
   enters ``guard.authorized`` so the adapter's ``@state_changing`` method re-verifies the token),
   and mark ``RELEASED`` (effective) or ``RELEASE_FAILED``. One failure never stops other actions.
4. Overall from the final registry status of every control of the package (approved or not): all
   released ``RESTORED``, none ``RESTORATION_FAILED``, otherwise ``PARTIALLY_RESTORED`` (a selective
   release never reports RESTORED while package controls remain in force). Audit
   ``RESTORATION_RESULT`` per action and ``RESTORATION_COMPLETED`` per run; its ``released`` and
   ``still_in_force`` lists come from the controls the actions really restore.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, Protocol

from xdr_response import guard
from xdr_response.clock import Clock, SystemClock
from xdr_response.config.schema import Settings
from xdr_response.errors import (
    ApprovalRequiredError,
    AuditError,
    RegistryError,
    TokenInvalidError,
    TokenMismatchError,
)
from xdr_response.interfaces import AuditSink, ControlRegistry, TokenVerifier
from xdr_response.dryrun.simulator import apply_token_grants
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import (
    ActionPackage,
    ActionResult,
    ActionResultStatus,
    ApprovalLevel,
    ApprovalPurpose,
    ApprovalToken,
    AuditEventType,
    ContainmentReport,
    ControlStatus,
    ErrorCode,
    ErrorInfo,
    RecommendedAction,
    ReleasePackage,
    RestorationOverall,
    RestorationReport,
    SkipReason,
    TemporaryControl,
    VerificationStatus,
    format_datetime,
    get_action_spec,
)
from xdr_response.restoration.planner import (
    CriticalAssetEvaluator,
    ProvenanceCheck,
    dependent_incidents,
    incident_asset,
    release_params,
    required_release_level,
)
from xdr_response.restoration.registry import RELEASABLE_STATUSES

__all__ = [
    "RestorationEngine",
    "RollbackRunner",
    "ReleaseSimulator",
    "ACTOR",
    "is_release_effective",
    "compute_overall",
]

ACTOR = "automation:restoration_engine"


class RollbackRunner(Protocol):
    """The part of ``execution.ActionRunner`` the engine needs (section 13.16)."""

    def run(self, action: RecommendedAction, token: ApprovalToken, *, package: ActionPackage,
            decision_id: str) -> ActionResult:  # never raises for one action
        ...


class ReleaseSimulator(Protocol):
    """The part of ``dryrun.DryRunSimulator`` the engine needs (section 13.18)."""

    def simulate(self, package: ActionPackage) -> ContainmentReport:
        ...


def is_release_effective(result: ActionResult, *, unable_to_verify_counts: bool) -> bool:
    """A rollback took effect: executed (or already in the released state) and verified."""
    if result.status not in (ActionResultStatus.SUCCESS, ActionResultStatus.ALREADY_CONTAINED):
        return False
    status = result.verification.status if result.verification else None
    if status is VerificationStatus.VERIFIED:
        return True
    return status is VerificationStatus.UNABLE_TO_VERIFY and unable_to_verify_counts


def compute_overall(final_statuses: Mapping[str, ControlStatus | None]) -> RestorationOverall:
    """Overall result from the final registry status of every approved control."""
    released = sum(1 for s in final_statuses.values() if s is ControlStatus.RELEASED)
    if final_statuses and released == len(final_statuses):
        return RestorationOverall.RESTORED
    if released == 0:
        return RestorationOverall.RESTORATION_FAILED
    return RestorationOverall.PARTIALLY_RESTORED


class RestorationEngine:
    """Executes approved release packages under the execution guard. Implements contract 13.17."""

    def __init__(self, runner: RollbackRunner, registry: ControlRegistry, tokens: TokenVerifier,
                 settings: Settings, *, audit: AuditSink, simulator: ReleaseSimulator | None = None,
                 clock: Clock | None = None, id_factory: Callable[[], str] | None = None,
                 critical_assets: CriticalAssetEvaluator | None = None, executions: Any = None,
                 provenance: ProvenanceCheck | None = None, incidents: Any = None) -> None:
        self._critical_assets = critical_assets
        self._executions = executions  # ExecutionStateStore: other incidents relying on a control
        self._provenance = provenance  # automation provenance of a registry entry
        self._incidents = incidents  # IncidentStore: asset context for the critical-asset rules
        self._runner = runner
        self._registry = registry
        self._tokens = tokens
        self._settings = settings
        self._audit = audit
        self._simulator = simulator
        self._clock: Clock = clock or SystemClock()
        self._new_id: Callable[[], str] = id_factory or (lambda: uuid.uuid4().hex)

    # ----------------------------------------------------------------- public --
    def execute(self, package: ReleasePackage, token: ApprovalToken | None, *,
                dry_run: bool = False) -> RestorationReport:
        """Run the approved release actions of ``package`` (see module docstring)."""
        if not isinstance(package, ReleasePackage):
            raise TypeError("package must be a ReleasePackage")
        if guard.is_dry_run() or dry_run or package.dry_run:
            return self._simulate(package, token)
        self._check_package(package)
        if self._settings.runtime.dry_run:
            # DRY_RUN=true in this engine's settings wins over a flipped process-wide guard flag.
            self._require_token(package, token)  # a missing or wrong token is refused, never previewed
            return self._simulate(package, token)
        token = self._require_token(package, token)
        started_at = self._clock.now()
        attention: list[str] = []
        results = [self._run_one(package, action, token, attention) for action in package.actions]
        report = RestorationReport(
            report_id=self._new_id(), incident_id=package.incident_id, package_id=package.package_id,
            token_id=token.token_id, dry_run=False, started_at=started_at,
            finished_at=self._clock.now(), results=tuple(results),
            overall=self._overall(package, token), attention=tuple(attention),
        )
        return self._record_completed(package, report)

    @staticmethod
    def _check_package(package: ReleasePackage) -> None:
        """Re-validate what ``model_construct`` could skip: control_keys == what the actions restore."""
        restores = tuple(str(a.params.get("restores", "")) for a in package.actions)
        if (not restores or any(not k for k in restores) or len(set(restores)) != len(restores)
                or tuple(package.control_keys) != restores):
            raise RegistryError("release package is inconsistent: control_keys must be exactly the controls "
                                "its actions restore; nothing was released")

    # ------------------------------------------------------------- dry run --
    def _simulate(self, package: ReleasePackage, token: ApprovalToken | None = None) -> RestorationReport:
        started_at = self._clock.now()
        with guard.dry_run():
            simulate_restoration = getattr(self._simulator, "simulate_restoration", None)
            if callable(simulate_restoration):
                report = simulate_restoration(package)
                if not isinstance(report, RestorationReport) or not report.dry_run or report.overall is not None:
                    raise RuntimeError("dry-run simulator returned a non dry-run report")
                if token is not None:
                    report = report.model_copy(update={"results": apply_token_grants(report.results, token)})
                return report
            if self._simulator is not None:
                results = tuple(self._simulator.simulate(package).results)
            else:
                results = tuple(self._dry_run_result(a, started_at) for a in package.actions)
        return RestorationReport(
            report_id=self._new_id(), incident_id=package.incident_id, package_id=package.package_id,
            token_id=None, dry_run=True, started_at=started_at, finished_at=self._clock.now(),
            results=apply_token_grants(results, token), overall=None,
        )

    @staticmethod
    def _dry_run_result(action: RecommendedAction, at: datetime) -> ActionResult:
        verb = get_action_spec(action.action_type).dry_run_verb
        return ActionResult(
            idempotency_key=action.idempotency_key, action_type=action.action_type,
            target=action.target, integration=action.integration,
            approval_level=action.approval_level, status=ActionResultStatus.DRY_RUN,
            started_at=at, finished_at=at, message="dry run: no release executed",
            dry_run_line=f"{verb}: {action.target}",
        )

    # ------------------------------------------------------- token binding --
    def _require_token(self, package: ReleasePackage, token: ApprovalToken | None) -> ApprovalToken:
        """Deterministic checks that ``token`` is the release approval of exactly this package.

        Every refusal is audited as ``GUARD_DENIED`` (like the containment executor) and re-raised.
        """
        try:
            return self._check_token(package, token)
        except ApprovalRequiredError as exc:
            payload: dict[str, Any] = {
                "package_id": package.package_id, "purpose": ApprovalPurpose.RELEASE.value,
                "reason": str(exc), "error": type(exc).__name__,
                "token_id": token.token_id if isinstance(token, ApprovalToken) else None,
            }
            failures: list[str] = []
            self._append(AuditEventType.GUARD_DENIED, package, payload, failures)
            raise

    def _check_token(self, package: ReleasePackage, token: ApprovalToken | None) -> ApprovalToken:
        if not isinstance(token, ApprovalToken):
            raise ApprovalRequiredError("a human release approval token is required to release controls")
        claims = token.claims
        if claims.purpose is not ApprovalPurpose.RELEASE:
            raise TokenMismatchError(f"a {claims.purpose.value} token cannot authorize a release")
        mismatches = [
            name for name, ok in (
                ("package_id", claims.package_id == package.package_id),
                ("incident_id", claims.incident_id == package.incident_id),
                ("evidence_snapshot_hash", claims.evidence_snapshot_hash == package.evidence_snapshot_hash),
                ("workflow_version", claims.workflow_version == package.workflow_version),
            ) if not ok
        ]
        if mismatches:
            raise TokenMismatchError(f"release token does not bind this package: {', '.join(mismatches)}")
        self._check_grants(package, token)
        verify_package = getattr(self._tokens, "verify_package", None)
        if callable(verify_package):
            try:
                verify_package(token, package)
            except ApprovalRequiredError:
                raise
            except Exception as exc:  # noqa: BLE001 - unexpected verifier failure: fail closed
                raise TokenInvalidError(f"release package verification error: {type(exc).__name__}") from exc
        return token

    @staticmethod
    def _check_grants(package: ReleasePackage, token: ApprovalToken) -> None:
        keys = set(package.keys)
        for grant in token.claims.actions:
            if grant.idempotency_key not in keys:
                raise TokenMismatchError(f"token grants {grant.idempotency_key}, which is not in the package")
            action = package.action(grant.idempotency_key)
            if (grant.action_type, grant.target, grant.params_hash) != (
                    action.action_type, action.target, action.params_hash):
                raise TokenMismatchError(f"token grant for {grant.idempotency_key} does not match the action")

    # ------------------------------------------------------------ per action --
    def _run_one(self, package: ReleasePackage, action: RecommendedAction, token: ApprovalToken,
                 attention: list[str]) -> ActionResult:
        control_key = str(action.params.get("restores", ""))
        if token.claims.grant(action.idempotency_key) is None:
            return self._skipped(action, SkipReason.REJECTED_BY_ANALYST, "not approved by the analyst")
        problem = self._binding_problem(package, action, control_key)
        if problem is not None:
            attention.append(f"{action.action_type.value} {action.target}: {problem}")
            result = self._failed(action, ErrorCode.APPROVAL_DENIED, problem)
        elif (status := self._status_of(control_key)) not in RELEASABLE_STATUSES:
            result = self._skipped(action, SkipReason.CONTROL_NOT_ACTIVE,
                                   f"control {control_key} is {status.value if status else 'unknown'}")
        else:
            result = self._release(package, action, token, control_key, attention)
        self._record_result(package, action, control_key, result, attention)
        return result

    def _binding_problem(self, package: ReleasePackage, action: RecommendedAction,
                         control_key: str) -> str | None:
        """Why this action may not release its control, or None."""
        control = self._registry.get(control_key) if control_key else None
        if control is None:
            return f"control {control_key or '<missing>'} is not registered; only registered controls can be released"
        if control.incident_id != package.incident_id:
            return f"control {control_key} belongs to another incident"
        if control.rollback_action_type is not action.action_type or control.target != action.target:
            return f"action does not match the rollback recorded for control {control_key}"
        if dict(action.params) != release_params(control):
            return (f"action params differ from the rollback parameters recorded for control {control_key} "
                    f"(integration {control.rollback_params.get('integration')!r}); only the recorded "
                    "rollback can be executed")
        dependents = dependent_incidents(control, self._registry, self._executions)
        required = required_release_level(control, self._critical_assets, asset=self._asset(control),
                                          dependents=dependents)
        if required is ApprovalLevel.ELEVATED and action.approval_level is not ApprovalLevel.ELEVATED:
            why = f"; incidents {dependents} depend on it" if dependents else ""
            return (f"release of control {control_key} requires ELEVATED approval (registry record, "
                    f"rollback type, critical asset or dependent incident{why}); the package labels it STANDARD")
        provenance = self._provenance_problem(control)
        if provenance is not None:
            return (f"control {control_key} has no confirmed automation provenance ({provenance}); "
                    "only controls created by approved automation can be released")
        return self._registration_problem(package, control)

    def _asset(self, control: TemporaryControl) -> Any:
        if self._incidents is None:
            return None
        try:
            incident = self._incidents.get(control.incident_id)
        except Exception:  # noqa: BLE001 - unknown incident: name rules still apply
            return None
        return incident_asset(incident, control.target, control.target_kind)

    def _provenance_problem(self, control: TemporaryControl) -> str | None:
        if self._provenance is None:
            return None
        try:
            return self._provenance(control)
        except Exception as exc:  # noqa: BLE001 - fail closed
            return f"provenance could not be checked ({type(exc).__name__})"

    @staticmethod
    def _registration_problem(package: ReleasePackage, control: TemporaryControl) -> str | None:
        """The package's registry evidence must describe the current registration of the control."""
        recorded = [e for e in package.evidence if e.reference == control.control_key]
        if not recorded:
            return f"release package carries no registry evidence for control {control.control_key}"
        expected = {"package_id": control.package_id, "token_id": control.token_id,
                    "created_at": format_datetime(control.created_at)}
        for evidence in recorded:
            data = evidence.data or {}
            if all(data.get(k) == v for k, v in expected.items()):
                return None
        return (f"control {control.control_key} was registered again after this release package was "
                "built; the release approval does not cover the current control")

    def _status_of(self, control_key: str) -> ControlStatus | None:
        control = self._registry.get(control_key)
        return control.status if control else None

    def _release(self, package: ReleasePackage, action: RecommendedAction, token: ApprovalToken,
                 control_key: str, attention: list[str]) -> ActionResult:
        try:
            self._registry.mark_release_pending(control_key, release_package_id=package.package_id,
                                                token_id=token.token_id)
        except RegistryError as exc:  # lost a race with another release run
            return self._skipped(action, SkipReason.CONTROL_NOT_ACTIVE, str(exc))
        result = self._invoke_runner(package, action, token)
        unable_counts = self._settings.thresholds.verification.unable_to_verify_counts_as_contained
        if is_release_effective(result, unable_to_verify_counts=unable_counts):
            self._registry.mark_released(control_key, at=result.finished_at)
        else:
            self._registry.mark_release_failed(control_key, error=self._failure_info(result))
            attention.append(self._attention_line(action, result))
        return result

    def _invoke_runner(self, package: ReleasePackage, action: RecommendedAction,
                       token: ApprovalToken) -> ActionResult:
        started_at = self._clock.now()
        try:
            return self._runner.run(action, token, package=package, decision_id=token.claims.decision_id)
        except Exception as exc:  # noqa: BLE001 - the runner must never stop the other actions
            message = get_redactor().redact_text(f"rollback runner error: {type(exc).__name__}: {exc}")
            return self._failed(action, ErrorCode.INTERNAL, message, started_at=started_at)

    @staticmethod
    def _failure_info(result: ActionResult) -> ErrorInfo:
        if result.error is not None:
            return result.error
        verification = result.verification.status.value if result.verification else "none"
        return ErrorInfo(
            code=ErrorCode.API_ERROR, integration=result.integration,
            message=f"release not confirmed: status {result.status.value}, verification {verification}",
        )

    @staticmethod
    def _attention_line(action: RecommendedAction, result: ActionResult) -> str:
        if result.verification and result.verification.status is VerificationStatus.UNABLE_TO_VERIFY:
            return f"{action.action_type.value} {action.target}: verify manually; control kept RELEASE_FAILED"
        return f"{action.action_type.value} {action.target}: release failed; control still in force"

    # --------------------------------------------------------------- results --
    def _skipped(self, action: RecommendedAction, reason: SkipReason, message: str) -> ActionResult:
        now = self._clock.now()
        return ActionResult(
            idempotency_key=action.idempotency_key, action_type=action.action_type,
            target=action.target, integration=action.integration,
            approval_level=action.approval_level, status=ActionResultStatus.SKIPPED,
            skip_reason=reason, started_at=now, finished_at=now, message=message,
        )

    def _failed(self, action: RecommendedAction, code: ErrorCode, message: str, *,
                started_at: datetime | None = None) -> ActionResult:
        now = self._clock.now()
        return ActionResult(
            idempotency_key=action.idempotency_key, action_type=action.action_type,
            target=action.target, integration=action.integration,
            approval_level=action.approval_level, status=ActionResultStatus.FAILED,
            started_at=started_at or now, finished_at=now, message=message,
            error=ErrorInfo(code=code, message=message, integration=action.integration),
            requires_attention=True,
        )

    def _overall(self, package: ReleasePackage, token: ApprovalToken) -> RestorationOverall:
        """Every control of the package counts: controls the analyst left out are still in force."""
        statuses = {
            a.idempotency_key: self._status_of(str(a.params.get("restores", ""))) for a in package.actions
        }
        return compute_overall(statuses)

    # ----------------------------------------------------------------- audit --
    def _record_result(self, package: ReleasePackage, action: RecommendedAction, control_key: str,
                       result: ActionResult, attention: list[str]) -> None:
        control = self._registry.get(control_key) if control_key else None
        payload: dict[str, Any] = {
            "package_id": package.package_id,
            "control_key": control_key,
            "control_status": control.status.value if control else None,
            "control_incident_id": control.incident_id if control else None,
            "result": result.model_dump(mode="json"),
        }
        self._append(AuditEventType.RESTORATION_RESULT, package, payload, attention)

    def _record_completed(self, package: ReleasePackage, report: RestorationReport) -> RestorationReport:
        """Audit RESTORATION_COMPLETED; an audit failure is surfaced on the report, never hidden."""
        restored = [str(a.params.get("restores", "")) for a in package.actions]  # what really ran
        payload: dict[str, Any] = {
            "package_id": package.package_id,
            "report_id": report.report_id,
            "token_id": report.token_id,
            "overall": report.overall.value if report.overall else None,
            "released": [k for k in restored if self._status_of(k) is ControlStatus.RELEASED],
            "still_in_force": [k for k in restored if self._status_of(k) in RELEASABLE_STATUSES],
            "attention": list(report.attention),
        }
        failures: list[str] = []
        self._append(AuditEventType.RESTORATION_COMPLETED, package, payload, failures)
        if not failures:
            return report
        return report.model_copy(update={"attention": (*report.attention, *failures)})

    def _append(self, event: AuditEventType, package: ReleasePackage, payload: dict[str, Any],
                attention: list[str]) -> None:
        try:
            self._audit.append(
                event, incident_id=package.incident_id, actor=ACTOR,
                payload=get_redactor().redact(payload), workflow_id=package.workflow_id,
                workflow_version=package.workflow_version,
            )
        except AuditError as exc:
            attention.append(f"audit write failed for {event.value}: {type(exc).__name__}")

