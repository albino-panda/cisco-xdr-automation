"""Containment executor: runs an approved ContainmentPackage automatically (architecture 6.1, 13.16).

``execute(package, token)``:

* Effective dry run (``guard.is_dry_run()``, the executor's own ``settings.runtime.dry_run``,
  ``dry_run=True`` or ``package.dry_run``): the package is simulated inside ``guard.dry_run()`` and
  no adapter method is reachable. ``overall`` is None. Flipping the process-wide guard flag alone
  never turns an executor configured with ``DRY_RUN=true`` live. With a token, actions the token
  does not grant are previewed as skipped (never as "Would ...").
* Otherwise a token is mandatory (:class:`ApprovalRequiredError`) and must bind this exact package
  (package id, incident, purpose, evidence snapshot hash, workflow and every grant), checked
  deterministically here and by ``tokens.verify_package`` when the verifier offers it.
* Every package action goes through :class:`ActionRunner`; actions without a grant in the token are
  ``SKIPPED`` (``REJECTED_BY_ANALYST``). One failure never stops another action. Concurrency is
  bounded globally (``max_concurrency``) and per integration (``integration_concurrency``).
* The overall result follows section 6.4; ``CONTAINMENT_COMPLETED`` is audited.
"""
from __future__ import annotations

import contextvars
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from xdr_response import guard
from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.config.schema import Settings
from xdr_response.errors import ApprovalRequiredError, TokenInvalidError, TokenMismatchError
from xdr_response.execution._support import (
    ACTOR,
    attention_lines,
    error_info_for,
    failed_result,
    safe_audit,
)
from xdr_response.dryrun.simulator import apply_token_grants
from xdr_response.execution.outcome import compute_containment_overall
from xdr_response.execution.protocols import PackageSimulator
from xdr_response.execution.runner import ActionRunner
from xdr_response.interfaces import AuditSink, TokenVerifier
from xdr_response.logs.redaction import Redactor, get_redactor
from xdr_response.models import (
    ActionPackage,
    ActionResult,
    ActionResultStatus,
    ApprovalPurpose,
    ApprovalToken,
    AuditEventType,
    ContainmentPackage,
    ContainmentReport,
    RecommendedAction,
    evidence_snapshot_hash,
    get_action_spec,
)

__all__ = ["ContainmentExecutor", "check_token_binds_package"]


def check_token_binds_package(token: ApprovalToken, package: ActionPackage) -> None:
    """Deterministic package binding check (no signature check). Raises TokenMismatchError."""
    claims = token.claims
    problems: list[str] = []
    if claims.package_id != package.package_id:
        problems.append("package id")
    if claims.incident_id != package.incident_id:
        problems.append("incident")
    if claims.purpose != package.purpose:
        problems.append("purpose")
    if claims.workflow_id != package.workflow_id or claims.workflow_version != package.workflow_version:
        problems.append("workflow")
    if claims.dry_run or bool(package.dry_run):
        problems.append("dry run (a dry-run approval never authorizes live execution)")
    recomputed = evidence_snapshot_hash(package.evidence)
    if claims.evidence_snapshot_hash != package.evidence_snapshot_hash or recomputed != claims.evidence_snapshot_hash:
        problems.append("evidence snapshot hash")
    for grant in claims.actions:
        try:
            action = package.action(grant.idempotency_key)
        except KeyError:
            problems.append(f"grant {grant.idempotency_key} is not in the package")
            continue
        if (grant.action_type, grant.target, grant.params_hash, grant.approval_level) != (
                action.action_type, action.target, action.params_hash, action.approval_level):
            problems.append(f"grant {grant.idempotency_key} does not match the package action")
    if problems:
        raise TokenMismatchError("approval token does not bind this package: " + ", ".join(problems))


class ContainmentExecutor:
    """Runs approved containment automatically right after a human approval."""

    def __init__(self, runner: ActionRunner, tokens: TokenVerifier, settings: Settings, *,
                 audit: AuditSink, simulator: PackageSimulator | None = None,
                 clock: Clock | None = None, max_concurrency: int = 1,
                 integration_concurrency: Mapping[str, int] | None = None,
                 id_factory: Callable[[], str] | None = None, redactor: Redactor | None = None,
                 actor: str = ACTOR) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        limits = dict(integration_concurrency or {})
        if any(v < 1 for v in limits.values()):
            raise ValueError("integration_concurrency limits must be >= 1")
        self._runner = runner
        self._tokens = tokens
        self._settings = settings
        self._audit = audit
        self._simulator = simulator
        self._clock: Clock = clock or DEFAULT_CLOCK
        self._max_concurrency = max_concurrency
        self._semaphores = {name: threading.BoundedSemaphore(v) for name, v in limits.items()}
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)
        self._redactor = redactor or get_redactor()
        self._actor = actor

    # ------------------------------------------------------------------ API --
    def execute(self, package: ContainmentPackage, token: ApprovalToken | None, *,
                dry_run: bool = False) -> ContainmentReport:
        """Execute the approved actions of ``package`` (or simulate them in dry run)."""
        if not isinstance(package, ContainmentPackage):
            raise TypeError("package must be a ContainmentPackage")
        if guard.is_dry_run() or dry_run or package.dry_run:
            return self._simulate(package, token)
        if self._settings.runtime.dry_run:
            # DRY_RUN=true in this executor's settings wins over a flipped process-wide guard flag.
            # The token is still checked (a missing or wrong token is refused, never previewed).
            self._authorize_package(package, token)
            return self._simulate(package, token)
        checked = self._authorize_package(package, token)
        started = self._clock.now()
        results = self._run_all(package, checked)
        flag = self._settings.thresholds.verification.unable_to_verify_counts_as_contained
        overall = compute_containment_overall(results, unable_to_verify_counts_as_contained=flag)
        report = ContainmentReport(
            report_id=self._id_factory(), incident_id=package.incident_id,
            package_id=package.package_id, token_id=checked.token_id, dry_run=False,
            started_at=started, finished_at=max(started, self._clock.now()), results=tuple(results),
            overall=overall, attention=attention_lines(results),
        )
        return self._audit_completed(report, package)

    # ------------------------------------------------------------- dry run --
    def _simulate(self, package: ContainmentPackage, token: ApprovalToken | None) -> ContainmentReport:
        with guard.dry_run():
            if self._simulator is not None:
                report = self._simulator.simulate(package)
            else:
                report = self._fallback_simulation(package, token)
        if not isinstance(report, ContainmentReport) or not report.dry_run or report.overall is not None:
            raise RuntimeError("dry-run simulator returned a non dry-run report")
        if token is not None:
            report = report.model_copy(update={"results": apply_token_grants(report.results, token),
                                               "token_id": token.token_id
                                               if isinstance(token, ApprovalToken) else report.token_id})
        return report

    def _fallback_simulation(self, package: ContainmentPackage,
                             token: ApprovalToken | None) -> ContainmentReport:
        """Used only when no simulator is wired: DRY_RUN lines, no adapter call, audited."""
        now = self._clock.now()
        results = tuple(
            ActionResult(
                idempotency_key=a.idempotency_key, action_type=a.action_type, target=a.target,
                integration=a.integration, approval_level=a.approval_level,
                status=ActionResultStatus.DRY_RUN, started_at=now, finished_at=now,
                dry_run_line=f"{get_action_spec(a.action_type).dry_run_verb}: {a.target}",
            )
            for a in package.actions
        )
        safe_audit(self._audit, AuditEventType.DRY_RUN_SIMULATION, package=package,
                   redactor=self._redactor, actor=self._actor,
                   payload={"package_id": package.package_id,
                            "lines": [r.dry_run_line for r in results]})
        return ContainmentReport(
            report_id=self._id_factory(), incident_id=package.incident_id,
            package_id=package.package_id, token_id=token.token_id if token is not None else None,
            dry_run=True, started_at=now, finished_at=now, results=results, overall=None,
        )

    # ------------------------------------------------------------ approval --
    def _authorize_package(self, package: ContainmentPackage, token: ApprovalToken | None) -> ApprovalToken:
        """Fail closed before any action runs. Every denial is audited (GUARD_DENIED)."""
        try:
            if token is None:
                raise ApprovalRequiredError("an approval token is required to execute containment")
            if not isinstance(token, ApprovalToken):
                raise ApprovalRequiredError("approval token has the wrong type")
            if token.claims.purpose is not ApprovalPurpose.CONTAINMENT:
                raise TokenMismatchError("token purpose does not authorize containment")
            check_token_binds_package(token, package)
            self._verify_package(token, package)
        except ApprovalRequiredError as exc:
            safe_audit(self._audit, AuditEventType.GUARD_DENIED, package=package,
                       redactor=self._redactor, actor=self._actor,
                       payload={"package_id": package.package_id, "reason": str(exc),
                                "error": type(exc).__name__,
                                "token_id": token.token_id if isinstance(token, ApprovalToken) else None})
            raise
        return token

    def _verify_package(self, token: ApprovalToken, package: ContainmentPackage) -> None:
        verify_package = getattr(self._tokens, "verify_package", None)
        if verify_package is None:
            return  # signature and expiry are still checked per action by guard.authorized
        try:
            verify_package(token, package)
        except ApprovalRequiredError:
            raise
        except Exception as exc:  # noqa: BLE001 - unexpected verifier failure: fail closed
            raise TokenInvalidError(f"package verification error: {type(exc).__name__}") from exc

    # ----------------------------------------------------------- execution --
    def _run_all(self, package: ContainmentPackage, token: ApprovalToken) -> list[ActionResult]:
        actions: Sequence[RecommendedAction] = package.actions
        if self._max_concurrency == 1 or len(actions) <= 1:
            return [self._run_one(a, token, package) for a in actions]
        workers = min(self._max_concurrency, len(actions))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xdr-exec") as pool:
            futures = [pool.submit(contextvars.copy_context().run, self._run_one, a, token, package)
                       for a in actions]
            return [f.result() for f in futures]  # package order, whatever the completion order

    def _run_one(self, action: RecommendedAction, token: ApprovalToken,
                 package: ContainmentPackage) -> ActionResult:
        semaphore = self._semaphores.get(action.integration)
        started: datetime = self._clock.now()
        try:
            if semaphore is None:
                return self._runner.run(action, token, package=package,
                                        decision_id=token.claims.decision_id)
            with semaphore:
                return self._runner.run(action, token, package=package,
                                        decision_id=token.claims.decision_id)
        except Exception as exc:  # noqa: BLE001 - the runner should never raise; contain it anyway
            error = error_info_for(exc, action.integration, self._redactor)
            return failed_result(action, started_at=started, finished_at=self._clock.now(), error=error)

    def _audit_completed(self, report: ContainmentReport, package: ContainmentPackage) -> ContainmentReport:
        payload = {
            "report_id": report.report_id, "package_id": report.package_id,
            "token_id": report.token_id,
            "overall": report.overall.value if report.overall is not None else None,
            "results": [{"idempotency_key": r.idempotency_key, "status": r.status.value,
                         "skip_reason": r.skip_reason.value if r.skip_reason else None,
                         "verification": r.verification.status.value if r.verification else None,
                         "control_registered": r.control_registered,
                         "requires_attention": r.requires_attention} for r in report.results],
            "attention": list(report.attention),
        }
        if safe_audit(self._audit, AuditEventType.CONTAINMENT_COMPLETED, package=package,
                      payload=payload, redactor=self._redactor, actor=self._actor):
            return report
        note = "Requires attention: CONTAINMENT_COMPLETED audit record could not be written"
        return report.model_copy(update={"attention": (*report.attention, note)})
