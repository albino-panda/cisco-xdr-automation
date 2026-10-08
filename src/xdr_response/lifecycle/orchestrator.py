"""Response orchestrator: drives an incident through the whole lifecycle (architecture 13.19).

::

    detect --open_incident--> NOT_STARTED
           --investigate (read adapters, automatic)--> recommend (automatic)
           --propose--> AWAITING_APPROVAL                       (human decision required)
    submit_decision:
        REJECT                      -> CLOSED
        REQUEST_MORE_INVESTIGATION  -> NOT_STARTED (then investigate_and_propose again)
        APPROVE_ALL / APPROVE_SELECTED (human token)
            -> APPROVED -> CONTAINMENT_RUNNING -> execute approved actions automatically
            -> verify every action automatically
            -> CONTAINED | PARTIALLY_CONTAINED | CONTAINMENT_FAILED
            -> REMEDIATION_REQUIRED when verification says a human must act
    propose_release --> AWAITING_RELEASE_APPROVAL                (separate human decision required)
    submit_release_decision:
        REJECT / REQUEST_MORE_INVESTIGATION -> REMEDIATION_REQUIRED (controls stay ACTIVE)
        APPROVE_* (human release token)
            -> RESTORATION_RUNNING -> roll back automatically -> verify
            -> RESTORED | AWAITING_RELEASE_APPROVAL (partial or failed release)
    close --> CLOSED (never touches the temporary control registry)

Safety properties, all enforced by deterministic code:

* Only :meth:`submit_decision` / :meth:`submit_release_decision` can lead to a state change at a
  vendor, and only with a token the :class:`~xdr_response.approval.ApprovalEngine` issued to
  authenticated HUMAN approvers. The state machine refuses ``APPROVED`` / ``RESTORATION_RUNNING``
  without that token, the executor re-checks the token against the package, and every adapter write
  re-verifies it through the execution guard.
* Packages execute at most once (package store ``mark_executed`` plus the execution state store).
* In dry run (global, or a package proposed while dry run was active) approvals are recorded but
  execution is simulated (``"Would isolate: TH-LT-1047"``) and the incident state does not advance.
  The decision is taken on the package marked ``dry_run``, so the issued token carries
  ``dry_run=True`` and can never authorize a live execution later (not even after dry run is
  switched off within the token TTL).
* Every step is audited; a failed state-transition audit write leaves the incident unchanged.

Phase 1 (section 14.3.6): with a workflow catalog wired, :meth:`open_incident` stores the incident
with the resolved workflow id and version (so packages and tokens carry them), and lifecycle
observers receive a ``LifecycleEvent`` after investigation and proposal, decisions, release
proposals and closing. Observers are bookkeeping only: their exceptions are logged and swallowed,
they never change state and never see a token.
"""
from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from xdr_response import guard
from xdr_response.audit.summary import ExecutionAuditSummary, build_execution_summary
from xdr_response.errors import ApprovalRequiredError, DecisionError, InvalidTransitionError, RegistryError
from xdr_response.execution.outcome import ActionVerdict, to_incident_state
from xdr_response.interfaces import IncidentStore, PackageStore
from xdr_response.lifecycle.investigation import InvestigationReport
from xdr_response.lifecycle.machine import LIFECYCLE_ACTOR
from xdr_response.lifecycle.recommendation import Recommendation
from xdr_response.logs.redaction import get_redactor
from xdr_response.logs.setup import get_logger
from xdr_response.models import (
    ActionPackage,
    ApprovalOutcome,
    ApprovalPurpose,
    ApproverCredential,
    ContainmentPackage,
    ContainmentReport,
    DecisionRequest,
    DecisionType,
    EvidenceDraft,
    Incident,
    IncidentState,
    ProposedAction,
    ReleasePackage,
    RestorationReport,
    TemporaryControl,
    can_transition,
)
from xdr_response.verification.outcome import ContainmentAssessment, assess_containment, assess_restoration

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.lifecycle.runtime import Runtime

__all__ = ["ResponseOrchestrator", "DecisionResult", "DetectionResult", "VERIFICATION_ACTOR",
           "EXECUTION_ACTOR"]

EXECUTION_ACTOR = "automation:execution"
VERIFICATION_ACTOR = "automation:verification"
_APPROVING = frozenset({DecisionType.APPROVE_ALL, DecisionType.APPROVE_SELECTED})
_log = get_logger("lifecycle.orchestrator")


@dataclass(frozen=True)
class DecisionResult:
    """What a decision led to. ``report`` is None for REJECT / REQUEST_MORE_INVESTIGATION."""

    outcome: ApprovalOutcome
    incident: Incident
    report: ContainmentReport | RestorationReport | None
    assessment: ContainmentAssessment | None = None
    error: str | None = None

    @property
    def dry_run(self) -> bool:
        return self.report is not None and self.report.dry_run

    @property
    def recommended_next_state(self) -> IncidentState | None:
        return self.assessment.recommended_next_state if self.assessment is not None else None


@dataclass(frozen=True)
class DetectionResult:
    """Result of the automatic part of the lifecycle (investigate, recommend, propose)."""

    incident: Incident
    investigation: InvestigationReport
    recommendation: Recommendation
    package: ContainmentPackage | None
    dry_run_report: ContainmentReport | None = None
    notes: tuple[str, ...] = field(default=())


class ResponseOrchestrator:
    """Composition-layer driver of the incident lifecycle (see module docstring)."""

    def __init__(self, runtime: "Runtime", *, incidents: IncidentStore, packages: PackageStore) -> None:
        self._rt = runtime
        self._incidents = incidents
        self._packages = packages
        self._locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()
        self._reports: dict[str, ContainmentReport | RestorationReport] = {}

    # ------------------------------------------------------------- helpers --
    def _dry_run_active(self) -> bool:
        """The guard flag OR this runtime's own ``runtime.dry_run`` setting (either one is enough)."""
        return guard.is_dry_run() or bool(self._rt.settings.runtime.dry_run)

    def _lock(self, incident_id: str) -> threading.RLock:
        with self._locks_guard:
            return self._locks.setdefault(incident_id, threading.RLock())

    def _transition(self, incident_id: str, to_state: IncidentState, **kwargs: object) -> Incident:
        return self._rt.machine.transition(incident_id, to_state, **kwargs)  # type: ignore[arg-type]

    def get_incident(self, incident_id: str) -> Incident:
        return self._incidents.get(incident_id)

    def get_package(self, package_id: str) -> ActionPackage:
        return self._packages.get(package_id)

    def latest_package(self, incident_id: str, purpose: ApprovalPurpose = ApprovalPurpose.CONTAINMENT
                       ) -> ActionPackage | None:
        return self._packages.latest_for_incident(incident_id, purpose)

    def report_for(self, package_id: str) -> ContainmentReport | RestorationReport | None:
        """The last execution (or simulation) report of a package, if any."""
        return self._reports.get(package_id)

    def outstanding_controls(self, incident_id: str) -> list[TemporaryControl]:
        """Temporary controls of the incident that are still in force (ACTIVE or RELEASE_FAILED)."""
        return self._rt.planner.outstanding(incident_id)

    def audit_summary(self, incident_id: str) -> ExecutionAuditSummary:
        """Brief section 35 summary built from the (redacted) audit records of the incident."""
        return build_execution_summary(self._rt.audit.records(incident_id), incident_id)

    # ---------------------------------------------------------- detection --
    def open_incident(self, incident: Incident) -> Incident:
        """Register a detected incident in ``NOT_STARTED`` and audit ``INCIDENT_RECEIVED``.

        With a workflow catalog the stored incident carries the resolved workflow id and version.
        """
        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident")
        if incident.state is not IncidentState.NOT_STARTED or incident.history:
            raise ValueError("a new incident must be NOT_STARTED with an empty history")
        catalog = self._rt.workflows
        if catalog is not None:
            incident = catalog.assign(incident)
        with self._lock(incident.incident_id):
            try:
                self._incidents.get(incident.incident_id)
            except KeyError:
                pass
            else:
                raise ValueError(f"incident {incident.incident_id} is already open")
            self._rt.recorder.incident_received(incident, actor=LIFECYCLE_ACTOR)
            self._incidents.save(incident)
            return incident

    def investigate(self, incident_id: str) -> InvestigationReport:
        """Read-only enrichment and investigation (automatic; no approval needed)."""
        return self._rt.investigator.run(self._incidents.get(incident_id))

    def recommend(self, incident_id: str, investigation: InvestigationReport) -> Recommendation:
        """Deterministic recommendation from the investigation (automatic; never executes anything)."""
        return self._rt.recommender.recommend(self._incidents.get(incident_id), investigation)

    def build_package(self, incident_id: str, recommendation: Recommendation) -> ContainmentPackage:
        """Containment package (allow-lists, critical-asset elevation, blast radius, evidence hash)."""
        incident = self._incidents.get(incident_id)
        return self._rt.packages.build(
            incident, recommendation.proposals, risk_score=recommendation.risk_score,
            confidence_score=recommendation.confidence_score, summary=recommendation.summary,
            dry_run=self._dry_run_active())

    def handle_detection(self, incident: Incident) -> DetectionResult:
        """Open, investigate, recommend and propose in one automatic step."""
        self.open_incident(incident)
        return self.investigate_and_propose(incident.incident_id)

    def investigate_and_propose(self, incident_id: str) -> DetectionResult:
        """Investigation, recommendation and proposal for a ``NOT_STARTED`` incident.

        With nothing to contain (or everything allow-listed) the incident stays ``NOT_STARTED``.
        In dry run the package is also simulated and the DRY RUN report returned.
        """
        result = self._investigate_and_propose(incident_id)
        if self._rt.observers:
            self._emit_detection(result)
        return result

    def _investigate_and_propose(self, incident_id: str) -> DetectionResult:
        with self._lock(incident_id):
            incident = self._incidents.get(incident_id)
            if incident.state is not IncidentState.NOT_STARTED:
                raise InvalidTransitionError(incident.state, IncidentState.AWAITING_APPROVAL,
                                             "investigation starts from NOT_STARTED")
            investigation = self.investigate(incident_id)
            recommendation = self.recommend(incident_id, investigation)
            notes = list(recommendation.notes)
            notes.extend(f"not proposed: {u.action_type.value} {u.target} ({u.reason})"
                         for u in recommendation.unrouted)
            if recommendation.empty:
                return DetectionResult(incident=self._incidents.get(incident_id), investigation=investigation,
                                       recommendation=recommendation, package=None, notes=tuple(notes))
            try:
                package = self.build_package(incident_id, recommendation)
            except ValueError as exc:  # every target allow-listed: nothing to approve
                notes.append(f"no package: {exc}")
                return DetectionResult(incident=self._incidents.get(incident_id), investigation=investigation,
                                       recommendation=recommendation, package=None, notes=tuple(notes))
            self.propose(incident_id, package)
            report = self.dry_run(package) if package.dry_run or self._dry_run_active() else None
            return DetectionResult(incident=self._incidents.get(incident_id), investigation=investigation,
                                   recommendation=recommendation, package=package, dry_run_report=report,
                                   notes=tuple(notes))

    def reinvestigate(self, incident_id: str, *, actor: str, reason: str) -> DetectionResult:
        """Withdraw the pending package (for example an expired one) and investigate again.

        ``AWAITING_APPROVAL -> NOT_STARTED`` and then :meth:`investigate_and_propose`. Nothing is
        executed; the withdrawn package can no longer be decided because a newer one supersedes it
        (or, with nothing to propose, because the incident is no longer awaiting approval).
        """
        with self._lock(incident_id):
            incident = self._incidents.get(incident_id)
            if incident.state is not IncidentState.NOT_STARTED:
                self._transition(incident_id, IncidentState.NOT_STARTED, actor=actor, reason=reason)
            return self.investigate_and_propose(incident_id)

    # ------------------------------------------------------------ proposal --
    def propose(self, incident_id: str, package: ContainmentPackage) -> ContainmentPackage:
        """Record ``package`` for human approval and move the incident to ``AWAITING_APPROVAL``.

        A newer package proposed while the incident is already awaiting approval supersedes the
        older one (only the latest containment package can be decided).
        """
        if not isinstance(package, ContainmentPackage):
            raise TypeError("propose() needs a ContainmentPackage")
        if package.incident_id != incident_id:
            raise ValueError("package belongs to a different incident")
        with self._lock(incident_id):
            incident = self._incidents.get(incident_id)
            target = IncidentState.AWAITING_APPROVAL
            if incident.state is not target and not can_transition(incident.state, target):
                raise InvalidTransitionError(incident.state, target, "cannot propose containment now")
            violations = self._rt.packages.policy_violations(package, incident)
            if violations:
                raise ValueError("package approval levels are lower than the policy requires: "
                                 + "; ".join(violations))
            self._packages.save(package)
            self._rt.recorder.package_proposed(package)
            if incident.state is not target:
                self._transition(incident_id, target, actor=LIFECYCLE_ACTOR,
                                 reason=f"containment package proposed ({len(package.actions)} action(s))",
                                 package_id=package.package_id)
            return package

    def dry_run(self, package: ContainmentPackage) -> ContainmentReport:
        """Simulate a containment package. Never changes vendor or incident state."""
        report = self._rt.executor.execute(package, None, dry_run=True)
        self._reports[package.package_id] = report
        return report

    # ------------------------------------------------------------ decision --
    def _decidable(self, request: DecisionRequest, purpose: ApprovalPurpose,
                   expected_state: IncidentState) -> tuple[ActionPackage, Incident]:
        try:
            package = self._packages.get(request.package_id)
        except KeyError:
            raise DecisionError(f"unknown package {request.package_id}") from None
        if package.purpose is not purpose:
            raise DecisionError(f"package {package.package_id} is a {package.purpose.value} package")
        incident = self._incidents.get(package.incident_id)
        if incident.state is not expected_state:
            raise DecisionError(f"incident {incident.incident_id} is {incident.state.value}, "
                                f"not {expected_state.value}")
        latest = self._packages.latest_for_incident(incident.incident_id, purpose)
        if latest is None or latest.package_id != package.package_id:
            raise DecisionError("package was superseded by a newer proposal")
        if self._packages.is_executed(package.package_id):
            raise DecisionError("package was already executed")
        return package, incident

    def submit_decision(self, request: DecisionRequest,
                        credentials: Sequence[ApproverCredential]) -> DecisionResult:
        """Record a human decision on the pending containment package and act on it."""
        result = self._submit_decision(request, credentials)
        if self._rt.observers:
            self._emit_decision(result, request.package_id, "containment_completed")
        return result

    def _submit_decision(self, request: DecisionRequest,
                         credentials: Sequence[ApproverCredential]) -> DecisionResult:
        package_id = request.package_id
        try:
            incident_id = self._packages.get(package_id).incident_id
        except KeyError:
            raise DecisionError(f"unknown package {package_id}") from None
        with self._lock(incident_id):
            package, incident = self._decidable(request, ApprovalPurpose.CONTAINMENT,
                                                IncidentState.AWAITING_APPROVAL)
            package = _as_simulation_if_dry_run(package, self._dry_run_active())
            outcome = self._rt.approval.decide(package, request, credentials)
            decision = outcome.decision
            analyst = decision.analyst_identity
            if decision.decision is DecisionType.REJECT:
                incident = self._transition(incident_id, IncidentState.CLOSED, actor=analyst,
                                            reason=f"containment rejected: {decision.comment}".strip(),
                                            package_id=package.package_id)
                return DecisionResult(outcome=outcome, incident=incident, report=None)
            if decision.decision is DecisionType.REQUEST_MORE_INVESTIGATION:
                incident = self._transition(incident_id, IncidentState.NOT_STARTED, actor=analyst,
                                            reason=f"more investigation requested: {decision.comment}".strip(),
                                            package_id=package.package_id)
                return DecisionResult(outcome=outcome, incident=incident, report=None)
            assert isinstance(package, ContainmentPackage) and outcome.token is not None
            if self._dry_run_active() or package.dry_run:
                report = self._rt.executor.execute(package, outcome.token, dry_run=True)
                self._reports[package.package_id] = report
                return DecisionResult(outcome=outcome, incident=self._incidents.get(incident_id), report=report)
            return self._execute_containment(package, outcome)

    def _execute_containment(self, package: ContainmentPackage, outcome: ApprovalOutcome) -> DecisionResult:
        token = outcome.token
        assert token is not None
        incident_id = package.incident_id
        approved = len(outcome.decision.approved_action_keys)
        self._packages.mark_executed(package.package_id)  # first: a failure below can never allow a second run
        self._transition(incident_id, IncidentState.APPROVED, actor=outcome.decision.analyst_identity,
                         reason=f"{outcome.decision.decision.value}: {approved} action(s) approved",
                         package_id=package.package_id, token=token)
        self._transition(incident_id, IncidentState.CONTAINMENT_RUNNING, actor=EXECUTION_ACTOR,
                         reason="approved containment starts automatically", package_id=package.package_id,
                         token=token)
        try:
            report = self._rt.executor.execute(package, token)
        except ApprovalRequiredError as exc:
            reason = get_redactor().redact_text(f"execution refused: {type(exc).__name__}: {exc}")
            incident = self._transition(incident_id, IncidentState.CONTAINMENT_FAILED, actor=EXECUTION_ACTOR,
                                        reason=reason, package_id=package.package_id)
            return DecisionResult(outcome=outcome, incident=incident, report=None, error=reason)
        self._reports[package.package_id] = report
        assert report.overall is not None
        flag = self._rt.settings.thresholds.verification.unable_to_verify_counts_as_contained
        assessment = assess_containment(incident_id, report.results, unable_to_verify_counts_as_contained=flag)
        incident = self._transition(incident_id, to_incident_state(report.overall), actor=VERIFICATION_ACTOR,
                                    reason=f"containment {report.overall.value} (verified)",
                                    package_id=package.package_id, token=token, report=report)
        if assessment.recommended_next_state is IncidentState.REMEDIATION_REQUIRED:
            incident = self._transition(incident_id, IncidentState.REMEDIATION_REQUIRED,
                                        actor=VERIFICATION_ACTOR,
                                        reason="; ".join(assessment.remediation_reasons)[:2000],
                                        package_id=package.package_id)
        return DecisionResult(outcome=outcome, incident=incident, report=report, assessment=assessment)

    def propose_retry(self, incident_id: str, *, requested_by: str = LIFECYCLE_ACTOR) -> ContainmentPackage:
        """New package with the approved actions of the last run that failed (needs a new approval)."""
        with self._lock(incident_id):
            last = self._packages.latest_for_incident(incident_id, ApprovalPurpose.CONTAINMENT)
            report = self._reports.get(last.package_id) if last is not None else None
            if last is None or not isinstance(report, ContainmentReport) or report.dry_run:
                raise DecisionError("no executed containment package to retry")
            flag = self._rt.settings.thresholds.verification.unable_to_verify_counts_as_contained
            assessment = assess_containment(incident_id, report.results,
                                            unable_to_verify_counts_as_contained=flag)
            failed = {a.idempotency_key for a in assessment.actions if a.verdict is ActionVerdict.FAILED}
            proposals = [_as_proposal(a) for a in last.actions if a.idempotency_key in failed]
            if not proposals:
                raise DecisionError("nothing to retry: no approved action failed")
            incident = self._incidents.get(incident_id)
            package = self._rt.packages.build(
                incident, proposals, risk_score=max(p.risk_score for p in proposals),
                confidence_score=round(sum(p.confidence_score for p in proposals) / len(proposals)),
                summary=f"Retry of {len(proposals)} failed action(s) from package {last.package_id}",
                dry_run=self._dry_run_active(), requested_by=requested_by)
            return self.propose(incident_id, package)

    def mark_remediation_required(self, incident_id: str, *, actor: str, reason: str) -> Incident:
        """Record that a human must remediate (no vendor change; controls stay in force)."""
        with self._lock(incident_id):
            return self._transition(incident_id, IncidentState.REMEDIATION_REQUIRED, actor=actor, reason=reason)

    # ------------------------------------------------------------- release --
    def propose_release(self, incident_id: str, control_keys: Sequence[str] | None = None, *,
                        requested_by: str = "automation:restoration_planner") -> ReleasePackage:
        """Release package for ACTIVE controls of the incident -> ``AWAITING_RELEASE_APPROVAL``."""
        package = self._propose_release(incident_id, control_keys, requested_by=requested_by)
        if self._rt.observers:
            self._emit("release_proposed", self._incidents.get(incident_id), package=package,
                       dry_run=package.dry_run or self._dry_run_active())
        return package

    def _propose_release(self, incident_id: str, control_keys: Sequence[str] | None, *,
                         requested_by: str) -> ReleasePackage:
        with self._lock(incident_id):
            incident = self._incidents.get(incident_id)
            target = IncidentState.AWAITING_RELEASE_APPROVAL
            if incident.state is not target and not can_transition(incident.state, target):
                raise InvalidTransitionError(incident.state, target, "cannot propose a release now")
            package = self._rt.planner.build_release_package(incident, control_keys, requested_by=requested_by)
            self._packages.save(package)
            self._rt.recorder.release_package_proposed(package)
            if incident.state is not target:
                self._transition(incident_id, target, actor=LIFECYCLE_ACTOR,
                                 reason=f"release package proposed ({len(package.actions)} control(s))",
                                 package_id=package.package_id)
            return package

    def submit_release_decision(self, request: DecisionRequest,
                                credentials: Sequence[ApproverCredential]) -> DecisionResult:
        """Record a human decision on the pending release package and act on it."""
        result = self._submit_release_decision(request, credentials)
        if self._rt.observers:
            self._emit_decision(result, request.package_id, "restoration_completed")
        return result

    def _submit_release_decision(self, request: DecisionRequest,
                                 credentials: Sequence[ApproverCredential]) -> DecisionResult:
        try:
            incident_id = self._packages.get(request.package_id).incident_id
        except KeyError:
            raise DecisionError(f"unknown package {request.package_id}") from None
        with self._lock(incident_id):
            package, _ = self._decidable(request, ApprovalPurpose.RELEASE, IncidentState.AWAITING_RELEASE_APPROVAL)
            package = _as_simulation_if_dry_run(package, self._dry_run_active())
            outcome = self._rt.approval.decide(package, request, credentials)
            decision = outcome.decision
            if decision.decision not in _APPROVING:
                incident = self._transition(
                    incident_id, IncidentState.REMEDIATION_REQUIRED, actor=decision.analyst_identity,
                    reason=f"release {decision.decision.value}: {decision.comment}; controls stay ACTIVE",
                    package_id=package.package_id)
                return DecisionResult(outcome=outcome, incident=incident, report=None)
            assert isinstance(package, ReleasePackage) and outcome.token is not None
            if self._dry_run_active() or package.dry_run:
                report = self._rt.restoration.execute(package, outcome.token, dry_run=True)
                self._reports[package.package_id] = report
                return DecisionResult(outcome=outcome, incident=self._incidents.get(incident_id), report=report)
            return self._execute_release(package, outcome)

    def _execute_release(self, package: ReleasePackage, outcome: ApprovalOutcome) -> DecisionResult:
        token = outcome.token
        assert token is not None
        incident_id = package.incident_id
        self._packages.mark_executed(package.package_id)  # first: a failure below can never allow a second run
        self._transition(incident_id, IncidentState.RESTORATION_RUNNING, actor=outcome.decision.analyst_identity,
                         reason=f"release approved: {len(outcome.decision.approved_action_keys)} control(s)",
                         package_id=package.package_id, token=token)
        try:
            report = self._rt.restoration.execute(package, token)
        except (ApprovalRequiredError, RegistryError) as exc:
            reason = get_redactor().redact_text(f"release refused: {type(exc).__name__}: {exc}")
            incident = self._transition(incident_id, IncidentState.AWAITING_RELEASE_APPROVAL,
                                        actor=EXECUTION_ACTOR, reason=reason, package_id=package.package_id)
            return DecisionResult(outcome=outcome, incident=incident, report=None, error=reason)
        self._reports[package.package_id] = report
        assert report.overall is not None
        flag = self._rt.settings.thresholds.verification.unable_to_verify_counts_as_contained
        assessment = assess_restoration(incident_id, report.results, unable_to_verify_counts_as_contained=flag)
        incident = self._transition(incident_id, to_incident_state(report.overall), actor=VERIFICATION_ACTOR,
                                    reason=f"restoration {report.overall.value} (verified)",
                                    package_id=package.package_id, report=report)
        return DecisionResult(outcome=outcome, incident=incident, report=report, assessment=assessment)

    # --------------------------------------------------------------- close --
    def close(self, incident_id: str, *, actor: str, reason: str) -> Incident:
        """Close the incident. Temporary controls are never removed by closing.

        Approvals issued for packages of the incident that were not executed are voided (their
        tokens stop verifying), so nothing can run against a closed incident later.
        """
        with self._lock(incident_id):
            outstanding = self.outstanding_controls(incident_id)
            note = (f"; {len(outstanding)} temporary control(s) remain in force: "
                    + ", ".join(c.control_key for c in outstanding)) if outstanding else ""
            incident = self._transition(incident_id, IncidentState.CLOSED, actor=actor,
                                        reason=f"{reason}{note}"[:4000])
            self._void_unexecuted_approvals(incident_id)
        if self._rt.observers:
            self._emit("incident_closed", incident, notes=(note.lstrip("; "),) if note else (),
                       dry_run=self._dry_run_active())
        return incident

    # ----------------------------------------------------------- observers --
    def _emit(self, kind: str, incident: Incident, **fields: Any) -> None:
        """Build a ``LifecycleEvent`` and hand it to every observer (failures logged, never raised)."""
        from xdr_response.atomics.notifications.models import LifecycleEvent, LifecycleEventKind
        from xdr_response.lifecycle.observers import notify_observers

        try:
            event = LifecycleEvent(kind=LifecycleEventKind(kind), at=self._rt.clock.now(), incident=incident,
                                   **fields)
        except (ValueError, TypeError) as exc:  # an event that cannot be built is logged, never fatal
            _log.error("lifecycle event %s for %s not emitted: %s", kind, incident.incident_id,
                       type(exc).__name__)
            return
        notify_observers(self._rt.observers, event)

    def _emit_detection(self, result: DetectionResult) -> None:
        summary = _workflow_summary(result.investigation)
        kind = "package_proposed" if result.package is not None else "detection_completed"
        dry_run = result.package.dry_run if result.package is not None else self._dry_run_active()
        self._emit(kind, result.incident, package=result.package, summary=summary, notes=result.notes,
                   dry_run=dry_run)

    def _emit_decision(self, result: DecisionResult, package_id: str, completed: str) -> None:
        try:
            package = self._packages.get(package_id)
        except KeyError:
            package = None
        dry_run = result.dry_run or self._dry_run_active() or bool(package is not None and package.dry_run)
        self._emit("decision_recorded", result.incident, package=package, decision=result.outcome.decision,
                   dry_run=dry_run)
        if result.report is not None and not result.report.dry_run:
            self._emit(completed, result.incident, package=package, decision=result.outcome.decision,
                       report=result.report, dry_run=False)

    def _void_unexecuted_approvals(self, incident_id: str) -> None:
        for purpose in (ApprovalPurpose.CONTAINMENT, ApprovalPurpose.RELEASE):
            package = self._packages.latest_for_incident(incident_id, purpose)
            if package is not None and not self._packages.is_executed(package.package_id):
                self._rt.tokens.revoke_package(package.package_id)


def _workflow_summary(investigation: InvestigationReport) -> Any:
    """``run.summary()`` of a workflow investigation, else None (Phase 0 generic path)."""
    run = getattr(investigation, "run", None)
    if run is None:
        return None
    try:
        return run.summary()
    except Exception as exc:  # noqa: BLE001 - a summary problem never blocks the lifecycle
        _log.error("workflow summary unavailable: %s", type(exc).__name__)
        return None


def _as_simulation_if_dry_run(package: ActionPackage, dry_run_active: bool) -> ActionPackage:
    """While dry run is active, decide on a copy marked ``dry_run`` (its token never runs live)."""
    if dry_run_active and not package.dry_run:
        return package.model_copy(update={"dry_run": True})
    return package


def _as_proposal(action: object) -> ProposedAction:
    from xdr_response.models import RecommendedAction

    assert isinstance(action, RecommendedAction)
    drafts = tuple(EvidenceDraft(**e.model_dump(exclude={"number"})) for e in action.evidence)
    return ProposedAction(action_type=action.action_type, target=action.target, target_kind=action.target_kind,
                          params=dict(action.params), evidence=drafts, risk_score=action.risk_score,
                          confidence_score=action.confidence_score,
                          rationale=action.rationale or "retry of a failed approved action")
