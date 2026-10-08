"""Plugging workflows into the Phase 0 lifecycle (architecture 14.3.6).

:class:`WorkflowInvestigator` has the contract of ``InvestigationService.run``: it resolves the
incident's workflow, runs it with the read-only :class:`WorkflowRunner` and returns a
:class:`WorkflowInvestigationReport` (the Phase 0 report plus the run). An incident no workflow
handles (or whose workflow is a legacy spec not migrated yet) takes the Phase 0 generic path.

:class:`WorkflowRecommender` implements ``lifecycle.recommendation.Recommender``: a report with a run
becomes a :class:`Recommendation` of the run's proposals and scores; anything else goes to the
fallback (the Phase 0 ``RuleBasedRecommender``).

Both only investigate and recommend. The proposals go to ``PackageBuilder`` (allow-lists,
critical-asset ELEVATED, blast radius) and wait for a human decision in the orchestrator; nothing
here executes, approves or touches a token.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from xdr_response.atomics.evidence import EvidenceBuilder, EvidenceError
from xdr_response.audit.events import AuditRecorder
from xdr_response.errors import AuditError
from xdr_response.interfaces import AuditSink
from xdr_response.lifecycle.investigation import INVESTIGATION_ACTOR, InvestigationReport, InvestigationService
from xdr_response.lifecycle.recommendation import Recommendation, Recommender, UnroutedAction
from xdr_response.logs.redaction import get_redactor
from xdr_response.logs.setup import get_logger
from xdr_response.models import Incident, ProposedAction, evidence_snapshot_hash
from xdr_response.workflows.discovery import WorkflowCatalog, not_migrated
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun, WorkflowRunner

__all__ = ["WorkflowInvestigationReport", "WorkflowInvestigator", "WorkflowRecommender"]

_log = get_logger("lifecycle.workflow_adapter")


@dataclass(frozen=True)
class WorkflowInvestigationReport(InvestigationReport):
    """Phase 0 report (raw vendor results and health) plus the workflow run, when one ran."""

    run: WorkflowRun | None = None
    notes: tuple[str, ...] = ()  # routing notes (for example "workflow <id> not migrated yet")


class WorkflowInvestigator:
    """Same contract as ``InvestigationService.run``; runs the incident's workflow when there is one."""

    def __init__(self, catalog: WorkflowCatalog, runner: WorkflowRunner, fallback: InvestigationService, *,
                 audit: AuditSink | None, dry_run: Callable[[], bool]) -> None:
        self._catalog = catalog
        self._runner = runner
        self._fallback = fallback
        self._audit = AuditRecorder(audit, actor=INVESTIGATION_ACTOR) if audit is not None else None
        self._dry_run = dry_run

    @property
    def catalog(self) -> WorkflowCatalog:
        return self._catalog

    def run(self, incident: Incident) -> InvestigationReport:
        """Resolve, run (or fall back), audit, report. Never raises for a source, rule or hook."""
        workflow = self._catalog.resolve(incident)
        if workflow is None:
            note = (f"workflow {incident.workflow_id} not migrated yet: Phase 0 generic investigation used"
                    if not_migrated(incident.workflow_id, self._catalog) else "")
            return self._generic(incident, note)
        try:
            run = self._runner.run(workflow.definition, workflow.hooks, incident, dry_run=bool(self._dry_run()))
        except Exception as exc:  # noqa: BLE001 - a framework bug never blocks the generic recommendation
            reason = get_redactor().redact_text(f"{type(exc).__name__}: {exc}")[:500]
            _log.error("workflow %s failed for %s: %s", workflow.id, incident.incident_id, reason)
            return self._generic(incident, f"workflow {workflow.id} failed ({reason}): Phase 0 generic "
                                           "investigation used")
        report = WorkflowInvestigationReport(
            incident_id=incident.incident_id, enrichments=run.raw_enrichments(),
            investigations=run.raw_investigations(), health=dict(run.health), run=run)
        self._audit_run(incident, report)
        return report

    def _generic(self, incident: Incident, note: str) -> InvestigationReport:
        report = self._fallback.run(incident)
        if not note:
            return report
        return WorkflowInvestigationReport(incident_id=report.incident_id, enrichments=report.enrichments,
                                           investigations=report.investigations, health=dict(report.health),
                                           run=None, notes=(note,))

    def _audit_run(self, incident: Incident, report: WorkflowInvestigationReport) -> None:
        """ENRICHMENT_RESULT per raw enrichment and INVESTIGATION_COMPLETED once (InvestigationService policy)."""
        if self._audit is None:
            return
        for result in report.enrichments:
            try:
                self._audit.enrichment_result(incident.incident_id, result)
            except (AuditError, OSError) as exc:  # read-only step: log loudly, keep going
                _log.error("ENRICHMENT_RESULT audit failed for %s: %s", incident.incident_id, type(exc).__name__)
        evidence = report.evidence
        try:
            self._audit.investigation_completed(
                incident.incident_id, report.investigations, evidence=evidence,
                evidence_snapshot_hash=evidence_snapshot_hash(evidence) if evidence else None)
        except (AuditError, OSError) as exc:
            _log.error("INVESTIGATION_COMPLETED audit failed for %s: %s", incident.incident_id,
                       type(exc).__name__)


class WorkflowRecommender:
    """Implements ``Recommender``: a workflow run's proposals, else the fallback recommender."""

    def __init__(self, fallback: Recommender) -> None:
        self._fallback = fallback

    def recommend(self, incident: Incident, investigation: InvestigationReport) -> Recommendation:
        run = investigation.run if isinstance(investigation, WorkflowInvestigationReport) else None
        if run is None:
            recommendation = self._fallback.recommend(incident, investigation)
            notes = investigation.notes if isinstance(investigation, WorkflowInvestigationReport) else ()
            return replace(recommendation, notes=(*notes, *recommendation.notes)) if notes else recommendation
        proposals, refused = _verified_proposals(run)
        if refused:
            run = replace(run, proposals=proposals)
        return Recommendation(
            incident_id=incident.incident_id, proposals=proposals, risk_score=run.risk_score,
            confidence_score=run.confidence_score, summary=_summary(incident, run),
            unrouted=tuple(UnroutedAction(o.action_type, o.target or "", o.detail)
                           for o in run.outcomes_with(RuleOutcomeStatus.UNROUTED)),
            notes=(*run.notes, *refused))


def _verified_proposals(run: WorkflowRun) -> tuple[tuple[ProposedAction, ...], tuple[str, ...]]:
    """The run's proposals whose evidence all cites records of this run, unchanged (14.9.7).

    The last read-zone boundary before ``PackageBuilder``: a proposal whose evidence names a record
    the run never produced, or differs from the record it cites, is refused and noted (visible to
    the analyst, never forwarded and never silently dropped).
    """
    builder = EvidenceBuilder(run.index)
    kept: list[ProposedAction] = []
    refused: list[str] = []
    for proposal in run.proposals:
        try:
            if not proposal.evidence:
                raise EvidenceError("no evidence")
            builder.verify(proposal.evidence)
        except EvidenceError as exc:
            reason = get_redactor().redact_text(str(exc))[:300]
            _log.error("refused workflow %s proposal %s: evidence does not cite this run's records",
                       run.workflow.id, proposal.action_type.value)
            refused.append(f"refused {proposal.action_type.value} {proposal.target}: evidence does not match the "
                           f"records of this run ({reason}); not packaged")
            continue
        kept.append(proposal)
    return tuple(kept), tuple(refused)


def _summary(incident: Incident, run: WorkflowRun) -> str:
    label = f"workflow {run.workflow.id} {run.workflow.version}"
    if not run.proposals:
        return f"No containment recommended for {incident.incident_id} by {label}: no rule proposed an action"
    parts = ", ".join(f"{p.action_type.value} {p.target}" for p in run.proposals)
    return (f"{len(run.proposals)} containment action(s) recommended by {label} for {incident.title}: {parts} "
            f"(risk {run.risk_score}, confidence {run.confidence_score})")
