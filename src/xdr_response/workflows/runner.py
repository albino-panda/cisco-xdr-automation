"""Workflow runner (architecture 14.3.4): investigate, correlate, score and recommend. Never executes.

:meth:`WorkflowRunner.run` turns a :class:`WorkflowDefinition` and an incident into a
:class:`WorkflowRun`: typed records from the read atomics, correlation and blast radius, record-backed
scores per target and :class:`~xdr_response.models.ProposedAction` objects built by the containment
builders. Everything after that (packaging, ELEVATED approval, the human decision, execution,
verification, restoration) is Phase 0 lifecycle code.

``run`` is deterministic (injected clock, sorted inputs) and never raises because of a source, a rule
or a hook: a failing source is a degraded :class:`SourceStatus`; a failing step, expression, builder
call or hook is noted and skipped, and the rest of the run still produces a recommendation backed by
the evidence that is available.

Read zone (14.0.1): this module holds a :class:`ReadOnlyAdapters` facade only, never an adapter,
token, guard or audit writer. Its only output type is ``ProposedAction``; approval levels, numbering
and idempotency keys stay with ``PackageBuilder``.
"""
from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from xdr_response.approval.critical_assets import CriticalAssetPolicy
from xdr_response.atomics import containment_builders, read_atomics
from xdr_response.atomics.containment.builders import _merge_assets, build_containment
from xdr_response.atomics.containment.models import BuiltRecommendation
from xdr_response.atomics.context import AtomicContext, ReadOnlyAdapters, _context
from xdr_response.atomics.correlation.blast_radius import blast_radius as compute_blast_radius
from xdr_response.atomics.correlation.correlate import correlate
from xdr_response.atomics.correlation.models import BlastRadiusReport, CorrelationLink, CorrelationResult, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.evidence import EvidenceBuilder, EvidenceError, RecordIndex
from xdr_response.atomics.notifications.models import WorkflowSummary
from xdr_response.atomics.records import AnyRecord, AtomicResult, EnrichmentRecord, SourceOutcome
from xdr_response.clock import Clock
from xdr_response.config import Settings
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import (
    ActionType,
    Asset,
    CriticalAssetWarning,
    EnrichmentResult,
    EvidenceDraft,
    FrozenModel,
    HealthStatus,
    Incident,
    InvestigationResult,
    Observable,
    ObservableType,
    ProposedAction,
    RiskBand,
    TargetKind,
    Verdict,
    canonical_json,
    get_action_spec,
    normalize_target,
)
from xdr_response.models.recommendation import risk_band
from xdr_response.models.scoring import ScoreBreakdown, ScoringContext, ScoringSignal
from xdr_response.scoring.engine import ScoringEngine
from xdr_response.scoring.signals import signals_from_enrichment, signals_from_records
from xdr_response.workflows.definition import InvestigationStep, RecommendationRule, WorkflowDefinition
from xdr_response.workflows.expr import ExprError, evaluate
from xdr_response.workflows.hooks import RunView, WorkflowHooks

__all__ = ["RuleOutcomeStatus", "RuleOutcome", "WorkflowRun", "WorkflowRunner"]

_O = ObservableType
_T = TargetKind
_NOTE_CHARS = 500
_SUPPORTING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_HEALTH_RANK: Mapping[HealthStatus, int] = {
    HealthStatus.CONNECTED: 0, HealthStatus.UNKNOWN: 1, HealthStatus.DEGRADED: 2,
    HealthStatus.RATE_LIMITED: 3, HealthStatus.AUTH_FAILED: 4, HealthStatus.UNAVAILABLE: 5,
}
_HASH_TYPES: Mapping[int, ObservableType] = {64: _O.SHA256, 40: _O.SHA1, 32: _O.MD5}

#: Rule-item fields that mention an entity of a subject type (values found by earlier steps).
_MENTION_FIELDS: Mapping[ObservableType, tuple[str, ...]] = {
    _O.HOSTNAME: ("hostname", "endpoint", "endpoints"),
    _O.ENDPOINT_ID: ("connector_guid", "mde_machine_id", "intune_device_id"),
    _O.USER: ("user", "users", "mailbox"),
    _O.EMAIL_ADDRESS: ("sender", "recipients"),
    _O.DOMAIN: ("domain", "domains", "sender_domain"),
    _O.URL: ("url", "urls"),
    _O.IP: ("remote_ip", "local_ip", "ip", "client_ip", "ip_addresses", "response_ips"),
    _O.IPV6: ("remote_ip", "local_ip", "ip", "client_ip", "ip_addresses", "response_ips"),
    _O.SHA256: ("sha256", "parent_sha256", "attachment_hashes"),
    _O.SHA1: ("sha256", "parent_sha256", "attachment_hashes"),
    _O.MD5: ("sha256", "parent_sha256", "attachment_hashes"),
    _O.EMAIL_MESSAGE_ID: ("message_id",),
}
_SKIP_MENTIONS = frozenset({"enrichment", "generic"})


class RuleOutcomeStatus(StrEnum):
    PROPOSED = "PROPOSED"
    BELOW_THRESHOLD = "BELOW_THRESHOLD"
    UNROUTED = "UNROUTED"
    DUPLICATE = "DUPLICATE"
    NO_EVIDENCE = "NO_EVIDENCE"
    ERROR = "ERROR"


class RuleOutcome(FrozenModel):
    """What one recommendation rule did for one ``for_each`` item."""

    rule_id: str
    status: RuleOutcomeStatus
    action_type: ActionType
    target: str | None = None
    risk_score: int = 0
    confidence_score: int = 0
    record_ids: tuple[str, ...] = ()
    detail: str = ""

    @property
    def selector(self) -> str:
        """``"<action_type>:<target>"`` (the scenario expectation format)."""
        return f"{self.action_type.value}:{self.target or ''}"


@dataclass(frozen=True)
class WorkflowRun:
    """Everything one run learned and recommended (read-zone output, no state change)."""

    workflow: WorkflowDefinition
    incident_id: str
    dry_run: bool
    started_at: datetime
    finished_at: datetime
    results: tuple[AtomicResult, ...]
    index: RecordIndex
    correlation: CorrelationResult
    blast_radius: BlastRadiusReport
    signals: tuple[ScoringSignal, ...]  # hook-derived, validated
    built: tuple[BuiltRecommendation, ...]
    outcomes: tuple[RuleOutcome, ...]
    proposals: tuple[ProposedAction, ...]  # == [b.proposal for b in built if b.proposal]
    breakdowns: Mapping[tuple[ActionType, str], ScoreBreakdown]
    risk_score: int  # ScoringEngine.package_scores
    confidence_score: int
    health: Mapping[str, HealthStatus]  # worst status per integration
    notes: tuple[str, ...]

    def outcomes_with(self, status: RuleOutcomeStatus) -> tuple[RuleOutcome, ...]:
        """Outcomes of one status, in rule order."""
        return tuple(o for o in self.outcomes if o.status is status)

    def degraded_sources(self) -> tuple[str, ...]:
        """Integrations that FAILED in any atomic result, sorted."""
        return tuple(sorted({s.integration for r in self.results for s in r.sources
                             if s.outcome is SourceOutcome.FAILED}))

    def summary(self) -> WorkflowSummary:
        """Read-zone facts for notifications and the decision card."""
        return WorkflowSummary(
            workflow_id=self.workflow.id, workflow_version=self.workflow.version,
            risk_score=self.risk_score, confidence_score=self.confidence_score, risk_band=self._band(),
            evidence=self._evidence_lines(), degraded_sources=self.degraded_sources(),
            unrouted=tuple(f"{o.action_type.value} {o.target}: {o.detail}"
                           for o in self.outcomes_with(RuleOutcomeStatus.UNROUTED)),
            below_threshold=tuple(f"{o.action_type.value} {o.target}: risk {o.risk_score}, confidence "
                                  f"{o.confidence_score} (rule {o.rule_id})"
                                  for o in self.outcomes_with(RuleOutcomeStatus.BELOW_THRESHOLD)),
            blast_radius=self.blast_radius.to_blast_radius(),
        )

    def raw_enrichments(self) -> tuple[EnrichmentResult, ...]:
        """Vendor enrichment results behind the records (audited as ENRICHMENT_RESULT)."""
        return tuple(raw for r in self.results for raw in r.raw if isinstance(raw, EnrichmentResult))

    def raw_investigations(self) -> tuple[InvestigationResult, ...]:
        """Vendor investigation results behind the records (audited in INVESTIGATION_COMPLETED)."""
        return tuple(raw for r in self.results for raw in r.raw if isinstance(raw, InvestigationResult))

    def _band(self) -> RiskBand:
        for proposal in self.proposals:
            breakdown = self.breakdowns.get((proposal.action_type, proposal.target))
            if breakdown is not None and breakdown.risk_score == self.risk_score:
                return breakdown.risk_band
        return risk_band(self.risk_score)

    def _evidence_lines(self) -> tuple[str, ...]:
        lines: dict[str, None] = {}
        for proposal in self.proposals:
            for draft in proposal.evidence:
                lines.setdefault(f"[{draft.data.get('record_id', '?')}] {draft.summary}", None)
        return tuple(lines)


# ------------------------------------------------------------- run state --
@dataclass
class _Run:
    """Mutable state of one run (private; frozen into a WorkflowRun at the end)."""

    workflow: WorkflowDefinition
    hooks: WorkflowHooks | None
    incident: Incident
    ctx: AtomicContext
    notes: list[str] = field(default_factory=list)
    results: list[AtomicResult] = field(default_factory=list)
    index: RecordIndex = field(default_factory=RecordIndex)
    correlation: CorrelationResult | None = None
    blast: BlastRadiusReport | None = None
    signals: tuple[ScoringSignal, ...] = ()
    facts: Mapping[str, Any] = field(default_factory=dict)
    built: list[BuiltRecommendation] = field(default_factory=list)
    outcomes: list[RuleOutcome] = field(default_factory=list)
    breakdowns: dict[tuple[ActionType, str], ScoreBreakdown] = field(default_factory=dict)
    assets: dict[tuple[ActionType, str], Asset | None] = field(default_factory=dict)  # union per key
    evidence_ids: dict[tuple[ActionType, str], list[str]] = field(default_factory=dict)  # every rule's ids
    called: set[str] = field(default_factory=set)  # read calls already made in this run

    def note(self, text: str) -> None:
        clean = get_redactor().redact_text(" ".join(str(text).split()))[:_NOTE_CHARS]
        if clean not in self.notes:
            self.notes.append(clean)

    @property
    def origin(self) -> str:
        return f"workflow:{self.workflow.id}"


@dataclass(frozen=True)
class _Scored:
    """A target's evidence and score inside one rule evaluation."""

    target: str
    kind: TargetKind
    rule_ids: tuple[str, ...]
    drafts: tuple[EvidenceDraft, ...]
    breakdown: ScoreBreakdown
    asset: Asset | None


class _RuleFailure(Exception):
    """A rule item ends with a non-PROPOSED outcome (status and detail carried)."""

    def __init__(self, status: RuleOutcomeStatus, detail: str, *, target: str | None = None,
                 record_ids: Sequence[str] = (), breakdown: ScoreBreakdown | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.target = target
        self.record_ids = tuple(record_ids)
        self.breakdown = breakdown


def _error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


class WorkflowRunner:
    """Runs workflow definitions against the read-only adapter facade."""

    def __init__(self, adapters: ReadOnlyAdapters, settings: Settings, *, clock: Clock,
                 scorer: ScoringEngine | None = None) -> None:
        if not isinstance(adapters, ReadOnlyAdapters):
            raise TypeError("WorkflowRunner needs a ReadOnlyAdapters facade, never a registry or adapter")
        self._adapters = adapters
        self._settings = settings
        self._clock = clock
        self._scorer = scorer if scorer is not None else ScoringEngine(settings.thresholds.scoring)
        self._critical = CriticalAssetPolicy(settings.critical_assets)

    # ------------------------------------------------------------------ API --
    def run(self, workflow: WorkflowDefinition, hooks: WorkflowHooks | None, incident: Incident, *,
            dry_run: bool) -> WorkflowRun:
        """Investigate, correlate, score and recommend (see module docstring). Never executes."""
        started = self._clock.now()
        ctx = _context(incident, self._adapters, self._settings, clock=self._clock, dry_run=dry_run)
        state = _Run(workflow=workflow, hooks=hooks, incident=incident, ctx=ctx)
        self._note_disabled_integrations(state)
        for step in workflow.investigation:
            self._run_step(state, step)
        state.index = self._index(state)
        self._correlate(state)
        self._hook_signals_and_facts(state)
        for rule in workflow.recommendations:
            self._run_rule(state, rule)
        return self._finish(state, started, dry_run)

    # ------------------------------------------------------- investigation --
    def _note_disabled_integrations(self, state: _Run) -> None:
        enabled = set(self._adapters.enabled())
        for requirement in state.workflow.required_integrations:
            if requirement.integration not in enabled:
                state.note(f"required integration {requirement.integration} is not enabled: its evidence is "
                           "missing and confidence is reduced; other evidence still counts")

    def _run_step(self, state: _Run, step: InvestigationStep) -> None:
        names = self._names(state)
        if step.when is not None:
            try:
                if not evaluate(step.when, names):
                    state.note(f"step {step.id} skipped: condition is false")
                    return
            except ExprError as exc:
                state.note(f"step {step.id} skipped: condition failed: {exc}")
                return
        try:
            subjects = self._subjects(state, step, names)
        except (ExprError, ValueError) as exc:
            state.note(f"step {step.id} skipped: subjects failed: {exc}")
            return
        if len(subjects) > step.max_subjects:
            extra = ", ".join(o.value for o in subjects[step.max_subjects:])
            state.note(f"step {step.id}: {len(subjects) - step.max_subjects} subject(s) not queried "
                       f"(max_subjects {step.max_subjects}): {extra}")
            subjects = subjects[:step.max_subjects]
        if not subjects:
            state.note(f"step {step.id}: no {step.atomic} subject in the incident or earlier results")
            return
        ctx = state.ctx if step.lookback_hours is None else replace(
            state.ctx, lookback=timedelta(hours=step.lookback_hours))
        for observable in subjects:
            self._call_atomic(state, step, ctx, observable)

    def _subjects(self, state: _Run, step: InvestigationStep, names: Mapping[str, Any]) -> list[Observable]:
        if step.subjects is None:
            return _default_subjects(step.subject_types(), state.incident, state.results)
        value = evaluate(step.subjects, names)
        values = [value] if isinstance(value, str) else list(value or [])
        subject_type = step.subject_type or next(iter(step.subject_types()))
        out: dict[tuple[ObservableType, str], Observable] = {}
        for item in values:
            if item is None or str(item).strip() == "":
                continue
            observable = Observable(type=subject_type, value=str(item))
            out.setdefault((observable.type, observable.value.lower()), observable)
        return list(out.values())

    def _call_atomic(self, state: _Run, step: InvestigationStep, ctx: AtomicContext,
                     observable: Observable) -> None:
        atomic = read_atomics().get(step.atomic)
        if atomic is None:
            state.note(f"step {step.id}: read atomic {step.atomic} is not available")
            return
        call = _call_key(step, ctx, observable)
        if call in state.called:
            return  # the same read already ran in this run: its records are reused, never fetched twice
        state.called.add(call)
        try:
            if step.atomic.startswith("enrich_"):
                result = atomic(ctx, observable)
            else:
                result = atomic(ctx, observable, options=dict(step.options), integrations=step.integrations)
        except Exception as exc:  # noqa: BLE001 - a failing step never stops the run
            state.note(f"step {step.id}: {step.atomic} {observable.value} failed: {_error_text(exc)}")
            return
        if not isinstance(result, AtomicResult):
            state.note(f"step {step.id}: {step.atomic} returned {type(result).__name__}, not an AtomicResult")
            return
        state.results.append(result)

    def _index(self, state: _Run) -> RecordIndex:
        try:
            return RecordIndex(state.results)
        except EvidenceError:
            kept: list[AtomicResult] = []
            for result in state.results:
                try:
                    RecordIndex([*kept, result])
                except EvidenceError as exc:
                    state.note(f"{result.atomic} {result.subject.value}: records rejected: {exc}")
                    continue
                kept.append(result)
            state.results = kept
            return RecordIndex(kept)

    # ----------------------------------------------------------- correlation --
    def _view(self, state: _Run, *, final: bool) -> RunView:
        return RunView(workflow=state.workflow, incident=state.incident, results=tuple(state.results),
                       index=state.index, correlation=state.correlation if final else None,
                       blast_radius=state.blast if final else None)

    def _correlate(self, state: _Run) -> None:
        links = self._hook_links(state)
        state.correlation = self._correlation(state, links)
        if state.correlation is None and links:
            state.note("hook links ignored: correlation is retried without them")
            state.correlation = self._correlation(state, [])
        if state.correlation is None:
            state.correlation = CorrelationResult(incident_id=state.incident.incident_id)
        try:
            state.blast = compute_blast_radius(state.ctx, state.correlation, state.results)
        except Exception as exc:  # noqa: BLE001
            state.note(f"blast radius failed: {_error_text(exc)}")
            state.blast = BlastRadiusReport()

    @staticmethod
    def _correlation(state: _Run, links: Sequence[CorrelationLink]) -> CorrelationResult | None:
        spec = state.workflow.correlation
        try:
            return correlate(state.ctx, state.results, extra_links=links,
                             window=timedelta(minutes=spec.window_minutes), link_kinds=spec.link_kinds)
        except Exception as exc:  # noqa: BLE001 - correlation is context, never a blocker
            state.note(f"correlation failed: {_error_text(exc)}")
            return None

    def _hook_links(self, state: _Run) -> list[CorrelationLink]:
        if state.hooks is None:
            return []
        try:
            proposed = list(state.hooks.correlate(self._view(state, final=False)) or ())
        except Exception as exc:  # noqa: BLE001 - hooks never crash a run
            state.note(f"hook correlate failed: {_error_text(exc)}")
            return []
        valid: list[CorrelationLink] = []
        for link in proposed:
            problem = self._link_problem(state, link)
            if problem:
                state.note(f"hook link ignored: {problem}")
            else:
                valid.append(link)
        return valid

    @staticmethod
    def _link_problem(state: _Run, link: object) -> str:
        if not isinstance(link, CorrelationLink):
            return f"not a CorrelationLink ({type(link).__name__})"
        if link.kind is not LinkKind.WORKFLOW or link.origin != state.origin:
            return f"link {link.link_id} must have kind workflow and origin {state.origin}"
        try:
            state.index.require(link.record_ids)
        except EvidenceError as exc:
            return f"link {link.link_id}: {exc}"
        return ""

    def _hook_signals_and_facts(self, state: _Run) -> None:
        if state.hooks is None:
            return
        view = self._view(state, final=True)
        state.signals = tuple(self._valid_signals(state, view))
        try:
            facts = state.hooks.facts(view)
            if not isinstance(facts, Mapping):
                raise TypeError(f"facts must be a mapping, got {type(facts).__name__}")
            state.facts = json.loads(json.dumps(dict(facts), allow_nan=False))
        except Exception as exc:  # noqa: BLE001 - non-JSON facts are noted and ignored
            state.note(f"hook facts ignored: {_error_text(exc)}")
            state.facts = {}

    def _valid_signals(self, state: _Run, view: RunView) -> list[ScoringSignal]:
        try:
            proposed = list(state.hooks.derive_signals(view) or ())  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            state.note(f"hook derive_signals failed: {_error_text(exc)}")
            return []
        valid: list[ScoringSignal] = []
        for signal in proposed:
            if not isinstance(signal, ScoringSignal) or signal.origin != state.origin:
                state.note(f"hook signal ignored: needs a ScoringSignal with origin {state.origin}")
                continue
            try:
                cited = state.index.require(signal.record_ids)
            except EvidenceError as exc:
                state.note(f"hook signal ignored: {exc}")
                continue
            sources = {record.integration for record in cited}
            if signal.integration not in sources:
                # A hook may only attribute a signal to a source that produced a cited record:
                # anything else is fabricated attribution (and would inflate independent sources).
                state.note(f"hook signal ignored: attributed to {signal.integration} but cites only records of "
                           f"{', '.join(sorted(sources))}")
                continue
            own = [record for record in cited if record.integration == signal.integration]
            if not signal.vendor_verdict and all(str(record.kind) == "enrichment" for record in own):
                # A pattern over enrichment answers is still a vendor's word, never a detection. It is
                # judged by the records of the source the signal is attributed to: citing another
                # source's context record next to the vendor's answer does not make it behaviour.
                signal = signal.model_copy(update={"vendor_verdict": True})
            valid.append(signal)
        return valid

    # ----------------------------------------------------------------- names --
    def _names(self, state: _Run, item: Any = None) -> dict[str, Any]:
        names: dict[str, Any] = {
            "incident": _incident_item(state.incident),
            "results": _results_item(state.results),
            "enrichment": _enrichment_item(state.results),
            "correlation": (state.correlation.rule_item() if state.correlation is not None
                            else CorrelationResult(incident_id=state.incident.incident_id).rule_item()),
            "blast": (state.blast or BlastRadiusReport()).rule_item(),
            "facts": dict(state.facts),
        }
        if item is not None:
            names["item"] = item
        return names

    # ----------------------------------------------------------------- rules --
    def _run_rule(self, state: _Run, rule: RecommendationRule) -> None:
        names = self._names(state)
        try:
            items = evaluate(rule.for_each, names)
            if isinstance(items, (str, Mapping)) or not isinstance(items, Iterable):
                raise ExprError(f"for_each must give a list, got {type(items).__name__}")
        except ExprError as exc:
            self._outcome(state, rule, _RuleFailure(RuleOutcomeStatus.ERROR, f"for_each: {exc}"))
            return
        for item in items:
            try:
                self._run_item(state, rule, {**names, "item": item})
            except _RuleFailure as failure:
                self._outcome(state, rule, failure)

    def _run_item(self, state: _Run, rule: RecommendationRule, names: Mapping[str, Any]) -> None:
        if rule.when is not None and not self._expr(rule.when, names, "when"):
            return
        scored = self._score(state, rule, names)
        breakdown = scored.breakdown
        if breakdown.risk_score < rule.min_risk or breakdown.confidence_score < rule.min_confidence:
            raise _RuleFailure(RuleOutcomeStatus.BELOW_THRESHOLD,
                               f"risk {breakdown.risk_score} (min {rule.min_risk}), confidence "
                               f"{breakdown.confidence_score} (min {rule.min_confidence}): considered, not proposed",
                               target=scored.target, record_ids=scored.rule_ids, breakdown=breakdown)
        built = self._build(state, rule, names, scored)
        self._accept(state, rule, built, scored)

    def _expr(self, expression: str, names: Mapping[str, Any], what: str) -> Any:
        try:
            return evaluate(expression, names)
        except ExprError as exc:
            raise _RuleFailure(RuleOutcomeStatus.ERROR, f"{what}: {exc}") from None

    def _score(self, state: _Run, rule: RecommendationRule, names: Mapping[str, Any]) -> _Scored:
        kind = get_action_spec(rule.action).target_kind
        raw_target = self._expr(rule.target, names, "target")
        if raw_target is None or not str(raw_target).strip():
            raise _RuleFailure(RuleOutcomeStatus.ERROR, "target: empty value")
        target = _normalized(kind, str(raw_target))
        rule_ids = _id_list(self._expr(rule.evidence, names, "evidence"))
        if not rule_ids:
            raise _RuleFailure(RuleOutcomeStatus.NO_EVIDENCE, "the rule's evidence expression cited no record",
                               target=target)
        try:
            cited = state.index.require(rule_ids)
        except EvidenceError as exc:
            raise _RuleFailure(RuleOutcomeStatus.NO_EVIDENCE, str(exc), target=target, record_ids=rule_ids) from None
        asset = self._asset(rule, names, target, kind)
        observable = _target_observable(kind, target) or cited[0].subject
        enrichments = _target_enrichments(state.index, observable)
        extra = [r.record_id for r in enrichments if r.verdict in _SUPPORTING] if rule.include_target_enrichment else []
        drafts = EvidenceBuilder(state.index).cite([*rule_ids, *extra])
        uncited = [r for r in enrichments if r.record_id not in set(rule_ids)]  # never count a record twice
        signals = (*signals_from_records(cited, observable=observable), *signals_from_enrichment(uncited),
                   *(s for s in state.signals if _same(s.observable, observable)))
        context = self._scoring_context(state, target, kind, asset, observable, rule_ids)
        weights = dict(state.workflow.scoring.weights) or None
        breakdown = self._scorer.score(signals, context=context, weights=weights)
        return _Scored(target=target, kind=kind, rule_ids=rule_ids, drafts=drafts, breakdown=breakdown, asset=asset)

    def _asset(self, rule: RecommendationRule, names: Mapping[str, Any], target: str,
               kind: TargetKind) -> Asset | None:
        if rule.asset is None:
            return None
        value = self._expr(rule.asset, names, "asset")
        if value is None:
            return None
        if not isinstance(value, Mapping) or set(value) - {"groups", "tags", "roles", "ip"}:
            raise _RuleFailure(RuleOutcomeStatus.ERROR, "asset: must be a mapping of groups, tags, roles, ip")
        try:
            return Asset(name=target, kind=kind, groups=tuple(value.get("groups") or ()),
                         tags=tuple(value.get("tags") or ()), roles=tuple(value.get("roles") or ()),
                         ip=value.get("ip") or None)
        except ValueError as exc:
            raise _RuleFailure(RuleOutcomeStatus.ERROR, f"asset: {exc}") from None

    def _scoring_context(self, state: _Run, target: str, kind: TargetKind, asset: Asset | None,
                         observable: Observable, rule_ids: Sequence[str]) -> ScoringContext:
        cited = set(rule_ids)
        failed: dict[str, HealthStatus] = {}  # worst health per integration: one failed source, one penalty
        not_queried: set[tuple[str, str]] = set()
        for result in state.results:
            if not (_same(result.subject, observable) or cited.intersection(result.record_ids())):
                continue
            for source in result.sources:
                if source.outcome is SourceOutcome.FAILED:
                    worst = failed.get(source.integration)
                    if worst is None or _HEALTH_RANK[source.health] > _HEALTH_RANK[worst]:
                        failed[source.integration] = source.health
                elif source.outcome is SourceOutcome.NOT_QUERIED:
                    not_queried.add((source.integration, source.reason or "not queried"))
        return ScoringContext(critical_asset_classes=tuple(self._critical.classify(target, kind, asset)),
                              expected_sources=state.workflow.expected_sources(),
                              failed_sources=tuple(failed.items()), not_queried=tuple(not_queried))

    def _build(self, state: _Run, rule: RecommendationRule, names: Mapping[str, Any],
               scored: _Scored) -> BuiltRecommendation:
        rationale = self._expr(rule.rationale, names, "rationale")
        params = {key: self._expr(expression, names, f"param {key}") for key, expression in rule.params.items()}
        text = f"{str(rationale).strip() or rule.description}; {scored.breakdown.explain()}"
        kwargs: dict[str, Any] = {"evidence": scored.drafts, "risk_score": scored.breakdown.risk_score,
                                  "confidence_score": scored.breakdown.confidence_score, "rationale": text,
                                  "asset": scored.asset, "params": params or None}
        try:
            if rule.builder is not None:
                return containment_builders()[rule.builder](state.ctx, scored.target, **kwargs)
            return build_containment(state.ctx, rule.action, scored.target, **kwargs)
        except Exception as exc:  # noqa: BLE001 - a builder refusal is a rule ERROR, never a crash
            raise _RuleFailure(RuleOutcomeStatus.ERROR, f"builder: {_error_text(exc)}", target=scored.target,
                               record_ids=scored.rule_ids, breakdown=scored.breakdown) from None

    def _accept(self, state: _Run, rule: RecommendationRule, built: BuiltRecommendation, scored: _Scored) -> None:
        key = (built.action_type, built.target)
        breakdown = scored.breakdown
        if built.warnings:
            state.note(f"critical asset: {built.action_type.value} {built.target} needs ELEVATED approval ("
                       + "; ".join(w.message for w in built.warnings) + ")")
        if built.excluded_reason:
            state.note(f"allow-listed (shown as excluded, not executed): {built.action_type.value} "
                       f"{built.target}: {built.excluded_reason}")
        existing = next((i for i, b in enumerate(state.built) if (b.action_type, b.target) == key), None)
        if existing is not None and state.built[existing].proposal is None and built.proposal is not None:
            # An earlier rule could not route this action (its product is not enabled); this rule can.
            # A missing product never blocks a recommendation another route can execute: the routed
            # proposal replaces the unrouted entry and keeps its evidence, asset context and warnings.
            self._promote(state, existing, built, scored)
            state.note(f"rule {rule.id} routes {built.action_type.value} {built.target} through "
                       f"{built.route.integration}: the unrouted recommendation of an earlier rule is merged into it")
            self._proposed(state, rule, built, scored)
            return
        if existing is not None:
            self._merge(state, existing, built, scored)
            self._outcome(state, rule, _RuleFailure(
                RuleOutcomeStatus.DUPLICATE, "same action and target as an earlier rule: evidence merged, "
                "higher risk kept", target=built.target, record_ids=scored.rule_ids, breakdown=breakdown))
            return
        state.built.append(built)
        state.breakdowns[key] = breakdown
        state.assets[key] = scored.asset
        state.evidence_ids[key] = list(EvidenceBuilder.record_ids(scored.drafts))
        if built.proposal is None:
            self._outcome(state, rule, _RuleFailure(
                RuleOutcomeStatus.UNROUTED, built.unrouted_reason or "no execution path", target=built.target,
                record_ids=scored.rule_ids, breakdown=breakdown))
            return
        self._proposed(state, rule, built, scored)

    @staticmethod
    def _proposed(state: _Run, rule: RecommendationRule, built: BuiltRecommendation, scored: _Scored) -> None:
        breakdown = state.breakdowns[(built.action_type, built.target)]
        state.outcomes.append(RuleOutcome(
            rule_id=rule.id, status=RuleOutcomeStatus.PROPOSED, action_type=built.action_type, target=built.target,
            risk_score=breakdown.risk_score, confidence_score=breakdown.confidence_score,
            record_ids=scored.rule_ids, detail=rule.description))

    @staticmethod
    def _union_warnings(*groups: Iterable[CriticalAssetWarning]) -> tuple[CriticalAssetWarning, ...]:
        return tuple({w.message: w for group in groups for w in group}.values())

    def _remember(self, state: _Run, key: tuple[ActionType, str], scored: _Scored) -> list[str]:
        """Union the asset context and evidence ids every rule saw for ``key``; the merged ids."""
        state.assets[key] = _merge_assets(state.assets.get(key), scored.asset)
        ids = list(dict.fromkeys([*state.evidence_ids.get(key, []), *EvidenceBuilder.record_ids(scored.drafts)]))
        state.evidence_ids[key] = ids
        return ids

    def _merge(self, state: _Run, position: int, built: BuiltRecommendation, scored: _Scored) -> None:
        """Merge a duplicate (same action and target) into the first recommendation.

        Evidence is merged and the higher risk of a routed duplicate kept; the asset context and the
        critical-asset warnings are unioned (never shrunk) whether the duplicate is routed or not, so a
        duplicate rule that saw a critical asset still makes the packaged action ELEVATED.
        """
        first = state.built[position]
        key = (first.action_type, first.target)
        breakdown = scored.breakdown
        ids = self._remember(state, key, scored)
        update_built: dict[str, Any] = {"warnings": self._union_warnings(first.warnings, built.warnings)}
        if first.proposal is not None:
            ids = list(dict.fromkeys([*EvidenceBuilder.record_ids(first.proposal.evidence), *ids]))
            update: dict[str, Any] = {"evidence": EvidenceBuilder(state.index).cite(ids),
                                      "asset": _merge_assets(first.proposal.asset, state.assets[key])}
            if built.proposal is not None and breakdown.risk_score > state.breakdowns[key].risk_score:
                update.update(risk_score=breakdown.risk_score, confidence_score=breakdown.confidence_score,
                              rationale=built.proposal.rationale)
                state.breakdowns[key] = breakdown
            update_built["proposal"] = first.proposal.model_copy(update=update)
        state.built[position] = first.model_copy(update=update_built)

    def _promote(self, state: _Run, position: int, built: BuiltRecommendation, scored: _Scored) -> None:
        """Replace an unrouted first entry with a routed duplicate (evidence, asset, warnings unioned)."""
        assert built.proposal is not None
        first = state.built[position]
        key = (built.action_type, built.target)
        ids = self._remember(state, key, scored)
        ids = list(dict.fromkeys([*EvidenceBuilder.record_ids(built.proposal.evidence), *ids]))
        proposal = built.proposal.model_copy(update={
            "evidence": EvidenceBuilder(state.index).cite(ids),
            "asset": _merge_assets(built.proposal.asset, state.assets[key])})
        state.built[position] = built.model_copy(update={
            "proposal": proposal, "warnings": self._union_warnings(first.warnings, built.warnings)})
        state.breakdowns[key] = scored.breakdown

    def _outcome(self, state: _Run, rule: RecommendationRule, failure: _RuleFailure) -> None:
        breakdown = failure.breakdown
        state.outcomes.append(RuleOutcome(
            rule_id=rule.id, status=failure.status, action_type=rule.action, target=failure.target,
            risk_score=breakdown.risk_score if breakdown else 0,
            confidence_score=breakdown.confidence_score if breakdown else 0,
            record_ids=failure.record_ids, detail=failure.detail[:_NOTE_CHARS]))
        label = f"{rule.action.value} {failure.target}" if failure.target else rule.action.value
        if failure.status is RuleOutcomeStatus.ERROR:
            state.note(f"rule {rule.id} error ({label}): {failure.detail}")
        elif failure.status is RuleOutcomeStatus.BELOW_THRESHOLD:
            state.note(f"rule {rule.id} below threshold ({label}): {failure.detail}")
        elif failure.status is RuleOutcomeStatus.UNROUTED:
            state.note(f"rule {rule.id} unrouted ({label}): {failure.detail}; manual handling required")
        elif failure.status is RuleOutcomeStatus.NO_EVIDENCE:
            state.note(f"rule {rule.id} not proposed ({label}): no evidence: {failure.detail}")

    # ---------------------------------------------------------------- finish --
    def _finish(self, state: _Run, started: datetime, dry_run: bool) -> WorkflowRun:
        proposals = tuple(b.proposal for b in state.built if b.proposal is not None)
        scored = [state.breakdowns[(p.action_type, p.target)] for p in proposals]
        risk, confidence = self._scorer.package_scores(scored)
        health = _health(state.results)
        for result in state.results:
            for source in result.sources:
                if source.outcome is SourceOutcome.FAILED:
                    state.note(f"degraded source: {source.integration} ({source.health.value}) failed for "
                               f"{result.atomic} {result.subject.value}")
        return WorkflowRun(
            workflow=state.workflow, incident_id=state.incident.incident_id, dry_run=bool(dry_run),
            started_at=started, finished_at=self._clock.now(), results=tuple(state.results), index=state.index,
            correlation=state.correlation or CorrelationResult(incident_id=state.incident.incident_id),
            blast_radius=state.blast or BlastRadiusReport(), signals=state.signals, built=tuple(state.built),
            outcomes=tuple(state.outcomes), proposals=proposals, breakdowns=dict(state.breakdowns),
            risk_score=risk, confidence_score=confidence, health=health, notes=tuple(state.notes))


# ------------------------------------------------------------ pure helpers --
def _incident_item(incident: Incident) -> dict[str, Any]:
    item = incident.model_dump(mode="json")
    by_type: dict[str, list[str]] = {}
    for observable in incident.observables:
        by_type.setdefault(observable.type.value, []).append(observable.value)
    item["observables_by_type"] = by_type
    return item


def _results_item(results: Sequence[AtomicResult]) -> dict[str, list[dict[str, Any]]]:
    items: dict[str, list[dict[str, Any]]] = {name: [] for name in read_atomics()}
    for result in results:
        items.setdefault(result.atomic, []).append(result.rule_item())
    return items


def _enrichment_item(results: Sequence[AtomicResult]) -> dict[str, dict[str, Any]]:
    return {f"{r.subject.type.value}:{r.subject.value}": r.rule_item()
            for r in results if isinstance(r, ObservableReport)}


def _observable_key(observable: Observable) -> tuple[ObservableType, str]:
    return observable.type, observable.value.strip().lower()


def _same(first: Observable, second: Observable) -> bool:
    return _observable_key(first) == _observable_key(second)


def _default_subjects(types: frozenset[ObservableType], incident: Incident,
                      results: Sequence[AtomicResult]) -> list[Observable]:
    """Incident observables of the step's types, then values found by earlier steps (first seen)."""
    out: dict[tuple[ObservableType, str], Observable] = {}
    for observable in incident.observables:
        if observable.type in types:
            out.setdefault(_observable_key(observable), observable)
    for result in results:
        for record in result.records:
            for observable in _mentions(record, types):
                out.setdefault(_observable_key(observable), observable)
    return list(out.values())


def _mentions(record: AnyRecord, types: frozenset[ObservableType]) -> list[Observable]:
    if str(record.kind) in _SKIP_MENTIONS:
        return []
    item = record.rule_item()
    found: list[Observable] = []
    for observable_type in sorted(types, key=lambda t: t.value):
        for name in _MENTION_FIELDS.get(observable_type, ()):
            value = item.get(name)
            for candidate in (value if isinstance(value, list) else [value]):
                if isinstance(candidate, str) and _fits(observable_type, candidate):
                    found.append(Observable(type=observable_type, value=candidate))
    return found


def _fits(observable_type: ObservableType, value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if observable_type in (_O.IP, _O.IPV6):
        try:
            version = ipaddress.ip_address(text).version
        except ValueError:
            return False
        return version == (4 if observable_type is _O.IP else 6)
    if observable_type in _HASH_TYPES.values():
        return _HASH_TYPES.get(len(text)) is observable_type and all(c in "0123456789abcdefABCDEF" for c in text)
    return True


def _normalized(kind: TargetKind, value: str) -> str:
    try:
        return normalize_target(kind, value)
    except ValueError:
        return value.strip()


def _id_list(value: Any) -> tuple[str, ...]:
    values = [value] if isinstance(value, str) else list(value or [])
    return tuple(dict.fromkeys(str(v) for v in values if v))


def _target_observable(kind: TargetKind, target: str) -> Observable | None:
    """The observable a target stands for in scoring (composite targets: their host or user part)."""
    head = target.split("/", 1)[0]
    simple: Mapping[TargetKind, tuple[ObservableType, str]] = {
        _T.ENDPOINT: (_O.HOSTNAME, target), _T.USER: (_O.USER, target), _T.EMAIL_ADDRESS: (_O.EMAIL_ADDRESS, target),
        _T.DOMAIN: (_O.DOMAIN, target), _T.URL: (_O.URL, target), _T.EMAIL_MESSAGE: (_O.EMAIL_MESSAGE_ID, target),
        _T.PROCESS: (_O.PROCESS, target), _T.FILE: (_O.HOSTNAME, head), _T.PERSISTENCE_ITEM: (_O.HOSTNAME, head),
        _T.ROLE_ASSIGNMENT: (_O.USER, head),
    }
    if kind in simple:
        observable_type, value = simple[kind]
    elif kind is _T.IP:
        observable_type, value = (_O.IPV6 if ":" in target else _O.IP), target
    elif kind is _T.HASH and len(target) in _HASH_TYPES:
        observable_type, value = _HASH_TYPES[len(target)], target
    else:
        return None
    try:
        return Observable(type=observable_type, value=value)
    except ValueError:
        return None


def _target_enrichments(index: RecordIndex, observable: Observable) -> list[EnrichmentRecord]:
    """Enrichment records about the target (one per answering source)."""
    return [r for r in (index.get(i) for i in index.ids())
            if isinstance(r, EnrichmentRecord) and _same(r.subject, observable)]


def _call_key(step: InvestigationStep, ctx: AtomicContext, observable: Observable) -> str:
    """Identity of one read call: atomic, subject and (for investigation) options, sources and lookback.

    Enrichment asks every enricher under the disclosure policy, so the atomic and subject identify it.
    De-duplicating keeps one run from fetching the same fact twice (with a real clock a second fetch
    would carry another ``observed_at`` and collide with the first record id).
    """
    otype, value = _observable_key(observable)
    if step.atomic.startswith("enrich_"):
        return canonical_json([step.atomic, otype.value, value]).decode("utf-8")
    return canonical_json([step.atomic, otype.value, value, dict(step.options),
                           sorted(step.integrations) if step.integrations is not None else None,
                           ctx.lookback.total_seconds()], allow_floats=True).decode("utf-8")


#: Outcomes where the source was actually called (NOT_QUERIED / NOT_SUPPORTED call nothing).
_CALLED = frozenset({SourceOutcome.ANSWERED, SourceOutcome.EMPTY, SourceOutcome.FAILED})


def _health(results: Iterable[AtomicResult]) -> dict[str, HealthStatus]:
    """Worst health per integration over the sources actually called.

    A source that was not queried (disclosure policy, not enabled) or does not support the subject
    was never called, so its ``UNKNOWN`` never hides or degrades a real answer; an integration seen
    only that way is reported ``UNKNOWN``.
    """
    worst: dict[str, HealthStatus] = {}
    uncalled: set[str] = set()
    for result in results:
        for source in result.sources:
            if source.outcome not in _CALLED:
                uncalled.add(source.integration)
                continue
            current = worst.get(source.integration)
            if current is None or _HEALTH_RANK[source.health] > _HEALTH_RANK[current]:
                worst[source.integration] = source.health
    for integration in uncalled - set(worst):
        worst[integration] = HealthStatus.UNKNOWN
    return dict(sorted(worst.items()))

