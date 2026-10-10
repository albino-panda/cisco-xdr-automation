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
import re
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
from xdr_response.atomics.records import (
    AnyRecord,
    AtomicResult,
    DetectionRecord,
    EmailMessageRecord,
    EndpointRecord,
    EnrichmentRecord,
    HashPrevalenceRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
    RoleChangeRecord,
    SourceOutcome,
    UserProfileRecord,
)
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
    same_endpoint,
)
from xdr_response.models.recommendation import risk_band
from xdr_response.models.scoring import ScoreBreakdown, ScoringContext, ScoringSignal
from xdr_response.scoring.engine import ScoringEngine
from xdr_response.scoring.signals import signals_from_enrichment, signals_from_records
from xdr_response.workflows.definition import InvestigationStep, RecommendationRule, WorkflowDefinition
from xdr_response.workflows.expr import ExprError, evaluate
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks

__all__ = ["RuleOutcomeStatus", "RuleOutcome", "WorkflowRun", "WorkflowRunner"]

_O = ObservableType
_T = TargetKind
_NOTE_CHARS = 500
_SUBJECT_CHARS = 200
#: Keys a rule's ``asset`` expression may return (14.3, 14.11.6).
_ASSET_KEYS = frozenset({"groups", "tags", "roles", "ip", "ips", "users", "privileged"})
_MAX_HOOK_ITEMS = 50  # considerations or hand-offs kept per run (the rest is noted as omitted)
_MAX_CITED = 3  # record ids shown per summary line
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
    #: The file the action targets carries the signer of an approved tool (``approved_rmm`` /
    #: ``approved_dns_tools`` ``signers``) in a record of the run, or the process the action targets
    #: (``<HOST>/<pid>``) runs a binary whose SHA-256 is allow-listed (``never_block.hashes``, an
    #: approved tool's ``hashes``): not proposed, shown as considered. Also an action that rests only
    #: on sanctioned binaries (``RecommendationRule.binaries``) or only on indicators whose block the
    #: allow-list excludes (``RecommendationRule.indicators``).
    ALLOWLISTED = "ALLOWLISTED"


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
    considered: tuple[Consideration, ...] = ()  # hook items not recommended, and manual steps (14.10.1)
    handoffs: tuple[Handoff, ...] = ()  # hook hand-off suggestions, never started (14.10.1)

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
            considered=tuple(_consideration_line(c) for c in self.considered if not c.manual),
            manual_steps=tuple(_consideration_line(c) for c in self.considered if c.manual),
            handoffs=tuple(_handoff_line(h) for h in self.handoffs),
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
    considered: list[Consideration] = field(default_factory=list)
    handoffs: list[Handoff] = field(default_factory=list)
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


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _process_events(index: RecordIndex, kind: TargetKind, target: str) -> list[ProcessEventRecord]:
    """The run's process events of a ``<HOST>/<pid>`` PROCESS target that report the binary's hash."""
    if kind is not TargetKind.PROCESS:
        return []
    host, _, rest = target.partition("/")
    rest = rest.strip()
    if not rest.isdigit():
        return []
    return [r for r in index.records()
            if isinstance(r, ProcessEventRecord) and r.sha256 and r.pid is not None
            and str(r.pid) == rest and same_endpoint(str(r.endpoint), host)]


def _file_hashes(index: RecordIndex, kind: TargetKind, target: str) -> set[str]:
    """SHA-256 values of the file a HASH / FILE / PROCESS target names.

    ``<HOST>/<sha256>`` composites name the hash directly; a ``<HOST>/<pid>`` process target names the
    hashes of the run's process events of that pid on that host (short name or FQDN).
    """
    if kind is TargetKind.HASH:
        value = target.strip().lower()
        return {value} if _is_sha256(value) else set()
    if kind not in (TargetKind.FILE, TargetKind.PROCESS):
        return set()
    rest = target.partition("/")[2].strip().lower()
    if _is_sha256(rest):
        return {rest}
    return {str(r.sha256).lower() for r in _process_events(index, kind, target)}


def _executable(name: str | None) -> str:
    """Lower-case file name of a process name or path (``C:\\x\\Agent.exe`` -> ``agent.exe``)."""
    if not name:
        return ""
    return re.split(r"[\\/]", name.strip())[-1].strip().lower()


def _process_candidates(index: RecordIndex, kind: TargetKind, target: str) -> tuple[set[str], list[str], bool]:
    """``(hashes, record_ids, complete)``: every candidate binary of a ``<HOST>/<pid>`` process.

    Process ids are reused, so every process event of that pid on that host (short name or FQDN)
    counts, not only the newest. An event that reports a SHA-256 contributes it. An event that
    reports only a name and the pid (Defender timeline rows, some trajectory events) is identified by
    the run's records on the same host that name the same executable and report its SHA-256 (process
    events, detections, connections, persistence items, hash prevalence records that list the host),
    or by a connection of that pid; every such hash is a candidate. ``complete`` is False when an
    event's binary cannot be identified (a hashless event whose executable no record of the host
    reports with a hash): its binary is unknown, so the process is never treated as sanctioned.

    A caller treats the process as a sanctioned binary only when the candidates are complete and
    *all* of them are sanctioned (14.11.6, 14.11.7): one unknown build of the same name, or one
    unsanctioned binary that ran under the same pid, keeps the action proposed.
    """
    if kind is not TargetKind.PROCESS:
        return set(), [], False
    host, _, rest = target.partition("/")
    rest = rest.strip()
    if not rest.isdigit():
        return set(), [], False
    events = [r for r in index.records() if isinstance(r, ProcessEventRecord) and r.pid is not None
              and str(r.pid) == rest and same_endpoint(str(r.endpoint), host)]
    if not events:
        return set(), [], False
    hashes: dict[str, None] = {}
    ids: dict[str, None] = {r.record_id: None for r in events}
    for record in events:
        if record.sha256:
            hashes[str(record.sha256).lower()] = None
    hashless = [r for r in events if not r.sha256]
    if not hashless:
        return set(hashes), list(ids), True
    event_names = [{_executable(n) for n in (r.process_name, r.file_path)} - {""} for r in hashless]
    names = set().union(*event_names)
    unnamed = any(not n for n in event_names)
    found_names: set[str] = set()
    pid_hash = False
    for record in index.records():
        sha: str | None = None
        on_host = False
        record_names: tuple[str | None, ...] = ()
        same_pid = False
        if isinstance(record, ProcessEventRecord):
            sha, record_names = record.sha256, (record.process_name, record.file_path)
            on_host = same_endpoint(str(record.endpoint), host)
        elif isinstance(record, DetectionRecord):
            sha, record_names = record.sha256, (record.process_name, record.file_path)
            on_host = bool(record.endpoint) and same_endpoint(str(record.endpoint), host)
        elif isinstance(record, NetworkConnectionRecord):
            sha, record_names = record.sha256, (record.process_name,)
            on_host = bool(record.endpoint) and same_endpoint(str(record.endpoint), host)
            same_pid = record.pid is not None and str(record.pid) == rest
        elif isinstance(record, PersistenceItemRecord):
            sha, record_names = record.sha256, (record.path, record.name)
            on_host = same_endpoint(str(record.endpoint), host)
        elif isinstance(record, HashPrevalenceRecord):
            sha, record_names = record.sha256, (record.file_name,)
            on_host = any(same_endpoint(str(e), host) for e in record.endpoints)
        if not sha or not on_host:
            continue
        matched = names & {_executable(n) for n in record_names}
        if same_pid or matched:
            hashes[str(sha).lower()] = None
            ids[record.record_id] = None
            found_names |= matched
            pid_hash = pid_hash or same_pid
    identified = all((n & found_names) or pid_hash for n in event_names if n)
    complete = bool(hashes) and identified and (not unnamed or pid_hash)
    return set(hashes), list(ids), complete


def _sanctioned(state: _Run, hashes: Iterable[str]) -> tuple[list[str], list[str]] | None:
    """``(reasons, record_ids)`` when *every* hash is a sanctioned binary, else ``None``.

    Sanctioned: the hash is in ``never_block.hashes`` or is an approved tool's hash
    (``approved_rmm`` / ``approved_dns_tools``), or a hash prevalence record of the run reports it
    signed by an approved tool's signer. An empty set, or one value that is not a SHA-256 or not
    sanctioned, is never sanctioned (nothing is withheld on a guess).
    """
    wanted = [str(h).strip().lower() for h in hashes]
    if not wanted:
        return None
    allowlists = state.ctx.allowlists
    reasons: dict[str, None] = {}
    record_ids: dict[str, None] = {}
    for sha in wanted:
        if not _is_sha256(sha):
            return None
        reason = allowlists.hash_reason(sha)
        if reason:
            reasons[reason] = None
            continue
        signed = [r for r in state.index.records() if isinstance(r, HashPrevalenceRecord)
                  and r.sha256.lower() == sha and r.signer and allowlists.signer_reason(r.signer)]
        if not signed:
            return None
        for record in signed:
            reasons[str(allowlists.signer_reason(record.signer))] = None
            record_ids[record.record_id] = None
    return list(reasons), list(record_ids)


_ENDPOINT_TARGETS = frozenset({TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM})


def _record_users(index: RecordIndex, kind: TargetKind, target: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(users, record_ids)``: who uses the asset a target acts on, as the run's records report it.

    An endpoint (or a file, process or persistence item on it): the users of its endpoint records
    (matched by host identity, short name or FQDN). An email message: the recipients of its message
    records (matched by message id, internet message id or network message id), whose mailboxes the
    action changes. Used only to add critical-asset context (an executive's endpoint or mailbox is
    ELEVATED), never to remove any.
    """
    users: dict[str, None] = {}
    ids: dict[str, None] = {}
    if kind in _ENDPOINT_TARGETS:
        host = target.partition("/")[0] if kind is not TargetKind.ENDPOINT else target
        for record in index.records():
            if isinstance(record, EndpointRecord) and record.users and same_endpoint(str(record.hostname), host):
                users.update(dict.fromkeys(str(u).lower() for u in record.users))
                ids[record.record_id] = None
    elif kind is TargetKind.EMAIL_MESSAGE:
        wanted = target.strip()
        for record in index.records():
            if isinstance(record, EmailMessageRecord) and record.recipients and wanted in {
                    record.message_id, record.internet_message_id, record.network_message_id}:
                users.update(dict.fromkeys(str(u).lower() for u in record.recipients))
                ids[record.record_id] = None
    return tuple(users), tuple(ids)


def _record_addresses(index: RecordIndex, kind: TargetKind, target: str) -> tuple[str, ...]:
    """Every IP address the run's endpoint records report for the host an endpoint action acts on
    (matched by host identity, short name or FQDN), in record order. Context only, never removes."""
    if kind not in _ENDPOINT_TARGETS:
        return ()
    host = target.partition("/")[0] if kind is not TargetKind.ENDPOINT else target
    out: dict[str, None] = {}
    for record in index.records():
        if isinstance(record, EndpointRecord) and record.ip_addresses and same_endpoint(str(record.hostname), host):
            out.update(dict.fromkeys(str(a) for a in record.ip_addresses))
    return tuple(out)


def _record_endpoint_labels(index: RecordIndex, kind: TargetKind,
                            target: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(groups, tags)`` every endpoint record of the run reports for the host an endpoint action acts
    on, matched by host identity (``same_endpoint``: short name or FQDN, any case), in record order.
    Two sources can spell one host differently (``TH-LT-1047`` with the connector, its DNS name with
    the ``Domain Controllers`` group or the ``production`` tag): the critical context of either
    spelling applies to the host (14.13.3). Context only, never removes."""
    if kind not in _ENDPOINT_TARGETS:
        return (), ()
    host = target.partition("/")[0] if kind is not TargetKind.ENDPOINT else target
    groups: dict[str, None] = {}
    tags: dict[str, None] = {}
    for record in index.records():
        if isinstance(record, EndpointRecord) and (record.groups or record.tags)                 and same_endpoint(str(record.hostname), host):
            groups.update(dict.fromkeys(str(g) for g in record.groups))
            tags.update(dict.fromkeys(str(t) for t in record.tags))
    return tuple(groups), tuple(tags)


#: Role changes after which the account holds (or can activate at will) the role.
_ROLE_GAINED = frozenset({"assigned", "activated", "eligible_assigned"})


def _record_privileged(index: RecordIndex, kind: TargetKind, target: str) -> bool:
    """True when a record of the run reports that the account an action acts on is privileged.

    A user profile record marks it (``UserProfileRecord.privileged``: the source's flag, or a listed
    privileged directory role), or a role change record reports that the account was assigned,
    activated or made eligible for a privileged role (``RoleChangeRecord.privileged``, 14.11.7). The
    profile can predate a role granted during the incident; a later removal does not undo it here
    (context is only ever added: the action is ELEVATED, never weaker).
    """
    if kind not in (TargetKind.USER, TargetKind.EMAIL_ADDRESS):
        return False
    wanted = target.strip().lower()
    for record in index.records():
        if isinstance(record, UserProfileRecord) and record.privileged and str(record.user).lower() == wanted:
            return True
        if (isinstance(record, RoleChangeRecord) and record.privileged and record.change in _ROLE_GAINED
                and str(record.user).lower() == wanted):
            return True
    return False


def _record_directory(index: RecordIndex, kind: TargetKind, target: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(groups, roles)`` the run's user profile records report for the account an action acts on.

    Context only, never removes: an account in a critical group (``Executives``, ``Service Accounts``,
    ``Domain Admins`` ...) or holding a critical role is then classified by the critical-asset policy
    whatever the rule's asset expression says (14.13.6).
    """
    if kind not in (TargetKind.USER, TargetKind.EMAIL_ADDRESS):
        return (), ()
    wanted = target.strip().lower()
    groups: dict[str, None] = {}
    roles: dict[str, None] = {}
    for record in index.records():
        if isinstance(record, UserProfileRecord) and str(record.user).lower() == wanted:
            groups.update(dict.fromkeys(str(g) for g in record.groups if str(g).strip()))
            roles.update(dict.fromkeys(str(r) for r in record.roles if str(r).strip()))
    return tuple(groups), tuple(roles)


def _indicator_entry(value: Any) -> tuple[ActionType, TargetKind, str] | None:
    """``(block action, target kind, target)`` of one ``RecommendationRule.indicators`` entry
    (``"<block action>:<target>"``), else None."""
    if not isinstance(value, str):
        return None
    action_text, sep, target = value.partition(":")
    if not sep or not target.strip():
        return None
    try:
        action = ActionType(action_text.strip())
    except ValueError:
        return None
    return action, get_action_spec(action).target_kind, target.strip()


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
        state.considered = self._valid_considerations(state, view)
        state.handoffs = self._valid_handoffs(state, view)

    @staticmethod
    def _hook_items(state: _Run, items_of: Any, view: RunView, method: str, kind: type) -> list[Any]:
        """The hook's items of ``kind`` (an exception or a wrong type is noted and ignored)."""
        try:
            items = list(items_of(view) or ())
        except Exception as exc:  # noqa: BLE001 - hooks never crash a run
            state.note(f"hook {method} failed: {_error_text(exc)}")
            return []
        valid = []
        for item in items:
            if not isinstance(item, kind):
                state.note(f"hook {method} item ignored: not a {kind.__name__} ({type(item).__name__})")
            else:
                valid.append(item)
        if len(valid) > _MAX_HOOK_ITEMS:
            state.note(f"hook {method}: {len(valid) - _MAX_HOOK_ITEMS} item(s) omitted (max {_MAX_HOOK_ITEMS})")
            valid = valid[:_MAX_HOOK_ITEMS]
        return valid

    @staticmethod
    def _cited_problem(state: _Run, record_ids: object) -> str:
        if not isinstance(record_ids, tuple) or not record_ids or not all(isinstance(r, str) for r in record_ids):
            return "needs a non-empty tuple of record ids"
        try:
            state.index.require(record_ids)
        except EvidenceError as exc:
            return str(exc)
        return ""

    def _valid_considerations(self, state: _Run, view: RunView) -> list[Consideration]:
        redactor = get_redactor()
        kept: dict[tuple[str, bool], Consideration] = {}
        items = self._hook_items(state, state.hooks.considered, view,  # type: ignore[union-attr]
                                 "considered", Consideration)
        for item in items:
            subject, reason = _one_line(item.subject), _one_line(item.reason)
            problem = self._cited_problem(state, item.record_ids)
            if not subject or not reason:
                problem = problem or "needs a subject and a reason"
            if problem:
                state.note(f"hook consideration ignored ({subject or '?'}): {problem}")
                continue
            clean = Consideration(subject=redactor.redact_text(subject)[:_SUBJECT_CHARS],
                                  reason=redactor.redact_text(reason)[:_NOTE_CHARS],
                                  record_ids=tuple(dict.fromkeys(item.record_ids)), manual=bool(item.manual))
            key = (clean.subject, clean.manual)
            first = kept.get(key)
            if first is not None:  # the same subject twice: one entry, the first reason, both records
                clean = replace(first, record_ids=tuple(dict.fromkeys((*first.record_ids, *clean.record_ids))))
            kept[key] = clean
        for item in kept.values():
            label = "manual step" if item.manual else "considered, not proposed"
            state.note(f"{label}: {item.subject}: {item.reason}")
        return list(kept.values())

    def _valid_handoffs(self, state: _Run, view: RunView) -> list[Handoff]:
        redactor = get_redactor()
        allowed = state.workflow.handoff_to
        kept: dict[str, Handoff] = {}
        items = self._hook_items(state, state.hooks.handoffs, view, "handoffs", Handoff)  # type: ignore[union-attr]
        for item in items:
            raw = item.subjects if isinstance(item.subjects, tuple) else ()
            subjects = tuple(dict.fromkeys(_one_line(s) for s in raw if _one_line(s)))
            reason = _one_line(item.reason)
            problem = self._cited_problem(state, item.record_ids)
            if item.workflow_id not in allowed:
                problem = f"{item.workflow_id!r} is not in handoff_to {list(allowed)}"
            elif not subjects or not reason:
                problem = problem or "needs subjects and a reason"
            if problem:
                state.note(f"hook hand-off ignored: {problem}")
                continue
            clean = Handoff(workflow_id=item.workflow_id,
                            subjects=tuple(redactor.redact_text(s)[:_SUBJECT_CHARS] for s in subjects),
                            reason=redactor.redact_text(reason)[:_NOTE_CHARS],
                            record_ids=tuple(dict.fromkeys(item.record_ids)))
            first = kept.get(clean.workflow_id)
            if first is not None:  # one hand-off per workflow: the first reason, subjects and records unioned
                clean = replace(first, subjects=tuple(dict.fromkeys((*first.subjects, *clean.subjects))),
                                record_ids=tuple(dict.fromkeys((*first.record_ids, *clean.record_ids))))
            kept[clean.workflow_id] = clean
        for item in kept.values():
            state.note(f"hand-off: run {item.workflow_id} for {', '.join(item.subjects)}: {item.reason} "
                       "(suggestion only; nothing is started)")
        return list(kept.values())

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
        self._approved_signer(state, rule, scored)
        self._allowlisted_binary(state, rule, scored)
        self._sanctioned_binaries(state, rule, scored, names)
        self._allowlisted_indicators(state, rule, scored, names)
        if breakdown.risk_score < rule.min_risk or breakdown.confidence_score < rule.min_confidence:
            raise _RuleFailure(RuleOutcomeStatus.BELOW_THRESHOLD,
                               f"risk {breakdown.risk_score} (min {rule.min_risk}), confidence "
                               f"{breakdown.confidence_score} (min {rule.min_confidence}): considered, not proposed",
                               target=scored.target, record_ids=scored.rule_ids, breakdown=breakdown)
        built = self._build(state, rule, names, scored)
        self._accept(state, rule, built, scored)

    @staticmethod
    def _approved_signer(state: _Run, rule: RecommendationRule, scored: _Scored) -> None:
        """Withhold a file action (hash block, quarantine, terminate) whose file a record of the run
        reports as signed by an approved tool's signer (``approved_rmm`` / ``approved_dns_tools``
        ``signers``). A new build of a sanctioned tool is identified by its signer before its hash is
        listed. The action is not proposed; it is shown as considered (subject, reason, the records
        that report the signer) and as an ``ALLOWLISTED`` outcome, never silently dropped."""
        if scored.kind is TargetKind.PROCESS:
            return  # every binary of the pid must be sanctioned: _allowlisted_binary (14.11.7)
        hashes = _file_hashes(state.index, scored.kind, scored.target)
        if not hashes:
            return
        reasons: list[str] = []
        record_ids: list[str] = []
        signed: set[str] = set()
        for record in state.index.records():
            if not isinstance(record, HashPrevalenceRecord):
                continue  # the record kind that reports a file's code-signing subject
            signer = record.signer
            if not signer or record.sha256.lower() not in hashes:
                continue
            reason = state.ctx.allowlists.signer_reason(signer)
            if reason:
                reasons.append(reason)
                record_ids.append(record.record_id)
                signed.add(record.sha256.lower())
        if not reasons or signed != hashes:
            return  # every file the target names must be signed by an approved signer
        detail = (f"file {', '.join(sorted(hashes))} is signed by an approved tool's signer ({'; '.join(dict.fromkeys(reasons))}): "
                  "allow-listed, not proposed")
        subject = f"{rule.action.value}:{scored.target}"
        if not any(c.subject == subject for c in state.considered):
            redactor = get_redactor()
            state.considered.append(Consideration(
                subject=redactor.redact_text(subject)[:_SUBJECT_CHARS], reason=redactor.redact_text(detail)[:_NOTE_CHARS],
                record_ids=tuple(dict.fromkeys(record_ids))))
        raise _RuleFailure(RuleOutcomeStatus.ALLOWLISTED, detail, target=scored.target,
                           record_ids=tuple(dict.fromkeys([*scored.rule_ids, *record_ids])),
                           breakdown=scored.breakdown)

    @staticmethod
    def _allowlisted_binary(state: _Run, rule: RecommendationRule, scored: _Scored) -> None:
        """Withhold an action on a running process (``<HOST>/<pid>``) whose binary is sanctioned.

        The allow-list sees only the pid in the target, so the binary comes from the run's process
        events of that pid on that host (:func:`_process_candidates`): the hash each event reports,
        or, for an event that reports only a name, the hashes the host's other records give for the
        same executable. Process ids are reused, so every event of the pid counts. The termination is
        withheld only when the candidates are complete and **every** candidate is sanctioned
        (:func:`_sanctioned`: in ``never_block.hashes``, an approved tool's hash, or an approved
        signer on a prevalence record of that hash); terminating it would kill the sanctioned tool.
        It is then shown as considered (subject, reason, the records) and as an ``ALLOWLISTED``
        outcome, never silently dropped. One unknown or unsanctioned binary under the same pid keeps
        the action proposed (14.11.6, 14.11.7).
        """
        if state.ctx.allowlists.excluded_reason(rule.action, scored.target, scored.kind):
            return  # the allow-list already excludes the target itself (shown in excluded_targets)
        hashes, ids, complete = _process_candidates(state.index, scored.kind, scored.target)
        if not complete:
            return
        sanctioned = _sanctioned(state, hashes)
        if sanctioned is None:
            return
        reasons, signer_ids = sanctioned
        record_ids = list(dict.fromkeys([*ids, *signer_ids]))
        inferred = ""
        if not _process_events(state.index, scored.kind, scored.target):
            inferred = (f" (the process events report no hash; the host's records name the same executable "
                        f"with {', '.join(sorted(hashes))})")
        detail = (f"process {scored.target} runs an allow-listed binary ({'; '.join(reasons)}){inferred}: "
                  "allow-listed, not proposed")
        subject = f"{rule.action.value}:{scored.target}"
        if not any(c.subject == subject for c in state.considered):
            redactor = get_redactor()
            state.considered.append(Consideration(
                subject=redactor.redact_text(subject)[:_SUBJECT_CHARS],
                reason=redactor.redact_text(detail)[:_NOTE_CHARS], record_ids=tuple(record_ids)))
        raise _RuleFailure(RuleOutcomeStatus.ALLOWLISTED, detail, target=scored.target,
                           record_ids=tuple(dict.fromkeys([*scored.rule_ids, *record_ids])),
                           breakdown=scored.breakdown)

    def _sanctioned_binaries(self, state: _Run, rule: RecommendationRule, scored: _Scored,
                             names: Mapping[str, Any]) -> None:
        """Withhold an action that rests only on binaries that are sanctioned (``rule.binaries``).

        A rule whose case is the behaviour of a tool (a relay domain block because the tool is
        flagged) names the tool's SHA-256 values in ``binaries``. When every one is sanctioned (an
        allow-listed or approved-tool hash, or a file a record of the run reports signed by an
        approved signer: :func:`_sanctioned`), the action would cut the sanctioned tool everywhere: it
        is not proposed, shown as considered and as an ``ALLOWLISTED`` outcome, never silently
        dropped. A rule passes ``[]`` when the target stands on its own evidence (a rated
        destination); a target the allow-list already excludes is left to ``PackageBuilder``.
        """
        if rule.binaries is None:
            return
        if state.ctx.allowlists.excluded_reason(rule.action, scored.target, scored.kind):
            return
        value = self._expr(rule.binaries, names, "binaries")
        if value is None:
            return
        if isinstance(value, (str, Mapping)) or not isinstance(value, Iterable):
            raise _RuleFailure(RuleOutcomeStatus.ERROR, f"binaries: must give a list, got {type(value).__name__}")
        values = list(value)
        hashes = [str(v) for v in values if v]
        # a binary without a hash (a tool known only by name) can never be shown to be sanctioned
        sanctioned = _sanctioned(state, hashes) if len(hashes) == len(values) else None
        if sanctioned is None:
            return
        reasons, record_ids = sanctioned
        detail = (f"{rule.action.value} {scored.target} rests only on sanctioned binaries "
                  f"({', '.join(sorted({h.lower() for h in hashes}))}: {'; '.join(reasons)}): allow-listed, not proposed")
        subject = f"{rule.action.value}:{scored.target}"
        if not any(c.subject == subject for c in state.considered):
            redactor = get_redactor()
            state.considered.append(Consideration(
                subject=redactor.redact_text(subject)[:_SUBJECT_CHARS],
                reason=redactor.redact_text(detail)[:_NOTE_CHARS],
                record_ids=tuple(dict.fromkeys([*scored.rule_ids, *record_ids]))))
        raise _RuleFailure(RuleOutcomeStatus.ALLOWLISTED, detail, target=scored.target,
                           record_ids=tuple(dict.fromkeys([*scored.rule_ids, *record_ids])),
                           breakdown=scored.breakdown)

    def _allowlisted_indicators(self, state: _Run, rule: RecommendationRule, scored: _Scored,
                                names: Mapping[str, Any]) -> None:
        """Withhold an action that rests only on indicators the allow-list excludes (``rule.indicators``).

        A rule whose case is "the asset met an indicator" (an account revoked because it signed in
        from a rated IP) names those indicators as ``<block action>:<target>`` entries. When the
        allow-list excludes the block of **every** one (``never_block`` IPs, CIDRs, domains, URLs or
        hashes, an approved tool, a non-public address or an internal domain), the action would rest
        only on the organisation's own infrastructure and would hit every user behind it: it is not
        proposed, shown as considered and as an ``ALLOWLISTED`` outcome, never silently dropped. One
        indicator that is not excluded keeps the action proposed. ``[]`` (or None) when the target
        stands on its own evidence; a target the allow-list already excludes is left to
        ``PackageBuilder`` (14.13.6).
        """
        if rule.indicators is None:
            return
        allowlists = state.ctx.allowlists
        if allowlists.excluded_reason(rule.action, scored.target, scored.kind):
            return
        value = self._expr(rule.indicators, names, "indicators")
        if value is None:
            return
        if isinstance(value, (str, Mapping)) or not isinstance(value, Iterable):
            raise _RuleFailure(RuleOutcomeStatus.ERROR, f"indicators: must give a list, got {type(value).__name__}")
        entries = list(value)
        if not entries:
            return
        reasons: dict[str, None] = {}
        for raw in entries:
            entry = _indicator_entry(raw)
            if entry is None:
                raise _RuleFailure(RuleOutcomeStatus.ERROR,
                                   "indicators: every entry must be '<block action>:<target>'")
            action, kind, target = entry
            try:
                normalized = _normalized(kind, target)
            except ValueError:
                return  # an indicator that cannot be normalized is never shown to be allow-listed
            reason = allowlists.excluded_reason(action, normalized, kind)
            if not reason:
                return
            reasons[f"{action.value}:{normalized}: {reason}"] = None
        detail = (f"{rule.action.value} {scored.target} rests only on allow-listed indicators "
                  f"({'; '.join(reasons)}): allow-listed, not proposed")
        subject = f"{rule.action.value}:{scored.target}"
        if not any(c.subject == subject for c in state.considered):
            redactor = get_redactor()
            state.considered.append(Consideration(
                subject=redactor.redact_text(subject)[:_SUBJECT_CHARS],
                reason=redactor.redact_text(detail)[:_NOTE_CHARS], record_ids=tuple(scored.rule_ids)))
        raise _RuleFailure(RuleOutcomeStatus.ALLOWLISTED, detail, target=scored.target,
                           record_ids=scored.rule_ids, breakdown=scored.breakdown)

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
        asset = self._record_asset(state, target, kind, self._asset(rule, names, target, kind))
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
        if not isinstance(value, Mapping) or set(value) - _ASSET_KEYS:
            raise _RuleFailure(RuleOutcomeStatus.ERROR,
                               "asset: must be a mapping of groups, tags, roles, ip, ips, users, privileged")
        try:
            return Asset(name=target, kind=kind, groups=tuple(value.get("groups") or ()),
                         tags=tuple(value.get("tags") or ()), roles=tuple(value.get("roles") or ()),
                         ip=value.get("ip") or None, ips=tuple(a for a in value.get("ips") or () if a),
                         users=tuple(value.get("users") or ()), privileged=value.get("privileged") is True)
        except ValueError as exc:
            raise _RuleFailure(RuleOutcomeStatus.ERROR, f"asset: {exc}") from None

    @staticmethod
    def _record_asset(state: _Run, target: str, kind: TargetKind, asset: Asset | None) -> Asset | None:
        """The rule's asset context plus what the run's records report about the target.

        Framework-level, for every workflow: the users of the endpoint an action contains (endpoint
        records) and the recipients of the message an action quarantines or deletes (message
        records); every address of the endpoint (all ``ip_addresses`` of its endpoint records, not
        only the first: a production address on a second interface counts); and, for an account,
        the identity source's ``privileged`` flag, groups and roles (user profile records); for an
        endpoint action, the groups and tags of every endpoint record of the same host under any
        spelling (``same_endpoint``: short name or FQDN). An
        executive's endpoint or mailbox, a host with a critical address, an account the source marks
        privileged and an account in a critical group (``Executives``, ``Service Accounts``, ``Domain
        Admins``) are then ELEVATED with a warning whatever the rule's asset expression says. Context
        is only ever added.
        """
        users, _ids = _record_users(state.index, kind, target)
        addresses = _record_addresses(state.index, kind, target)
        privileged = _record_privileged(state.index, kind, target)
        groups, roles = _record_directory(state.index, kind, target)
        host_groups, tags = _record_endpoint_labels(state.index, kind, target)
        groups = tuple(dict.fromkeys((*groups, *host_groups)))
        if not users and not addresses and not privileged and not groups and not roles and not tags:
            return asset
        try:
            found = Asset(name=target, kind=kind, users=users, ip=addresses[0] if addresses else None,
                          ips=addresses[1:], privileged=privileged, groups=groups, roles=roles, tags=tags)
        except ValueError:
            return asset
        return _merge_assets(asset, found)

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
        elif failure.status is RuleOutcomeStatus.ALLOWLISTED:
            state.note(f"considered, not proposed: {label}: {failure.detail}")
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
            risk_score=risk, confidence_score=confidence, health=health, notes=tuple(state.notes),
            considered=tuple(state.considered), handoffs=tuple(state.handoffs))


# ------------------------------------------------------------ pure helpers --
def _one_line(text: object) -> str:
    return " ".join(text.split()) if isinstance(text, str) else ""


def _cited(record_ids: Sequence[str]) -> str:
    shown = ", ".join(record_ids[:_MAX_CITED])
    more = f" +{len(record_ids) - _MAX_CITED}" if len(record_ids) > _MAX_CITED else ""
    return f"[{shown}{more}]"


def _consideration_line(item: Consideration) -> str:
    """``"<subject>: <reason> [rec_...]"`` (workflow summary)."""
    return f"{item.subject}: {item.reason} {_cited(item.record_ids)}"


def _handoff_line(item: Handoff) -> str:
    """``"<workflow> for <subjects>: <reason> [rec_...]"`` (workflow summary)."""
    return f"{item.workflow_id} for {', '.join(item.subjects)}: {item.reason} {_cited(item.record_ids)}"


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

