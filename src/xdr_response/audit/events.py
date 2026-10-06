"""Typed audit record payloads for every lifecycle event, and a recorder facade.

Every :class:`AuditEventType` has exactly one payload type in :data:`EVENT_PAYLOAD_TYPES`. Events
that carry a core model use it directly (payload conventions of architecture section 13.12):
``PACKAGE_PROPOSED`` a ``ContainmentPackage``, ``DECISION_RECORDED`` an ``AnalystDecision``,
``API_CALL`` an ``ApiCallSummary``, ``ACTION_RESULT`` / ``RESTORATION_RESULT`` an ``ActionResult``,
``VERIFICATION_RESULT`` a ``VerificationResult``, ``CONTROL_REGISTERED`` a ``TemporaryControl``,
``ERROR`` an ``ErrorInfo`` and so on. The others get a small frozen model defined here.

:class:`AuditRecorder` wraps any ``AuditSink`` with one method per event type, so callers never
assemble payload dicts by hand. ``TOKEN_ISSUED`` stores the token id and the claims hash, never the
signature.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType

from pydantic import AwareDatetime, BaseModel, Field

from xdr_response.interfaces import AuditSink
from xdr_response.models import (
    ActionRequest,
    ActionResult,
    AnalystDecision,
    ApiCallSummary,
    ApprovalLevel,
    ApprovalPurpose,
    ApprovalToken,
    ContainmentPackage,
    ContainmentReport,
    EnrichmentResult,
    ErrorInfo,
    Evidence,
    Incident,
    IntegrationHealth,
    InvestigationResult,
    PrincipalKind,
    ReleasePackage,
    RestorationReport,
    StateTransition,
    TemporaryControl,
    VerificationResult,
    canonical_json,
    sha256_hex,
)
from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models.audit import AuditRecord
from xdr_response.models.catalog import ActionType
from xdr_response.models.enums import AuditEventType

__all__ = [
    "IncidentReceivedPayload",
    "InvestigationCompletedPayload",
    "TokenIssuedPayload",
    "ApprovalDeniedPayload",
    "GuardDeniedPayload",
    "ActionStartedPayload",
    "RunCompletedPayload",
    "DryRunSimulationPayload",
    "EVENT_PAYLOAD_TYPES",
    "DEFAULT_ACTOR",
    "AuditRecorder",
    "payload_type_for",
]

DEFAULT_ACTOR = "automation:xdr_response"


# ------------------------------------------------------------ payloads ---
class IncidentReceivedPayload(FrozenModel):
    """``INCIDENT_RECEIVED``: the trigger and the observables it carried."""

    trigger: JsonDict
    observables: tuple[JsonDict, ...] = ()
    title: str | None = None
    severity: str | None = None
    source: str | None = None


class InvestigationCompletedPayload(FrozenModel):
    """``INVESTIGATION_COMPLETED``: per-query results and the numbered evidence."""

    results: tuple[InvestigationResult, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    evidence_snapshot_hash: str | None = None


class TokenIssuedPayload(FrozenModel):
    """``TOKEN_ISSUED``: identifies the token without the signature (a bearer secret)."""

    token_id: str
    purpose: ApprovalPurpose
    package_id: str
    decision_id: str
    claims_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    action_keys: tuple[str, ...]


class ApprovalDeniedPayload(FrozenModel):
    """``APPROVAL_DENIED``: an approval attempt the approval engine refused."""

    package_id: str | None
    principal_id: str | None
    principal_kind: PrincipalKind | None = None
    reason: str
    error_type: str | None = None


class GuardDeniedPayload(FrozenModel):
    """``GUARD_DENIED``: the execution guard refused a state-changing call."""

    reason: str
    error_type: str
    idempotency_key: str | None = None
    action_type: ActionType | None = None
    target: str | None = None


class ActionStartedPayload(FrozenModel):
    """``ACTION_STARTED``: written before an approved action is executed."""

    idempotency_key: str
    action_type: ActionType
    target: str
    integration: str | None
    approval_level: ApprovalLevel | None = None
    package_id: str | None = None
    token_id: str | None = None
    dry_run: bool = False


class RunCompletedPayload(FrozenModel):
    """``CONTAINMENT_COMPLETED`` / ``RESTORATION_COMPLETED``: the run outcome per action key."""

    report_id: str
    package_id: str
    token_id: str | None
    dry_run: bool
    overall: str | None
    started_at: AwareDatetime
    finished_at: AwareDatetime
    statuses: dict[str, str]
    attention: tuple[str, ...] = ()


class DryRunSimulationPayload(FrozenModel):
    """``DRY_RUN_SIMULATION``: what would have happened ("Would isolate: TH-LT-1047")."""

    package_id: str | None
    lines: tuple[str, ...]


EVENT_PAYLOAD_TYPES: Mapping[AuditEventType, type[BaseModel]] = MappingProxyType({
    AuditEventType.INCIDENT_RECEIVED: IncidentReceivedPayload,
    AuditEventType.INVESTIGATION_COMPLETED: InvestigationCompletedPayload,
    AuditEventType.ENRICHMENT_RESULT: EnrichmentResult,
    AuditEventType.PACKAGE_PROPOSED: ContainmentPackage,
    AuditEventType.DECISION_RECORDED: AnalystDecision,
    AuditEventType.TOKEN_ISSUED: TokenIssuedPayload,
    AuditEventType.APPROVAL_DENIED: ApprovalDeniedPayload,
    AuditEventType.GUARD_DENIED: GuardDeniedPayload,
    AuditEventType.STATE_TRANSITION: StateTransition,
    AuditEventType.ACTION_STARTED: ActionStartedPayload,
    AuditEventType.API_CALL: ApiCallSummary,
    AuditEventType.ACTION_RESULT: ActionResult,
    AuditEventType.VERIFICATION_RESULT: VerificationResult,
    AuditEventType.CONTROL_REGISTERED: TemporaryControl,
    AuditEventType.CONTAINMENT_COMPLETED: RunCompletedPayload,
    AuditEventType.RELEASE_PACKAGE_PROPOSED: ReleasePackage,
    AuditEventType.RESTORATION_RESULT: ActionResult,
    AuditEventType.RESTORATION_COMPLETED: RunCompletedPayload,
    AuditEventType.DRY_RUN_SIMULATION: DryRunSimulationPayload,
    AuditEventType.HEALTH_CHECK: IntegrationHealth,
    AuditEventType.ERROR: ErrorInfo,
})


def _run_payload(report: ContainmentReport | RestorationReport) -> RunCompletedPayload:
    overall = report.overall.value if report.overall is not None else None
    return RunCompletedPayload(
        report_id=report.report_id, package_id=report.package_id, token_id=report.token_id,
        dry_run=report.dry_run, overall=overall, started_at=report.started_at,
        finished_at=report.finished_at,
        statuses={r.idempotency_key: r.status.value for r in report.results},
        attention=report.attention)


# ------------------------------------------------------------ recorder ---
class AuditRecorder:
    """One typed method per :class:`AuditEventType`, writing to any ``AuditSink``.

    ``actor`` defaults to ``automation:xdr_response``; human-driven events (decisions, state
    transitions) use the principal recorded in the model. ``workflow_id`` / ``workflow_version``
    are defaults used when the event's own model does not carry them.
    """

    def __init__(self, sink: AuditSink, *, actor: str = DEFAULT_ACTOR,
                 workflow_id: str | None = None, workflow_version: str | None = None) -> None:
        self._sink = sink
        self._actor = actor
        self._workflow_id = workflow_id
        self._workflow_version = workflow_version

    @property
    def sink(self) -> AuditSink:
        """The underlying sink."""
        return self._sink

    def record(self, event_type: AuditEventType, payload: BaseModel, *, incident_id: str | None,
               actor: str | None = None, workflow_id: str | None = None,
               workflow_version: str | None = None) -> AuditRecord:
        """Append ``payload`` after checking it is the registered type for ``event_type``."""
        expected = EVENT_PAYLOAD_TYPES[AuditEventType(event_type)]
        if not isinstance(payload, expected):
            raise TypeError(f"{AuditEventType(event_type).value} payload must be "
                            f"{expected.__name__}, got {type(payload).__name__}")
        return self._sink.append(
            AuditEventType(event_type), incident_id=incident_id, actor=actor or self._actor,
            payload=payload.model_dump(mode="json"),
            workflow_id=workflow_id or self._workflow_id,
            workflow_version=workflow_version or self._workflow_version)

    # -------------------------------------------------------- investigation --
    def incident_received(self, incident: Incident, *, actor: str | None = None) -> AuditRecord:
        """``INCIDENT_RECEIVED`` with the trigger and observables of ``incident``."""
        payload = IncidentReceivedPayload(
            trigger=incident.trigger,
            observables=tuple(o.model_dump(mode="json") for o in incident.observables),
            title=incident.title, severity=incident.severity.value, source=incident.source)
        return self.record(AuditEventType.INCIDENT_RECEIVED, payload, incident_id=incident.incident_id,
                           actor=actor, workflow_id=incident.workflow_id,
                           workflow_version=incident.workflow_version)

    def investigation_completed(self, incident_id: str, results: Sequence[InvestigationResult], *,
                                evidence: Sequence[Evidence] = (),
                                evidence_snapshot_hash: str | None = None) -> AuditRecord:
        """``INVESTIGATION_COMPLETED`` with every query result and the numbered evidence."""
        payload = InvestigationCompletedPayload(results=tuple(results), evidence=tuple(evidence),
                                                evidence_snapshot_hash=evidence_snapshot_hash)
        return self.record(AuditEventType.INVESTIGATION_COMPLETED, payload, incident_id=incident_id)

    def enrichment_result(self, incident_id: str, result: EnrichmentResult) -> AuditRecord:
        """``ENRICHMENT_RESULT`` for one observable from one source."""
        return self.record(AuditEventType.ENRICHMENT_RESULT, result, incident_id=incident_id)

    # ------------------------------------------------------------- approval --
    def package_proposed(self, package: ContainmentPackage) -> AuditRecord:
        """``PACKAGE_PROPOSED`` with the full containment package."""
        return self.record(AuditEventType.PACKAGE_PROPOSED, package, incident_id=package.incident_id,
                           actor=package.requested_by, workflow_id=package.workflow_id,
                           workflow_version=package.workflow_version)

    def decision_recorded(self, decision: AnalystDecision) -> AuditRecord:
        """``DECISION_RECORDED``; the actor is the analyst who decided."""
        return self.record(AuditEventType.DECISION_RECORDED, decision,
                           incident_id=decision.incident_id, actor=decision.analyst_identity,
                           workflow_id=decision.workflow_id,
                           workflow_version=decision.workflow_version)

    def token_issued(self, token: ApprovalToken) -> AuditRecord:
        """``TOKEN_ISSUED`` with token id and claims hash (the signature is never recorded)."""
        claims = token.claims
        payload = TokenIssuedPayload(
            token_id=claims.token_id, purpose=claims.purpose, package_id=claims.package_id,
            decision_id=claims.decision_id, claims_hash=sha256_hex(canonical_json(claims)),
            issued_at=claims.issued_at, expires_at=claims.expires_at,
            action_keys=tuple(a.idempotency_key for a in claims.actions))
        return self.record(AuditEventType.TOKEN_ISSUED, payload, incident_id=claims.incident_id,
                           workflow_id=claims.workflow_id, workflow_version=claims.workflow_version)

    def approval_denied(self, incident_id: str | None, *, reason: str, package_id: str | None = None,
                        principal_id: str | None = None, principal_kind: PrincipalKind | None = None,
                        error: BaseException | None = None) -> AuditRecord:
        """``APPROVAL_DENIED`` for a refused approver or decision."""
        payload = ApprovalDeniedPayload(
            package_id=package_id, principal_id=principal_id, principal_kind=principal_kind,
            reason=reason, error_type=type(error).__name__ if error is not None else None)
        return self.record(AuditEventType.APPROVAL_DENIED, payload, incident_id=incident_id)

    def guard_denied(self, reason: str, request: ActionRequest | None,
                     error: BaseException) -> AuditRecord:
        """``GUARD_DENIED``; same arguments as the guard's denial hook."""
        payload = GuardDeniedPayload(
            reason=reason, error_type=type(error).__name__,
            idempotency_key=request.idempotency_key if request else None,
            action_type=request.action_type if request else None,
            target=request.target if request else None)
        return self.record(AuditEventType.GUARD_DENIED, payload,
                           incident_id=request.incident_id if request else None)

    def guard_denial_hook(self) -> Callable[[str, ActionRequest | None, Exception], None]:
        """A callable suitable for ``guard.set_denial_hook``."""
        def hook(reason: str, request: ActionRequest | None, error: Exception) -> None:
            self.guard_denied(reason, request, error)
        return hook

    # ------------------------------------------------------------ lifecycle --
    def state_transition(self, incident_id: str, transition: StateTransition) -> AuditRecord:
        """``STATE_TRANSITION``; the actor is the transition's actor."""
        return self.record(AuditEventType.STATE_TRANSITION, transition, incident_id=incident_id,
                           actor=transition.actor)

    # ------------------------------------------------------------ execution --
    def action_started(self, request: ActionRequest, *, approval_level: ApprovalLevel | None = None,
                       package_id: str | None = None, token_id: str | None = None,
                       dry_run: bool = False) -> AuditRecord:
        """``ACTION_STARTED``, written before an approved action runs."""
        integration = request.params.get("integration")
        payload = ActionStartedPayload(
            idempotency_key=request.idempotency_key, action_type=request.action_type,
            target=request.target, integration=integration if isinstance(integration, str) else None,
            approval_level=approval_level, package_id=package_id, token_id=token_id, dry_run=dry_run)
        return self.record(AuditEventType.ACTION_STARTED, payload, incident_id=request.incident_id)

    def api_call(self, incident_id: str | None, summary: ApiCallSummary) -> AuditRecord:
        """``API_CALL`` with a redacted request/response summary."""
        return self.record(AuditEventType.API_CALL, summary, incident_id=incident_id)

    def action_result(self, incident_id: str, result: ActionResult) -> AuditRecord:
        """``ACTION_RESULT`` of one containment action."""
        return self.record(AuditEventType.ACTION_RESULT, result, incident_id=incident_id)

    def verification_result(self, incident_id: str, result: VerificationResult) -> AuditRecord:
        """``VERIFICATION_RESULT`` of one action."""
        return self.record(AuditEventType.VERIFICATION_RESULT, result, incident_id=incident_id)

    def control_registered(self, control: TemporaryControl) -> AuditRecord:
        """``CONTROL_REGISTERED`` for a temporary control created by automation."""
        return self.record(AuditEventType.CONTROL_REGISTERED, control,
                           incident_id=control.incident_id, workflow_id=control.workflow_id,
                           workflow_version=control.workflow_version)

    def containment_completed(self, report: ContainmentReport) -> AuditRecord:
        """``CONTAINMENT_COMPLETED`` with the overall outcome and per-action statuses."""
        return self.record(AuditEventType.CONTAINMENT_COMPLETED, _run_payload(report),
                           incident_id=report.incident_id)

    def dry_run_simulation(self, incident_id: str, lines: Sequence[str], *,
                           package_id: str | None = None) -> AuditRecord:
        """``DRY_RUN_SIMULATION`` with the "Would ..." lines."""
        payload = DryRunSimulationPayload(package_id=package_id, lines=tuple(lines))
        return self.record(AuditEventType.DRY_RUN_SIMULATION, payload, incident_id=incident_id)

    # ---------------------------------------------------------- restoration --
    def release_package_proposed(self, package: ReleasePackage) -> AuditRecord:
        """``RELEASE_PACKAGE_PROPOSED`` with the full release package."""
        return self.record(AuditEventType.RELEASE_PACKAGE_PROPOSED, package,
                           incident_id=package.incident_id, actor=package.requested_by,
                           workflow_id=package.workflow_id,
                           workflow_version=package.workflow_version)

    def restoration_result(self, incident_id: str, result: ActionResult) -> AuditRecord:
        """``RESTORATION_RESULT`` of one release action."""
        return self.record(AuditEventType.RESTORATION_RESULT, result, incident_id=incident_id)

    def restoration_completed(self, report: RestorationReport) -> AuditRecord:
        """``RESTORATION_COMPLETED`` with the overall outcome and per-action statuses."""
        return self.record(AuditEventType.RESTORATION_COMPLETED, _run_payload(report),
                           incident_id=report.incident_id)

    # ----------------------------------------------------------- operations --
    def health_check(self, health: IntegrationHealth) -> AuditRecord:
        """``HEALTH_CHECK`` for one integration."""
        return self.record(AuditEventType.HEALTH_CHECK, health, incident_id=None)

    def error(self, incident_id: str | None, error: ErrorInfo) -> AuditRecord:
        """``ERROR`` with a (redacted) :class:`ErrorInfo`."""
        return self.record(AuditEventType.ERROR, error, incident_id=incident_id)


def payload_type_for(event_type: AuditEventType | str) -> type[BaseModel]:
    """The payload model registered for ``event_type``."""
    return EVENT_PAYLOAD_TYPES[AuditEventType(event_type)]
