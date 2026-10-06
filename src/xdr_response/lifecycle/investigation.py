"""Automatic investigation and enrichment (the first lifecycle step after detection).

:class:`InvestigationService` asks every enabled adapter that can enrich an observable type (and
every adapter serving the configured investigation queries) about each incident observable. It only
calls read methods (``enrich`` / ``investigate``), which never need an approval token.

Failure isolation: an error from one source becomes an ``EnrichmentResult`` / ``InvestigationResult``
with verdict ``UNKNOWN``, the classified health status and a redacted :class:`ErrorInfo`. It never
stops the other sources, so a recommendation backed by other evidence is still produced.

Every enrichment result is audited (``ENRICHMENT_RESULT``) and the run ends with one
``INVESTIGATION_COMPLETED`` record carrying the numbered evidence and its snapshot hash.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from types import MappingProxyType

from pydantic import ValidationError

from xdr_response.audit.events import AuditRecorder
from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.errors import AuditError, IntegrationError
from xdr_response.integrations.health import classify_exception
from xdr_response.interfaces import AuditSink
from xdr_response.logs.redaction import get_redactor
from xdr_response.logs.setup import get_logger
from xdr_response.models import (
    ActionType,
    EnrichmentResult,
    ErrorCode,
    ErrorInfo,
    Evidence,
    EvidenceDraft,
    HealthStatus,
    Incident,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    ObservableType,
    Verdict,
    evidence_snapshot_hash,
    number_evidence,
)

__all__ = [
    "DEFAULT_INVESTIGATIONS",
    "InvestigationReport",
    "InvestigationService",
    "INVESTIGATION_ACTOR",
    "observable_key",
]

INVESTIGATION_ACTOR = "automation:investigation"
_log = get_logger("lifecycle.investigation")

_O = ObservableType
_A = ActionType

#: Investigation queries run per observable type (read-only; adapters that do not serve a query
#: are simply not asked).
DEFAULT_INVESTIGATIONS: Mapping[ObservableType, tuple[ActionType, ...]] = MappingProxyType({
    _O.HOSTNAME: (_A.INVESTIGATE_ENDPOINT,),
    _O.USER: (_A.INVESTIGATE_USER, _A.INVESTIGATE_AUTHENTICATION),
    _O.EMAIL_MESSAGE_ID: (_A.INVESTIGATE_EMAIL,),
    _O.SHA256: (_A.SEARCH_HASH_ENTERPRISE,),
    _O.DOMAIN: (_A.SEARCH_DOMAIN_ENTERPRISE,),
    _O.IP: (_A.SEARCH_IP_ENTERPRISE,),
})


def observable_key(observable: Observable) -> tuple[ObservableType, str]:
    """Identity of an observable for de-duplication and lookups (type, trimmed lower-case value)."""
    return observable.type, observable.value.strip().lower()


@dataclass(frozen=True)
class InvestigationReport:
    """Everything the read-only investigation learned about one incident."""

    incident_id: str
    enrichments: tuple[EnrichmentResult, ...] = ()
    investigations: tuple[InvestigationResult, ...] = ()
    health: Mapping[str, HealthStatus] = field(default_factory=dict)

    @property
    def errors(self) -> tuple[ErrorInfo, ...]:
        return tuple(e for r in (*self.enrichments, *self.investigations) for e in r.errors)

    @property
    def evidence_drafts(self) -> tuple[EvidenceDraft, ...]:
        return tuple(d for r in (*self.enrichments, *self.investigations) for d in r.evidence)

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        return number_evidence(self.evidence_drafts)

    def enrichments_for(self, observable: Observable) -> list[EnrichmentResult]:
        key = observable_key(observable)
        return [r for r in self.enrichments if (r.type, r.value.strip().lower()) == key]

    def investigations_for(self, observable: Observable) -> list[InvestigationResult]:
        key = observable_key(observable)
        return [r for r in self.investigations if observable_key(r.subject) == key]

    @property
    def degraded_sources(self) -> tuple[str, ...]:
        """Integrations whose health was not CONNECTED during this investigation."""
        return tuple(sorted(n for n, s in self.health.items() if s is not HealthStatus.CONNECTED))


class InvestigationService:
    """Runs read-only enrichment and investigation for an incident through the adapter registry."""

    def __init__(self, adapters: object, *, audit: AuditSink | None = None, clock: Clock | None = None,
                 investigations: Mapping[ObservableType, Sequence[ActionType]] = DEFAULT_INVESTIGATIONS,
                 enrichment_sources: Mapping[ObservableType, Sequence[str]] | None = None,
                 lookback: timedelta = timedelta(hours=24),
                 query_options: Callable[[ActionType, Observable], Mapping[str, object]] | None = None) -> None:
        """``adapters`` is an ``AdapterRegistry`` (``for_observable`` / ``for_action``).

        ``enrichment_sources`` optionally restricts which integrations enrich a type.
        ``query_options`` may add adapter-specific ``InvestigationQuery.options``.
        """
        self._adapters = adapters
        self._audit = AuditRecorder(audit, actor=INVESTIGATION_ACTOR) if audit is not None else None
        self._clock: Clock = clock or DEFAULT_CLOCK
        self._investigations = dict(investigations)
        self._sources = dict(enrichment_sources or {})
        self._lookback = lookback
        self._query_options = query_options
        self._redactor = get_redactor()

    # ------------------------------------------------------------------ API --
    def run(self, incident: Incident) -> InvestigationReport:
        """Enrich and investigate every distinct observable of ``incident``. Never raises for a source."""
        observables = self._distinct(incident.observables)
        health: dict[str, HealthStatus] = {}
        enrichments: list[EnrichmentResult] = []
        investigations: list[InvestigationResult] = []
        for observable in observables:
            for result in self._enrich(observable, health):
                enrichments.append(result)
                self._audit_enrichment(incident, result)
            investigations.extend(self._investigate(incident, observable, health))
        report = InvestigationReport(incident_id=incident.incident_id, enrichments=tuple(enrichments),
                                     investigations=tuple(investigations), health=dict(health))
        self._audit_completed(incident, report)
        return report

    # ------------------------------------------------------------ enrichment --
    @staticmethod
    def _distinct(observables: Iterable[Observable]) -> list[Observable]:
        seen: set[tuple[ObservableType, str]] = set()
        out: list[Observable] = []
        for observable in observables:
            key = observable_key(observable)
            if key not in seen:
                seen.add(key)
                out.append(observable)
        return out

    def _enrichers(self, observable_type: ObservableType) -> list[object]:
        adapters = list(self._adapters.for_observable(observable_type))  # type: ignore[attr-defined]
        allowed = self._sources.get(observable_type)
        if allowed is not None:
            adapters = [a for a in adapters if getattr(a, "name", None) in set(allowed)]
        return adapters

    def _enrich(self, observable: Observable, health: dict[str, HealthStatus]) -> list[EnrichmentResult]:
        results: list[EnrichmentResult] = []
        for adapter in self._enrichers(observable.type):
            name = str(getattr(adapter, "name", "unknown"))
            try:
                result = adapter.enrich(observable)  # type: ignore[attr-defined]
                if not isinstance(result, EnrichmentResult):
                    raise TypeError("adapter returned no EnrichmentResult")
            except Exception as exc:  # noqa: BLE001 - one failing source never blocks the others
                status = classify_exception(exc)
                result = EnrichmentResult(
                    type=observable.type, value=observable.value, risk_score=0, confidence=0,
                    sources=(name,), verdict=Verdict.UNKNOWN, integration=name, health=status,
                    errors=(self._error(exc, name),))
            health[name] = _worst(health.get(name), result.health)
            results.append(result)
        return results

    # --------------------------------------------------------- investigation --
    def _investigate(self, incident: Incident, observable: Observable,
                     health: dict[str, HealthStatus]) -> list[InvestigationResult]:
        out: list[InvestigationResult] = []
        now = self._clock.now()
        for action_type in self._investigations.get(observable.type, ()):
            options = dict(self._query_options(action_type, observable)) if self._query_options else {}
            try:
                query = InvestigationQuery(action_type=action_type, subject=observable,
                                           time_from=min(incident.created_at, now) - self._lookback,
                                           time_to=now, options=options)
            except ValidationError:
                continue
            for adapter in self._adapters.for_action(action_type):  # type: ignore[attr-defined]
                name = str(getattr(adapter, "name", "unknown"))
                try:
                    result = adapter.investigate(query)
                    if not isinstance(result, InvestigationResult):
                        raise TypeError("adapter returned no InvestigationResult")
                except Exception as exc:  # noqa: BLE001 - failure isolation per source
                    result = InvestigationResult(integration=name, action_type=action_type, subject=observable,
                                                 health=classify_exception(exc), errors=(self._error(exc, name),))
                health[name] = _worst(health.get(name), result.health)
                out.append(result)
        return out

    # ----------------------------------------------------------------- audit --
    def _error(self, exc: BaseException, integration: str) -> ErrorInfo:
        if isinstance(exc, IntegrationError):
            return exc.to_error_info()
        return ErrorInfo(code=ErrorCode.INTERNAL, integration=integration,
                         message=self._redactor.redact_text(f"{type(exc).__name__}: {exc}")[:500])

    def _audit_enrichment(self, incident: Incident, result: EnrichmentResult) -> None:
        if self._audit is None:
            return
        try:
            self._audit.enrichment_result(incident.incident_id, result)
        except (AuditError, OSError) as exc:  # read-only step: log loudly, keep investigating
            _log.error("ENRICHMENT_RESULT audit failed for %s: %s", incident.incident_id, type(exc).__name__)

    def _audit_completed(self, incident: Incident, report: InvestigationReport) -> None:
        if self._audit is None:
            return
        evidence = report.evidence
        try:
            self._audit.investigation_completed(
                incident.incident_id, report.investigations, evidence=evidence,
                evidence_snapshot_hash=evidence_snapshot_hash(evidence) if evidence else None)
        except (AuditError, OSError) as exc:
            _log.error("INVESTIGATION_COMPLETED audit failed for %s: %s", incident.incident_id,
                       type(exc).__name__)


_HEALTH_RANK = {
    HealthStatus.CONNECTED: 0, HealthStatus.UNKNOWN: 1, HealthStatus.DEGRADED: 2,
    HealthStatus.RATE_LIMITED: 3, HealthStatus.AUTH_FAILED: 4, HealthStatus.UNAVAILABLE: 5,
}


def _worst(a: HealthStatus | None, b: HealthStatus) -> HealthStatus:
    if a is None:
        return b
    return a if _HEALTH_RANK[a] >= _HEALTH_RANK[b] else b
