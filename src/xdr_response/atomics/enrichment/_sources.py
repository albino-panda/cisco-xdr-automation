"""Querying every enrichment source for one subject (architecture 14.1.3 step 2).

Each enricher of the subject's type is asked in ``INTEGRATION_NAMES`` order and its answer becomes
exactly one :class:`SourceStatus`:

* a third-party source (VirusTotal, OTX, HIBP) that the disclosure policy refuses is
  ``NOT_QUERIED`` with reason ``"disclosure policy"`` and is never called, so internal observables
  and personal data never leave the organization;
* an exception is ``FAILED`` (health from :func:`classify_exception`, redacted :class:`ErrorInfo`);
* a result with ``errors`` and verdict ``UNKNOWN`` is ``FAILED`` with the result's health;
* verdict ``UNKNOWN`` without evidence is ``EMPTY``;
* anything else is ``ANSWERED`` and yields one :class:`EnrichmentRecord`.

A failing source never stops the others: this module never raises because of a source.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from xdr_response.atomics.context import AtomicContext
from xdr_response.atomics.enrichment._records import build_record
from xdr_response.atomics.records import EnrichmentRecord, SourceOutcome, SourceStatus
from xdr_response.config.policy import THIRD_PARTY_INTEGRATIONS
from xdr_response.errors import IntegrationError
from xdr_response.integrations.health import classify_exception
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import (
    INTEGRATION_NAMES,
    EnrichmentResult,
    ErrorCode,
    ErrorInfo,
    HealthStatus,
    Observable,
    Verdict,
)

__all__ = ["DISCLOSURE_REASON", "SourceAnswer", "query_sources", "may_query"]

#: ``SourceStatus.reason`` of a third-party source withheld by the disclosure policy.
DISCLOSURE_REASON = "disclosure policy"
_MAX_MESSAGE = 500


@dataclass(frozen=True)
class SourceAnswer:
    """What one source said about the subject: its status, its record and the raw result for audit."""

    status: SourceStatus
    record: EnrichmentRecord | None = None
    raw: EnrichmentResult | None = None


def may_query(ctx: AtomicContext, subject: Observable, integration: str) -> bool:
    """True unless ``integration`` is a third-party lookup the disclosure policy refuses.

    Fails closed: a policy error withholds the observable from the third party.
    """
    if integration not in THIRD_PARTY_INTEGRATIONS:
        return True
    try:
        return bool(ctx.disclosure.may_disclose(subject, integration))
    except Exception:  # noqa: BLE001 - never disclose when the policy cannot decide
        return False


def _error_info(exc: Exception, integration: str) -> ErrorInfo:
    if isinstance(exc, IntegrationError):
        return exc.to_error_info()
    message = get_redactor().redact_text(f"{type(exc).__name__}: {exc}")[:_MAX_MESSAGE]
    return ErrorInfo(code=ErrorCode.INTERNAL, message=message, integration=integration)


def _failed_from_exception(subject: Observable, integration: str, exc: Exception) -> SourceAnswer:
    """``FAILED`` status plus a failure result (audited like Phase 0 ``InvestigationService``)."""
    health = classify_exception(exc)
    error = _error_info(exc, integration)
    raw = EnrichmentResult(type=subject.type, value=subject.value, risk_score=0, confidence=0,
                           sources=(integration,), verdict=Verdict.UNKNOWN, integration=integration,
                           health=health, errors=(error,))
    status = SourceStatus(integration=integration, outcome=SourceOutcome.FAILED, health=health,
                          reason=error.code.value, error=error)
    return SourceAnswer(status=status, raw=raw)


def _classify(atomic: str, subject: Observable, integration: str, result: EnrichmentResult) -> SourceAnswer:
    """Map a returned result onto FAILED / EMPTY / ANSWERED."""
    if result.verdict is Verdict.UNKNOWN and result.errors:
        error = result.errors[0]
        status = SourceStatus(integration=integration, outcome=SourceOutcome.FAILED, health=result.health,
                              reason=error.code.value, error=error)
        return SourceAnswer(status=status, raw=result)
    if result.verdict is Verdict.UNKNOWN and not result.evidence:
        status = SourceStatus(integration=integration, outcome=SourceOutcome.EMPTY, health=result.health)
        return SourceAnswer(status=status, raw=result)
    record = build_record(atomic, subject, integration, result)
    status = SourceStatus(integration=integration, outcome=SourceOutcome.ANSWERED, health=result.health, records=1)
    return SourceAnswer(status=status, record=record, raw=result)


def _ask(ctx: AtomicContext, atomic: str, subject: Observable, integration: str) -> SourceAnswer:
    """One source, isolated: every failure becomes a ``FAILED`` answer."""
    if not may_query(ctx, subject, integration):
        status = SourceStatus(integration=integration, outcome=SourceOutcome.NOT_QUERIED,
                              health=HealthStatus.UNKNOWN, reason=DISCLOSURE_REASON)
        return SourceAnswer(status=status)
    try:
        result = ctx.adapters.enrich(integration, subject)
        if not isinstance(result, EnrichmentResult):
            raise TypeError("adapter returned no EnrichmentResult")
        return _classify(atomic, subject, integration, result)
    except Exception as exc:  # noqa: BLE001 - one failing source never blocks the others
        return _failed_from_exception(subject, integration, exc)


def _ordered(names: Sequence[str]) -> list[str]:
    """Distinct known names in ``INTEGRATION_NAMES`` order."""
    wanted = set(names)
    return [name for name in INTEGRATION_NAMES if name in wanted]


def query_sources(ctx: AtomicContext, atomic: str, subject: Observable,
                  enrichers: Sequence[str]) -> list[SourceAnswer]:
    """One answer per enricher, in ``INTEGRATION_NAMES`` order."""
    return [_ask(ctx, atomic, subject, name) for name in _ordered(enrichers)]
