"""Turning one source's :class:`EnrichmentResult` into an :class:`EnrichmentRecord` (14.1.2, 14.1.3).

Only facts the source itself returned are copied: its verdict, risk and confidence, the vendor
categories found in its evidence data, a ``first_seen`` timestamp when the source reported one, and
its own first evidence summary. Nothing is inferred or invented; a field the source did not report
stays empty.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from xdr_response.atomics.records import EnrichmentRecord, RecordKind, make_record_id
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import EnrichmentResult, EvidenceDraft, Observable

__all__ = ["CATEGORY_KEYS", "build_record", "categories_of", "first_seen_of"]

#: Evidence ``data`` keys whose string lists are vendor categories (Umbrella reports the last two).
CATEGORY_KEYS = ("categories", "security_categories", "content_categories")
_MAX_CATEGORIES = 20
_MAX_CATEGORY_LENGTH = 100


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str) and item.strip():
                yield item.strip()


def categories_of(evidence: Iterable[EvidenceDraft]) -> tuple[str, ...]:
    """Distinct vendor categories named in the evidence data, first-seen order, capped and redacted."""
    redactor = get_redactor()
    seen: list[str] = []
    for draft in evidence:
        for key in CATEGORY_KEYS:
            for name in _strings(draft.data.get(key)):
                clean = redactor.redact_text(name)[:_MAX_CATEGORY_LENGTH]
                if clean not in seen:
                    seen.append(clean)
    return tuple(seen[:_MAX_CATEGORIES])


def _aware(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None


def first_seen_of(evidence: Iterable[EvidenceDraft]) -> datetime | None:
    """Earliest timezone-aware ``first_seen`` the source reported in its evidence data."""
    stamps = [stamp for draft in evidence if (stamp := _aware(draft.data.get("first_seen"))) is not None]
    return min(stamps) if stamps else None


def _reference(evidence: tuple[EvidenceDraft, ...]) -> str | None:
    """First evidence reference that is already clean (records refuse references needing redaction)."""
    redactor = get_redactor()
    for draft in evidence:
        if draft.reference and redactor.redact_text(draft.reference) == draft.reference:
            return draft.reference
    return None


def build_record(atomic: str, subject: Observable, integration: str, result: EnrichmentResult) -> EnrichmentRecord:
    """The one :class:`EnrichmentRecord` for ``integration``'s answer about ``subject``."""
    evidence = result.evidence
    return EnrichmentRecord(
        record_id=make_record_id(integration, RecordKind.ENRICHMENT, subject, {}),
        integration=integration,
        atomic=atomic,
        subject=subject,
        observed_at=evidence[0].observed_at if evidence else None,
        reference=_reference(evidence),
        verdict=result.verdict,
        risk_score=result.risk_score,
        confidence=result.confidence,
        categories=categories_of(evidence),
        first_seen=first_seen_of(evidence),
        detail=evidence[0].summary if evidence else "",
    )
