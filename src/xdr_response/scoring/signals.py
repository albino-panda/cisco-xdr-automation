"""Scoring signals from normalized records (architecture 14.2.3).

Every signal cites the id of the record it was built from. Records that only give context
(sign-ins, MFA events, endpoints, generic findings) produce no signal here; patterns over them are
hook-derived signals (14.3.3) that cite the records they were computed from.

The record models live in ``xdr_response.atomics.records`` (owner: investigation). This module
reads records by their documented fields only and dispatches on ``record.kind``; it never builds
a record.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from xdr_response.models.catalog import INTEGRATION_NAMES
from xdr_response.models.enums import Severity, Verdict
from xdr_response.models.observable import Observable
from xdr_response.models.scoring import ScoringSignal, SignalCategory

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.records import AnyRecord, EnrichmentRecord, RecordKind

__all__ = [
    "ENRICHMENT_CATEGORY",
    "SEVERITY_POINTS",
    "LEVEL_POINTS",
    "RECORD_CONFIDENCE",
    "signals_from_enrichment",
    "signals_from_records",
]

_ENRICHMENT_SPECIFIC: dict[str, SignalCategory] = {
    "secure_malware_analytics": SignalCategory.SANDBOX_VERDICT,
    "secure_endpoint": SignalCategory.ENDPOINT_DETECTION,
    "defender_endpoint": SignalCategory.ENDPOINT_DETECTION,
    "intune": SignalCategory.ENDPOINT_DETECTION,
    "entra": SignalCategory.AUTHENTICATION_ANOMALY,
    "secure_email": SignalCategory.EMAIL_VERDICT,
    "defender_o365": SignalCategory.EMAIL_VERDICT,
}

ENRICHMENT_CATEGORY: Mapping[str, SignalCategory] = MappingProxyType({
    name: _ENRICHMENT_SPECIFIC.get(name, SignalCategory.REPUTATION) for name in INTEGRATION_NAMES
})

SEVERITY_POINTS: Mapping[Severity, int] = MappingProxyType({
    Severity.CRITICAL: 95, Severity.HIGH: 80, Severity.MEDIUM: 60, Severity.LOW: 30, Severity.INFO: 10,
})

LEVEL_POINTS: Mapping[str, int] = MappingProxyType({"high": 80, "medium": 60, "low": 40, "none": 0, "unknown": 0})

# Keys are the RecordKind values; RecordKind is a StrEnum, so RecordKind members look them up too.
RECORD_CONFIDENCE: Mapping[RecordKind, int] = MappingProxyType({  # type: ignore[dict-item]
    "detection": 80, "process_event": 70, "network_connection": 60, "dns_query": 60, "hash_prevalence": 70,
    "persistence_item": 60, "anomaly": 70, "mailbox_rule": 70, "role_change": 75, "email_message": 80,
    "cloud_app": 60,
    # user_profile: same value as anomaly (both are identity-protection statements from the same source)
    "user_profile": 70,
})

_BY_VERDICT_70_50: Mapping[Verdict, int] = MappingProxyType(
    {Verdict.MALICIOUS: 70, Verdict.SUSPICIOUS: 50, Verdict.CLEAN: 0})
_EMAIL_SEVERITY: Mapping[Verdict, int] = MappingProxyType(
    {Verdict.MALICIOUS: 80, Verdict.SUSPICIOUS: 50, Verdict.CLEAN: 0})
_SUPPORTING = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)


def _signal(record: Any, observable: Observable, category: SignalCategory, verdict: Verdict,
            severity: int, confidence: int, *, vendor_verdict: bool = False) -> ScoringSignal:
    return ScoringSignal(category=category, integration=record.integration, observable=observable,
                         verdict=verdict, severity=severity, confidence=confidence,
                         record_ids=(record.record_id,), vendor_verdict=vendor_verdict)


def _kind_confidence(record: Any) -> int:
    return RECORD_CONFIDENCE[str(record.kind)]


def _enrichment(record: Any, observable: Observable) -> ScoringSignal | None:
    if record.verdict is Verdict.UNKNOWN:
        return None
    category = ENRICHMENT_CATEGORY.get(record.integration, SignalCategory.REPUTATION)
    # An enrichment answer is a vendor's verdict, not a behavioural detection (14.2.2): the engine
    # never lets it reach CRITICAL alone and aggregate_verdict never makes it MALICIOUS alone.
    return _signal(record, observable, category, record.verdict, record.risk_score, record.confidence,
                   vendor_verdict=True)


def _detection_category(category: str | None) -> SignalCategory:
    """endpoint_detection; persistence or lateral_movement when the vendor category names them."""
    text = "".join(ch for ch in (category or "").lower() if ch.isalnum())
    if "lateralmovement" in text:
        return SignalCategory.LATERAL_MOVEMENT
    if "persistence" in text:
        return SignalCategory.PERSISTENCE
    return SignalCategory.ENDPOINT_DETECTION


def _detection(record: Any, observable: Observable) -> ScoringSignal | None:
    return _signal(record, observable, _detection_category(record.category), record.verdict,
                   SEVERITY_POINTS[Severity(record.severity)], _kind_confidence(record))


def _process_event(record: Any, observable: Observable) -> ScoringSignal | None:
    if record.verdict not in _SUPPORTING:
        return None
    return _signal(record, observable, SignalCategory.ENDPOINT_DETECTION, record.verdict,
                   _BY_VERDICT_70_50[record.verdict], _kind_confidence(record))


def _network(record: Any, observable: Observable) -> ScoringSignal | None:
    if record.verdict is Verdict.UNKNOWN:
        return None
    return _signal(record, observable, SignalCategory.NETWORK_BEHAVIOUR, record.verdict,
                   _BY_VERDICT_70_50[record.verdict], _kind_confidence(record))


def _hash_prevalence(record: Any, observable: Observable) -> ScoringSignal | None:
    if record.verdict is not Verdict.MALICIOUS:
        return None
    return _signal(record, observable, SignalCategory.ENDPOINT_DETECTION, Verdict.MALICIOUS, 70,
                   _kind_confidence(record))


def _persistence_item(record: Any, observable: Observable) -> ScoringSignal | None:
    if record.verdict not in _SUPPORTING:
        return None
    return _signal(record, observable, SignalCategory.PERSISTENCE, record.verdict,
                   _BY_VERDICT_70_50[record.verdict], _kind_confidence(record))


def _anomaly(record: Any, observable: Observable) -> ScoringSignal | None:
    severity = Severity(record.severity)
    verdict = Verdict.MALICIOUS if severity in (Severity.HIGH, Severity.CRITICAL) else Verdict.SUSPICIOUS
    return _signal(record, observable, SignalCategory.AUTHENTICATION_ANOMALY, verdict,
                   SEVERITY_POINTS[severity], _kind_confidence(record))


def _user_profile(record: Any, observable: Observable) -> ScoringSignal | None:
    if record.risk_state == "confirmed_compromised":
        return _signal(record, observable, SignalCategory.AUTHENTICATION_ANOMALY, Verdict.MALICIOUS, 85,
                       _kind_confidence(record))
    if record.risk_level == "high":
        return _signal(record, observable, SignalCategory.AUTHENTICATION_ANOMALY, Verdict.SUSPICIOUS,
                       LEVEL_POINTS[record.risk_level], _kind_confidence(record))
    return None


def _mailbox_rule(record: Any, observable: Observable) -> ScoringSignal | None:
    if not (record.external_forwarding or record.delete):
        return None
    return _signal(record, observable, SignalCategory.PERSISTENCE, Verdict.SUSPICIOUS, 70,
                   _kind_confidence(record))


def _role_change(record: Any, observable: Observable) -> ScoringSignal | None:
    if not (record.privileged and record.change in ("assigned", "activated")):
        return None
    return _signal(record, observable, SignalCategory.PERSISTENCE, Verdict.SUSPICIOUS, 75,
                   _kind_confidence(record))


def _email_message(record: Any, observable: Observable) -> ScoringSignal | None:
    if record.verdict is Verdict.UNKNOWN:
        return None
    return _signal(record, observable, SignalCategory.EMAIL_VERDICT, record.verdict,
                   _EMAIL_SEVERITY[record.verdict], _kind_confidence(record))


def _cloud_app(record: Any, observable: Observable) -> ScoringSignal | None:
    if record.verdict is Verdict.UNKNOWN:
        return None
    return _signal(record, observable, SignalCategory.PERSISTENCE, record.verdict, 60, _kind_confidence(record))


_RULES: Mapping[str, Callable[[Any, Observable], ScoringSignal | None]] = MappingProxyType({
    "enrichment": _enrichment,
    "detection": _detection,
    "process_event": _process_event,
    "network_connection": _network,
    "dns_query": _network,
    "hash_prevalence": _hash_prevalence,
    "persistence_item": _persistence_item,
    "anomaly": _anomaly,
    "user_profile": _user_profile,
    "mailbox_rule": _mailbox_rule,
    "role_change": _role_change,
    "email_message": _email_message,
    "cloud_app": _cloud_app,
    # sign_in, mfa_event, endpoint, generic: context only, no signal
})


def _kind(record: Any) -> str:
    return str(record.kind)


def signals_from_enrichment(records: Sequence[EnrichmentRecord]) -> tuple[ScoringSignal, ...]:
    """One signal per enrichment record whose verdict is not UNKNOWN, about the record's subject.

    Category from ENRICHMENT_CATEGORY; severity is the record's risk score and confidence the
    record's confidence; ``vendor_verdict`` is True. Records of another kind raise ValueError.
    """
    out: list[ScoringSignal] = []
    for record in records:
        if _kind(record) != "enrichment":
            raise ValueError(f"signals_from_enrichment takes enrichment records only, got {_kind(record)!r}")
        signal = _enrichment(record, record.subject)
        if signal is not None:
            out.append(signal)
    return tuple(out)


def signals_from_records(records: Sequence[AnyRecord], *, observable: Observable) -> tuple[ScoringSignal, ...]:
    """Signals for the target ``observable`` from any records, per the table of 14.2.3.

    Every signal is about ``observable`` (the caller passes the records it attributes to that
    target) and cites exactly the one record it was built from.
    """
    out: list[ScoringSignal] = []
    for record in records:
        rule = _RULES.get(_kind(record))
        if rule is None:
            continue
        signal = rule(record, observable)
        if signal is not None:
            out.append(signal)
    return tuple(out)
