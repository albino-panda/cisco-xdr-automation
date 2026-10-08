"""Normalizer for ``microsoft_cloud`` investigation results (architecture 14.1.4).

Sources (Microsoft Graph security v1.0):

* List alerts_v2, ``GET /security/alerts_v2``
  (https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0). An alert
  becomes a ``DetectionRecord``. Mapped alert properties: ``id``, ``title``, ``severity``, ``status``,
  ``classification``, ``category``, ``mitreTechniques``, ``firstActivityDateTime``,
  ``lastActivityDateTime``, ``createdDateTime``, ``alertWebUrl``, and from ``evidence[]``:
  ``deviceEvidence.deviceDnsName``, ``userEvidence.userAccount.userPrincipalName``,
  ``fileEvidence.fileDetails.sha256`` / ``filePath``.
* Advanced hunting, ``POST /security/runHuntingQuery``: rows are whatever the operator's KQL
  projects, so every row becomes a ``GenericRecord``.

Verdict comes only from the vendor's own ``classification``: ``truePositive`` is MALICIOUS,
``falsePositive`` and ``informationalExpectedActivity`` are CLEAN, an unclassified alert is
SUSPICIOUS (the product raised it). Severity ``unknown`` maps to INFO (never inflated).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any, Literal

from xdr_response.atomics.investigation.normalize.typed import (
    _datetime,
    _normalize_findings,
    _path,
    _reference,
    _strings,
    _text,
)
from xdr_response.atomics.records import AnyRecord, DetectionRecord
from xdr_response.models import InvestigationResult, Severity, Verdict

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.investigation.normalize import NormalizeContext

__all__: list[str] = []

_ALERT_MARKERS = ("serviceSource", "alertWebUrl", "detectionSource", "providerAlertId")
_SEVERITY: Mapping[str, Severity] = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
                                     "informational": Severity.INFO}
_CLASSIFICATION: Mapping[str, Verdict] = {"truepositive": Verdict.MALICIOUS, "falsepositive": Verdict.CLEAN,
                                          "informationalexpectedactivity": Verdict.CLEAN}
_STATUS: Mapping[str, Literal["active", "resolved"]] = {"new": "active", "inprogress": "active",
                                                        "resolved": "resolved"}
_HEX = frozenset("0123456789abcdef")


def _is_alert(finding: Mapping[str, Any]) -> bool:
    return bool(_text(finding, "id") and _text(finding, "title") and _text(finding, "severity")
                and any(marker in finding for marker in _ALERT_MARKERS))


def _evidence(finding: Mapping[str, Any], odata_suffix: str) -> Iterable[Mapping[str, Any]]:
    items = finding.get("evidence")
    if not isinstance(items, list):
        return ()
    return [e for e in items if isinstance(e, Mapping)
            and str(e.get("@odata.type", "")).lower().endswith(odata_suffix.lower())]


def _first(values: Iterable[str | None]) -> str | None:
    return next((v for v in values if v), None)


def _sha256(value: Any) -> str | None:
    v = value.strip().lower() if isinstance(value, str) else ""
    return v if len(v) == 64 and set(v) <= _HEX else None


def _alert(finding: Mapping[str, Any], nctx: "NormalizeContext", result: InvestigationResult) -> list[AnyRecord]:
    """One ``DetectionRecord`` per alerts_v2 alert (``ValueError`` for hunting rows)."""
    if not _is_alert(finding):
        raise ValueError("not an alerts_v2 alert")
    files = list(_evidence(finding, "fileEvidence"))
    first_seen = _datetime(finding.get("firstActivityDateTime"))
    return [DetectionRecord(
        integration=result.integration, atomic=nctx.atomic, subject=nctx.subject,
        observed_at=_datetime(finding.get("createdDateTime")) or first_seen,
        reference=_reference(finding.get("alertWebUrl")) or _reference(finding.get("id")),
        detection_id=_text(finding, "id"), name=_text(finding, "title") or "",
        verdict=_CLASSIFICATION.get((_text(finding, "classification") or "").lower(), Verdict.SUSPICIOUS),
        severity=_SEVERITY.get((_text(finding, "severity") or "").lower(), Severity.INFO),
        category=_text(finding, "category"),
        endpoint=_first(_text(e, "deviceDnsName") for e in _evidence(finding, "deviceEvidence")),
        user=_first(_text(e, "userAccount", "userPrincipalName") for e in _evidence(finding, "userEvidence")),
        sha256=_first(_sha256(_path(e, "fileDetails", "sha256")) for e in files),
        file_path=_first(_text(e, "fileDetails", "filePath") for e in files),
        mitre_techniques=_strings(finding.get("mitreTechniques")),
        status=_STATUS.get((_text(finding, "status") or "").lower(), "unknown"),
        first_seen=first_seen, last_seen=_datetime(finding.get("lastActivityDateTime")),
    )]


def _normalize(result: InvestigationResult, nctx: "NormalizeContext") -> list[AnyRecord]:
    """Alerts as detection records; hunting rows and anything else generic."""
    return _normalize_findings(result, nctx, _alert)
