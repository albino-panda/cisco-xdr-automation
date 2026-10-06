"""Per-incident execution summary built from audit records (brief section 35).

The summary is derived only from the (already redacted) audit records, never from live objects,
so it shows exactly what the tamper-evident trail can prove. Payloads are read defensively: a
missing or redacted field yields ``None`` / an empty list instead of an exception.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from pydantic import AwareDatetime

from xdr_response.errors import AuditError
from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models.audit import AuditRecord
from xdr_response.models.enums import ApprovalPurpose, AuditEventType, DecisionType

__all__ = ["ExecutionAuditSummary", "build_execution_summary"]

_APPROVING = {DecisionType.APPROVE_ALL.value, DecisionType.APPROVE_SELECTED.value}
_REQUEST_FIELDS = ("integration", "operation", "method", "url", "kind", "attempt", "request_summary")
_RESPONSE_FIELDS = ("integration", "operation", "status_code", "duration_ms", "response_summary",
                    "error")
_ACTION_FIELDS = ("idempotency_key", "action_type", "target", "target_kind", "approval_level",
                  "risk_score", "confidence_score", "rationale")


class ExecutionAuditSummary(FrozenModel):
    """Brief section 35 fields, one per incident execution."""

    incident_id: str
    workflow_id: str | None
    workflow_version: str | None
    timestamp: AwareDatetime
    trigger: JsonDict
    observables: list[JsonDict]
    evidence: list[JsonDict]
    risk_score: int | None
    confidence_score: int | None
    recommended_actions: list[JsonDict]
    analyst_identity: str | None
    approval_timestamp: AwareDatetime | None
    approved_actions: list[str]
    rejected_actions: list[str]
    api_requests: list[JsonDict]
    api_responses: list[JsonDict]
    containment_results: list[JsonDict]
    verification_results: list[JsonDict]
    restoration_results: list[JsonDict]
    errors: list[JsonDict]


def build_execution_summary(records: Iterable[AuditRecord], incident_id: str) -> ExecutionAuditSummary:
    """Summarize every record of ``incident_id``. :class:`AuditError` when there are none."""
    mine = [r for r in records if r.incident_id == incident_id]
    if not mine:
        raise AuditError(f"no audit records for incident {incident_id}")
    received = _first(mine, AuditEventType.INCIDENT_RECEIVED)
    package = _last(mine, AuditEventType.PACKAGE_PROPOSED)
    decision = _containment_decision(mine)
    return ExecutionAuditSummary(
        incident_id=incident_id,
        workflow_id=_first_value(mine, "workflow_id"),
        workflow_version=_first_value(mine, "workflow_version"),
        timestamp=mine[0].timestamp,
        trigger=_mapping(received, "trigger"),
        observables=_dicts(received, "observables"),
        evidence=_evidence(mine, package),
        risk_score=_int(package, "risk_score"),
        confidence_score=_int(package, "confidence_score"),
        recommended_actions=[_pick(a, _ACTION_FIELDS) for a in _dicts(package, "actions")],
        analyst_identity=_str(decision, "analyst_identity"),
        approval_timestamp=_approval_time(decision),
        approved_actions=_strings(decision, "approved_action_keys"),
        rejected_actions=_strings(decision, "rejected_action_keys"),
        api_requests=[_api_part(r, _REQUEST_FIELDS) for r in _of(mine, AuditEventType.API_CALL)],
        api_responses=[_api_part(r, _RESPONSE_FIELDS) for r in _of(mine, AuditEventType.API_CALL)],
        containment_results=_payloads(mine, AuditEventType.ACTION_RESULT),
        verification_results=_payloads(mine, AuditEventType.VERIFICATION_RESULT),
        restoration_results=_payloads(mine, AuditEventType.RESTORATION_RESULT),
        errors=_errors(mine),
    )


# ------------------------------------------------------------- selectors ---
def _of(records: list[AuditRecord], event: AuditEventType) -> list[AuditRecord]:
    return [r for r in records if r.event_type is event]


def _first(records: list[AuditRecord], event: AuditEventType) -> Mapping[str, Any]:
    found = _of(records, event)
    return found[0].payload if found else {}


def _last(records: list[AuditRecord], event: AuditEventType) -> Mapping[str, Any]:
    found = _of(records, event)
    return found[-1].payload if found else {}


def _containment_decision(records: list[AuditRecord]) -> Mapping[str, Any]:
    decisions = [r.payload for r in _of(records, AuditEventType.DECISION_RECORDED)
                 if r.payload.get("purpose", ApprovalPurpose.CONTAINMENT.value)
                 == ApprovalPurpose.CONTAINMENT.value]
    return decisions[-1] if decisions else {}


def _first_value(records: list[AuditRecord], field: str) -> str | None:
    return next((getattr(r, field) for r in records if getattr(r, field)), None)


def _payloads(records: list[AuditRecord], event: AuditEventType) -> list[JsonDict]:
    return [{"seq": r.seq, **r.payload} for r in _of(records, event)]


# -------------------------------------------------------------- coercion ---
def _mapping(payload: Mapping[str, Any], key: str) -> JsonDict:
    value = payload.get(key)
    return dict(value) if isinstance(value, Mapping) else {}


def _dicts(payload: Mapping[str, Any], key: str) -> list[JsonDict]:
    value = payload.get(key)
    if not isinstance(value, list):
        return []
    return [dict(v) for v in value if isinstance(v, Mapping)]


def _strings(payload: Mapping[str, Any], key: str) -> list[str]:
    value = payload.get(key)
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _int(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) else None


def _pick(payload: Mapping[str, Any], fields: tuple[str, ...]) -> JsonDict:
    return {f: payload.get(f) for f in fields if f in payload}


def _api_part(record: AuditRecord, fields: tuple[str, ...]) -> JsonDict:
    return {"seq": record.seq, **_pick(record.payload, fields)}


def _approval_time(decision: Mapping[str, Any]) -> datetime | None:
    if decision.get("decision") not in _APPROVING:
        return None
    value = decision.get("decided_at")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _evidence(records: list[AuditRecord], package: Mapping[str, Any]) -> list[JsonDict]:
    evidence = _dicts(package, "evidence")
    if evidence:
        return evidence
    return _dicts(_last(records, AuditEventType.INVESTIGATION_COMPLETED), "evidence")


def _errors(records: list[AuditRecord]) -> list[JsonDict]:
    out: list[JsonDict] = []
    for r in records:
        if r.event_type in (AuditEventType.ERROR, AuditEventType.GUARD_DENIED,
                            AuditEventType.APPROVAL_DENIED):
            out.append({"seq": r.seq, "event_type": r.event_type.value, **r.payload})
        elif r.event_type in (AuditEventType.ACTION_RESULT, AuditEventType.RESTORATION_RESULT):
            error = r.payload.get("error")
            if isinstance(error, Mapping):
                out.append({"seq": r.seq, "event_type": r.event_type.value,
                            "idempotency_key": r.payload.get("idempotency_key"), **error})
    return out
