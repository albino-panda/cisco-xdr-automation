"""Normalizer for ``entra`` investigation results (architecture 14.1.4).

Sources (Microsoft Graph v1.0):

* ``investigate_user``: Get user, ``GET /users/{id or userPrincipalName}``
  (https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0). Mapped user properties:
  ``id``, ``userPrincipalName``, ``displayName``, ``department``, ``jobTitle``, ``accountEnabled``,
  ``signInSessionsValidFromDateTime``. Roles, groups and risk are not user properties and stay empty.
* ``investigate_authentication`` / ``search_user_activity``: List signIns, ``GET /auditLogs/signIns``
  (https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0). Mapped signIn
  properties: ``id``, ``createdDateTime``, ``userPrincipalName``, ``ipAddress``, ``location.city``,
  ``location.countryOrRegion``, ``appDisplayName``, ``clientAppUsed``, ``deviceDetail.deviceId``,
  ``deviceDetail.isCompliant``, ``status.errorCode`` (0 is success), ``status.failureReason``,
  ``conditionalAccessStatus``, ``riskLevelDuringSignIn``. MFA detail is not mapped (unknown).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal

from xdr_response.atomics.investigation.normalize.typed import (
    _datetime,
    _flag,
    _ips,
    _normalize_findings,
    _path,
    _reference,
    _text,
)
from xdr_response.atomics.records import AnyRecord, Level, SignInRecord, UserProfileRecord
from xdr_response.models import ActionType, InvestigationResult, ObservableType

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.investigation.normalize import NormalizeContext

__all__: list[str] = []

_SIGN_IN_ACTIONS = frozenset({ActionType.INVESTIGATE_AUTHENTICATION, ActionType.SEARCH_USER_ACTIVITY})
_CA_STATUS: Mapping[str, Literal["success", "failure", "not_applied"]] = {
    "success": "success", "failure": "failure", "notapplied": "not_applied"}
_RISK_LEVELS: Mapping[str, Level] = {"none": "none", "low": "low", "medium": "medium", "high": "high"}


def _subject_user(nctx: "NormalizeContext") -> str | None:
    if nctx.subject.type in (ObservableType.USER, ObservableType.EMAIL_ADDRESS):
        return nctx.subject.value
    return None


def _user(finding: Mapping[str, Any], nctx: "NormalizeContext", result: InvestigationResult) -> AnyRecord:
    """A ``UserProfileRecord`` for a Graph user resource."""
    object_id = _text(finding, "id")
    upn = _text(finding, "userPrincipalName") or (_subject_user(nctx) if object_id else None)
    if upn is None:
        raise ValueError("not a Graph user resource")
    return UserProfileRecord(
        integration=result.integration, atomic=nctx.atomic, subject=nctx.subject,
        reference=_reference(object_id), user=upn, object_id=object_id,
        display_name=_text(finding, "displayName"), department=_text(finding, "department"),
        job_title=_text(finding, "jobTitle"), account_enabled=_flag(finding, "accountEnabled"),
        sessions_valid_from=_datetime(finding.get("signInSessionsValidFromDateTime")),
    )


def _sign_in_result(finding: Mapping[str, Any]) -> Literal["success", "failure", "unknown"]:
    code = _path(finding, "status", "errorCode")
    if isinstance(code, bool) or not isinstance(code, int):
        return "unknown"
    return "success" if code == 0 else "failure"


def _sign_in(finding: Mapping[str, Any], nctx: "NormalizeContext", result: InvestigationResult) -> AnyRecord:
    """A ``SignInRecord`` for a Graph signIn resource."""
    timestamp = _datetime(finding.get("createdDateTime"))
    user = _text(finding, "userPrincipalName") or _subject_user(nctx)
    if timestamp is None or user is None:
        raise ValueError("not a Graph signIn resource")
    outcome = _sign_in_result(finding)
    ips = _ips((finding.get("ipAddress"),))
    ca = (_text(finding, "conditionalAccessStatus") or "").lower()
    risk = (_text(finding, "riskLevelDuringSignIn") or "").lower()
    sign_in_id = _text(finding, "id")
    return SignInRecord(
        integration=result.integration, atomic=nctx.atomic, subject=nctx.subject,
        observed_at=timestamp, reference=_reference(sign_in_id), sign_in_id=sign_in_id, user=user,
        timestamp=timestamp, ip=ips[0] if ips else None, country=_text(finding, "location", "countryOrRegion"),
        city=_text(finding, "location", "city"), app=_text(finding, "appDisplayName"),
        client_app=_text(finding, "clientAppUsed"), device_id=_text(finding, "deviceDetail", "deviceId"),
        device_compliant=_flag(finding, "deviceDetail", "isCompliant"), result=outcome,
        failure_reason=_text(finding, "status", "failureReason") if outcome == "failure" else None,
        conditional_access=_CA_STATUS.get(ca, "unknown"), risk_level=_RISK_LEVELS.get(risk, "unknown"),
    )


def _entra_finding(finding: Mapping[str, Any], nctx: "NormalizeContext",
                   result: InvestigationResult) -> list[AnyRecord]:
    if result.action_type is ActionType.INVESTIGATE_USER:
        return [_user(finding, nctx, result)]
    if result.action_type in _SIGN_IN_ACTIONS:
        return [_sign_in(finding, nctx, result)]
    raise ValueError(f"no entra mapping for {result.action_type.value}")


def _normalize(result: InvestigationResult, nctx: "NormalizeContext") -> list[AnyRecord]:
    """Users as profiles, sign-ins as sign-in records; anything else generic."""
    return _normalize_findings(result, nctx, _entra_finding)
