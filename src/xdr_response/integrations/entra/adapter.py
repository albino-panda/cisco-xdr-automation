"""Microsoft Entra ID adapter via Microsoft Graph v1.0 (docs/integrations.md section 2.8).

State changes: disable / enable account (PATCH ``accountEnabled``), revoke sign-in sessions,
confirm user compromised, remove / restore a directory role assignment. Every reversible write
reads the current state first (idempotency) and every verifiable one is re-read afterwards.
Role removal captures ``roleDefinitionId``, ``principalId`` and ``directoryScopeId`` **before** the
delete so the release can recreate the assignment. riskyUser get/dismiss, password reset, MFA reset
and app-credential revocation are UNVERIFIED and raise.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, ClassVar, NoReturn

from xdr_response.clock import utc
from xdr_response.errors import ApiError, CapabilityNotSupportedError, InvalidTargetError
from xdr_response.guard import state_changing
from xdr_response.integrations._adapter_support import ApiRequest, HttpResultLike, VendorAdapter, body_dict, body_list
from xdr_response.integrations._graph import GRAPH_BASE_URL, graph_scope, microsoft_auth
from xdr_response.integrations.entra import builders
from xdr_response.integrations.entra.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    ActionType,
    EnrichmentResult,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    ObservableType,
    OperationKind,
    TargetState,
    TargetStateCheck,
    Verdict,
    VerificationResult,
    VerificationStatus,
)

__all__ = ["EntraAdapter"]

_ENABLE_TYPES = {ActionType.DISABLE_USER: False, ActionType.ENABLE_USER: True}
_USER_FIELDS = ("id", "displayName", "userPrincipalName", "accountEnabled")
_V = OperationKind.VERIFY


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _same_role(a: Mapping[str, Any], role_definition_id: str, directory_scope_id: str) -> bool:
    return a.get("roleDefinitionId") == role_definition_id and a.get("directoryScopeId") == directory_scope_id


class EntraAdapter(VendorAdapter):
    """Entra ID: users, sign-ins, account state, sessions, risky users and role assignments."""

    name: ClassVar[str] = "entra"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = GRAPH_BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """Client credentials at the identity platform with ``options.oauth_scope``."""
        return microsoft_auth(self, scope=graph_scope(self))

    def _health_probe(self) -> ApiRequest | None:
        return builders.list_sign_ins(top=1)

    # ---------------------------------------------------------------- reads --
    def get_user(self, user: str, select: tuple[str, ...] = _USER_FIELDS) -> dict[str, Any]:
        """One user by object ID or userPrincipalName."""
        return body_dict(self._send(builders.get_user(user, select)).body)

    def list_role_assignments(self, principal_id: str) -> list[dict[str, Any]]:
        """Directory role assignments of one principal."""
        result = self._send(builders.list_role_assignments(principal_id))
        return [a for a in body_list(result.body, "value") if isinstance(a, dict)]

    def get_risky_user(self, user_id: str) -> NoReturn:
        """riskyUser GET: UNVERIFIED."""
        self._unverified("risky_user")

    def dismiss_risky_user(self, user_id: str) -> NoReturn:
        """riskyUser dismiss: UNVERIFIED (so confirm_user_compromised has no rollback)."""
        self._unverified("dismiss_risky_user")

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Account context for a user (no reputation verdict)."""
        if observable.type not in (ObservableType.USER, ObservableType.EMAIL_ADDRESS):
            raise CapabilityNotSupportedError(f"entra cannot enrich {observable.type.value}", integration=self.name)
        result = self._send(builders.get_user(observable.value, _USER_FIELDS))
        user = body_dict(result.body)
        evidence = [self._evidence(f"Entra user {user.get('userPrincipalName', observable.value)}: "
                                   f"accountEnabled={user.get('accountEnabled')}", reference=user.get("id"),
                                   data={k: user[k] for k in _USER_FIELDS if k in user})]
        return self._enrichment(observable, Verdict.UNKNOWN, risk=0, confidence=60, evidence=evidence)

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        """``investigate_user`` reads the user; authentication / activity types read sign-ins."""
        subject = query.subject.value
        if query.action_type is ActionType.INVESTIGATE_USER:
            result = self._send(builders.get_user(subject, _USER_FIELDS))
            findings = (body_dict(result.body),)
        elif query.action_type in (ActionType.INVESTIGATE_AUTHENTICATION, ActionType.SEARCH_USER_ACTIVITY):
            result = self._send(builders.list_sign_ins(user=subject, since=query.time_from, top=query.limit))
            findings = tuple(s for s in body_list(result.body, "value") if isinstance(s, dict))[: query.limit]
        else:
            raise CapabilityNotSupportedError(f"entra cannot run {query.action_type.value}", integration=self.name)
        evidence = (self._evidence(f"{len(findings)} Entra record(s) for {subject} ({query.action_type.value})"),) \
            if findings else ()
        return InvestigationResult(integration=self.name, action_type=query.action_type, subject=query.subject,
                                   findings=findings, evidence=evidence, api_calls=self._calls([result]))

    # ------------------------------------------------------------ state reads --
    def _account_enabled(self, user: str) -> tuple[bool | None, HttpResultLike]:
        result = self._send(builders.get_user(user, ("accountEnabled",), kind=_V))
        value = body_dict(result.body).get("accountEnabled")
        return (value if isinstance(value, bool) else None), result

    def _assignments(self, principal_id: str) -> tuple[list[dict[str, Any]], HttpResultLike]:
        result = self._send(builders.list_role_assignments(principal_id, kind=_V))
        return [a for a in body_list(result.body, "value") if isinstance(a, dict)], result

    def _role_triple(self, request: ActionRequest) -> tuple[str, str, str]:
        return (str(self._param(request, "role_definition_id")), str(self._param(request, "principal_id")),
                str(self._param(request, "directory_scope_id")))

    def current_state(self, request: ActionRequest) -> TargetStateCheck:
        """Account state for disable/enable; other types report UNKNOWN."""
        if request.action_type not in _ENABLE_TYPES:
            return super().current_state(request)
        enabled, result = self._account_enabled(request.target)
        desired = enabled is _ENABLE_TYPES[request.action_type]
        state = TargetState.UNKNOWN if enabled is None else (
            TargetState.IN_DESIRED_STATE if desired else TargetState.NOT_IN_DESIRED_STATE)
        return TargetStateCheck(state=state, detail=f"accountEnabled={enabled}", api_calls=self._calls([result]))

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """Re-read the user or the role assignments (VERIFIED reads)."""
        action = request.action_type
        if action in _ENABLE_TYPES:
            enabled, result = self._account_enabled(request.target)
            ok = enabled is _ENABLE_TYPES[action]
            return self._verdict(request, ok, "get_user", f"accountEnabled={enabled}", result)
        if action is ActionType.REVOKE_SESSIONS:
            return self._verify_revoke(request, outcome)
        if action is ActionType.REMOVE_PRIVILEGED_ROLE:
            assignments, result = self._assignments(str(self._param(request, "principal_id")))
            ok = all(a.get("id") != request.target for a in assignments)
            return self._verdict(request, ok, "list_role_assignments", f"assignment {'absent' if ok else 'present'}",
                                 result)
        if action is ActionType.RESTORE_PRIVILEGED_ROLE:
            role, principal, scope = self._role_triple(request)
            assignments, result = self._assignments(principal)
            ok = any(_same_role(a, role, scope) for a in assignments)
            return self._verdict(request, ok, "list_role_assignments", f"assignment {'present' if ok else 'absent'}",
                                 result)
        return super().verify(request, outcome)

    def _verdict(self, request: ActionRequest, ok: bool, method: str, details: str,
                 result: HttpResultLike) -> VerificationResult:
        status = VerificationStatus.VERIFIED if ok else VerificationStatus.NOT_VERIFIED
        return self._verification(request, status, method=method, details=details, results=[result])

    def _verify_revoke(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        if outcome is None:
            return self._verification(request, VerificationStatus.UNABLE_TO_VERIFY, method="none",
                                      details="no action time to compare signInSessionsValidFromDateTime with")
        result = self._send(builders.get_user(request.target, ("signInSessionsValidFromDateTime",), kind=_V))
        valid_from = _parse_dt(body_dict(result.body).get("signInSessionsValidFromDateTime"))
        if valid_from is None:
            return self._verification(request, VerificationStatus.UNABLE_TO_VERIFY, method="get_user",
                                      details="signInSessionsValidFromDateTime missing", results=[result])
        ok = valid_from >= utc(outcome.executed_at)
        return self._verdict(request, ok, "get_user", f"signInSessionsValidFromDateTime={valid_from.isoformat()}",
                             result)

    # --------------------------------------------------------------- writes --
    def _set_enabled(self, request: ActionRequest, enabled: bool) -> ActionOutcome:
        current, before = self._account_enabled(request.target)
        rollback = {"user": request.target} if not enabled else None
        if current is enabled:
            return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[before], rollback=rollback,
                                 message=f"accountEnabled already {enabled}")
        changed = self._send(builders.set_account_enabled(request.target, enabled))
        return self._outcome(ActionResultStatus.SUCCESS, results=[before, changed], rollback=rollback,
                             message=f"accountEnabled set to {enabled} for {request.target}")

    @state_changing
    def disable_user(self, request: ActionRequest) -> ActionOutcome:
        """Set ``accountEnabled`` to false."""
        return self._set_enabled(request, False)

    @state_changing
    def enable_user(self, request: ActionRequest) -> ActionOutcome:
        """Set ``accountEnabled`` back to true (release)."""
        return self._set_enabled(request, True)

    @state_changing
    def revoke_sessions(self, request: ActionRequest) -> ActionOutcome:
        """Invalidate refresh tokens and session cookies (not reversible; may take minutes)."""
        result = self._send(builders.revoke_sign_in_sessions(request.target))
        return self._outcome(ActionResultStatus.SUCCESS, results=[result],
                             message=f"sign-in sessions revoked for {request.target}")

    @state_changing
    def confirm_user_compromised(self, request: ActionRequest) -> ActionOutcome:
        """Mark the user compromised in Identity Protection (Entra ID P2; no verified rollback)."""
        results: list[HttpResultLike] = []
        # The object id always comes from a lookup of the approved target, never from params alone.
        lookup = self._send(builders.get_user(request.target, ("id", "userPrincipalName", "mail")))
        results.append(lookup)
        record = body_dict(lookup.body)
        user_id = record.get("id")
        if not user_id:
            raise ApiError(f"entra: no object id returned for {request.target}", integration=self.name)
        if record.get("userPrincipalName") or record.get("mail"):
            self._require_identity(request, str(user_id), record, ("userPrincipalName", "mail"), what="user")
        wanted = request.params.get("user_id")
        if wanted and str(wanted).strip().lower() != str(user_id).strip().lower():
            raise InvalidTargetError(
                f"entra: params.user_id {wanted!r} is not the object id of the approved target "
                f"{request.target!r}; refusing to act on another account", integration=self.name)
        results.append(self._send(builders.confirm_compromised([str(user_id)])))
        return self._outcome(ActionResultStatus.SUCCESS, results=results, external_ref=str(user_id),
                             message=f"{request.target} confirmed compromised")

    @state_changing
    def remove_privileged_role(self, request: ActionRequest) -> ActionOutcome:
        """Delete the role assignment ``request.target`` after capturing it for the release."""
        principal = str(self._param(request, "principal_id"))
        assignments, before = self._assignments(principal)
        match = next((a for a in assignments if a.get("id") == request.target), None)
        if match is None:
            rollback = {"principal_id": principal, "role_definition_id": request.params.get("role_definition_id"),
                        "directory_scope_id": request.params.get("directory_scope_id")}
            return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[before], rollback=rollback,
                                 message=f"role assignment {request.target} not present")
        rollback = {"principal_id": principal, "role_definition_id": match.get("roleDefinitionId"),
                    "directory_scope_id": match.get("directoryScopeId")}
        deleted = self._send(builders.remove_role_assignment(request.target))
        return self._outcome(ActionResultStatus.SUCCESS, results=[before, deleted], rollback=rollback,
                             external_ref=request.target, message=f"role assignment {request.target} removed")

    @state_changing
    def restore_privileged_role(self, request: ActionRequest) -> ActionOutcome:
        """Recreate the captured role assignment (release)."""
        role, principal, scope = self._role_triple(request)
        assignments, before = self._assignments(principal)
        if any(_same_role(a, role, scope) for a in assignments):
            return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[before],
                                 message="role assignment already present")
        created = self._send(builders.create_role_assignment(role, principal, scope))
        new_id = body_dict(created.body).get("id")
        return self._outcome(ActionResultStatus.SUCCESS, results=[before, created],
                             external_ref=str(new_id) if new_id else None, message="role assignment restored")

    @state_changing
    def reset_password(self, request: ActionRequest) -> ActionOutcome:
        """UNVERIFIED."""
        self._unverified("reset_password")

    @state_changing
    def reset_mfa(self, request: ActionRequest) -> ActionOutcome:
        """UNVERIFIED."""
        self._unverified("reset_mfa")

    @state_changing
    def revoke_app_credentials(self, request: ActionRequest) -> ActionOutcome:
        """UNVERIFIED."""
        self._unverified("revoke_app_credentials")
