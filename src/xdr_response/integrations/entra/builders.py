"""Pure request builders for Microsoft Entra ID via Graph v1.0 (docs/integrations.md section 2.8).

Paths are relative to ``https://graph.microsoft.com`` and start with ``v1.0/``.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from xdr_response.integrations._adapter_support import ApiRequest, segment
from xdr_response.integrations._graph import odata_string
from xdr_response.models import OperationKind, format_datetime

__all__ = ["get_user", "list_sign_ins", "set_account_enabled", "revoke_sign_in_sessions", "confirm_compromised",
           "list_role_assignments", "remove_role_assignment", "create_role_assignment"]

_SC = OperationKind.STATE_CHANGING


def _user(user: str) -> str:
    return f"v1.0/users/{segment(user, safe='@')}"


def get_user(user: str, select: Sequence[str] = (), *, kind: OperationKind = OperationKind.READ) -> ApiRequest:
    """``GET /users/{id or userPrincipalName}`` with optional ``$select``. Source: user-get."""
    params = {"$select": ",".join(select)} if select else None
    return ApiRequest(operation="get_user", method="GET", path=_user(user), params=params, kind=kind)


def list_sign_ins(*, user: str | None = None, since: datetime | None = None, top: int | None = None) -> ApiRequest:
    """``GET /auditLogs/signIns`` with an optional ``$filter`` (time and user) and ``$top`` (max 1000)."""
    clauses = []
    if since is not None:
        clauses.append(f"createdDateTime ge {format_datetime(since)}")
    if user:
        clauses.append(f"userPrincipalName eq {odata_string(user)}")
    params: dict[str, str] = {}
    if clauses:
        params["$filter"] = " and ".join(clauses)
    if top is not None:
        params["$top"] = str(max(1, min(top, 1000)))
    return ApiRequest(operation="list_sign_ins", method="GET", path="v1.0/auditLogs/signIns", params=params or None)


def set_account_enabled(user: str, enabled: bool) -> ApiRequest:
    """``PATCH /users/{id}`` with ``{"accountEnabled": bool}`` (STATE_CHANGING, 204). Source: user-update."""
    return ApiRequest(operation="update_account_enabled", method="PATCH", path=_user(user), kind=_SC,
                      json={"accountEnabled": enabled}, expected=(200, 204))


def revoke_sign_in_sessions(user: str) -> ApiRequest:
    """``POST /users/{id}/revokeSignInSessions`` (STATE_CHANGING). Source: user-revokesigninsessions."""
    return ApiRequest(operation="revoke_sign_in_sessions", method="POST", path=f"{_user(user)}/revokeSignInSessions",
                      kind=_SC)


def confirm_compromised(user_ids: Sequence[str]) -> ApiRequest:
    """``POST /identityProtection/riskyUsers/confirmCompromised`` with ``{"userIds": [...]}`` (204)."""
    return ApiRequest(operation="confirm_compromised", method="POST",
                      path="v1.0/identityProtection/riskyUsers/confirmCompromised", kind=_SC,
                      json={"userIds": list(user_ids)}, expected=(200, 204))


def list_role_assignments(principal_id: str, *, kind: OperationKind = OperationKind.READ) -> ApiRequest:
    """``GET /roleManagement/directory/roleAssignments?$filter=principalId eq '..'``."""
    return ApiRequest(operation="list_role_assignments", method="GET",
                      path="v1.0/roleManagement/directory/roleAssignments", kind=kind,
                      params={"$filter": f"principalId eq {odata_string(principal_id)}"})


def remove_role_assignment(assignment_id: str) -> ApiRequest:
    """``DELETE /roleManagement/directory/roleAssignments/{id}`` (STATE_CHANGING, 204)."""
    return ApiRequest(operation="remove_role_assignment", method="DELETE",
                      path=f"v1.0/roleManagement/directory/roleAssignments/{segment(assignment_id)}",
                      kind=_SC, expected=(204,))


def create_role_assignment(role_definition_id: str, principal_id: str, directory_scope_id: str) -> ApiRequest:
    """``POST /roleManagement/directory/roleAssignments`` with the captured triple (STATE_CHANGING, 201)."""
    return ApiRequest(operation="create_role_assignment", method="POST",
                      path="v1.0/roleManagement/directory/roleAssignments", kind=_SC, expected=(201,),
                      json={"roleDefinitionId": role_definition_id, "principalId": principal_id,
                            "directoryScopeId": directory_scope_id})
