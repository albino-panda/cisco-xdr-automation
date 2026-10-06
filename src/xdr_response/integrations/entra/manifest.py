"""Capability manifest for Microsoft Entra ID through Microsoft Graph (docs/integrations.md section 2.8)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations._graph import GRAPH_SECRET_NAMES, token_operation
from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, ObservableType, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE"]

_V, _U = EndpointStatus.VERIFIED, EndpointStatus.UNVERIFIED
_R, _VF, _SC = OperationKind.READ, OperationKind.VERIFY, OperationKind.STATE_CHANGING

_GRAPH = "https://learn.microsoft.com/en-us/graph/api/"
SRC_USER_GET = _GRAPH + "user-get?view=graph-rest-1.0"
SRC_SIGNINS = _GRAPH + "signin-list?view=graph-rest-1.0"
SRC_USER_UPDATE = _GRAPH + "user-update?view=graph-rest-1.0"
SRC_REVOKE = _GRAPH + "user-revokesigninsessions?view=graph-rest-1.0"
SRC_CONFIRM = _GRAPH + "riskyuser-confirmcompromised?view=graph-rest-1.0"
SRC_ROLES_LIST = _GRAPH + "rbacapplication-list-roleassignments?view=graph-rest-1.0"
SRC_ROLE_DELETE = _GRAPH + "unifiedroleassignment-delete?view=graph-rest-1.0"
SRC_ROLE_POST = _GRAPH + "rbacapplication-post-roleassignments?view=graph-rest-1.0"

_BASE = "https://graph.microsoft.com/v1.0"

REQUIRED_SECRETS: Mapping[str, str] = GRAPH_SECRET_NAMES
CONFIG_OPTIONS: Mapping[str, str] = {
    "oauth_scope": "Graph client-credentials scope (required; the string is UNVERIFIED in section 2.8)",
}
HEALTH_PROBE = "list_sign_ins"

MANIFEST = CapabilityManifest(
    integration="entra",
    display_name="Microsoft Entra ID",
    supported_actions=frozenset({A.DISABLE_USER, A.ENABLE_USER, A.REVOKE_SESSIONS, A.CONFIRM_USER_COMPROMISED,
                                 A.REMOVE_PRIVILEGED_ROLE, A.RESTORE_PRIVILEGED_ROLE}),
    verifiable_actions=frozenset({A.DISABLE_USER, A.ENABLE_USER, A.REVOKE_SESSIONS, A.REMOVE_PRIVILEGED_ROLE,
                                  A.RESTORE_PRIVILEGED_ROLE}),
    read_actions=frozenset({A.ENRICH_USER, A.INVESTIGATE_USER, A.INVESTIGATE_AUTHENTICATION,
                            A.SEARCH_USER_ACTIVITY}),
    enrichment_types=frozenset({ObservableType.USER, ObservableType.EMAIL_ADDRESS}),
    operations=(
        token_operation(),
        OperationSpec(name="get_user", kind=_R, status=_V, method="GET", path=_BASE + "/users/{id}",
                      source=SRC_USER_GET, action_types=(A.ENRICH_USER, A.INVESTIGATE_USER)),
        OperationSpec(name="list_sign_ins", kind=_R, status=_V, method="GET", path=_BASE + "/auditLogs/signIns",
                      source=SRC_SIGNINS, action_types=(A.INVESTIGATE_AUTHENTICATION, A.SEARCH_USER_ACTIVITY)),
        OperationSpec(name="update_account_enabled", kind=_SC, status=_V, method="PATCH",
                      path=_BASE + "/users/{id}", source=SRC_USER_UPDATE,
                      action_types=(A.DISABLE_USER, A.ENABLE_USER)),
        OperationSpec(name="revoke_sign_in_sessions", kind=_SC, status=_V, method="POST",
                      path=_BASE + "/users/{id}/revokeSignInSessions", source=SRC_REVOKE,
                      action_types=(A.REVOKE_SESSIONS,)),
        OperationSpec(name="confirm_compromised", kind=_SC, status=_V, method="POST",
                      path=_BASE + "/identityProtection/riskyUsers/confirmCompromised", source=SRC_CONFIRM,
                      action_types=(A.CONFIRM_USER_COMPROMISED,)),
        OperationSpec(name="risky_user", kind=_VF, status=_U),
        OperationSpec(name="dismiss_risky_user", kind=_SC, status=_U),
        OperationSpec(name="list_role_assignments", kind=_R, status=_V, method="GET",
                      path=_BASE + "/roleManagement/directory/roleAssignments", source=SRC_ROLES_LIST),
        OperationSpec(name="remove_role_assignment", kind=_SC, status=_V, method="DELETE",
                      path=_BASE + "/roleManagement/directory/roleAssignments/{id}", source=SRC_ROLE_DELETE,
                      action_types=(A.REMOVE_PRIVILEGED_ROLE,)),
        OperationSpec(name="create_role_assignment", kind=_SC, status=_V, method="POST",
                      path=_BASE + "/roleManagement/directory/roleAssignments", source=SRC_ROLE_POST,
                      action_types=(A.RESTORE_PRIVILEGED_ROLE,)),
        # Not in the section 2.8 table: no endpoint was read for these remediation types.
        OperationSpec(name="reset_password", kind=_SC, status=_U, action_types=(A.RESET_PASSWORD,)),
        OperationSpec(name="reset_mfa", kind=_SC, status=_U, action_types=(A.RESET_MFA,)),
        OperationSpec(name="revoke_app_credentials", kind=_SC, status=_U, action_types=(A.REVOKE_APP_CREDENTIALS,)),
    ),
    escalation_hint="Entra ID privileged role administrator",
    rate_limit_note="429 with Retry-After (wait that long; exponential backoff when absent).",
)
