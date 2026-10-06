"""Microsoft Entra ID adapter (Graph v1.0)."""
from __future__ import annotations

from datetime import timedelta

import pytest

from tests.fixtures.factories import FIXED_NOW
from tests.unit.vendors._helpers import Router, action_request, body_of, json_response, make_adapter, run_authorized
from xdr_response.integrations.entra import builders
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    InvestigationQuery,
    Observable,
    ObservableType,
    OperationKind,
    TargetState,
    VerificationStatus,
)

USER = "j.doe@example.com"
USER_PATH = f"/v1.0/users/{USER}"
ROLES = "/v1.0/roleManagement/directory/roleAssignments"
ROLE = {"id": "ra-0001", "roleDefinitionId": "rd-0001", "principalId": "pr-0001", "directoryScopeId": "/"}


def test_entra_builders_match_documentation():
    patch = builders.set_account_enabled(USER, False)
    assert (patch.method, patch.path, patch.json, patch.kind) == ("PATCH", "v1.0/users/j.doe@example.com",
                                                                  {"accountEnabled": False},
                                                                  OperationKind.STATE_CHANGING)
    assert builders.revoke_sign_in_sessions(USER).path == "v1.0/users/j.doe@example.com/revokeSignInSessions"
    assert builders.confirm_compromised(["u1"]).json == {"userIds": ["u1"]}
    assert builders.list_role_assignments("p'1").params == {"$filter": "principalId eq 'p''1'"}
    assert builders.remove_role_assignment("ra/1").path == "v1.0/roleManagement/directory/roleAssignments/ra%2F1"
    assert builders.create_role_assignment("rd", "pr", "/").json == {"roleDefinitionId": "rd", "principalId": "pr",
                                                                     "directoryScopeId": "/"}
    signins = builders.list_sign_ins(user=USER, since=FIXED_NOW, top=5000)
    assert signins.params == {"$filter": "createdDateTime ge 2026-01-15T12:00:00.000000Z and "
                                         "userPrincipalName eq 'j.doe@example.com'", "$top": "1000"}


def test_disable_user_reads_then_patches_and_verifies():
    router = Router().add("GET", USER_PATH, json_response(200, {"accountEnabled": True}),
                          json_response(200, {"accountEnabled": False}))
    router.add("PATCH", USER_PATH, json_response(204))
    adapter = make_adapter("entra", router)
    request = action_request(ActionType.DISABLE_USER, "entra")
    outcome = run_authorized(adapter, request)
    assert dict(router.calls[0].url.params) == {"$select": "accountEnabled"}
    assert router.calls[1].method == "PATCH" and body_of(router.calls[1]) == {"accountEnabled": False}
    assert outcome.status is ActionResultStatus.SUCCESS
    assert outcome.rollback_params == {"integration": "entra", "user": USER}
    assert adapter.verify(request, outcome).status is VerificationStatus.VERIFIED


def test_disable_user_already_disabled_is_idempotent():
    router = Router().add("GET", USER_PATH, json_response(200, {"accountEnabled": False}))
    adapter = make_adapter("entra", router)
    request = action_request(ActionType.DISABLE_USER, "entra")
    assert run_authorized(adapter, request).status is ActionResultStatus.ALREADY_CONTAINED
    assert [c.method for c in router.calls] == ["GET"]
    assert adapter.current_state(request).state is TargetState.IN_DESIRED_STATE


def test_enable_user_is_the_release():
    router = Router().add("GET", USER_PATH, json_response(200, {"accountEnabled": False}))
    router.add("PATCH", USER_PATH, json_response(204))
    outcome = run_authorized(make_adapter("entra", router), action_request(ActionType.ENABLE_USER, "entra"))
    assert body_of(router.last()) == {"accountEnabled": True} and outcome.rollback_params == {}


@pytest.mark.parametrize(("offset", "expected"), [(timedelta(seconds=5), VerificationStatus.VERIFIED),
                                                  (timedelta(minutes=-5), VerificationStatus.NOT_VERIFIED)])
def test_revoke_sessions_and_verify_against_action_time(offset, expected):
    valid_from = (FIXED_NOW + offset).strftime("%Y-%m-%dT%H:%M:%SZ")
    router = Router().add("POST", f"{USER_PATH}/revokeSignInSessions", json_response(200, {"value": True}))
    router.add("GET", USER_PATH, json_response(200, {"signInSessionsValidFromDateTime": valid_from}))
    adapter = make_adapter("entra", router)
    request = action_request(ActionType.REVOKE_SESSIONS, "entra")
    outcome = run_authorized(adapter, request)
    assert outcome.rollback_params == {}
    assert adapter.verify(request, outcome).status is expected
    assert adapter.verify(request, None).status is VerificationStatus.UNABLE_TO_VERIFY


def test_confirm_compromised_resolves_object_id():
    router = Router().add("GET", USER_PATH, json_response(200, {"id": "u-0001"}))
    router.add("POST", "/v1.0/identityProtection/riskyUsers/confirmCompromised", json_response(204))
    adapter = make_adapter("entra", router)
    request = action_request(ActionType.CONFIRM_USER_COMPROMISED, "entra")
    assert run_authorized(adapter, request).external_ref == "u-0001"
    assert body_of(router.last()) == {"userIds": ["u-0001"]}
    assert adapter.verify(request, None).status is VerificationStatus.UNABLE_TO_VERIFY


def test_remove_role_captures_assignment_before_delete():
    router = Router().add("GET", ROLES, json_response(200, {"value": [ROLE]}), json_response(200, {"value": []}))
    router.add("DELETE", f"{ROLES}/ra-0001", json_response(204))
    adapter = make_adapter("entra", router)
    request = action_request(ActionType.REMOVE_PRIVILEGED_ROLE, "entra", principal_id="pr-0001")
    outcome = run_authorized(adapter, request)
    assert [c.method for c in router.calls] == ["GET", "DELETE"]
    assert dict(router.calls[0].url.params) == {"$filter": "principalId eq 'pr-0001'"}
    assert outcome.rollback_params == {"integration": "entra", "principal_id": "pr-0001",
                                       "role_definition_id": "rd-0001", "directory_scope_id": "/"}
    assert adapter.verify(request, outcome).status is VerificationStatus.VERIFIED


def test_restore_role_posts_the_captured_triple():
    router = Router().add("GET", ROLES, json_response(200, {"value": []}),
                          json_response(200, {"value": [{**ROLE, "id": "ra-0002"}]}))
    router.add("POST", ROLES, json_response(201, {"id": "ra-0002"}))
    adapter = make_adapter("entra", router)
    request = action_request(ActionType.RESTORE_PRIVILEGED_ROLE, "entra", principal_id="pr-0001",
                             role_definition_id="rd-0001", directory_scope_id="/")
    outcome = run_authorized(adapter, request)
    assert body_of(router.calls[1]) == {"roleDefinitionId": "rd-0001", "principalId": "pr-0001",
                                        "directoryScopeId": "/"}
    assert outcome.external_ref == "ra-0002"
    assert adapter.verify(request, outcome).status is VerificationStatus.VERIFIED


def test_investigate_authentication_reads_sign_ins():
    router = Router().add("GET", "/v1.0/auditLogs/signIns", json_response(200, {"value": [{"id": "s1"}]}))
    query = InvestigationQuery(action_type=ActionType.INVESTIGATE_AUTHENTICATION, limit=10,
                               subject=Observable(type=ObservableType.USER, value=USER))
    assert make_adapter("entra", router).investigate(query).findings == ({"id": "s1"},)
    assert dict(router.last().url.params)["$top"] == "10"
