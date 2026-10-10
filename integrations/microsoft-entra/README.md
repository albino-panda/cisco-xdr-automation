# Integration: Microsoft Entra ID

Users, sign-ins and directory roles; disable and enable, session revocation, role removal and restore.

Runtime adapter: `src/xdr_response/integrations/entra/` (integration name `entra`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.8 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

App registration with client credentials (certificate preferred over secret).

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `tenant_id`: `ENTRA_TENANT_ID`
- `client_id`: `ENTRA_CLIENT_ID`
- `client_secret`: `ENTRA_CLIENT_SECRET`

Base URL in the example configuration: `https://graph.microsoft.com`. Enabled in the example configuration: yes.

## Least-privilege permissions

Microsoft Graph or API permissions of the VERIFIED operations (docs/integrations.md):

- `User.Read.All`; reading `accountEnabled` needs `User.EnableDisableAccount.All` + `User.Read.All` (Get user (incl. `accountEnabled`, `signInSessionsValidFromDateTime` via `$select`))
- `AuditLog.Read.All` (Sign-in logs)
- `User.EnableDisableAccount.All` + `User.Read.All` (Disable / enable account)
- `User.RevokeSessions.All` (Revoke sign-in sessions)
- `IdentityRiskyUser.ReadWrite.All` (Confirm user compromised)
- `RoleManagement.Read.Directory` (List role assignments)
- `RoleManagement.ReadWrite.Directory` (Remove role)
- `RoleManagement.ReadWrite.Directory` (Restore role (rollback))
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): `confirm_user_compromised`, `disable_user`, `enable_user`, `remove_privileged_role`, `restore_privileged_role`, `revoke_sessions`
- Verified by an independent read after execution: `disable_user`, `enable_user`, `remove_privileged_role`, `restore_privileged_role`, `revoke_sessions`
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): `confirm_user_compromised`
- Read (investigation and enrichment) actions: `enrich_user`, `investigate_authentication`, `investigate_user`, `search_user_activity`
- Enrichment observable types: `email_address`, `user`
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `token` | READ | VERIFIED | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp |
| `get_user` | READ | VERIFIED | `GET https://graph.microsoft.com/v1.0/users/{id}` | https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0 |
| `list_sign_ins` | READ | VERIFIED | `GET https://graph.microsoft.com/v1.0/auditLogs/signIns` | https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0 |
| `update_account_enabled` | STATE_CHANGING | VERIFIED | `PATCH https://graph.microsoft.com/v1.0/users/{id}` | https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0 |
| `revoke_sign_in_sessions` | STATE_CHANGING | VERIFIED | `POST https://graph.microsoft.com/v1.0/users/{id}/revokeSignInSessions` | https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0 |
| `confirm_compromised` | STATE_CHANGING | VERIFIED | `POST https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised` | https://learn.microsoft.com/en-us/graph/api/riskyuser-confirmcompromised?view=graph-rest-1.0 |
| `risky_user` | VERIFY | UNVERIFIED |  |  |
| `dismiss_risky_user` | STATE_CHANGING | UNVERIFIED |  |  |
| `list_role_assignments` | READ | VERIFIED | `GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments` | https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0 |
| `remove_role_assignment` | STATE_CHANGING | VERIFIED | `DELETE https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/{id}` | https://learn.microsoft.com/en-us/graph/api/unifiedroleassignment-delete?view=graph-rest-1.0 |
| `create_role_assignment` | STATE_CHANGING | VERIFIED | `POST https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments` | https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleassignments?view=graph-rest-1.0 |
| `reset_password` | STATE_CHANGING | UNVERIFIED |  |  |
| `reset_mfa` | STATE_CHANGING | UNVERIFIED |  |  |
| `revoke_app_credentials` | STATE_CHANGING | UNVERIFIED |  |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Grant the write permissions to a separate app registration used only by the orchestrator's approved-containment path.
- Session revocation can take minutes to propagate; access tokens stay valid until expiry unless Continuous Access Evaluation applies.
- Password reset, MFA reset and application credential revocation are UNVERIFIED and never called; they are manual steps (docs/architecture.md section 15.2). Confirm compromised executes but cannot be read back (`UNABLE_TO_VERIFY`).
- Escalation: Entra ID privileged role administrator
- Rate limit: 429 with Retry-After (wait that long; exponential backoff when absent).
