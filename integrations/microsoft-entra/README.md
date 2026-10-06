# Integration: Microsoft Entra ID (via Microsoft Graph)

User and sign-in investigation, session revocation and account disablement.

## Authentication

App registration with client credentials (certificate preferred over secret).

Environment variables (see the root [`.env.example`](../../.env.example)):

- `ENTRA_TENANT_ID`
- `ENTRA_CLIENT_ID`
- `ENTRA_CLIENT_SECRET`

## Least-privilege permissions

- User.Read.All
- AuditLog.Read.All
- IdentityRiskyUser.Read.All
- User.RevokeSessions.All (revoke-session)
- User.EnableDisableAccount.All (disable-user)

## API surface used

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| User profile and sign-ins | `GET /v1.0/users/{id}, GET /v1.0/auditLogs/signIns` |
| Revoke sessions | `POST /v1.0/users/{id}/revokeSignInSessions` |
| Disable / enable account | `PATCH /v1.0/users/{id} {"accountEnabled": false}` |

Vendor documentation: <https://learn.microsoft.com/graph/api/overview>

## Used by atomics

[`investigate-user`](../../atomic/investigate-user/README.md), [`disable-user`](../../atomic/disable-user/README.md), [`revoke-session`](../../atomic/revoke-session/README.md)

## Notes

- Grant the write permissions to a separate app registration used only by containment atomics.
- Session revocation can take minutes to propagate; access tokens stay valid until expiry unless Continuous Access Evaluation applies.
