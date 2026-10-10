# Integration: Microsoft Defender for Office 365

Email remediation through Microsoft Graph (quarantine, delete, release).

Runtime adapter: `src/xdr_response/integrations/defender_o365/` (integration name `defender_o365`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.10 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `tenant_id`: `ENTRA_TENANT_ID`
- `client_id`: `ENTRA_CLIENT_ID`
- `client_secret`: `ENTRA_CLIENT_SECRET`

Base URL in the example configuration: `https://graph.microsoft.com`. Enabled in the example configuration: yes.

## Least-privilege permissions

Microsoft Graph or API permissions of the VERIFIED operations (docs/integrations.md):

- `SecurityAnalyzedMessage.ReadWrite.All` (Remediate email (move to junk/inbox/deleted items, soft/hard delete, move to quarantine))
- same (Rollback)
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): `delete_email`, `quarantine_email`, `release_email`
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): `delete_email`, `quarantine_email`, `release_email`
- Read (investigation and enrichment) actions: none
- Enrichment observable types: none
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `token` | READ | VERIFIED | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp |
| `remediate` | STATE_CHANGING | VERIFIED | `POST https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate` | https://learn.microsoft.com/en-us/graph/api/security-analyzedemail-remediate?view=graph-rest-beta |
| `rollback_to_inbox` | STATE_CHANGING | VERIFIED | `POST https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate` | https://learn.microsoft.com/en-us/graph/api/security-analyzedemail-remediate?view=graph-rest-beta |
| `list_analyzed_emails` | READ | UNVERIFIED |  |  |
| `quarantine_release` | STATE_CHANGING | UNVERIFIED |  |  |
| `verify_remediation` | VERIFY | UNVERIFIED |  |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Remediation executes, but the remediation status read is UNVERIFIED, so every email action ends `UNABLE_TO_VERIFY`.
- Escalation: Microsoft 365 security administrator
- Rate limit: Graph throttling: 429 with Retry-After. Application permission and global cloud only.
