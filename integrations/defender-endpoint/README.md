# Integration: Microsoft Defender for Endpoint

Machines and alerts, machine isolation and release, file and network indicators.

Runtime adapter: `src/xdr_response/integrations/defender_endpoint/` (integration name `defender_endpoint`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.9 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `tenant_id`: `ENTRA_TENANT_ID`
- `client_id`: `MDE_CLIENT_ID`
- `client_secret`: `MDE_CLIENT_SECRET`

Base URL in the example configuration: `https://api.security.microsoft.com/api`. Enabled in the example configuration: yes.

## Least-privilege permissions

Microsoft Graph or API permissions of the VERIFIED operations (docs/integrations.md):

- `Machine.ReadWrite.All` (app) (Get machine)
- `Machine.Isolate` (Isolate)
- `Machine.Isolate` (Release from isolation)
- `Machine.ReadWrite.All` (Get machine action)
- `Machine.ReadWrite.All` (List machine actions (idempotency pre-check))
- `Ti.ReadWrite.All` (Block indicator (hash/IP/domain/URL))
- `Ti.ReadWrite.All` (Remove indicator)
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): `block_domain`, `block_hash`, `block_ip`, `block_url`, `isolate_endpoint`, `release_endpoint`, `unblock_domain`, `unblock_hash`, `unblock_ip`, `unblock_url`
- Verified by an independent read after execution: `isolate_endpoint`, `release_endpoint`
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): `block_domain`, `block_hash`, `block_ip`, `block_url`, `unblock_domain`, `unblock_hash`, `unblock_ip`, `unblock_url`
- Read (investigation and enrichment) actions: `enrich_endpoint`, `investigate_endpoint`
- Enrichment observable types: `endpoint_id`, `hostname`
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `token` | READ | VERIFIED | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp |
| `get_machine` | READ | VERIFIED | `GET /api/machines/{id}` | https://learn.microsoft.com/en-us/defender-endpoint/api/get-machine-by-id |
| `isolate` | STATE_CHANGING | VERIFIED | `POST /api/machines/{id}/isolate` | https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine |
| `unisolate` | STATE_CHANGING | VERIFIED | `POST /api/machines/{id}/unisolate` | https://learn.microsoft.com/en-us/defender-endpoint/api/unisolate-machine |
| `get_machine_action` | VERIFY | VERIFIED | `GET /api/machineactions/{id}` | https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineaction-object |
| `list_machine_actions` | VERIFY | VERIFIED | `GET /api/machineactions` | https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineactions-collection |
| `submit_indicator` | STATE_CHANGING | VERIFIED | `POST /api/indicators` | https://learn.microsoft.com/en-us/defender-endpoint/api/post-ti-indicator |
| `delete_indicator` | STATE_CHANGING | VERIFIED | `DELETE /api/indicators/{id}` | https://learn.microsoft.com/en-us/defender-endpoint/api/delete-ti-indicator-by-id |
| `list_indicators` | VERIFY | UNVERIFIED | `GET /api/indicators` |  |
| `terminate_process` | STATE_CHANGING | UNVERIFIED |  |  |
| `quarantine_file` | STATE_CHANGING | UNVERIFIED |  |  |
| `restore_file` | STATE_CHANGING | UNVERIFIED |  |  |
| `remove_application` | STATE_CHANGING | UNVERIFIED |  |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Isolation and release are verified through the machine-action reads. Indicator blocks execute but the indicator list read is UNVERIFIED, so they end `UNABLE_TO_VERIFY`. Process, file and application remediation are UNVERIFIED and never called.
- Escalation: Defender for Endpoint security administrator
- Rate limit: 100 calls/min and 1,500 calls/h per API; at most 15,000 active indicators.
