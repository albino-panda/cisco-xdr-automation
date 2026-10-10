# Integration: Microsoft Intune

Managed device lookup and remote lock.

Runtime adapter: `src/xdr_response/integrations/intune/` (integration name `intune`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.11 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `tenant_id`: `ENTRA_TENANT_ID`
- `client_id`: `ENTRA_CLIENT_ID`
- `client_secret`: `ENTRA_CLIENT_SECRET`

Base URL in the example configuration: `https://graph.microsoft.com`. Enabled in the example configuration: yes.

## Least-privilege permissions

Microsoft Graph or API permissions of the VERIFIED operations (docs/integrations.md):

- `DeviceManagementManagedDevices.Read.All` (Get managed device (includes `deviceActionResults[].actionState`, `complianceState`, `lastSyncDateTime`))
- `DeviceManagementManagedDevices.PrivilegedOperations.All` (Remote lock)
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): `lock_device`
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): `lock_device`
- Read (investigation and enrichment) actions: `enrich_endpoint`, `investigate_endpoint`
- Enrichment observable types: `endpoint_id`
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `token` | READ | VERIFIED | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp |
| `get_managed_device` | READ | VERIFIED | `GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{managedDeviceId}` | https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-get?view=graph-rest-1.0 |
| `remote_lock` | STATE_CHANGING | VERIFIED | `POST https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{managedDeviceId}/remoteLock` | https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-remotelock?view=graph-rest-1.0 |
| `retire_wipe` | STATE_CHANGING | UNVERIFIED |  |  |
| `sync_scan` | STATE_CHANGING | UNVERIFIED |  |  |
| `remove_application` | STATE_CHANGING | UNVERIFIED |  |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Only remote lock is VERIFIED; it has no read-back, so it ends `UNABLE_TO_VERIFY`. Other device actions (wipe, retire, application removal) are UNVERIFIED and never called.
- Only remote lock is VERIFIED. The managed-device read is VERIFIED, but the `actionName` of the lock in `deviceActionResults` was not read, so the lock cannot be matched and ends `UNABLE_TO_VERIFY`. Other device actions (wipe, retire, application removal) are UNVERIFIED and never called.
- Escalation: Intune administrator
- Rate limit: Graph throttling: 429 with Retry-After. Requires an active Intune licence.
