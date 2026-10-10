# Integration: Cisco Secure Endpoint

Endpoint telemetry and device trajectory, host isolation and release.

Runtime adapter: `src/xdr_response/integrations/secure_endpoint/` (integration name `secure_endpoint`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.2 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

API client ID + API key (HTTP Basic auth) for API v1. Use a read/write client only for the orchestrator's approved-containment path.

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `client_id`: `SE_CLIENT_ID`
- `api_key`: `SE_API_KEY`

Base URL in the example configuration: `https://api.amp.cisco.com`. Enabled in the example configuration: yes.

## Least-privilege permissions

- Read-only client for enrichment and investigation
- Read/write client for isolation and release (file lists are UNVERIFIED and never called)
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): `isolate_endpoint`, `release_endpoint`
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): `isolate_endpoint`, `release_endpoint`
- Read (investigation and enrichment) actions: `enrich_endpoint`, `investigate_endpoint`
- Enrichment observable types: `endpoint_id`
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `list_computers` | READ | VERIFIED | `GET /v1/computers` | https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/222226-automate-start-stop-isolation-on-multipl.html |
| `get_computer` | READ | VERIFIED | `GET /v1/computers/{connector_guid}` | https://developer.cisco.com/docs/secure-endpoint/whats-new/ |
| `get_trajectory` | READ | VERIFIED | `GET /v1/computers/{connector_guid}/trajectory` | https://developer.cisco.com/docs/secure-endpoint/whats-new/ |
| `list_audit_logs` | READ | VERIFIED | `GET /v1/audit_logs` | https://developer.cisco.com/docs/secure-endpoint/whats-new/ |
| `isolate` | STATE_CHANGING | VERIFIED | `PUT /v1/computers/{connector_guid}/isolation` | https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/222226-automate-start-stop-isolation-on-multipl.html |
| `stop_isolation` | STATE_CHANGING | VERIFIED | `DELETE /v1/computers/{connector_guid}/isolation` | https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/222226-automate-start-stop-isolation-on-multipl.html |
| `get_isolation` | VERIFY | UNVERIFIED | `GET /v1/computers/{connector_guid}/isolation` |  |
| `list_events` | READ | UNVERIFIED | `GET /v1/events` |  |
| `block_hash` | STATE_CHANGING | UNVERIFIED | `POST /v1/file_lists/{guid}/files/{sha256}` |  |
| `unblock_hash` | STATE_CHANGING | UNVERIFIED | `DELETE /v1/file_lists/{guid}/files/{sha256}` |  |
| `get_file_list_entry` | VERIFY | UNVERIFIED | `GET /v1/file_lists/{guid}/files/{sha256}` |  |
| `terminate_process` | STATE_CHANGING | UNVERIFIED |  |  |
| `quarantine_file` | STATE_CHANGING | UNVERIFIED |  |  |
| `restore_file` | STATE_CHANGING | UNVERIFIED |  |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Isolation must be allowed by the connector policy, otherwise the API call fails.
- Keep an isolation allow-list in the policy so analysts and the XDR cloud stay reachable.
- The real adapter executes only isolation and release. Hash blocks (simple custom detection lists), process termination and file quarantine are UNVERIFIED, so those recommendations are `UNROUTED` (manual handling) unless another enabled adapter has a VERIFIED write. The isolation status read is UNVERIFIED, so isolation and release end `UNABLE_TO_VERIFY` and the analyst confirms them in the console (docs/architecture.md section 15.1).
- Isolation unlock codes stay in the Secure Endpoint console; they are never copied to notes, tickets or notifications.
- Escalation: Secure Endpoint administrator
- Rate limit: Hourly quota reported in X-RateLimit-* headers; 429 when exceeded.
