# Integration: Cisco Secure Endpoint

Endpoint telemetry, device trajectory, host isolation and simple custom detection (hash block) lists.

## Authentication

API client ID + API key (Basic auth) for API v1, or an XDR-issued token for API v3. Use a read/write client only for containment atomics.

Environment variables (see the root [`.env.example`](../../.env.example)):

- `SE_CLIENT_ID`
- `SE_API_KEY`
- `SE_API_BASE_URL`

## Least-privilege permissions

- Read-only client for enrichment and investigation
- Read/write client for isolation and file lists

## API surface used

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Computer lookup and trajectory | `GET /v1/computers, GET /v1/computers/{guid}/trajectory` |
| Host isolation start / stop / status | `PUT\|DELETE\|GET /v1/computers/{guid}/isolation` |
| Simple custom detection list | `POST\|DELETE /v1/file_lists/{list_guid}/files/{sha256}` |

Vendor documentation: <https://developer.cisco.com/docs/secure-endpoint/>

## Used by atomics

[`enrich-hash`](../../atomic/enrich-hash/README.md), [`investigate-host`](../../atomic/investigate-host/README.md), [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md), [`block-hash`](../../atomic/block-hash/README.md)

## Notes

- Isolation must be allowed by the connector policy, otherwise the API call fails.
- Keep an isolation allow-list in the policy so analysts and the XDR cloud stay reachable.
