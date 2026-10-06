# Integration: Cisco Secure Email (Threat Defense / Gateway)

Message search, quarantine and remediation of delivered mail.

## Authentication

Email Threat Defense: API client ID, client secret and API key (`x-api-key`). Secure Email Gateway/Cloud Gateway: AsyncOS API user.

Environment variables (see the root [`.env.example`](../../.env.example)):

- `ETD_CLIENT_ID`
- `ETD_CLIENT_SECRET`
- `ETD_API_KEY`
- `ETD_API_BASE_URL`

## Least-privilege permissions

- ETD tenant in Read/Write remediation mode for move/quarantine
- Read-only is enough for message search

## API surface used

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Message search | `POST /v1/messages/search` |
| Move or reclassify messages | `POST /v1/messages/remediate (max 100 ids per call)` |

Vendor documentation: <https://developer.cisco.com/docs/>

## Used by atomics

[`quarantine-email`](../../atomic/quarantine-email/README.md)

## Notes

- Variable names match the mail-bomb detector so both projects can share one `.env` template.
- ETD API limits are shared with the mail-bomb detector: about 2 requests/second and 10 000/day per tenant.
