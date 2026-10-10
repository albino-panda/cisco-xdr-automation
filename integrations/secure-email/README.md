# Integration: Cisco Secure Email Threat Defense

Message search and remediation of delivered mail: quarantine, release and delete.

Runtime adapter: `src/xdr_response/integrations/secure_email/` (integration name `secure_email`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.3 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Email Threat Defense: API client ID, client secret and API key (`x-api-key`). Secure Email Gateway/Cloud Gateway: AsyncOS API user.

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `client_id`: `ETD_CLIENT_ID`
- `client_secret`: `ETD_CLIENT_SECRET`
- `api_key`: `ETD_API_KEY`

Base URL in the example configuration: `https://api.us.etd.cisco.com`. Enabled in the example configuration: yes.

## Least-privilege permissions

- ETD tenant in Read/Write remediation mode for move/quarantine
- Read-only is enough for message search
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): `delete_email`, `quarantine_email`, `release_email`
- Verified by an independent read after execution: `delete_email`, `quarantine_email`, `release_email`
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): none
- Read (investigation and enrichment) actions: `investigate_email`, `search_email_campaign`
- Enrichment observable types: none
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `token` | READ | VERIFIED | `POST https://api.{us|de|au|in|ae}.etd.cisco.com/v1/oauth/token` | https://developer.cisco.com/docs/message-search-api/authentication/ |
| `search_messages` | READ | VERIFIED | `POST /v1/messages/search` | https://developer.cisco.com/docs/message-search-api/message-search-api/ |
| `move_messages` | STATE_CHANGING | VERIFIED | `POST /v1/messages/move` | https://developer.cisco.com/docs/message-search-api/remediation-and-reclassification-api/ |
| `release_to_inbox` | STATE_CHANGING | VERIFIED | `POST /v1/messages/move` | https://developer.cisco.com/docs/message-search-api/remediation-and-reclassification-api/ |
| `message_status` | VERIFY | VERIFIED | `POST /v1/messages/status` | https://developer.cisco.com/docs/message-search-api/status-api/ |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Variable names match the mail-bomb detector so both projects can share one `.env` template.
- ETD API limits are shared with the mail-bomb detector: about 2 requests/second and 10 000/day per tenant.
- Escalation: Microsoft 365 administrator (403 means the tenant lacks write permission)
- Rate limit: Not documented; search pages hold at most 100 messages, remediation 100 IDs per call.
