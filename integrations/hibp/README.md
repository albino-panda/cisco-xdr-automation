# Integration: Have I Been Pwned

Credential exposure of an email address (third-party disclosure policy applies).

Runtime adapter: `src/xdr_response/integrations/hibp/` (integration name `hibp`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.15 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `api_key`: `HIBP_API_KEY`

Base URL in the example configuration: `https://haveibeenpwned.com/api/v3`. Enabled in the example configuration: yes.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): none
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): none
- Read (investigation and enrichment) actions: `enrich_email_address`
- Enrichment observable types: `email_address`
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `breached_account` | READ | VERIFIED | `GET /breachedaccount/{account}` | https://haveibeenpwned.com/API/v3 |
| `paste_account` | READ | VERIFIED | `GET /pasteaccount/{account}` | https://haveibeenpwned.com/API/v3 |
| `all_breaches` | READ | VERIFIED | `GET /breaches` | https://haveibeenpwned.com/API/v3 |
| `pwned_passwords_range` | READ | VERIFIED | `GET https://api.pwnedpasswords.com/range/{first5sha1}` | https://haveibeenpwned.com/API/v3 |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Rate limit: Depends on the subscription; 429 carries retry-after in seconds. Attribution (CC BY 4.0) is required when breach data is shown.
