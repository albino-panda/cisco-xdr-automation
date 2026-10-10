# Integration: Cisco Umbrella

Domain and URL reputation, DNS activity and destination-list blocks for domains and URLs.

Runtime adapter: `src/xdr_response/integrations/umbrella/` (integration name `umbrella`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.6 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

API key + secret exchanged for an OAuth2 token at `https://api.umbrella.com/auth/v2/token`.

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `api_key`: `UMBRELLA_API_KEY`
- `api_secret`: `UMBRELLA_API_SECRET`

Base URL in the example configuration: `https://api.umbrella.com`. Enabled in the example configuration: yes.

## Least-privilege permissions

- Investigate (read)
- Reports (read)
- Policies > Destination Lists (read/write)
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): `block_domain`, `block_url`, `unblock_domain`, `unblock_url`
- Verified by an independent read after execution: `block_domain`, `block_url`, `unblock_domain`, `unblock_url`
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): none
- Read (investigation and enrichment) actions: `enrich_domain`
- Enrichment observable types: `domain`
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `token` | READ | VERIFIED | `POST https://api.umbrella.com/auth/v2/token` | https://developer.cisco.com/docs/cloud-security/umbrella-api-getting-started/ |
| `domain_categorization` | READ | VERIFIED | `GET https://api.umbrella.com/investigate/v2/domains/categorization/{domain}` | https://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-investigate-investigate-api-domain-status-and-categorization-get-domain-status-and-categorization/ |
| `security_scores` | READ | UNVERIFIED | `GET /investigate/v2/security/name/{domain}` |  |
| `risk_score` | READ | UNVERIFIED | `GET /investigate/v2/domains/risk-score/{domain}` |  |
| `list_destination_lists` | READ | VERIFIED | `GET https://api.umbrella.com/policies/v2/destinationlists` | https://developer.cisco.com/docs/cloud-security/umbrella-api-reference-destination-lists-overview/ |
| `list_destinations` | VERIFY | VERIFIED | `GET /policies/v2/destinationlists/{destinationListId}/destinations` | https://developer.cisco.com/docs/cloud-security/umbrella-api-reference-destination-lists-overview/ |
| `add_destinations` | STATE_CHANGING | VERIFIED | `POST /policies/v2/destinationlists/{destinationListId}/destinations` | https://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-policies-destination-lists-api-destinations-add-destinations-to-destination-list/ |
| `remove_destinations` | STATE_CHANGING | VERIFIED | `DELETE /policies/v2/destinationlists/{destinationListId}/destinations/remove` | https://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-policies-destination-lists-api-destinations-delete-destinations-from-destination-list/ |
| `block_ip` | STATE_CHANGING | UNVERIFIED | `POST /policies/v2/destinationlists/{destinationListId}/destinations` |  |
| `unblock_ip` | STATE_CHANGING | UNVERIFIED | `DELETE /policies/v2/destinationlists/{destinationListId}/destinations/remove` |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Create one dedicated block destination list per automation source so entries are easy to audit and expire.
- Escalation: Umbrella / Secure Access policy administrator
- Rate limit: Token 20/min per key; policies 2000/min and 6000/h; Investigate 3 req/s; on 429 wait 1 s.
