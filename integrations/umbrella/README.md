# Integration: Cisco Umbrella / Secure Access

Domain and IP reputation, DNS activity lookups and destination-list blocking.

## Authentication

API key + secret exchanged for an OAuth2 token at `https://api.umbrella.com/auth/v2/token`.

Environment variables (see the root [`.env.example`](../../.env.example)):

- `UMBRELLA_API_KEY`
- `UMBRELLA_API_SECRET`
- `UMBRELLA_BLOCK_LIST_ID`

## Least-privilege permissions

- Investigate (read)
- Reports (read)
- Policies > Destination Lists (read/write)

## API surface used

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Domain / IP investigation | `GET /investigate/v2/domains/categorization/{domain}` |
| DNS activity | `GET /reports/v2/activity/dns` |
| Destination list add / remove | `POST /policies/v2/destinationlists/{id}/destinations[/remove]` |

Vendor documentation: <https://developer.cisco.com/docs/cloud-security/>

## Used by atomics

[`enrich-ip`](../../atomic/enrich-ip/README.md), [`enrich-domain`](../../atomic/enrich-domain/README.md), [`block-domain`](../../atomic/block-domain/README.md), [`block-url`](../../atomic/block-url/README.md)

## Notes

- Create one dedicated block destination list per automation source so entries are easy to audit and expire.
