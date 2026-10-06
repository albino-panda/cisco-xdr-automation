# Integration: Cloudflare

Edge blocking of IPs and URLs for internet-facing applications, and Zero Trust Gateway lists.

## Authentication

Scoped API token (never the global API key).

Environment variables (see the root [`.env.example`](../../.env.example)):

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_IP_LIST_ID`
- `CLOUDFLARE_GATEWAY_LIST_ID`

## Least-privilege permissions

- Account Filter Lists: Edit
- Zero Trust: Edit (Gateway lists)

## API surface used

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Account IP list items | `POST\|DELETE /accounts/{account_id}/rules/lists/{list_id}/items` |
| Gateway list items | `PATCH /accounts/{account_id}/gateway/lists/{list_id}` |

Vendor documentation: <https://developers.cloudflare.com/api/>

## Used by atomics

[`block-domain`](../../atomic/block-domain/README.md), [`block-ip`](../../atomic/block-ip/README.md), [`block-url`](../../atomic/block-url/README.md)

## Notes

- Reference the IP list from a WAF custom rule once; automation then only edits list items.
