# Integration: Cloudflare

Edge blocking of IPs and URLs for internet-facing applications, and Zero Trust Gateway lists.

**Spec only: there is no runtime adapter.** No integration named `cloudflare` exists in `src/xdr_response/integrations/` or in `docs/integrations.md`, so the router never sends an action here: domain, URL and IP blocks route to Cisco XDR native actions, Umbrella, Meraki or Defender for Endpoint. Before an adapter could be built, its endpoints must be VERIFIED in `docs/integrations.md` (docs/architecture.md section 15).

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

## API surface (not implemented)

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Account IP list items | `POST\|DELETE /accounts/{account_id}/rules/lists/{list_id}/items` |
| Gateway list items | `PATCH /accounts/{account_id}/gateway/lists/{list_id}` |

Vendor documentation: <https://developers.cloudflare.com/api/>

## Used by atomics

None at runtime. The catalog actions it could serve (`block_domain`, `block_url`, `block_ip`) are listed in the [atomic table](../../atomic/README.md); they route to other integrations.

## Notes

- Reference the IP list from a WAF custom rule once; automation then only edits list items.
