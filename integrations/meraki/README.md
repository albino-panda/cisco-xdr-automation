# Integration: Cisco Meraki

Network client lookup and perimeter IP blocking on MX appliances.

## Authentication

Dashboard API key (`Authorization: Bearer`), scoped to an organisation admin with the least privilege needed.

Environment variables (see the root [`.env.example`](../../.env.example)):

- `MERAKI_API_KEY`
- `MERAKI_ORG_ID`
- `MERAKI_NETWORK_IDS`

## Least-privilege permissions

- Read for client lookup
- Network write for firewall rules

## API surface used

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Find a client | `GET /organizations/{orgId}/clients/search` |
| MX L3 firewall rules | `GET\|PUT /networks/{networkId}/appliance/firewall/l3FirewallRules` |

Vendor documentation: <https://developer.cisco.com/meraki/api-v1/>

## Used by atomics

[`investigate-host`](../../atomic/investigate-host/README.md), [`block-ip`](../../atomic/block-ip/README.md)

## Notes

- The L3 rules PUT replaces the whole rule set. Always read, modify and write, and keep a copy of the previous rules for rollback.
