# Integration: Cisco Meraki

Network client lookup, MX L3 firewall IP blocks and network client blocks.

Runtime adapter: `src/xdr_response/integrations/meraki/` (integration name `meraki`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.7 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Dashboard API key (`Authorization: Bearer`), scoped to an organisation admin with the least privilege needed.

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `api_key`: `MERAKI_API_KEY`

Base URL in the example configuration: `https://api.meraki.com/api/v1`. Enabled in the example configuration: yes.

## Least-privilege permissions

- Read for client lookup
- Network write for firewall rules
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): `block_ip`, `block_network_client`, `restore_network_client`, `unblock_ip`
- Verified by an independent read after execution: `block_ip`, `block_network_client`, `restore_network_client`, `unblock_ip`
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): none
- Read (investigation and enrichment) actions: none
- Enrichment observable types: none
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `search_clients` | READ | VERIFIED | `GET /organizations/{organizationId}/clients/search` | https://developer.cisco.com/meraki/api-v1/get-organization-clients-search/ |
| `get_client_policy` | VERIFY | VERIFIED | `GET /networks/{networkId}/clients/{clientId}/policy` | https://developer.cisco.com/meraki/api-v1/get-network-client-policy/ |
| `update_client_policy` | STATE_CHANGING | VERIFIED | `PUT /networks/{networkId}/clients/{clientId}/policy` | https://developer.cisco.com/meraki/api-v1/update-network-client-policy/ |
| `get_l3_rules` | VERIFY | VERIFIED | `GET /networks/{networkId}/appliance/firewall/l3FirewallRules` | https://developer.cisco.com/meraki/api-v1/get-network-appliance-firewall-l-3-firewall-rules/ |
| `update_l3_rules` | STATE_CHANGING | VERIFIED | `PUT /networks/{networkId}/appliance/firewall/l3FirewallRules` | https://developer.cisco.com/meraki/api-v1/update-network-appliance-firewall-l-3-firewall-rules/ |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- The L3 rules PUT replaces the whole rule set. Always read, modify and write, and keep a copy of the previous rules for rollback.
- Escalation: Meraki network administrator
- Rate limit: 10 req/s per organization (burst +10 in the first second); 429 with Retry-After.
