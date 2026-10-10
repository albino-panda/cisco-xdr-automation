# Integration: Microsoft Defender XDR (Graph Security)

Cross-product alerts (alerts_v2) and advanced hunting through Microsoft Graph security (read only).

Runtime adapter: `src/xdr_response/integrations/microsoft_cloud/` (integration name `microsoft_cloud`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.12 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `tenant_id`: `ENTRA_TENANT_ID`
- `client_id`: `ENTRA_CLIENT_ID`
- `client_secret`: `ENTRA_CLIENT_SECRET`

Base URL in the example configuration: `https://graph.microsoft.com`. Enabled in the example configuration: yes.

## Least-privilege permissions

Microsoft Graph or API permissions of the VERIFIED operations (docs/integrations.md):

- `SecurityAlert.Read.All` (List alerts)
- `ThreatHunting.Read.All` (Advanced hunting (KQL))
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): none
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): none
- Read (investigation and enrichment) actions: `investigate_domain`, `investigate_email`, `investigate_endpoint`, `investigate_hash`, `investigate_ip`, `investigate_network_connection`, `investigate_process`, `investigate_user`, `search_domain_enterprise`, `search_hash_enterprise`, `search_ip_enterprise`, `search_related_endpoints`, `search_related_users`, `search_user_activity`
- Enrichment observable types: none
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `token` | READ | VERIFIED | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp |
| `list_alerts` | READ | VERIFIED | `GET https://graph.microsoft.com/v1.0/security/alerts_v2` | https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0 |
| `run_hunting_query` | READ | VERIFIED | `POST https://graph.microsoft.com/v1.0/security/runHuntingQuery` | https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0 |
| `list_incidents` | READ | UNVERIFIED | `GET /security/incidents` |  |
| `cloud_resource_actions` | STATE_CHANGING | UNVERIFIED |  |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Escalation: Microsoft 365 Defender administrator
- Rate limit: Graph throttling: 429 with Retry-After.
