# Integration: Splunk (optional)

Optional SIEM search and audit forwarding to HTTP Event Collector. Disabled by default.

Runtime adapter: `src/xdr_response/integrations/splunk/` (integration name `splunk`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.16 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Splunk authentication token (search) and HTTP Event Collector token (audit sink).

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `token`: `SPLUNK_TOKEN`
- `hec_token`: `SPLUNK_HEC_TOKEN`

Base URL in the example configuration: `https://splunk.example.test:8089`. Enabled in the example configuration: no.

## Least-privilege permissions

- Role limited to the security indexes needed
- HEC token bound to an audit index
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): none
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): none
- Read (investigation and enrichment) actions: `investigate_authentication`, `investigate_network_connection`, `search_domain_enterprise`, `search_hash_enterprise`, `search_ip_enterprise`, `search_related_endpoints`, `search_related_users`, `search_user_activity`
- Enrichment observable types: none
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `create_search_job` | READ | VERIFIED | `POST /services/search/jobs` | https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/9.4/rest-api-tutorials/creating-searches-using-the-rest-api |
| `get_search_results` | READ | VERIFIED | `GET /services/search/jobs/{sid}/results` | https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/9.4/rest-api-tutorials/creating-searches-using-the-rest-api |
| `auth_login` | READ | VERIFIED | `POST /services/auth/login` | https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/9.4/rest-api-tutorials/creating-searches-using-the-rest-api |
| `auth_bearer_token` | READ | UNVERIFIED |  |  |
| `export` | READ | UNVERIFIED | `GET /services/search/v2/jobs/export` |  |
| `forward_audit` | BOOKKEEPING | VERIFIED | `POST https://{host}:8088/services/collector/event` | https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/http-event-collector-examples |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Keep saved searches in Splunk and call them by name so queries are versioned with your Splunk content.
- Audit forwarding runs outside the response path: schedule `tools/deployment/forward_audit.py`, which verifies the audit chain first and resumes from a checkpoint (docs/deployment.md section 5.1).
- Rate limit: Not documented on the pages read.
