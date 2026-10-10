# Integration: Cisco XDR

Incident source of truth, observable enrichment and native response actions (respond/trigger).

Runtime adapter: `src/xdr_response/integrations/cisco_xdr/` (integration name `cisco_xdr`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.1 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

OAuth2 client credentials (Administration > API Clients). Token from `/iroh/oauth2/token` on the regional platform URL.

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `client_id`: `XDR_CLIENT_ID`
- `client_secret`: `XDR_CLIENT_SECRET`

Base URL in the example configuration: `https://visibility.amp.cisco.com`. Enabled in the example configuration: yes.

## Least-privilege permissions

- Incidents (read/write)
- Enrich / Inspect
- Private Intelligence (read/write)
- Response (native response actions, respond/trigger)
- Use separate read-only and read/write credentials where the product supports it.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): `block_domain`, `block_hash`, `block_ip`, `block_url`, `delete_email`, `disable_user`, `enable_user`, `isolate_endpoint`, `quarantine_email`, `release_email`, `release_endpoint`, `unblock_domain`, `unblock_hash`, `unblock_ip`, `unblock_url`
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): `block_domain`, `block_hash`, `block_ip`, `block_url`, `delete_email`, `disable_user`, `enable_user`, `isolate_endpoint`, `quarantine_email`, `release_email`, `release_endpoint`, `unblock_domain`, `unblock_hash`, `unblock_ip`, `unblock_url`
- Read (investigation and enrichment) actions: `enrich_domain`, `enrich_email_address`, `enrich_endpoint`, `enrich_hash`, `enrich_ip`, `enrich_url`, `enrich_user`, `investigate_domain`, `investigate_email`, `investigate_endpoint`, `investigate_hash`, `investigate_ip`, `investigate_user`, `search_domain_enterprise`, `search_hash_enterprise`, `search_ip_enterprise`, `update_incident_status`
- Enrichment observable types: `domain`, `email_address`, `email_message_id`, `file_path`, `hostname`, `ip`, `ipv6`, `mac_address`, `md5`, `sha1`, `sha256`, `url`, `user`
- Native Cisco XDR response action route: yes

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `token` | READ | VERIFIED | `POST https://visibility.amp.cisco.com/iroh/oauth2/token` | https://developer.cisco.com/docs/cisco-xdr/authentication/ |
| `deliberate_observables` | READ | VERIFIED | `POST /iroh/iroh-enrich/deliberate/observables` | https://developer.cisco.com/docs/cisco-xdr/enrich-api-guide/ |
| `observe_observables` | READ | VERIFIED | `POST /iroh/iroh-enrich/observe/observables` | https://developer.cisco.com/docs/cisco-xdr/enrich-api-guide/ |
| `refer_observables` | READ | VERIFIED | `POST /iroh/iroh-enrich/refer/observables` | https://developer.cisco.com/docs/cisco-xdr/enrich-api-guide/ |
| `list_response_actions` | READ | VERIFIED | `POST /iroh/iroh-response/respond/observables` | https://developer.cisco.com/docs/cisco-xdr/response-api-guide/ |
| `trigger_response_action` | STATE_CHANGING | VERIFIED | `POST /iroh/iroh-response/respond/trigger/{module-instance-id}/{action-id}` | https://developer.cisco.com/docs/cisco-xdr/trigger-an-action/ |
| `get_incident_summary` | READ | VERIFIED | `GET https://visibility.amp.cisco.com/iroh/private-intel/incident/{incident_id}/summary` | https://developer.cisco.com/docs/cisco-xdr/incident-management-api-guide/ |
| `get_incident_full` | READ | VERIFIED | `GET https://conure.us.security.cisco.com/incidents/{incident-id}` | https://developer.cisco.com/docs/cisco-xdr/get-a-full-summary-of-the-incident-everything-seen-in-xdr/ |
| `create_incident_bundle` | STATE_CHANGING | VERIFIED | `POST /iroh/private-intel/bundle/import` | https://developer.cisco.com/docs/cisco-xdr/incident-management-api-guide/ |
| `update_incident_status` | BOOKKEEPING | VERIFIED | `POST https://intel.amp.cisco.com/ctia/incident/{id}/status` | https://developer.cisco.com/docs/cisco-xdr/global-intelligence-api-incident-update-an-incident-status/ |
| `update_incident_status_private_intel` | BOOKKEEPING | UNVERIFIED | `POST https://private.intel.amp.cisco.com/ctia/incident/{id}/status` |  |
| `add_incident_note` | BOOKKEEPING | UNVERIFIED |  |  |
| `search_incidents` | READ | UNVERIFIED |  |  |
| `inspect` | READ | UNVERIFIED |  |  |
| `list_workflows` | READ | VERIFIED | `GET https://automate.us.security.cisco.com/api/v1/workflows` | https://developer.cisco.com/docs/cisco-xdr/automation-api-guide/ |
| `run_workflow` | STATE_CHANGING | UNVERIFIED |  |  |
| `approval_tasks` | READ | UNVERIFIED |  |  |
| `verify_native_action` | VERIFY | NOT_APPLICABLE |  |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Regional base URLs match the mail-bomb detector: `visibility.amp.cisco.com`, `visibility.eu.amp.cisco.com`, `visibility.apjc.amp.cisco.com`.
- Inside XDR Automation the Cisco-managed *XDR - ...* atomics handle their own auth; these secrets are used by the external orchestrator (`xdr_response`).
- SOC notifications from the orchestrator go to a local JSONL outbox. The incident note endpoint (`add_incident_note`) is UNVERIFIED, so nothing is posted to the XDR incident (docs/architecture.md section 15.4). XDR Automation targets (Webex, Microsoft Teams, Slack, SMTP) stay available to the trigger workflow on the XDR side.
- Native response actions run through the VERIFIED respond/trigger endpoints, but the action status read is UNVERIFIED, so every native action ends `UNABLE_TO_VERIFY` (docs/architecture.md section 15.1).
- Escalation: Cisco XDR administrator
- Rate limit: Not documented: honor 429 and Retry-After, otherwise exponential backoff.
