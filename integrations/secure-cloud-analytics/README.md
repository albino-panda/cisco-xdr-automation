# Integration: Cisco Secure Cloud Analytics

Network behaviour analytics. Stub only: every endpoint is UNVERIFIED.

Runtime adapter: `src/xdr_response/integrations/secure_cloud_analytics/` (integration name `secure_cloud_analytics`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.5 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `api_key`: `SCA_API_KEY`

Base URL in the example configuration: `not set`. Enabled in the example configuration: no.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): none
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): none
- Read (investigation and enrichment) actions: none
- Enrichment observable types: none
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `list_alerts` | READ | UNVERIFIED |  |  |
| `list_observations` | READ | UNVERIFIED |  |  |
| `get_device` | READ | UNVERIFIED |  |  |
| `state_changing_ops` | STATE_CHANGING | NOT_APPLICABLE |  |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Stub: every method raises `UnverifiedEndpointError` and health is `UNKNOWN`; its alerts reach the workflows only as Cisco XDR incidents (docs/architecture.md section 15.5).
- Rate limit: Unknown: no official API reference was read.
