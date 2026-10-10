# Integration: LevelBlue OTX (AlienVault)

Independent community reputation (third-party disclosure policy applies).

Runtime adapter: `src/xdr_response/integrations/alienvault_otx/` (integration name `alienvault_otx`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.14 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `api_key`: `OTX_API_KEY`

Base URL in the example configuration: `https://otx.alienvault.com`. Enabled in the example configuration: yes.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): none
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): none
- Read (investigation and enrichment) actions: `enrich_domain`, `enrich_hash`, `enrich_ip`, `enrich_url`
- Enrichment observable types: `domain`, `hostname`, `ip`, `ipv6`, `md5`, `sha1`, `sha256`, `url`
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `indicators_ipv4` | READ | VERIFIED | `GET /api/v1/indicators/IPv4/{value}/{section}` | https://otx.alienvault.com/assets/static/external_api.html |
| `indicators_ipv6` | READ | VERIFIED | `GET /api/v1/indicators/IPv6/{value}/{section}` | https://otx.alienvault.com/assets/static/external_api.html |
| `indicators_domain` | READ | VERIFIED | `GET /api/v1/indicators/domain/{value}/{section}` | https://otx.alienvault.com/assets/static/external_api.html |
| `indicators_hostname` | READ | VERIFIED | `GET /api/v1/indicators/hostname/{value}/{section}` | https://otx.alienvault.com/assets/static/external_api.html |
| `indicators_file` | READ | VERIFIED | `GET /api/v1/indicators/file/{value}/{section}` | https://otx.alienvault.com/assets/static/external_api.html |
| `indicators_url` | READ | VERIFIED | `GET /api/v1/indicators/url/{value}/{section}` | https://otx.alienvault.com/assets/static/external_api.html |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Rate limit: Not documented: honor 429 and back off.
