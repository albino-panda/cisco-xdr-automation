# Integration: VirusTotal

Public reputation for hashes, domains, URLs and IPs (third-party disclosure policy applies).

Runtime adapter: `src/xdr_response/integrations/virustotal/` (integration name `virustotal`). The capability and API tables below follow the adapter's capability manifest (`manifest.py`); [`docs/integrations.md`](../../docs/integrations.md) section 2.13 is the source of truth for every endpoint and its VERIFIED or UNVERIFIED status, and `tools/validation/check_endpoints.py` checks the manifest against it.

## Authentication

Secret names in `config/integrations.example.yaml` (environment variables or mounted secret files under `XDR_RESPONSE_SECRETS_DIR`; never values in config):

- `api_key`: `VT_API_KEY`

Base URL in the example configuration: `https://www.virustotal.com/api/v3`. Enabled in the example configuration: yes.

## Capabilities

- State-changing actions (each needs a human approval and runs only through the orchestrator and the guard): none
- Verified by an independent read after execution: none
- Executed but not verifiable (`UNABLE_TO_VERIFY`, checked by hand): none
- Read (investigation and enrichment) actions: `enrich_domain`, `enrich_hash`, `enrich_ip`, `enrich_url`
- Enrichment observable types: `domain`, `ip`, `ipv6`, `md5`, `sha1`, `sha256`, `url`
- Native Cisco XDR response action route: no

## API surface (from the manifest)

| Operation | Kind | Status | Method and path | Source |
|---|---|---|---|---|
| `file_report` | READ | VERIFIED | `GET /files/{id}` | https://docs.virustotal.com/reference/file-info |
| `domain_report` | READ | VERIFIED | `GET /domains/{domain}` | https://docs.virustotal.com/reference/domain-info |
| `ip_report` | READ | VERIFIED | `GET /ip_addresses/{ip}` | https://docs.virustotal.com/reference/ip-info |
| `url_report` | READ | VERIFIED | `GET /urls/{id}` | https://docs.virustotal.com/reference/url-info |
| `state_changing_ops` | STATE_CHANGING | NOT_APPLICABLE |  |  |

An UNVERIFIED operation is never called: the adapter raises `UnverifiedEndpointError` instead.

## Used by atomics

The legacy atomic names and their runtime action types are in the [atomic table](../../atomic/README.md).

## Notes

- Rate limit: Public API: 4 requests/min and 500/day, non-commercial use only; 429 QuotaExceededError.
