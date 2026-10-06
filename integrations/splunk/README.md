# Integration: Splunk

Historical log search for enrichment and investigation, and an optional event sink for automation audit records.

## Authentication

Splunk authentication token (search) and HTTP Event Collector token (audit sink).

Environment variables (see the root [`.env.example`](../../.env.example)):

- `SPLUNK_BASE_URL`
- `SPLUNK_TOKEN`
- `SPLUNK_HEC_URL`
- `SPLUNK_HEC_TOKEN`

## Least-privilege permissions

- Role limited to the security indexes needed
- HEC token bound to an audit index

## API surface used

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Run a search | `POST /services/search/jobs (then poll results)` |
| Send audit event | `POST /services/collector/event` |

Vendor documentation: <https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog>

## Used by atomics

[`enrich-ip`](../../atomic/enrich-ip/README.md), [`investigate-user`](../../atomic/investigate-user/README.md), [`investigate-host`](../../atomic/investigate-host/README.md)

## Notes

- Keep saved searches in Splunk and call them by name so queries are versioned with your Splunk content.
