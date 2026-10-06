# Integration: Cisco XDR

Incident source of truth, threat-intel enrichment, automation engine, incident notes and SOC notification targets.

## Authentication

OAuth2 client credentials (Administration > API Clients). Token from `/iroh/oauth2/token` on the regional platform URL.

Environment variables (see the root [`.env.example`](../../.env.example)):

- `XDR_CLIENT_ID`
- `XDR_CLIENT_SECRET`
- `XDR_API_BASE_URL`

## Least-privilege permissions

- Incidents (read/write)
- Enrich / Inspect
- Private Intelligence (read/write)
- Response (for pivot actions)

## API surface used

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Inspect observables | `POST /iroh/iroh-inspect/inspect` |
| Enrich observables | `POST /iroh/iroh-enrich/observe/observables` |
| Incident read / patch / notes | `/iroh/private-intel/incident` |
| Automation webhook trigger | `XDR_WEBHOOK_URL from Automate > Rules > Webhooks` |

Vendor documentation: <https://developer.cisco.com/docs/cisco-xdr/>

## Used by atomics

[`enrich-ip`](../../atomic/enrich-ip/README.md), [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-hash`](../../atomic/enrich-hash/README.md), [`investigate-user`](../../atomic/investigate-user/README.md), [`investigate-host`](../../atomic/investigate-host/README.md), [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md), [`create-ticket`](../../atomic/create-ticket/README.md), [`notify-soc`](../../atomic/notify-soc/README.md)

## Notes

- Regional base URLs match the mail-bomb detector: `visibility.amp.cisco.com`, `visibility.eu.amp.cisco.com`, `visibility.apjc.amp.cisco.com`.
- Inside XDR Automation the Cisco-managed *XDR - ...* atomics already handle auth; these variables are only needed for code that runs outside XDR.
- Notification targets (Webex, Microsoft Teams, Slack, SMTP) are configured under Automate > Targets and used by `notify-soc`.
