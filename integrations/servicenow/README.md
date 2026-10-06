# Integration: ServiceNow

Incident / security incident ticketing and status sync.

## Authentication

OAuth2 (preferred) or basic auth for an integration user.

Environment variables (see the root [`.env.example`](../../.env.example)):

- `SNOW_INSTANCE_URL`
- `SNOW_CLIENT_ID`
- `SNOW_CLIENT_SECRET`
- `SNOW_ASSIGNMENT_GROUP`

## Least-privilege permissions

- Integration user limited to the incident (or sn_si_incident) table

## API surface used

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Create / update ticket | `POST\|PATCH /api/now/table/incident` |

Vendor documentation: <https://developer.servicenow.com/>

## Used by atomics

[`create-ticket`](../../atomic/create-ticket/README.md)

## Notes

- Store the XDR incident ID in a correlation field so re-runs update the same ticket instead of creating duplicates.
