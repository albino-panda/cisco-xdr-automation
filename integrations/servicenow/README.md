# Integration: ServiceNow

Incident / security incident ticketing and status sync.

**Spec only: there is no runtime adapter.** `create_ticket` is a catalog bookkeeping operation with no executing adapter, so no ticket is created anywhere (docs/architecture.md section 15.4). Before an adapter could be built, its endpoints must be VERIFIED in `docs/integrations.md`.

## Authentication

OAuth2 (preferred) or basic auth for an integration user.

Environment variables (see the root [`.env.example`](../../.env.example)):

- `SNOW_INSTANCE_URL`
- `SNOW_CLIENT_ID`
- `SNOW_CLIENT_SECRET`
- `SNOW_ASSIGNMENT_GROUP`

## Least-privilege permissions

- Integration user limited to the incident (or sn_si_incident) table

## API surface (not implemented)

Verify every endpoint against the vendor documentation for your region and product version before building on it.

| Purpose | Endpoint |
|---|---|
| Create / update ticket | `POST\|PATCH /api/now/table/incident` |

Vendor documentation: <https://developer.servicenow.com/>

## Used by atomics

None at runtime. `create-ticket` maps to the catalog bookkeeping operation `create_ticket` in the [atomic table](../../atomic/README.md), which has no executing adapter.

## Notes

- Store the XDR incident ID in a correlation field so re-runs update the same ticket instead of creating duplicates.
