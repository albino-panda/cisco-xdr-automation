# Atomic: Create ticket

Create or update a ServiceNow ticket linked to the XDR incident.

|  |  |
|---|---|
| Category | ticketing |
| Integrations | [ServiceNow](../../integrations/servicenow/README.md), [Cisco XDR](../../integrations/cisco-xdr/README.md) |
| Approval required | no |
| Reversible | Close the ticket. |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `title` | string | yes | Ticket short description. |
| `severity` | string | yes | low \| medium \| high \| critical |
| `body` | string | yes | Markdown summary of enrichment, findings and actions. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `ticket_id` | string | ServiceNow number. |
| `ticket_url` | string | Link written back to the XDR incident. |
| `error` | string | Empty on success. |

## Behaviour

- Read-only. Safe to run repeatedly and in parallel.
- Returns `unknown` rather than failing when a source has no data.
- Idempotent: a second run with the same input does not create duplicate changes.
- Idempotent: looks up an existing ticket by XDR incident ID first.

## Used by

[`privilege-escalation`](../../workflows/privilege-escalation/README.md), [`vulnerability-exploitation`](../../workflows/vulnerability-exploitation/README.md), [`web-attacks`](../../workflows/web-attacks/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
