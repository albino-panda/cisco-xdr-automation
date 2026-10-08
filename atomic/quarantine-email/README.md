# Atomic: Quarantine email

Find delivered messages matching sender, subject or URL and move them to quarantine.

|  |  |
|---|---|
| Category | containment |
| Integrations | [Cisco Secure Email (Threat Defense / Gateway)](../../integrations/secure-email/README.md) |
| Approval required | yes |
| Reversible | yes. Move messages back to the inbox. |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `search` | object | yes | Sender, recipient, subject, URL or time-window filters. |
| `max_messages` | integer | no | Safety cap; default 500. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `matched` | integer | Messages found. |
| `moved` | integer | Messages moved. |
| `status` | string | quarantined \| partial \| planned |
| `error` | string | Empty on success. |

## Behaviour

- Runs only after a human approval. Checks the allow-lists before acting and returns a `skipped_*` status instead of failing.
- With `dry_run = true` it returns `planned` and makes no change.
- Writes the action, target, result and rollback instructions to the incident note.
- Idempotent: a second run with the same input does not create duplicate changes.
- Call the remediate API in chunks of 100 ids.
- Show the matched count and a sample to the approver before moving.

## Used by

No legacy spec. The migrated workflows (Phase 2) use `xdr_response.atomics` instead; see [docs/workflows/README.md](../../docs/workflows/README.md).

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
