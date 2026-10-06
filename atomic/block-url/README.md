# Atomic: Block URL

Block a specific URL in Umbrella and/or Cloudflare without blocking the whole domain.

|  |  |
|---|---|
| Category | containment |
| Integrations | [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Cloudflare](../../integrations/cloudflare/README.md) |
| Approval required | yes |
| Reversible | yes. Remove the URL from the list. |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `url` | string | yes | Full URL. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `status` | string | blocked \| already_blocked \| skipped_allowlisted \| planned |
| `error` | string | Empty on success. |

## Behaviour

- Checks the guardrails file before acting and returns a `skipped_*` status instead of failing.
- With `dry_run = true` it returns `planned` and makes no change.
- Writes the action, target, result and rollback instructions to the incident note.
- Idempotent: a second run with the same input does not create duplicate changes.
- Prefer URL blocks over domain blocks for compromised legitimate sites.

## Used by

[`phishing`](../../workflows/phishing/README.md), [`vulnerability-exploitation`](../../workflows/vulnerability-exploitation/README.md), [`web-attacks`](../../workflows/web-attacks/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
