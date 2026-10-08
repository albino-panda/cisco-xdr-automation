# Atomic: Block domain

Add a domain to the automation block list in Umbrella and, optionally, Cloudflare Gateway.

|  |  |
|---|---|
| Category | containment |
| Integrations | [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Cloudflare](../../integrations/cloudflare/README.md) |
| Approval required | yes |
| Reversible | yes. Remove the destination from the list. |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | yes | Domain to block. |
| `expires_hours` | integer | no | Release-review reminder in hours (never an automatic release; removal needs a separate human release approval); default 720 (30 days). |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `status` | string | blocked \| already_blocked \| skipped_allowlisted \| planned |
| `error` | string | Empty on success. |

## Behaviour

- Runs only after a human approval. Checks the allow-lists before acting and returns a `skipped_*` status instead of failing.
- With `dry_run = true` it returns `planned` and makes no change.
- Writes the action, target, result and rollback instructions to the incident note.
- Idempotent: a second run with the same input does not create duplicate changes.
- Refuse own domains, allow-listed SaaS and top-level shared hosting domains.

## Used by

No legacy spec. The migrated workflows use `xdr_response.atomics` instead; see [docs/workflows/README.md](../../docs/workflows/README.md).

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
