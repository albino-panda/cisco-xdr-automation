# Atomic: Block IP

Block an external IP at the perimeter (Meraki MX) and/or edge (Cloudflare IP list).

|  |  |
|---|---|
| Category | containment |
| Integrations | [Cisco Meraki](../../integrations/meraki/README.md), [Cloudflare](../../integrations/cloudflare/README.md) |
| Approval required | yes |
| Reversible | yes. Remove the rule or list item; Meraki restores from the saved rule set. |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `ip` | string | yes | External IP address. |
| `expires_hours` | integer | no | Auto-expiry; default 168 (7 days). |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `status` | string | blocked \| already_blocked \| skipped_internal \| planned |
| `error` | string | Empty on success. |

## Behaviour

- Checks the guardrails file before acting and returns a `skipped_*` status instead of failing.
- With `dry_run = true` it returns `planned` and makes no change.
- Writes the action, target, result and rollback instructions to the incident note.
- Idempotent: a second run with the same input does not create duplicate changes.
- Refuse internal, reserved and allow-listed ranges, and shared infrastructure such as major CDN egress.

## Used by

[`account-takeover`](../../workflows/account-takeover/README.md), [`c2`](../../workflows/c2/README.md), [`password-spray`](../../workflows/password-spray/README.md), [`exfiltration`](../../workflows/exfiltration/README.md), [`vulnerability-exploitation`](../../workflows/vulnerability-exploitation/README.md), [`cloud-compromise`](../../workflows/cloud-compromise/README.md), [`web-attacks`](../../workflows/web-attacks/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
