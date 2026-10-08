# Atomic: Revoke sessions

Invalidate refresh tokens and browser sessions for a user.

|  |  |
|---|---|
| Category | containment |
| Integrations | [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md) |
| Approval required | yes |
| Reversible | Not reversible; the user signs in again. |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `user` | string | yes | UPN or object ID. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `status` | string | revoked \| planned |
| `error` | string | Empty on success. |

## Behaviour

- Runs only after a human approval. A protected (critical) target needs ELEVATED approval and is never skipped silently.
- With `dry_run = true` it returns `planned` and makes no change.
- Writes the action, target, result and rollback instructions to the incident note.
- Idempotent: a second run with the same input does not create duplicate changes.
- Always requires human approval before it runs, whatever the severity: revoking sessions is a state-changing action.

## Used by

[`ransomware`](../../workflows/ransomware/README.md), [`mail-bombing`](../../workflows/mail-bombing/README.md), [`bec`](../../workflows/bec/README.md), [`account-takeover`](../../workflows/account-takeover/README.md), [`lateral-movement`](../../workflows/lateral-movement/README.md), [`password-spray`](../../workflows/password-spray/README.md), [`credential-dumping`](../../workflows/credential-dumping/README.md), [`privilege-escalation`](../../workflows/privilege-escalation/README.md), [`cloud-compromise`](../../workflows/cloud-compromise/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
