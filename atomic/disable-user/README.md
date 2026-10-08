# Atomic: Disable user

Disable an Entra ID account so no new sign-ins succeed.

|  |  |
|---|---|
| Category | containment |
| Integrations | [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md) |
| Approval required | yes |
| Reversible | yes. Set accountEnabled back to true. |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `user` | string | yes | UPN or object ID. |
| `reason` | string | yes | Recorded in the incident note. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `status` | string | disabled \| already_disabled \| planned |
| `error` | string | Empty on success. |

## Behaviour

- Runs only after a human approval. A protected (critical) target needs ELEVATED approval and is never skipped silently.
- With `dry_run = true` it returns `planned` and makes no change.
- Writes the action, target, result and rollback instructions to the incident note.
- Idempotent: a second run with the same input does not create duplicate changes.
- Never disable break-glass accounts. Pair with `revoke-session` because disabling alone does not end existing sessions.

## Used by

[`ransomware`](../../workflows/ransomware/README.md), [`bec`](../../workflows/bec/README.md), [`account-takeover`](../../workflows/account-takeover/README.md), [`lateral-movement`](../../workflows/lateral-movement/README.md), [`password-spray`](../../workflows/password-spray/README.md), [`credential-dumping`](../../workflows/credential-dumping/README.md), [`privilege-escalation`](../../workflows/privilege-escalation/README.md), [`exfiltration`](../../workflows/exfiltration/README.md), [`cloud-compromise`](../../workflows/cloud-compromise/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
