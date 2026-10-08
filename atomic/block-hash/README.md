# Atomic: Block file hash

Add a SHA-256 to the Secure Endpoint simple custom detection list.

|  |  |
|---|---|
| Category | containment |
| Integrations | [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md) |
| Approval required | yes |
| Reversible | yes. Delete the hash from the file list. |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256` | string | yes | SHA-256 to block. |
| `description` | string | no | Shown in the Secure Endpoint console. |
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
- Refuse hashes with high clean prevalence (signed OS or line-of-business binaries).

## Used by

[`ransomware`](../../workflows/ransomware/README.md), [`phishing`](../../workflows/phishing/README.md), [`malware`](../../workflows/malware/README.md), [`persistence`](../../workflows/persistence/README.md), [`unauthorized-rmm`](../../workflows/unauthorized-rmm/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
