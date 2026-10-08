# Atomic: Isolate endpoint

Network-isolate a host with Secure Endpoint while keeping the management channel open.

|  |  |
|---|---|
| Category | containment |
| Integrations | [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco XDR](../../integrations/cisco-xdr/README.md) |
| Approval required | yes |
| Reversible | yes. Stop isolation (DELETE /v1/computers/{guid}/isolation). |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `connector_guid` | string | yes | Secure Endpoint connector GUID. |
| `reason` | string | yes | Free text written to the isolation comment and the incident note. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `status` | string | isolated \| pending \| already_isolated \| planned |
| `unlock_code` | string | Isolation unlock code. It stays in the Secure Endpoint console and is never copied to notes, tickets or notifications. |
| `error` | string | Empty on success. |

## Behaviour

- Runs only after a human approval. A protected (critical) target needs ELEVATED approval and is never skipped silently.
- With `dry_run = true` it returns `planned` and makes no change.
- Writes the action, target, result and rollback instructions to the incident note.
- Idempotent: a second run with the same input does not create duplicate changes.
- A protected host (domain controllers, hypervisors, OT) needs ELEVATED approval by a lead; it is never isolated on a normal approval.

## Used by

[`ransomware`](../../workflows/ransomware/README.md), [`malware`](../../workflows/malware/README.md), [`malicious-powershell`](../../workflows/malicious-powershell/README.md), [`lateral-movement`](../../workflows/lateral-movement/README.md), [`c2`](../../workflows/c2/README.md), [`dns-tunneling`](../../workflows/dns-tunneling/README.md), [`credential-dumping`](../../workflows/credential-dumping/README.md), [`privilege-escalation`](../../workflows/privilege-escalation/README.md), [`persistence`](../../workflows/persistence/README.md), [`unauthorized-rmm`](../../workflows/unauthorized-rmm/README.md), [`exfiltration`](../../workflows/exfiltration/README.md), [`vulnerability-exploitation`](../../workflows/vulnerability-exploitation/README.md), [`web-attacks`](../../workflows/web-attacks/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
