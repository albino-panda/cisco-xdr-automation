# Atomic: Notify SOC

Send a concise alert to the SOC channel through an XDR Automation target.

|  |  |
|---|---|
| Category | notification |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md) |
| Approval required | no |
| Reversible | Not applicable. |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `message` | string | yes | Short summary with incident and ticket links. |
| `severity` | string | yes | Controls channel and mention policy. |
| `channel` | string | no | Override the default target. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `delivered` | boolean | Whether the target accepted the message. |
| `error` | string | Empty on success. |

## Behaviour

- Read-only. Safe to run repeatedly and in parallel.
- Returns `unknown` rather than failing when a source has no data.
- Idempotent: a second run with the same input does not create duplicate changes.
- Never include secrets, unlock codes or full message bodies.

## Used by

[`ransomware`](../../workflows/ransomware/README.md), [`phishing`](../../workflows/phishing/README.md), [`mail-bombing`](../../workflows/mail-bombing/README.md), [`bec`](../../workflows/bec/README.md), [`account-takeover`](../../workflows/account-takeover/README.md), [`malware`](../../workflows/malware/README.md), [`powershell`](../../workflows/powershell/README.md), [`lateral-movement`](../../workflows/lateral-movement/README.md), [`c2`](../../workflows/c2/README.md), [`dns-tunneling`](../../workflows/dns-tunneling/README.md), [`password-spray`](../../workflows/password-spray/README.md), [`credential-dumping`](../../workflows/credential-dumping/README.md), [`privilege-escalation`](../../workflows/privilege-escalation/README.md), [`persistence`](../../workflows/persistence/README.md), [`rmm`](../../workflows/rmm/README.md), [`exfiltration`](../../workflows/exfiltration/README.md), [`vulnerability-exploitation`](../../workflows/vulnerability-exploitation/README.md), [`cloud-compromise`](../../workflows/cloud-compromise/README.md), [`web-attacks`](../../workflows/web-attacks/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
