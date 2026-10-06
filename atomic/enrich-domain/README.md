# Atomic: Enrich domain

Reputation, categorisation, age and internal DNS activity for a domain.

|  |  |
|---|---|
| Category | enrichment |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md) |
| Approval required | no |
| Reversible | Read-only |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | yes | Fully qualified domain name. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `verdict` | string | malicious \| suspicious \| clean \| unknown |
| `categories` | list | Security and content categories. |
| `first_seen` | string | First-seen date when available. |
| `internal_queries` | integer | Internal DNS queries in the lookback window. |
| `error` | string | Empty on success. |

## Behaviour

- Read-only. Safe to run repeatedly and in parallel.
- Returns `unknown` rather than failing when a source has no data.
- Idempotent: a second run with the same input does not create duplicate changes.
- Never treat your own domains or allow-listed SaaS as malicious; check the guardrails allow-list first.

## Used by

[`ransomware`](../../workflows/ransomware/README.md), [`phishing`](../../workflows/phishing/README.md), [`mail-bombing`](../../workflows/mail-bombing/README.md), [`bec`](../../workflows/bec/README.md), [`malware`](../../workflows/malware/README.md), [`powershell`](../../workflows/powershell/README.md), [`c2`](../../workflows/c2/README.md), [`dns-tunneling`](../../workflows/dns-tunneling/README.md), [`persistence`](../../workflows/persistence/README.md), [`rmm`](../../workflows/rmm/README.md), [`exfiltration`](../../workflows/exfiltration/README.md), [`web-attacks`](../../workflows/web-attacks/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
