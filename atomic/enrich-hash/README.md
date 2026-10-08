# Atomic: Enrich file hash

Disposition and prevalence of a SHA-256 across threat intel and the endpoint fleet.

|  |  |
|---|---|
| Category | enrichment |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md) |
| Approval required | no |
| Reversible | Read-only |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256` | string | yes | SHA-256 of the file. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `disposition` | string | malicious \| clean \| unknown |
| `prevalence` | integer | Number of endpoints that have seen the file. |
| `hosts` | list | Up to 50 endpoint GUIDs and hostnames. |
| `error` | string | Empty on success. |

## Behaviour

- Read-only. Safe to run repeatedly and in parallel.
- Returns `unknown` rather than failing when a source has no data.
- Idempotent: a second run with the same input does not create duplicate changes.

## Used by

[`ransomware`](../../workflows/ransomware/README.md), [`phishing`](../../workflows/phishing/README.md), [`malware`](../../workflows/malware/README.md), [`malicious-powershell`](../../workflows/malicious-powershell/README.md), [`lateral-movement`](../../workflows/lateral-movement/README.md), [`credential-dumping`](../../workflows/credential-dumping/README.md), [`privilege-escalation`](../../workflows/privilege-escalation/README.md), [`persistence`](../../workflows/persistence/README.md), [`unauthorized-rmm`](../../workflows/unauthorized-rmm/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
