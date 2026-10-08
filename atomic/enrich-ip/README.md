# Atomic: Enrich IP

Reputation, geolocation, ASN and internal sightings for an IP address.

|  |  |
|---|---|
| Category | enrichment |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md) |
| Approval required | no |
| Reversible | Read-only |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `ip` | string | yes | IPv4 or IPv6 address. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `verdict` | string | malicious \| suspicious \| clean \| unknown |
| `sources` | list | Per-source verdicts and links. |
| `internal_sightings` | integer | Number of internal hosts seen talking to the IP in the lookback window. |
| `is_internal` | boolean | True for RFC 1918 or configured internal ranges. |
| `error` | string | Empty on success. |

## Behaviour

- Read-only. Safe to run repeatedly and in parallel.
- Returns `unknown` rather than failing when a source has no data.
- Idempotent: a second run with the same input does not create duplicate changes.
- Skip external lookups for internal and reserved ranges.

## Used by

[`c2`](../../workflows/c2/README.md), [`exfiltration`](../../workflows/exfiltration/README.md), [`vulnerability-exploitation`](../../workflows/vulnerability-exploitation/README.md), [`cloud-compromise`](../../workflows/cloud-compromise/README.md), [`web-attacks`](../../workflows/web-attacks/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
