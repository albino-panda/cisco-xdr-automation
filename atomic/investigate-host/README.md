# Atomic: Investigate host

Endpoint context: owner, OS, recent detections, process and network trajectory, network location.

|  |  |
|---|---|
| Category | investigation |
| Integrations | [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Splunk](../../integrations/splunk/README.md) |
| Approval required | no |
| Reversible | Read-only |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `host` | string | yes | Hostname, connector GUID or IP. |
| `lookback_hours` | integer | no | Default 24. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `connector_guid` | string | Secure Endpoint connector GUID. |
| `detections` | list | Recent detections and their dispositions. |
| `trajectory` | list | Summarised process and network events. |
| `isolation_capable` | boolean | Whether the connector policy allows isolation. |
| `is_protected` | boolean | True when the host is in the guardrails protected list. |
| `error` | string | Empty on success. |

## Behaviour

- Read-only. Safe to run repeatedly and in parallel.
- Returns `unknown` rather than failing when a source has no data.
- Idempotent: a second run with the same input does not create duplicate changes.

## Used by

[`c2`](../../workflows/c2/README.md), [`dns-tunneling`](../../workflows/dns-tunneling/README.md), [`privilege-escalation`](../../workflows/privilege-escalation/README.md), [`exfiltration`](../../workflows/exfiltration/README.md), [`vulnerability-exploitation`](../../workflows/vulnerability-exploitation/README.md), [`web-attacks`](../../workflows/web-attacks/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
