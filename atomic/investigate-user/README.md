# Atomic: Investigate user

Identity context for an account: profile, risk state, recent sign-ins, MFA events and mailbox rules.

|  |  |
|---|---|
| Category | investigation |
| Integrations | [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco XDR](../../integrations/cisco-xdr/README.md) |
| Approval required | no |
| Reversible | Read-only |
| Spec | [`atomic.yaml`](atomic.yaml) |

## Inputs

| Name | Type | Required | Description |
|---|---|---|---|
| `user` | string | yes | UPN or email address. |
| `lookback_hours` | integer | no | Default 72. |
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |

## Outputs

| Name | Type | Description |
|---|---|---|
| `profile` | object | Department, manager, privileged role membership. |
| `risk_level` | string | Entra risk level when available. |
| `signins` | list | Recent sign-ins with IP, location, app and result. |
| `anomalies` | list | Impossible travel, new device, unfamiliar location, MFA fatigue patterns. |
| `is_protected` | boolean | True when the user is in the guardrails protected list. |
| `error` | string | Empty on success. |

## Behaviour

- Read-only. Safe to run repeatedly and in parallel.
- Returns `unknown` rather than failing when a source has no data.
- Idempotent: a second run with the same input does not create duplicate changes.

## Used by

[`privilege-escalation`](../../workflows/privilege-escalation/README.md)

## Building it in XDR Automation

Prefer the Cisco-managed atomic from the Exchange when one exists for the target product. Otherwise build a custom atomic with the inputs and outputs above, export it and commit the JSON here as `atomic.export.json`.
