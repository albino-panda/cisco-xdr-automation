# Workflow: DNS tunneling

Respond to data or command traffic hidden in DNS queries.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Splunk](../../integrations/splunk/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Umbrella DNS tunneling category hit
- High-entropy or high-volume subdomain queries to one parent domain

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS |
| [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md).
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-domain`](../../atomic/block-domain/README.md) | Tunneling parent domain. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Querying hosts when the process is not a known security or VPN tool. | yes |

## Inputs

| Variable | Type | Required | Description |
|---|---|---|---|
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |
| `observables` | list | no | Overrides the incident observables. |

## Guardrails

- `dry_run` defaults to `true`. Switch it off per workflow only after a successful review of dry-run output.
- Protected hosts, protected users and allow-listed indicators are never actioned automatically.
- Blast-radius limits cap how many hosts, users or indicators a single run may touch.
- Every containment action is reversible except session revocation, and the rollback is written into the incident note.

## Notes

- Some security and VPN products legitimately use DNS-based lookups; check the allow-list first.

## Related workflows

[`c2`](../c2/README.md), [`exfiltration`](../exfiltration/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
