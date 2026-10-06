# Workflow: Command and control

Cut off a host beaconing to attacker infrastructure and find other hosts talking to it.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Umbrella security category hit (C2 / malware)
- Periodic beaconing detection
- XDR incident with C2 indicators

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel |
| [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | Domain Generation Algorithms |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-ip`](../../atomic/enrich-ip/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md).
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-domain`](../../atomic/block-domain/README.md) | C2 domains. | yes |
| [`block-ip`](../../atomic/block-ip/README.md) | C2 IPs that are not shared hosting or CDN. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Hosts with confirmed beaconing. | yes |

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

- Use internal_sightings from enrichment to find every beaconing host, not just the alerting one.

## Related workflows

[`dns-tunneling`](../dns-tunneling/README.md), [`malware`](../malware/README.md), [`exfiltration`](../exfiltration/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
