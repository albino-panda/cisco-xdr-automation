# Workflow: Persistence

Find and remove attacker footholds such as run keys, scheduled tasks, services and new accounts.

|  |  |
|---|---|
| Default severity | medium |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Splunk](../../integrations/splunk/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- New autorun entry or service from an unknown binary
- New local or cloud account outside change windows

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-hash`](../../atomic/enrich-hash/README.md), [`enrich-domain`](../../atomic/enrich-domain/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md).
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-hash`](../../atomic/block-hash/README.md) | Persisted binary with malicious disposition. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Persistence linked to active malicious execution. | yes |

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

- Removal of the persistence item itself is a manual or EDR-assisted step; record each item removed.

## Related workflows

[`malware`](../malware/README.md), [`privilege-escalation`](../privilege-escalation/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
