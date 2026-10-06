# Workflow: Mail bombing

Respond to an email or subscription bombing burst, clear the flood and watch for the follow-up social engineering it often hides.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco Secure Email (Threat Defense / Gateway)](../../integrations/secure-email/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Incident raised by the cisco-xdr-mailbomb-detector project
- Sudden volume spike of neutral or graymail messages to one recipient

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service |
| [T1656](https://attack.mitre.org/techniques/T1656/) | Impersonation |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md).
3. **Investigate.** [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`quarantine-email`](../../atomic/quarantine-email/README.md) | Burst messages with neutral or graymail verdicts only. | yes |
| [`revoke-session`](../../atomic/revoke-session/README.md) | When a password change or MFA prompt was buried in the flood. | no |

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

- Detection lives in the existing mail-bomb detector project; this workflow is the response side.
- Alert the user and help desk: mail bombing is often followed by fake IT-support calls or chats that push remote-access tools.

Detection is provided by the sibling project [cisco-xdr-mailbomb-detector](<../../../Mail Bombing/cisco-xdr-mailbomb-detector/README.md>). Its `xdr-response` workflow already covers ETD move/quarantine; this workflow adds identity checks, ticketing and the hand-off to the RMM and account-takeover workflows.

## Related workflows

[`rmm`](../rmm/README.md), [`account-takeover`](../account-takeover/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
