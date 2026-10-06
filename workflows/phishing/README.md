# Workflow: Phishing

Triage a reported or detected phishing message, remove copies from all mailboxes and block its indicators.

|  |  |
|---|---|
| Default severity | medium |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [Cisco Secure Email (Threat Defense / Gateway)](../../integrations/secure-email/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- User-reported phish
- Secure Email verdict change to malicious after delivery
- XDR incident from email telemetry

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-ip`](../../atomic/enrich-ip/README.md), [`enrich-hash`](../../atomic/enrich-hash/README.md).
3. **Investigate.** [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`quarantine-email`](../../atomic/quarantine-email/README.md) | All delivered copies matching sender and subject or URL. | yes |
| [`block-url`](../../atomic/block-url/README.md) | Malicious URLs on otherwise legitimate domains. | yes |
| [`block-domain`](../../atomic/block-domain/README.md) | Domains with a malicious verdict that are not allow-listed. | yes |
| [`block-hash`](../../atomic/block-hash/README.md) | Malicious attachments. | yes |

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

- If any recipient clicked or entered credentials, hand off to the account-takeover workflow.

## Related workflows

[`account-takeover`](../account-takeover/README.md), [`bec`](../bec/README.md), [`malware`](../malware/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
