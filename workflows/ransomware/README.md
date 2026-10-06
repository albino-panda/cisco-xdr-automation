# Workflow: Ransomware

Contain suspected ransomware quickly to limit encryption spread, then scope affected hosts and accounts.

|  |  |
|---|---|
| Default severity | critical |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Secure Endpoint ransomware or malicious-activity-protection detection
- Mass file modification or shadow copy deletion alerts
- XDR incident tagged with an impact technique

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery |
| [T1489](https://attack.mitre.org/techniques/T1489/) | Service Stop |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-hash`](../../atomic/enrich-hash/README.md), [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-ip`](../../atomic/enrich-ip/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md) for the incident hosts plus the hosts `enrich-hash` lists for a malicious payload, and [`investigate-user`](../../atomic/investigate-user/README.md) for the users of the incident and its targets.
4. **Decide.** Build a containment plan from the rules below and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note with the rollback for every action, and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Isolation-capable host that has a malicious detection, or that has seen a malicious payload hash with a prevalence of 50 or less. Protected hosts are skipped. Eligible for auto-approval when guardrails allow. | yes |
| [`block-hash`](../../atomic/block-hash/README.md) | Payload hash with malicious disposition and a prevalence of 50 or less. Unknown-disposition or more widespread hashes are left to the approver. | yes |
| [`revoke-session`](../../atomic/revoke-session/README.md) | Account listed in the same incident target as a host that has a malicious detection. | no |
| [`disable-user`](../../atomic/disable-user/README.md) | Account with Entra risk level high and at least one sign-in anomaly. | yes |

### Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) holds the exact expressions. Guardrails (protected hosts and users, allow-listed hashes, blast-radius caps) run after every rule and are not repeated in it.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `isolate_detected_hosts` | `isolate-endpoint` | An investigated host has at least one detection with disposition `malicious` and its connector policy allows isolation. Target: connector GUID. |
| `isolate_payload_hosts` | `isolate-endpoint` | An investigated host, isolation-capable, appears (by connector GUID or hostname) in the `hosts` list of a payload hash that is `malicious` with prevalence 50 or less, even without its own detection. |
| `block_payload_hash` | `block-hash` | A hash is `malicious` and seen on 50 endpoints or fewer. Above 50 the `hosts` list is truncated and a mis-scored common binary becomes likely, so the approver decides. |
| `revoke_sessions_on_affected_hosts` | `revoke-session` | An investigated user shares an incident target with a hostname whose investigation shows a `malicious` detection. |
| `disable_compromised_users` | `disable-user` | An investigated user has Entra `risk_level` high and at least one entry in `anomalies`. |

A host whose policy does not allow isolation is never planned; it shows up in the findings for manual containment.

### Error handling

| Phase | `on_error` | Why |
|---|---|---|
| Intake (`load_incident`, `load_guardrails`) | `stop` | Without the incident or the guardrails no safe plan can be built. |
| Enrich, investigate | `continue` | A missing lookup only removes candidates from the plan; it never adds one. |
| Decide (`build_plan`, `approval`) | `escalate` | A plan that cannot be built or approved goes to a human instead of silently doing nothing. |
| Contain (all four actions) | `escalate` | A failed isolation, block or account action leaves encryption able to spread, so a human must pick it up. |
| `incident_note`, `notify_soc` | `escalate` | The note carries the rollback, and the SOC must hear about a critical incident. |
| `create_ticket` | `continue` | The incident note and notification still carry the record. |

### Message templates

`templates` in [`workflow.yaml`](workflow.yaml) defines the approval text, incident note, ticket title and body, and the SOC notification. Placeholders use only `incident.`, `plan.`, `ticket.`, `workflow.` and `approver.` values. Templates never contain secrets or the isolation unlock code; the unlock code stays in the Secure Endpoint console.

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with `PYTHONPATH=engine python -m xdr_plan check ransomware`.

| File | What it proves |
|---|---|
| [`01-workstation-encryption.yaml`](scenarios/01-workstation-encryption.yaml) | True positive: the detected host and a second host holding the payload are isolated, the hash is blocked, the account loses its sessions and is disabled. |
| [`02-benign-backup-reencryption.yaml`](scenarios/02-benign-backup-reencryption.yaml) | A backup agent's mass file modification (clean, widespread hash, no malicious detection) produces no actions. |
| [`03-protected-hypervisor-and-admins.yaml`](scenarios/03-protected-hypervisor-and-admins.yaml) | Guardrails: hypervisor, domain controller and OT-range hosts, a break-glass account and a Domain Admins member are `skipped_protected`; only the workstation and the hash are planned. |
| [`04-outbreak-blast-radius.yaml`](scenarios/04-outbreak-blast-radius.yaml) | Seven isolations exceed `max_hosts_isolated`, so all become `skipped_limit` and the plan escalates; the hash block and session revocation stay planned. |
| [`05-fresh-build-remote-share-encryption.yaml`](scenarios/05-fresh-build-remote-share-encryption.yaml) | Per-victim payload with unknown disposition: the source host is isolated on behaviour alone, the hash is not blocked, and the file server whose shares are encrypted remotely is not isolated. |
| [`06-widespread-hash-not-blocked.yaml`](scenarios/06-widespread-hash-not-blocked.yaml) | Prevalence gate: a malicious-scored hash on 1800 endpoints is neither blocked nor used to isolate hosts; the low-prevalence payload is. |

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

- Speed matters more than completeness here. Keep enrichment lookbacks short, and consider auto-approving isolation of non-protected workstations so containment never waits on a human. Do this only in the guardrails file (`auto_approve.ransomware.isolate-endpoint`), never in the workflow.
- The hosts that `enrich-hash` lists for a malicious payload are looped through `investigate-host`, and `isolate_payload_hosts` isolates them even before they raise their own detection.

## Related workflows

[`malware`](../malware/README.md), [`lateral-movement`](../lateral-movement/README.md), [`exfiltration`](../exfiltration/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
