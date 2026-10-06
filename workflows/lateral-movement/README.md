# Workflow: Lateral movement

Contain an attacker moving between hosts with remote services or admin shares.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Unusual remote logons across many hosts
- Remote service creation
- XDR incident linking multiple endpoints

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares |
| [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management |
| [T1570](https://attack.mitre.org/techniques/T1570/) | Lateral Tool Transfer |

## Response flow

1. **Intake.** Load the incident summary, observables, the source hosts of the remote logons (`incident.context.source_hosts`, when the detection provides them) and the guardrails file.
2. **Enrich.** [`enrich-ip`](../../atomic/enrich-ip/README.md), [`enrich-hash`](../../atomic/enrich-hash/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md), [`investigate-user`](../../atomic/investigate-user/README.md), for every source and destination host and every account involved.
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Isolation-capable source or destination hosts that have a malicious detection, hold a file enrich-hash rates malicious, or are named in `incident.context.source_hosts` while the movement is confirmed malicious. | yes |
| [`revoke-session`](../../atomic/revoke-session/README.md) | Accounts in the incident when the movement is confirmed malicious (any host with a malicious detection or any malicious hash), or any account with a successful sign-in from a malicious IP. | no |
| [`disable-user`](../../atomic/disable-user/README.md) | Accounts confirmed compromised and not protected, meaning confirmed malicious movement plus high Entra risk or sign-in anomalies, or a successful sign-in from a malicious IP. | yes |

"Confirmed malicious movement" means at least one host in `investigate-host` has a detection with disposition `malicious`, or at least one hash in `enrich-hash` is `malicious`. Without it, remote logons alone (for example sanctioned admin work) produce no containment.

### Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) turns the conditions above into rule expressions for the [plan engine](../../engine/README.md). Guardrails (protected hosts and users, blast-radius caps) apply after each rule matches.

| Rule id | Atomic | Condition |
|---|---|---|
| `isolate_hosts_with_malicious_detections` | `isolate-endpoint` | Any investigated host, source or destination, that has at least one malicious detection and whose connector policy allows isolation. |
| `isolate_hosts_with_transferred_malicious_file` | `isolate-endpoint` | An isolation-capable host whose hostname or connector GUID appears in the `hosts` list of a hash enrich-hash rates malicious (lateral tool transfer), even before that file raised a detection. |
| `isolate_movement_source_hosts` | `isolate-endpoint` | An isolation-capable host listed in `incident.context.source_hosts` (case-insensitive), once the movement is confirmed malicious anywhere in the incident. Catches a source that used only built-in tools. |
| `revoke_sessions_of_movement_accounts` | `revoke-session` | Every investigated account when the movement is confirmed malicious, or any account with a successful sign-in from an IP enrich-ip rates malicious. |
| `disable_compromised_accounts` | `disable-user` | Confirmed malicious movement and the account has Entra risk `high` or at least one sign-in anomaly, or the account has a successful sign-in from a malicious IP. |

Step failures: intake steps `stop`; enrichment, investigation, record and notify steps `continue`; plan building, approval and every containment step `escalate` to a human.

## Inputs

| Variable | Type | Required | Description |
|---|---|---|---|
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |
| `observables` | list | no | Overrides the incident observables. |

## Guardrails

- `dry_run` defaults to `true`. Switch it off per workflow only after a successful review of dry-run output.
- Protected hosts, protected users and allow-listed indicators are never actioned automatically.
- Blast-radius limits cap how many hosts, users or indicators a single run may touch. Over the limit, that whole group is skipped and the run escalates to a human.
- Every containment action is reversible except session revocation, and the rollback is written into the incident note.

## Notes

- Map the account and host graph before isolating; isolating only the newest host leaves the source active. Run `investigate-host` for every source and destination, and pass the detection's origin hosts as `incident.context.source_hosts` so a quiet source is still isolated.
- Domain controllers (`dc-*`) and Domain Admins accounts are protected and are only reported as `skipped_protected`; contain them manually with the incident commander.
- Session revocation does not reset on-premises AD credentials. The incident note lists password resets as analyst follow-up.

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with `PYTHONPATH=engine python -m xdr_plan check lateral-movement` from the repository root.

| File | What it proves |
|---|---|
| [`01-rdp-pivot-confirmed.yaml`](scenarios/01-rdp-pivot-confirmed.yaml) | True positive: an RDP pivot with malicious detections on source and destination isolates both hosts, revokes the account's sessions and disables the high-risk account. |
| [`02-sanctioned-admin-winrm.yaml`](scenarios/02-sanctioned-admin-winrm.yaml) | Benign: change-approved WinRM patching from a jump host with clean hosts, a clean hash and no account risk produces no actions, even though the jump host is a listed source. |
| [`03-domain-controller-destination.yaml`](scenarios/03-domain-controller-destination.yaml) | Guardrails: the source workstation is isolated, but the `dc-01` destination and the Domain Admins account are `skipped_protected` for isolation, revocation and disabling. |
| [`04-admin-share-fan-out.yaml`](scenarios/04-admin-share-fan-out.yaml) | Blast radius: seven hosts to isolate exceed `max_hosts_isolated` (5), so all become `skipped_limit` and the plan escalates. The account is still revoked and disabled because it signed in from a malicious IP. |
| [`05-tool-transfer-quiet-source.yaml`](scenarios/05-tool-transfer-quiet-source.yaml) | Edge case (T1570): a transferred file not yet executed isolates the destination through the hash `hosts` list, and the detection-free source is isolated through `source_hosts`. A clean bystander host is untouched, and the account is revoked but not disabled. |

## Related workflows

[`credential-dumping`](../credential-dumping/README.md), [`ransomware`](../ransomware/README.md), [`privilege-escalation`](../privilege-escalation/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
