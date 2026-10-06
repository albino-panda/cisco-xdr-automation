# Workflow: Privilege escalation

Respond to a user or process gaining higher privileges than expected.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Splunk](../../integrations/splunk/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Unexpected addition to a privileged group or role
- Exploit prevention alert
- UAC bypass detection

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-hash`](../../atomic/enrich-hash/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md), [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Host is isolation-capable and has a malicious detection (exploit prevention, UAC bypass), or a file that `enrich-hash` rates malicious was seen on it. | yes |
| [`revoke-session`](../../atomic/revoke-session/README.md) | Account that was created or gained a role or group, or that granted one to another account, with no approved change request covering the change. | no |
| [`disable-user`](../../atomic/disable-user/README.md) | Account created outside an approved change, or elevated outside an approved change while its Entra risk level is high or `investigate-user` reports anomalies. | yes |

### Error handling

Every step sets `on_error`. Intake failures (`load_incident`, `load_guardrails`) stop the run, because containment without the incident or the guardrails is unsafe.
Enrichment and investigation failures continue, so the plan is built from whatever data is available.
Plan building, approval and every containment step escalate to a human. The incident note escalates too, because it is the only place the isolation unlock code is kept.
Ticket creation continues; the SOC notification escalates so a silent run cannot go unnoticed.

### Incident context

The rules read `incident.context.privilege_changes`, which intake fills from the detection source (Entra ID audit log, Windows security events through Splunk, or the XDR incident). One entry per change:

| Field | Meaning |
|---|---|
| `user` | UPN that was created, or that gained the role or group. |
| `change` | `role_assigned`, `group_added` or `account_created`. |
| `role` / `group` | What was granted. Informational. |
| `actor` | UPN that made the change. |
| `approved_change` | Number of an approved change request whose window covers the change, otherwise empty. |

`investigate_user` runs for the user observables and for every `user` and `actor` in this list.

## Containment rules

The `plan` rules in [`workflow.yaml`](workflow.yaml) turn the conditions above into expressions the [plan engine](../../engine/README.md) evaluates. Guardrails (protected hosts, users and groups, blast-radius caps) apply after a rule matches.

| Rule id | Atomic | Condition |
|---|---|---|
| `isolate_exploited_hosts` | `isolate-endpoint` | For each investigated host: isolation is possible, and either a detection on it is malicious or a malicious hash from `enrich-hash` lists its connector GUID or hostname. Target is the connector GUID. |
| `revoke_unapproved_privilege_sessions` | `revoke-session` | For each investigated user: the user is the subject or the actor of a privilege change that has no approved change number. |
| `disable_attacker_accounts` | `disable-user` | For each investigated user: the user is the subject of a privilege change with no approved change number, and the change created the account or the user's risk level is high or the user has sign-in anomalies. |

An actor who granted rights without approval loses sessions but is not disabled automatically; the approver decides from the investigation.

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

- Reverse unauthorised role or group changes manually and record them in the ticket: remove the role assignment or group membership in Entra ID or Active Directory, and delete or keep disabled any account created outside an approved change. The incident note and ticket templates carry this step.
- An account the attacker added to a protected group (for example `Domain Admins`) is skipped by the protected-group guardrail, because investigation reads the membership after the change. The approval text warns about this; remove the membership by hand before anything else. Scenario 04 pins this behaviour.
- A host that is not isolation-capable is never isolated by the plan, even with a malicious detection. Contain it by hand.

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with `PYTHONPATH=engine python -m xdr_plan check privilege-escalation` from the repository root.

| File | What it proves |
|---|---|
| [`01-exploit-then-rogue-admin.yaml`](scenarios/01-exploit-then-rogue-admin.yaml) | True positive: exploit host isolated, sessions revoked for the acting account and the new account, new account disabled. The actor is not disabled. |
| [`02-approved-change-window.yaml`](scenarios/02-approved-change-window.yaml) | Benign: a role assignment covered by an approved change request and a host with only clean detections produce no actions. |
| [`03-protected-dc-and-breakglass.yaml`](scenarios/03-protected-dc-and-breakglass.yaml) | Guardrails: a domain controller (`dc-*`) and a break-glass account match every rule but are `skipped_protected`. |
| [`04-elevated-into-protected-group.yaml`](scenarios/04-elevated-into-protected-group.yaml) | Edge case: an account self-added to `Domain Admins` is `skipped_protected` for revoke and disable, while the UAC-bypass host is still isolated. |
| [`05-mass-account-creation.yaml`](scenarios/05-mass-account-creation.yaml) | Blast radius: four attacker-created accounts exceed `max_users_disabled`, so disable-user becomes `skipped_limit` and the plan escalates; revoke-session still runs; a non-isolation-capable host is not isolated. |

## Related workflows

[`credential-dumping`](../credential-dumping/README.md), [`persistence`](../persistence/README.md), [`cloud-compromise`](../cloud-compromise/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
