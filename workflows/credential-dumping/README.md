# Workflow: Credential dumping

Contain a host where credential material was accessed and treat exposed accounts as compromised.

|  |  |
|---|---|
| Default severity | critical |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Splunk](../../integrations/splunk/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Secure Endpoint detection of credential-theft tooling or LSASS access
- XDR incident tagged T1003

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager |
| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | NTDS |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file. Record the accounts with an interactive or cached logon on the affected hosts in the lookback window (default 24 hours) as `incident.context.logged_on_users`. Failure here stops the run.
2. **Enrich.** [`enrich-hash`](../../atomic/enrich-hash/README.md). Failures continue.
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md), [`investigate-user`](../../atomic/investigate-user/README.md) for the incident users and every logged-on account. Failures continue.
4. **Decide.** Build the containment plan from the rules below and skip allow-listed and internal targets; protected and over-limit targets stay planned with ELEVATED approval and a visible warning. Credential access counts as **confirmed** on a host when a Secure Endpoint detection on it is `malicious` or a `malicious` hash was seen on it. If a protected host (domain controller) is confirmed, no account action is planned and the run escalates to the incident commander. Send the plan to an approver unless `dry_run` is true. Failures escalate.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped. Failures escalate.
6. **Record.** Add an incident note (results, rollback per action, credential-reset plan) and [`create-ticket`](../../atomic/create-ticket/README.md). Failures continue.
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md). Failures continue.

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Investigated host where credential access is confirmed and the connector policy allows isolation. | yes |
| [`revoke-session`](../../atomic/revoke-session/README.md) | Accounts in `incident.context.logged_on_users` (logged on to the host in the lookback window) when credential access is confirmed on an affected host and no protected host is confirmed. | yes |
| [`disable-user`](../../atomic/disable-user/README.md) | The same exposed accounts when they hold a privileged role (`profile.privileged_roles` not empty), after approver review. | yes |

### Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) holds the exact expressions. The engine guardrails (protected hosts, users and groups, blast-radius caps) run after each rule.

| Rule id | Atomic | Condition |
|---|---|---|
| `isolate_confirmed_hosts` | `isolate-endpoint` | For each investigated host: isolation is possible and either a detection on the host is malicious or a malicious hash was seen on it (by connector GUID or hostname). Target is the connector GUID. A domain controller matches `dc-*` and needs ELEVATED approval. |
| `revoke_exposed_sessions` | `revoke-session` | For each investigated user: the account is in `incident.context.logged_on_users`, at least one investigated host is confirmed, and no protected host is confirmed. |
| `disable_exposed_privileged_accounts` | `disable-user` | Same as `revoke_exposed_sessions`, and the account holds at least one privileged role. Capped by `max_users_disabled`; over the cap every disable is skipped and the run escalates. |

### Templates

`templates` in [`workflow.yaml`](workflow.yaml) holds the approval text, incident note, ticket title and body, and SOC notification. The incident note carries the rollback for each containment action and the credential-reset plan for every account cached on the host: reset passwords (privileged and service accounts first), rotate service account secrets and the host's local administrator password, re-enable accounts only after reset and MFA review, and reimage the host. When a domain controller or protected account is involved, the incident commander owns the reset.

## Inputs

| Variable | Type | Required | Description |
|---|---|---|---|
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |
| `observables` | list | no | Overrides the incident observables. |

## Guardrails

- `dry_run` defaults to `true`. Switch it off per workflow only after a successful review of dry-run output.
- Nothing is actioned without a human approval. Allow-listed indicators are never actioned; protected hosts and users, and every action over a blast-radius cap, need ELEVATED approval with a visible warning.
- Blast-radius limits cap how many hosts, users or indicators a single run may touch.
- Every containment action is reversible except session revocation, and the rollback is written into the incident note.
- Isolating a domain controller (`dc-*`) or any other protected host needs ELEVATED approval by the incident commander. When credential access is confirmed on one, no account action is planned and the incident commander owns the domain-wide reset.
- Session revocation and disabling of members of protected groups (`Domain Admins`) and of protected users need ELEVATED approval.

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with `PYTHONPATH=engine python -m xdr_plan check credential-dumping` from the repository root.

| File | What it proves |
|---|---|
| [`01-workstation-lsass-access.yaml`](scenarios/01-workstation-lsass-access.yaml) | True positive on a workstation: host isolated, both logged-on accounts revoked, the privileged one disabled with approval; an incident user who never logged on is not actioned. |
| [`02-security-agent-memory-read.yaml`](scenarios/02-security-agent-memory-read.yaml) | Benign: an approved security agent reading LSASS memory (clean detection and hash) produces no actions. |
| [`03-domain-controller-ntds.yaml`](scenarios/03-domain-controller-ntds.yaml) | Guardrail: isolation of a confirmed domain controller is planned with `elevated: true` and no account action is planned, so the incident commander decides. |
| [`04-domain-admin-exposed.yaml`](scenarios/04-domain-admin-exposed.yaml) | Guardrail: a Domain Admins member on the host is skipped for revoke and disable while the host and the standard user are still actioned. |
| [`05-shared-admin-server.yaml`](scenarios/05-shared-admin-server.yaml) | Edge case: a malicious hash alone confirms access on a shared admin server; four privileged disables exceed the cap, stay planned with `elevated: true` and escalate. |

## Notes

- Plan credential resets for every account cached on the host. If a domain controller is involved, escalate to the incident commander instead of automating.
- `incident.context.logged_on_users` is filled at intake because no atomic yet returns the accounts logged on to a host. Once `investigate-host` declares such an output, the rules should read it instead.
- `profile.privileged_roles` and `profile.groups` are sub-fields of the `investigate-user` profile object; their exact names are not yet declared in its `atomic.yaml`.

## Related workflows

[`lateral-movement`](../lateral-movement/README.md), [`privilege-escalation`](../privilege-escalation/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
