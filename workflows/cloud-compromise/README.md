# Workflow: Cloud compromise

Respond to abuse of cloud identities, app credentials or OAuth consent.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- New credential added to an app registration or service principal
- Risky OAuth consent
- Unusual admin activity from new locations

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Additional Cloud Credentials |
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-ip`](../../atomic/enrich-ip/README.md).
3. **Investigate.** [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan from the rules below and skip allow-listed and internal targets; protected and over-limit targets stay planned with ELEVATED approval and a visible warning. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`revoke-session`](../../atomic/revoke-session/README.md) | Investigated user with high identity risk, medium risk plus at least one sign-in anomaly, or a successful sign-in from an IP enriched as malicious. | yes |
| [`disable-user`](../../atomic/disable-user/README.md) | Investigated user holding a privileged role, with high identity risk or a successful sign-in from an IP enriched as malicious. | yes |
| [`block-ip`](../../atomic/block-ip/README.md) | IP enriched as malicious, or suspicious and used for a successful sign-in by a high-risk user. Internal and allow-listed ranges are skipped by the guardrails. | yes |

### Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) holds the exact expressions. The engine then applies the guardrails (protected users and groups, internal and allow-listed IPs, blast-radius caps) to every matched target.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `revoke_compromised_user_sessions` | `revoke-session` | For each investigated user: Entra risk is high, or risk is medium and at least one anomaly is reported, or a sign-in succeeded from an IP that `enrich-ip` rated malicious. Also catches users who granted a risky consent; revocation invalidates refresh tokens issued to apps for that user. |
| `disable_compromised_privileged_users` | `disable-user` | For each investigated user with at least one entry in `profile.privileged_roles`: Entra risk is high, or a sign-in succeeded from a malicious IP. A privileged role alone, or medium risk with anomalies alone, never disables. |
| `block_attacker_ips` | `block-ip` | For each enriched IP: verdict is malicious, or verdict is suspicious and a high-risk investigated user signed in successfully from it. Expiry comes from `guardrails.expiry_hours.block-ip` (default 168 hours). |

### Error handling

| Step | `on_error` | Why |
|---|---|---|
| `load_incident`, `load_guardrails` | stop | Without the incident or the guardrails nothing may be planned or contained. |
| `enrich_ip`, `investigate_user` | continue | A missing record only removes evidence; no rule fires without it. |
| `build_plan`, `approval` | escalate | A human decides when the plan or the approval cannot be produced. |
| `revoke_session`, `disable_user` | escalate | A compromised identity that could not be contained needs a human now. |
| `block_ip` | continue | A perimeter block is a secondary control for cloud identities; the failure is recorded in the note and ticket. |
| `incident_note`, `notify_soc` | continue | Recording and notification failures do not change containment. |
| `create_ticket` | escalate | The ticket carries the manual removal of app credentials and consents and must not be lost. |

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

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with `PYTHONPATH=engine python -m xdr_plan check cloud-compromise`.

| File | What it proves |
|---|---|
| [`01-admin-takeover-rogue-app-credential.yaml`](scenarios/01-admin-takeover-rogue-app-credential.yaml) | True positive: a high-risk admin is revoked and disabled, a consenting medium-risk user with an anomaly is only revoked, the malicious IP and the suspicious IP the admin used are blocked, the clean IP is not. |
| [`02-approved-certificate-rotation.yaml`](scenarios/02-approved-certificate-rotation.yaml) | Benign: an approved certificate rotation by a privileged app owner with no risk, no anomalies and clean internal sign-ins produces no actions. |
| [`03-protected-break-glass-admin.yaml`](scenarios/03-protected-break-glass-admin.yaml) | Guardrail: a break-glass Global Administrator matches the revoke and disable rules but both are planned with `elevated: true`; the attacker IP is still blocked. |
| [`04-service-principal-secret-used-from-attacker-ip.yaml`](scenarios/04-service-principal-secret-used-from-attacker-ip.yaml) | Cloud edge case: app-only use of a leaked service principal secret. A failed sign-in from the attacker IP does not revoke or disable the clean owner; only the IP is blocked and secret removal stays manual. |
| [`05-tenant-admins-over-disable-limit.yaml`](scenarios/05-tenant-admins-over-disable-limit.yaml) | Guardrail: four compromised admins exceed `max_users_disabled`, so every disable stays planned with `elevated: true` and the plan escalates; revocations and the IP block still run. |

## Notes

- Rogue app credentials and OAuth consents are removed manually; automation here covers user identities and IPs only. The ticket body lists the steps: review the app registrations and service principals in the incident context and directory audit log, remove client secrets and certificates added in the window without an approved change, revoke delegated permission grants and app role assignments for the suspicious app, review cloud storage and mailbox access (T1530), and reset credentials and MFA before re-enabling disabled accounts.
- Revoking a user's sessions does not stop app-only tokens obtained with a service principal credential (scenario 04); only removing that credential does.
- `profile.privileged_roles` and the sign-in fields `ip` and `result` are the shapes the rules expect inside `investigate-user` output. `atomic.yaml` documents them only in prose.
- Templates use placeholders under `incident.`, `plan.`, `ticket.`, `workflow.` and `approver.`. Every containment action's rollback is written into the incident note and the ticket.

## Related workflows

[`account-takeover`](../account-takeover/README.md), [`exfiltration`](../exfiltration/README.md), [`privilege-escalation`](../privilege-escalation/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
