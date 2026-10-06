# Workflow: Account takeover

Respond to a sign-in by an attacker using valid credentials or a stolen session.

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

- Entra risky sign-in or impossible travel
- MFA fatigue pattern
- Sign-in from anonymising infrastructure

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts |
| [T1621](https://attack.mitre.org/techniques/T1621/) | Multi-Factor Authentication Request Generation |
| [T1539](https://attack.mitre.org/techniques/T1539/) | Steal Web Session Cookie |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-ip`](../../atomic/enrich-ip/README.md).
3. **Investigate.** [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`revoke-session`](../../atomic/revoke-session/README.md) | The investigated user has Entra risk level high, a successful sign-in from an IP enriched as malicious or suspicious, or an MFA fatigue anomaly followed by a successful sign-in. | no (auto-approved in the guardrails file) |
| [`disable-user`](../../atomic/disable-user/README.md) | The user meets the `revoke-session` condition and holds a privileged role, or the user's sessions were already revoked earlier for this incident and a successful sign-in from a malicious or suspicious IP is still present. | yes |
| [`block-ip`](../../atomic/block-ip/README.md) | An enriched IP that is not shared infrastructure (no internal sightings) and either has verdict malicious and appears in an investigated user's sign-ins, or is not clean and sent 3 or more denied MFA prompts to a user with an MFA fatigue anomaly. | yes |

### Error handling

| Phase | `on_error` | Why |
|---|---|---|
| Intake (`load_incident`, `load_guardrails`) | `stop` | Without the incident or the guardrails nothing may be contained. |
| Enrich, investigate | `continue` | Missing data only means fewer rules match; the gap is recorded in the note. |
| Decide (`build_plan`, `approval`) | `escalate` | No containment runs without a plan and an approval; a human takes over. |
| Contain (all three actions) | `escalate` | A failed identity or perimeter action leaves the attacker in place and needs a human. |
| Record, notify | `continue` | The note, ticket and notification are independent; one failing must not hide the others. |

## Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) turns the conditions above into rules the
[plan engine](../../engine/README.md) evaluates. "Compromised" below means: Entra risk level high, or a
successful sign-in from an IP enriched as malicious or suspicious, or an `mfa_fatigue` anomaly together
with a successful sign-in. Guardrails (protected users and groups, internal and allow-listed IPs,
blast-radius caps) are applied by the engine after each rule and are not repeated in the rules.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `revoke_compromised_sessions` | `revoke-session` | The investigated user is compromised. |
| `disable_privileged_compromised_user` | `disable-user` | The user is compromised and `profile.privileged_roles` is not empty. |
| `disable_user_active_after_revocation` | `disable-user` | The user is listed in `incident.context.previously_revoked_users` and still has a successful sign-in from a malicious or suspicious IP. |
| `block_malicious_signin_ips` | `block-ip` | The IP's verdict is malicious, no internal hosts talk to it (`internal_sightings` is 0), and it appears in an investigated user's sign-ins. |
| `block_mfa_fatigue_sources` | `block-ip` | The IP's verdict is not clean, `internal_sightings` is 0, and it sent 3 or more `mfa_denied` sign-ins to a user with an `mfa_fatigue` anomaly. This catches fresh attacker infrastructure with no reputation yet. |

Fields used inside `profile` (`privileged_roles`, `groups`) and `signins` (`ip`, `result`) follow the
descriptions in the [`investigate-user`](../../atomic/investigate-user/atomic.yaml) outputs. Expected
`anomalies` values include `impossible_travel`, `unfamiliar_location`, `new_device` and `mfa_fatigue`.

## Scenarios

Each file in [`scenarios/`](scenarios/) pins the exact plan for one case. Run them with
`PYTHONPATH=engine python -m xdr_plan check account-takeover` from the repository root.

| File | What it proves |
|---|---|
| [`01-confirmed-takeover.yaml`](scenarios/01-confirmed-takeover.yaml) | True positive: sessions revoked without an approval wait, attacker IP blocked with approval, a suspicious shared VPN exit is not blocked, and a non-privileged user is not disabled. |
| [`02-business-travel-benign.yaml`](scenarios/02-business-travel-benign.yaml) | Impossible travel explained by a business trip (clean IP, medium risk, no MFA fatigue) produces no actions. |
| [`03-breakglass-protected.yaml`](scenarios/03-breakglass-protected.yaml) | A compromised break-glass Global Administrator meets the revoke and disable rules, but both are `skipped_protected`; the attacker IP is still blocked. |
| [`04-internal-vpn-source.yaml`](scenarios/04-internal-vpn-source.yaml) | A malicious sign-in from an internal VPN pool address revokes sessions, and `block-ip` is `skipped_internal`. |
| [`05-mfa-fatigue-approved.yaml`](scenarios/05-mfa-fatigue-approved.yaml) | MFA fatigue (T1621) followed by an approved push from an IP with no reputation still revokes sessions and blocks the prompt source; an unrelated unknown IP is not blocked. |
| [`06-attacker-returns-after-revocation.yaml`](scenarios/06-attacker-returns-after-revocation.yaml) | An attacker sign-in after an earlier revocation leads to revoke again, disable with approval and an IP block. |

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
- `revoke-session` is auto-approved for this workflow in `auto_approve.account-takeover` of the guardrails file, because it only forces a new sign-in. It still respects protected users and `dry_run`. `disable-user` and `block-ip` always need approval.

## Notes

- Require a password reset and MFA re-registration through the help desk with identity verification out of band. This step is in the incident note, ticket and notification templates. Re-enable a disabled account only after both are done.
- A protected account (for example break-glass) that meets the rules is never touched automatically; the skipped actions in the note tell the analyst to handle it by hand.

## Related workflows

[`bec`](../bec/README.md), [`cloud-compromise`](../cloud-compromise/README.md), [`password-spray`](../password-spray/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
