# Workflow: Password spray

Block spray sources and protect any accounts where the spray succeeded.

|  |  |
|---|---|
| Default severity | medium |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Many failed sign-ins across many accounts from few sources
- Entra password spray risk detection

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-ip`](../../atomic/enrich-ip/README.md).
3. **Investigate.** [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan from the [containment rules](#containment-rules) and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-ip`](../../atomic/block-ip/README.md) | Spray source IP with an enrichment verdict other than clean, no internal hosts talking to it (not shared infrastructure) and no enrichment error. | yes |
| [`revoke-session`](../../atomic/revoke-session/README.md) | Account with at least one successful sign-in whose IP is a spray source. | no |
| [`disable-user`](../../atomic/disable-user/README.md) | Account with a successful sign-in from a spray source and suspicious follow-on activity (impossible travel, new device or MFA fatigue anomaly, or Entra risk level high). | yes |

A spray source is an `ip` observable on the incident. Failed attempts alone never touch an account.

### Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) turns the conditions above into rule expressions
(language in [`engine/README.md`](../../engine/README.md)). Guardrails run after each rule and are not repeated in it.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `block_spray_sources` | `block-ip` | For each enriched IP: the verdict is not `clean`, `internal_sightings` is 0 and enrichment returned no error. A clean verdict or any internal host talking to the IP marks it as possibly shared infrastructure (cloud egress, partner proxy, CDN), which is left to the analyst. Expiry comes from `expiry_hours.block-ip` in the guardrails (default 168 hours). Internal and allow-listed ranges end as `skipped_internal`. |
| `revoke_sprayed_sessions` | `revoke-session` | For each investigated user: at least one sign-in has `result == 'success'` and an IP that is one of the incident's `ip` observables. Spray sources come from the incident rather than from enrichment, so revocation still happens when enrichment fails. |
| `disable_compromised_accounts` | `disable-user` | The same successful sign-in from a spray source, and Entra `risk_level` is `high` or an anomaly of type `impossible_travel`, `new_device` or `mfa_fatigue` is present. An unfamiliar location alone does not count, because every spray success from an external IP has one. |

### Error handling

| Steps | `on_error` | Why |
|---|---|---|
| `load_incident`, `load_guardrails` | `stop` | No safe plan without the incident and the guardrails. |
| `enrich_ip`, `investigate_user` | `continue` | A failed lookup leaves a record with `error` set; the rules treat it conservatively. |
| `build_plan`, `approval` | `escalate` | A human decides when the plan or approval cannot complete. |
| `block_ip` | `continue` | A failed perimeter block must not hold up session revocation for accounts the spray already compromised. The failure is recorded. |
| `revoke_session`, `disable_user` | `escalate` | A failure leaves an attacker with a live session or a working account. |
| `incident_note`, `create_ticket`, `notify_soc` | `continue` | Recording and notification failures must not block each other. |

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
- In this workflow, `block-ip` and `disable-user` need approval. `revoke-session` does not and cannot be undone; the user signs in again.
- The approval, incident note, ticket and notification texts are in `templates` in [`workflow.yaml`](workflow.yaml). The incident note carries the rollback for each action.

## Scenarios

Each file in [`scenarios/`](scenarios/) pins the exact plan for one case. Run them with
`PYTHONPATH=engine python -m xdr_plan check password-spray` from the repository root.

| File | What it proves |
|---|---|
| [`01-single-success.yaml`](scenarios/01-single-success.yaml) | True positive: both spray IPs blocked with approval. Only the account with a successful sign-in from a spray source has its sessions revoked. Failed-only accounts and a success from a non-spray IP are left alone. |
| [`02-benign-shared-egress.yaml`](scenarios/02-benign-shared-egress.yaml) | Benign: failures from a clean corporate VPN egress with many internal sightings produce an empty plan. |
| [`03-guardrail-skips.yaml`](scenarios/03-guardrail-skips.yaml) | Guardrails: an internal spray source ends `skipped_internal`. The break-glass user and a Domain Admins member end `skipped_protected` for revoke and disable. |
| [`04-blast-radius-many-ips.yaml`](scenarios/04-blast-radius-many-ips.yaml) | Blast radius: 12 source IPs over a cap of 10. Every block becomes `skipped_limit` and the plan escalates, while session revocation for the compromised account still goes ahead. |
| [`05-all-attempts-failed.yaml`](scenarios/05-all-attempts-failed.yaml) | Spray edge case: no attempt succeeded, so only IPs are blocked. A high-risk account with failures only is not touched, and an IP whose enrichment failed is not blocked. |
| [`06-success-with-follow-on-activity.yaml`](scenarios/06-success-with-follow-on-activity.yaml) | MFA fatigue and a new device after a successful sign-in from a spray source lead to revoke and disable (with approval). An unfamiliar location alone leads to revoke only. |

## Notes

- Escalate to account-takeover for each account with a successful sign-in from a spray source.
- Internal spray sources are not blocked at the perimeter. Contain the internal host through lateral-movement.

## Related workflows

[`account-takeover`](../account-takeover/README.md), [`cloud-compromise`](../cloud-compromise/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
