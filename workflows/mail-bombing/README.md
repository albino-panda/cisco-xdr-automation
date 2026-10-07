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

### Error handling

Every step sets `on_error` in [`workflow.yaml`](workflow.yaml):

| Steps | `on_error` | Why |
|---|---|---|
| `load_incident`, `load_guardrails` | `stop` | Without the incident or the guardrails nothing can be planned safely. |
| `enrich_domain`, `investigate_user` | `continue` | Missing enrichment only removes evidence; rules that need it simply do not fire. |
| `build_plan`, `approval`, `quarantine_email`, `revoke_session` | `escalate` | A failed plan, approval or containment action goes to an analyst instead of being retried blindly. |
| `incident_note`, `create_ticket`, `notify_soc` | `continue` | Recording and notification failures must not undo or block containment. |

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`quarantine-email`](../../atomic/quarantine-email/README.md) | Detector incident whose burst has at least 10 unique sender domains and at least half neutral or graymail messages. The search only matches the recipient's incoming neutral and graymail mail since the detection window start, capped at `max_messages_quarantined`. | yes |
| [`revoke-session`](../../atomic/revoke-session/README.md) | The bombed recipient has a `password_reset`, `password_change`, `mfa_prompt`, `mfa_fatigue` or `mfa_method_registered` anomaly at or after the detection window start. Protected users are skipped. | no |

## Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) turns the conditions above into rule expressions that
[`xdr_plan`](../../engine/README.md) evaluates. The detector's webhook payload (`event_type`, `recipient`,
`is_escalation`, `metrics`) is expected in `incident.context`.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `quarantine_burst_messages` | `quarantine-email` | The incident comes from the detector (`event_type` is `mailbomb.detection`), the burst has at least 10 unique sender domains (the detector's medium floor), some neutral or graymail messages, and neutral plus graymail make up at least half of all messages. Target is the recipient. The search is limited to `direction: incoming`, verdicts `neutral` and `graymail`, and mail received since `metrics.window_start`; `max_messages` comes from `blast_radius.max_messages_quarantined`. Low-diversity floods and spam or malicious storms are left to an analyst and to Secure Email policies, the same split as the detector's ContainBurst workflow. |
| `revoke_after_buried_identity_event` | `revoke-session` | For the investigated user that equals the detector's recipient: an `anomalies` entry of type `password_reset`, `password_change`, `mfa_prompt`, `mfa_fatigue` or `mfa_method_registered` with a `time` at or after `metrics.window_start`. Events before the window and runs without detector metrics are left to the analyst. The guardrails skip protected users (break-glass accounts, `Domain Admins`). |

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with
`PYTHONPATH=engine python -m xdr_plan check mail-bombing` from the repository root.

| File | What it proves |
|---|---|
| [`01-subscription-bomb.yaml`](scenarios/01-subscription-bomb.yaml) | True positive: a 120-message, 45-domain burst is quarantined behind approval. A password change the day before the flood does not revoke sessions. |
| [`02-newsletter-spike-benign.yaml`](scenarios/02-newsletter-spike-benign.yaml) | Benign: a single-domain newsletter resend loop trips the detector's extreme-volume rule but produces no actions. |
| [`03-buried-mfa-and-reset.yaml`](scenarios/03-buried-mfa-and-reset.yaml) | Edge case: a password reset and an MFA prompt inside the flood revoke the recipient's sessions (no approval) next to the approval-gated quarantine. |
| [`04-breakglass-recipient.yaml`](scenarios/04-breakglass-recipient.yaml) | Guardrail: an MFA fatigue pattern on a break-glass mailbox gives `skipped_protected` for session revocation; the reversible quarantine is still planned. |
| [`05-spam-storm-not-quarantined.yaml`](scenarios/05-spam-storm-not-quarantined.yaml) | Verdict limit: a burst that is mostly spam and malicious (clean ratio 17 percent) is not quarantined by this workflow. |

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
- Alert the user and help desk: mail bombing is often followed by fake IT-support calls or chats that push remote-access tools. The ticket body, incident note and SOC notification templates in [`workflow.yaml`](workflow.yaml) carry this warning.
- Quarantine also hides the message the flood was meant to bury. The approval text asks the approver to confirm the hidden-message search is done first; quarantined messages stay recoverable.

Detection is provided by the sibling project `cisco-xdr-mailbomb-detector`, a separate repository that sits next to this one locally under `Mail Bombing/`. Its `xdr-response` workflow already covers ETD move/quarantine; this workflow adds identity checks, ticketing and the hand-off to the RMM and account-takeover workflows.

## Related workflows

[`rmm`](../rmm/README.md), [`account-takeover`](../account-takeover/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
