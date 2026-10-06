# Workflow: Business email compromise

Contain a mailbox used for fraud and catch payment-redirection or forwarding-rule abuse.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [Cisco Secure Email (Threat Defense / Gateway)](../../integrations/secure-email/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Suspicious inbox or forwarding rule creation
- Lookalike sender domain targeting finance
- Payment change requests flagged by users

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1534](https://attack.mitre.org/techniques/T1534/) | Internal Spearphishing |
| [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | Email Forwarding Rule |
| [T1656](https://attack.mitre.org/techniques/T1656/) | Impersonation |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-ip`](../../atomic/enrich-ip/README.md).
3. **Investigate.** [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan from the [containment rules](#containment-rules) and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval | On error |
|---|---|---|---|
| [`revoke-session`](../../atomic/revoke-session/README.md) | Investigated user is an internal (tenant) mailbox with compromise evidence: Entra risk level high, or a successful sign-in from an IP that `enrich-ip` rates malicious or suspicious. | no | escalate |
| [`disable-user`](../../atomic/disable-user/README.md) | Same compromise evidence, plus ongoing abuse: a rule forwarding mail outside the organisation, or the mailbox is a listed sender of the fraudulent messages. | yes | escalate |
| [`quarantine-email`](../../atomic/quarantine-email/README.md) | Fraudulent messages, searched across all recipients, from a compromised internal mailbox that is a listed fraud sender, or from a gateway-flagged lookalike sender domain that is not rated clean and not allow-listed. | yes | escalate |
| [`block-domain`](../../atomic/block-domain/README.md) | Domain flagged by the email gateway as a lookalike of an organisation domain and not rated clean by `enrich-domain`. Allow-listed domains are skipped. | yes | continue |

Intake failures stop the run, enrichment and investigation failures continue with what is available,
and a failed plan, approval or mailbox containment step escalates to a human. A failed domain block
continues, because the mailbox and quarantine actions matter more and the failure is recorded in the note.

### Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) turns the conditions above into rule expressions
(see the [plan engine](../../engine/README.md)). "Compromise evidence" below always means: the
`investigate-user` record has no `error` and a non-empty `profile` (a tenant account, so internal), and
either `risk_level` is `high` or a sign-in with `result: success` came from an IP that `enrich-ip` rates
`malicious` or `suspicious`.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `revoke_compromised_mailbox_sessions` | `revoke-session` | Each investigated user with compromise evidence. Target: the user. |
| `disable_abused_mailbox` | `disable-user` | Compromise evidence and either an external forwarding rule for that user in `incident.context.mailbox_rules` or the user is in `incident.context.fraud_senders`. Target: the user. |
| `quarantine_compromised_mailbox_fraud` | `quarantine-email` | Compromise evidence and the user is in `incident.context.fraud_senders`. Target: that sender address, searched across all recipients, capped at `blast_radius.max_messages_quarantined`. |
| `quarantine_lookalike_sender_mail` | `quarantine-email` | An enriched domain listed in `incident.context.lookalike_domains`, not rated `clean`, and neither an allow-listed domain nor a subdomain of one. Target: the sender domain, searched across all recipients. |
| `block_lookalike_domain` | `block-domain` | An enriched domain listed in `incident.context.lookalike_domains` and not rated `clean`. Target: the domain, expiring after `expiry_hours.block-domain`. |

The engine then applies the guardrails: protected users and groups skip `revoke-session` and
`disable-user`, allow-listed domains skip `block-domain`, and more disables than
`blast_radius.max_users_disabled` turn every disable into `skipped_limit` and escalate.

Facts no atomic returns yet are read from `incident.context`, filled at intake from the email gateway
and the mailbox audit log:

| Field | Meaning |
|---|---|
| `fraud_senders` | Sender addresses of the reported or gateway-classified fraudulent messages. |
| `lookalike_domains` | Sender domains the gateway flags as impersonating an organisation domain. |
| `mailbox_rules` | Inbox rules seen in the lookback window: `user`, `action`, `destination`, `forwards_externally`. |

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
- Quarantine has no engine guardrail, so the lookalike quarantine rule itself refuses allow-listed domains and every quarantine is capped at `blast_radius.max_messages_quarantined`.

## Notes

- Notify finance to hold pending payments to changed bank details. The incident note, ticket and SOC notification templates carry this reminder.
- Review and remove malicious inbox rules manually; record them in the ticket.

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with
`PYTHONPATH=engine python -m xdr_plan check bec`.

| File | What it proves |
|---|---|
| [`01-compromised-finance-mailbox.yaml`](scenarios/01-compromised-finance-mailbox.yaml) | True positive: a mailbox with a malicious-IP sign-in, an external forwarding rule and sent fraud gets sessions revoked, the account disabled and its messages quarantined. |
| [`02-external-lookalike-sender.yaml`](scenarios/02-external-lookalike-sender.yaml) | Impersonation with no internal compromise: the lookalike domain is blocked and its mail quarantined; the external sender and the targeted user get no identity action. |
| [`03-protected-executive-mailbox.yaml`](scenarios/03-protected-executive-mailbox.yaml) | A protected executive mailbox is skipped for revoke and disable (`skipped_protected`) while its fraudulent messages are still quarantined. |
| [`04-breakglass-and-allowlisted-domain.yaml`](scenarios/04-breakglass-and-allowlisted-domain.yaml) | Break-glass account is never revoked automatically; an allow-listed subdomain flagged as lookalike is `skipped_allowlisted` and its mail is not quarantined. |
| [`05-benign-vendor-bank-change.yaml`](scenarios/05-benign-vendor-bank-change.yaml) | Benign vendor bank-detail change: clean domain, no compromise evidence, empty plan. |
| [`06-forwarding-rules-over-limit.yaml`](scenarios/06-forwarding-rules-over-limit.yaml) | Compromised mailboxes with forwarding rules but no sent fraud: sessions revoked, disables over the limit become `skipped_limit` and the plan escalates. |

## Related workflows

[`account-takeover`](../account-takeover/README.md), [`phishing`](../phishing/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
