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

1. **Intake.** Load the incident summary, observables, the message facts in `incident.context` (`sender`, `subject`, `email_verdict`, `malicious_urls`) and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-ip`](../../atomic/enrich-ip/README.md), [`enrich-hash`](../../atomic/enrich-hash/README.md).
3. **Investigate.** [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan from the [containment rules](#containment-rules) and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`quarantine-email`](../../atomic/quarantine-email/README.md) | The message is confirmed malicious and has a sender plus a subject or malicious URL to match. Delivered copies from that sender matching the subject or a malicious URL, capped at `max_messages_quarantined`. | yes |
| [`block-url`](../../atomic/block-url/README.md) | A URL listed as malicious whose host has no malicious domain verdict (malicious URL on an otherwise legitimate domain). | yes |
| [`block-domain`](../../atomic/block-domain/README.md) | Domain with a malicious `enrich-domain` verdict. Allow-listed domains are skipped by the guardrail. | yes |
| [`block-hash`](../../atomic/block-hash/README.md) | Attachment with a malicious `enrich-hash` disposition. Allow-listed hashes are skipped by the guardrail. | yes |

### Error handling

Each step sets `on_error`. Intake steps `stop` (no incident or guardrails means no safe plan). Enrichment and
investigation steps `continue`, so a failed lookup only removes evidence and can never add an action. Plan
building, approval and every containment step `escalate` to a human, because a failed quarantine leaves
copies in mailboxes and a failed block leaves an indicator reachable. Record and notify steps `continue`.

## Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) is the exact logic. Guardrails (allow-lists and the
indicator cap) run after each rule and are not repeated in it.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `quarantine_malicious_message` | `quarantine-email` | Run once when `incident.context` has a sender and a subject or malicious URL, and the message is malicious by any of: Secure Email verdict, a listed malicious URL, a malicious domain verdict or a malicious attachment. Target is the sender; the search adds the subject and malicious URLs; `max_messages` comes from `blast_radius.max_messages_quarantined`. |
| `block_malicious_url_on_legitimate_domain` | `block-url` | For each URL observable that is in `incident.context.malicious_urls` and whose host (or an enriched parent domain) has no malicious `enrich-domain` verdict. URLs on malicious domains are left to `block_malicious_domain`. |
| `block_malicious_domain` | `block-domain` | For each `enrich-domain` result with verdict `malicious` and no lookup error. Expiry comes from `expiry_hours.block-domain`. |
| `block_malicious_attachment` | `block-hash` | For each `enrich-hash` result with disposition `malicious` and no lookup error. |

## Scenarios

Run with `PYTHONPATH=engine python -m xdr_plan check phishing` from the repository root.

| File | What it proves |
|---|---|
| [`01-credential-link-and-attachment.yaml`](scenarios/01-credential-link-and-attachment.yaml) | True positive: quarantine, block-domain and block-hash are planned; the URL on the malicious domain is not blocked twice. |
| [`02-benign-user-report.yaml`](scenarios/02-benign-user-report.yaml) | A clean user-reported newsletter produces no actions. |
| [`03-allowlisted-partner-indicators.yaml`](scenarios/03-allowlisted-partner-indicators.yaml) | Guardrails: a compromised partner's allow-listed domain and hash are `skipped_allowlisted`, while quarantine stays planned. |
| [`04-campaign-over-indicator-cap.yaml`](scenarios/04-campaign-over-indicator-cap.yaml) | Blast radius: a campaign with rotating domains exceeds `max_indicators_blocked`, all blocks become `skipped_limit` and the plan escalates; quarantine is not capped by the indicator limit. |
| [`05-malicious-url-on-legitimate-host.yaml`](scenarios/05-malicious-url-on-legitimate-host.yaml) | Edge case: malicious URLs on legitimate file-sharing hosts are blocked by exact URL, never by domain; the allow-listed host is skipped, the benign link is ignored and the internal sender is quarantined by sender plus subject. |

## Inputs

| Variable | Type | Required | Description |
|---|---|---|---|
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |
| `observables` | list | no | Overrides the incident observables. |

## Guardrails

- `dry_run` defaults to `true`. Switch it off per workflow only after a successful review of dry-run output.
- Protected hosts, protected users and allow-listed indicators are never actioned automatically.
- Blast-radius limits cap how many hosts, users or indicators a single run may touch. URL, domain and hash blocks share `max_indicators_blocked`; quarantine passes `max_messages_quarantined` to the atomic as `max_messages`.
- Every containment action in this workflow is reversible, and the rollback is written into the incident note (`templates.incident_note`): release messages from quarantine, remove URLs and domains from the block lists, delete hashes from the Secure Endpoint custom detection list.

## Notes

- If any recipient clicked or entered credentials, hand off to the account-takeover workflow.
- Templates for the approval, incident note, ticket and SOC notification are in `templates` in [`workflow.yaml`](workflow.yaml).
- The URL verdict comes from `incident.context.malicious_urls` (Secure Email / XDR), because no URL enrichment atomic exists yet.

## Related workflows

[`account-takeover`](../account-takeover/README.md), [`bec`](../bec/README.md), [`malware`](../malware/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
