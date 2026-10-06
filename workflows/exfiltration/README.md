# Workflow: Data exfiltration

Stop large or unusual outbound transfers and preserve evidence for impact assessment.

|  |  |
|---|---|
| Default severity | critical |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Outbound volume anomaly
- Upload to unsanctioned cloud storage
- Archive creation followed by transfer

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-ip`](../../atomic/enrich-ip/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md), [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-domain`](../../atomic/block-domain/README.md) | Domain with verdict malicious or suspicious, or a transfer destination with verdict unknown. Clean destinations are not blocked at the domain level; sanctioned services are allow-listed and skipped. | yes |
| [`block-ip`](../../atomic/block-ip/README.md) | IP seen from at most 3 internal hosts (not shared infrastructure) with verdict malicious or suspicious, or a transfer destination with verdict unknown. Internal and allow-listed ranges are skipped. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Isolation-capable source host while the transfer is still running and shows exfiltration evidence. Finished transfers are not isolated. Protected hosts are skipped. | yes |
| [`disable-user`](../../atomic/disable-user/README.md) | Account driving the transfer that is compromised (risk high, or risk medium with a sign-in anomaly) or flagged as an insider by the source. Protected users and groups are skipped. | yes |

### Error handling

| Steps | `on_error` | Why |
|---|---|---|
| Intake (`load_incident`, `load_guardrails`) | `stop` | Without the incident or the guardrails no safe plan can be built. |
| Enrich and investigate | `continue` | A missing lookup only removes evidence. Records with an `error` are never actioned. |
| Decide (`build_plan`, `approval`) | `escalate` | A human decides when the plan cannot be built or approved. |
| Contain (all four actions) | `escalate` | A failed block, isolation or disable leaves a data loss path open; a human must close it. |
| Record and notify | `continue` | The note, ticket and message are retried by hand; they never undo containment. |

## Containment rules

The `plan` block in [`workflow.yaml`](workflow.yaml) turns the conditions above into rules that the
[plan engine](../../engine/README.md) evaluates. Guardrails (protected, allow-listed, internal, blast
radius) run after each rule and are not repeated in it. A record whose enrichment or investigation
returned an `error` never matches.

| Rule id | Atomic | Condition |
|---|---|---|
| `block_exfil_domains` | `block-domain` | Any enriched domain with verdict malicious or suspicious, or a domain in `destination_domains` with verdict unknown. Expiry from `expiry_hours.block-domain`. |
| `block_exfil_ips` | `block-ip` | Any enriched IP that at most 3 internal hosts talk to, with verdict malicious or suspicious, or listed in `destination_ips` with verdict unknown. Expiry from `expiry_hours.block-ip`. |
| `isolate_active_source_hosts` | `isolate-endpoint` | `transfer_ongoing` is true, the host can be isolated, it is a source host (every investigated host when `source_hosts` is absent), and there is evidence: a destination domain or IP that is not clean, a malicious detection on the host, or `insider_risk`. |
| `disable_compromised_actor` | `disable-user` | The user drives the transfer (every investigated user when `actor_users` is absent) and has Entra risk high, or risk medium with at least one sign-in anomaly. |
| `disable_insider_actor` | `disable-user` | `insider_risk` is true and the user is named in `actor_users`. There is no default, so the decision never spreads to other users. |

### Incident context

The rules and templates read these source-specific facts from `incident.context`. Missing keys fall back
to the defaults shown, which never widen containment beyond what the enrichment verdicts support.

| Key | Type | Used for | Default |
|---|---|---|---|
| `destination_domains` | list | Which domains received the data (domain block, isolation evidence) | `[]` |
| `destination_ips` | list | Which IPs received the data (IP block, isolation evidence) | `[]` |
| `source_hosts` | list | Hosts that sent the data (isolation) | every investigated host |
| `actor_users` | list | Accounts that drove the transfer (disable) | every investigated user; none for insider cases |
| `transfer_ongoing` | boolean | Isolation only while the transfer runs | `false` |
| `insider_risk` | boolean | Insider disable and isolation evidence | `false` |
| `data_types`, `bytes_out`, `file_count`, `transfer_started`, `transfer_last_seen` | various | Approval, incident note and ticket for legal and privacy review | not used by rules |

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
- Sanctioned backup, file-transfer and partner services go into `allowlist.domains`, so they are never blocked.

## Notes

- Involve legal and privacy teams early. The ticket captures data types, volumes, file count, transfer window and
  destinations from `incident.context` for notification decisions.
- Clean, widely used cloud storage is not blocked at the domain or IP level because that would break sanctioned use;
  containment then relies on the account and, while the transfer runs, the host.
- Isolation preserves evidence: the host stays powered on with the management channel open. Do not reimage before
  forensic collection and legal sign-off.

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with
`PYTHONPATH=engine python -m xdr_plan check exfiltration` from the repository root.

| File | What it proves |
|---|---|
| [`01-ongoing-upload-compromised-account.yaml`](scenarios/01-ongoing-upload-compromised-account.yaml) | True positive: an ongoing upload to an unknown domain and IP by a high-risk account plans all four actions, each behind approval. |
| [`02-sanctioned-backup.yaml`](scenarios/02-sanctioned-backup.yaml) | Benign: a running backup to the allow-listed, clean backup service produces no actions; an ongoing transfer alone never isolates a host. |
| [`03-guardrail-skips.yaml`](scenarios/03-guardrail-skips.yaml) | Guardrails: an allow-listed partner domain, an internal relay IP, a `dc-*` host and a Domain Admins account are kept in the plan as `skipped_allowlisted`, `skipped_internal` and `skipped_protected`. |
| [`04-finished-transfer.yaml`](scenarios/04-finished-transfer.yaml) | Edge case: when the transfer has finished, the destinations are still blocked but the host is not isolated, and a low-risk account stays enabled. |
| [`05-insider-personal-cloud.yaml`](scenarios/05-insider-personal-cloud.yaml) | Insider: only the named actor is disabled; clean personal cloud storage is not blocked and a second user in the incident is untouched. |
| [`06-spread-destinations-over-limit.yaml`](scenarios/06-spread-destinations-over-limit.yaml) | Blast radius and shared infrastructure: a CDN address used by 40 hosts is not blocked, three IP blocks over the limit become `skipped_limit` and escalate, while isolation and disable stay planned. |

## Related workflows

[`c2`](../c2/README.md), [`dns-tunneling`](../dns-tunneling/README.md), [`cloud-compromise`](../cloud-compromise/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from the `plan` rules, error handling from `on_error` and texts from `templates`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
