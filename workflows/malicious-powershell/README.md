# Workflow: Suspicious PowerShell

Investigate encoded, obfuscated or download-cradle style PowerShell and contain the host when malicious.

|  |  |
|---|---|
| Default severity | medium |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Secure Endpoint behavioural protection or exploit prevention alert
- Script block logging alert from SIEM

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-ip`](../../atomic/enrich-ip/README.md), [`enrich-hash`](../../atomic/enrich-hash/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md), [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan and skip allow-listed and internal targets; protected and over-limit targets stay planned with ELEVATED approval and a visible warning. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-domain`](../../atomic/block-domain/README.md) | Download destination domain with verdict malicious, or suspicious while an enriched payload hash is malicious. Allow-listed domains are skipped. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Isolation-capable host where a malicious payload hash was seen (payload retrieved), or with a malicious Secure Endpoint detection while a download destination domain or IP is malicious (payload executed). Protected hosts need ELEVATED approval. | yes |

### Error handling

| Steps | `on_error` | Why |
|---|---|---|
| `load_incident`, `load_guardrails` | `stop` | Without observables or guardrails nothing can be planned safely. |
| Enrichment and investigation | `continue` | A missing verdict only removes evidence; rules ignore records with an `error`. |
| `build_plan`, `approval` | `escalate` | Containment must not run on a partial plan or without a decision. |
| `block_domain`, `isolate_endpoint` | `escalate` | A failed block or isolation leaves the threat active; a human takes over. |
| `incident_note`, `create_ticket`, `notify_soc` | `continue` | Recording failures do not change containment; the run result keeps the plan. |

## Containment rules

The `plan` block in [`workflow.yaml`](workflow.yaml) turns the conditions above into expressions the
[plan engine](../../engine/README.md) evaluates. Records whose `error` is non-empty never trigger an action.
Guardrails (allow-list, protected hosts, blast radius) are applied by the engine after each rule matches.

| Rule id | Atomic | Condition |
|---|---|---|
| `block_malicious_download_domain` | `block-domain` | The domain the script contacted is rated malicious by `enrich-domain`. Blocks expire after `expiry_hours.block-domain` (720 h by default). |
| `block_suspicious_domain_serving_payload` | `block-domain` | The domain is rated suspicious and a payload hash in the same incident is malicious, which confirms the domain served the payload. |
| `isolate_host_with_retrieved_payload` | `isolate-endpoint` | The host can be isolated and its connector GUID or hostname is in the host list of a malicious payload hash (payload retrieved). |
| `isolate_host_with_executed_payload` | `isolate-endpoint` | The host can be isolated, has a malicious Secure Endpoint detection in the lookback window, and at least one download destination (domain or IP) is malicious (payload executed). Covers payloads fetched from a bare IP. |

Encoding or obfuscation alone never triggers containment: a clean script is only recorded, and a malicious
destination without a retrieved or executed payload blocks the domain but does not isolate the host.

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

Each file in [`scenarios/`](scenarios/) pins the plan the engine must produce. Run them with
`PYTHONPATH=engine python -m xdr_plan check malicious-powershell` from the repository root.

| File | What it proves |
|---|---|
| [`01-encoded-cradle-payload-executed.yaml`](scenarios/01-encoded-cradle-payload-executed.yaml) | True positive: encoded command downloads and runs a malicious payload from an unknown domain; the domain is blocked and the host isolated, both with approval. |
| [`02-software-deployment-script.yaml`](scenarios/02-software-deployment-script.yaml) | Benign: a signed, encoded software-deployment script with a clean destination and a common clean installer produces no actions. |
| [`03-protected-host-allowlisted-domain.yaml`](scenarios/03-protected-host-allowlisted-domain.yaml) | Guardrails: a payload served from the organisation's own allow-listed domain onto a domain controller gives `skipped_allowlisted` and `elevated: true`. |
| [`04-fleet-wide-payload-over-limit.yaml`](scenarios/04-fleet-wide-payload-over-limit.yaml) | Blast radius: the same payload on six hosts exceeds `max_hosts_isolated`, so every isolation stays planned with `elevated: true` and the run escalates; the domain block is still planned. |
| [`05-ip-literal-cradle.yaml`](scenarios/05-ip-literal-cradle.yaml) | Edge case: a cradle that downloads from a bare IP has no domain to block, but a malicious detection plus a malicious IP still isolates the host. |
| [`06-cradle-contact-no-payload.yaml`](scenarios/06-cradle-contact-no-payload.yaml) | Edge case: a malicious domain contacted without a payload landing blocks the domain but does not isolate the host. |

## Notes

- Check against known admin and software-deployment scripts before escalating; tune exclusions in Secure Endpoint, not here.
- Domain, IP and hash observables are taken as the script's download destinations and written files as reported by the source alert. Investigation results do not yet declare structured network events, so the rules cannot tie a destination to the PowerShell process itself.
- A cradle that downloads from a bare IP is not blocked here; this workflow has no `block-ip` step. Hand the IP to the [`c2`](../c2/README.md) workflow when network blocking is needed.

## Related workflows

[`malware`](../malware/README.md), [`c2`](../c2/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
