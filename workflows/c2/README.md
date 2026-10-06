# Workflow: Command and control

Cut off a host beaconing to attacker infrastructure and find other hosts talking to it.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Umbrella security category hit (C2 / malware)
- Periodic beaconing detection
- XDR incident with C2 indicators

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel |
| [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | Domain Generation Algorithms |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-ip`](../../atomic/enrich-ip/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md).
4. **Decide.** Build a containment plan and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-domain`](../../atomic/block-domain/README.md) | Domain with `enrich-domain` verdict malicious, or verdict suspicious with a Command and Control category. Allow-listed domains are skipped by the guardrails. | yes |
| [`block-ip`](../../atomic/block-ip/README.md) | IP with `enrich-ip` verdict malicious that is not listed in `incident.context.shared_infrastructure_ips` (shared hosting or CDN). Internal and allow-listed ranges are skipped by the guardrails. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Isolation-capable host with a malicious endpoint detection while at least one domain or IP in the incident has a malicious verdict. Protected hosts are skipped; more than `max_hosts_isolated` escalates. | yes |

### Error handling

Every step in [`workflow.yaml`](workflow.yaml) sets `on_error`:

| Steps | `on_error` | Why |
|---|---|---|
| `load_incident`, `load_guardrails` | `stop` | Without the incident or the guardrails nothing can be planned safely. |
| `enrich_domain`, `enrich_ip`, `investigate_host` | `continue` | A failed lookup leaves that indicator or host without a verdict, so no rule fires for it. The error is recorded. |
| `build_plan`, `approval` | `escalate` | No containment runs without a reviewed plan; a human takes over. |
| `block_domain`, `block_ip` | `continue` | Indicator blocks are independent. If one fails, the other block and the host isolation still cut the channel, and the failure is written to the note, ticket and notification. |
| `isolate_endpoint` | `escalate` | A host that keeps beaconing needs a human straight away. |
| `incident_note`, `create_ticket`, `notify_soc` | `continue` | Recording and notification failures must not hide each other. |

## Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) turns the conditions above into rules the
[plan engine](../../engine/README.md) evaluates. Guardrails (protected hosts, allow-lists, internal ranges,
blast-radius caps) are applied by the engine after each rule and are not repeated in the rules.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `block_c2_domains` | `block-domain` | Every enriched domain with a malicious verdict, or a suspicious verdict plus a Command and Control category. Malicious blocks use the guardrails expiry (default 720 h); suspicious blocks expire after 168 h. |
| `block_c2_ips` | `block-ip` | Every enriched IP with a malicious verdict, unless it is listed in `incident.context.shared_infrastructure_ips` as shared hosting or CDN. Expiry from the guardrails (default 168 h). |
| `isolate_beaconing_hosts` | `isolate-endpoint` | Every investigated host that is isolation-capable and has a malicious endpoint detection, provided at least one domain or IP in the incident is malicious. Targets the connector GUID with reason `C2 beaconing: <incident title>`. |

Hosts that match but are not isolation-capable are not planned. They appear in the incident note for
manual handling.

## Scenarios

Run them with `PYTHONPATH=engine python -m xdr_plan check c2` from the repository root.

| File | What it proves |
|---|---|
| [`01-confirmed-beaconing.yaml`](scenarios/01-confirmed-beaconing.yaml) | True positive: malicious C2 domain and IP are blocked and the infected host is isolated; a host that only queried the domain is left alone. |
| [`02-benign-saas-heartbeat.yaml`](scenarios/02-benign-saas-heartbeat.yaml) | A periodic check-in to a clean SaaS endpoint produces no actions. |
| [`03-guardrail-skips.yaml`](scenarios/03-guardrail-skips.yaml) | Allow-listed own domain, internal relay IP and protected domain controller are kept as `skipped_allowlisted`, `skipped_internal` and `skipped_protected` while the external C2 domain is planned. |
| [`04-blast-radius-many-hosts.yaml`](scenarios/04-blast-radius-many-hosts.yaml) | Six beaconing hosts exceed `max_hosts_isolated`: every isolation becomes `skipped_limit` and the run escalates, while the domain and IP blocks stay planned. |
| [`05-suspicious-dga-domain.yaml`](scenarios/05-suspicious-dga-domain.yaml) | Suspicious DGA-style domains: only the one categorised Command and Control is blocked (168 h expiry); the host with only a suspicious detection is not isolated. |
| [`06-shared-hosting-ip.yaml`](scenarios/06-shared-hosting-ip.yaml) | A malicious domain behind a shared CDN address: the domain is blocked and the host isolated, the shared IP is not blocked, and a host that is not isolation-capable is not planned. |

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
- Every containment action is reversible, and the rollback is written into the incident note: remove the domain or IP from the block list (blocks also auto-expire), or stop isolation for the connector GUID in Secure Endpoint. The Secure Endpoint stop-isolation endpoint is not yet verified against vendor documentation.

## Notes

- Use `internal_queries` and `internal_sightings` from enrichment to find every beaconing host, not just the alerting one. Both are counts, so the hosts themselves must be added as incident targets (by the source or the analyst) before `investigate-host` runs.
- A suspicious verdict never isolates a host on its own. It only blocks a domain that is also categorised Command and Control, with a shorter expiry.
- Shared hosting and CDN addresses are listed in `incident.context.shared_infrastructure_ips` at intake; blocking them would cut legitimate traffic, so only the domain is blocked.
- `templates` in [`workflow.yaml`](workflow.yaml) hold the approval text, incident note (with rollback), ticket title and body, and SOC notification.

## Related workflows

[`dns-tunneling`](../dns-tunneling/README.md), [`malware`](../malware/README.md), [`exfiltration`](../exfiltration/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
