# Workflow: Web application attacks

Respond to injection, scanning or web shell activity against internet-facing applications.

|  |  |
|---|---|
| Default severity | medium |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Splunk](../../integrations/splunk/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Cloudflare WAF rule hits above baseline
- Web shell detection on a web server

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Vulnerability Scanning |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-ip`](../../atomic/enrich-ip/README.md), [`enrich-domain`](../../atomic/enrich-domain/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md).
4. **Decide.** Build a containment plan from the [containment rules](#containment-rules) and drop protected, allow-listed or over-limit targets. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note (plan, approvals, results and the rollback for every action) and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-ip`](../../atomic/block-ip/README.md) | External source IP from the incident whose `enrich-ip` verdict is malicious or suspicious and that is not in `incident.context.authorized_scanners`. Internal, allow-listed or private addresses are skipped by the guardrails. Expires after `expiry_hours.block-ip`. | yes |
| [`block-url`](../../atomic/block-url/README.md) | Endpoint listed in `incident.context.targeted_endpoints` that is known vulnerable while its fix is still pending (virtual patch at the edge). URLs on allow-listed domains are skipped by the guardrails. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Investigated web server with a detection of disposition malicious and technique T1505.003 (confirmed web shell) whose connector allows isolation. Scanning or exploit attempts alone never isolate. Runs only after the approver and the server owner accept the plan. | yes |

### Error handling

Every step sets `on_error` in [`workflow.yaml`](workflow.yaml):

| Steps | `on_error` | Why |
|---|---|---|
| `load_incident`, `load_guardrails` | `stop` | Without the incident or the guardrails nothing can be planned safely. |
| `enrich_ip`, `enrich_domain`, `investigate_host` | `continue` | A missing record only means fewer rules match; the gap is shown in the note. |
| `build_plan`, `approval` | `escalate` | No plan or no approval means a human decides; containment never runs without an approved plan. |
| `block_ip`, `block_url`, `isolate_endpoint` | `escalate` | A failed containment action leaves the attack path open and needs a human. |
| `incident_note` | `escalate` | The rollback record for every containment action is mandatory. |
| `create_ticket`, `notify_soc` | `continue` | The incident note already holds the record. |

## Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) turns the conditions above into rule expressions
(language in [`engine/README.md`](../../engine/README.md)). The guardrails run after each rule matches.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `block_attacking_sources` | `block-ip` | For each enriched IP: the verdict is malicious or suspicious and the IP is not listed as an authorised scanner in the incident context. Target is the IP; expiry comes from the guardrails (default 168 hours). |
| `block_vulnerable_endpoint` | `block-url` | For each endpoint in `incident.context.targeted_endpoints`: it is marked vulnerable and its fix is pending. Target is the endpoint URL. |
| `isolate_web_shell_host` | `isolate-endpoint` | For each investigated host: the connector allows isolation and at least one detection is malicious with technique T1505.003 (web shell). Target is the connector GUID; the reason names the host and incident. |

Incident context fields the rules read (set by the triggering source or the analyst):

- `authorized_scanners`: list of IPs of sanctioned external scanners. Optional.
- `targeted_endpoints`: list of `{url, vulnerable, fix_pending}` for application endpoints the attack targeted. Optional.

`investigate-host` detections are read as `{name, disposition, technique}`; `technique` is optional.

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

- Scanning alone is usually low severity; escalate only when combined with success indicators. Scanning
  sources may be blocked, but isolation needs a confirmed web shell.
- A web server with a confirmed web shell that is protected or not isolation-capable is not isolated
  automatically; the ticket asks the owner to take it out of the pool and review its web root.
- `block-url` targets on an allow-listed domain (for example `example.com`) are skipped by the guardrails,
  so virtual patches for applications on your own allow-listed domains need a manual edge rule.

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with
`PYTHONPATH=engine python -m xdr_plan check web-attacks` from the repository root. They use
`shop.example.net` as an internet-facing application domain that is not on the allow-list.

| File | What it proves |
|---|---|
| [`01-confirmed-web-shell.yaml`](scenarios/01-confirmed-web-shell.yaml) | A confirmed web shell plans all three actions: block the source, block the vulnerable endpoint and isolate the infected server, while a clean server in the same pool is left alone. |
| [`02-authorised-scanner.yaml`](scenarios/02-authorised-scanner.yaml) | An authorised external scanner with a suspicious reputation, no vulnerable endpoint and a clean server produces no actions. |
| [`03-scanning-only.yaml`](scenarios/03-scanning-only.yaml) | Unauthorised scanning blocks the source only; a suspicious non-web-shell detection does not isolate the server. |
| [`04-guardrail-skips.yaml`](scenarios/04-guardrail-skips.yaml) | Guardrails skip a protected server (`skipped_protected`), an internal source (`skipped_internal`) and an endpoint on the allow-listed domain (`skipped_allowlisted`), while the external source is still blocked. |
| [`05-distributed-sources-escalate.yaml`](scenarios/05-distributed-sources-escalate.yaml) | More attacking sources than `max_indicators_blocked` turns every block into `skipped_limit` and escalates to a human. |

## Related workflows

[`vulnerability-exploitation`](../vulnerability-exploitation/README.md), [`persistence`](../persistence/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
