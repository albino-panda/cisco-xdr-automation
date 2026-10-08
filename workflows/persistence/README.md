# Workflow: Persistence

Find and remove attacker footholds such as run keys, scheduled tasks, services and new accounts.

|  |  |
|---|---|
| Default severity | medium |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Splunk](../../integrations/splunk/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- New autorun entry or service from an unknown binary
- New local or cloud account outside change windows

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-hash`](../../atomic/enrich-hash/README.md), [`enrich-domain`](../../atomic/enrich-domain/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md).
4. **Decide.** Build a containment plan and skip allow-listed and internal targets; protected and over-limit targets stay planned with ELEVATED approval and a visible warning. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-hash`](../../atomic/block-hash/README.md) | `enrich-hash` returned disposition `malicious` without an error for the persisted binary. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | `investigate-host` returned at least one `malicious` detection in the lookback window, the connector is isolation capable and the lookup had no error. | yes |

### Error handling

Every step sets `on_error` in [`workflow.yaml`](workflow.yaml). `escalate` records the failure, flags the
incident for a human and lets the record and notify steps still run.

| Step | `on_error` | Why |
|---|---|---|
| `load_incident`, `load_guardrails` | stop | Without the incident or the guardrails nothing can be decided safely. |
| `enrich_hash`, `enrich_domain`, `investigate_host` | continue | A failed lookup only removes evidence; rules ignore records with an `error`. |
| `build_plan`, `approval` | escalate | No containment runs without a plan and an approval; a human takes over. |
| `block_hash`, `isolate_endpoint` | escalate | A failed containment leaves the foothold active, so a human must follow up. |
| `incident_note`, `create_ticket`, `notify_soc` | continue | Recording or notification failures do not change containment; the remaining channels still carry the result. |

## Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) turns the conditions above into expressions the
[plan engine](../../engine/README.md) evaluates. Guardrails (allow-listed hashes, protected hosts,
blast-radius caps) are applied by the engine after each rule matches.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `block_malicious_persisted_binary` | `block-hash` | For each `enrich-hash` result: the binary behind the run key, startup item, scheduled task or service has disposition `malicious` and the lookup returned no error. Clean or unknown binaries are not blocked. Target: `sha256`. |
| `isolate_hosts_with_active_execution` | `isolate-endpoint` | For each `investigate-host` result: the connector is isolation capable, the lookup returned no error and at least one detection in the lookback window is `malicious`. A host where the item is present but has not executed (only suspicious or no detections) is not isolated. Target: `connector_guid`. |

Rollback for both actions is written into the incident note (`templates.incident_note`): delete the
hash from the Secure Endpoint simple custom detection list, and stop isolation for the connector GUID.
The stop-isolation call is taken from the `isolate-endpoint` atomic and is not yet verified against
current Secure Endpoint API documentation.

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with
`PYTHONPATH=engine python -m xdr_plan check persistence`.

| File | What it proves |
|---|---|
| [`01-malicious-run-key.yaml`](scenarios/01-malicious-run-key.yaml) | True positive: a Run key binary rated malicious and executing produces a planned hash block and a planned isolation, both needing approval. |
| [`02-legit-updater-service.yaml`](scenarios/02-legit-updater-service.yaml) | Benign: a newly installed, clean and widespread vendor updater service with no malicious detections produces no actions. |
| [`03-allowlisted-hash-protected-host.yaml`](scenarios/03-allowlisted-hash-protected-host.yaml) | Guardrails: an allow-listed admin tool hash is `skipped_allowlisted` and isolation of the protected domain controller is planned with `elevated: true`. |
| [`04-dormant-scheduled-task.yaml`](scenarios/04-dormant-scheduled-task.yaml) | Edge case: a scheduled task that has not run yet gets its malicious binary blocked but the host is not isolated; an unknown binary with an enrichment error is left alone. |
| [`05-fleet-wide-service.yaml`](scenarios/05-fleet-wide-service.yaml) | Edge case: one malicious service on six hosts exceeds `max_hosts_isolated`, so every isolation stays planned with `elevated: true` and the plan escalates, while the single hash block stays planned. |

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

## Notes

- Removal of the persistence item itself is a manual or EDR-assisted step; record each item removed.
  The incident note and ticket templates carry a checklist line per item type: Run / RunOnce value,
  startup folder item, scheduled task, service, unauthorised account, the persisted binary on every
  affected host, and a re-scan after reboot.
- `enrich-domain` results are context for the note and ticket only. Blocking C2 domains belongs to the
  [`c2`](../c2/README.md) workflow.
- New-account persistence (T1136) has no automated containment here: no plan rule disables accounts.
  The account is handled through the manual checklist.

## Related workflows

[`malware`](../malware/README.md), [`privilege-escalation`](../privilege-escalation/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from the `plan` rules, error handling from `on_error`, and texts from `templates`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
