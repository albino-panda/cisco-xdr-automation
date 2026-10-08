# Workflow: Unauthorised remote access tool

Detect and remove remote monitoring and management tools that are not sanctioned by IT.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Splunk](../../integrations/splunk/README.md), [Microsoft Entra ID (via Microsoft Graph)](../../integrations/microsoft-entra/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Installation or execution of an RMM tool not on the approved list
- DNS queries to RMM vendor relay domains from unexpected hosts

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Tools |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md), [`enrich-hash`](../../atomic/enrich-hash/README.md).
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md), [`investigate-user`](../../atomic/investigate-user/README.md).
4. **Decide.** Build a containment plan from the [containment rules](#containment-rules) and skip allow-listed and internal targets; protected and over-limit targets stay planned with ELEVATED approval and a visible warning. A tool named in `guardrails.allowlist.approved_rmm` is never blocked. Send the plan to an approver unless `dry_run` is true.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped.
6. **Record.** Add an incident note (with the rollback for every action) and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-domain`](../../atomic/block-domain/README.md) | Enriched domain is listed in `incident.context.rmm_relay_domains`, and the detected tool (`incident.context.rmm_tool`) is named and not in `guardrails.allowlist.approved_rmm`. | yes |
| [`block-hash`](../../atomic/block-hash/README.md) | Enriched SHA-256 is listed in `incident.context.rmm_installer_sha256`, and the detected tool is named and not in `guardrails.allowlist.approved_rmm`. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | Investigated host is isolation-capable and has an active session in `incident.context.rmm_sessions` whose remote operator is not verified as IT staff. Applies to sanctioned tools too. | yes |

### Incident context

No atomic returns the RMM tool name or the session operator, so the rules read these facts from `incident.context`, filled at intake from the detection (Secure Endpoint or XDR):

| Field | Type | Meaning |
|---|---|---|
| `rmm_tool` | string | Name of the detected remote access tool, compared case-insensitively with `allowlist.approved_rmm`. When empty, nothing is blocked. |
| `rmm_relay_domains` | list | Relay or broker domains the detection attributes to that tool. |
| `rmm_installer_sha256` | list | SHA-256 of the tool's installer or binary. |
| `rmm_sessions` | list | `{host, active, operator_verified}` per session. `host` is a hostname or connector GUID. `operator_verified` is true only when IT matched the session to a service desk ticket. |

### Error handling

| Steps | `on_error` | Why |
|---|---|---|
| `load_incident`, `load_guardrails` | `stop` | Without the incident or guardrails nothing can be decided safely. |
| `enrich_*`, `investigate_*` | `continue` | A missing record only means fewer targets in the plan. |
| `build_plan`, `approval` | `escalate` | No containment without a plan and an approval decision; a human takes over. |
| `block_domain`, `block_hash` | `continue` | Continuing is safer: halting here would leave the remote session open when isolation is still to run. The failure is recorded in the note and ticket. |
| `isolate_endpoint` | `escalate` | A failed isolation may leave an attacker with live access. |
| `incident_note` | `escalate` | The note is the only record of the rollback steps. The isolation unlock code stays in the Secure Endpoint console. |
| `create_ticket`, `notify_soc` | `continue` | Record and notify are best effort once the note is written. |

## Containment rules

The `plan` list in [`workflow.yaml`](workflow.yaml) holds the exact expressions. The engine applies the protected-host, allow-list and blast-radius guardrails after each rule.

| Rule id | Atomic | Condition in plain English |
|---|---|---|
| `block_unapproved_rmm_relay_domain` | [`block-domain`](../../atomic/block-domain/README.md) | For each enriched domain: the detection names the tool, the tool is not on the approved RMM list, and the domain is one of the tool's relay domains. Expires after `expiry_hours.block-domain` (default 720). |
| `block_unapproved_rmm_installer` | [`block-hash`](../../atomic/block-hash/README.md) | For each enriched hash: the detection names the tool, the tool is not on the approved RMM list, and the hash is the tool's installer. |
| `isolate_host_with_unverified_rmm_session` | [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | For each investigated host: isolation is possible and an active session on that host (by hostname or connector GUID) has a remote operator IT has not verified. Applies even to an approved tool, because the session, not the tool, is the threat. |

## Scenarios

Run with `PYTHONPATH=engine python -m xdr_plan check unauthorized-rmm`. Tool names are fictional: `FictiDesk` is unapproved and `ExampleRMM` is the sanctioned tool from the example guardrails.

| File | What it proves |
|---|---|
| [`01-unapproved-tool-fake-helpdesk.yaml`](scenarios/01-unapproved-tool-fake-helpdesk.yaml) | True positive: after a fake help-desk call, both relay domains and the installer of the unapproved tool are blocked and the host with the live session is isolated. Internal domain, unrelated hash and a host without a session are left alone. |
| [`02-sanctioned-examplermm.yaml`](scenarios/02-sanctioned-examplermm.yaml) | Benign: the sanctioned `ExampleRMM` used by verified IT staff produces no actions, even with its relay domain and installer in the context. |
| [`03-guardrail-skips.yaml`](scenarios/03-guardrail-skips.yaml) | Guardrails: isolation of a domain controller is planned with `elevated: true`, an allow-listed installer hash is `skipped_allowlisted`, and the relay domain is still blocked. |
| [`04-sanctioned-tool-unverified-operator.yaml`](scenarios/04-sanctioned-tool-unverified-operator.yaml) | RMM edge case: the attacker uses the sanctioned tool through a fake help-desk call. Nothing about the tool is blocked (that would break IT support), but the host with the unverified session is isolated. |
| [`05-helpdesk-campaign-blast-radius.yaml`](scenarios/05-helpdesk-campaign-blast-radius.yaml) | Blast radius: six hosts with live sessions exceed `max_hosts_isolated` (5), so every isolation stays planned with `elevated: true` and the plan escalates, while the domain and hash blocks are still planned once. |

## Inputs

| Variable | Type | Required | Description |
|---|---|---|---|
| `incident_id` | string | no | Cisco XDR incident ID, used for notes and audit. |
| `dry_run` | boolean | no | When true, report the planned change without making it. Default true for containment. |
| `observables` | list | no | Overrides the incident observables. |

## Guardrails

- `dry_run` defaults to `true`. Switch it off per workflow only after a successful review of dry-run output.
- Nothing is actioned without a human approval. Allow-listed indicators are never actioned; protected hosts and users, and every action over a blast-radius cap, need ELEVATED approval with a visible warning.
- Tools in `allowlist.approved_rmm` are never blocked. The engine does not check this list itself, so the block rules read it.
- Blast-radius limits cap how many hosts, users or indicators a single run may touch.
- Every containment action is reversible except session revocation, and the rollback is written into the incident note.

## Notes

- Keep the approved-RMM list in the guardrails file so sanctioned tools are never blocked.
- Common follow-up to mail bombing and fake help-desk contact.

## Related workflows

[`mail-bombing`](../mail-bombing/README.md), [`persistence`](../persistence/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from the `plan` rules, error handling from `on_error`, texts from `templates`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
