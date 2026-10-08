# Workflow: DNS tunneling

Respond to data or command traffic hidden in DNS queries.

|  |  |
|---|---|
| Default severity | high |
| Status | Specification. Not yet built in XDR Automation. |
| Machine-readable spec | [`workflow.yaml`](workflow.yaml) |
| Integrations | [Cisco XDR](../../integrations/cisco-xdr/README.md), [Cisco Umbrella / Secure Access](../../integrations/umbrella/README.md), [Cisco Secure Endpoint](../../integrations/secure-endpoint/README.md), [Cisco Meraki](../../integrations/meraki/README.md), [Splunk](../../integrations/splunk/README.md), [Cloudflare](../../integrations/cloudflare/README.md), [ServiceNow](../../integrations/servicenow/README.md) |

## Triggers

- **Incident rule** in XDR Automation matching the techniques below or the detection titles your sources produce.
- **Pivot menu** on an incident or observable for manual runs.
- **Playbook task** in the matching XDR incident response playbook.

## Detection signals

Typical alerts that should route to this workflow:

- Umbrella DNS tunneling category hit
- High-entropy or high-volume subdomain queries to one parent domain

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS |
| [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling |

## Response flow

1. **Intake.** Load the incident summary, observables and the guardrails file. A failure stops the run.
2. **Enrich.** [`enrich-domain`](../../atomic/enrich-domain/README.md) on the tunneling parent domain named by the detection, not on each unique subdomain. A failure is recorded and the run continues.
3. **Investigate.** [`investigate-host`](../../atomic/investigate-host/README.md) on every host that queried the parent domain, including clients found in internal resolver logs when Umbrella only sees the forwarding resolver. A failure is recorded and the run continues.
4. **Decide.** Build a containment plan and skip allow-listed and internal targets; protected and over-limit targets stay planned with ELEVATED approval and a visible warning. Send the plan to an approver unless `dry_run` is true. A failure escalates to a lead.
5. **Contain.** Run the approved actions below. Each action records its result, even when skipped. A failure escalates to a lead.
6. **Record.** Add an incident note with the rollback for every action, and [`create-ticket`](../../atomic/create-ticket/README.md).
7. **Notify.** [`notify-soc`](../../atomic/notify-soc/README.md).

### Containment actions

| Action | When | Approval |
|---|---|---|
| [`block-domain`](../../atomic/block-domain/README.md) | The parent domain is a confirmed tunnel. Enrichment rates it malicious, or rates it suspicious or unknown while Umbrella puts it in the DNS Tunneling VPN category with at least 1000 internal queries in the lookback window. Clean domains and failed enrichments are never blocked. | yes |
| [`isolate-endpoint`](../../atomic/isolate-endpoint/README.md) | The host can be isolated and its trajectory shows a process that queried a confirmed tunnel parent domain or one of its subdomains. The process is not an approved security or VPN tool (`allowlist.approved_dns_tools`) and not a DNS server forwarding client queries (`dns.exe`, `named`, `unbound`, `dnsmasq`). | yes |

### Containment rules

The `plan` rules in [`workflow.yaml`](workflow.yaml) are the exact form of the conditions above. The guardrails (protected hosts, allow-listed domains, blast-radius caps) run after each rule.

| Rule id | Atomic | Condition |
|---|---|---|
| `block_tunnel_parent_domain` | `block-domain` | For each enriched domain without an error: the verdict is malicious, or the verdict is suspicious or unknown and the categories include DNS Tunneling VPN and internal queries are 1000 or more. Targets the parent domain in lower case, with expiry from `expiry_hours.block-domain` (default 720 hours). |
| `isolate_tunnel_client_hosts` | `isolate-endpoint` | For each investigated host without an error that is isolation-capable: a trajectory event's process is neither in `allowlist.approved_dns_tools` nor a DNS server process, and it queried a domain that passes the block test above (the parent itself or any subdomain). Targets the connector GUID. |

## Scenarios

Scenario files in [`scenarios/`](scenarios/) pin the expected plan. Run them with `PYTHONPATH=engine python -m xdr_plan check dns-tunneling`.

| File | What it proves |
|---|---|
| [`01-confirmed-tunnel.yaml`](scenarios/01-confirmed-tunnel.yaml) | True positive: a malicious tunnel parent domain is blocked once and the workstation whose unknown process queried it is isolated, both pending approval. |
| [`02-security-product-lookups.yaml`](scenarios/02-security-product-lookups.yaml) | Benign: an approved antivirus product's encoded DNS lookups are high-volume and in the tunneling category, but the clean verdict and approved process produce no actions. |
| [`03-protected-host.yaml`](scenarios/03-protected-host.yaml) | Guardrail: a protected `hv-*` host is planned with `elevated: true`, a host that cannot be isolated gets no action, and the other workstation is isolated. |
| [`04-blast-radius.yaml`](scenarios/04-blast-radius.yaml) | Guardrail: six querying hosts exceed `max_hosts_isolated`, so every isolation stays planned with `elevated: true` and the plan escalates; the domain block stays planned. |
| [`05-internal-resolver-forwarding.yaml`](scenarios/05-internal-resolver-forwarding.yaml) | DNS edge case: the internal resolver that forwards the queries (`dns.exe`) is never isolated even though it is not protected; only the real client is isolated, and many subdomains still give one block. |
| [`06-new-domain-without-reputation.yaml`](scenarios/06-new-domain-without-reputation.yaml) | DNS edge case: a new domain with an unknown verdict is blocked on category and volume, while a low-volume VPN health-check domain in the same category is not. |

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

- Some security and VPN products legitimately use DNS-based lookups; check the allow-list first. Add their domains to `allowlist.domains` and their process names to `allowlist.approved_dns_tools` in the guardrails file. The rules read `approved_dns_tools` with an empty default, because the key is not yet in `guardrails.example.yaml`.
- The isolation rule reads `process` and `domain` from each `investigate-host` trajectory event. The atomic declares `trajectory` as a list without an entry schema, so the built atomic must return DNS events in that shape.
- Umbrella only sees the resolver that forwards a query. When the incident names an internal resolver, find the real clients in the resolver logs (Splunk) and investigate them too.
- The isolation rollback endpoint (`DELETE /v1/computers/{guid}/isolation`) is taken from the atomic spec and has not been verified against Secure Endpoint documentation.

## Related workflows

[`c2`](../c2/README.md), [`exfiltration`](../exfiltration/README.md)

## Building it in XDR Automation

1. Import the Cisco-managed atomics this workflow needs from the Exchange, plus the custom atomics in [`atomic/`](../../atomic/README.md).
2. Create the workflow from [`workflow.yaml`](workflow.yaml): variables from `inputs`, one group per `phase`, conditions from `when`.
3. Test with `dry_run = true` against a test incident (see [docs/testing](../../docs/testing/README.md)).
4. Export the workflow JSON and commit it here as `workflow.export.json`.
