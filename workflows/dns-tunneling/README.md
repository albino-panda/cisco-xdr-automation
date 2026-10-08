# DNS tunneling

Phase 4 workflow `dns-tunneling` (definition version 2.0.0). Code:
`src/xdr_response/workflows/dns_tunneling/` (`definition.py`, `hooks.py`). It replaces the legacy
plan-rule spec (`workflow.yaml` and its six scenarios), which were migrated to typed simulation
scenarios and deleted. The binding design is [docs/architecture.md](../../docs/architecture.md)
sections 12 to 14.

## Purpose

Respond to data or command traffic hidden in DNS queries. A client process encodes data into long,
random-looking labels under one parent domain that the operator controls, and reads the answers
(often TXT records) back. The workflow automatically investigates:

- the **parent domain**: reputation and the Umbrella "DNS Tunneling VPN" category;
- the **DNS behaviour** under it: query volume and frequency, subdomain variation, the longest label
  (query length), the Shannon entropy of the child labels and the record types that carry data back;
- the **endpoints and processes** that issued the queries, including the real client behind an
  internal resolver that only forwards queries;
- the **querying binaries**: reputation, prevalence and code-signing subject;
- the **transfer pattern**: queries, time window, rate and an upper-bound estimate of the encoded
  bytes sent upstream.

It then **recommends** a containment package with numbered evidence and separate risk and confidence
scores:

- block the tunnel parent domain once (never each random subdomain);
- terminate the querying process;
- isolate the client endpoint.

Things that look like a tunnel but are not are never contained. A parent domain that reputation rates
clean (a security, VPN or diagnostics product that encodes lookups in DNS) is listed as considered. A
forwarding resolver is never isolated. The approved DNS tools of `allowlists.approved_dns_tools`
(`config/allowlists.yaml`) are enforced by the framework on every proposal: the tool's domains are
moved to the package's excluded targets (shown, never executed). The termination of an approved
binary is withheld, and so is an isolation or an unrated domain block that rests only on approved
binaries. Each of these is shown as considered.

The workflow never executes, approves or chooses an approval level. A human approves the package.
Only then does the lifecycle orchestrator execute and verify it, and restoration needs a separate
human release approval.

Default severity: HIGH. Related workflows: [c2](../c2/README.md) (other command and control
channels), [exfiltration](../exfiltration/README.md) (data that left through the tunnel),
[malware](../malware/README.md) (the client binary).

## Trigger

| Type | Matches | Priority |
|---|---|---|
| XDR incident rule | the incident reports one of the techniques of the MITRE mapping (DNS application-layer protocol or protocol tunneling) **and** carries a domain or a hostname | 170 |
| XDR incident rule | the title matches `*dns tunnel*`, `*dns-tunnel*`, `*tunneling over dns*`, `*tunnelling over dns*` or `*dns tunneling vpn*` (for example an Umbrella "DNS Tunneling VPN" category hit) **and** the incident carries a domain or a hostname | 165 |
| Manual | an analyst starts the workflow from an incident, a domain or an endpoint observable (never matches automatically) | n/a |

An incident whose `workflow_id` is `dns-tunneling` always runs this workflow. When several workflows
match, the highest priority wins, then the workflow id. A DNS-specific detection should come here
rather than to a generic command and control workflow, hence the high priority.

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence
drops, but a recommendation backed by other evidence is still made.

- `umbrella`: domain status and categories of the tunnel parent domain (`enrich_domain`, VERIFIED
  categorization endpoint; the "DNS Tunneling VPN" category), and the landing product for approved
  domain blocks (destination lists, VERIFIED).
- `secure_endpoint`: endpoint record, device trajectory (the process that issued the DNS queries),
  hash prevalence and signer, and the isolation of the client endpoint (`investigate_endpoint`,
  `search_hash_enterprise`). The computer and trajectory reads are VERIFIED, but trajectory events have
  no documented field schema (see Known limitations).

## Optional integrations

- `splunk`: internal resolver and DNS security logs (`search_domain_enterprise`): query volume,
  subdomain variation, label length, record types and the real client behind a forwarding resolver.
- `defender_endpoint`: second endpoint source (machine, alerts, timeline, prevalence), DNS activity
  rows, and isolation or process termination for the endpoints it manages.
- `cisco_xdr`: platform verdicts and sightings for the parent domain and the querying binaries, and the
  native response actions (`respond/observables`, `respond/trigger`) the router prefers when
  configured.
- `virustotal`: public reputation of the parent domain and the querying binaries (disclosure policy
  applies: internal domains are never sent).
- `alienvault_otx`: independent reputation (OTX pulses, passive DNS) for the parent domain and the
  querying binaries.

## Input data

Incident observables of type `domain` (the tunnel parent the detection names), `hostname`, `ip` and
`sha256`, and `trigger.mitre_techniques` / `trigger.source` for routing. Values found by earlier steps
feed later steps: the endpoints a DNS source names as querying clients are investigated next, and the
hashes of the querying processes are enriched. Free text such as a vendor's "mean label entropy" stays
in `incident.trigger` as data; it is never evidence on its own (the workflow computes its own entropy
from the names the records report). All test data is fake.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues.

| # | Step | Atomic | Subjects | Sources |
|---|---|---|---|---|
| 1 | `endpoint_triage` | `investigate_endpoint` | incident hostnames | Secure Endpoint, Defender, Cisco XDR |
| 2 | `dns_activity` | `search_domain_enterprise` | the tunnel parents: incident domains and domains a DNS source aggregates over subdomains (at most 10) | Splunk, Cisco XDR, Defender |
| 3 | `tunnel_clients` | `investigate_endpoint` | incident hostnames and every endpoint a DNS record names as a querying client | Secure Endpoint, Defender, Cisco XDR |
| 4 | `parent_reputation` | `enrich_domain` | the tunnel parents (never each random child name; at most 10) | every enricher, disclosure policy applies |
| 5 | `querying_binary_reputation` | `enrich_hash` | hashes of processes that issued DNS queries and of detections (at most 10) | every enricher |
| 6 | `querying_binary_prevalence` | `search_hash_enterprise` | the same hashes (prevalence, endpoints, code-signing subject) | Secure Endpoint, Defender, Cisco XDR |

The hooks (`hooks.py`) then derive facts from the run's own records, each with the record ids it was
computed from:

- **tunnels**, one per parent domain. Child names are grouped under the shortest known parent
  (incident domain, aggregated or enriched domain), else under the registrable domain. Each tunnel
  carries the five indicators, the category, the reputation and record verdicts, the client and
  resolver hosts and the transfer pattern. The five indicators are:
  - volume: at least 1000 queries;
  - subdomain variation: at least 200 distinct child names;
  - long labels: at least 40 characters;
  - label entropy: at least 3.5 bits per character over child labels of 12 characters or more;
  - data record types: TXT or NULL.
- **clients**: endpoints whose process (not a DNS server process) queried a confirmed tunnel, with the
  querying processes, their binaries and the endpoint identity for isolation.
- **processes**: those querying processes that were not seen ending (termination targets
  `<ENDPOINT>/<pid>`).

## Correlation logic

- Child names are grouped under their parent domain, so thousands of random subdomains give one tunnel
  and at most one block.
- Framework links: the same domain, hash or IP on two or more endpoints (one tunnel parent or one
  client binary across the estate); the same endpoint or user across sources; process lineage. Window
  120 minutes.
- Workflow links (hooks, kind `workflow`): a tunnel client, meaning the endpoint, the querying binary
  and the parent domain its process queried.
- A parent is a **confirmed tunnel** only when reputation does not rate it CLEAN **and** one of these
  holds:
  - reputation rates it MALICIOUS, or a DNS or process record of it is MALICIOUS;
  - a detection that names DNS tunneling (the techniques of the MITRE mapping or the words "DNS
    tunnel") is tied to a process that queried it on the same endpoint;
  - it is in the DNS tunneling category with at least 1000 queries (the legacy rule: new tunnel
    domains often have no reputation yet);
  - it shows a behaviour profile: at least 3 of the 5 indicators, one of them volume or subdomain
    variation.
- A host whose only queries come from DNS server software is a **forwarding resolver**: dns.exe,
  named, unbound, dnsmasq, pdns_recursor, pdns_server, coredns and kresd. The real client comes from
  the resolver's own log.
- Links shape the clusters, the blast radius and the decision card. They are never evidence on their
  own and never change an approval level.

## Risk calculation

Each target is scored by the scoring engine (docs/threat-scoring.md) from the records its rule cites
plus the target's enrichment:

- reputation answers from Umbrella, Cisco XDR, VirusTotal and OTX are vendor verdicts, capped by the
  engine. One vendor alone is never an aggregate MALICIOUS verdict.
- DNS and network records with a verdict, and malicious or suspicious process events, count as
  `network_behaviour` or `endpoint_detection`.
- The tunnel pattern itself is a hook-derived `network_behaviour` signal (SUSPICIOUS, severity 70,
  confidence 60): the DNS tunneling category with high volume, or the behaviour profile. It cites the
  DNS and process records it was computed from and is attributed to the source of those records, so
  two sources that both saw the pattern corroborate each other. The same pattern scores the client
  endpoint and the querying process from their own process records.
- A critical asset adds the engine's critical-asset bonus (only with malicious or suspicious
  evidence).

Risk and confidence are separate integers. The expected sources are Umbrella and Secure Endpoint: a
failed one costs confidence once and is listed as degraded. Rule thresholds: a domain block needs risk
40, a termination or an isolation risk 50. Below them the action is "considered, not proposed" and is
listed in the notes, never hidden.

## Containment recommendations

| Rule | Action (builder) | Proposed when | Evidence cited |
|---|---|---|---|
| `block_tunnel_parent_domain` | `block_domain` (catalog order: native, Umbrella, Defender) | the parent is a confirmed tunnel | the DNS records and process events under the parent, connection records, tied detections, the reputation answers that rate it |
| `terminate_tunnel_process` | `terminate_process` (target `<ENDPOINT>/<pid>`, or `<ENDPOINT>/<sha256>` without a pid) | a client process queried a confirmed tunnel and no `process_end` was seen | the process's query events, the records that make the parent a tunnel |
| `isolate_tunnel_client_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`, `connector_guid` param) | the client endpoint has a Secure Endpoint connector and isolation is not known to be impossible | the client's query events and DNS records, the records that make the parent a tunnel, the endpoint record |
| `isolate_tunnel_client_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | the same, for an endpoint with a Defender machine id (a duplicate of the Secure Endpoint proposal is merged) | the same |

Approved DNS tools (`allowlists.approved_dns_tools`) are handled by the framework, never by the
workflow:

- the tool's domains are built and shown as excluded with the reason;
- a termination of a process whose binary is an approved hash, or is reported signed by an approved
  signer, is withheld (`ALLOWLISTED`, shown as considered);
- an isolation whose querying binaries are all approved is withheld the same way (rule `binaries`,
  architecture 14.11.6);
- an unrated tunnel whose clients all run approved binaries is not blocked on their behaviour alone.

A process known only by name is never treated as approved.

### Items not proposed and manual steps

- Not proposed, and listed as considered:
  - a parent with tunnel indications that is not a confirmed tunnel (for example a VPN health check in
    the tunneling category with 40 queries, or a CDN with two of the five indicators);
  - a parent that reputation rates CLEAN although it looks like a tunnel;
  - the isolation of a forwarding resolver;
  - the isolation of an endpoint that reports it cannot be isolated, or that has no Secure Endpoint
    connector or Defender machine id;
  - the isolation of a host named only by DNS logs, with no endpoint record of the querying process;
  - from the framework, the termination, isolation and block that rest only on an approved DNS tool.
- Manual steps (no VERIFIED write or read):
  - remove the tunnel client binary on each client endpoint through the endpoint console;
  - assess the data that may have left through each confirmed tunnel (the transfer pattern is cited);
  - find the client behind a resolver when only the resolver is seen.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps"), each with the record ids that show it (architecture 14.10.1). This workflow declares
no hand-offs; it never starts another workflow.

## Approval requirements

- Every action in the package needs human approval before it runs: domain block, process
  termination, isolation, and later every release. AI and automation principals can never approve,
  and nothing in the workflow can switch approval off.
- ELEVATED approval applies, with a visible warning on the decision card, in two cases. It needs a
  human holding the elevated approver role, for example the SOC lead.
  - A target is a critical asset: for example a hypervisor, a production server or a domain
    controller, also for the endpoint part of a process target, or a host holding an allow-listed
    infrastructure address.
  - A blast-radius cap is exceeded: for example a tunnel client on more than 5 endpoints.
- ELEVATED is decided by `PackageBuilder` from the investigated asset context. The workflow never sets
  it, and a critical asset is never skipped silently.
- Before approving, the analyst checks that no listed domain or process belongs to a sanctioned
  security, VPN or diagnostics product. If one does, it is added to `allowlists.approved_dns_tools`
  with its hashes, signers and domains.
- The analyst may approve all, approve a selection, reject, or ask for more investigation.

## Containment execution

After approval the orchestrator executes the approved actions automatically, through the guard and
the approval token. It tries the native route first (Cisco XDR `respond/trigger` when
`native_actions` is configured), then the direct one:

| Action | Route with the real adapters |
|---|---|
| block domain | Umbrella destination lists (VERIFIED), Defender indicators, or the native action |
| isolate endpoint | Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` (VERIFIED) or Defender `POST /api/machines/{id}/isolate` (VERIFIED), or the native action |
| terminate process | no VERIFIED vendor endpoint: reported UNROUTED, with a manual step in the endpoint console |

An UNROUTED action is listed on the decision card and in the notes for manual handling; it is never
dropped. Unlock codes for isolated endpoints stay in the Secure Endpoint console and are never copied
into notes, notifications or reports.

## Verification

Verification is automatic after execution and reads the target state back:

- Umbrella destination lists are read back;
- Defender machine actions are VERIFIED or NOT_VERIFIED;
- Secure Endpoint isolation is UNABLE_TO_VERIFY until its isolation-state read is VERIFIED
  (docs/integrations.md section 3).

The result table shows every action with its execution and verification status: SUCCESS,
ALREADY_CONTAINED, FAILED, SKIPPED or REJECTED_BY_ANALYST.

## Rollback

Every reversible action registers a temporary control: isolation (release endpoint) and the domain
block (unblock). Process termination is not reversible and registers no control. Restoration needs
its own human release approval of a release package built from the registry. Closing the incident
never removes a control by itself, and a block has a release-review reminder, never an automatic
expiry. Removing the client binary is a manual step and has no automated rollback.

## Failure handling

- A failed or degraded source (for example Umbrella unavailable) is listed as degraded and lowers
  confidence once. It never blocks a recommendation that other evidence supports: the resolver logs
  still show the category and the behaviour profile.
- A step, rule or hook that fails is noted and skipped; the rest of the run still recommends.
- A rule with no citable record proposes nothing (no invented evidence).
- An approved action that fails at the vendor is reported FAILED and never retried silently. The
  overall result is then PARTIALLY_CONTAINED or CONTAINMENT_FAILED.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0011 Command and Control | T1071 Application Layer Protocol | T1071.004 DNS | command or data traffic carried in DNS queries and answers: the workflow blocks the parent domain the client queries, terminates the querying process and isolates the client endpoint |
| TA0011 Command and Control | T1572 Protocol Tunneling | none | DNS tunneling wraps another protocol or a data stream inside DNS: the workflow measures that pattern (volume, subdomain variation, label length and entropy, record types) and contains both ends of the tunnel |

No other technique is mapped. Data that leaves through the tunnel is assessed as a manual step and
belongs to the exfiltration workflow; it is not mapped here (no forced mappings).

## Testing instructions

- Simulation scenarios: `tests/fixtures/workflows/dns-tunneling/`. They hold the minimum set of 14.5.3,
  three edge cases and the six migrated legacy scenarios `legacy-01` to `legacy-06`. The edge cases are
  an approved DNS tool, a resolver with no known client, and a behaviour profile on a Defender-managed
  endpoint. The scenarios run automatically, in dry run and simulated live, in
  `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/dns_tunneling/`.
- Commands (from the repository root):
  - `python -m pytest -q -p no:cacheprovider tests/workflows/dns_tunneling tests/simulation/test_workflow_scenarios.py -k "dns-tunneling or dns_tunneling"`
  - `python tools/validation/check_workflow_readmes.py --workflow dns-tunneling`
  - `python tools/simulator/simulate.py --workflow dns-tunneling --scenario tp-approve-all --check` (add `--live` for the simulated live run)

## Known limitations

- Hooks and rule expressions cannot read `allowlists.approved_dns_tools`: the framework enforces it on
  the proposals (excluded domains; withheld terminations, isolations and unrated blocks for approved
  binaries and signers). An entry that lists only a name protects nothing; list the tool's hashes,
  signers and domains.
- No DNS activity endpoint is VERIFIED in docs/integrations.md (Umbrella reporting is not listed).
  Real Splunk rows, Cisco XDR sightings, Defender hunting rows and Secure Endpoint trajectory events
  have no documented field schema, so they stay generic records: citable, never scored. Query volume,
  subdomain variation, label length, record types and the querying process come only from typed
  sources. Until a schema is VERIFIED, a real tenant gets a block proposal only when reputation rates
  the parent malicious or a typed source reports the pattern.
- Label entropy is computed from the child names the records report. A source that reports only an
  aggregate (count and unique subdomains) gives no entropy, and entropy is never used alone.
- Parent domains are the incident's domains and the domains a DNS source aggregates over subdomains.
  Other names are grouped by a two-label heuristic, or three labels under a known second-level public
  suffix. A tunnel under a deeper delegated zone of a shared provider may be grouped too broadly, so
  the analyst checks the block target before approving. Only enriched parents carry a reputation.
- Terminate process has no VERIFIED vendor endpoint: with the real adapters it is UNROUTED and handled
  manually in the endpoint console; only the simulated lab executes it.
- Removing the tunnel client binary and assessing what data left through the tunnel have no VERIFIED
  write or read: both are manual steps.
- A host whose only queries come from DNS server software is treated as a forwarding resolver and never
  isolated; the real client must come from resolver logs. A tunnel client that renames itself to a DNS
  server process name on a non-resolver host is shown as a resolver (considered), never silently
  skipped.
- A host named only by DNS logs, with no endpoint record of the querying process, is not isolated (it
  may be another forwarder); it is listed as considered.
- Secure Endpoint isolation verifies as UNABLE_TO_VERIFY (its isolation-state read is UNVERIFIED);
  Umbrella destination-list blocks are read back.
- Third-party reputation is limited by the disclosure policy and the VirusTotal public quota: internal
  domains are never sent, and a withheld or failed source lowers confidence and is listed as degraded.
