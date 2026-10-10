# Web application attacks

Phase 5 add-on workflow `web-attacks` (definition version 2.0.0). Code:
`src/xdr_response/workflows/web_attacks/` (`definition.py`, `hooks.py`). It replaces the legacy
plan-rule spec (`workflow.yaml` and its five scenarios), which were migrated to typed simulation
scenarios and deleted. The binding design is [docs/architecture.md](../../docs/architecture.md)
sections 12 to 14.

## Purpose

Handle injection, exploit, scanning or web shell activity against an internet-facing application.
The workflow automatically investigates the web servers (detections, inbound requests, the web
worker's process and file activity), rates every external source that attacked them, finds the
other servers the same sources reached, and then **recommends** a containment package with
numbered evidence and separate risk and confidence scores:

- block an attacking source IP that is rated (enrichment MALICIOUS or SUSPICIOUS, or a request the
  security product flagged MALICIOUS);
- block the targeted application URL that was exploited (a flagged or attacker request to it
  reached a server that shows a web shell or a successful exploit); the virtual patch at the WAF
  or CDN is a manual step;
- isolate a web server with a confirmed web shell.

Scanning or exploit attempts alone never isolate a server: isolation needs a confirmed web shell.
The workflow never executes, approves or chooses an approval level. A human approves the package;
only then does the lifecycle orchestrator execute, verify and (after a separate human release
approval) restore.

Default severity: MEDIUM. Related workflows: [malware](../malware/README.md) (hand-off target),
[vulnerability-exploitation](../vulnerability-exploitation/README.md),
[persistence](../persistence/README.md).

## Trigger

| Type | Matches | Priority |
|---|---|---|
| XDR incident rule | the incident reports a web shell (T1505.003) | 145 |
| XDR incident rule | the incident reports vulnerability scanning (T1595.002) **and** carries an IP, URL or hostname | 125 |
| XDR incident rule | the title names a web shell, an injection (`*sql injection*`, `*command injection*`, `*code injection*`, `*cross-site scripting*`, `*path traversal*`, `*directory traversal*`, `*file inclusion*`), a web or vulnerability scan, a web application attack or a WAF alert (`*waf rule*`, `*waf alert*`, `*web application firewall*`) **and** the incident carries an IP, URL or hostname | 120 |
| Manual | an analyst starts the workflow for an incident, a web server, a source IP or a URL (never matches automatically) | n/a |

An incident whose `workflow_id` is `web-attacks` always runs this workflow. When several workflows
match, the highest priority wins, then the workflow id. Every automatic trigger outranks malware
(100), which this workflow hands off to. Exploitation of a public-facing application (T1190) is
not a trigger here: an incident that reports it goes to the vulnerability-exploitation workflow
(priority 135, exposed services in general), unless it also reports a web shell, which this
workflow takes (145). Run this workflow manually, or set the incident's `workflow_id`, for an
exploitation incident that is a web application attack.

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence
drops, but a recommendation backed by other evidence is still made.

- `secure_endpoint`: web server detections (web shell, exploit), device trajectory (the web
  worker's process and file activity, inbound requests) and the isolation of a web server with a
  confirmed web shell (`investigate_endpoint`). With the real adapter the computer, trajectory and
  isolation calls are VERIFIED; trajectory events stay generic records until their field schema is
  documented.
- `cisco_xdr`: platform verdicts of the attacking sources and of the web shell hash (`enrich_ip`,
  `enrich_hash`), enterprise sightings of the sources (`search_ip_enterprise`), endpoint context
  (`investigate_endpoint`) and the native response actions. WAF and IPS alerts arrive here as
  incidents.

## Optional integrations

- `defender_endpoint`: second web server source (machine, alerts, timeline, enterprise search) and
  isolation or indicator blocks for the servers it manages.
- `virustotal`: public reputation of the attacking sources and of the web shell hash (public
  indicators only, disclosure policy).
- `alienvault_otx`: independent reputation (OTX pulses) of the sources and the web shell hash.
- `microsoft_cloud`: Defender XDR alerts and hunting rows: other servers that received requests
  from the sources.
- `splunk`: WAF, load balancer and web server logs of other servers the sources reached (optional,
  disabled by default; rows stay citable generic records).
- `meraki`: landing product for approved blocks of an attacking source IP at the MX firewall.
- `umbrella`: landing product for an approved block of the exploited URL (destination lists).

The legacy Cloudflare edge is not an integration: there is no WAF, CDN or load balancer adapter
with a VERIFIED write, so the edge virtual patch is a manual step.

## Input data

Incident observables of type `ip` (attacking sources), `url` (targeted application paths),
`hostname` (web servers) and `sha256`, `trigger.mitre_techniques` / `trigger.source` for routing
and, optionally, `trigger.authorized_scanners` (addresses the detection source marks as sanctioned
external scanners). The legacy context fields `targeted_endpoints`, `vulnerable` and `fix_pending`
are not read: vulnerability state from incident context is data, never evidence. Values found by
earlier steps feed later steps (the servers the enterprise search finds are investigated next).
All test data is fake.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues.

| # | Step | Atomic | Subjects | Sources |
|---|---|---|---|---|
| 1 | `web_server_triage` | `investigate_endpoint` | incident hostnames | Secure Endpoint, Defender, Cisco XDR |
| 2 | `source_reputation` | `enrich_ip` | incident IPv4 addresses and the sources of inbound requests to the servers (at most 25) | every enricher, disclosure policy applies |
| 3 | `source_sightings` | `search_ip_enterprise` | incident IPv4 addresses and every source rated MALICIOUS or SUSPICIOUS (at most 10) | Cisco XDR, Defender, Defender XDR, Splunk |
| 4 | `related_servers` | `investigate_endpoint` | the other servers the searches saw receiving requests from those sources (at most 10) | Secure Endpoint, Defender, Cisco XDR |
| 5 | `web_shell_reputation` | `enrich_hash` | hashes of flagged detections and of flagged file or process events on the servers (at most 10) | every enricher |

The hooks (`hooks.py`) then derive facts from the run's own records, each with the record ids it
was computed from:

- **sources**: every external IPv4 source the incident names or that sent an inbound request to an
  investigated server. A source is *rated* when the aggregate enrichment is MALICIOUS or
  SUSPICIOUS, or when the security product flagged one of its requests MALICIOUS. A source listed
  in `trigger.authorized_scanners` is *authorized*.
- **servers**: every web server seen. A *confirmed web shell* is an active (not resolved) MALICIOUS
  detection that reports the web shell technique or a web-shell name or category. A *successful
  exploit* is an active MALICIOUS detection that reports exploitation of a public-facing
  application or an exploit category. Only a confirmed web shell makes the server a candidate for
  isolation.
- **urls**: every targeted application URL (inbound requests and incident URLs). A URL is
  *exploited* when a flagged request, or a request from a rated source, that was not blocked
  reached a server with a confirmed web shell or a successful exploit, or when the incident names
  both the URL and such a server and a request record to that server mentions the URL (a blocked
  request included). A URL that only the incident names (no request, WAF or IPS record mentions it) is never exploited, even when the
  incident also names such a server: the observable list is not evidence, so the URL is shown as
  considered (`block_url:<url>`, citing the server's compromise records) and never blocked.

## Correlation logic

- Framework links: the same IP, URL or hash on two or more servers (one source attacking a pool),
  the same server across sources, and process lineage on the server. Window 24 hours, because
  scans and exploitation are often hours apart.
- Workflow links (hooks, kind `workflow`): an attack request (the source IP, the server it reached
  and the targeted URL) and a web shell (the server and the hash of the web shell file).
- Links shape the clusters, the blast radius and the decision card. They are never evidence on
  their own and never change an approval level.

## Risk calculation

Each target is scored by the scoring engine (docs/threat-scoring.md) from the records its rule
cites plus the target's enrichment:

- web server detections (web shell, exploit) and malicious process or file events:
  `endpoint_detection` (weight 1.0);
- inbound request records that carry the security product's verdict: `network_behaviour`;
- Cisco XDR, VirusTotal and OTX answers: vendor reputation, capped by the engine; one vendor alone
  is never an aggregate MALICIOUS verdict;
- a critical asset adds the engine's critical-asset bonus (only with malicious evidence).

Risk and confidence are separate integers. Expected sources are Secure Endpoint and Cisco XDR: a
failed one costs confidence once and is listed as degraded. Rule thresholds (below them the action
is "considered, not proposed" and listed in the notes, never hidden): isolation risk 60, URL block
risk 30, source block risk 30 (the MEDIUM band: a scanning source rated SUSPICIOUS by vendor
reputation alone still reaches it).

## Containment recommendations

| Rule | Action (builder) | Proposed when | Evidence cited |
|---|---|---|---|
| `block_attacking_source` | `block_ip` | the source is rated and not listed as an authorised scanner | the source's inbound requests plus the rating records (flagging enrichment, MALICIOUS requests) |
| `block_exploited_url` | `block_url` | the URL is exploited | the flagged or attacker requests to the URL plus the compromise records (web shell or exploit detections) of the server they reached |
| `isolate_web_shell_server_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`, `connector_guid` param) | the server has a Secure Endpoint connector, isolation is not known to be impossible, and it has a confirmed web shell | the web shell detections, the server's flagged process and file events and the attack requests that reached it |
| `isolate_web_shell_server_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | the same, for a server with a Defender machine id (a duplicate of the Secure Endpoint proposal is merged) | the same |

Allow-listed and non-public targets (a sanctioned scanner in `allowlists.never_block.ips`, an
internal load-balancer address, a URL on an own domain) are still built and shown as excluded with
the reason, never dropped. A critical server (for example a production web server) stays proposed
with ELEVATED approval and a warning.

### Hand-offs, manual steps and items not proposed

- Not proposed, and listed as considered: a rated source the detection source lists as an
  authorised scanner; a source whose requests are flagged SUSPICIOUS only and that no source
  rates; a server with a successful exploit but no confirmed web shell, or with a web-shell
  detection that is only SUSPICIOUS or already resolved (not isolated); a URL probed by flagged
  requests without any sign that the exploitation succeeded (not blocked); a URL that only the
  incident names next to a compromised server, with no record that mentions it (not blocked: the
  observable list is not evidence).
- Manual steps: the virtual patch of every exploited URL at the WAF, CDN or load balancer
  (`waf-virtual-patch:<url>`); the review of the web root of every server with a confirmed web
  shell (`review-web-root:<HOST>`: remove the web shell after evidence capture, rotate the
  application's credentials); the isolation of a web-shell server whose agent policy forbids
  isolation or that no EDR manages (take it out of the load-balancer pool by hand).
- Hand-offs: `malware`, for the hashes of confirmed web shell files (scope the file across the
  estate, quarantine it and block its hash).

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a
suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action in the package needs human approval before it runs: source and URL blocks,
  isolation, and later every release. AI and automation principals can never approve, and nothing
  in the workflow can switch approval off.
- ELEVATED approval (a human holding the elevated approver role, for example the SOC lead) applies,
  with a visible warning on the decision card, when a target is a critical asset (for example a
  production web server, by host name pattern, tag, group or address) or when a blast-radius cap is
  exceeded (for example more than 50 indicators to block in one package). ELEVATED is decided by
  `PackageBuilder` from the investigated asset context; the workflow never sets it and a critical
  asset is never skipped silently.
- Isolating a web server takes the application offline: the decision card shows the server, the
  web shell evidence and the attack sources, so the approver can coordinate with the server owner
  before approving.
- The analyst may approve all, approve a selection, reject, or ask for more investigation.

## Containment execution

After approval the orchestrator executes the approved actions automatically, through the guard and
the approval token, native first (Cisco XDR `respond/trigger` when `native_actions` is configured),
then directly:

| Action | Route with the real adapters |
|---|---|
| block IP | Meraki MX L3 rules or Defender indicators (VERIFIED), or the native action; direct Umbrella IP blocking is UNVERIFIED and never called |
| block URL | Umbrella destination lists (VERIFIED), Defender indicators (VERIFIED), or the native action |
| isolate endpoint | Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` (VERIFIED) or Defender `POST /api/machines/{id}/isolate` (VERIFIED), or the native action |

A URL block lands on the DNS and web security layer: it stops the organisation's own users and
managed endpoints from reaching the path. Filtering internet traffic in front of the application
(the virtual patch) stays a manual step at the edge. An UNROUTED action is listed on the decision
card and in the notes for manual handling; it is never dropped. Unlock codes for isolated servers
stay in the Secure Endpoint console and are never copied into notes, notifications or reports.

## Verification

Verification is automatic after execution and reads the target state back: Umbrella destination
lists and Meraki rules are read back; Defender machine actions are VERIFIED or NOT_VERIFIED;
Secure Endpoint isolation and Defender indicators are UNABLE_TO_VERIFY until their read endpoints
are VERIFIED (docs/integrations.md section 3). The result table shows every action with its
execution and verification status (SUCCESS, ALREADY_CONTAINED, FAILED, SKIPPED,
REJECTED_BY_ANALYST).

## Rollback

Every action of the package is reversible and registers a temporary control: isolation (release
endpoint), IP and URL blocks (unblock). Restoration needs its own human release approval of a
release package built from the registry; closing the incident never removes a control by itself.
Release a web server only after the web root is clean and the fix is deployed; remove an edge block
once the fix ships. The legacy block expiry is a release-review reminder only: removing a block
always needs that separate approval.

## Failure handling

- A failed or degraded source (for example Cisco XDR unavailable or VirusTotal over quota) is
  listed as degraded, lowers confidence once, and never blocks a recommendation that other
  evidence supports (the security product's verdict on the requests still rates a source when
  enrichment fails, and the web shell detection still backs the isolation).
- A step, rule or hook that fails is noted and skipped; the rest of the run still recommends.
- A rule with no citable record proposes nothing (no invented evidence).
- An approved action that fails at the vendor is reported FAILED and never retried silently; the
  overall result is PARTIALLY_CONTAINED or CONTAINMENT_FAILED.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0001 Initial Access | T1190 Exploit Public-Facing Application | none | blocks the rated attacking sources and the exploited URL, and puts the edge virtual patch in front of the analyst as a manual step |
| TA0043 Reconnaissance | T1595 Active Scanning | T1595.002 Vulnerability Scanning | blocks a rated scanning source; scanning alone never isolates a server or blocks a URL |
| TA0003 Persistence | T1505 Server Software Component | T1505.003 Web Shell | isolates a server with a confirmed web shell, hands the web shell file to the malware workflow and lists the web root review as a manual step |

No other technique is mapped: what an attacker does through a web shell afterwards (commands,
credential access, lateral movement) is handled by the workflows for those techniques when their
detections fire.

## Testing instructions

- Simulation scenarios: `tests/fixtures/workflows/web-attacks/` (the minimum set of 14.5.3, five
  edge cases and the five migrated legacy scenarios `legacy-01` to `legacy-05`). They run
  automatically, in dry run and simulated live, in `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/web_attacks/`.
- Commands (from the repository root):
  - `python -m pytest -q -p no:cacheprovider tests/workflows/web_attacks tests/simulation/test_workflow_scenarios.py -k "web-attacks or web_attacks"`
  - `python tools/validation/check_workflow_readmes.py --workflow web-attacks`
  - `python tools/simulator/simulate.py --workflow web-attacks --scenario tp-approve-all --check` (add `--live` for the simulated live run)

## Known limitations

- There is no WAF, CDN or load balancer integration with a VERIFIED write (the legacy Cloudflare
  edge is not a Phase 0 integration): the edge virtual patch of an exploited URL is a manual step,
  and WAF alerts arrive only as Cisco XDR incidents.
- An approved URL block lands on the DNS and web security layer (Umbrella, Defender indicators or
  the native action) and an IP block on the Meraki MX, Defender indicators or the native action:
  they do not filter internet traffic in front of the application, which stays with the edge team
  by hand.
- Real Secure Endpoint trajectory events, Defender timeline and hunting rows, Cisco XDR sightings
  and Splunk WAF rows have no documented field schema, so they stay generic records (citable,
  never scored). Inbound requests and their verdicts come only from typed sources; until a schema
  is VERIFIED, a source block rests on enrichment and an exploited URL on the incident naming both
  the URL and the compromised server.
- Vulnerability state (a known-vulnerable endpoint with a pending fix) has no VERIFIED source: a
  URL is blocked only on records that show it was exploited.
- Sanctioned external scanners are recognised from `allowlists.never_block.ips` (excluded
  visibly) or `trigger.authorized_scanners` (considered); an unlisted scanner rated SUSPICIOUS is
  proposed and the analyst can deselect it.
- Isolation needs an active MALICIOUS web-shell detection; a resolved or SUSPICIOUS one, or an
  exploit without a web shell, is shown as considered and the analyst can isolate by hand.
- A web server whose agent policy forbids isolation, or that no EDR manages, is a manual step.
- Removing the web shell, reviewing the web root and rotating the application's credentials are
  manual steps; the web shell hash is handed off to the malware workflow.
- Secure Endpoint's isolation-state read is UNVERIFIED: a Secure Endpoint isolation verifies as
  UNABLE_TO_VERIFY.
- IPv6 sources are not enriched or blocked (IPv4 only).
- Third-party reputation is limited by the disclosure policy and the VirusTotal public quota.
