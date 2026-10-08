# Command and control

Phase 4 workflow `c2` (definition version 2.0.0). Code: `src/xdr_response/workflows/c2/`
(`definition.py`, `hooks.py`). It replaces the legacy plan-rule spec (`workflow.yaml` and its six
scenarios), which were migrated to typed simulation scenarios and deleted. The binding design is
[docs/architecture.md](../../docs/architecture.md) sections 12 to 14.

## Purpose

Handle an endpoint that talks to attacker infrastructure: a known command-and-control (C2) domain
or IP, a periodic beacon, a suspicious external connection or a malicious DNS lookup. The workflow
automatically investigates the endpoint (detections, connections, DNS queries and the process
behind the connection), rates every external destination it reached, finds the other endpoints that
talk to the same infrastructure, and then **recommends** a containment package with numbered
evidence and separate risk and confidence scores:

- block the C2 domain, IP and URL (a shared hosting or CDN address is never blocked by IP);
- isolate an endpoint that reached a MALICIOUS destination and shows malicious activity itself;
- terminate the flagged process that still holds the C2 connection.

The workflow never rates a destination by its traffic pattern alone: a periodic beacon to an
unrated destination is shown as considered, never blocked, because update agents and SaaS
heartbeats beacon too. It never executes, approves or chooses an approval level. A human approves
the package; only then does the lifecycle orchestrator execute, verify and (after a separate human
release approval) restore.

Default severity: HIGH. Related workflows: [malware](../malware/README.md),
[dns-tunneling](../dns-tunneling/README.md), [exfiltration](../exfiltration/README.md),
[unauthorized-rmm](../unauthorized-rmm/README.md).

## Trigger

| Type | Matches | Priority |
|---|---|---|
| XDR incident rule | the incident reports ATT&CK T1071.001 (web protocols), T1573 (encrypted channel) or T1568.002 (domain generation algorithms) | 115 |
| XDR incident rule | the title matches a beaconing or C2 pattern (`*beacon*`, `*command and control*`, `*command-and-control*`, `*c2 traffic*`, `*c2 communication*`, `*c2 callback*`, `*c2 server*`, `*c2 domain*`, `*c2 channel*`) **and** the incident carries a hostname, domain or IP | 105 |
| XDR incident rule | the source is Secure Cloud Analytics or Umbrella (read as a Cisco XDR incident) **and** the title names a suspicious external connection, a malicious DNS lookup or domain, a watchlist or threat-feed hit **and** the incident carries a domain or IP | 95 |
| Manual | an analyst starts the workflow for an incident, an endpoint or a destination (never matches automatically) | n/a |

An incident whose `workflow_id` is `c2` always runs this workflow. When several workflows match,
the highest priority wins, then the workflow id. Endpoint-specific workflows (ransomware,
lateral-movement, credential-dumping, unauthorized-rmm, malicious-powershell, persistence) and the
dns-tunneling and exfiltration workflows outrank c2; c2 outranks malware, which it hands off to.
Ransomware's title trigger names encrypted files (`*files encrypted*`, `*encrypted files*`, ...), not
any title with "encrypted", so a title such as "Encrypted beaconing from TH-LT-5520" routes here
(architecture 14.12.2). Parent technique T1071 is deliberately not listed:
DNS tunnelling (T1071.004) belongs to the dns-tunneling workflow.

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence
drops, but a recommendation backed by other evidence is still made.

- `secure_endpoint`: endpoint detections, device trajectory (connections, DNS lookups, the process
  behind the connection) and the isolation of the endpoint (`investigate_endpoint`). With the real
  adapter the computer, trajectory and isolation calls are VERIFIED; trajectory events stay generic
  records until their field schema is documented.
- `umbrella`: domain status and security categories (Command and Control, Malware) of the
  destinations (`enrich_domain`, VERIFIED categorisation endpoint), and the landing product for
  approved domain and URL blocks (destination lists, VERIFIED).

## Optional integrations

- `defender_endpoint`: second endpoint source (machine, alerts, timeline, enterprise search) and
  isolation or indicator blocks for the endpoints it manages.
- `cisco_xdr`: platform verdicts and sightings of the destinations and hashes (Secure Cloud
  Analytics alerts arrive here as incidents), and the native response actions the router prefers
  when `native_actions` is configured.
- `virustotal`: public reputation of the destinations and of the beaconing process's hash (public
  indicators only, disclosure policy).
- `alienvault_otx`: independent reputation (OTX pulses) for the destinations and the beaconing hash.
- `microsoft_cloud`: Defender XDR alerts and hunting rows: other endpoints that resolved or
  connected to the destinations.
- `splunk`: proxy, firewall and DNS logs of other endpoints that reached the destinations (optional,
  disabled by default; rows stay citable generic records).
- `meraki`: landing product for approved blocks of a C2 IP at the MX firewall.

Secure Cloud Analytics is not an integration of this workflow: its API is UNVERIFIED
(docs/integrations.md section 2.5), so its alerts are read only as Cisco XDR incidents.

## Input data

Incident observables of type `hostname`, `domain`, `ip`, `url` and `sha256`, the incident users,
`trigger.mitre_techniques` / `trigger.source` for routing and, optionally,
`trigger.shared_infrastructure_ips` (addresses the detection source marks as shared hosting or
CDN). Values found by earlier steps feed later steps (for example, the endpoints the enterprise
search finds are investigated next). All test data is fake.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues.

| # | Step | Atomic | Subjects | Sources |
|---|---|---|---|---|
| 1 | `endpoint_triage` | `investigate_endpoint` | incident hostnames | Secure Endpoint, Defender, Cisco XDR |
| 2 | `domain_reputation` | `enrich_domain` | incident domains and every domain the endpoints reached (connections, DNS queries, process events; at most 15) | every enricher, disclosure policy applies |
| 3 | `ip_reputation` | `enrich_ip` | incident IPv4 addresses and remote IPv4 addresses of outward connections (at most 15) | every enricher |
| 4 | `url_reputation` | `enrich_url` | incident URLs and URLs of outward connections (at most 10) | every enricher |
| 5 | `domain_sightings` | `search_domain_enterprise` | incident domains and every domain rated MALICIOUS or SUSPICIOUS | Cisco XDR, Defender, Defender XDR, Splunk |
| 6 | `ip_sightings` | `search_ip_enterprise` | incident IPv4 addresses and every IP rated MALICIOUS or SUSPICIOUS | Cisco XDR, Defender, Defender XDR, Splunk |
| 7 | `related_endpoints` | `investigate_endpoint` | the other endpoints the searches saw reaching those destinations | Secure Endpoint, Defender, Cisco XDR |
| 8 | `beacon_process_reputation` | `enrich_hash` | hashes of the processes behind the connections and of suspicious or malicious detections (at most 10) | every enricher |

The hooks (`hooks.py`) then derive facts from the run's own records, each with the record ids it
was computed from:

- **destinations**: every external domain, IPv4 address and URL reached or named by the incident.
  A destination is *rated* when the aggregate enrichment or the security product's verdict on a
  contact record is MALICIOUS, or when it is SUSPICIOUS and a source categorises it as command and
  control. Beacon-like repeated contact (at least 5 contacts from one endpoint, with the mean
  interval) is reported as context only.
- **hosts**: every endpoint seen, whether it reached a MALICIOUS destination (a contact record, or
  the incident names both) and whether it shows malicious activity itself (an active malicious
  detection, a malicious process event, or a process with a MALICIOUS hash on the C2 connection).
- **processes**: flagged processes (detection, malicious or suspicious process event, malicious
  hash) that hold a connection to a rated destination and were not seen ending.

## Correlation logic

- Framework links: the same domain, IP, URL or hash on two or more endpoints (one C2 server, many
  beaconing hosts), the same endpoint across sources, and process lineage. Window 24 hours,
  because beacons are long-lived.
- Workflow links (hooks, kind `workflow`): a beacon (an endpoint, the destination it reached and,
  when known, the hash of the process behind the connection) and a DNS resolution (a domain and the
  external IPv4 addresses it resolved to).
- Links shape the clusters, the blast radius and the decision card. They are never evidence on
  their own and never change an approval level.

## Risk calculation

Each target is scored by the scoring engine (docs/threat-scoring.md) from the records its rule
cites plus the target's enrichment:

- endpoint detections and malicious process events: `endpoint_detection` (weight 1.0);
- connection and DNS records that carry the security product's verdict: `network_behaviour`;
- Umbrella, Cisco XDR, VirusTotal and OTX answers: vendor reputation, capped by the engine; one
  vendor alone is never an aggregate MALICIOUS verdict;
- periodicity never adds risk: it is context in the rationale only;
- a critical asset adds the engine's critical-asset bonus (only with malicious evidence).

Risk and confidence are separate integers. Expected sources are Secure Endpoint and Umbrella: a
failed one costs confidence once and is listed as degraded. Rule thresholds (below them the action
is "considered, not proposed" and listed in the notes, never hidden): isolation risk 60, process
termination risk 50, destination blocks risk 30 (the MEDIUM band: a rated destination with vendor
reputation only still reaches it).

## Containment recommendations

| Rule | Action (builder) | Proposed when | Evidence cited |
|---|---|---|---|
| `block_c2_domain` | `block_domain` (catalog order: native, Umbrella, Defender) | the domain is rated (MALICIOUS, or SUSPICIOUS with a command-and-control category) and an investigated endpoint reached it or the incident names it | the contact records (DNS queries, connections, process events) plus the rating records (enrichment, flagged contacts, category records) |
| `block_c2_ip` | `block_ip` | the IPv4 address is rated and is not shared hosting or CDN infrastructure | the same |
| `block_c2_url` | `block_url` | the URL is rated | the same |
| `isolate_beaconing_endpoint_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`, `connector_guid` param) | the endpoint has a Secure Endpoint connector, isolation is not known to be impossible, it reached a MALICIOUS destination and shows malicious activity itself | the endpoint's detections, malicious process events or malicious-hash connections, its contact records and the destination's rating records |
| `isolate_beaconing_endpoint_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | the same, for an endpoint with a Defender machine id (a duplicate of the Secure Endpoint proposal is merged) | the same |
| `terminate_beaconing_process` | `terminate_process` (target `<ENDPOINT>/<pid>`) | a flagged process holds a connection to a rated destination and no `process_end` for it was seen | the connections, the start event, the flagging detection or event and the hash's malicious enrichment |

A shared hosting or CDN address (a DNS record shows it also serving a domain rated CLEAN, or the
incident source lists it in `trigger.shared_infrastructure_ips`) is not proposed for an IP block:
the domain block cuts the channel without cutting legitimate sites. Allow-listed and non-public
targets (an own domain, an internal relay address) are still built and shown as excluded with the
reason, never dropped.

### Hand-offs and items not proposed

- Not proposed, and listed as considered: a destination rated SUSPICIOUS without a
  command-and-control category; an unrated destination with beacon-like contact; a rated shared
  hosting or CDN IP; an endpoint that reached C2 without malicious activity of its own; the
  isolation of an endpoint whose only malicious activity is a MALICIOUS hash rating of a sanctioned
  binary (approved tool hash or signer, `never_block.hashes`) on the C2 connection, like that
  process's termination; an unflagged process (a browser or proxy) on a connection to a MALICIOUS
  destination.
- Manual steps: an endpoint that should be isolated but whose agent policy forbids isolation, or
  that neither Secure Endpoint nor Defender manages (contain it on the network by hand).
- Hand-offs: `malware`, for the hashes of flagged beaconing processes (scope the file across the
  estate, quarantine it and block its hash).

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a
suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action in the package needs human approval before it runs: domain, IP and URL blocks,
  isolation, process termination, and later every release. AI and automation principals can never
  approve, and nothing in the workflow can switch approval off.
- ELEVATED approval (a human holding the elevated approver role, for example the SOC lead) applies,
  with a visible warning on the decision card, when a target is a critical asset (for example a
  domain controller or a production server, also for the endpoint part of a process target) or
  when a blast-radius cap is exceeded (for example more than 5 endpoints to isolate). ELEVATED is
  decided by `PackageBuilder` from the investigated asset context; the workflow never sets it and a
  critical asset is never skipped silently.
- The analyst may approve all, approve a selection, reject, or ask for more investigation.

## Containment execution

After approval the orchestrator executes the approved actions automatically, through the guard and
the approval token, native first (Cisco XDR `respond/trigger` when `native_actions` is configured),
then directly:

| Action | Route with the real adapters |
|---|---|
| block domain, URL | Umbrella destination lists (VERIFIED), Defender indicators (VERIFIED), or the native action |
| block IP | Meraki MX L3 rules or Defender indicators (VERIFIED), or the native action; direct Umbrella IP blocking is UNVERIFIED and never called |
| isolate endpoint | Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` (VERIFIED) or Defender `POST /api/machines/{id}/isolate` (VERIFIED), or the native action |
| terminate process | no VERIFIED vendor endpoint: reported UNROUTED, with a manual step in the endpoint console |

An UNROUTED action is listed on the decision card and in the notes for manual handling; it is never
dropped. Unlock codes for isolated endpoints stay in the Secure Endpoint console and are never
copied into notes, notifications or reports.

## Verification

Verification is automatic after execution and reads the target state back: Umbrella destination
lists and Meraki rules are read back; Defender machine actions are VERIFIED or NOT_VERIFIED;
Secure Endpoint isolation and Defender indicators are UNABLE_TO_VERIFY until their read endpoints
are VERIFIED (docs/integrations.md section 3). The result table shows every action with its
execution and verification status (SUCCESS, ALREADY_CONTAINED, FAILED, SKIPPED,
REJECTED_BY_ANALYST).

## Rollback

Every reversible action registers a temporary control: isolation (release endpoint), domain, URL
and IP blocks (unblock). Process termination is not reversible and registers no control. Restoration
needs its own human release approval of a release package built from the registry; closing the
incident never removes a control by itself. The legacy block expiry is a release-review reminder
only: removing a block always needs that separate approval.

## Failure handling

- A failed or degraded source (for example Umbrella unavailable or VirusTotal over quota) is listed
  as degraded, lowers confidence once, and never blocks a recommendation that other evidence
  supports (a contact verdict still rates a destination when enrichment fails).
- A step, rule or hook that fails is noted and skipped; the rest of the run still recommends.
- A rule with no citable record proposes nothing (no invented evidence).
- An approved action that fails at the vendor is reported FAILED and never retried silently; the
  overall result is PARTIALLY_CONTAINED or CONTAINMENT_FAILED.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0011 Command and Control | T1071 Application Layer Protocol | T1071.001 Web Protocols | blocks the C2 domain, IP and URL of HTTP(S) beaconing, isolates the endpoints that show malicious activity and terminates the beaconing process |
| TA0011 Command and Control | T1573 Encrypted Channel | none | acts on the endpoints and destinations of an encrypted channel whose content it cannot see: blocks the C2 IP, isolates the endpoint and terminates the process |
| TA0011 Command and Control | T1568 Dynamic Resolution | T1568.002 Domain Generation Algorithms | blocks an algorithm-generated domain when a source categorises it as command and control; shows the others as considered |

No other technique is mapped: the workflow does not respond to anything else by design (DNS
tunnelling is the dns-tunneling workflow's).

## Testing instructions

- Simulation scenarios: `tests/fixtures/workflows/c2/` (the minimum set of 14.5.3, four edge cases
  and the six migrated legacy scenarios `legacy-01` to `legacy-06`). They run automatically, in dry
  run and simulated live, in `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/c2/`.
- Commands (from the repository root):
  - `python -m pytest -q -p no:cacheprovider tests/workflows/c2 tests/simulation/test_workflow_scenarios.py -k "c2"`
  - `python tools/validation/check_workflow_readmes.py --workflow c2`
  - `python tools/simulator/simulate.py --workflow c2 --scenario tp-approve-all --check` (add `--live` for the simulated live run)

## Known limitations

- Secure Cloud Analytics has no VERIFIED API: its alerts are read only as Cisco XDR incidents and
  sightings; its observations are not queried directly.
- Real Secure Endpoint trajectory events, Defender timeline and hunting rows, Cisco XDR sightings
  and Splunk rows have no documented field schema, so they stay generic records (citable, never
  scored). Contacts, the process behind a connection and beacon counts come only from typed
  sources; until a schema is VERIFIED, an isolation rests on the endpoint detection and on the
  incident naming both the endpoint and the rated destination.
- Umbrella security scores, risk scores and DNS activity reports are UNVERIFIED (only the
  categorisation is read); direct Umbrella IP blocking is UNVERIFIED, so IP blocks land on the
  native action, Meraki or Defender indicators.
- Terminate process has no VERIFIED vendor endpoint: with the real adapters it is UNROUTED and
  handled manually in the endpoint console.
- Secure Endpoint's isolation-state read is UNVERIFIED: a Secure Endpoint isolation verifies as
  UNABLE_TO_VERIFY.
- Beaconing is measured from connection counts and first and last seen times (a mean interval), not
  from per-connection timestamps; it never rates a destination.
- Shared hosting and CDN addresses are recognised only from a CLEAN domain on the same address (a
  DNS answer, or a connection record naming the domain with the address) or
  `trigger.shared_infrastructure_ips`; an unrecognised shared address rated MALICIOUS is proposed
  and the analyst can deselect it.
- An endpoint that reached C2 without malicious activity of its own is not isolated (considered);
  the analyst can isolate it by hand.
- An endpoint whose agent policy forbids isolation, or that no EDR manages, is a manual step.
- IPv6 destinations are not enriched or blocked (IPv4 only); DNS tunnelling is handled by the
  dns-tunneling workflow.
- Third-party reputation is limited by the disclosure policy and the VirusTotal public quota.
