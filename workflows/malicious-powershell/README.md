# Suspicious PowerShell

Phase 3 workflow `malicious-powershell` (definition version 2.0.0). Code:
`src/xdr_response/workflows/malicious_powershell/` (`definition.py`, `hooks.py`). It replaces the legacy
plan-rule spec (`workflow.yaml` and its six scenarios), which were migrated to typed simulation scenarios
and deleted. The binding design is [docs/architecture.md](../../docs/architecture.md) sections 12 to 14.

## Purpose

Handle an endpoint alert about PowerShell or another script host or signed Windows system binary used as
a proxy ("living off the land" binaries, LOLBins): `powershell`, `pwsh`, `mshta`, `rundll32`, `regsvr32`,
`certutil`, `wmic`, `wscript`, `cscript`, `bitsadmin` and `installutil`.

**Using one of these binaries is not malicious on its own.** Administrators, deployment agents and the
operating system run them every day. The workflow automatically investigates what the run actually did,
from the run's own records:

- the endpoint vendor's view of the command line and the process: detections that name the process, its
  image or its payload, with the ATT&CK techniques the vendor reported, and the process event's verdict;
- the parent process and the child processes (process lineage);
- the network destinations the process contacted and their reputation;
- download activity: files the process wrote (and their origin) and children it started, with the
  reputation and prevalence of those payload hashes;
- the user and the endpoint (asset context, critical-asset classes).

It then **recommends** a containment package with numbered evidence and separate risk and confidence
scores:

- terminate the malicious process that is still running;
- isolate the endpoint where a malicious payload landed or ran;
- block the payload hash (rare payloads only);
- block the malicious download or command-and-control (C2) destination: domain, URL or public IP.

The workflow never executes, approves or chooses an approval level. A human approves the package; only
then does the lifecycle orchestrator execute, verify and (after a separate human release approval)
restore.

Default severity: MEDIUM. Related workflows: [malware](../malware/README.md), [c2](../c2/README.md),
[persistence](../persistence/README.md), [lateral-movement](../lateral-movement/README.md),
[credential-dumping](../credential-dumping/README.md).

## Trigger

| Type | Matches | Priority |
|---|---|---|
| XDR incident rule | the incident reports ATT&CK technique T1059.001, T1027 or T1218 (a reported sub-technique matches its listed parent) | 125 |
| XDR incident rule | the title names PowerShell or one of the evaluated binaries (`*powershell*`, `*pwsh*`, `*mshta*`, `*rundll32*`, `*regsvr32*`, `*certutil*`, `*wmic*`, `*wscript*`, `*cscript*`, `*bitsadmin*`, `*installutil*`, `*lolbin*`, `*living off the land*`) **and** the incident carries a hostname | 110 |
| Webhook | the source is Secure Endpoint, Defender for Endpoint or Splunk **and** the incident reports T1059.001; the payload is the incident id only and the incident is re-read through the VERIFIED Cisco XDR APIs | 100 |
| Manual | an analyst starts the workflow for an incident (never matches automatically) | n/a |

An incident whose `workflow_id` is `malicious-powershell` always runs this workflow. When several
workflows match, the highest priority wins, then the workflow id. The priorities defer to the more
specific workflows: ransomware (200), lateral-movement (160) and credential-dumping (150) win when their
own techniques are reported. This workflow wins over the workflows it hands off to, persistence (120) and
malware (100), when their techniques are reported too, so the hand-off is still suggested (architecture
14.11.2).

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence drops,
but a recommendation backed by other evidence is still made.

- `secure_endpoint`: endpoint detections, device trajectory (process chain, file writes, connections),
  hash prevalence and the isolation of the endpoint (`investigate_endpoint`, `investigate_process`,
  `search_hash_enterprise`). With the real adapter only the computer and trajectory reads are VERIFIED;
  process and enterprise hash reads come from typed records in the simulated lab.
- `virustotal`: public reputation of the payload hashes and of the domains, IPs and URLs the process
  contacted (`enrich_hash`, `enrich_domain`, `enrich_ip`, `enrich_url`). Only public indicators are
  disclosed (disclosure policy).

## Optional integrations

- `defender_endpoint`: second endpoint source (machine, detections, timeline) and isolation or indicator
  blocks for the endpoints it manages.
- `cisco_xdr`: platform verdicts and sightings for every observable, and the native response actions
  (`respond/observables`, `respond/trigger`) the router prefers when configured.
- `umbrella`: domain reputation and the landing product for approved domain and URL blocks.
- `alienvault_otx`: independent reputation (OTX pulses) for the payload hashes and the destinations.
- `splunk`: script block and process logging from the SIEM; its rows stay generic records (citable,
  never scored) until a field schema is VERIFIED.
- `meraki`: landing product for approved public IP blocks (MX layer 3 rules, VERIFIED).

## Input data

Incident observables of type `hostname`, `sha256`, `domain`, `ip`, `url` and `user`, the incident users,
and `trigger.mitre_techniques` / `trigger.source` for routing. Values found by earlier steps feed later
steps (for example, the endpoints where a malicious payload is present are investigated next). The
workflow never needs or stores a raw command line: command-line characteristics reach it as the endpoint
vendor's detections and reported techniques. All test data is fake.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues.

| # | Step | Atomic | Subjects | Sources |
|---|---|---|---|---|
| 1 | `endpoint_triage` | `investigate_endpoint` | incident hostnames | Secure Endpoint, Defender, Cisco XDR |
| 2 | `process_tree` | `investigate_process` | `<ENDPOINT>/<pid>` of every evaluated binary the triage found (children, process connections) | Secure Endpoint, Defender, Splunk |
| 3 | `payload_reputation` | `enrich_hash` | incident hashes, detection hashes, files written and images of non-LOLBin processes (at most 10); a LOLBin's own image is never a payload | every enricher, disclosure policy applies |
| 4 | `payload_prevalence` | `search_hash_enterprise` | the same hashes | Secure Endpoint, Defender, Cisco XDR |
| 5 | `affected_endpoints` | `investigate_endpoint` | other endpoints where the endpoint source reports a malicious payload | Secure Endpoint, Defender, Cisco XDR |
| 6 | `domain_reputation` | `enrich_domain` | incident domains and every domain contacted (connections, DNS queries, file origin) | every enricher |
| 7 | `ip_reputation` | `enrich_ip` | incident IPv4 addresses and remote IPs of outbound connections | every enricher |
| 8 | `url_reputation` | `enrich_url` | incident URLs and URLs of connections | every enricher |

The hooks (`hooks.py`) then derive facts from the run's own records, per run of an evaluated binary: what
the vendor says about it, which payloads it wrote or started and whether they are malicious, which
destinations it contacted and their verdicts, and whether it is still running. A run is **malicious**
only when one of these holds:

1. it wrote or started a malicious payload (endpoint detection, malicious endpoint telemetry or an
   aggregate MALICIOUS enrichment of the payload hash);
2. the endpoint vendor rates the process, or an active detection naming it, MALICIOUS;
3. it contacted a malicious destination on an endpoint with an active malicious detection.

A SUSPICIOUS vendor detection (for example encoded content reported as T1027) is a characteristic, not
proof; it is cited, never actioned alone. Every fact carries the record ids it was computed from.

## Correlation logic

- Framework links: parent/child process lineage; the same hash, domain, IP or URL on two or more
  endpoints or users; the same endpoint or user across sources. Window 120 minutes.
- Workflow links (hooks, kind `workflow`): an evaluated process's endpoint and each destination it
  contacted, and the endpoint and each payload the process wrote or started.
- Links shape the clusters, the blast radius and the decision card. They are never evidence on their own
  and never change an approval level.

## Risk calculation

Each target is scored by the scoring engine (docs/threat-scoring.md) from the records its rule cites plus
the target's enrichment:

- endpoint detections naming the process or its payload, malicious process events and malicious hash
  prevalence: `endpoint_detection` (weight 1.0);
- network connections with a verdict: `network_behaviour`;
- VirusTotal, OTX, Cisco XDR and Umbrella answers: vendor reputation, capped by the engine; one vendor
  alone is never an aggregate MALICIOUS verdict;
- running a system binary adds nothing to the score;
- a critical asset adds the engine's critical-asset bonus (only with malicious evidence).

Risk and confidence are separate integers. Expected sources are Secure Endpoint and VirusTotal: a failed
one costs confidence once and is listed as degraded. Rule thresholds (below them the action is
"considered, not proposed" and listed in the notes, never hidden): isolation risk 60, termination and
hash block risk 50, network blocks risk 40.

## Containment recommendations

| Rule | Action (builder) | Proposed when | Evidence cited |
|---|---|---|---|
| `terminate_malicious_script_process` | `terminate_process` (`terminate_process`, target `<ENDPOINT>/<pid>`) | a malicious run (above) has a process id and no `process_end` was seen | the start event, the vendor detections, the payload records and the malicious destination records with their malicious enrichment |
| `isolate_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`, `connector_guid` param) | the endpoint has a Secure Endpoint connector, isolation is not known to be impossible, and a malicious payload of a malicious run landed there (the run's endpoint or one the payload's prevalence names), or a malicious detection there follows contact with a malicious destination | payload write and start events, detections, prevalence, malicious enrichment, contact records |
| `isolate_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | the same, for an endpoint with a Defender machine id (a duplicate of the Secure Endpoint proposal is merged) | the same |
| `block_payload_hash` | `block_hash` | a malicious payload of a malicious run is seen on 10 endpoints or fewer, or its prevalence is unknown | payload events, detections, prevalence, malicious enrichment |
| `block_c2_domain` | `block_domain` (catalog order: native, Umbrella, Defender) | an evaluated process contacted the domain and its aggregate enrichment or the contact record is MALICIOUS, or it is SUSPICIOUS while the process that contacted it retrieved a malicious payload | the contact records, the domain's supporting enrichment and, for the suspicious case, the payload records |
| `block_c2_url` | `block_url` | the same for a URL | the same |
| `block_c2_ip` | `block_ip` | the same for a public IPv4 address (internal, loopback, link-local and shared ranges are never proposed) | the same |

### Hand-offs and items not proposed

- Not proposed, and listed as considered: a run of an evaluated binary without malicious corroboration
  (with the parent, and the vendor's SUSPICIOUS characteristics when present); a run that contacted a
  malicious destination without a payload or detection (only the destination is blocked); a malicious
  process that already ended; a malicious payload seen on more than 10 endpoints; the image hash of a
  system binary named by a detection or rated by a vendor (blocking it would break legitimate use of the
  binary across the estate).
- Hand-offs: `malware` for the malicious payload hashes (the malware workflow scopes and quarantines the
  file; this workflow blocks the hash only), and `persistence` for the endpoint where a malicious run
  happened and a malicious or suspicious persistence item exists (the subject is the endpoint, as for
  every endpoint hand-off; the items are named in the reason).

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion
only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action in the package needs human approval before it runs: process termination, isolation,
  hash, domain, URL and IP blocks, and later every release. AI and automation principals can never
  approve, and nothing in the workflow can switch approval off.
- ELEVATED approval (a human holding the elevated approver role, for example the SOC lead) applies, with
  a visible warning on the decision card, when a target is a critical asset (for example a domain
  controller or a production server, also for the endpoint part of a process target) or when a
  blast-radius cap is exceeded (for example more than 5 endpoints to isolate). ELEVATED is decided by
  `PackageBuilder` from the investigated asset context; the workflow never sets it and a critical asset
  is never skipped silently.
- The analyst may approve all, approve a selection, reject, or ask for more investigation.

## Containment execution

After approval the orchestrator executes the approved actions automatically, through the guard and the
approval token, native first (Cisco XDR `respond/trigger` when `native_actions` is configured), then
directly:

| Action | Route with the real adapters |
|---|---|
| isolate endpoint | Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` (VERIFIED) or Defender `POST /api/machines/{id}/isolate` (VERIFIED), or the native action |
| block hash | Defender indicator `POST /api/indicators` (VERIFIED) or the native "Block File Hashes" action; Secure Endpoint file lists are UNVERIFIED and never called |
| block domain, URL | Umbrella destination lists (VERIFIED), Defender indicators, or the native action |
| block IP | Meraki or Defender indicators (VERIFIED), or the native action |
| terminate process | no VERIFIED vendor endpoint: reported UNROUTED, with a manual step in the endpoint console |

An UNROUTED action is listed on the decision card and in the notes for manual handling; it is never
dropped. Unlock codes for isolated endpoints stay in the Secure Endpoint console and are never copied
into notes, notifications or reports.

## Verification

Verification is automatic after execution and reads the target state back: Defender machine actions are
VERIFIED or NOT_VERIFIED; Umbrella destination lists and Meraki rules are read back; Secure Endpoint
isolation and Defender indicators are UNABLE_TO_VERIFY until their read endpoints are VERIFIED
(docs/integrations.md section 3). The result table shows every action with its execution and
verification status (SUCCESS, ALREADY_CONTAINED, FAILED, SKIPPED, REJECTED_BY_ANALYST).

## Rollback

Every reversible action registers a temporary control: isolation (release endpoint) and the hash,
domain, URL and IP blocks (unblock). Process termination is not reversible and registers no control.
Restoration needs its own human release approval of a release package built from the registry; closing
the incident never removes a control by itself.

## Failure handling

- A failed or degraded source (for example VirusTotal unavailable or over quota) is listed as degraded,
  lowers confidence once, and never blocks a recommendation that other evidence supports.
- A step, rule or hook that fails is noted and skipped; the rest of the run still recommends.
- A rule with no citable record proposes nothing (no invented evidence).
- An approved action that fails at the vendor is reported FAILED and never retried silently; the
  overall result is PARTIALLY_CONTAINED or CONTAINMENT_FAILED.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0002 Execution | T1059 Command and Scripting Interpreter | T1059.001 PowerShell | the core subject: PowerShell and pwsh runs are evaluated and a malicious one is terminated and contained |
| TA0002 Execution | T1059 Command and Scripting Interpreter | none | the script hosts (wscript, cscript) are evaluated the same way; the language is not known from the process alone, so no language sub-technique is mapped |
| TA0005 Defense Evasion | T1027 Obfuscated Files or Information | none | encoded or obfuscated content is a trigger; the vendor's detection of it is cited, never actioned alone |
| TA0005 Defense Evasion | T1218 System Binary Proxy Execution | none | signed system binaries used as a proxy are judged by what they ran, wrote and contacted |
| TA0005 Defense Evasion | T1218 System Binary Proxy Execution | T1218.004 InstallUtil | installutil is evaluated |
| TA0005 Defense Evasion | T1218 System Binary Proxy Execution | T1218.005 Mshta | mshta is evaluated |
| TA0005 Defense Evasion | T1218 System Binary Proxy Execution | T1218.010 Regsvr32 | regsvr32 is evaluated |
| TA0005 Defense Evasion | T1218 System Binary Proxy Execution | T1218.011 Rundll32 | rundll32 is evaluated |
| TA0002 Execution | T1047 Windows Management Instrumentation | none | wmic process activity on the endpoint is evaluated (remote execution on other hosts belongs to lateral-movement) |
| TA0011 Command and Control | T1105 Ingress Tool Transfer | none | download activity (PowerShell, certutil, bitsadmin and the proxy binaries writing a payload) is traced to its origin; the payload hash and the download destination are blocked |

No other technique is mapped: certutil and bitsadmin are mapped through their download behaviour only.

## Testing instructions

- Simulation scenarios: `tests/fixtures/workflows/malicious-powershell/` (the minimum set of 14.5.3, five
  edge cases and the six migrated legacy scenarios `legacy-01` to `legacy-06`). They run automatically,
  in dry run and simulated live, in `tests/simulation/test_workflow_scenarios.py`. Fixtures carry no
  command lines.
- Unit, hook and lifecycle tests: `tests/workflows/malicious_powershell/`.
- Commands (from the repository root):
  - `python -m pytest -q -p no:cacheprovider tests/workflows/malicious_powershell tests/simulation/test_workflow_scenarios.py -k "malicious-powershell or malicious_powershell"`
  - `python tools/validation/check_workflow_readmes.py --workflow malicious-powershell`
  - `python tools/simulator/simulate.py --workflow malicious-powershell --scenario tp-approve-all --check` (add `--live` for the simulated live run)

## Known limitations

- The workflow does not parse command lines: command-line characteristics (encoded, obfuscated or hidden
  content, download behaviour) reach it only as the endpoint vendor's detections, reported techniques and
  process verdicts. A command line no vendor flagged is context only, never scored.
- Real Secure Endpoint trajectory events, Defender timeline rows and Splunk rows have no documented field
  schema, so they stay generic records (citable, never scored); process, file and connection facts come
  only from typed sources until a schema is VERIFIED.
- A connection is attributed to a process by image name (and image hash when both are known) on the
  same endpoint, and by process id when the connection record carries one. A source that reports no
  process id for connections makes two concurrent PowerShell processes on one endpoint share their
  connections.
- Terminate process has no VERIFIED vendor endpoint: with the real adapters it is UNROUTED and handled
  manually in the endpoint console.
- Secure Endpoint hash blocking and its isolation-state read are UNVERIFIED: hash blocks use the native
  action or Defender indicators, and Secure Endpoint isolation verifies as UNABLE_TO_VERIFY.
- The payload file is not quarantined by this workflow; it is handed off to the malware workflow.
- A malicious payload seen on more than 10 endpoints is not proposed for a fleet-wide block, and a system
  binary's image hash is never blocked; both are listed as considered.
- An endpoint known to neither Secure Endpoint nor Defender is not proposed for isolation.
- IPv6 destinations are not blocked by this workflow (public IPv4 only).
- Third-party reputation is limited by the disclosure policy and the VirusTotal public quota.
