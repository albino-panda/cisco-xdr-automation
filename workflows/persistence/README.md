# Persistence

Phase 3 workflow `persistence` (definition version 2.0.0). Code: `src/xdr_response/workflows/persistence/`
(`definition.py`, `hooks.py`). It replaces the legacy plan-rule spec (`workflow.yaml` and its five
scenarios), which were migrated to typed simulation scenarios and deleted. The binding design is
[docs/architecture.md](../../docs/architecture.md) sections 12 to 14.

## Purpose

Handle an attacker foothold on an endpoint: a Registry Run key or startup-folder item, a scheduled
task, a new Windows service, a WMI event subscription, or a browser extension where the endpoint
source reports it. The workflow automatically investigates the persistence items of the endpoint,
the reputation and estate-wide prevalence of every persisted binary, the other endpoints that carry
the same binary and the persisted binary's process tree. It then **recommends** a containment package
with numbered evidence and separate risk and confidence scores:

- isolate the endpoint when its malicious persistence is backed by active malicious execution;
- terminate the persisted malicious process that is still running;
- block the malicious persisted binary's hash fleet-wide (rare binaries only).

Removing the persistence item itself (the Run value, task, service, subscription or extension) has
no VERIFIED vendor write, so it is never automated: every malicious item is listed as a **manual
step** with its records, outside the package.

The workflow never executes, approves or chooses an approval level. A human approves the package;
only then does the lifecycle orchestrator execute, verify and (after a separate human release
approval) restore.

Default severity: MEDIUM. Related workflows: [malware](../malware/README.md),
[privilege-escalation](../privilege-escalation/README.md), [c2](../c2/README.md).

## Trigger

| Type | Matches | Priority |
|---|---|---|
| XDR incident rule | the incident reports ATT&CK sub-technique T1547.001, T1053.005, T1543.003, T1546.003 or T1176.001 | 120 |
| XDR incident rule | the title matches a persistence pattern (`*run key*`, `*runonce*`, `*autorun*`, `*scheduled task*`, `*new service*`, `*service install*`, `*service created*`, `*wmi*subscription*`, `*startup folder*`, `*startup item*`, `*browser extension*`, `*persistence*`) **and** the incident carries a hostname | 95 |
| Manual | an analyst starts the workflow for an incident or an endpoint (never matches automatically) | n/a |

An incident whose `workflow_id` is `persistence` always runs this workflow. When several workflows
match, the highest priority wins, then the workflow id: ransomware (200) still wins over persistence,
and persistence wins over the malware triggers (100, 90, 80) when an incident reports both. The
workflows that hand persistence off to this one, malicious-powershell (125) and unauthorized-rmm
(150), win when their own techniques are reported too (architecture 14.11.2).

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence
drops, but a recommendation backed by other evidence is still made.

- `secure_endpoint`: persistence items, detections and trajectory of the endpoint, prevalence of the
  persisted binaries and the isolation of the endpoint (`investigate_endpoint`,
  `search_hash_enterprise`, `investigate_process`). With the real adapter only the computer reads
  are VERIFIED; persistence items, enterprise hash search and process reads come from typed records
  in the simulated lab (see Known limitations).
- `virustotal`: public reputation of every persisted binary's hash (`enrich_hash`). Only public
  indicators are disclosed (disclosure policy).

## Optional integrations

- `defender_endpoint`: second endpoint source (machine, detections, timeline) and isolation, hash
  indicators and process actions for the endpoints it manages.
- `alienvault_otx`: independent reputation (OTX pulses) for the persisted binaries.
- `cisco_xdr`: platform verdicts and sightings for the endpoint and the hashes, and the native
  response actions (`respond/observables`, `respond/trigger`) the router prefers when configured.

## Input data

Incident observables of type `hostname` and `sha256`, the incident users, and
`trigger.mitre_techniques` / `trigger.source` for routing. Values found by earlier steps feed later
steps (the binaries the persistence items launch are enriched and searched; the other endpoints that
saw a non-clean persisted binary are investigated next). All test data is fake.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues. Endpoint
and process reads look back 168 hours, because a persistence item may be days old.

| # | Step | Atomic | Subjects | Sources |
|---|---|---|---|---|
| 1 | `endpoint_triage` | `investigate_endpoint` | incident hostnames | Secure Endpoint, Defender, Cisco XDR |
| 2 | `persisted_binary_reputation` | `enrich_hash` | incident hashes and every hash a persistence item launches (at most 10) | every enricher, disclosure policy applies |
| 3 | `persisted_binary_prevalence` | `search_hash_enterprise` | the same hashes | Secure Endpoint, Defender, Cisco XDR |
| 4 | `affected_endpoints` | `investigate_endpoint` | the other endpoints that saw a persisted binary not rated clean (a fleet-wide foothold) | Secure Endpoint, Defender, Cisco XDR |
| 5 | `persisted_process_tree` | `investigate_process` | `<ENDPOINT>/<sha256>` of every persisted binary (at most 10) | Secure Endpoint, Defender |

The hooks (`hooks.py`) then derive facts from the run's own records: which persisted binaries are
malicious and how widespread, which persistence items are malicious, which endpoints carry a
malicious item backed by active malicious execution, and which persisted malicious processes are
still running. Every fact carries the record ids it was computed from.

- A persisted binary is malicious when an endpoint detection or endpoint telemetry (a process event
  or a prevalence record) rates its hash MALICIOUS, or its aggregate enrichment is MALICIOUS (two
  vendors, never one alone).
- A persistence item is malicious when the endpoint source rates the item MALICIOUS or its binary is
  malicious.
- Active malicious execution on an endpoint is an active (not resolved) MALICIOUS detection there, or
  an execution event (process_start, file_execute, module_load) of a malicious binary that a
  persistence item on that endpoint launches.

## Correlation logic

- Framework links: the same hash on two or more endpoints or users (a fleet-wide foothold), the same
  endpoint or user across sources, and parent/child process lineage. Window 120 minutes.
- Workflow links (hooks, kind `workflow`): each persistence item tied to the binary it launches on
  its endpoint and to that binary's execution events there.
- Links shape the clusters, the blast radius and the decision card. They are never evidence on
  their own and never change an approval level.

## Risk calculation

Each target is scored by the scoring engine (docs/threat-scoring.md) from the records its rule
cites plus the target's enrichment:

- endpoint detections and malicious process events: `endpoint_detection` (weight 1.0);
- a persistence item that the endpoint source rates malicious or suspicious: `persistence`,
  weighted 1.0 in this workflow (the engine default is 0.8) because persistence is what it responds to;
- a hash prevalence record marked malicious: `endpoint_detection`;
- VirusTotal, OTX and Cisco XDR answers: vendor reputation, capped by the engine; one vendor alone is
  never an aggregate MALICIOUS verdict;
- a critical asset adds the engine's critical-asset bonus (only with malicious evidence).

Risk and confidence are separate integers. Expected sources are Secure Endpoint and VirusTotal: a
failed one costs confidence once and is listed as degraded. Rule thresholds (below them the action
is "considered, not proposed" and listed in the notes, never hidden): isolation and termination
risk 60, hash block risk 50.

## Containment recommendations

| Rule | Action (builder) | Proposed when | Evidence cited |
|---|---|---|---|
| `isolate_persistence_host_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`, `connector_guid` param) | the endpoint has a Secure Endpoint connector, isolation is not known to be impossible, it carries a malicious persistence item and shows active malicious execution | the malicious items, the active detections, the execution events, and the malicious enrichment and prevalence of the persisted binaries |
| `isolate_persistence_host_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | the same, for an endpoint with a Defender machine id (a duplicate of the Secure Endpoint proposal is merged) | the same |
| `terminate_running_persisted_process` | `terminate_process` (target `<ENDPOINT>/<pid>`, or `<ENDPOINT>/<sha256>` without a pid) | a malicious binary that a persistence item on that endpoint launches started and no `process_end` for it was seen, and the agent has not remediated it | the start event, the persistence items, detections, malicious enrichment |
| `block_malicious_persisted_binary` | `block_hash` | the persisted binary (or an incident hash) is malicious and seen on 10 endpoints or fewer, or its prevalence is unknown | the persistence items launching it, malicious detections and events, prevalence records, malicious enrichment |

### Manual steps, hand-offs and items not proposed

- Manual step (one per malicious persistence item, subject `remove_persistence:<ENDPOINT>/<item id>`):
  remove the item by hand (delete the Run or RunOnce value or startup item, disable then delete the
  scheduled task, stop and disable then delete the service, remove the WMI event filter, consumer
  and binding, remove the browser extension and block it by browser policy), then re-scan after a
  reboot and record who removed it and when. On a critical asset the step says to coordinate with the
  asset owner. No VERIFIED vendor write removes persistence, so this is never in the package.
- Considered, not proposed: a persistence item that no source rates malicious (rated suspicious or
  not rated: an analyst reviews it); an endpoint whose malicious persistence is dormant (no active
  detection and no execution: not isolated); a malicious persisted binary seen on more than 10
  endpoints (no fleet-wide block, a human decides); an incident hash with no malicious verdict that
  no persistence item launches.
- A persistence item rated malicious whose binary is rated clean (a legitimate system tool started
  with hostile arguments) never leads to a hash block or a termination of that binary.
- Hand-offs: none. Network indicators the persisted binary contacted belong to the c2 workflow.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps"), each with the record ids that show it. Allow-listed targets (for example an
allow-listed hash) are still built and shown as excluded with the reason, never dropped.

## Approval requirements

- Every action in the package needs human approval before it runs: isolation, process termination
  and hash blocks, and later every release. AI and automation principals can never approve, and
  nothing in the workflow can switch approval off.
- ELEVATED approval (a human holding the elevated approver role, for example the SOC lead) applies,
  with a visible warning on the decision card, when a target is a critical asset (for example a
  domain controller or a production server, also for the endpoint part of a process target) or when
  a blast-radius cap is exceeded (for example more than 5 endpoints, as when the same malicious
  service is installed on six workstations). ELEVATED is decided by `PackageBuilder` from the
  investigated asset context; the workflow never sets it and a critical asset is never skipped
  silently.
- The analyst may approve all, approve a selection, reject, or ask for more investigation.
- Manual removal steps are not approvals: they are listed for the analyst and run by hand.

## Containment execution

After approval the orchestrator executes the approved actions automatically, through the guard and
the approval token, native first (Cisco XDR `respond/trigger` when `native_actions` is configured),
then directly:

| Action | Route with the real adapters |
|---|---|
| isolate endpoint | Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` (VERIFIED) or Defender `POST /api/machines/{id}/isolate` (VERIFIED), or the native action |
| block hash | Defender indicator `POST /api/indicators` (VERIFIED) or the native "Block File Hashes" action; Secure Endpoint file lists are UNVERIFIED and never called |
| terminate process | no VERIFIED vendor endpoint: reported UNROUTED, with a manual step in the endpoint console |
| remove persistence | no VERIFIED vendor endpoint and no catalog integration: never proposed, listed as a manual step |

An UNROUTED action is listed on the decision card and in the notes for manual handling; it is never
dropped. Unlock codes for isolated endpoints stay in the Secure Endpoint console and are never
copied into notes, notifications or reports.

## Verification

Verification is automatic after execution and reads the target state back: Defender machine actions
are VERIFIED or NOT_VERIFIED; Secure Endpoint isolation and Defender indicators are UNABLE_TO_VERIFY
until their read endpoints are VERIFIED (docs/integrations.md section 3). The result table shows
every action with its execution and verification status (SUCCESS, ALREADY_CONTAINED, FAILED,
SKIPPED, REJECTED_BY_ANALYST). Whether a removed persistence item comes back after a reboot is
checked by the analyst's re-scan (manual step), not by the lifecycle.

## Rollback

Every reversible action registers a temporary control: isolation (release endpoint) and hash blocks
(unblock). Process termination is not reversible and registers no control; a manually removed
persistence item is restored, if ever needed, by hand. Restoration needs its own human release
approval of a release package built from the registry; closing the incident never removes a control
by itself.

## Failure handling

- A failed or degraded source (for example VirusTotal unavailable or over quota) is listed as
  degraded, lowers confidence once, and never blocks a recommendation that other evidence supports.
- A required integration that is not enabled (for example a Defender-only tenant without Secure
  Endpoint) is noted; the other sources still recommend.
- A step, rule or hook that fails is noted and skipped; the rest of the run still recommends.
- A rule with no citable record proposes nothing (no invented evidence).
- An approved action that fails at the vendor is reported FAILED and never retried silently; the
  overall result is PARTIALLY_CONTAINED or CONTAINMENT_FAILED.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0003 Persistence | T1547 Boot or Logon Autostart Execution | T1547.001 Registry Run Keys / Startup Folder | blocks the malicious binary a Run value or startup item launches, isolates the endpoint when it is executing, lists the removal as a manual step |
| TA0003 Persistence | T1053 Scheduled Task/Job | T1053.005 Scheduled Task | the same for scheduled tasks, including dormant ones that have not run yet |
| TA0003 Persistence | T1543 Create or Modify System Process | T1543.003 Windows Service | the same for services, including one service installed on several endpoints; terminates the running service process |
| TA0003 Persistence | T1546 Event Triggered Execution | T1546.003 Windows Management Instrumentation Event Subscription | the same for WMI event subscriptions (the consumer's binary) |
| TA0003 Persistence | T1176 Software Extensions | T1176.001 Browser Extensions | only where the endpoint source reports the extension as a persistence item: blocks a malicious extension file, removal is a manual step |

No other technique is mapped: account creation from the legacy spec is not handled (see Known
limitations), and launch agents and cron items are handled when reported but not mapped.

## Testing instructions

- Simulation scenarios: `tests/fixtures/workflows/persistence/` (the minimum set of 14.5.3, four edge
  cases and the five migrated legacy scenarios `legacy-01` to `legacy-05`). They run automatically,
  in dry run and simulated live, in `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/persistence/`.
- Commands (from the repository root):
  - `python -m pytest -q -p no:cacheprovider tests/workflows/persistence tests/simulation/test_workflow_scenarios.py -k persistence`
  - `python tools/validation/check_workflow_readmes.py --workflow persistence`
  - `python tools/simulator/simulate.py --workflow persistence --scenario tp-approve-all --check` (add `--live` for the simulated live run)

## Known limitations

- Removing a persistence item has no VERIFIED vendor write and no catalog integration: it is never
  automated and every malicious item is a manual step outside the package and the decision card's
  action list.
- No VERIFIED vendor read returns persistence items as typed records (Secure Endpoint events and
  Defender timeline rows have no documented field schema): with the real adapters persistence items
  stay generic records (citable, never scored); the hash block still follows enrichment and the
  isolation follows typed detections.
- Browser extensions are recognised only when the endpoint source reports them as a persistence item:
  mechanism `browser_extension`, or mechanism other with an extension path or name (a source that does
  not map the dedicated mechanism); no VERIFIED vendor read maps extensions to typed records yet.
- Account creation (legacy mapping T1136) is not handled: no VERIFIED source returns account creation
  as a typed record. Launch agents and cron items are handled when reported but not triggered on or
  mapped.
- Isolation needs active malicious execution; a dormant malicious item is listed as considered, its
  binary is blocked, and the endpoint is not isolated.
- A persistence item rated malicious without a malicious verdict for its binary never leads to a hash
  block (the binary may be a legitimate system tool).
- Terminate process has no VERIFIED vendor endpoint: with the real adapters it is UNROUTED and handled
  manually in the endpoint console; only the simulated lab executes it.
- Secure Endpoint hash blocking and its isolation-state read are UNVERIFIED: hash blocks use the
  native action or Defender indicators, and Secure Endpoint isolation verifies as UNABLE_TO_VERIFY.
- A malicious persisted binary seen on more than 10 endpoints is not proposed for a fleet-wide block;
  it is listed as considered and a human decides.
- Network indicators the persisted binary contacted are not enriched or blocked here (c2 workflow).
- Third-party reputation is limited by the disclosure policy and the VirusTotal public quota.
