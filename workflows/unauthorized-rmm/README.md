# Unauthorised remote access tool

Phase 3 workflow `unauthorized-rmm` (definition version 3.0.0). Code:
`src/xdr_response/workflows/unauthorized_rmm/` (`definition.py`, `hooks.py`). It replaces the legacy
plan-rule spec (`workflow.yaml` and its five scenarios, renamed from `rmm` in Phase 1), which were
migrated to typed simulation scenarios and deleted. The binding design is
[docs/architecture.md](../../docs/architecture.md) sections 12 to 14.

## Purpose

Handle a remote monitoring and management (RMM) or remote desktop tool on an endpoint: AnyDesk,
RustDesk, ScreenConnect, TeamViewer, Splashtop, Atera, ConnectWise and others. These are legitimate
products that attackers abuse, typically after a fake help-desk call. The workflow automatically
identifies the tool, investigates how it was installed (installer source), who ran it, where it
executed, how it persists and which destinations its sessions reach, scopes the other endpoints that
run it, and then **recommends** a containment package with numbered evidence and separate risk and
confidence scores:

- terminate the running tool;
- block the tool's binary (hash) fleet-wide;
- block the destinations the tool talks to (relay or broker domains, a lure download domain, a session
  peer IP rated malicious or suspicious);
- isolate an endpoint whose remote session shows an untrusted operator.

**A sanctioned corporate tool is never treated as malicious.** The workflow never rates a tool by its
name: a tool is *flagged* only by an endpoint detection, a malicious or suspicious process event or a
reputation verdict that cites its records. `allowlists.approved_rmm` (alias `approved_rmm_allowlist`
in `config/allowlists.yaml`) is checked on every proposal by the framework: an approved tool's hashes
and domains are moved to the package's excluded targets (shown, never executed), and a hash block or
process termination of a file signed by an approved signer, or of an approved binary, is withheld and
shown as considered. A tool seen on more than 50 endpoints looks like a corporate deployment and gets
no fleet-wide block proposal; a human decides.

The workflow never executes, approves or chooses an approval level. A human approves the package; only
then does the lifecycle orchestrator execute, verify and (after a separate human release approval)
restore.

Default severity: HIGH. Related workflows: [mail-bombing](../mail-bombing/README.md) (the flood that
often precedes the fake help-desk call), [persistence](../persistence/README.md),
[account-takeover](../account-takeover/README.md), [malware](../malware/README.md),
[c2](../c2/README.md).

## Trigger

| Type | Matches | Priority |
|---|---|---|
| XDR incident rule | the incident reports the remote access tools technique of the MITRE mapping (a reported sub-technique matches its parent) **and** carries a hostname or a SHA-256 | 150 |
| XDR incident rule | the title matches `*remote access tool*`, `*remote access software*`, `*remote desktop tool*`, `*rmm tool*`, `*remote monitoring and management*` or `*unapproved rmm*` **and** the incident carries a hostname | 145 |
| Manual | an analyst starts the workflow from an incident or an endpoint observable (never matches automatically) | n/a |

An incident whose `workflow_id` is `unauthorized-rmm` always runs this workflow. When several workflows
match, the highest priority wins, then the workflow id. The title rule (145) ranks above the broader
lateral-movement titles (140, `*remote desktop*`), so a remote desktop tool alert comes here. The mail-bombing workflow hands an endpoint
off to this workflow when the fake help-desk follow-up appears after a flood.

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence
drops, but a recommendation backed by other evidence is still made.

- `secure_endpoint`: endpoint detections, device trajectory (execution, installer source, network
  sessions), persistence, hash prevalence and signer, and the isolation of the endpoint
  (`investigate_endpoint`, `search_hash_enterprise`). With the real adapter the computer and
  trajectory reads are VERIFIED, but trajectory events have no documented field schema (see Known
  limitations).
- `umbrella`: domain status and categories of the tool's relay and download domains
  (`enrich_domain`, VERIFIED categorization endpoint), and the landing product for approved domain
  blocks (destination lists, VERIFIED).

## Optional integrations

- `defender_endpoint`: second endpoint source (machine, alerts, timeline, prevalence) and isolation
  or hash and IP indicators for the endpoints it manages.
- `cisco_xdr`: platform verdicts and sightings for the tool's hash, domains and IPs, and the native
  response actions (`respond/observables`, `respond/trigger`) the router prefers when configured.
- `virustotal`: public reputation of the tool's hash and of the public domains and IPs its sessions
  reach (disclosure policy applies: internal values are never sent).
- `alienvault_otx`: independent reputation (OTX pulses) for the session peers and the tool's hash.
- `entra`: profile and risk state of the users who ran the tool or use the endpoint
  (`investigate_user`), for the account-takeover hand-off.
- `meraki`: landing product for approved blocks of a session peer IP rated malicious or suspicious.

## Input data

Incident observables of type `hostname`, `sha256`, `domain`, `ip` and `user`, the incident users, and
`trigger.mitre_techniques` / `trigger.source` for routing. Values found by earlier steps feed later
steps (for example, the endpoints that run the tool's hash are investigated next). Free text such as
the legacy `initial_contact` stays in `incident.trigger` as data; it is never evidence on its own. All
test data is fake.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues.

| # | Step | Atomic | Subjects | Sources |
|---|---|---|---|---|
| 1 | `endpoint_triage` | `investigate_endpoint` | incident hostnames | Secure Endpoint, Defender, Cisco XDR |
| 2 | `tool_reputation` | `enrich_hash` | incident hashes, detection hashes, hashes of processes that talk to the network, persistence items and executed files (in that order, at most 10) | every enricher, disclosure policy applies |
| 3 | `tool_prevalence` | `search_hash_enterprise` | the same hashes (prevalence, endpoints, code-signing subject) | Secure Endpoint, Defender, Cisco XDR |
| 4 | `affected_endpoints` | `investigate_endpoint` | endpoints of detections, and endpoints that saw an incident or detection hash seen on 50 endpoints or fewer | Secure Endpoint, Defender, Cisco XDR |
| 5 | `destination_domains` | `enrich_domain` | incident domains and every domain of connections, network and file events and DNS queries (at most 15) | every enricher |
| 6 | `destination_ips` | `enrich_ip` | incident IPv4 addresses and remote IPs of non-internal connections and events (at most 15) | every enricher |
| 7 | `tool_users` | `investigate_user` | incident users and the users the endpoint records name | Entra |

The hooks (`hooks.py`) then derive facts from the run's own records, each with the record ids it was
computed from:

- **tools**: every remote access binary, identified by a known executable name (a product table in
  `definition.py`), by a detection that reports the technique or names remote access, or by a
  prevalence or persistence record of such a binary; whether something flags it, its prevalence and
  signer;
- **running**: processes of a tool that started and were not seen ending;
- **sessions**: endpoints with an active session of a tool to a peer outside the organisation
  (internal and non-public peers are the organisation's own IT) and whether the operator is untrusted;
- **destinations**: relay, broker and peer domains and public IPs of the sessions, and the installer
  source (the domain or IP the binary was written from), with their ratings.

## Correlation logic

- Framework links: the same hash, domain or IP on two or more endpoints or users (one tool or relay
  across the estate); the same endpoint or user across sources; process lineage. Window 120 minutes.
- Workflow links (hooks, kind `workflow`): a remote session (the endpoint, the tool's hash and the
  peer domain or IP its process connected to) and the installer origin (the tool's hash written on an
  endpoint from a domain or IP).
- An untrusted session is concluded per endpoint from records: a session peer rated malicious or
  suspicious by reputation, a connection record carrying such a verdict, or a detection that rates the
  tool MALICIOUS on that endpoint.
- Links shape the clusters, the blast radius and the decision card. They are never evidence on their
  own and never change an approval level.

## Risk calculation

Each target is scored by the scoring engine (docs/threat-scoring.md) from the records its rule cites
plus the target's enrichment:

- endpoint detections and malicious or suspicious process events of the tool: `endpoint_detection`
  (weight 1.0); a detection rated SUSPICIOUS from one source is capped below CRITICAL;
- network connections and DNS queries with a verdict: `network_behaviour`;
- Umbrella, Cisco XDR, VirusTotal and OTX answers: vendor reputation, capped by the engine; one vendor
  alone is never an aggregate MALICIOUS verdict;
- a destination block and an isolation cite the tool's flagging records next to their own contact
  records, so they score on the same detection;
- a critical asset adds the engine's critical-asset bonus (only with malicious evidence).

The workflow never scores a tool by its name. Risk and confidence are separate integers. Expected
sources are Secure Endpoint and Umbrella: a failed one costs confidence once and is listed as
degraded. Rule thresholds (below them the action is "considered, not proposed" and listed in the
notes, never hidden): isolation risk 50, every other action risk 40.

## Containment recommendations

| Rule | Action (builder) | Proposed when | Evidence cited |
|---|---|---|---|
| `terminate_rmm_process` | `terminate_process` (target `<ENDPOINT>/<pid>`, or `<ENDPOINT>/<sha256>` without a pid) | a process of the tool started and no `process_end` was seen, and the tool is flagged or its session on that endpoint is untrusted | the start event, the tool's flagging records, the untrusted-session records |
| `block_rmm_binary` | `block_hash` | the tool is flagged and seen on 50 endpoints or fewer (or its prevalence is unknown) | flagging detections and events, prevalence records, malicious or suspicious enrichment |
| `block_rmm_destination_domain` | `block_domain` (catalog order: native, Umbrella, Defender) | a session domain of a flagged tool that is not widespread, or any session or installer domain rated malicious or suspicious | the contact records, the tool's flagging records, the domain's rating |
| `block_rmm_session_peer_ip` | `block_ip` (catalog order: native, Meraki, Defender) | a public session peer IP rated malicious or suspicious (by reputation or the connection record) | the contact records, flagging records, the IP's rating |
| `isolate_untrusted_session_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`, `connector_guid` param) | the endpoint has a Secure Endpoint connector, isolation is not known to be impossible, and an active session of a tool shows an untrusted operator; applies to sanctioned tools too | the untrusted-session basis, the tool's flagging records, the session connections, the running process, the endpoint record |
| `isolate_untrusted_session_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | the same, for an endpoint with a Defender machine id (a duplicate of the Secure Endpoint proposal is merged) | the same |

Allow-listed targets are still built and shown as excluded with the reason, never dropped. An approved
tool's hash or signer withholds its hash block and process termination (`ALLOWLISTED`, shown as
considered), also when the process start event carries no hash and the host's records name the same
executable (every candidate hash must be sanctioned). An unrated relay domain whose block rests only on
the flag of a tool sanctioned by hash or signer is withheld the same way (rule `binaries`, architecture
14.11.6); a relay that reputation itself rates malicious or suspicious is still proposed. Isolation follows the session, not the tool: a sanctioned tool driven by an untrusted
operator still gets the isolation proposal.

### Hand-offs and items not proposed

- Not proposed, and listed as considered: a tool nothing flags (`rmm_tool:<name>`, so the analyst can
  confirm the approved_rmm entry); the isolation of an endpoint with an active session of a flagged
  tool but no untrusted-operator evidence; the hash and relay domain blocks of a tool seen on more than
  50 endpoints; an unrated session peer IP (vendor relays are shared infrastructure); an unrated
  installer source domain (often the vendor's own download site); and, from the framework, the hash
  block or termination of an approved binary or signer, and the block of an unrated relay of such a
  tool.
- Manual steps (no VERIFIED write): uninstall the tool and its service on each affected endpoint
  through the endpoint management console, unless it is sanctioned (then review its configuration and
  operator accounts), and confirm with the user how the remote contact started.
- Hand-offs: `persistence` when the tool persists (a service, task or run key of the tool's binary);
  `account-takeover` when a user of an affected endpoint shows a compromise record (high or confirmed
  identity risk, or a high-severity anomaly).

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a
suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action in the package needs human approval before it runs: process termination, hash, domain
  and IP blocks, isolation, and later every release. AI and automation principals can never approve,
  and nothing in the workflow can switch approval off.
- ELEVATED approval (a human holding the elevated approver role, for example the SOC lead) applies,
  with a visible warning on the decision card, when a target is a critical asset (for example a domain
  controller or a production server, also for the endpoint part of a process target) or when a
  blast-radius cap is exceeded (for example a help-desk campaign that puts the tool on more than 5
  endpoints). ELEVATED is decided by `PackageBuilder` from the investigated asset context; the workflow
  never sets it and a critical asset is never skipped silently.
- Before approving an isolation of an endpoint running a sanctioned tool, the analyst confirms the
  remote operator with the service desk (no RMM console API is VERIFIED).
- The analyst may approve all, approve a selection, reject, or ask for more investigation.

## Containment execution

After approval the orchestrator executes the approved actions automatically, through the guard and
the approval token, native first (Cisco XDR `respond/trigger` when `native_actions` is configured),
then directly:

| Action | Route with the real adapters |
|---|---|
| isolate endpoint | Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` (VERIFIED) or Defender `POST /api/machines/{id}/isolate` (VERIFIED), or the native action |
| block hash | Defender indicator `POST /api/indicators` (VERIFIED) or the native "Block File Hashes" action; Secure Endpoint file lists are UNVERIFIED and never called |
| block domain | Umbrella destination lists (VERIFIED), Defender indicators, or the native action |
| block IP | Meraki or Defender indicators (VERIFIED), or the native action; direct Umbrella IP blocking is UNVERIFIED and never called |
| terminate process | no VERIFIED vendor endpoint: reported UNROUTED, with a manual step in the endpoint console |

An UNROUTED action is listed on the decision card and in the notes for manual handling; it is never
dropped. Unlock codes for isolated endpoints stay in the Secure Endpoint console and are never copied
into notes, notifications or reports.

## Verification

Verification is automatic after execution and reads the target state back: Defender machine actions
are VERIFIED or NOT_VERIFIED; Umbrella destination lists and Meraki rules are read back; Secure
Endpoint isolation and Defender indicators are UNABLE_TO_VERIFY until their read endpoints are
VERIFIED (docs/integrations.md section 3). The result table shows every action with its execution and
verification status (SUCCESS, ALREADY_CONTAINED, FAILED, SKIPPED, REJECTED_BY_ANALYST).

## Rollback

Every reversible action registers a temporary control: isolation (release endpoint), hash, domain and
IP blocks (unblock). Process termination is not reversible and registers no control. Restoration
needs its own human release approval of a release package built from the registry; closing the
incident never removes a control by itself. Uninstalling the tool is a manual step and has no
automated rollback.

## Failure handling

- A failed or degraded source (for example Umbrella unavailable) is listed as degraded, lowers
  confidence once, and never blocks a recommendation that other evidence supports. An action whose
  only backing came from the failed source (for example an isolation that rested on Umbrella's rating
  of the peer) is not proposed and is listed as considered with its records.
- A step, rule or hook that fails is noted and skipped; the rest of the run still recommends.
- A rule with no citable record proposes nothing (no invented evidence).
- An approved action that fails at the vendor is reported FAILED and never retried silently; the
  overall result is PARTIALLY_CONTAINED or CONTAINMENT_FAILED.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0011 Command and Control | T1219 Remote Access Tools | T1219.002 Remote Desktop Software | legitimate remote desktop and RMM software used as an unsanctioned or hostile control channel: the workflow terminates the tool, blocks its binary and relay destinations, and isolates an endpoint whose session shows an untrusted operator |

No other technique is mapped. The help-desk impersonation, the mail flood that often precedes it and
the persistence of the tool's service are handled by the related workflows, not mapped here.

## Testing instructions

- Simulation scenarios: `tests/fixtures/workflows/unauthorized-rmm/` (the minimum set of 14.5.3, six
  edge cases and the five migrated legacy scenarios `legacy-01` to `legacy-05`). They run
  automatically, in dry run and simulated live, in `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/unauthorized_rmm/`.
- Commands (from the repository root):
  - `python -m pytest -q -p no:cacheprovider tests/workflows/unauthorized_rmm tests/simulation/test_workflow_scenarios.py -k "unauthorized-rmm or unauthorized_rmm"`
  - `python tools/validation/check_workflow_readmes.py --workflow unauthorized-rmm`
  - `python tools/simulator/simulate.py --workflow unauthorized-rmm --scenario tp-approve-all --check` (add `--live` for the simulated live run)

## Known limitations

- Hooks and rule expressions cannot read `allowlists.approved_rmm`: the framework enforces it on the
  proposals (excluded hashes and domains; withheld hash blocks and terminations for approved binaries
  and signers). An approved_rmm entry that lists only a name protects nothing; list the tool's hashes,
  signers and domains.
- Isolation follows the session, not the tool: an endpoint with a session of a sanctioned tool is
  isolated when the peer is rated malicious or suspicious or a detection rates the tool malicious.
  Whether the remote operator is verified IT staff cannot be read (no RMM console API in
  docs/integrations.md); the analyst confirms it with the service desk before approving.
- Real Secure Endpoint trajectory events and Defender timeline rows have no documented field schema,
  so they stay generic records (citable, never scored). Execution, sessions, installer source and
  persistence facts come only from typed sources until a schema is VERIFIED.
- Terminate process has no VERIFIED vendor endpoint: with the real adapters it is UNROUTED and
  handled manually in the endpoint console.
- Uninstalling the tool and removing its service have no VERIFIED write: they are manual steps, and
  persistence is handed off to the persistence workflow.
- Secure Endpoint hash blocking and its isolation-state read are UNVERIFIED: hash blocks use the
  native action or Defender indicators, and Secure Endpoint isolation verifies as UNABLE_TO_VERIFY.
- A tool seen on more than 50 endpoints gets no fleet-wide hash or relay-domain block proposal; a
  human decides from the cited prevalence record.
- Session peer IPs are blocked only when rated malicious or suspicious; an unrated vendor relay is
  covered by the relay domain block.
- Tools are identified by known executable names, by detections that report the technique or name
  remote access, and by remote-access DNS categories; a renamed binary of an unlisted product without
  such a detection is not identified.
- IPv6 session peers are not enriched or blocked by this workflow.
- Third-party reputation is limited by the disclosure policy and the VirusTotal public quota.
