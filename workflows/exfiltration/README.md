# Data exfiltration

Phase 4 workflow `exfiltration` (definition version 2.0.0). Code:
`src/xdr_response/workflows/exfiltration/` (`definition.py`, `hooks.py`). It replaces the legacy
plan-rule spec (`workflow.yaml` and its six scenarios), which were migrated to typed simulation
scenarios and deleted. The binding design is [docs/architecture.md](../../docs/architecture.md)
sections 12 to 14.

## Purpose

Stop large or unusual outbound transfers and preserve evidence for impact assessment. The workflow
automatically investigates an outbound transfer that looks like data theft: an unusual upload volume,
a new or unrated external destination, unusual cloud storage, abnormal DNS, an unusual session of the
account that drives the transfer, or a large transfer reported by an endpoint or network source. It
correlates user, endpoint, process, destination, volume and authentication, and then **recommends** a
containment package with numbered evidence and separate risk and confidence scores:

- block the destination domains and public IPs that receive the data;
- isolate a source endpoint while its transfer is still running and shows exfiltration evidence;
- revoke the sign-in sessions of, and disable, an account that drives the transfer and is compromised
  or named by an insider-risk detection.

Clean, shared and internal destinations are never proposed for a block; they are listed as
considered with their records. Sanctioned backup, file-transfer and partner services belong in
`allowlists.never_block`: the package builder excludes their blocks (shown, never executed).

The workflow never executes, approves or chooses an approval level. A human approves the package; only
then does the lifecycle orchestrator execute, verify and (after a separate human release approval)
restore.

Default severity: CRITICAL. Related workflows: [c2](../c2/README.md) (a command and control channel
that also carries data), [dns-tunneling](../dns-tunneling/README.md) (DNS tunnels in general),
[cloud-compromise](../cloud-compromise/README.md) (data taken from cloud tenants),
[account-takeover](../account-takeover/README.md) (the hand-off for a compromised account),
[ransomware](../ransomware/README.md) (double extortion: ransomware wins the routing).

## Trigger

| Type | Matches | Priority |
|---|---|---|
| XDR incident rule | the incident reports an exfiltration technique of the MITRE mapping (a reported sub-technique matches its parent) | 150 |
| XDR incident rule | the title matches `*exfiltration*`, `*exfil *`, `*data theft*`, `*data loss*`, `*large outbound transfer*`, `*large upload*`, `*unusual upload*`, `*outbound volume anomaly*`, `*upload to unsanctioned*`, `*upload to personal cloud*` or `*data staged and sent*` **and** the incident carries a hostname, a user, a domain or an IP | 140 |
| Manual | an analyst starts the workflow from an incident, an endpoint, a user or a destination (never matches automatically) | n/a |

An incident whose `workflow_id` is `exfiltration` always runs this workflow. When several workflows
match, the highest priority wins, then the workflow id. The workflow outranks account-takeover (100),
which it hands off to; ransomware (200) wins a double-extortion incident. Secure Network Analytics
volume alerts and DLP or insider-risk alerts reach the workflow as Cisco XDR incidents through these
rules (the trigger workflow sends only the incident id).

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence
drops, but a recommendation backed by other evidence is still made.

- `secure_endpoint`: endpoint detections, staging events, outbound connections with their volumes and
  the DNS of the source endpoint (`investigate_endpoint`), and the isolation of the endpoint (VERIFIED
  computer read and isolation write).
- `umbrella`: status and categories of the destination domains (`enrich_domain`, VERIFIED
  categorization endpoint: cloud storage, newly seen), and the landing product for approved domain
  blocks (destination lists, VERIFIED).
- `entra`: profile, risk state, sign-ins and anomalies of the accounts that drive the transfer
  (`investigate_user`, VERIFIED user and sign-in reads), and the session revocation and account
  disable (VERIFIED writes).

## Optional integrations

- `defender_endpoint`: second endpoint source (machine, alerts, timeline, connections) and isolation
  or IP and domain indicators for the endpoints it manages.
- `cisco_xdr`: platform verdicts and sightings for the destinations, and the native response actions
  (`respond/observables`, `respond/trigger`) the router prefers when configured.
- `microsoft_cloud`: Defender XDR alerts of the source endpoint (`alerts_v2`, including data-loss and
  insider-risk alerts) and advanced hunting across the estate (which other endpoints reach a
  destination).
- `splunk`: enterprise search of proxy, firewall and DNS logs for the destinations (optional, disabled
  by default).
- `virustotal`: public reputation of the public destination domains and IPs (disclosure policy
  applies: internal values are never sent).
- `alienvault_otx`: independent reputation (OTX pulses) for the destination domains and IPs.
- `meraki`: landing product for approved blocks of a destination IP at the MX firewall.

## Input data

Incident observables of type `hostname`, `user`, `domain` and `ip`, the incident users, and
`trigger.mitre_techniques` / `trigger.source` for routing. Values found by earlier steps feed later
steps (the destinations of the endpoint's connections are enriched and searched, the accounts named on
the connections and endpoints are investigated). Detection-source context such as the legacy
`transfer_ongoing`, `insider_risk`, `data_types` or `bytes_out` fields is data, never evidence on its
own: whether a transfer still runs comes from the record times, an insider flag from an insider-risk
detection record, a volume from the connection records. All test data is fake.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues.

| # | Step | Atomic | Subjects | Sources |
|---|---|---|---|---|
| 1 | `endpoint_triage` | `investigate_endpoint` | incident hostnames | Secure Endpoint, Defender, Cisco XDR, Defender XDR alerts |
| 2 | `destination_domains` | `enrich_domain` | incident domains, domains of outbound connections, domains of abnormal DNS queries (at most 15) | every enricher |
| 3 | `destination_ips` | `enrich_ip` | incident IPv4 addresses and remote IPs of outbound connections (at most 15) | every enricher |
| 4 | `destination_reach_domains` | `search_domain_enterprise` | the same domains (at most 10) | Cisco XDR, Defender, Defender XDR hunting, Splunk |
| 5 | `destination_reach_ips` | `search_ip_enterprise` | the same IPs (at most 10) | the same |
| 6 | `transfer_actors` | `investigate_user` | incident users and the accounts the endpoints, connections and detections name (at most 10) | Entra |

The hooks (`hooks.py`) then derive facts from the run's own records, each with the record ids it was
computed from:

- **destinations**: every external domain and public IP that receives data (an outbound connection
  record with a volume, or abnormal DNS: at least 50 distinct child labels or a label of 40
  characters), the incident's domains and IPs, and what the source endpoints contacted; with the
  volume, whether the transfer still runs, the rating, cloud-storage and newly-seen categories, and how
  many endpoints of the estate reach it;
- **sources**: the endpoints the data leaves from, whether their transfer still runs (last record at
  most 30 minutes before the incident, or later), archives staged before the transfer, and the
  exfiltration evidence;
- **actors**: the accounts that drive the transfers, whether each is compromised (identity risk high
  or confirmed compromised, risk medium with an anomaly, or a high-severity anomaly) or named by an
  insider-risk detection.

## Correlation logic

- Framework links: the same domain or IP reached from two or more endpoints or users, the same user on
  several endpoints and the same endpoint used by several users. Window 180 minutes.
- Workflow links (hooks, kind `workflow`): each transfer (the source endpoint, the account and the
  destination domain or IP its connection record names), each abnormal DNS channel (endpoint and
  domain), and staging (an archive written on the source endpoint up to 180 minutes before a transfer
  from it).
- Exfiltration evidence for a source is concluded from records: a destination rated malicious or
  suspicious (by reputation or by the source's own connection verdict), a malicious detection or an
  active exfiltration detection on the endpoint, a compromised account driving the transfer, or an
  insider-risk detection naming an account of the endpoint.
- How many endpoints of the estate reach a destination comes from the enterprise searches plus the
  source endpoints; more than 3 means shared infrastructure.
- Links shape the clusters, the blast radius and the decision card. They are never evidence on their
  own and never change an approval level.

## Risk calculation

Each target is scored by the scoring engine (docs/threat-scoring.md) from the records its rule cites
plus the target's enrichment and the workflow signals for it:

- endpoint detections (exfiltration, data-loss, insider-risk or any malicious detection):
  `endpoint_detection` (weight 1.0);
- network connections and DNS queries with a verdict: `network_behaviour`;
- the transfer pattern (workflow signal, `network_behaviour`, SUSPICIOUS, of the source that reported
  the records): a large or abnormal upload to a destination that is not rated clean (severity 70, 50
  for a smaller upload), a running transfer from the source endpoint (70), an account that drives such
  a transfer (60);
- identity risk and anomalies: `authentication_anomaly`;
- Umbrella, Cisco XDR, VirusTotal and OTX answers: vendor reputation, capped by the engine; one vendor
  alone is never an aggregate MALICIOUS verdict;
- a critical asset adds the engine's critical-asset bonus (only with malicious evidence).

Risk and confidence are separate integers. When every weighty signal comes from one source, risk stays
below CRITICAL. Expected sources are Secure Endpoint, Umbrella and Entra: a failed one costs
confidence once and is listed as degraded. Rule thresholds (below them the action is "considered, not
proposed" and listed in the notes, never hidden): isolation and disable risk 50, blocks and session
revocation risk 40.

## Containment recommendations

| Rule | Action (builder) | Proposed when | Evidence cited |
|---|---|---|---|
| `block_exfil_domain` | `block_domain` (catalog order: native, Umbrella, Defender) | the domain is rated malicious or suspicious, or it is unrated (not clean), receives data (an upload or an abnormal DNS channel) that is large, new, cloud storage or abnormal DNS, and is reached from 3 endpoints or fewer | the transfer and DNS records, the rating records, the categorizing DNS records |
| `block_exfil_ip` | `block_ip` (catalog order: native, Meraki, Defender) | the same for a public IPv4 address, which must also not be shared when rated | the same |
| `isolate_source_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`, `connector_guid` param) | the transfer from the endpoint still runs, the endpoint shows exfiltration evidence, it has a Secure Endpoint connector and isolation is not known to be impossible | the exfiltration evidence, the running transfer records, staged archives, the endpoint record |
| `isolate_source_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | the same, for an endpoint with a Defender machine id (a duplicate of the Secure Endpoint proposal is merged) | the same |
| `revoke_actor_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | an account that drives the transfer is compromised or named by an insider-risk detection | the compromise or insider records and the account's transfer records |
| `disable_compromised_actor` | `disable_user` (`disable_entra_user`) | an account that drives the transfer is compromised | the same |
| `disable_insider_actor` | `disable_user` (`disable_entra_user`) | an insider-risk detection names the account explicitly (never spreads to other accounts of the incident) | the same |

Allow-listed targets are still built and shown as excluded with the reason, never dropped; a package
whose only action is excluded is not proposed and the run notes the exclusion. Internal and
non-public addresses are never block candidates.

### Hand-offs and items not proposed

- Not proposed, and listed as considered: a destination that receives data but is rated clean (the
  analyst confirms it is sanctioned); a shared destination (reached from more than 3 endpoints); an
  internal relay or proxy address that received data; the isolation of an endpoint whose transfer has
  finished (nothing left to stop; the evidence stays on it), whose running transfer shows no
  exfiltration evidence beyond the transfer, or that has no isolation-capable record; and the session
  revocation and disable of an account that drives the transfer but could not be assessed because the
  identity source failed; and the disable of a compromised account that no transfer record names (for
  example a second user of the source endpoint): account decisions never spread from the transfer's
  account to another user of the endpoint. A transfer record that names no account is attributed only
  to the endpoint's single user.
- Manual step (no VERIFIED write or read): assess the data exposure from each source endpoint with
  exfiltration indications. Legal and privacy assess what was sent (the cited volume, destinations and
  window) and decide notification obligations; the evidence stays on the endpoint (no reimage before
  forensic collection and legal sign-off).
- Hand-off: `account-takeover` for every compromised account tied to the transfer (review its
  sign-ins, mailbox and cloud activity beyond this transfer).

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a
suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action in the package needs human approval before it runs: domain and IP blocks, isolation,
  session revocation, account disable, and later every release. AI and automation principals can never
  approve, and nothing in the workflow can switch approval off.
- ELEVATED approval (a human holding the elevated approver role, for example the SOC lead) applies,
  with a visible warning on the decision card, when a target is a critical asset (a domain controller,
  a production server, a privileged or service account, an executive's endpoint or account) or when a
  blast-radius cap is exceeded (for example more destination blocks than `blast_radius.max_indicators`).
  ELEVATED is decided by `PackageBuilder` from the investigated asset context; the workflow never sets
  it and a critical asset is never skipped silently.
- The analyst may approve all, approve a selection, reject, or ask for more investigation. For an
  insider case, legal and HR agree before the account is disabled.

## Containment execution

After approval the orchestrator executes the approved actions automatically, through the guard and
the approval token, native first (Cisco XDR `respond/trigger` when `native_actions` is configured),
then directly:

| Action | Route with the real adapters |
|---|---|
| block domain | Umbrella destination lists (VERIFIED), Defender indicators, or the native action |
| block IP | Meraki MX rules or Defender indicators (VERIFIED), or the native action; direct Umbrella IP blocking is UNVERIFIED and never called |
| isolate endpoint | Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` (VERIFIED) or Defender `POST /api/machines/{id}/isolate` (VERIFIED), or the native action |
| revoke sessions | Entra `POST /users/{id}/revokeSignInSessions` (VERIFIED; not in the native catalog) |
| disable user | Entra `PATCH /users/{id}` with `accountEnabled: false` (VERIFIED), or the native action |

An UNROUTED action is listed on the decision card and in the notes for manual handling; it is never
dropped. Isolation keeps the endpoint powered on with the management channel open, so evidence is
preserved. Isolation release codes stay in the Secure Endpoint console and are never copied into
notes, notifications or reports.

## Verification

Verification is automatic after execution and reads the target state back: Umbrella destination
lists and Meraki rules are read back; Defender machine actions are VERIFIED or NOT_VERIFIED; Entra
`accountEnabled` and `signInSessionsValidFromDateTime` are read back; Secure Endpoint isolation and
Defender indicators are UNABLE_TO_VERIFY until their read endpoints are VERIFIED
(docs/integrations.md section 3). The result table shows every action with its execution and
verification status (SUCCESS, ALREADY_CONTAINED, FAILED, SKIPPED, REJECTED_BY_ANALYST).

## Rollback

Every reversible action registers a temporary control: domain and IP blocks (unblock), isolation
(release endpoint) and account disable (enable user). Session revocation is not reversible and
registers no control. Restoration needs its own human release approval of a release package built
from the registry; closing the incident never removes a control by itself. For an insider case the
account is enabled again only when the owner, HR and legal agree.

## Failure handling

- A failed or degraded source (for example Entra unavailable) is listed as degraded, lowers confidence
  once, and never blocks a recommendation that other evidence supports: the destination blocks are
  still proposed. An action whose only backing came from the failed source (the account actions, and
  an isolation that rested on the compromised account) is not proposed and is listed as considered
  with its records.
- A destination whose reputation failed stays unrated and is judged by the transfer itself; the failed
  source is named in the rationale.
- A step, rule or hook that fails is noted and skipped; the rest of the run still recommends.
- A rule with no citable record proposes nothing (no invented evidence).
- An approved action that fails at the vendor is reported FAILED and never retried silently; the
  overall result is PARTIALLY_CONTAINED or CONTAINMENT_FAILED.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0010 Exfiltration | T1041 Exfiltration Over C2 Channel | none | data sent to a destination that reputation or the source's own analytics rate malicious or suspicious: the workflow blocks it and isolates a source whose transfer still runs |
| TA0010 Exfiltration | T1048 Exfiltration Over Alternative Protocol | none | large transfers over non-web protocols (for example SFTP) and data carried in abnormal DNS queries: the workflow blocks the receiving domain or IP and isolates the running source |
| TA0010 Exfiltration | T1567 Exfiltration Over Web Service | T1567.002 Exfiltration to Cloud Storage | uploads to unsanctioned or unknown cloud or file storage: the workflow blocks the storage destination unless it is shared or allow-listed, and revokes and disables the account when it is compromised or an insider risk |

No other technique is mapped. Archive staging before the transfer is used as correlation and evidence
only; the account compromise and the DNS tunnel are handled by the related workflows.

## Testing instructions

- Simulation scenarios: `tests/fixtures/workflows/exfiltration/` (the minimum set of 14.5.3, three
  edge cases: sanctioned cloud storage, a Defender-managed source over SFTP, an abnormal DNS channel;
  and the six migrated legacy scenarios `legacy-01` to `legacy-06`). They run automatically, in dry run
  and simulated live, in `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/exfiltration/`.
- Commands (from the repository root):
  - `python -m pytest -q -p no:cacheprovider tests/workflows/exfiltration tests/simulation/test_workflow_scenarios.py -k "exfiltration"`
  - `python tools/validation/check_workflow_readmes.py --workflow exfiltration`
  - `python tools/simulator/simulate.py --workflow exfiltration --scenario tp-approve-all --check` (add `--live` for the simulated live run)

## Known limitations

- The transfer facts (volume, destination, time) come from typed connection and DNS records. With the
  real adapters, Secure Endpoint trajectory events, Defender timeline and hunting rows, Splunk rows and
  Cisco XDR sightings have no documented field schema (docs/integrations.md), so they stay generic
  records: citable, never scored, never a transfer. Until a schema is VERIFIED, blocks of unrated
  destinations and isolations are recommended only where typed records exist; rated destinations are
  still blocked from their reputation.
- Secure Cloud Analytics (Secure Network Analytics) volume alerts have no VERIFIED API: they arrive as
  Cisco XDR incidents and are used for routing, never as evidence on their own.
- Whether a transfer is still running is judged from the last record time: at most 30 minutes before
  the incident was created (or later). A source that reports no time, or reports late, makes a running
  transfer look finished, so the isolation is listed as considered and the analyst decides.
- A destination reached from more than 3 endpoints of the estate is treated as shared infrastructure
  and never proposed for a block. Without an enterprise search source (Cisco XDR, Defender, Microsoft
  Defender XDR hunting or Splunk) the reach is unknown and only the source endpoints count.
- Sanctioned backup, file-transfer and partner services must be listed in `allowlists.never_block`:
  hooks and rule expressions cannot read the allow-lists; the package builder excludes such blocks and
  shows them.
- The data that left is not classified: no VERIFIED read names the files or data types sent. The impact
  assessment (legal and privacy) is a manual step with the cited volume and window.
- An insider-risk flag is read only from an endpoint or platform detection that names insider risk and
  the account; an incident field alone (for example a legacy context flag) is data, never evidence.
- Abnormal DNS is judged from the distinct child labels and label length the source reports; a DNS
  tunnel without those fields is handled by the dns-tunneling workflow, not detected here.
- Revoking sessions does not affect external (guest) users and may take a few minutes (Microsoft
  Graph); it registers no control and cannot be rolled back.
- Secure Endpoint isolation verifies as UNABLE_TO_VERIFY (the isolation read is UNVERIFIED); direct
  Umbrella IP blocking is UNVERIFIED and never called (IP blocks use Meraki, Defender indicators or the
  native action).
- IPv6 destinations are not enriched or blocked by this workflow (IPv4 only).
- Third-party reputation is subject to the disclosure policy and to VirusTotal's public quota: a
  withheld or failed source lowers confidence and is listed as degraded; an unrated destination stays
  unrated.
