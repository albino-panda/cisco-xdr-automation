# Threat intelligence sweep

Phase 5 workflow `threat-intel-sweep` (definition version 1.0.0), new in Phase 5: it has no legacy
plan-rule spec and no legacy scenarios. Code: `src/xdr_response/workflows/threat_intel_sweep/`
(`definition.py`, `hooks.py`). The binding design is
[docs/architecture.md](../../docs/architecture.md) sections 12 to 14.

## Purpose

When a high-confidence indicator of compromise (IOC) arrives (a SHA-256 file hash, an IPv4 address,
a domain, a URL or a sender email address, alone or as a feed batch), sweep the estate for it and
recommend containment for every affected asset. The workflow automatically rates every indicator
with the enrichment sources, finds the endpoints that saw or ran the file, the endpoints and
accounts that resolved, reached or signed in from the indicator and the messages that carry it, and
then **recommends** a containment package with numbered evidence and separate risk and confidence
scores:

- block every rated indicator (hash, domain, IP, URL), preventively when nothing was hit yet;
- isolate an endpoint where the rated file ran, or that reached a rated indicator and shows
  malicious activity of its own;
- quarantine the rated file on every endpoint where it is still present;
- quarantine every delivered message that carries a rated indicator;
- revoke the sessions of an account that signed in successfully from a rated IP.

An indicator is acted on only when a source the framework queried rates it: the feed's own claim of
"high confidence" is incident data and never evidence. The workflow never executes, approves or
chooses an approval level. A human approves the package; only then does the lifecycle orchestrator
execute, verify and (after a separate human release approval) restore.

Default severity: HIGH. Related workflows (all hand-off targets): [malware](../malware/README.md),
[c2](../c2/README.md), [phishing](../phishing/README.md),
[account-takeover](../account-takeover/README.md).

## Trigger

| Type | Matches | Priority |
|---|---|---|
| Manual | an analyst starts a sweep for one indicator or a list of indicators (the incident carries them as observables; never matches automatically) | n/a |
| Schedule | a scheduled retro-hunt over a threat-intelligence feed's new high-confidence indicators: one incident per batch, at most 25 indicators of each type (never matches automatically; the scheduler creates the incident with `workflow_id: threat-intel-sweep`) | 120 |
| Webhook | a threat-intelligence platform webhook (incident id only; the incident is re-read through the VERIFIED Cisco XDR APIs) whose source is `threat_intel`, `threat_intelligence` or `threat-intel` **and** that carries an indicator | 120 |
| XDR incident rule | the title names an indicator sweep, a retro-hunt or a high-confidence indicator match (`*ioc sweep*`, `*indicator sweep*`, `*threat intel sweep*`, `*threat-intel sweep*`, `*threat intelligence sweep*`, `*retro hunt*`, `*retro-hunt*`, `*retrohunt*`, `*high-confidence ioc*`, `*high confidence ioc*`, `*high-confidence indicator*`, `*high confidence indicator*`) **and** the incident carries an indicator | 120 |

An incident whose `workflow_id` is `threat-intel-sweep` always runs this workflow. When several
workflows match, the highest priority wins, then the workflow id. The automatic triggers rank above
every workflow the sweep hands off to (c2 115, phishing 110, malware and account-takeover 100), so a
sweep incident stays with the sweep and the hand-offs are still made (architecture 14.11.2). The
title patterns name a sweep explicitly, so ordinary detections keep their own workflows. Secure
Cloud Analytics alerts reach the sweep only as Cisco XDR incidents (no VERIFIED API).

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence
drops, but a recommendation backed by other evidence is still made.

- `cisco_xdr`: platform verdicts for every indicator (`enrich_*`; private intelligence carries the
  feed's own verdict, counted as one vendor), sightings across the enabled Cisco modules
  (`search_hash_enterprise`, `search_domain_enterprise`, `search_ip_enterprise`,
  `investigate_user`, `investigate_email`, `investigate_endpoint`) and the native response actions
  the router prefers when `native_actions` is configured. Enrich, observe and response listing are
  VERIFIED; sightings stay generic records until their field schema is documented.
- `secure_endpoint`: computers and device trajectory of the endpoints the sweep found
  (`investigate_endpoint`, VERIFIED) and the isolation of an affected endpoint (VERIFIED). Its
  events search is UNVERIFIED, so on a tenant the hash sweep (`search_hash_enterprise`) runs
  through Cisco XDR and Defender XDR; the simulated lab serves it from Secure Endpoint.
- `secure_email`: Secure Email Threat Defense messages that carry an indicator, by message id
  (`investigate_email`) and the related campaign messages (`search_email_campaign`), and their
  quarantine (VERIFIED move and status APIs).

## Optional integrations

- `defender_endpoint`: second endpoint source (machines, alerts, enterprise search) and isolation
  or indicator blocks for the endpoints it manages.
- `microsoft_cloud`: Defender XDR alerts and advanced hunting (VERIFIED `runHuntingQuery`):
  endpoint, DNS, connection, sign-in and Defender for Office 365 email rows that name an indicator.
- `defender_o365`: alternative executor for quarantining messages; its message search is
  UNVERIFIED, so no read path is used.
- `umbrella`: domain status and security categories of the domain indicators (VERIFIED
  categorisation) and the landing product for approved domain and URL blocks (destination lists,
  VERIFIED); Umbrella DNS activity reports are UNVERIFIED and never read.
- `entra`: profile of an account that signed in from a swept IP (a privileged account is ELEVATED)
  and the revocation of its sessions (VERIFIED).
- `virustotal`: public reputation of the hash, domain, IP and URL indicators (public indicators
  only, disclosure policy).
- `alienvault_otx`: independent reputation (OTX pulses) of the same indicators.
- `secure_malware_analytics`: domain IOC feed (VERIFIED); sample search and sandbox reports are
  UNVERIFIED.
- `hibp`: breach exposure of a sender address indicator (context only, under the disclosure
  policy).
- `splunk`: proxy, firewall, DNS, mail and sign-in logs that name an indicator (optional, disabled
  by default; rows stay citable generic records).
- `meraki`: landing product for approved IP blocks at the MX firewall.

Secure Cloud Analytics is not an integration of this workflow: its API is UNVERIFIED
(docs/integrations.md section 2.5), so its alerts are read only as Cisco XDR incidents and
sightings.

## Input data

Incident observables of type `sha256`, `domain`, `ip` (IPv4), `url` and `email_address` are the
indicators; `email_message_id` observables name carrier messages the detection source already
knows. `incident.source` / `trigger.source` and the title route the incident; feed fields such as
`trigger.feed` or `trigger.feed_confidence` are kept as data and never scored. At most 25
indicators of each type are swept per run. Values found by earlier steps feed later steps (the
endpoints the sweeps find are investigated next; message ids found in mail rows are investigated
next). All test data is fake.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues. The
sighting, mail and sender steps look back 720 hours (the framework maximum).

| # | Step | Atomic | Subjects | Sources |
|---|---|---|---|---|
| 1 | `hash_reputation` | `enrich_hash` | the SHA-256 indicators | every enricher, disclosure policy applies |
| 2 | `domain_reputation` | `enrich_domain` | the domain indicators | every enricher |
| 3 | `ip_reputation` | `enrich_ip` | the IPv4 indicators | every enricher |
| 4 | `url_reputation` | `enrich_url` | the URL indicators | every enricher |
| 5 | `sender_reputation` | `enrich_email_address` | the sender address indicators | every enricher |
| 6 | `hash_sightings` | `search_hash_enterprise` | the SHA-256 indicators | Secure Endpoint, Defender, Cisco XDR, Defender XDR, Splunk |
| 7 | `domain_sightings` | `search_domain_enterprise` | the domain indicators and the host of every URL indicator | Cisco XDR, Defender, Defender XDR, Splunk |
| 8 | `ip_sightings` | `search_ip_enterprise` | the IPv4 indicators | Cisco XDR, Defender, Defender XDR, Splunk |
| 9 | `sender_activity` | `investigate_user` | the sender address indicators | Cisco XDR, Defender XDR, Splunk |
| 10 | `messages` | `investigate_email` | incident message ids and every message id the earlier steps found (at most 50) | Secure Email, Cisco XDR, Defender XDR, Splunk |
| 11 | `related_messages` | `search_email_campaign` | the same message ids | Secure Email, Defender XDR, Splunk |
| 12 | `affected_endpoints` | `investigate_endpoint` | every endpoint the hash, domain and IP sightings named (at most 50) | Secure Endpoint, Defender, Cisco XDR |
| 13 | `affected_accounts` | `investigate_user` | accounts with a successful sign-in from a swept IP | Entra |

The hooks (`hooks.py`) then derive facts from the run's own records, each with the record ids it
was computed from:

- **indicators**: every swept indicator with its rating and hits. *Rated* means the aggregate
  enrichment verdict is MALICIOUS (two vendors, or a behavioural detection) or a record that names
  the indicator carries the security product's own MALICIOUS verdict (a detection, prevalence or
  process record of the file, a connection or DNS record whose destination is exactly the
  indicator, a message from the sender). A process verdict rates the process, never a destination
  it reached; a verdict about a subdomain never rates its parent; and a record's verdict never
  overrides a CLEAN enrichment aggregate of a domain, IP or URL (the contradiction is shown as
  considered, never resolved towards a block). A *hit* is a record that names the indicator with an affected endpoint, account or
  message; a domain also matches its subdomains, a URL only the same URL, and a DNS answer that
  resolved to an IP indicator is a hit of that IP.
- **hosts**: every endpoint a hit names, whether a rated file ran on it (a process event of an
  execution type with its hash), whether it reached a rated network indicator and whether it shows
  malicious activity of its own (an active MALICIOUS detection, a MALICIOUS process event).
- **files**: every endpoint where a rated file is present and was neither remediated by the agent
  (a resolved detection without an active one) nor deleted.
- **messages**: every message that carries an indicator, whether it is still delivered (inbox or
  junk, never reported quarantined or deleted) and which of its indicators are rated.
- **accounts**: accounts a sign-in record ties to a rated IP, whether one sign-in succeeded, the
  identity source's groups, roles and privileged flag (an account in a critical group such as
  Executives, Service Accounts or Domain Admins is ELEVATED with a warning), and the `block_ip`
  indicators the revocation rests on.

## Correlation logic

- Framework links: the same hash, domain, IP or URL on two or more endpoints or users (one
  indicator, many affected assets), the same endpoint or user across sources, a message carrying an
  indicator followed by a click from a recipient (email to click), and campaign messages. Window 24
  hours.
- Workflow links (hooks, kind `workflow`): an indicator hit, tying each swept indicator to the
  endpoint, account or message one record names together with it.
- Links shape the clusters, the blast radius and the decision card. They are never evidence on
  their own and never change an approval level.

## Risk calculation

Each target is scored by the scoring engine (docs/threat-scoring.md) from the records its rule
cites plus the target's enrichment:

- Cisco XDR, VirusTotal, OTX, Umbrella and Secure Malware Analytics answers are vendor reputation,
  capped by the engine; one vendor alone is never an aggregate MALICIOUS verdict (a Cisco XDR
  private-intelligence verdict is one vendor);
- endpoint detections, malicious process events and malicious prevalence records:
  `endpoint_detection` (weight 1.0);
- connection and DNS records that carry the security product's verdict: `network_behaviour`;
- message verdicts: `email_verdict`;
- the feed's confidence is never scored;
- a critical asset adds the engine's critical-asset bonus (only with malicious evidence).

Risk and confidence are separate integers. Expected sources are Cisco XDR, Secure Endpoint and
Secure Email: a failed one costs confidence once and is listed as degraded. Rule thresholds (below
them the action is "considered, not proposed" and listed in the notes, never hidden): isolation risk
50, file and message quarantine risk 40, indicator blocks and session revocation risk 30.

## Containment recommendations

| Rule | Action (builder) | Proposed when | Evidence cited |
|---|---|---|---|
| `block_swept_hash` | `block_hash` (`block_hash`) | the SHA-256 indicator is rated (preventive when no endpoint saw it) | the rating records and every hit record |
| `block_swept_domain` | `block_domain` (catalog order: native, Umbrella, Defender) | the domain indicator is rated | the same |
| `block_swept_ip` | `block_ip` (`block_ip`) | the IPv4 indicator is rated | the same |
| `block_swept_url` | `block_url` (`block_url`) | the URL indicator is rated | the same |
| `isolate_affected_endpoint_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`, `connector_guid` param) | the endpoint has a Secure Endpoint connector, isolation is not known to be impossible, and a rated file ran on it, or it reached a rated network indicator and shows malicious activity of its own | the execution events, the endpoint's own detections and malicious process events, its hit records of rated network indicators and the indicators' rating records |
| `isolate_affected_endpoint_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | the same, for an endpoint with a Defender machine id (a duplicate of the Secure Endpoint proposal is merged) | the same |
| `quarantine_swept_file` | `quarantine_file` (target `<ENDPOINT>/<sha256>`) | a rated file is present on the endpoint, not remediated and not deleted | the presence records (detections, prevalence, process events) and the hash's rating records |
| `quarantine_carrier_message` | `quarantine_email` (`quarantine_email`, `recipient` param for the Defender for Office 365 route) | the message is still delivered and carries a rated indicator | the message records and the rating records of its rated indicators |
| `revoke_sessions_signed_in_from_indicator` | `revoke_sessions` (`revoke_entra_sessions`) | an account signed in successfully from a rated IP indicator | the sign-in records and the IP's rating records |

An isolation that rests only on the execution of rated files passes those hashes as the rule's
`binaries`: when every one is sanctioned (allow-listed hash, approved tool hash or signer) the
runner withholds the isolation and shows it as considered. A session revocation passes the rated
IPs the account signed in from as the rule's `indicators`: when the allow-list excludes the block
of every one (the organisation's own infrastructure in `never_block.ips` or `never_block.cidrs`, or
a private, carrier-grade NAT or other non-public address), the revocation would rest only on the
organisation's own egress and hit every user behind it, so the runner withholds it and shows it as
considered. Allow-listed, internal and non-public
targets (an own domain, an internal address) are still built and shown as excluded with the
reason, never dropped.

### Hand-offs and items not proposed

- Not proposed, and listed as considered: an indicator rated SUSPICIOUS only (one vendor, for
  example a feed indicator only Cisco XDR knows), rated CLEAN (the feed is contradicted, also when a
  connection or DNS record of it carries a MALICIOUS verdict, or a record of a subdomain does) or
  unrated with hits; a session revocation that rests only on allow-listed or non-public addresses; an endpoint that only reached a rated network indicator (no rated file ran, no
  malicious activity of its own); a delivered message that carries only unrated indicators; an
  account with failed sign-ins only from a rated IP.
- Manual steps: blocking a rated sender address (no VERIFIED gateway sender-block write: add it to
  the Secure Email Threat Defense or Defender for Office 365 block list by hand; the delivered
  messages are in the package); an endpoint that should be isolated but whose agent policy forbids
  isolation, or that neither Secure Endpoint nor Defender manages.
- Hand-offs: `malware` (rated file hashes found on endpoints: process tree, origin, connections),
  `c2` (endpoints that reached a rated network indicator), `phishing` (mailboxes that received a
  delivered carrier message) and `account-takeover` (accounts that signed in from a rated IP).

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a
suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action in the package needs human approval before it runs: indicator blocks, isolation,
  file and message quarantine, session revocation (not reversible), and later every release. AI and
  automation principals can never approve, and nothing in the workflow can switch approval off.
- ELEVATED approval (a human holding the elevated approver role, for example the SOC lead) applies,
  with a visible warning on the decision card, when a target is a critical asset (for example a
  production server, a domain controller, a privileged or executive account or mailbox, also for
  the endpoint part of a file target) or when a blast-radius cap is exceeded (for example more than
  5 endpoints, 3 users or 50 indicators in one package). ELEVATED is decided by `PackageBuilder`
  from the investigated asset context; the workflow never sets it and a critical asset is never
  skipped silently.
- The analyst may approve all, approve a selection, reject, or ask for more investigation.

## Containment execution

After approval the orchestrator executes the approved actions automatically, through the guard and
the approval token, native first (Cisco XDR `respond/trigger` when `native_actions` is configured),
then directly:

| Action | Route with the real adapters |
|---|---|
| block hash | Defender indicators (VERIFIED) or the native action; Secure Endpoint file lists are UNVERIFIED and never called |
| block domain, URL | Umbrella destination lists (VERIFIED), Defender indicators (VERIFIED), or the native action |
| block IP | Meraki MX L3 rules or Defender indicators (VERIFIED), or the native action; direct Umbrella IP blocking is UNVERIFIED and never called |
| isolate endpoint | Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` (VERIFIED) or Defender `POST /api/machines/{id}/isolate` (VERIFIED), or the native action |
| quarantine file | no VERIFIED vendor endpoint: reported UNROUTED, with a manual step in the endpoint console |
| quarantine email | Secure Email `POST /v1/messages/move` (VERIFIED; the tenant's `quarantine_verdict` option) or Defender for Office 365 remediate (VERIFIED, needs the single `recipient`), or the native action |
| revoke sessions | Entra `POST /users/{id}/revokeSignInSessions` (VERIFIED) |

An UNROUTED action is listed on the decision card and in the notes for manual handling; it is never
dropped. Unlock codes for isolated endpoints stay in the vendor console and are never copied into
notes, notifications or reports.

## Verification

Verification is automatic after execution and reads the target state back: Umbrella destination
lists, Meraki rules and Secure Email message status are read back; Defender machine actions are
VERIFIED or NOT_VERIFIED; Secure Endpoint isolation, Defender indicators and Defender for Office 365
remediation are UNABLE_TO_VERIFY until their read endpoints are VERIFIED (docs/integrations.md
section 3). The result table shows every action with its execution and verification status
(SUCCESS, ALREADY_CONTAINED, FAILED, SKIPPED, REJECTED_BY_ANALYST).

## Rollback

Every reversible action registers a temporary control: isolation (release endpoint), hash, domain,
IP and URL blocks (unblock), file quarantine (restore file) and message quarantine (release email).
Session revocation is not reversible and registers no control. Restoration needs its own human
release approval of a release package built from the registry; closing the incident never removes a
control by itself. A review reminder per control type (`temporary_controls.review_after_hours`) is a
reminder only: removing a control always needs that separate approval.

## Failure handling

- A failed or degraded source (for example Secure Email unavailable or VirusTotal over quota) is
  listed as degraded, lowers confidence once, and never blocks a recommendation that other evidence
  supports (a Defender XDR mail row still names the carrier message when Secure Email fails).
- When a rating source fails and only one vendor still rates an indicator, the indicator is shown
  as considered, never blocked on that single word; asset actions that rest on the security
  products' own records still stand.
- A step, rule or hook that fails is noted and skipped; the rest of the run still recommends.
- A rule with no citable record proposes nothing (no invented evidence).
- An approved action that fails at the vendor is reported FAILED and never retried silently; the
  overall result is PARTIALLY_CONTAINED or CONTAINMENT_FAILED.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0002 Execution | T1204 User Execution | T1204.002 Malicious File | a swept file indicator that ran on an endpoint: isolates the endpoint, quarantines the file wherever it is present and blocks its hash |
| TA0001 Initial Access | T1566 Phishing | T1566.001 Spearphishing Attachment | quarantines a delivered message whose attachment hash is a swept indicator |
| TA0001 Initial Access | T1566 Phishing | T1566.002 Spearphishing Link | quarantines a delivered message that carries a swept URL or domain (or comes from a swept sender) and blocks the URL |
| TA0001 Initial Access | T1078 Valid Accounts | none | revokes the sessions of an account that signed in successfully from a swept IP and hands it to account-takeover |

The domain and IP blocks map to no technique: an indicator names infrastructure, not a behaviour,
and the sweep does not know which technique the infrastructure served (no forced mapping).

## Testing instructions

- Simulation scenarios: `tests/fixtures/workflows/threat-intel-sweep/` (the minimum set of 14.5.3
  and five edge cases: `edge-no-hits`, `edge-hits-over-indicator-cap`,
  `edge-single-vendor-contact-only`, `edge-contact-only-and-allowlisted`,
  `edge-defender-managed-endpoint`; no legacy scenarios, the workflow is new). They run
  automatically, in dry run and simulated live, in `tests/simulation/test_workflow_scenarios.py`.
- Unit, hook and lifecycle tests: `tests/workflows/threat_intel_sweep/`.
- Commands (from the repository root):
  - `python -m pytest -q -p no:cacheprovider tests/workflows/threat_intel_sweep tests/simulation/test_workflow_scenarios.py -k "threat-intel-sweep or threat_intel_sweep"`
  - `python tools/validation/check_workflow_readmes.py --workflow threat-intel-sweep`
  - `python tools/simulator/simulate.py --workflow threat-intel-sweep --scenario tp-approve-all --check` (add `--live` for the simulated live run)

## Known limitations

- The feed's own confidence is never evidence: an indicator only one vendor rates (a Cisco XDR
  private-intelligence verdict alone, for example) is shown as considered, never blocked.
- Secure Cloud Analytics has no VERIFIED API: its alerts reach the sweep only as Cisco XDR
  incidents and sightings; its flow records are not searched directly.
- Umbrella DNS activity and reporting reads are UNVERIFIED: Umbrella only rates domain indicators;
  DNS hits come from Cisco XDR sightings, Defender XDR hunting or Splunk.
- Secure Email Threat Defense search by sender, URL or attachment hash is not usable (search body
  fields undocumented) and Defender for Office 365 message search is UNVERIFIED: carrier messages
  are found from incident message ids, Cisco XDR sightings and Defender XDR hunting rows; a carrier
  nobody names is not found and the phishing hand-off covers the mailbox review.
- Real Cisco XDR sightings, Defender XDR hunting rows and Splunk rows have no documented field
  schema, so they stay generic records (citable, never scored) and cannot name an affected asset;
  until a schema is VERIFIED, asset actions rest on typed sources and the blocks follow enrichment.
- Blocking a sender address has no VERIFIED write: it is a manual step.
- Quarantine file has no VERIFIED vendor endpoint (UNROUTED with the real adapters, handled in the
  endpoint console); Secure Endpoint isolation verifies as UNABLE_TO_VERIFY.
- An endpoint that only reached a rated network indicator is not isolated (considered, handed to
  c2); an endpoint no agent can isolate is a manual step.
- At most 25 indicators of each type per run (the rest are noted as not queried); over the
  blast-radius caps every action of that kind needs ELEVATED approval.
- SHA-1, MD5, IPv6 and file-name indicators are not swept.
- A sweep looks back at most 30 days (720 hours).
- Third-party reputation is limited by the disclosure policy and the VirusTotal public quota.
