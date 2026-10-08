# Ransomware

Phase 2 workflow `ransomware` (version 2.0.0, default severity CRITICAL). Definition:
[`src/xdr_response/workflows/ransomware/definition.py`](../../src/xdr_response/workflows/ransomware/definition.py),
hooks: [`hooks.py`](../../src/xdr_response/workflows/ransomware/hooks.py). It replaces the legacy
specification of this directory (`legacy_id: ransomware`); the six legacy scenarios now live as
`legacy-*` fixtures under `tests/fixtures/workflows/ransomware/`.

## Purpose

Contain suspected ransomware quickly to limit encryption spread, then scope the affected hosts,
accounts, destinations and lateral targets. The workflow looks for mass file modification,
suspicious encryption, shadow-copy deletion (recovery inhibition), known ransomware executables and
simultaneous endpoint and network indicators.

Investigation and recommendation are automatic. The workflow only **recommends**: it never calls a
state-changing adapter method, never builds approval tokens and never enters a guard context. Every
recommended action waits for a human decision in the lifecycle orchestrator.

## Trigger

- **XDR incident rule** (priority 200): the incident reports ATT&CK technique T1486 or T1490 (or one
  of their sub-techniques) in `trigger.mitre_techniques`.
- **XDR incident rule** (priority 150): the incident title matches `*ransom*`,
  `*mass file modification*`, `*shadow cop*`, `*files encrypted*`, `*file encrypted*`,
  `*encrypted files*`, `*share encrypted*`, `*mass encryption*` or `*file encryption*`
  (case-insensitive). A title about an encrypted network channel ("Encrypted beaconing ...") does not
  match; it belongs to `c2` (T1573).
- **Manual**: an analyst starts the workflow for an incident (`incident.workflow_id: ransomware`).

The XDR trigger sends only the incident id; the incident is re-read through the VERIFIED APIs
(`tools/deployment/xdr-trigger-workflow.md`).

## Required integrations

These are the expected sources. When one is disabled or failing the run notes it and confidence
drops; it never blocks a recommendation that other evidence supports.

- `secure_endpoint`: endpoint context, detections and device trajectory of the affected hosts
  (`investigate_endpoint`); preferred isolation route.
- `entra`: user profile, risk state, sign-ins and risk detections (`investigate_user`,
  `investigate_authentication`); session revocation and account disable route.

## Optional integrations

- `defender_endpoint`: context of Defender-managed devices; Defender isolation route when the host is
  managed there; indicator route for hashes, domains, URLs and IPs.
- `cisco_xdr`: enterprise hash and domain search, enrichment and native response actions (native
  routes need operator-configured action ids).
- `microsoft_cloud`: Microsoft Defender XDR alerts (typed detections) and hunting searches for payload
  prevalence, related endpoints and DNS activity.
- `splunk`: enterprise searches for payload prevalence, related endpoints, DNS and authentication.
- `umbrella`: domain reputation; domain and URL block route.
- `meraki`: IP block route at the network edge.
- `secure_email`: originating message and campaign search; quarantine route.
- `defender_o365`: quarantine route for Microsoft 365 mailboxes.
- `virustotal`: second opinion on hash, domain, URL and IP reputation (the disclosure policy decides
  what may be sent).
- `alienvault_otx`: additional reputation for hashes, domains, URLs and IPs (disclosure policy applies).
- `secure_malware_analytics`: sandbox-backed domain reputation.

## Input data

Incident observables of these types: hostname, endpoint id, SHA-256, user, domain, URL, IPv4 address
and email message id; plus `incident.users`, the title, the source and the reported ATT&CK
techniques. Everything else is learned by the investigation: values found by one step feed the
next (for example the endpoints a payload search lists become payload hosts to investigate).

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues.

1. `affected_endpoints`: `investigate_endpoint` for every incident hostname and endpoint id
   (endpoint record, detections, trajectory, network connections, DNS).
2. `hash_reputation`: `enrich_hash` for incident hashes and hashes the endpoint records name.
3. `payload_prevalence`: `search_hash_enterprise` (72 hour lookback) for hashes rated malicious or
   suspicious, incident hashes and hashes a malicious detection or process event names.
4. `payload_hosts`: `investigate_endpoint` for the endpoints that hold a flagged hash seen on at
   most 50 endpoints (or with unknown prevalence).
5. `lateral_scope`: `search_related_endpoints` for every endpoint with a malicious detection or
   process event.
6. `lateral_targets`: `investigate_endpoint` for the related endpoints.
7. `users`: `investigate_user` for incident users and the accounts the endpoint records name (UPNs
   only).
8. `authentication`: `investigate_authentication` for those users.
9. `email_origin`: `investigate_email` for incident message ids.
10. `email_campaign`: `search_email_campaign` for those messages.
11. `domain_reputation`: `enrich_domain` for incident domains and domains in DNS, connection and
    message records.
12. `url_reputation`: `enrich_url` for incident URLs and URLs in connection and message records.
13. `ip_reputation`: `enrich_ip` for incident IPv4 addresses and outbound remote addresses.
14. `domain_scope`: `search_domain_enterprise` for domains rated malicious or suspicious (other
    endpoints that resolved them).

## Correlation logic

The framework link rules run over every record of the run within 60 minutes: the same hash, domain,
IP or URL on two or more endpoints or users (payload spread, simultaneous network indicators), the
same user on several endpoints, process lineage on one endpoint, a delivered message followed by a
click, and campaign messages. The blast radius covers the incident clusters.

The workflow hooks (pure, no adapter access) derive these facts, each mapped to the record ids it
was computed from:

- **affected hosts**: a malicious detection, a malicious process event, execution of an
  intel-confirmed payload, or vendor-flagged mass file modification (100 or more file events of one
  process) together with vendor-flagged recovery inhibition (a recovery tool event or a detection
  naming shadow copies, recovery or the backup catalog) on the same host;
- **payload hosts**: endpoints holding a spreading payload (intel-confirmed, or named by a malicious
  detection) seen on at most 50 endpoints;
- **affected users** (accounts the records place on an affected host) and **compromised users**
  (confirmed compromised, or high risk with at least one risk detection);
- **blockable destinations**: domains, URLs and IPs rated malicious or suspicious that an affected
  or payload host contacted, a malicious delivered message carried, or the incident lists;
- **lateral targets**: related endpoints without ransomware activity of their own (scoped, not
  isolated); **widespread hashes** (more than 50 endpoints) left to the approver.

## Risk calculation

Each recommended target is scored from the records its rule cites (separate `risk_score` and
`confidence_score`, 0-100). Endpoint detections and vendor-flagged process events dominate. The
hooks add three record-backed signals: encryption with recovery inhibition (endpoint detection,
MALICIOUS, severity 90), payload spread to two or more hosts (lateral movement, SUSPICIOUS,
severity 70) and a flagged destination contacted by an affected host (network behaviour, SUSPICIOUS,
severity 60). The engine caps reputation at 50, caps a single source below CRITICAL unless it is a
MALICIOUS behavioural detection, adds the corroboration and critical-asset bonuses and lowers
confidence for failed expected sources. Default category weights. The package shows the highest
risk and the mean confidence; every rationale ends with the score explanation and settings hash.

## Containment recommendations

| Rule | Action (builder) | When | Min risk |
|---|---|---|---|
| `isolate_affected_hosts` | `isolate_endpoint` (`isolate_secure_endpoint`) | affected host, isolation not forbidden, known to Secure Endpoint (or not to Defender) | 60 |
| `isolate_payload_hosts` | `isolate_endpoint` (`isolate_secure_endpoint`) | payload host, same route conditions | 60 |
| `isolate_defender_hosts` | `isolate_endpoint` (`isolate_defender_endpoint`) | affected or payload host managed by Defender for Endpoint | 60 |
| `block_payload_hash` | `block_hash` (`block_hash`) | payload hash confirmed by reputation, not widespread | 60 |
| `block_destination_domains` | `block_domain` (`block_domain_umbrella`) | blockable domain | 50 |
| `block_destination_urls` | `block_url` (`block_url`) | blockable URL | 50 |
| `block_destination_ips` | `block_ip` (`block_ip`) | blockable IP | 50 |
| `revoke_affected_user_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | affected or compromised account | 60 |
| `disable_compromised_users` | `disable_user` (`disable_entra_user`) | compromised account | 60 |
| `quarantine_originating_campaign` | `quarantine_email` (`quarantine_email`) | originating or campaign message rated malicious or suspicious, still delivered | 60 |

A second rule for the same action and target merges its evidence into the first (one action per
target). Below its minimum risk an action is listed as "considered, not proposed", never hidden.
Every action carries numbered evidence that cites records of the run. Allow-listed targets are shown
as excluded with the reason, never silently dropped.

### Hand-offs and items not proposed

- Not proposed, and listed as considered: a host whose endpoint policy does not allow isolation (contain it by hand), a payload hash seen on more than 50 endpoints (a human decides on a fleet-wide block), and a hash named by a detection that no source rates.
- Hand-offs: none.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed", "Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

Every action needs human approval before it runs, including session revocation; there is no
automatic approval and no score can skip it. AI and automation principals can never approve.
ELEVATED approval (a lead with the elevated approver role) applies when a target is a critical
asset (for example a domain controller, hypervisor, production server or privileged account, by
host pattern, group, tag, role or address range), when an action type is always elevated, or when
a blast-radius cap is exceeded (for example more than five isolations in one package). The
decision card shows the ELEVATED warning with the asset, role and potential impact; a critical
asset is never skipped silently. The analyst may approve all, approve a selection or reject.

## Containment execution

After approval the lifecycle orchestrator executes the approved actions automatically through the
execution guard, on the routes chosen at recommendation time (native Cisco XDR response first when
configured, else the product adapter). Rejected or unselected actions are recorded as rejected by
the analyst and never run. Dry run (the default) simulates the package and changes nothing.

## Verification

Every executed action is verified automatically by reading the target state back. Defender
isolation, Umbrella destination lists, Meraki firewall rules, Entra account state and Secure Email
moves are verifiable. Secure Endpoint isolation reports `UNABLE_TO_VERIFY` until its isolation-state
read is verified (docs/integrations.md), and Microsoft 365 email remediation cannot be read back
either; the result says so and the analyst checks the console.

## Rollback

Isolation, hash, domain, URL and IP blocks, account disable and quarantine are temporary controls in
the restoration registry. Removing them needs a separate human release approval (release endpoint,
unblock, enable user, release email); nothing expires on its own. Session revocation is not
reversible: the user signs in again. Isolation release codes are never copied into notes or
notifications; they stay in the vendor console.

## Failure handling

- A failed or disabled source becomes a degraded source in the notes and lowers confidence; the
  recommendation stands on the remaining evidence (for example sessions are still revoked from the
  Secure Endpoint records when Entra is unavailable).
- A step whose expression or atomic fails is noted and skipped; partial results stay.
- An action without an executable route is reported as unrouted for manual handling.
- A failed execution is reported as FAILED (partial containment), never retried silently; the other
  approved actions still run.

## MITRE mapping

| Tactic | Technique | Sub-technique | Rules | Why |
|---|---|---|---|---|
| TA0040 Impact | T1486 Data Encrypted for Impact | none | isolation, hash block | flagged mass file modification and encryption |
| TA0040 Impact | T1490 Inhibit System Recovery | none | isolation | flagged shadow-copy, backup-catalog or boot-recovery tampering |
| TA0008 Lateral Movement | T1570 Lateral Tool Transfer | none | payload host isolation | the same low-prevalence payload staged on further endpoints |
| TA0011 Command and Control | T1071 Application Layer Protocol | none | destination blocks | affected hosts contacted destinations rated malicious |
| TA0001 Initial Access | T1078 Valid Accounts | none | session revocation, account disable | accounts on affected hosts or confirmed compromised |
| TA0001 Initial Access | T1566 Phishing | none | campaign quarantine | the originating message and its campaign |

No sub-technique is mapped: the records do not distinguish them (protocol, account type, delivery
form), so none is forced.

## Testing instructions

- Scenarios (format of architecture 14.5.2): `tests/fixtures/workflows/ransomware/`, the minimum set
  of 14.5.3, six edge cases and the six migrated `legacy-*` scenarios. They run automatically in
  dry run and simulated live through the orchestrator:
  `python -m pytest -q -p no:cacheprovider tests/simulation/test_workflow_scenarios.py -k ransomware`.
- Unit tests of the definition, rules and hooks: `tests/workflows/ransomware/`
  (`python -m pytest -q -p no:cacheprovider tests/workflows/ransomware`).
- One scenario by hand: `python tools/simulator/simulate.py --workflow ransomware --scenario tp-approve-all --check`
  (add `--live` for the simulated live run).
- README check: `python tools/validation/check_workflow_readmes.py --workflow ransomware`.

## Known limitations

- Real Secure Endpoint trajectory events stay generic records (no event field schema is verified),
  so behavioural evidence (mass file modification, recovery inhibition) comes from typed detections,
  for example Microsoft Defender XDR alerts, until the event schema is verified.
- A host whose connector policy forbids isolation, a malicious hash seen on more than 50 endpoints
  and a hash without a reputation verdict are not recommended; they are listed as considered (run
  notes and analyst summary, with their records), and the analyst contains them by hand if needed.
- Email origin is investigated only when the incident or a record carries a message id; mailboxes
  are not searched by payload hash.
- Lateral targets are scoped but isolated only with ransomware activity or the payload of their own;
  a file server encrypted remotely over a share is not isolated.
- Service Stop from the legacy specification is not mapped: no record kind carries service-stop
  evidence.
- Secure Endpoint hash blocking is UNVERIFIED, so a hash block routes through Defender for Endpoint
  indicators or a configured Cisco XDR native action; a tenant whose only executor is Cisco XDR
  native response needs product-pinned builders, and such actions are reported as unrouted for
  manual handling.
