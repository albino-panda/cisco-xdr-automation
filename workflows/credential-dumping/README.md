# Credential dumping

Phase 3 workflow `credential-dumping` (definition version 3.0.0). Code:
`src/xdr_response/workflows/credential_dumping/` (`definition.py`, `hooks.py`). It replaces the legacy
plan-rule spec (`workflow.yaml` and its five scenarios), which were migrated to typed simulation
scenarios and deleted. The binding design is [docs/architecture.md](../../docs/architecture.md)
sections 12 to 14.

## Purpose

Respond to credential dumping on an endpoint: LSASS memory access, SAM access, NTDS (Active
Directory database) activity, a credential-dumping tool detection, or suspicious access to credential
memory. The workflow automatically investigates the endpoints, the tool's file reputation and
prevalence, the other endpoints that hold the same tool, and the accounts whose credentials were
cached or used on an affected endpoint. It then **recommends** a containment package with numbered
evidence and separate risk and confidence scores:

- isolate every endpoint where credential access is confirmed;
- revoke the sign-in sessions of every exposed account;
- disable an exposed account where that is justified: the account is privileged, or the identity
  provider confirms it compromised;
- block the credential-dumping tool's hash (rare, malicious files only).

A domain controller is always contained under ELEVATED approval with a visible warning, and the
domain-wide credential reset after an NTDS exposure is a manual step for the incident commander.

The workflow never executes, approves or chooses an approval level. A human approves the package;
only then does the lifecycle orchestrator execute, verify and (after a separate human release
approval) restore.

Default severity: CRITICAL. Related workflows: [account-takeover](../account-takeover/README.md),
[lateral-movement](../lateral-movement/README.md),
[privilege-escalation](../privilege-escalation/README.md), [malware](../malware/README.md).

## Trigger

| Type | Matches | Priority |
|---|---|---|
| XDR incident rule | the incident reports ATT&CK technique T1003 or one of its sub-techniques (a reported sub-technique matches the listed parent) | 150 |
| XDR incident rule | the title matches `*credential dump*`, `*credential theft*`, `*lsass*`, `*ntds*`, `*security account manager*` or `*directory database*` **and** the incident carries a hostname or an endpoint id | 120 |
| Manual | an analyst starts the workflow for an incident or an endpoint (never matches automatically) | n/a |

An incident whose `workflow_id` is `credential-dumping` always runs this workflow. When several
workflows match, the highest priority wins (ransomware, 200, and lateral-movement, 160, which hands
credential access off to this workflow, stay above it), then the workflow id. The trigger payload is the incident id only; the incident is re-read through the
VERIFIED Cisco XDR APIs.

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence
drops, but a recommendation backed by other evidence is still made.

- `secure_endpoint`: endpoint context (logged-on users, groups, isolation capability), detections and
  device trajectory of the affected endpoints, hash prevalence, and the isolation route
  (`investigate_endpoint`, `search_hash_enterprise`). With the real adapter the computer and
  trajectory reads are VERIFIED; enterprise hash search comes from Cisco XDR or Defender in
  production and from typed records in the simulated lab.
- `entra`: profiles, directory roles and risk state of the exposed accounts (`investigate_user`);
  executes the approved session revocation and account disable (both VERIFIED Graph writes).

## Optional integrations

- `defender_endpoint`: second endpoint source (machine, alerts, timeline) and the isolation or
  hash-indicator route for the endpoints it manages.
- `microsoft_cloud`: Microsoft Defender XDR alerts (typed detections) and hunting searches for the
  endpoints, the tool's prevalence and the exposed accounts.
- `cisco_xdr`: platform verdicts and sightings for the endpoints and the tool hash, and the native
  response actions (`respond/observables`, `respond/trigger`) the router prefers when configured.
- `virustotal`: public file reputation of the tool hash (disclosure policy applies).
- `alienvault_otx`: independent file reputation (OTX pulses) of the tool hash (disclosure policy
  applies).

## Input data

Incident observables of type `hostname`, `endpoint_id`, `sha256` and `user`, the incident users, and
`trigger.mitre_techniques` / `trigger.source` / the title for routing. Values found by earlier steps
feed later steps: hashes named by detections are enriched and scoped, endpoints that hold a rare
malicious tool are investigated, and the accounts the endpoint records place on an endpoint are
investigated. The legacy `incident.context.logged_on_users` is replaced by the endpoint record's
`users` (logged-on or recent users) and the users of detections and process events. All test data is
fake.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues.

| # | Step | Atomic | Subjects | Sources |
|---|---|---|---|---|
| 1 | `endpoint_triage` | `investigate_endpoint` | incident hostnames and endpoint ids | Secure Endpoint, Defender, Microsoft Defender XDR, Cisco XDR |
| 2 | `tool_reputation` | `enrich_hash` | incident hashes, hashes named by detections and by flagged process events (at most 10) | every enricher, disclosure policy applies |
| 3 | `tool_prevalence` | `search_hash_enterprise` | the same hashes, 72 hours | Secure Endpoint, Defender, Microsoft Defender XDR, Cisco XDR |
| 4 | `affected_endpoints` | `investigate_endpoint` | endpoints that hold a malicious tool seen on 10 endpoints or fewer, and endpoints named by detections | the same endpoint sources |
| 5 | `exposed_accounts` | `investigate_user` | the incident users and every directory account (UPN) an endpoint, detection or process event names | Entra, Microsoft Defender XDR |

The hooks (`hooks.py`) then derive facts from the run's own records, each with the record ids it was
computed from:

- **Credential behaviour** of a detection or process event: from the vendor-reported ATT&CK ids
  (T1003, T1003.001, T1003.002, T1003.003) and from the vendor's name, category, process name or file
  path (LSASS; SAM or Security Account Manager; NTDS or directory database; credential).
- **Confirmed credential access** on an endpoint: a MALICIOUS credential-related detection, a
  MALICIOUS credential-related process event, or a tool file with a malicious file reputation
  (aggregate enrichment MALICIOUS, or the endpoint product's file disposition MALICIOUS) seen on the
  endpoint. A widespread file confirms access only where a credential-related record names it.
  SUSPICIOUS or unknown activity alone is never confirmation.
- **Exposed accounts**: the directory accounts a record places on a confirmed endpoint.
- **Domain controller**: the endpoint matches the domain-controller critical-asset class, or NTDS
  access is shown.

## Correlation logic

- Framework links: the same tool hash on two or more endpoints or users; the same account on several
  endpoints; the same endpoint reported with several accounts; parent/child process lineage on one
  endpoint. Window 120 minutes.
- Workflow links (hooks, kind `workflow`): credential exposure, which ties an endpoint where credential
  access is confirmed to every account a record places on it.
- Links shape the clusters, the blast radius and the decision card. They are never evidence on their
  own and never change an approval level.

## Risk calculation

Each target is scored by the scoring engine (docs/threat-scoring.md) from the records its rule cites
plus the target's enrichment:

- credential-related endpoint detections and vendor-flagged process events: `endpoint_detection`
  (weight 1.0);
- a hash prevalence record marked malicious: `endpoint_detection`;
- Entra risk detections and a high user risk: `authentication_anomaly`;
- VirusTotal, OTX and Cisco XDR file answers: vendor reputation, capped by the engine; one vendor
  alone is never an aggregate MALICIOUS verdict;
- a critical asset adds the engine's critical-asset bonus (only with malicious evidence).

An account's revocation and disable cite the endpoint evidence that exposed it, so their risk follows
the confirmed credential access. Risk and confidence are separate integers. Expected sources are
Secure Endpoint and Entra: a failed one costs confidence once and is listed as degraded. Rule
thresholds (below them the action is "considered, not proposed" and listed in the notes, never
hidden): isolation and disable risk 60, revocation and hash block risk 50.

## Containment recommendations

| Rule | Action (builder) | Proposed when | Evidence cited |
|---|---|---|---|
| `isolate_credential_host_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`, `connector_guid` param) | credential access is confirmed on the endpoint, it has a Secure Endpoint connector and isolation is not known to be impossible | the confirming detections, process events, tool prevalence and malicious enrichment, plus the endpoint records |
| `isolate_credential_host_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | the same, for an endpoint with a Defender machine id (a duplicate of the Secure Endpoint proposal is merged) | the same |
| `revoke_exposed_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | a record places the account on an endpoint where credential access is confirmed | the endpoint evidence and the records that place the account on the endpoint |
| `disable_exposed_account` | `disable_user` (`disable_entra_user`) | the exposed account is privileged (profile flag, a privileged directory role, a privileged role assigned or activated during the incident, or the privileged-account policy) or confirmed compromised (risk state, or high risk with a risk detection) | the revocation evidence plus the account's profile (and risk detections) |
| `block_credential_tool_hash` | `block_hash` | the tool's file reputation is malicious, no source rates it CLEAN, and it is seen on 10 endpoints or fewer (or its prevalence is unknown) | prevalence records, malicious enrichment, the flagged detections and events naming it |

Allow-listed targets (for example a break-glass account in `allowlists.never_block.users`) are still
built and shown as excluded with the reason, never dropped. A hash signed by an approved tool's signer
is withheld by the runner and shown as considered.

### Hand-offs and items not proposed

- Not proposed, and listed as considered: credential activity that is not confirmed (SUSPICIOUS or
  unknown) or rated CLEAN by the endpoint product; a confirmed endpoint whose connector policy forbids
  isolation or that neither Secure Endpoint nor Defender knows; a tool hash seen on more than 10
  endpoints, rated CLEAN, with conflicting verdicts, without a file reputation, or named only by a
  behaviour detection (often a misused system binary); a disable that cannot be assessed because the
  identity source failed.
- Manual steps (no VERIFIED automated action, never in the package): `credential-reset:<endpoint>`
  (reset the credentials of the accounts exposed there, privileged and service accounts first, rotate
  the endpoint's local administrator credential and service secrets, review MFA methods, rebuild the
  endpoint before release) and, for a domain controller, `domain-credential-reset:<endpoint>` (the
  incident commander owns the domain-wide reset, including the Kerberos ticket-granting account,
  twice).
- Hand-offs: `account-takeover` for the exposed accounts (review their sign-ins, MFA and cloud
  activity for use of the stolen credentials).

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a
suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

Phase 3 review of the legacy rule "no account action when a protected domain controller is
confirmed": the accounts signed in on a domain controller are still exposed, so their revocation (and
disable when justified) is proposed like anywhere else, never silently skipped; privileged accounts
and the domain controller need ELEVATED approval, and the domain-wide reset is the manual step above.

## Approval requirements

- Every action in the package needs human approval before it runs: isolation, session revocation,
  account disable, hash block, and later every release. AI and automation principals can never
  approve, and nothing in the workflow can switch approval off.
- ELEVATED approval (a human holding the elevated approver role, for example the SOC lead or the
  incident commander) applies, with a visible warning on the decision card, when a target is a
  critical asset: a domain controller, identity infrastructure or another critical endpoint, or a
  privileged, service or break-glass account (by user pattern, group or directory role). It also
  applies when a blast-radius cap is exceeded (for example more than 3 users or 5 endpoints). ELEVATED
  is decided by `PackageBuilder` from the investigated asset context; the workflow never sets it and
  a critical asset is never skipped silently.
- The analyst may approve all, approve a selection, reject, or ask for more investigation.

## Containment execution

After approval the orchestrator executes the approved actions automatically, through the guard and
the approval token, native first (Cisco XDR `respond/trigger` when `native_actions` is configured),
then directly:

| Action | Route with the real adapters |
|---|---|
| isolate endpoint | Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` (VERIFIED) or Defender `POST /api/machines/{id}/isolate` (VERIFIED), or the native action |
| revoke sessions | Entra `POST /users/{id}/revokeSignInSessions` (VERIFIED; not reversible) |
| disable user | Entra `PATCH /users/{id}` with `accountEnabled: false` (VERIFIED), or the native action |
| block hash | Defender indicator (VERIFIED) or the native "Block File Hashes" action; Secure Endpoint file lists are UNVERIFIED and never called |
| credential reset | no VERIFIED automated action: manual step |

An UNROUTED action is listed on the decision card and in the notes for manual handling; it is never
dropped. Unlock codes for isolated endpoints stay in the Secure Endpoint console and are never copied
into notes, notifications or reports.

## Verification

Verification is automatic after execution and reads the target state back: Entra `accountEnabled`
and `signInSessionsValidFromDateTime` are VERIFIED reads; Defender machine actions are VERIFIED or
NOT_VERIFIED; Secure Endpoint isolation and Defender indicators are UNABLE_TO_VERIFY until their read
endpoints are VERIFIED (docs/integrations.md section 3). The result table shows every action with its
execution and verification status (SUCCESS, ALREADY_CONTAINED, FAILED, SKIPPED, REJECTED_BY_ANALYST).

## Rollback

Isolation (release endpoint), the account disable (re-enable user) and the hash block (unblock)
register a temporary control. Session revocation is not reversible and registers no control: the
user signs in again, after the credential reset. Restoration needs its own human release approval of
a release package built from the registry; re-enable an account only after its credential reset and
an MFA method review, and release an endpoint only after it was rebuilt. Closing the incident never
removes a control by itself.

## Failure handling

- A failed or degraded source is listed as degraded, lowers confidence once, and never blocks a
  recommendation that other evidence supports. When Entra fails, the endpoint containment, the hash
  block and the revocations are still proposed from the endpoint evidence; the disables that cannot
  be assessed are listed as considered.
- A step, rule or hook that fails is noted and skipped; the rest of the run still recommends.
- A rule with no citable record proposes nothing (no invented evidence).
- An approved action that fails at the vendor is reported FAILED and never retried silently; the
  overall result is PARTIALLY_CONTAINED or CONTAINMENT_FAILED.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0006 Credential Access | T1003 OS Credential Dumping | none | a credential-dumping tool detection or suspicious access to credential memory whose records do not show the method |
| TA0006 Credential Access | T1003 OS Credential Dumping | T1003.001 LSASS Memory | LSASS memory holds the credentials of the accounts signed in to the endpoint; those accounts are treated as exposed |
| TA0006 Credential Access | T1003 OS Credential Dumping | T1003.002 Security Account Manager | the SAM hive holds local account credentials; the endpoint is isolated and its local credentials reset by hand |
| TA0006 Credential Access | T1003 OS Credential Dumping | T1003.003 NTDS | the Active Directory database exposes every domain credential; the domain controller is isolated under ELEVATED approval and the domain-wide reset is a manual step |

No other technique is mapped: the workflow does not respond to anything else by design (use of the
stolen credentials afterwards is handed off).

## Testing instructions

- Simulation scenarios: `tests/fixtures/workflows/credential-dumping/` (the minimum set of 14.5.3,
  five edge cases: domain controller NTDS, misused built-in tool, suspected but not confirmed access,
  account confirmed compromised, Defender-managed endpoint; and the five migrated legacy scenarios
  `legacy-01` to `legacy-05`).
  They run automatically, in dry run and simulated live, in
  `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/credential_dumping/`.
- Commands (from the repository root):
  - `python -m pytest -q -p no:cacheprovider tests/workflows/credential_dumping tests/simulation/test_workflow_scenarios.py -k "credential-dumping or credential_dumping"`
  - `python tools/validation/check_workflow_readmes.py --workflow credential-dumping`
  - `python tools/simulator/simulate.py --workflow credential-dumping --scenario tp-approve-all --check` (add `--live` for the simulated live run)

## Known limitations

- Credential access is recognised from vendor-reported ATT&CK ids (T1003 family) and from detection or
  process names and categories (LSASS, SAM, NTDS, directory database, credential); a vendor detection
  that names none of these is not treated as credential dumping.
- Real Secure Endpoint trajectory events have no documented field schema, so they stay generic
  records (citable, never scored); confirmation then comes from typed detections (for example
  Microsoft Defender XDR alerts) or the tool's file reputation.
- Exposed accounts are the directory accounts (UPNs) a record places on an affected endpoint. Local
  and down-level accounts and the endpoint's local administrator credential are covered only by the
  manual credential-reset step.
- Credential reset, service-account secret rotation and the domain-wide reset after a domain
  controller is affected (including the Kerberos ticket-granting account, twice) have no VERIFIED
  automated action; they are manual steps owned by the incident commander and never in the package.
- An account is disabled only when the identity provider shows it privileged or confirms it
  compromised; when the identity source fails, the disable is listed as considered and only the
  revocation is proposed.
- Session revocation is not reversible, can take a few minutes and does not reach on-premises
  Kerberos tickets or external (guest) users.
- A tool hash seen on more than 10 endpoints, a hash named only by a behaviour detection (often a
  misused system binary) and a hash rated clean are never blocked; they are listed as considered.
- Secure Endpoint hash blocking and its isolation-state read are UNVERIFIED: hash blocks use the native
  action or Defender indicators, and Secure Endpoint isolation verifies as UNABLE_TO_VERIFY.
- An endpoint known to neither Secure Endpoint nor Defender, or whose connector policy forbids
  isolation, is not proposed for isolation; it is listed as considered.
