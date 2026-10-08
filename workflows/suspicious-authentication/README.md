# Suspicious authentication

Workflow id `suspicious-authentication`, version 1.0.0, Phase 4 (new; no legacy spec), default
severity MEDIUM. Definition: `src/xdr_response/workflows/suspicious_authentication/definition.py`;
indicator hooks: `src/xdr_response/workflows/suspicious_authentication/hooks.py`.

## Purpose

Respond to a sign-in that does not look like the account owner:

- an unusual country (the account's own 14-day baseline never shows it);
- a new, unregistered or non-compliant device, or a managed device that Intune reports non-compliant;
- an anonymising network (Tor, an open proxy, an anonymous VPN) where a source can tell;
- impossible travel (two countries within 120 minutes);
- an hour the account never signs in at;
- a source IP that reputation rates malicious or suspicious;
- credential exposure (the address in breach data, or a leaked-credentials detection).

The workflow investigates automatically and then **recommends** a containment package with numbered
evidence and separate risk and confidence scores:

- revoke the account's sign-in sessions;
- disable the account when the compromise went further;
- block the attacker source IP.

It never executes anything itself. Every action needs a human approval, and execution happens only
through the lifecycle orchestrator after that approval. A likely compromise is also handed off to
`account-takeover` (a suggestion; nothing is started).

## Trigger

Triggers of the definition (the incident re-read through the VERIFIED Cisco XDR APIs is the input;
see `tools/deployment/xdr-trigger-workflow.md`):

| Type | Matches | Priority |
|---|---|---|
| `xdr_incident_rule` | the title matches a suspicious-sign-in pattern (`*suspicious sign-in*`, `*suspicious login*`, `*suspicious authentication*`, `*unusual sign-in*`, `*anomalous sign-in*`, `*anonymous ip*`, `*tor exit*`, `*unmanaged device*`, `*non-compliant device*`, `*leaked credential*`, `*credential exposure*`, `*unusual location*`, `*new country*`, `*abnormal sign-in time*` and similar, case-insensitive) and the incident carries a `user` observable | 105 |
| `xdr_incident_rule` | the incident reports the valid-accounts technique (any sub-technique) and carries a `user` observable | 95 |
| `manual` | an analyst runs the workflow for an incident or a user pivot | n/a |

An incident whose `workflow_id` is `suspicious-authentication` always routes here. Routing between
overlapping identity workflows: mfa-fatigue (200) and password-spray (110) keep their incidents; the
title trigger (105) outranks account-takeover (100), which this workflow hands off to; account-takeover
keeps its cloud-account and stolen-session technique trigger (100) and its own title patterns (risky,
high-risk or unfamiliar sign-in, impossible or atypical travel, token replay), which this workflow does
not repeat. The technique trigger (95) catches valid-account incidents that account-takeover does not
claim.

## Required integrations

- `entra` (Microsoft Entra ID through Microsoft Graph): the user (`GET /users/{id}`, including
  `accountEnabled` and `signInSessionsValidFromDateTime`) and the sign-in logs
  (`GET /auditLogs/signIns`: country, city, app, device id, device compliance, conditional access and
  sign-in risk); it executes the approved `revoke_sessions` (`POST /users/{id}/revokeSignInSessions`)
  and `disable_user` (`PATCH /users/{id}` with `accountEnabled`), both VERIFIED. Read atomics:
  `investigate_user`, `investigate_authentication`, `search_user_activity`.
- `cisco_xdr`: verdicts for the sign-in source IPs and the account address (deliberate observables,
  VERIFIED) and enterprise sightings of the IPs; the native response route when the operator
  configured `native_actions`. Read atomics: `enrich_ip`, `enrich_email_address`,
  `search_ip_enterprise`.

A required integration that is disabled or failing never blocks a recommendation backed by other
evidence: the run notes it as a degraded source and confidence drops.

## Optional integrations

- `microsoft_cloud`: Defender XDR alerts (alerts_v2), including identity-protection alerts such as an
  anonymous-IP or leaked-credentials alert, for the account and the source IPs; hunting rows stay
  generic records.
- `intune`: compliance state and primary user of the managed device the incident names
  (`GET /deviceManagement/managedDevices/{id}`, VERIFIED); read only by the `managed_device` step.
- `defender_endpoint`: enterprise prevalence of the source IPs; executes an approved IP block as a
  Defender for Endpoint indicator.
- `hibp`: breaches for the account address (`GET /breachedaccount/{account}`, VERIFIED), only for
  addresses the disclosure policy allows; attribution "Have I Been Pwned (CC BY 4.0)" is kept in the
  evidence text.
- `virustotal`: second opinion on public sign-in source IPs (never non-public addresses).
- `alienvault_otx`: second opinion on public sign-in source IPs (never non-public addresses).
- `meraki`: executes the approved IP block as a tagged MX layer 3 firewall rule (no read atomic).

## Input data

- Incident observables: `user` (required in practice: the account), `email_address` (an address to
  check for exposure), `ip` / `ipv6` (the sign-in source the alert names) and `endpoint_id` (an Intune
  managed device id), plus the incident title, severity, creation time and trigger.
- Typed records returned by the read atomics: `user_profile` (groups, roles, privileged flag, risk,
  sessions valid from), `sign_in` (time, IP, country, city, app, device id, device compliance, result,
  risk), `anomaly` (vendor risk detections: impossible travel, unfamiliar location, new device,
  anonymous IP, malicious IP, leaked credentials and others), `detection` (identity-protection alerts),
  `mailbox_rule`, `role_change`, `cloud_app`, `endpoint` (Intune managed device), enterprise sightings
  of the IPs (other accounts' sign-ins, endpoint connections) and `enrichment` answers for IPs and
  the account address.
- Lab configuration only through the scenario `config` keys (critical assets, allow-lists,
  thresholds, exclusions). No input can carry an approval setting.

## Investigation steps

All steps are read-only atomics run through the read-only adapter facade, in this order. Values found
by earlier steps feed later default subjects.

1. `user_profile` (`investigate_user`, the incident's accounts): profile, groups, roles, privileged
   flag, risk state, sessions valid from, vendor detections.
2. `authentication` (`investigate_authentication`, lookback 336 hours): the account's sign-ins over
   14 days (the baseline and the recent sign-ins) and risk detections.
3. `post_sign_in_activity` (`search_user_activity`, lookback 72 hours): mailbox rules, role changes
   and application consents of the account.
4. `credential_exposure` (`enrich_email_address`, the email-shaped accounts and address observables):
   every enricher the disclosure policy allows; HIBP never receives an address of an internal domain
   or of `third_party_lookup.user_domains` (the source is then NOT_QUERIED with reason "disclosure
   policy").
5. `source_ip_reputation` (`enrich_ip`, incident IPs plus every sign-in IP): reputation from every
   enricher the disclosure policy allows; non-public addresses never leave the organisation.
6. `source_ip_prevalence` (`search_ip_enterprise`, lookback 168 hours): other accounts' sign-ins and
   internal endpoints that reach the same IPs (how a shared egress is recognised).
7. `managed_device` (`investigate_endpoint`, restricted to `intune`): the managed devices the incident
   names by id.

A failing step or source is noted and skipped; partial results stay.

## Correlation logic

Framework links (240-minute window): same IP, same user, and sign-in to later mailbox-rule, role or
app-consent activity. The hooks add `WORKFLOW` links from each account to the source IPs of its
suspicious sign-ins, citing those sign-ins.

The assessment, per account (constants in `hooks.py`):

1. **Recent and baseline.** Recent sign-ins are the successful sign-ins in the 24 hours before the
   incident (and any sign-in from an IP the incident names); older successful sign-ins are the
   baseline.
2. **Shared or internal egress.** A non-public source address, or a source that at least two other
   accounts sign in from successfully (or that internal endpoints reach) and that no source flags, is a
   shared egress: a sign-in through it never counts as an unusual country, travel or hour, and vendor
   location detections for it are not counted either. This is how a corporate VPN exit is told apart
   from a new country; the discount is listed as "considered" with the records that prove it.
3. **Indicator families and points.** Each family counts once with its strongest finding:

| Family | Finding | Points |
|---|---|---|
| source IP | a source rates the IP malicious (or a HIGH malicious-IP detection) / only suspicious | 2 / 1 |
| anonymising network | vendor anonymous-IP detection, Tor or proxy category, identity-protection alert / VPN category | 2 / 1 |
| impossible travel | two successful sign-ins from different countries within 120 minutes / a vendor detection | 2 / HIGH 2, else 1 |
| unusual country | a country the baseline never shows / a vendor unfamiliar-location detection | 1 / HIGH 2, else 1 |
| device | a new device id, an unregistered device when the baseline uses registered ones, a non-compliant device, or a non-compliant Intune device | 1 |
| hour | the sign-in hour is at least 4 hours (UTC) from every baseline hour (needs 3 baseline sign-ins) | 1 |
| identity risk | the identity provider rates the account high risk or confirmed compromised, or the sign-in risk is high / medium | 2 / 1 |
| vendor detection | another vendor risk detection (HIGH 2, else 1) | 1-2 |
| credential exposure | breach data (HIBP) or a leaked-credentials detection; never on its own | 1 |

4. **Likely compromise.** At least one recent successful sign-in, at least 3 points in all, and at
   least 2 of them from the sign-in itself (source IP, anonymising network, travel, country, device,
   hour). A vendor detection that names the IP of a failed attempt does not count for the account.
5. **Disable reasons** (only for a likely compromise): a privileged account (role, privileged flag or
   a privileged role granted), a suspicious sign-in after the sessions were last revoked, a confirmed
   compromise, or post-sign-in persistence from 10 minutes before the first suspicious sign-in (an
   external forwarding or delete mailbox rule, a privileged role grant, a flagged app consent).
6. **Block candidates.** A sign-in source of the recent window (successful or not) or an IP the
   incident names, that a source rates MALICIOUS or that a HIGH or CRITICAL anonymous or malicious IP
   detection names, and that is neither shared nor non-public.

## Risk calculation

The scoring engine computes risk and confidence separately from the records each rule cites. Sign-in
records give no framework signal, so the hooks derive authentication-anomaly signals that cite them:

| Finding | Verdict | Severity | Confidence |
|---|---|---|---|
| successful sign-in from an IP rated malicious / suspicious | MALICIOUS / SUSPICIOUS | 80 / 65 | 75 / 65 |
| successful sign-in through an anonymising network | SUSPICIOUS | 70 | 70 |
| impossible travel | SUSPICIOUS | 75 | 65 |
| unusual country | SUSPICIOUS | 50 | 60 |
| new, unregistered or non-compliant device | SUSPICIOUS | 50 | 60 |
| abnormal hour | SUSPICIOUS | 40 | 50 |
| suspicious sign-in after the sessions were revoked | MALICIOUS | 85 | 80 |
| source IP of a likely compromised account (block) | MALICIOUS or SUSPICIOUS | 60-80 | 70 |

Vendor detections, identity risk, post-sign-in persistence and the enrichment answers add their
framework signals; enrichment and HIBP are vendor verdicts (reputation, capped; breach data is
SUSPICIOUS at most). A critical asset adds the context bonus only with a supporting signal. Rule
thresholds: revoke and block need a risk of at least 50, disable at least 60; below that the action is
reported as BELOW_THRESHOLD ("considered, not proposed"), never hidden. With the lab data a typical
likely compromise scores risk 70-85 (HIGH) for the account.

## Containment recommendations

| Rule | Action (builder) | When | Evidence |
|---|---|---|---|
| `revoke_suspicious_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | the account is a likely compromise | the suspicious sign-ins, the baseline sign-ins a "new" claim rests on, the vendor detections, the flagged reputation answers, the HIBP answer, the Intune device and the profile |
| `disable_compromised_account` | `disable_user` (`disable_entra_user`) | a likely compromise with at least one disable reason | the above plus the records of each reason (profile, role change, later sign-in, mailbox rule, app consent) |
| `block_attacker_source_ip` | `block_ip` (`block_ip`) | a block candidate | the sign-ins and attempts from the IP, the vendor detections and the reputation answers |

Each action carries numbered evidence that cites real investigation and enrichment records, a
`risk_score` and a separate `confidence_score`, and a rationale with the indicators, the points and
the score explanation. Allow-listed targets are shown as excluded, never dropped.

### Hand-offs and items not proposed

- Hand-off to `account-takeover` for every likely compromised account: account-takeover reviews the
  wider activity, MFA methods and app consents.
- Considered, not proposed: an account with indicators below the threshold (or without a recent
  successful sign-in), with the indicators and points; a sign-in or detection discounted because it
  came through a shared or non-public egress; a malicious-rated IP that is shared or non-public.
- Manual steps: the password reset and MFA re-registration of a likely compromised account, and,
  for credential exposure without a suspicious sign-in, confirming that the password was changed
  after the breach (no VERIFIED write exists).

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a
suggestion only: it starts nothing and never changes the package.

## Approval requirements

- Every action needs human approval, including `revoke_sessions`. There is no automatic approval and no
  switch for it; AI and automation principals can never approve.
- ELEVATED approval (a lead with the elevated role) applies when a target is a critical asset: a
  privileged account (user pattern, group, directory role, the identity provider's privileged flag, or
  a privileged role granted during the incident), a break-glass or service account, an executive
  account, or an IP in a critical class. ELEVATED also applies over a blast-radius cap and for
  always-elevated actions. The action is never skipped: it stays in the package with a visible
  warning.
- The workflow only passes investigated asset context (groups, roles, privileged flag); the package
  builder decides the approval level and can never be made weaker.

## Containment execution

After the human approval the lifecycle orchestrator executes the approved actions automatically
inside the execution guard, with the approval token bound to the package. Routes in this workflow:
`revoke_sessions` and `disable_user` on `entra` (disable also has a native Cisco XDR route when
configured), `block_ip` on Meraki MX (L3 rule), a Defender for Endpoint indicator or the native Cisco
XDR action. Unselected actions are recorded as rejected by the analyst and never run. In dry run the
same package is rendered as a DRY RUN report and nothing changes.

## Verification

Verification is automatic after execution: `disable_user` re-reads `accountEnabled`;
`revoke_sessions` checks that `signInSessionsValidFromDateTime` is at or after the action time;
`block_ip` re-reads the MX L3 rule set (a Defender indicator stays UNABLE_TO_VERIFY until its read is
VERIFIED, which never counts as contained by default).

## Rollback

Restoration needs a separate human release approval; nothing is released automatically.

- `disable_user`: re-enable the account, only after the help desk has reset the password and
  re-registered MFA.
- `block_ip`: remove the tagged MX rule (or the indicator).
- `revoke_sessions`: not reversible (the user signs in again); it creates no temporary control.

Temporary controls carry review reminders (`temporary_controls.review_after_hours`); an
already-contained target creates no control, so a release never removes a block this incident did not
create.

## Failure handling

- A failed or degraded source (for example Cisco XDR enrichment being unavailable) never blocks a
  recommendation backed by other evidence; it is listed as degraded and lowers confidence.
- When the identity reads fail, an IP the incident names and a source rates malicious is still
  proposed for a block on its reputation; the account itself is then not assessed and the run notes
  the degraded source.
- A failing step, hook or rule expression is noted and skipped; the run still recommends what the
  rest of the evidence supports.
- An action with no executor is reported as UNROUTED for manual handling, never dropped.
- A failed execution is reported (partial containment), never retried silently.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why |
|---|---|---|---|
| TA0001 Initial Access | T1078 Valid Accounts | T1078.004 Cloud Accounts | a sign-in to the cloud identity with valid credentials that does not look like the owner |
| TA0011 Command and Control | T1090 Proxy | T1090.003 Multi-hop Proxy | a sign-in through Tor or an anonymising proxy chain; the package blocks the exit when a source rates it malicious |

No other technique is mapped. Credential exposure in breach data happens before the incident and
outside the organisation; the workflow uses it only as a supporting indicator and contains its use,
so no reconnaissance technique is mapped for it. Impossible travel, unusual hours and unmanaged
devices are detection analytics for valid-account use, not techniques of their own.

## Testing instructions

- Scenarios: `tests/fixtures/workflows/suspicious-authentication/` (the minimum set of 14.5.3 and the
  edge cases corporate VPN egress, impossible travel, credential exposure only, Tor failed attempts,
  and unmanaged device with leaked credentials). Every scenario runs in dry run and/or simulated live
  through the lifecycle orchestrator in `tests/simulation/test_workflow_scenarios.py`. There is no
  legacy spec, so there are no legacy scenarios.
- Unit and lifecycle tests: `tests/workflows/suspicious_authentication/`.
- Commands:

```
python -m pytest -q -p no:cacheprovider tests/workflows/suspicious_authentication tests/simulation/test_workflow_scenarios.py -k "suspicious-authentication or suspicious_authentication"
python tools/validation/check_workflow_readmes.py --workflow suspicious-authentication
python tools/simulator/simulate.py --workflow suspicious-authentication --scenario tp-approve-all --live --check
```

All test data is fake: documentation IP ranges, `example.com` users, hosts like `TH-LT-2044`.

## Known limitations

- The autonomous system (ASN) of a sign-in is not in the normalized sign-in record (the Entra
  normalizer does not map it), so an unusual ASN is not assessed; unusual geography is country-level
  only.
- Impossible travel is computed from countries and times only (two countries within 120 minutes); no
  distance or city coordinates are used, and a VPN exit that is neither shared nor allow-listed can
  look like travel. Vendor impossible-travel detections are used as reported.
- With the real Entra adapter, risk detections (riskDetections and riskyUser are UNVERIFIED), MFA
  detail and directory roles are not normalized; anonymising networks are then recognised only from
  Defender XDR alerts, reputation categories and the incident itself, and privileged accounts through
  the critical-asset patterns and groups.
- The baseline is the account's own successful sign-ins in the investigation lookback (14 days, at most
  100 records per source); without at least one older sign-in the country and device are not assessed,
  and without three the sign-in hour is not assessed (hours are compared in UTC).
- The shared-egress check needs typed enterprise sightings (other accounts' sign-ins or internal
  endpoints reaching the IP); Entra sign-ins by IP are not queryable through a VERIFIED filter and
  hunting rows stay generic, so list the corporate VPN egress in `allowlists.never_block` (and the VPN
  pool in `exclusions.third_party_lookup.cidrs`) so that a block of it is excluded and never executed.
- Sign-in device ids are Entra device ids and are not resolved to Intune managed devices; Intune is
  read only for a managed device id the incident names, and its compliance state is a supporting
  indicator.
- HIBP is queried only for addresses the disclosure policy allows (never internal domains or
  `third_party_lookup.user_domains`); breach data is credential exposure, never a recommendation on
  its own, and the password reset it calls for is a manual help-desk step (no VERIFIED write).
- Session revocation is not reversible, can take a few minutes and does not affect external (guest)
  users; MFA re-registration stays a manual help-desk step.
- Direct Umbrella IP blocking is UNVERIFIED; IP blocks route to Meraki MX, a Defender for Endpoint
  indicator or the native Cisco XDR action.
- Thresholds (24-hour recent window, 3 indicator points, 120-minute travel window, 4-hour hour gap)
  are fixed in the workflow hooks, not configurable per tenant.
