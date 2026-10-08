# MFA fatigue

Workflow id `mfa-fatigue`, version 1.0.0, Phase 2, default severity HIGH. Definition:
`src/xdr_response/workflows/mfa_fatigue/definition.py`; pattern hooks:
`src/xdr_response/workflows/mfa_fatigue/hooks.py`. Seeded from the legacy account-takeover scenario
`05-mfa-fatigue-approved`, which is migrated here as `legacy-05-mfa-fatigue-approved`.

## Purpose

Respond to MFA fatigue (also called push bombing or push spam): an attacker who already holds a
user's password requests MFA prompts again and again until the user, tired or confused, approves
one; the attacker then signs in with that approval.

The workflow investigates automatically: the user, the source IPs of the prompts (location and
reputation), the device and endpoint, and what the session did after the approval. It then
**recommends** a containment package with numbered evidence and separate risk and confidence
scores:

- revoke the user's sign-in sessions;
- disable the account when the compromise went further;
- isolate a compromised endpoint;
- block the prompt source IP and any malicious IP the session signed in from.

It never executes anything itself. Every action needs a human approval, and execution happens only
through the lifecycle orchestrator after that approval.

## Trigger

Triggers of the definition (the incident re-read through the VERIFIED Cisco XDR APIs is the input;
see `tools/deployment/xdr-trigger-workflow.md`):

| Type | Matches | Priority |
|---|---|---|
| `xdr_incident_rule` | the incident reports ATT&CK technique T1621 (or a sub-technique of it) and carries a `user` observable | 200 |
| `xdr_incident_rule` | the incident title matches `*mfa fatigue*`, `*mfa push*`, `*push bombing*`, `*push spam*`, `*mfa bombing*` or `*mfa spam*` (case-insensitive) | 200 |
| `manual` | an analyst runs the workflow for an incident or a user observable | n/a |

An incident whose `workflow_id` is `mfa-fatigue` always routes here. Priority 200 makes an
MFA-fatigue incident come here rather than to the broader account-takeover workflow when both
match. Typical sources are an Entra ID Protection MFA-fatigue risk detection, a SIEM correlation
search or a Cisco XDR incident rule.

## Required integrations

- `entra` (Microsoft Entra ID through Microsoft Graph): sign-ins (`GET /auditLogs/signIns`), the
  user and roles (`GET /users/{id}`), post-authentication activity; it also executes the approved
  `revoke_sessions` (`POST /users/{id}/revokeSignInSessions`) and `disable_user`
  (`PATCH /users/{id}` with `accountEnabled`), both VERIFIED in `docs/integrations.md`. Read atomics:
  `investigate_authentication`, `investigate_user`, `search_user_activity`.

A required integration that is disabled or failing never blocks a recommendation backed by other
evidence: the run notes it and confidence drops.

## Optional integrations

- `microsoft_cloud`: Defender XDR alerts (alerts_v2) on the user, the source IP and the endpoint.
- `splunk`: SIEM sign-in, activity and IP rows; cited as generic records, never scored.
- `cisco_xdr`: incident context, IP reputation and sightings; the native response route when the
  operator configured `native_actions`.
- `virustotal`: third-party IP reputation, public addresses only (disclosure policy).
- `alienvault_otx`: third-party IP reputation, public addresses only (disclosure policy).
- `secure_endpoint`: detections and trajectory of the user's device; executes an approved isolation.
- `defender_endpoint`: alerts and timeline of the user's device; executes an approved isolation.
- `meraki`: executes an approved `block_ip` as a tagged MX L3 firewall rule (no read atomic).

## Input data

- Incident observables of type `user` (required in practice: the fatigued account), `ip` (prompt
  source or sign-in IP) and `hostname` (the user's device), plus the incident title, severity and
  trigger (ATT&CK techniques, source).
- Typed records returned by the read atomics: `mfa_event` (method, result, IP, country, app),
  `sign_in` (result, IP, location, app, device, MFA result, risk), `user_profile` (groups, roles,
  risk state, sessions valid from), `anomaly` (vendor risk detections such as `mfa_fatigue`),
  `mailbox_rule`, `role_change`, `cloud_app`, `endpoint`, `detection`, `process_event`,
  `network_connection`, and `enrichment` answers for IPs.
- Lab configuration only through the scenario `config` keys (critical assets, allow-lists,
  thresholds, exclusions). No input can carry an approval setting.

## Investigation steps

All steps are read-only atomics run through the read-only adapter facade, in this order. Values
found by earlier steps feed later default subjects.

1. `authentication` (`investigate_authentication`, the incident users): MFA prompts and their
   results, sign-ins, counts of successes, failures, denials and approvals, distinct IPs and
   countries.
2. `user_profile` (`investigate_user`): department, groups, directory roles, privileged flag,
   account state, identity-provider risk, sessions valid from, vendor anomalies.
3. `post_authentication_activity` (`search_user_activity`): mailbox rules, role changes and
   application consents of the user.
4. `source_ip_reputation` (`enrich_ip`, incident IPs plus every IP seen in sign-ins and prompts):
   reputation from every enricher the disclosure policy allows.
5. `source_ip_activity` (`investigate_ip`): other sign-ins, connections and endpoints that touched
   those IPs (this is how an endpoint talking to the prompt source is found).
6. `endpoint` (`investigate_endpoint`, incident hostnames plus endpoints found above): detections,
   process events, connections, groups and tags.

A failing step or source is noted and skipped; partial results stay.

## Correlation logic

Framework links (60-minute window): same user, same IP, same endpoint and sign-in to activity. The
workflow hooks add `WORKFLOW` links, each citing the records it was computed from:

- each user to every IP that sent them rejected or unanswered prompts;
- each compromised user to an endpoint tied to the compromise.

The pattern, per user (constants in `hooks.py`):

1. Unsuccessful prompts are MFA events with result `denied`, `fraud_reported` or `timeout`. Only
   when a user has no MFA event record at all, sign-ins with MFA result `denied` or `timeout` are
   used instead, so the same attempt is never counted twice.
2. The approval is the first approved prompt preceded by at least 3 unsuccessful prompts within 60
   minutes. Such a user is `approved_after_prompts` (compromised). With 3 or more unsuccessful
   prompts and no such approval, the user is `prompts_only`.
3. The suspicious login is any successful sign-in from 10 minutes before to 60 minutes after the
   approval.
4. Post-authentication actions are attributed to the attacker only when their timestamp is at or
   after 10 minutes before the approval: a forwarding, redirect or delete mailbox rule, a granted
   directory role, or an application consent.
5. A tied endpoint is used by the compromised user (endpoint users, detection or process user) or
   connects to a prompt source IP of a compromise, and shows a MALICIOUS or SUSPICIOUS detection,
   process or such a connection.

## Risk calculation

Sign-in and MFA records give no framework signal (`docs/threat-scoring.md`), so the hooks derive
signals that cite them; the scoring engine computes risk and confidence separately with its caps:

| Finding | Category | Verdict | Severity | Confidence |
|---|---|---|---|---|
| prompt approved after the threshold, then a successful sign-in | authentication_anomaly | MALICIOUS | 85 | 75 |
| the same without a sign-in record in the window | authentication_anomaly | MALICIOUS | 75 | 75 |
| unsuccessful prompts only | authentication_anomaly | SUSPICIOUS | 60 | 70 |
| source IP of a compromise | authentication_anomaly | MALICIOUS | 80 | 70 |
| source IP of unsuccessful prompts only | authentication_anomaly | SUSPICIOUS | 60 | 70 |
| endpoint connecting to a prompt source | network_behaviour | SUSPICIOUS | 70 | 60 |

Vendor anomalies, risky-user state, post-authentication mailbox rules and role grants, endpoint
detections and IP reputation add their framework signals. Reputation is a vendor verdict and is
capped. A critical asset adds the context bonus only with a supporting signal. Every rule needs a
risk of at least 60; below that the action is reported as BELOW_THRESHOLD ("considered, not
proposed"), never hidden. With the default weights a typical compromise scores risk 77 (HIGH) for the
user and 72 for the prompt source IP; prompts without an approval score 54 and stay below the
threshold.

## Containment recommendations

| Rule | Action (builder) | When | Evidence |
|---|---|---|---|
| `revoke_sessions_after_fatigue_approval` | `revoke_sessions` (`revoke_entra_sessions`) | user is `approved_after_prompts` | the unsuccessful prompts in the window, the approval, the suspicious sign-ins, vendor `mfa_fatigue` anomalies |
| `disable_compromised_account` | `disable_user` (`disable_entra_user`) | compromised and at least one of: post-authentication mailbox rule, role grant or app consent; a privileged account; identity-provider risk high or confirmed compromised; a new attacker sign-in after sessions were revoked | the above plus the records of each reason |
| `isolate_compromised_endpoint` | `isolate_endpoint` (catalog order, native first) | a tied endpoint (see Correlation logic); also, when a user's identity reads failed (unassessed), an incident endpoint with an active malicious detection, on the detection alone with a rationale that says so | the detections, processes, connections and endpoint records plus the compromise records (prompts, approval, sign-in, anomaly) of the users it is tied to |
| `block_mfa_prompt_source_ip` | `block_ip` (`block_ip`) | a public IP with at least 3 unsuccessful prompts that no reputation source rates CLEAN | the prompts, approval and sign-ins from that IP |
| `block_malicious_signin_ip` | `block_ip` (`block_ip`) | an IP rated MALICIOUS or SUSPICIOUS from which the compromised user signed in after the approval | the sign-ins and the approval, plus the reputation answers |

Each action carries numbered evidence that cites real investigation and enrichment records, a
`risk_score` and a separate `confidence_score`, and a rationale with the score explanation. When
two rules propose the same block, the evidence is merged into one action. Allow-listed targets are
shown as excluded, never dropped. Password reset and MFA re-registration are not proposed: they
are a manual help-desk step after out-of-band identity verification.

### Hand-offs and items not proposed

- Hand-off to `account-takeover` for every account that approved a prompt after the fatigue sequence: the password is known to someone else, and account-takeover reviews the account's wider activity.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed", "Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action needs human approval, including `revoke_sessions`. There is no auto-approval and
  no switch for it; AI and automation principals can never approve.
- ELEVATED approval (a lead with the elevated role) applies when a target is a critical asset: a
  privileged account (user pattern, group, or a privileged directory role in the profile or
  **granted after the approval**), a break-glass or service account, or an endpoint or IP in a
  critical class. ELEVATED also applies over a blast-radius cap and for always-elevated actions.
  The action is never skipped: it stays in the package with a visible warning.
- The workflow only passes investigated asset context (groups, tags, roles, IP); the package
  builder decides the approval level and can never be made weaker.

## Containment execution

After the human approval the lifecycle orchestrator executes the approved actions automatically
inside the execution guard, with the approval token bound to the package. Routes in this workflow:
`revoke_sessions` and `disable_user` on `entra` (disable also has a native Cisco XDR route when
configured), `isolate_endpoint` on the enabled EDR (`secure_endpoint` or `defender_endpoint`,
native first when configured), `block_ip` on `meraki` (MX L3 rule) or the native route. Unselected
actions are recorded as rejected by the analyst and never run. In dry run the same package is
rendered as a DRY RUN report and nothing changes.

## Verification

Verification is automatic after execution: `disable_user` re-reads `accountEnabled`;
`revoke_sessions` checks that `signInSessionsValidFromDateTime` is at or after the action time;
`block_ip` re-reads the MX L3 rule set; `isolate_endpoint` is VERIFIED on Defender for Endpoint and
UNABLE_TO_VERIFY on Secure Endpoint (the isolation-status endpoint is UNVERIFIED), which never counts
as contained by default.

## Rollback

Restoration needs a separate human release approval; nothing is released automatically.

- `disable_user`: re-enable the account, only after the help desk has reset the password and
  re-registered MFA.
- `block_ip`: remove the tagged MX rule.
- `isolate_endpoint`: release the endpoint after it is cleaned.
- `revoke_sessions`: not reversible (the user signs in again); it creates no temporary control.

Temporary controls carry review reminders (`temporary_controls.review_after_hours`); an
already-contained target creates no control, so a release never removes a block this incident did
not create.

## Failure handling

- A failed or degraded source (for example the EDR being unavailable) never blocks a recommendation
  backed by other evidence; it is listed as degraded and lowers confidence.
- A failing step, hook or rule expression is noted and skipped; the run still recommends what the
  rest of the evidence supports.
- An action with no executor is reported as UNROUTED for manual handling, never dropped.
- A failed execution is reported (partial containment), never retried silently; the incident needs
  remediation.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why |
|---|---|---|---|
| TA0006 Credential Access | T1621 Multi-Factor Authentication Request Generation | none | the trigger and the core pattern |
| TA0001 Initial Access | T1078 Valid Accounts | T1078.004 Cloud Accounts | the sign-in with the valid account after the approval |
| TA0009 Collection | T1114 Email Collection | T1114.003 Email Forwarding Rule | a forwarding rule after the approval is a disable reason |
| TA0003 Persistence | T1098 Account Manipulation | T1098.003 Additional Cloud Roles | a role grant after the approval is a disable reason |

No other technique is mapped: the endpoint isolation responds to whatever the endpoint product
detected, and that product reports its own techniques.

## Testing instructions

- Scenarios: `tests/fixtures/workflows/mfa-fatigue/` (minimum set of 14.5.3, eight edge cases and
  the migrated legacy scenario). Every scenario runs in dry run and/or simulated live through the
  lifecycle orchestrator in `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/mfa_fatigue/`.
- Commands:

```
python -m pytest -q -p no:cacheprovider tests/workflows/mfa_fatigue tests/simulation/test_workflow_scenarios.py -k mfa-fatigue
python tools/validation/check_workflow_readmes.py --workflow mfa-fatigue
python tools/simulator/simulate.py --workflow mfa-fatigue --scenario tp-approve-all --live --check
```

All test data is fake: documentation IP ranges, `example.com` users, hosts like `TH-LT-1047`.

## Known limitations

- The real Entra sign-in normalizer does not map MFA details yet (no MFA event records, MFA result
  unknown) and Entra ID Protection risk detections are not normalized, so with production adapters
  the pattern is only found when another source supplies typed MFA records; otherwise nothing is
  proposed and the run notes say why.
- There is no adapter for a third-party MFA provider (for example Duo); push logs from such a
  provider are not investigated.
- Thresholds (3 rejected or unanswered prompts within 60 minutes, sign-in from 10 minutes before to
  60 minutes after the approval) are fixed in the workflow hooks, not configurable per tenant.
- `revoke_sessions` is not reversible, is not in the Cisco XDR native catalog (direct Entra call
  only), can take a few minutes to apply and does not affect external users.
- Password reset and MFA re-registration are not proposed; they stay a manual help-desk step after
  out-of-band identity verification.
- Post-authentication actions without a timestamp are not attributed to the attacker.
- Isolation needs an enabled EDR executor; with only Cisco XDR enabled the isolation is reported as
  unrouted for manual handling.
- A prompt source IP can be shared infrastructure (mobile carrier NAT, cloud egress); only
  allow-listed IPs are excluded automatically, so the analyst reviews the block.
