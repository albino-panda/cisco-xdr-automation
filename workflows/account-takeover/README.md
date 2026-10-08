# Account takeover

Workflow id `account-takeover`, version 2.0.0, Phase 2. Definition:
[`definition.py`](../../src/xdr_response/workflows/account_takeover/definition.py), hooks:
[`hooks.py`](../../src/xdr_response/workflows/account_takeover/hooks.py). Binding design:
[`docs/architecture.md`](../../docs/architecture.md) sections 13 and 14.

## Purpose

Respond to a sign-in by an attacker who uses valid credentials or a stolen session. The workflow
investigates the account (identity profile and session state, sign-ins, MFA activity, identity-provider
risk detections, post-sign-in cloud activity), the sign-in source IPs (reputation and enterprise
prevalence) and the user's endpoints named by the incident, and then **recommends** a containment
package: revoke the account's sessions, disable the account, isolate a linked infected endpoint and
block the attacker IP.

Investigation and recommendation are automatic. The workflow never changes anything itself: every
action waits for a human approval, approved actions are executed and verified by the lifecycle, and
undoing a reversible action needs a separate human release approval.

## Trigger

- **XDR incident rule** (priority 100): the incident's detections report `T1078.004` or `T1539` and the
  incident carries a user observable.
- **XDR incident rule** (priority 90): the incident title looks like a risky, high-risk, unfamiliar,
  impossible-travel or atypical-travel sign-in, an account takeover or a token replay, and the incident
  carries a user observable.
- **Manual**: an analyst starts the workflow from an incident or a user pivot.

MFA prompt floods (`T1621` reported on its own) route to the `mfa-fatigue` workflow (priority 200);
password-spray and BEC incidents route to their own workflows. The XDR trigger only sends the incident
id; the incident is re-read through the VERIFIED APIs (`tools/deployment/xdr-trigger-workflow.md`).

## Required integrations

The expected sources. When one is disabled or failing the run notes it and confidence drops; a
recommendation backed by other evidence is still made.

| Integration | Purpose | Read atomics |
|---|---|---|
| `entra` | User profile and session state, sign-in logs, MFA and risk context; executes the approved session revocation and account disable | `investigate_user`, `investigate_authentication`, `search_user_activity` |
| `cisco_xdr` | Verdicts for the sign-in source IPs and enterprise sightings of those IPs | `enrich_ip`, `search_ip_enterprise` |

## Optional integrations

| Integration | Purpose | Read atomics |
|---|---|---|
| `microsoft_cloud` | Defender XDR alerts and advanced hunting for sign-ins, user activity and IP prevalence | `investigate_authentication`, `search_user_activity`, `search_ip_enterprise` |
| `secure_endpoint` | Detections and isolation state of the user's endpoints; executes the approved isolation | `investigate_endpoint` |
| `defender_endpoint` | Detections of the user's endpoints and IP prevalence; executes an approved isolation or IP indicator | `investigate_endpoint`, `search_ip_enterprise` |
| `virustotal` | Second opinion on public sign-in source IPs (never non-public addresses) | `enrich_ip` |
| `alienvault_otx` | Second opinion on public sign-in source IPs (never non-public addresses) | `enrich_ip` |
| `meraki` | Executes the approved attacker IP block as an MX layer 3 firewall rule (no reads) | none |
| `splunk` | Optional SIEM search for sign-ins, user activity and IP prevalence | `investigate_authentication`, `search_user_activity`, `search_ip_enterprise` |

## Input data

- The Cisco XDR incident: id, title, severity, source, trigger (reported techniques), `users`, assets and
  observables.
- Observable types used: `user` (the investigated accounts), `ip` / `ipv6` (sign-in sources), `hostname`
  (the user's endpoints). Incident trigger context (for example a travel request or a "previously
  revoked" list) is data shown to the analyst, never evidence.
- Policy from `config/`: critical assets (privileged and break-glass account patterns, directory roles,
  production and network CIDRs), allow-lists (`never_block` users, IPs and CIDRs such as VPN pools),
  disclosure exclusions and scoring thresholds.

## Investigation steps

All steps are read-only atomics (`ReadOnlyAdapters`); a failing source becomes a degraded source, never
an error that stops the run.

| Step | Atomic | Subjects | Lookback | What it learns |
|---|---|---|---|---|
| `user_profile` | `investigate_user` | incident `users` and user observables | 24 h | profile, account state, `signInSessionsValidFromDateTime`, risk state, roles and groups when the source reports them |
| `authentication` | `investigate_authentication` | same accounts | 72 h | sign-ins (IP, location, app, result, MFA, risk), MFA events, identity-provider risk detections |
| `user_activity` | `search_user_activity` | same accounts | 72 h | mailbox rules, role changes, app consents after the sign-in |
| `ip_reputation` | `enrich_ip` | incident IPs and every IP found by the steps above | n/a | per-source verdicts and the aggregate verdict (third parties never receive non-public IPs) |
| `ip_prevalence` | `search_ip_enterprise` | the same IPs | 7 days | internal endpoints and other accounts that use the IP (shared infrastructure) |
| `user_endpoints` | `investigate_endpoint` | hostnames the incident names (observables and endpoint assets) | 24 h | endpoint, detections (verdict, status, user), isolation state |

## Correlation logic

- Records are grouped per account: profile, sign-ins, MFA events, risk detections and cloud activity.
- Framework links: `sign_in_to_activity` ties a successful sign-in to the account's mailbox-rule, role or
  app-consent activity within 240 minutes; `same_ip`, `same_user` and `same_endpoint` cluster accounts,
  IPs and endpoints that share records (blast radius).
- The hooks decide, from records only, which account shows a **compromise indicator**:
  1. the identity provider rates the user high risk or confirmed compromised;
  2. a successful sign-in from an IP that enrichment rates malicious or suspicious, or that a vendor
     anonymous-IP or malicious-IP detection names;
  3. a successful sign-in that the identity provider rates high risk;
  4. a HIGH or CRITICAL risk detection (impossible travel, unfamiliar location, new device, anonymous or
     malicious IP, token replay, leaked credentials and similar) together with a successful sign-in;
  5. a session token replay detection (stolen session);
  6. an MFA approval after at least three denied or fraud-reported prompts, or an MFA fatigue detection
     followed by a successful sign-in.
- **Disable** applies to a compromised account that holds a privileged directory role (from the profile
  or a privileged role assignment it just received), or whose attacker sign-in is later than its
  `signInSessionsValidFromDateTime` (the attacker came back after an earlier revocation).
- **Attacker IP**: a sign-in or MFA source of an investigated account that at least one source rates
  malicious (or that a HIGH vendor malicious-IP detection names) and that is **not shared**: no internal
  endpoint reaches it and no other account signs in from it. A shared IP (VPN exit, proxy) is never
  proposed for a block; its sign-in stays in the revocation evidence.
- **Endpoint**: an incident endpoint linked to a compromised account (logged-on user or detection user)
  with an active MALICIOUS detection.

## Risk calculation

Each target is scored by the scoring engine from exactly the records its rule cites (separate
`risk_score` and `confidence_score`, both integers 0-100, with the explanation and settings hash in the
rationale):

- identity-provider risk detections and a high user risk are `authentication_anomaly` signals;
- privileged role assignments, external-forwarding or deleting mailbox rules and flagged app consents are
  `persistence` signals;
- endpoint detections are `endpoint_detection` signals;
- IP enrichment is `reputation` (capped at 50; one vendor's MALICIOUS is never an aggregate MALICIOUS);
- the hooks add `authentication_anomaly` signals computed from cited records: a successful sign-in from an
  IP rated malicious (severity 80) or suspicious (70), an attacker sign-in after the sessions were revoked
  (85), an MFA approval after repeated denials (70), and a sign-in source IP used against an investigated
  account (60 to 80). Each is attributed to the source of the sign-in or MFA records it cites.

A failed expected source (`entra`, `cisco_xdr`) costs confidence and is listed; it never blocks a
recommendation that other evidence supports. Critical assets add the critical-asset bonus to risk; they
never change confidence. Minimum risk per rule: revoke 50, disable 60, isolate 60, block 50 (below the
minimum an action is listed as "considered, not proposed", never hidden). Dry run and live score
identically.

## Containment recommendations

| Rule | Action (builder) | Target | Evidence (numbered in the package) |
|---|---|---|---|
| `revoke_compromised_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | every compromised account | the indicator records: profile, attacker sign-ins, risk detections, MFA events, IP enrichment that rated the source, post-sign-in cloud activity |
| `disable_compromised_account` | `disable_user` (`disable_entra_user`) | a compromised account that is privileged or was used again after a revocation | the same records plus the profile with the session timestamp |
| `isolate_compromised_user_endpoint` | `isolate_endpoint` (catalog order, native Cisco XDR first) | an incident endpoint of a compromised account with an active malicious detection; also, when the account's identity reads failed (unassessed), an incident endpoint with an active malicious detection, on the detection alone with a rationale that says so | the detection and endpoint records plus the records that prove the account's compromise (only the detection and endpoint records when the account is unassessed) |
| `block_attacker_ip` | `block_ip` (`block_ip`) | a non-shared sign-in source IP that a source rates malicious | the sign-in, MFA and detection records from that IP and the MALICIOUS or SUSPICIOUS enrichment answers |

Every recommendation carries numbered evidence that cites investigation or enrichment records of the run
(the lifecycle refuses anything else) and a rationale with the score explanation. Password reset and MFA
re-registration are not recommended actions: the help desk does them after out-of-band identity
verification, before any release.

### Hand-offs and items not proposed

- Not proposed, and listed as considered: a sign-in IP rated malicious or suspicious that is shared infrastructure (seen from internal endpoints or used by other accounts).
- Hand-offs: none; this workflow is the hand-off target of phishing, password-spray, mfa-fatigue, mail-bombing and bec.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed", "Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action, including session revocation and every later release or restoration, needs an explicit
  human approval by an authenticated HUMAN principal holding the approver role. AI and automation
  principals can never approve, and there is no auto-approval switch.
- ELEVATED approval (a principal with the elevated role, and a visible warning on the decision card)
  applies when a target matches a critical-asset class (for example a privileged or break-glass account
  by user pattern, group or directory role such as Global Administrator or Security Administrator, an
  executive endpoint, or an IP in a production or network-infrastructure CIDR), when the catalog always
  elevates the action, or when a blast-radius cap is exceeded. `PackageBuilder` decides this; the
  workflow only passes the investigated asset context (groups, roles, tags, IP) and can never lower it.
- Allow-listed targets (for example `breakglass@example.com` or a VPN pool CIDR) are shown as excluded
  with the reason and never executed; nothing is dropped silently.

## Containment execution

After the approval the lifecycle executes exactly the approved actions through the execution guard with
the HMAC approval token; the workflow is not involved:

- `revoke_sessions`: Entra `POST /users/{id}/revokeSignInSessions` (VERIFIED, not reversible, effective
  within minutes, no effect on external users);
- `disable_user`: Entra `PATCH /users/{id}` with `accountEnabled: false` (VERIFIED), or the native Cisco
  XDR disable action when configured;
- `isolate_endpoint`: the native Cisco XDR action when configured, else Defender for Endpoint isolate or
  Secure Endpoint isolation;
- `block_ip`: the native Cisco XDR action when configured, else a Meraki MX layer 3 rule or a Defender for
  Endpoint IP indicator. Direct Umbrella IP blocking is UNVERIFIED and never used.

A target already in the desired state reports `ALREADY_CONTAINED`. In dry run the lifecycle prints the
DRY RUN block (`Would revoke sessions: ...`, `Would disable user: ...`, `Would isolate: ...`,
`Would block: ...`) and changes nothing.

## Verification

Automatic, after execution, with the product's own read call: Entra
`GET /users/{id}?$select=signInSessionsValidFromDateTime` (revocation) and `accountEnabled` (disable),
Meraki `GET .../l3FirewallRules`, Defender for Endpoint `GET /api/machineactions/{id}` (VERIFIED).
Secure Endpoint isolation and Defender indicators have no VERIFIED read and report `UNABLE_TO_VERIFY`,
which never counts as contained. The overall result is CONTAINED, PARTIALLY_CONTAINED or
CONTAINMENT_FAILED.

## Rollback

- `revoke_sessions`: not reversible; the user signs in again after the help desk reset.
- `disable_user`: `enable_user` (Entra `accountEnabled: true`), only after the password reset and MFA
  re-registration are done.
- `isolate_endpoint`: release from isolation after the endpoint is cleaned.
- `block_ip`: `unblock_ip` (remove the tagged MX rule or the indicator).

Reversible actions are registered as temporary controls; review reminders never release anything. A
release package is proposed from the registry and executed only after its own human release approval,
then verified.

## Failure handling

- A failed or degraded source (health UNAVAILABLE, AUTH_FAILED, RATE_LIMITED) is noted, lowers
  confidence and never blocks a recommendation backed by other evidence.
- A failing step, expression or hook is noted and skipped; partial results stay usable.
- A recommendation without an enabled executor is reported as UNROUTED for manual handling, never
  dropped.
- During execution a failed action is reported FAILED (PARTIALLY_CONTAINED or CONTAINMENT_FAILED) and
  the incident needs remediation; nothing is retried silently and the other approved actions still run.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why the workflow responds |
|---|---|---|---|
| TA0001 Initial Access | T1078 Valid Accounts | T1078.004 Cloud Accounts | The incident is a sign-in to a cloud identity with valid credentials; the package revokes the sessions, disables the account when needed and blocks the source IP. |
| TA0006 Credential Access | T1539 Steal Web Session Cookie | none | A replayed session token or an infected endpoint of the account is how a session is stolen; revocation invalidates it and isolation stops the theft. |
| TA0006 Credential Access | T1621 Multi-Factor Authentication Request Generation | none | An MFA approval after repeated denied prompts is a compromise indicator that leads to revocation; prompt floods without an approval belong to the mfa-fatigue workflow. |

No other technique is mapped: mailbox rules, app consents and role assignments are cited as
post-compromise context only, and their remediation belongs to the bec and cloud-compromise workflows.

## Testing instructions

- Scenarios: `tests/fixtures/workflows/account-takeover/` (the minimum set of 14.5.3, five edge cases and
  the migrated legacy scenarios 01, 02, 03, 04 and 06; legacy scenario 05 seeds the mfa-fatigue
  workflow). They run automatically, in dry run and simulated live, in
  `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/account_takeover/`.
- Commands:

```bash
python -m pytest -q -p no:cacheprovider tests/workflows/account_takeover tests/simulation/test_workflow_scenarios.py -k account-takeover
python tools/validation/check_workflow_readmes.py --workflow account-takeover
python tools/simulator/simulate.py --workflow account-takeover --scenario tp-approve-all --check
python tools/simulator/simulate.py --workflow account-takeover --scenario tp-approve-all --live --check
```

All test data is fake: `example.com` accounts, documentation IP ranges, hosts like `TH-LT-1047`.

## Known limitations

- With the real Entra adapter only user properties and sign-in logs are normalized: risk detections, the
  riskyUser state (UNVERIFIED), MFA method detail, directory roles and group memberships are not mapped.
  On a tenant the indicators therefore come from sign-in risk and IP reputation, and privileged accounts
  are recognised through the critical-asset user patterns and groups.
- Session revocation is not reversible, can take a few minutes and does not affect external (guest)
  users; the password reset and MFA re-registration stay a manual help-desk step.
- The shared-infrastructure check needs typed enterprise sightings. Hunting rows without a documented
  schema (Splunk, `runHuntingQuery`) stay generic records, so a VPN exit may still be proposed for a
  block and the analyst decides.
- A non-public sign-in IP (corporate VPN pool) is proposed like any other; list VPN pools in
  `allowlists.never_block.cidrs` so the block is shown as excluded and never executed.
- Direct Umbrella IP blocking is UNVERIFIED; IP blocks route to Meraki MX, a Defender for Endpoint
  indicator or the native Cisco XDR action, and Secure Endpoint isolation is UNABLE_TO_VERIFY.
- Only endpoints the incident names (hostname observables or endpoint assets) are investigated; sign-in
  device ids are not resolved to endpoints.
- MFA prompt floods without an approval are handled by the mfa-fatigue workflow, mailbox-rule and
  app-consent remediation by the bec and cloud-compromise workflows.
- A shared IP that is not proposed for a block is listed as considered (run notes and analyst summary)
  only when some source rates it; an unrated shared IP is simply not a block candidate.
