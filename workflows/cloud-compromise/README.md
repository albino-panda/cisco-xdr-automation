# Cloud compromise

Workflow id `cloud-compromise`, version 2.0.0, Phase 4. Definition:
[`definition.py`](../../src/xdr_response/workflows/cloud_compromise/definition.py), hooks:
[`hooks.py`](../../src/xdr_response/workflows/cloud_compromise/hooks.py). Binding design:
[`docs/architecture.md`](../../docs/architecture.md) sections 13 and 14.

## Purpose

Respond to the abuse of Microsoft cloud identities and of what an attacker plants in the tenant with them:
new application credentials, OAuth consents, service-principal changes and privileged directory role
assignments. The workflow investigates the accounts an incident names in Microsoft Entra ID and Microsoft
Defender XDR (profile, roles and session state, sign-ins and risk detections, then the accounts' cloud
activity: role assignments, application credentials, consents and the cloud alerts raised for them) and
the sign-in source IPs, and then **recommends** a containment package:

- revoke the sign-in sessions, and with them the refresh tokens issued to applications, of a compromised
  account or of an account that consented to a risky OAuth application ("revoke token" and "revoke
  session");
- disable a compromised account that is privileged or that planted cloud persistence ("disable compromised
  account");
- remove a privileged directory role granted by, or to, a compromised account ("remove unauthorized role");
- block the attacker sign-in IP.

Application credentials, OAuth permission grants and service principals ("disable principal" for an
application) have no VERIFIED write in `docs/integrations.md`: the workflow reports them as **manual steps**
with the records that show them and never puts them in the package.

Investigation and recommendation are automatic. The workflow never changes anything itself: every action
waits for a human approval, approved actions are executed and verified by the lifecycle, and undoing a
reversible action needs a separate human release approval.

## Trigger

- **XDR incident rule** (priority 130): the incident's detections report `T1098.001` (additional cloud
  credentials), `T1098.003` (additional cloud roles) or `T1528` (steal application access token) and the
  incident carries a user observable.
- **XDR incident rule** (priority 105): the incident title names an OAuth consent, a consent grant, an app
  registration, a service principal, a client secret, an application credential, a certificate added to an
  app or a directory role, and the incident carries a user observable.
- **Manual**: an analyst starts the workflow from an incident or a user pivot.

A sign-in alone (`T1078.004` reported on its own) routes to `account-takeover` (priority 100); this workflow
outranks it when cloud persistence is reported, and hands compromised accounts off to it. Entry-vector
workflows with higher priority (phishing, password-spray and bec at 110, mfa-fatigue at 200) keep their
incidents. The XDR trigger only sends the incident id; the incident is re-read through the VERIFIED APIs
(`tools/deployment/xdr-trigger-workflow.md`).

## Required integrations

The expected sources. When one is disabled or failing the run notes it and confidence drops; a
recommendation backed by other evidence is still made.

| Integration | Purpose | Read atomics |
|---|---|---|
| `entra` | User profile, directory roles and session state, sign-in logs and risk context; executes the approved session revocation, account disable and role-assignment removal | `investigate_user`, `investigate_authentication`, `search_user_activity` |
| `microsoft_cloud` | Defender XDR alerts (alerts_v2) for the accounts' cloud activity: OAuth applications, new application credentials, suspicious cloud API activity | `investigate_user`, `search_user_activity`, `search_ip_enterprise` |
| `cisco_xdr` | Verdicts for the sign-in source IPs and enterprise sightings of those IPs | `enrich_ip`, `search_ip_enterprise` |

## Optional integrations

| Integration | Purpose | Read atomics |
|---|---|---|
| `virustotal` | Second opinion on public sign-in source IPs (never non-public addresses) | `enrich_ip` |
| `alienvault_otx` | Second opinion on public sign-in source IPs (never non-public addresses) | `enrich_ip` |
| `meraki` | Executes the approved attacker IP block as an MX layer 3 firewall rule (no reads) | none |
| `defender_endpoint` | IP prevalence on managed endpoints; executes an approved IP block as an indicator | `search_ip_enterprise` |
| `splunk` | Optional SIEM search for sign-ins, cloud audit activity and IP prevalence (generic rows) | `investigate_authentication`, `search_user_activity`, `search_ip_enterprise` |

## Input data

- The Cisco XDR incident: id, title, severity, source, trigger (reported techniques and context such as an
  application name or a change ticket), `users` and observables. Trigger context is data shown to the
  analyst, never evidence.
- Observable types used: `user` (the investigated accounts) and `ip` / `ipv6` (sign-in sources). Accounts
  that only appear in the investigated records (the receiver of a role, an application's consenting user)
  are judged from those records.
- Records the atomics return: user profiles (risk, roles, `privileged`, session timestamp), sign-ins, risk
  detections, Defender XDR cloud alerts (detections without an endpoint), role changes (`user`, `role_name`,
  `role_definition_id`, `change`, `actor`), cloud applications (`app_id`, publisher verification,
  permissions, consent type and consenting user, credential and creation times, vendor verdict), IP
  enrichment and enterprise sightings.
- Policy from `config/`: critical assets (privileged and break-glass account patterns, directory roles such
  as Global Administrator or Application Administrator, production and network CIDRs), allow-lists
  (`never_block` users, IPs and CIDRs), disclosure exclusions and scoring thresholds.

## Investigation steps

All steps are read-only atomics (`ReadOnlyAdapters`); a failing source becomes a degraded source, never an
error that stops the run.

| Step | Atomic | Subjects | Lookback | What it learns |
|---|---|---|---|---|
| `user_profile` | `investigate_user` | incident `users` and user observables | 24 h | profile, account state, risk state, directory roles, Defender XDR alerts for the account |
| `authentication` | `investigate_authentication` | same accounts | 72 h | sign-ins (IP, location, app, result, MFA, risk) and identity-provider risk detections |
| `cloud_activity` | `search_user_activity` | same accounts | 7 days | role assignments made by or to the account, application credentials added, OAuth consents granted, service-principal changes and cloud alerts |
| `ip_reputation` | `enrich_ip` | incident IPs and every sign-in IP found by the steps above | n/a | per-source verdicts and the aggregate verdict (third parties never receive non-public IPs) |
| `ip_prevalence` | `search_ip_enterprise` | the same IPs | 7 days | internal endpoints and other accounts that use the IP (shared infrastructure) |

## Correlation logic

- Records are grouped per account (profile, sign-ins, risk detections, cloud alerts), per application
  (`app_id`, with the accounts whose activity shows it) and per role change.
- Framework links: `sign_in_to_activity` ties a successful sign-in to the account's later role, consent or
  application activity within 1440 minutes; `same_ip` and `same_user` cluster accounts and IPs that share
  records (blast radius).
- The hooks decide, from records only, which account shows a **compromise indicator**. *Strong*
  indicators: the identity provider rates the account high risk or confirmed compromised; a successful
  sign-in from an IP that a source rates malicious (or that a HIGH vendor malicious-IP detection names); a
  successful sign-in the identity provider rates high risk; a HIGH or CRITICAL risk detection with a
  successful sign-in; a session token replay; an active Defender XDR cloud alert rated malicious. *Weak*
  indicators: a successful sign-in from an IP rated only suspicious; medium identity risk with risk
  detections; an unresolved HIGH cloud alert without a classification.
- A **risky application** is rated malicious or suspicious by a vendor, or had a credential added, was
  registered or changed, or received a consent (unverified publisher) by a compromised account.
- An **unauthorized role** is a privileged directory role assigned, activated or made eligible for an
  account during the window, not removed since, and granted by a compromised account or received by one.
  A privileged grant between accounts with no compromise indicator is shown as considered, and so is a
  grant dated more than 24 hours before the earliest dated compromise record (sign-in, risk detection or
  alert) of the account that ties it to the incident: a pre-existing assignment the incident did not
  create.
- **Revoke** applies to every compromised account and to every account that granted a *user* consent to a
  risky application. **Disable** applies to an account with a strong indicator that is privileged (profile
  roles, the source's flag or a privileged role it received) or planted persistence (granted a privileged
  role, added an application credential, granted tenant-wide consent to a risky application).
- **Attacker IP**: a sign-in source of an investigated account that a source rates malicious (or that is
  rated suspicious and was used for a successful sign-in by a high-risk account) and that is **not shared**:
  no internal endpoint reaches it and no other account signs in from it.

## Risk calculation

Each target is scored by the scoring engine from exactly the records its rule cites (separate
`risk_score` and `confidence_score`, both integers 0-100, with the explanation and settings hash in the
rationale):

- identity-provider risk detections and a high user risk are `authentication_anomaly` signals;
- privileged role assignments and vendor-rated applications are `persistence` signals; cloud persistence
  is this workflow's primary evidence, so `persistence` weighs 1.0 here (default 0.8; caps and penalties are
  not overridable);
- Defender XDR cloud alerts are detection signals;
- IP enrichment is `reputation` (capped at 50; one vendor's MALICIOUS is never an aggregate MALICIOUS);
- the hooks add signals computed from cited records: a successful sign-in from an IP rated malicious (80)
  or suspicious (70), a credential added to or a consent granted to an unrated application by a compromised
  account (70), and a sign-in source IP used against an investigated account (60 to 80). Each is attributed
  to the source of the records it cites.

A failed expected source (`entra`, `microsoft_cloud`, `cisco_xdr`) costs confidence and is listed; it never
blocks a recommendation that other evidence supports. Critical assets add the critical-asset bonus to risk;
they never change confidence. Minimum risk per rule: revoke 50, disable 60, role removal 50, block 50 (below
the minimum an action is listed as "considered, not proposed", never hidden). Dry run and live score
identically.

## Containment recommendations

| Rule | Action (builder) | Target | Evidence (numbered in the package) |
|---|---|---|---|
| `revoke_compromised_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | every compromised account and every account that consented to a risky application | the indicator records (profile, attacker sign-ins, risk detections, cloud alerts, IP enrichment that rated the source) and the consent records with the application's rating |
| `disable_compromised_account` | `disable_user` (`disable_entra_user`) | an account with a strong indicator that is privileged or planted cloud persistence | the same indicator records plus the role change, application credential or consent records it planted |
| `remove_unauthorized_role` | `remove_privileged_role` (`remove_privileged_role`) | `<user>/<roleDefinitionId>` of a privileged role granted by or to a compromised account | the role change record and the records that prove the compromise of the actor or receiver |
| `block_attacker_ip` | `block_ip` (`block_ip`) | a non-shared sign-in source IP rated malicious (or suspicious and used by a high-risk account) | the sign-in and detection records from that IP and the MALICIOUS or SUSPICIOUS enrichment answers |

Every recommendation carries numbered evidence that cites investigation or enrichment records of the run
(the lifecycle refuses anything else) and a rationale with the score explanation. Password reset and MFA
re-registration are not recommended actions: the help desk does them after out-of-band identity
verification, before any release.

### Hand-offs, manual steps and items not proposed

- Manual steps (no VERIFIED write; never in the package), per risky application: `remove-app-credentials:<app id>`
  (when a credential was added), `revoke-oauth-consent:<app id>` (when a consent was granted) and
  `disable-service-principal:<app id>`; and `remove-role:<user>/<role>` when a role change record carries no
  role definition id.
- Considered, not proposed: `revoke_sessions:<admin>` for a tenant-wide consent to a risky application by an
  administrator with no compromise indicator (revocation would not stop the application's own tokens);
  `disable_user:<account>` for an uncompromised account that added a credential to a risky application;
  `remove_privileged_role:<target>` for a privileged grant between accounts with no compromise indicator;
  `block_ip:<ip>` for a rated sign-in IP that is shared infrastructure.
- Hand-offs: every compromised account to `account-takeover` for the broader account review (mailbox rules,
  sign-ins, endpoints). This workflow keeps its own containment.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed", "Manual
steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion only: it
starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action, including session revocation, role removal and every later release or restoration, needs an
  explicit human approval by an authenticated HUMAN principal holding the approver role. AI and automation
  principals can never approve, and there is no auto-approval switch.
- ELEVATED approval (a principal with the elevated role, and a visible warning on the decision card)
  applies when a target matches a critical-asset class (a privileged or break-glass account by user
  pattern, group, directory role such as Global Administrator or Cloud Application Administrator, or the
  identity source's privileged flag; an executive account; an IP in a production or network-infrastructure
  CIDR), when the catalog always elevates the action (`remove_privileged_role` and its restoration
  `restore_privileged_role` are always ELEVATED), or when a blast-radius cap is exceeded (more than three
  accounts). `PackageBuilder` decides this; the workflow only passes the investigated asset context (groups,
  roles) and can never lower it.
- Allow-listed targets (for example `breakglass@example.com` or a VPN pool CIDR) are shown as excluded with
  the reason and never executed; nothing is dropped silently.

## Containment execution

After the approval the lifecycle executes exactly the approved actions through the execution guard with the
HMAC approval token; the workflow is not involved:

- `revoke_sessions`: Entra `POST /users/{id}/revokeSignInSessions` (VERIFIED, not reversible, effective
  within minutes, no effect on external users; it also invalidates the refresh tokens issued to applications
  for the account);
- `disable_user`: Entra `PATCH /users/{id}` with `accountEnabled: false` (VERIFIED), or the native Cisco XDR
  disable action when configured;
- `remove_privileged_role`: Entra `DELETE /roleManagement/directory/roleAssignments/{id}` (VERIFIED) after
  the assignment is captured for the release;
- `block_ip`: the native Cisco XDR action when configured, else a Meraki MX layer 3 rule or a Defender for
  Endpoint IP indicator. Direct Umbrella IP blocking is UNVERIFIED and never used.

A target already in the desired state reports `ALREADY_CONTAINED`. In dry run the lifecycle prints the DRY
RUN block (`Would revoke sessions: ...`, `Would disable user: ...`, `Would remove role: ...`,
`Would block: ...`) and changes nothing.

## Verification

Automatic, after execution, with the product's own read call: Entra
`GET /users/{id}?$select=signInSessionsValidFromDateTime` (revocation), `accountEnabled` (disable) and
`GET /roleManagement/directory/roleAssignments?$filter=principalId eq '..'` (role removal), Meraki
`GET .../l3FirewallRules` (VERIFIED). Defender indicators have no VERIFIED read and report
`UNABLE_TO_VERIFY`, which never counts as contained. The overall result is CONTAINED, PARTIALLY_CONTAINED or
CONTAINMENT_FAILED. Manual steps are not verified by the workflow; the analyst records them in the incident.

## Rollback

- `revoke_sessions`: not reversible; the user signs in again after the help desk reset.
- `disable_user`: `enable_user` (Entra `accountEnabled: true`), only after the password reset, MFA
  re-registration and the manual removal of planted credentials and consents.
- `remove_privileged_role`: `restore_privileged_role` (Entra `POST /roleManagement/directory/roleAssignments`
  with the captured role, principal and scope), always ELEVATED, only when the assignment proves legitimate.
- `block_ip`: `unblock_ip` (remove the tagged MX rule or the indicator).

Reversible actions are registered as temporary controls; review reminders never release anything. A release
package is proposed from the registry and executed only after its own human release approval, then verified.

## Failure handling

- A failed or degraded source (health UNAVAILABLE, AUTH_FAILED, RATE_LIMITED) is noted, lowers confidence and
  never blocks a recommendation backed by other evidence: with Defender XDR down, an Entra high-risk account
  with an attacker sign-in is still revoked.
- A failing step, expression or hook is noted and skipped; partial results stay usable.
- A recommendation without an enabled executor is reported as UNROUTED for manual handling, never dropped.
- During execution a failed action is reported FAILED (PARTIALLY_CONTAINED or CONTAINMENT_FAILED) and the
  incident needs remediation; nothing is retried silently and the other approved actions still run.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why the workflow responds |
|---|---|---|---|
| TA0001 Initial Access | T1078 Valid Accounts | T1078.004 Cloud Accounts | The incident is the use of a cloud identity with valid credentials; the package revokes the sessions, disables the account when needed and blocks the source IP. |
| TA0003 Persistence | T1098 Account Manipulation | T1098.001 Additional Cloud Credentials | A credential added to an application or service principal by a compromised account is investigated; the account is disabled and the credential removal is a manual step. |
| TA0003 Persistence | T1098 Account Manipulation | T1098.003 Additional Cloud Roles | A privileged directory role granted by or to a compromised account is recommended for removal (always ELEVATED) and the granting account for disable. |
| TA0006 Credential Access | T1528 Steal Application Access Token | none | A consent to a risky OAuth application hands it the user's tokens; revocation invalidates the refresh tokens issued to applications and the consent revocation is a manual step. |

No other technique is mapped. The legacy specification also listed data from cloud storage; the workflow
neither investigates nor contains storage access (no VERIFIED read), so that mapping is dropped rather than
forced (see Known limitations).

## Testing instructions

- Scenarios: `tests/fixtures/workflows/cloud-compromise/` (the minimum set of 14.5.3, four edge cases: admin
  OAuth consent, user consent phishing, rogue role assignment, shared attacker IP; and the migrated legacy
  scenarios 01 to 05). They run automatically, in dry run and simulated live, in
  `tests/simulation/test_workflow_scenarios.py`.
- Unit and lifecycle tests: `tests/workflows/cloud_compromise/`.
- Commands:

```bash
python -m pytest -q -p no:cacheprovider tests/workflows/cloud_compromise tests/simulation/test_workflow_scenarios.py -k "cloud-compromise or cloud_compromise"
python tools/validation/check_workflow_readmes.py --workflow cloud-compromise
python tools/simulator/simulate.py --workflow cloud-compromise --scenario tp-approve-all --check
python tools/simulator/simulate.py --workflow cloud-compromise --scenario tp-approve-all --live --check
```

All test data is fake: `example.com` accounts, documentation IP ranges, fake application and role ids.

## Known limitations

- Application credentials, OAuth permission grants and service principals have no VERIFIED Graph write in
  `docs/integrations.md` (`revoke_app_credentials` is UNVERIFIED and there is no service-principal or consent
  action type), so removing a credential, revoking a consent and disabling a service principal are manual
  steps in the run notes and analyst summary, never package actions.
- With the real adapters role changes and application records are not normalized: the Entra directory audit
  log and the servicePrincipals and oauth2PermissionGrants reads are not in `docs/integrations.md`. On a
  tenant the cloud-persistence indicators therefore come only from Defender XDR alerts (alerts_v2), sign-in
  risk and IP reputation, and role removal and the application manual steps need typed records from another
  source.
- Role removal targets `<user>/<roleDefinitionId>`. The real Entra adapter resolves the user's object id and
  the assignment of that role (at the scope of the grant when the role change record names it) through VERIFIED
  reads before the delete and again in verification (architecture 14.12.3). When the user holds the role at
  several scopes and the record names none, the approved removal fails visibly and the analyst removes the right
  assignment by hand.
- Session revocation is not reversible, can take a few minutes, does not affect external (guest) users and
  does not stop application-only tokens of a service principal: tenant-wide (admin) consents and
  service-principal secrets need the manual steps.
- Whether a role assignment or an application credential was an approved change cannot be read from a
  VERIFIED source (no change-management integration); a privileged grant between accounts with no compromise
  indicator is shown as considered, not proposed, and the analyst checks the change record.
- Direct Umbrella IP blocking is UNVERIFIED; IP blocks route to Meraki MX, a Defender for Endpoint indicator
  or the native Cisco XDR action. A non-public sign-in IP (corporate VPN pool) is excluded only when
  `allowlists.never_block` lists it or it is in a non-public range.
- Access to cloud storage and mailboxes by the application or the accounts (Data from Cloud Storage) is not
  investigated: no VERIFIED read exists; it is the exfiltration workflow's and the analyst's review.
