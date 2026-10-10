# Privilege escalation

Workflow id `privilege-escalation`, version 2.0.0, Phase 5. Definition:
[`definition.py`](../../src/xdr_response/workflows/privilege_escalation/definition.py), hooks:
[`hooks.py`](../../src/xdr_response/workflows/privilege_escalation/hooks.py). Binding design:
[`docs/architecture.md`](../../docs/architecture.md) sections 13 and 14. It replaces the legacy specification
`workflows/privilege-escalation/workflow.yaml` (its five scenarios are migrated as `legacy-*` fixtures).

## Purpose

Respond to an account, a service principal or a process gaining more privilege than expected:

- a new privileged directory role or an unexpected administrator assignment;
- a privileged group membership change (for example Domain Admins);
- a high-privilege permission granted to an application (service principal);
- an exploit or a UAC bypass on an endpoint (local privilege escalation).

For every privileged change the workflow establishes **who** made it (the actor), who received it, when,
the **source device** (the originating endpoint the incident names and the users a record places on it), the
**authentication context** (the accounts' sign-ins, identity risk and risk detections), the **change
reference** when one is available, and whether the change is **normal or anomalous**. It then
**recommends** a containment package:

- remove the unauthorized privilege (an Entra directory role assignment, always ELEVATED);
- revoke the sessions of the accounts that made or received an anomalous change;
- disable the compromised identity, or the account the attacker created or staged;
- isolate the originating endpoint.

An account that received its privilege through an anomalous change is **never shielded** by that privilege
(a protected group or an administrator role): its actions stay proposed and are ELEVATED with a visible
warning. Privileged group membership, role assignments without a role definition id and application
permissions have no VERIFIED write in `docs/integrations.md`: they are **manual steps** with the records that
show them.

Investigation and recommendation are automatic. The workflow never changes anything itself: every action
waits for a human approval, approved actions are executed and verified by the lifecycle, and undoing a
reversible action needs a separate human release approval.

## Trigger

- **XDR incident rule** (priority 128): the incident's detections report `T1068` (exploitation for privilege
  escalation), `T1548` or one of its sub-techniques (for example `T1548.002` UAC bypass) or `T1098`
  (account manipulation, any sub-technique not claimed by a higher-priority workflow).
- **XDR incident rule** (priority 104): the incident title names a privilege escalation, a privileged role, an
  administrator or role assignment, a privileged or sensitive group, Domain Admins or Enterprise Admins, a
  UAC bypass, an elevation of privilege or a local privilege escalation, and the incident carries a user,
  hostname or endpoint id.
- **Manual**: an analyst starts the workflow from an incident, a user or an endpoint.

Routing: `cloud-compromise` (priority 130) keeps incidents that report `T1098.001` or `T1098.003` and its
own directory-role titles (105); this workflow (128, 104) outranks `account-takeover` (100), which it hands
compromised accounts off to. Workflows with higher technique priorities (ransomware, mfa-fatigue,
dns-tunneling, lateral-movement, credential-dumping and the others at 150 and above) keep their incidents.
The XDR trigger only sends the incident id; the incident is re-read through the VERIFIED APIs
(`tools/deployment/xdr-trigger-workflow.md`).

## Required integrations

The expected sources. When one is disabled or failing the run notes it and confidence drops; a
recommendation backed by other evidence is still made.

| Integration | Purpose | Read atomics |
|---|---|---|
| `entra` | Profiles, directory roles, risk state and sign-ins of the accounts involved and their role changes; executes the approved session revocation, account disable and role removal | `investigate_user`, `search_user_activity`, `investigate_authentication` |
| `secure_endpoint` | The originating endpoint: logged-on users, isolation capability, detections and device trajectory, and the isolation route | `investigate_endpoint`, `enrich_hash` |

## Optional integrations

| Integration | Purpose | Read atomics |
|---|---|---|
| `defender_endpoint` | Second endpoint source (machine, alerts) and the isolation route for the endpoints it manages | `investigate_endpoint` |
| `microsoft_cloud` | Microsoft Defender XDR alerts (alerts_v2) about the accounts and the endpoints, for example suspicious role or sensitive group changes | `investigate_endpoint`, `investigate_user`, `search_user_activity` |
| `cisco_xdr` | Platform verdicts for the endpoint and its files, and the native response actions the router prefers when configured | `investigate_endpoint`, `enrich_hash` |
| `virustotal` | Public file reputation of the exploit or bypass payload hash (disclosure policy applies) | `enrich_hash` |
| `alienvault_otx` | Independent file reputation of the payload hash (disclosure policy applies) | `enrich_hash` |
| `splunk` | Optional SIEM search for directory and Windows security events of the accounts (generic rows: citable, never scored) | `search_user_activity`, `investigate_authentication` |

## Input data

- The Cisco XDR incident: id, title, severity, source, trigger (reported techniques, and an optional
  `change_reference` the detection source reports), `users` and observables. Trigger context is data shown
  to the analyst, never evidence: a change reference never withholds or creates a recommendation.
- Observable types used: `user` (accounts), `hostname` and `endpoint_id` (the originating endpoint) and
  `sha256` (the exploit or bypass payload). Accounts that only appear in the records (the receiver of a role,
  the actor of a change, the user of the endpoint, the account that granted an application permission) are
  investigated too.
- Records the atomics return: endpoint records (connector GUID, Defender machine id, users, groups,
  isolation capability), detections (verdict, status, ATT&CK ids), process events, file reputation, user
  profiles (risk, roles, groups, `privileged`, last sign-in), sign-ins, risk detections, identity alerts
  (detections without an endpoint), role changes (`user`, `role_name`, `role_definition_id`,
  `directory_scope_id`, `change`, `privileged`, `actor`, `timestamp`, the source's `reference`) and cloud
  applications (permissions, consent type, consenting account, vendor verdict).
- Policy from `config/`: critical assets (domain controllers, executive endpoints and accounts, privileged
  and break-glass accounts by pattern, group or directory role, service accounts), allow-lists, disclosure
  exclusions, blast-radius caps and scoring thresholds.

## Investigation steps

All steps are read-only atomics (`ReadOnlyAdapters`); a failing source becomes a degraded source, never an
error that stops the run.

| Step | Atomic | Subjects | Lookback | What it learns |
|---|---|---|---|---|
| `originating_endpoint` | `investigate_endpoint` | incident hostnames and endpoint ids | 24 h | the device, its users, isolation capability, detections and trajectory |
| `payload_reputation` | `enrich_hash` | incident hashes and hashes named by the endpoint's detections and process events (10 at most) | n/a | per-source verdicts and the aggregate file verdict |
| `account_profile` | `investigate_user` | incident users and user observables, and the directory accounts the endpoint records name | 24 h | profile, roles, groups, risk, identity alerts |
| `privilege_activity` | `search_user_activity` | the same accounts | 7 days | role and group changes made by or to the account, application permission grants, identity alerts |
| `related_profile` | `investigate_user` | the grantees and actors of those changes and the accounts that granted application permissions | 24 h | the same, for the accounts the changes name |
| `related_activity` | `search_user_activity` | the same related accounts | 7 days | further changes made by them (one hop) |
| `authentication` | `investigate_authentication` | every account above | 72 h | sign-ins (IP, app, result, risk) and risk detections: the authentication context of each change |

## Correlation logic

- Records are grouped per endpoint (endpoint, detections, process events, users), per account (profile,
  sign-ins, risk detections, identity alerts) and per privileged change (de-duplicated across the accounts
  whose activity reported it). Framework links: `same_user`, `same_endpoint`, `same_hash` and
  `sign_in_to_activity` (a successful sign-in tied to the account's later change within 1440 minutes).
- **Escalated endpoint**: an investigated endpoint with an active MALICIOUS detection, or a file its records
  name whose aggregate reputation is MALICIOUS. Its users are tied to it.
- **Compromise indicators** of an account. *Strong*: identity risk high or confirmed compromised; a successful
  sign-in rated high risk; a HIGH or CRITICAL risk detection with a successful sign-in; token replay; an
  active identity alert rated malicious. *Weak*: medium identity risk with risk detections; an unresolved
  HIGH identity alert without a classification; using an escalated endpoint.
- **Privileged change**: a role change that assigns, activates or makes eligible a privileged directory role
  (the source's flag or the privileged role list) or a privileged group (Domain Admins, Enterprise Admins,
  Administrators, ...), not removed since; or an application consent that grants a high-privilege permission
  (for example `RoleManagement.ReadWrite.Directory`).
- Each change is classified: **anomalous** when it was granted by a compromised account, received by one, or
  self-assigned (an `assigned` grant the account made to itself; a privileged identity management
  `activated` grant is the normal self-service path and never counts); **pre-existing** when it is dated more
  than 24 hours before the earliest dated compromise record of the account that ties it to the incident;
  **unassessed** when an identity read of the grantee or actor failed; otherwise **normal**.
- **Revoke**: every account that made or received an anomalous change (or granted an anomalous application
  permission). **Disable**: an account with a strong indicator that made or received an anomalous change, a
  compromised account that elevated itself, and an account that received a privilege through an anomalous
  change and has no sign-in before the grant (likely created or staged by the attacker). Other involved
  accounts are shown as considered. **Isolate**: every escalated endpoint that its connector policy allows to
  isolate.

## Risk calculation

Each target is scored by the scoring engine from exactly the records its rule cites (separate
`risk_score` and `confidence_score`, both integers 0-100, with the explanation and settings hash in the
rationale):

- endpoint detections and malicious process events are `endpoint_detection` signals; file reputation is
  `reputation` (one vendor's MALICIOUS is never an aggregate MALICIOUS on its own);
- privileged role changes are `persistence` signals (SUSPICIOUS on their own); privileged grants are this
  workflow's primary evidence, so `persistence` weighs 1.0 here (default 0.8; caps and penalties are not
  overridable);
- identity risk, risky sign-ins and risk detections are `authentication_anomaly` signals;
- the hooks add one `persistence` signal per anomalous grant and account, cited by its role change records:
  MALICIOUS (80) when a compromised account made or received it, SUSPICIOUS (70) when it is only
  self-assigned.

The account and role actions cite the compromise records that make the change anomalous (for example the
exploit detection on the actor's endpoint), so their risk follows that evidence. A failed expected source
(`entra`, `secure_endpoint`) costs confidence and is listed; it never blocks a recommendation that other
evidence supports. Critical assets add the critical-asset bonus to risk; they never change confidence. Minimum
risk per rule: role removal 50, revoke 50, disable 60, isolation 60 (below the minimum an action is listed as
"considered, not proposed", never hidden). Dry run and live score identically.

## Containment recommendations

| Rule | Action (builder) | Target | Evidence (numbered in the package) |
|---|---|---|---|
| `remove_unauthorized_role` | `remove_privileged_role` (`remove_privileged_role`) | `<user>/<roleDefinitionId>` of an anomalous directory role grant still in place (the grant's directory scope is passed) | the role change records and the records that make it anomalous (compromise of the actor or receiver) |
| `revoke_escalation_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | every account that made or received an anomalous change | the change records, the account's profile and its compromise records |
| `disable_escalation_identity` | `disable_user` (`disable_entra_user`) | a compromised identity used for or elevated by the change, a compromised account that elevated itself, an account with no prior sign-in made privileged by the change | the same records (and the profile that shows no prior sign-in) |
| `isolate_originating_endpoint_secure_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`) | an escalated endpoint with a Secure Endpoint connector | the MALICIOUS detections, the endpoint record and the MALICIOUS file reputation answers |
| `isolate_originating_endpoint_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | an escalated endpoint Defender for Endpoint manages (merged with the Secure Endpoint recommendation when both manage it) | the same |

Every recommendation carries numbered evidence that cites investigation or enrichment records of the run
(the lifecycle refuses anything else) and a rationale with the score explanation. An account that the
anomalous change made privileged is passed with `privileged: true`, and its rationale says so: the privilege
under investigation makes the action ELEVATED, never skipped.

### Hand-offs, manual steps and items not proposed

- Manual steps (no VERIFIED write; never in the package): `remove-group-membership:<user>/<group>` for an
  anomalous privileged group membership (do it before the account is ever re-enabled);
  `remove-role-assignment:<user>/<role>` for an anomalous role grant whose record has no role definition id;
  `revoke-app-permissions:<app id>` for an anomalous high-privilege application permission (remove the grants
  and app role assignments, disable the service principal unless sanctioned).
- Considered, not proposed: `remove_privileged_role:<target>` (or `remove-privilege:<user>/<role>`) for a
  normal, pre-existing or unassessed change, with the change reference when the incident reports one;
  `revoke-app-permissions:<app id>` for a normal application grant; `disable_user:<account>` for an involved
  account that is not disabled (no strong indicator, an established account, or unassessed);
  `isolate_endpoint:<host>` for an escalated endpoint that cannot be isolated (connector policy, no endpoint
  product) or whose detection is only SUSPICIOUS.
- Hand-offs: every compromised account to `account-takeover` for the broader account review. This workflow
  keeps its own containment.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed", "Manual
steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion only: it
starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

- Every action, including session revocation, role removal and every later release or restoration, needs an
  explicit human approval by an authenticated HUMAN principal holding the approver role. AI and automation
  principals can never approve, and there is no auto-approval switch.
- ELEVATED approval (a principal with the elevated role, and a visible warning on the decision card)
  applies when a target matches a critical-asset class (a domain controller or executive endpoint; a
  privileged or break-glass account by user pattern, group such as Domain Admins, directory role, the
  identity source's privileged flag, a privileged role granted during the incident, or the `privileged: true`
  context this workflow passes for an account an anomalous change made privileged; a service account), when
  the catalog always elevates the action (`remove_privileged_role` and its restoration
  `restore_privileged_role`), or when a blast-radius cap is exceeded (for example more than three accounts).
  `PackageBuilder` decides this; the workflow only passes investigated asset context and can never lower it.
- An attacker-added privileged account is never shielded by protected-group or privileged-role matching: the
  match makes its actions ELEVATED, it never removes them from the package.
- Allow-listed targets are shown as excluded with the reason and never executed; nothing is dropped silently.

## Containment execution

After the approval the lifecycle executes exactly the approved actions through the execution guard with the
HMAC approval token; the workflow is not involved:

- `remove_privileged_role`: Entra `DELETE /roleManagement/directory/roleAssignments/{id}` (VERIFIED) after the
  adapter resolves `<user>/<roleDefinitionId>` through VERIFIED reads and captures the assignment for the
  release (architecture 14.12.3);
- `revoke_sessions`: Entra `POST /users/{id}/revokeSignInSessions` (VERIFIED, not reversible);
- `disable_user`: Entra `PATCH /users/{id}` with `accountEnabled: false` (VERIFIED), or the native Cisco XDR
  disable action when configured;
- `isolate_endpoint`: Secure Endpoint `PUT /v1/computers/{connector_guid}/isolation` or Defender for Endpoint
  `POST /api/machines/{id}/isolate` (VERIFIED), or the native Cisco XDR action when configured.

A target already in the desired state reports `ALREADY_CONTAINED`. In dry run the lifecycle prints the DRY
RUN block (`Would remove role: ...`, `Would revoke sessions: ...`, `Would disable user: ...`,
`Would isolate: ...`) and changes nothing.

## Verification

Automatic, after execution, with the product's own read call: Entra
`GET /roleManagement/directory/roleAssignments?$filter=principalId eq '..'` (role removal; NOT_VERIFIED while
an assignment of the role remains), `GET /users/{id}?$select=signInSessionsValidFromDateTime` (revocation)
and `accountEnabled` (disable), Defender for Endpoint `GET /api/machineactions/{id}` (isolation). Secure
Endpoint isolation reports `UNABLE_TO_VERIFY` (its isolation-state read is UNVERIFIED), which never counts as
verified. The overall result is CONTAINED, PARTIALLY_CONTAINED or CONTAINMENT_FAILED. Manual steps are not
verified by the workflow; the analyst records them in the incident.

## Rollback

- `remove_privileged_role`: `restore_privileged_role` (Entra `POST /roleManagement/directory/roleAssignments`
  with the captured role, principal and scope), always ELEVATED, only when the assignment proves legitimate.
- `revoke_sessions`: not reversible; the user signs in again.
- `disable_user`: `enable_user` (Entra `accountEnabled: true`), only after the privilege the account received
  was removed and the account was confirmed legitimate.
- `isolate_endpoint`: `release_endpoint` (stop isolation in the product that isolated it). The isolation
  unlock code stays in the Secure Endpoint console and is never copied.
- Manual steps (group membership, application permissions) are reversed by hand and recorded in the incident.

Reversible actions are registered as temporary controls; review reminders never release anything. A release
package is proposed from the registry and executed only after its own human release approval, then verified.

## Failure handling

- A failed or degraded source (health UNAVAILABLE, AUTH_FAILED, RATE_LIMITED) is noted, lowers confidence and
  never blocks a recommendation backed by other evidence: with Secure Endpoint down, an anomalous role grant
  by a high-risk account is still removed, revoked and disabled.
- A change whose grantee or actor could not be assessed (an identity read failed) is shown as considered
  ("unassessed"), never silently dropped and never proposed on a guess.
- A failing step, expression or hook is noted and skipped; partial results stay usable.
- A recommendation without an enabled executor is reported as UNROUTED for manual handling, never dropped.
- During execution a failed action is reported FAILED (PARTIALLY_CONTAINED or CONTAINMENT_FAILED); nothing is
  retried silently and the other approved actions still run.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why the workflow responds |
|---|---|---|---|
| TA0004 Privilege Escalation | T1068 Exploitation for Privilege Escalation | none | An exploit detection on an endpoint shows a process gaining higher privileges; the originating endpoint is isolated and the accounts it was used to change are contained. |
| TA0004 Privilege Escalation | T1548 Abuse Elevation Control Mechanism | T1548.002 Bypass User Account Control | A UAC bypass detection on an endpoint is local privilege escalation; the endpoint is isolated and its users' privilege changes are assessed. |
| TA0003 Persistence | T1098 Account Manipulation | none | A privileged change the source reports without a sub-technique (an administrator assignment, a new privileged account): the privilege is removed, the sessions revoked and the identity disabled when compromised or attacker-created. |
| TA0003 Persistence | T1098 Account Manipulation | T1098.003 Additional Cloud Roles | A privileged Entra directory role or a high-privilege application permission granted by or to a compromised account: the role is removed (always ELEVATED) and the application permissions are a manual step. |
| TA0003 Persistence | T1098 Account Manipulation | T1098.007 Additional Local or Domain Groups | An account added to a privileged local or domain group: the membership removal is a manual step and the account's sessions and identity are contained under ELEVATED approval. |

Account Manipulation keeps the Persistence tactic used by the other workflows that map it (one tactic set per
technique across the catalog). No other technique is mapped: account creation is not observed by any VERIFIED
source, so it is not mapped rather than forced (see Known limitations).

## Testing instructions

- Scenarios: `tests/fixtures/workflows/privilege-escalation/` (the minimum set of 14.5.3; five edge cases:
  protected group self-add, self-assigned role always ELEVATED, privileged identity management activation,
  service principal permissions, Defender-managed endpoint; and the migrated legacy scenarios 01 to 05). They
  run automatically, in dry run and simulated live, in `tests/simulation/test_workflow_scenarios.py`.
- Unit, hook and lifecycle tests: `tests/workflows/privilege_escalation/`.
- Commands:

```bash
python -m pytest -q -p no:cacheprovider tests/workflows/privilege_escalation tests/simulation/test_workflow_scenarios.py -k "privilege-escalation or privilege_escalation"
python tools/validation/check_workflow_readmes.py --workflow privilege-escalation
python tools/simulator/simulate.py --workflow privilege-escalation --scenario tp-approve-all --check
python tools/simulator/simulate.py --workflow privilege-escalation --scenario tp-approve-all --live --check
```

All test data is fake: `example.com` accounts, documentation IP ranges, fake hashes and role ids.

## Known limitations

- Privileged group membership (Active Directory or Entra groups), role assignments whose record carries no role
  definition id and application (service principal) permissions have no VERIFIED write in
  `docs/integrations.md`: removing them is a manual step in the run notes and analyst summary, never a package
  action. Only an Entra directory role assignment is removed by the package.
- With the real adapters role and group changes are not normalized: the Entra directory audit log, group
  membership reads and the servicePrincipals / oauth2PermissionGrants reads are not in `docs/integrations.md`,
  so on a tenant privilege changes come from typed records of another source; Defender XDR alerts (alerts_v2)
  and endpoint detections still feed the compromise assessment and the isolation.
- Whether a change was approved cannot be read from a VERIFIED source (no change-management integration). A
  change reference the incident reports (`trigger.change_reference`) is shown as unverified context and never
  withholds or creates a recommendation; a privileged grant between accounts with no compromise indicator that
  is not self-assigned is shown as considered and the analyst checks the change record.
- Account creation is not observed (no VERIFIED source returns it). An account that receives a privilege
  through an anomalous change and has no sign-in before the grant (72 hours of sign-ins and the profile's last
  sign-in) is treated as created or staged by the attacker and proposed for disable under ELEVATED approval; an
  established account keeps only the revocation and the privilege removal.
- The originating endpoint is an endpoint the incident names (and the users a record places on it); a
  sign-in's device id is not resolved to an endpoint (no atomic), so a privilege change made from an unnamed
  device is contained on the identity side only.
- Session revocation is not reversible, can take a few minutes, does not reach on-premises Kerberos tickets or
  external (guest) users and does not stop application-only tokens of a service principal (the application
  permission manual step covers those).
- Escalation on an endpoint is recognised from an active MALICIOUS detection or a file whose aggregate
  reputation is MALICIOUS; a SUSPICIOUS-only detection is shown as considered, and an endpoint whose connector
  policy forbids isolation, or that no endpoint product manages, is contained by hand. When files rated
  MALICIOUS are the only basis and every one is sanctioned (allow-listed hash, approved tool hash or signer),
  the isolation and the account actions that rest on that endpoint alone (revocation, disable, role removal)
  are withheld and shown as considered (rule `binaries`); the account-takeover hand-off is still suggested.
- Secure Endpoint isolation verifies as UNABLE_TO_VERIFY (its isolation-state read is UNVERIFIED); Defender for
  Endpoint isolation verifies through the machine action status.
