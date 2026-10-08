# Password spray

Workflow `password-spray`, version 2.0.0 (Phase 2), defined in
`src/xdr_response/workflows/password_spray/` (`definition.py` and the pure `hooks.py`). It replaces
the legacy specification of the same id. The binding design is
[docs/architecture.md](../../docs/architecture.md) sections 12 to 14.

## Purpose

Respond to a password spray: one source address tries a few common passwords against many accounts,
which shows up as many failed sign-ins and sometimes a later success. Investigation and
recommendation are automatic. The workflow investigates the targeted accounts and their sign-in
logs, enriches the spray sources (reputation and internal sightings), and recommends one
containment package:

- block the spray source IP (the attacker infrastructure);
- revoke the sign-in sessions of every account the spray signed in to;
- disable an account whose spray success was followed by suspicious activity (confirmed abuse).

The workflow never executes anything. Every action needs human approval first, and only the
lifecycle orchestrator executes it.

## Trigger

- Cisco XDR incident rule: the incident reports the Password Spraying sub-technique (priority 110).
- Cisco XDR incident rule: the incident title matches `*password spray*`, `*password-spray*` or
  `*password spraying*` and the incident carries an `ip` or `ipv6` observable (priority 105).
- Manual: an analyst starts the workflow for an incident or observable. A manual trigger never
  matches automatically.

The deployment's intake receives only the incident id and re-reads the incident through the
VERIFIED Cisco XDR APIs (`tools/deployment/xdr-trigger-workflow.md`).

## Required integrations

- `cisco_xdr`: incident source; verdicts for the spray source addresses (enrich `deliberate/observables`)
  and their sightings (`observe/observables`).
- `entra`: the targeted accounts (Get user) and their sign-in logs (List signIns). After approval it
  executes session revocation (`revokeSignInSessions`) and account disable (`accountEnabled: false`).

A required integration that is disabled or failing never blocks a recommendation that other
evidence supports: the run notes it, lists it as degraded and confidence drops.

## Optional integrations

- `virustotal`: second reputation opinion on public spray sources only (the disclosure policy
  decides; non-public addresses are never sent).
- `alienvault_otx`: third reputation opinion, same disclosure rule.
- `meraki`: executes an approved IP block as one tagged MX L3 firewall rule (verified by reading the
  rule set back).
- `defender_endpoint`: alternative route for an approved IP block (an `IpAddress` indicator).
- `microsoft_cloud`: advanced hunting for internal sightings of a spray source; rows stay generic
  records (citable, not scored).
- `splunk`: optional SIEM searches for sign-ins and sightings; rows stay generic records.

## Input data

- `ip` and `ipv6` observables: the spray sources named by the detection.
- `user` and `email_address` observables and the incident's `users`: the targeted accounts.
- Sign-in records of those accounts (time, source address, application, result, risk level), user
  profiles (groups, directory roles, risk), vendor anomaly records, IP reputation and sightings.

An address the incident does not name becomes a spray source only when its failed sign-ins hit at
least 3 distinct targeted accounts.

## Investigation steps

1. `targeted_accounts`: `investigate_user` for every targeted account (profile, groups, roles, risk,
   anomalies).
2. `sign_in_history`: `investigate_authentication` for every targeted account (sign-in log of the
   last 24 hours).
3. `source_reputation` and `source_reputation_v6`: `enrich_ip` for the incident addresses plus any
   address whose failed sign-ins hit 3 or more targeted accounts (IPv4 and IPv6 separately).
4. `source_sightings` and `source_sightings_v6`: `search_ip_enterprise` for the same addresses
   (internal endpoints talking to them, or an internal endpoint owning them).

Each step reads only; a failing source becomes a degraded source status and the other sources
still answer. At most 50 subjects per step; the rest are listed in the run notes.

## Correlation logic

The framework links the typed records: a spray source mentioned by the sign-ins of two or more
accounts becomes a `same_ip` link (the spray fan-out) and an account seen with several addresses a
`same_user` link; the window is 60 minutes. The workflow hook then derives, from the records only:

- per spray source: the accounts that failed, the accounts that signed in, the reputation verdicts,
  the internal sightings and whether an investigated endpoint owns the address;
- per account with a successful sign-in from a spray source: the successes, the failures from spray
  sources and the suspicious activity that followed (an `impossible_travel`, `mfa_fatigue`,
  `new_device` or `token_replay` anomaly, a high Entra account risk or a confirmed compromise, or a
  high-risk successful sign-in). An unfamiliar location alone does not count: every spray success
  from an external address has one.

A source is shared infrastructure (never recommended for a block) when a source rates it CLEAN and
no source rates it MALICIOUS or SUSPICIOUS, or when internal endpoints talk to it.

## Risk calculation

Sign-ins carry no score on their own. The hook derives behavioural `authentication_anomaly`
signals that cite the sign-in records they were computed from, attributed to the integration that
produced those records:

| Pattern | Severity |
|---|---|
| failed sign-ins from one source against 2 to 4 accounts | 60 |
| failed sign-ins from one source against 5 or more accounts | 70 |
| the spray succeeded from this source | 80 |
| an account signed in successfully from a spray source | 75 |

Vendor anomalies, a high Entra risk level and IP reputation add the framework signals
(`docs/threat-scoring.md`); one vendor's reputation alone is capped by the engine and is never an
aggregate MALICIOUS verdict. Risk and confidence are separate scores. A failed source lowers
confidence and never blocks the recommendation. Dry run and live score identically.

## Containment recommendations

| Rule | Action (builder) | When | Minimum risk |
|---|---|---|---|
| `block_spray_source` | `block_ip` (`block_ip`) | every spray source that is neither shared infrastructure nor an internal endpoint | 30 |
| `revoke_sprayed_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | an account with a successful sign-in from a spray source | 50 |
| `disable_compromised_account` | `disable_user` (`disable_entra_user`) | the same, followed by suspicious activity | 60 |

Every recommendation carries numbered evidence (the sign-in, anomaly, profile and reputation
records it cites, never a computed statement) and separate risk and confidence scores. A rule
item without a record is reported as not proposed (no evidence); one under its minimum risk is
listed below threshold. Failed attempts alone never revoke or disable an account.

### Hand-offs and items not proposed

- Not proposed, and listed as considered: a spray source that is shared infrastructure (rated CLEAN, or internal endpoints talk to it) or the address of an internal endpoint.
- Hand-off to `account-takeover` for every account that signed in successfully from a spray source.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed", "Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

Every recommended action needs human approval before anything changes, including session
revocation. ELEVATED approval (a lead holding the elevated approver role) applies when:

- the target is a critical asset, for example a privileged account (`adm-*`, `breakglass*`,
  Domain Admins, Global Administrator or another privileged directory role) or a protected address
  range: the decision card shows a visible warning and an analyst alone cannot approve;
- a blast-radius cap is exceeded (for example more than 3 users or more than 50 indicators in one
  package): every action of that kind becomes ELEVATED with a warning.

Allow-listed targets (for example never-block ranges) are shown as excluded and never executed.
AI and automation principals can never approve. A critical asset is never skipped silently.

## Containment execution

After the human decision the orchestrator executes the approved actions automatically, never the
workflow: `block_ip` routes native first (a configured Cisco XDR response action), then Meraki MX
or Defender for Endpoint; `revoke_sessions` and `disable_user` run on Entra ID. Unapproved actions
are recorded as rejected by the analyst. Dry run produces the exact DRY RUN report and changes
nothing.

## Verification

Verification is automatic after execution: the Meraki L3 rule set or the Defender indicator is read
back for the IP block, `accountEnabled` for the disable and `signInSessionsValidFromDateTime` (at
or after the action time) for the session revocation. Each result is VERIFIED, NOT_VERIFIED or
UNABLE_TO_VERIFY.

## Rollback

The IP block (`unblock_ip`) and the account disable (`enable_user`) are temporary controls in the
registry. Restoring them needs a separate human release approval; closing the incident never
removes them. Session revocation is not reversible: the user signs in again. Before re-enabling an
account, reset its password and re-register MFA (manual steps).

## Failure handling

- A failed or degraded source (reputation, sign-in log, sightings) is noted and listed as degraded;
  it never blocks a recommendation backed by other evidence.
- A failed action is reported as FAILED (containment PARTIALLY_CONTAINED) and never retried
  silently; the other approved actions still run.
- A rule or hook problem is noted and never crashes the run; an action with no execution path is
  reported unrouted for manual handling.

## MITRE mapping

| Tactic | Technique | Sub-technique | Responds with |
|---|---|---|---|
| TA0006 Credential Access | T1110 Brute Force | T1110.003 Password Spraying | IP block, and the account actions |
| TA0001 Initial Access | T1078 Valid Accounts | T1078.004 Cloud Accounts | session revocation, account disable |

A successful sign-in from a spray source is the use of a valid Entra ID (cloud) account.

## Testing instructions

- Scenarios: `tests/fixtures/workflows/password-spray/` (the minimum set of 14.5.3, three
  `edge-*` scenarios and the six migrated `legacy-*` scenarios). They run automatically in
  `tests/simulation/test_workflow_scenarios.py`, in dry run and simulated live.
- Unit and lifecycle tests: `tests/workflows/password_spray/`.

```
python -m pytest -q -p no:cacheprovider tests/workflows/password_spray tests/simulation/test_workflow_scenarios.py -k password-spray
python tools/validation/check_workflow_readmes.py --workflow password-spray
python tools/simulator/simulate.py --workflow password-spray --scenario tp-approve-all --check
```

All test data is fake (`example.com`, documentation address ranges).

## Known limitations

- Targeted accounts must be named by the incident; no VERIFIED read lists Entra sign-ins by source
  address, so an account the incident does not name is not investigated.
- Entra Identity Protection risk detections are not a VERIFIED read: anomaly records come only from
  sources with a typed mapping, so in production a follow-on is mostly a high sign-in risk level.
- Sightings from Cisco XDR, Defender XDR advanced hunting and Splunk stay generic records: they are
  citable but cannot mark a source as shared infrastructure until a typed mapping exists.
- Shared egress is recognised only from evidence (a CLEAN verdict or internal sightings); an
  unrated cloud or partner egress address is still recommended and the analyst decides.
- Session revocation is not reversible; password reset and MFA re-registration are manual
  follow-up steps (`reset_password` and `reset_mfa` are UNVERIFIED).
- Direct Umbrella IP blocking is UNVERIFIED (conflict in `docs/integrations.md`): an IP block routes
  to Meraki, Defender for Endpoint or a configured Cisco XDR native action, otherwise it is reported
  unrouted for manual handling.
- An internal spray source (an address an investigated endpoint owns) is not blocked at the
  perimeter; contain the endpoint through the lateral-movement workflow.
- A source that is shared infrastructure or internal is not proposed; it is listed as considered in
  the run notes and the analyst summary, not on the decision card (which shows the package only).
