# Business email compromise

Workflow id `bec`, version 1.0.0, Phase 2, default severity HIGH. Definition:
`src/xdr_response/workflows/bec/definition.py`; pure hooks: `src/xdr_response/workflows/bec/hooks.py`.
Binding design: `docs/architecture.md` sections 13 and 14.

## Purpose

Investigate a mailbox used for payment fraud or impersonation and recommend containment. The
workflow covers three shapes of business email compromise:

- a compromised **internal mailbox** (stolen credentials or session) that sends payment-change
  requests to colleagues, often after creating mailbox rules that forward or hide mail;
- an **external sender** that impersonates the organisation, an executive or a vendor from a
  look-alike or gateway-flagged domain;
- a mailbox whose **OAuth consent** gives an unverified application access to the mail.

Investigation and recommendation are automatic. The workflow never executes anything: it produces
a containment package with numbered evidence and separate risk and confidence scores, and a human
decides. Approved containment then runs automatically through the lifecycle orchestrator.

## Trigger

- `xdr_incident_rule` (priority 110): the incident's ATT&CK techniques include `T1534`,
  `T1114.003` or `T1656` (a reported sub-technique also matches its parent).
- `xdr_incident_rule` (priority 100): the incident title names business email compromise or payment
  fraud (`*business email compromise*`, `BEC *`, `* BEC *`, `*(BEC)*`, `*bank detail*`,
  `*wire transfer*`, `*payment change*`, `*payment request*`, `*forwarding rule*`, `*inbox rule*`)
  and the incident carries an email address, message id, user or domain.
- `manual`: an analyst starts the workflow for an incident or a mailbox.

An incident whose `workflow_id` is `bec` always runs this workflow. The deployment trigger (incident
or webhook rule that sends only the incident id) is described in
`tools/deployment/xdr-trigger-workflow.md`.

## Required integrations

These are the expected sources: when one is disabled or failing, the run notes it and confidence
drops, but other evidence still produces a recommendation.

- `entra`: mailbox account profile (`investigate_user`), sign-ins and MFA events
  (`investigate_authentication`); executes session revocation and account disable after approval.
- `secure_email`: reported and related messages (`investigate_email`, `search_email_campaign`);
  executes the message quarantine after approval.

## Optional integrations

- `umbrella`: sender-domain reputation (`enrich_domain`); executes the DNS-layer domain block after
  approval.
- `virustotal`: second opinion on sender-domain and sign-in IP reputation; public values only (the
  disclosure policy never sends internal or documentation-range values).
- `cisco_xdr`: XDR enrichment of IPs, domains and addresses; native response actions where the
  operator configured them.
- `microsoft_cloud`: Defender XDR alerts and hunting rows about the mailboxes and messages (cited as
  context; hunting rows are generic records and never scored).
- `defender_o365`: alternative executor for the message quarantine (no read path is used).
- `secure_endpoint`: endpoint telemetry of the incident's hosts (`investigate_endpoint`); executes
  the endpoint isolation after approval.
- `splunk`: SIEM rows about sign-ins, mailbox activity and messages (cited as context).

## Input data

From the incident: message ids (`email_message_id`), sender and mailbox addresses
(`email_address`), users (`user` observables and `incident.users`), sender domains (`domain`),
sign-in IPs (`ip`) and hosts (`hostname`). Values found by earlier steps feed later steps (message
senders become mailboxes to investigate, sender domains are enriched, successful sign-in IPs are
enriched). Lab scenarios provide typed records through the simulated adapters.

## Investigation steps

All steps are read-only atomics (`docs/architecture.md` 14.1); a failing source is noted and never
stops the run.

1. `reported_messages`: `investigate_email` for every incident message id (sender, recipients,
   gateway verdict, threat types, SPF/DKIM/DMARC, delivery location, campaign id).
2. `related_messages`: `search_email_campaign` for the same messages (the rest of the campaign,
   across all recipients).
3. `sender_addresses`: `enrich_email_address` for every sender and incident address.
4. `sender_domains`: `enrich_domain` for every incident domain and message sender domain.
5. `mailboxes`: `investigate_user` (72 h lookback) for incident users and addresses and every
   message sender: profile (groups, roles, risk), mailbox rules, OAuth app consents, role changes.
   External senders have no tenant account and come back empty.
6. `sign_ins`: `investigate_authentication` (72 h lookback) for the same subjects: sign-ins, MFA
   events and identity-protection anomalies.
7. `sign_in_ips`: `enrich_ip` for incident IPs, successful sign-in IPs and approved-MFA IPs.
8. `endpoints`: `investigate_endpoint` for the incident's hosts (endpoint telemetry: detections,
   isolation state, logged-on users).

## Correlation logic

Framework links over the run's records within a 4-hour window: `sign_in_to_activity` (a successful
sign-in followed by a mailbox rule or OAuth consent for the same user), `campaign` (messages sharing
a campaign id, or a sender domain plus URL or attachment), `same_ip`, `same_domain`, `same_user`,
`same_endpoint` and `email_to_click`. The workflow hook adds one `workflow` link per tenant mailbox
that is also the sender of investigated messages, so the account and the fraud it sent form one
cluster in the blast radius.

The hook also computes, from the records only, the facts the rules use (`facts.mailboxes`,
`facts.fraud_messages`, `facts.impersonation_domains`):

- **identity compromise** of a tenant mailbox: Entra risk state confirmed compromised or user risk
  high; a successful sign-in or an approved MFA prompt from an IP whose enrichment is malicious or
  suspicious; an MFA prompt the user reported as fraud; a HIGH or CRITICAL anomaly;
- **mailbox abuse**: an enabled rule forwarding or redirecting mail outside
  `exclusions.internal_domains`, an enabled rule deleting messages, an OAuth consent with mailbox
  permissions that is rated malicious or suspicious or comes from an unverified publisher, or a sent
  message the mail gateway flagged;
- **fraud message**: still in a mailbox (not quarantined, deleted or failed) and sent by a mailbox
  with compromise evidence, flagged by the gateway, or sent from a look-alike domain;
- **impersonation domain**: the sender domain (never a tenant mailbox's own) of a flagged message or
  a look-alike of an organisation domain. Organisation domains are the domains of tenant mailboxes,
  incident users and inbound recipients. The look-alike test is a deterministic heuristic over the
  registrable label: homoglyph digits, one edit, the organisation name as a hyphenated token, or the
  same name under another suffix.

## Risk calculation

Each target is scored by the scoring engine (`docs/threat-scoring.md`) from the records its rule
cites, plus the target's malicious or suspicious enrichment and the hook signals about it:

- identity: Entra risk (`user_profile`), anomalies, and the hook signal "successful sign-in or
  approved MFA from an IP rated malicious (severity 80) or suspicious (60)" and "the user reported an
  MFA prompt as fraud" (70), category `authentication_anomaly`;
- persistence: external forwarding or deleting mailbox rules (70), OAuth consents (vendor verdict, or
  the hook signal for an unverified app with mailbox access, 60);
- email: the gateway verdict of the message, and the hook signal "sender domain is a look-alike of an
  organisation domain" (70), category `email_verdict`;
- reputation of sign-in IPs and domains (capped at 50 by the engine), endpoint detections.

Workflow weights: `persistence` 0.9 and `email_verdict` 0.9 (forwarding rules and gateway verdicts
are the core of BEC); every other category keeps the default. Risk and confidence are separate
integers; a single source stays below CRITICAL; a failed expected source lowers confidence only. The
explanation line with the settings hash is appended to every rationale.

## Containment recommendations

| Rule | Action (builder) | When | Minimum risk |
|---|---|---|---|
| `revoke_compromised_mailbox_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | tenant mailbox with identity compromise or mailbox abuse | 40 |
| `disable_abused_mailbox` | `disable_user` (`disable_entra_user`) | identity compromise **and** mailbox abuse | 50 |
| `quarantine_fraud_messages` | `quarantine_email` (`quarantine_email`) | every fraud message still in a mailbox, by message id | 40 |
| `block_impersonation_domain` | `block_domain` (catalog order: Umbrella, Defender for Endpoint, native) | impersonation domain whose enrichment is not clean | 40 |
| `isolate_infected_endpoint` | `isolate_endpoint` (catalog order) | investigated endpoint with an active malicious detection | 60 |

Evidence of each action is exactly the records its rule cites (profile, sign-ins, IP enrichment,
anomalies, MFA events, mailbox rules, OAuth consents, messages, detections), numbered by
`PackageBuilder`. A target below its minimum risk is reported as "considered, not proposed", never
dropped silently.

Manual steps (no action type and no VERIFIED write endpoint in `docs/integrations.md`). Steps 1 to 3
are named in the rationale of the identity and domain actions (package report and `PACKAGE_PROPOSED`
audit record), and the rule removal and consent revocation are also listed as manual steps in the run
notes and the analyst summary (the decision card shows the package only). The analyst follows this
list:

1. Remove the malicious inbox or forwarding rule(s) from the mailbox (the rationale names each rule
   and its id).
2. Revoke the OAuth consent of a risky application.
3. Block the sender address or domain at the mail gateway (the DNS-layer block does not stop
   inbound mail).
4. Reset the password and re-register MFA before the account is re-enabled.
5. Finance: hold payments to changed bank details until each change is verified by phone with a
   known contact, never with contact details taken from the email.

### Hand-offs and items not proposed

- Manual steps (no VERIFIED write exists): remove each malicious mailbox rule, revoke each risky OAuth consent. They are listed per mailbox with the record that shows them.
- Hand-off to `account-takeover` for every mailbox with identity compromise behind the abuse.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed", "Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

Every recommended action needs human approval before it runs, including session revocation (which
cannot be undone), and every restoration needs a separate human release approval. AI and automation
principals can never approve, and the workflow never chooses or changes an approval level.

ELEVATED approval (a lead holding the elevated-approver role) applies when `PackageBuilder` finds:

- a critical asset: for this workflow typically an executive mailbox (group `Executives`), a
  privileged or break-glass account (for example `breakglass*`, Global Administrator and other
  privileged directory roles), a service or automation account, or a critical endpoint;
- an action type that is always ELEVATED in the catalog;
- a blast-radius cap exceeded (`thresholds.blast_radius`, for example more users than `max_users`
  or more messages than `max_messages`).

A critical asset is never skipped: the action stays in the package with the warning on the
decision card. Allow-listed targets (`allowlists.never_block`, for example the organisation's own
domains) are shown as excluded and never executed.

## Containment execution

After approval, the lifecycle orchestrator executes the approved actions automatically through the
guard with the approval token; the workflow is not involved. Routes (native first, then direct):

- `revoke_sessions`: Entra `POST /users/{id}/revokeSignInSessions` (direct only).
- `disable_user`: Entra `PATCH /users/{id}` with `accountEnabled: false`, or the XDR native action.
- `quarantine_email`: Secure Email Threat Defense `POST /v1/messages/move` to `quarantine`, or
  Defender for Office 365 remediation, or the XDR native action.
- `block_domain`: Umbrella destination list, Defender for Endpoint indicator, or the XDR native
  action.
- `isolate_endpoint`: Secure Endpoint or Defender for Endpoint, or the XDR native action.

In dry run (the default) nothing is executed: the package is simulated and the output starts with
`DRY RUN`.

## Verification

Every executed action is verified automatically by reading the target state back: Entra
`signInSessionsValidFromDateTime` (revocation) and `accountEnabled` (disable), Secure Email message
status (quarantine), the Umbrella destination list (domain block), Defender for Endpoint machine
action (isolation). Where no VERIFIED read exists (Secure Endpoint isolation, Defender for Office 365
remediation) the result is `UNABLE_TO_VERIFY`, never assumed.

## Rollback

| Action | Rollback | Notes |
|---|---|---|
| `revoke_sessions` | not reversible | the user signs in again after the password reset |
| `disable_user` | `enable_user` | only after the password reset and MFA re-registration |
| `quarantine_email` | `release_email` | Secure Email moves the message back to the inbox with the recorded verdict |
| `block_domain` | `unblock_domain` | removes the destination recorded at containment time |
| `isolate_endpoint` | `release_endpoint` | after the endpoint is cleaned |

Reversible actions create temporary controls in the registry. Removing them needs a separate human
release approval; closing the incident never removes a control.

## Failure handling

- A failed or degraded source (for example Entra unavailable) is noted, lowers confidence and never
  blocks a recommendation backed by other evidence; identity actions are not proposed without
  identity evidence.
- A step, expression or hook problem is noted and skipped; the rest of the run continues.
- An action with no enabled executor is reported as unrouted for manual handling, never dropped.
- A failed action is reported as `FAILED` and the package as `PARTIALLY_CONTAINED`; nothing is
  retried silently.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why this workflow responds |
|---|---|---|---|
| TA0001 Initial Access | T1078 Valid Accounts | T1078.004 Cloud Accounts | fraud sent from a tenant mailbox whose credentials or session the adversary uses |
| TA0009 Collection | T1114 Email Collection | T1114.003 Email Forwarding Rule | rules forwarding or redirecting mail outside the organisation |
| TA0005 Defense Evasion | T1564 Hide Artifacts | T1564.008 Email Hiding Rules | rules that delete messages hide the victim's replies |
| TA0008 Lateral Movement | T1534 Internal Spearphishing | | a compromised internal mailbox sends fraud to colleagues |
| TA0005 Defense Evasion | T1656 Impersonation | | a look-alike or flagged domain impersonates the organisation, an executive or a vendor |

No technique is mapped without a rule or investigation step that responds to it.

## Testing instructions

- Scenarios (simulation fixtures, format of `docs/architecture.md` 14.5.2):
  `tests/fixtures/workflows/bec/` (the minimum set, three edge cases and the six migrated legacy
  scenarios).
- Unit tests (rules, hooks, definition): `tests/workflows/bec/`.

```
python -m pytest -q -p no:cacheprovider tests/workflows/bec tests/simulation/test_workflow_scenarios.py -k bec
python tools/validation/check_workflow_readmes.py --workflow bec
python tools/simulator/simulate.py --workflow bec --scenario tp-approve-all --check
python tools/simulator/simulate.py --workflow bec --scenario tp-approve-all --live --check
```

All test data is fake: `example.com`, `*.example`, `*.test`, documentation IP ranges, hosts like
`TH-LT-1047`, users like `jsmith@example.com`.

## Known limitations

- No action type and no VERIFIED write endpoint exist for removing a mailbox rule, revoking an OAuth
  consent or blocking a sender at the mail gateway: these are manual steps named in the rationale and
  in this README.
- Mailbox rules, OAuth app consents and typed message records come only from sources whose field
  schema is documented; with today's real adapters Secure Email message search, Splunk rows and
  Defender hunting rows stay generic records (cited, never scored), so the quarantine and domain
  rules need typed message records.
- Password and MFA-method changes have no record kind yet; they appear only as generic records and
  are not scored.
- Look-alike detection is a deterministic heuristic over the registrable label; it does not handle
  internationalised (IDN) domains or public suffixes beyond common two-level ones.
- Quarantine through Secure Email takes its move verdict from
  `integrations.secure_email.options.quarantine_verdict`, and through Defender for Office 365 needs the
  message's single recipient. Without them the quarantine is reported unrouted for manual handling; the
  workflow never invents either.
- The DNS-layer domain block stops users and endpoints from reaching the domain; it does not stop
  inbound mail. Free-mail, partner and the organisation's own domains must be in
  `allowlists.never_block.domains`, otherwise a gateway-flagged message can lead to a (human-reviewed)
  block recommendation.
- Only senders, incident users and incident addresses are investigated as mailboxes; recipients who
  replied or paid are not investigated automatically.
