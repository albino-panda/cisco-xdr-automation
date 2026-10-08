# Phishing

Phase 2 workflow `phishing` (definition version 1.0.0). Code: `src/xdr_response/workflows/phishing/`
(`definition.py`, `hooks.py`). It replaces the legacy plan-rule spec (`workflow.yaml` and its five
scenarios), whose scenarios were migrated to typed simulation scenarios (`legacy-01` to `legacy-05`).
The binding design is `docs/architecture.md` sections 12 to 14.

## Purpose

Triage a reported or detected credential-phishing message. The workflow investigates the message, its
sender and sending infrastructure, its URLs, domains and attachments, the recipients, the recipients
who clicked, authentication after the click and endpoint activity after the click. It then
**recommends** one containment package for a human to approve:

- quarantine every delivered copy of the confirmed phishing messages (the campaign included);
- block phishing URLs (on otherwise legitimate hosts), phishing domains and malicious attachment hashes;
- revoke the sign-in sessions of recipients who clicked and then signed in or were flagged;
- disable an account where the evidence justifies it;
- isolate an endpoint with malicious activity after the click.

Users whose sessions are revoked are handed off to the account-takeover workflow (the rationale of
every account action says so). The workflow never executes anything itself: investigation and
recommendation are automatic, approval is human, and approved actions execute and verify through the
Phase 0 lifecycle.

## Trigger

Automatic triggers (XDR Automation incident rule or webhook that sends only the incident id; the
incident is re-read through the VERIFIED APIs, see `tools/deployment/xdr-trigger-workflow.md`):

| Priority | Matches when |
|---|---|
| 110 | the incident's detection reports the phishing technique or one of its sub-techniques |
| 100 | the source is Secure Email Threat Defense (`secure_email`) and the incident carries an `email_message_id` (verdict changed after delivery, user-reported phish) |
| 90 | the title matches `*phish*` and the incident carries an `email_message_id` |

Manual trigger: an analyst starts the workflow for an incident (the legacy pivot-menu and playbook-task
entry points). An incident whose `workflow_id` is `phishing` always runs this workflow.

## Required integrations

These are the expected sources: when one is disabled or failing the run notes it and confidence drops,
but recommendations backed by other evidence are still made.

- `secure_email`: message facts and the campaign search (VERIFIED `POST /v1/messages/search`);
  quarantines delivered copies (VERIFIED `POST /v1/messages/move`) and verifies them (VERIFIED
  `POST /v1/messages/status`).
- `entra`: recipient profiles, roles and risk, sign-ins after the click (VERIFIED Graph user and
  sign-in reads); revokes sessions and disables accounts (VERIFIED).
- `umbrella`: domain status and categorization (VERIFIED Investigate read); blocks domains and URLs
  through a destination list (VERIFIED) and verifies the list.

## Optional integrations

- `defender_o365`: quarantines delivered copies through `analyzedEmails/remediate` (VERIFIED) when
  Secure Email is not enabled. It has no VERIFIED read API, so it adds no investigation records, and its
  remediation is UNABLE_TO_VERIFY.
- `virustotal`: second opinion on URL, domain, IP and attachment reputation; the disclosure policy
  never sends internal domains, internal URLs or addresses to it.
- `alienvault_otx`: threat-intelligence context on URLs, domains, sending IPs and attachments.
- `secure_endpoint`: endpoint facts, detections and trajectory after the click; isolates an endpoint
  (VERIFIED `PUT /v1/computers/{guid}/isolation`).
- `defender_endpoint`: endpoint facts after the click; isolates (VERIFIED) and blocks attachment
  hashes, URLs and domains through indicators (VERIFIED).
- `cisco_xdr`: sightings of the message, domains and attachments (citable generic records); executes an
  approved action natively when the operator configured the native action id.
- `microsoft_cloud`: Defender XDR alerts and advanced-hunting rows about the message, domains,
  attachments and users (citable generic records in production; typed DNS and network clicks in the lab).

## Input data

The incident (Phase 0 `Incident`) with any of these observables: `email_message_id` (needed for the
message and campaign steps), `email_address` (sender), `url`, `domain`, `ip` (sending infrastructure),
`sha256` (attachment), `user` (reporting or affected recipient), `hostname`. `incident.users` lists the
reporting or affected recipients. Values found by earlier steps feed later steps (message URLs, domains,
attachments, recipients, clicking endpoints and users).

## Investigation steps

All steps are reads through the read-only adapter facade; a failing source becomes a degraded source and
never stops the run.

| Step | Atomic | Subjects |
|---|---|---|
| `message` | `investigate_email` | incident message ids |
| `campaign` | `search_email_campaign` | incident message ids (same campaign, sender, URL or attachment) |
| `sender_reputation` | `enrich_email_address` | incident sender addresses and message senders (max 10) |
| `url_reputation` | `enrich_url` | incident URLs and message URLs |
| `domain_reputation` | `enrich_domain` | incident domains, URL hosts, message domains, sender domains |
| `sending_infrastructure` | `enrich_ip` | incident IP addresses (max 10) |
| `attachment_reputation` | `enrich_hash` | incident hashes and message attachment hashes |
| `click_activity` | `search_domain_enterprise` | the domains the messages and incident carry (who resolved or contacted them) |
| `attachment_activity` | `search_hash_enterprise` | attachment hashes (which endpoints saw them) |
| `post_click_endpoints` | `investigate_endpoint` | endpoints from click and attachment activity, incident hosts |
| `recipients` | `investigate_user` | reported users, recipients, clicking users, endpoint users (max 50) |
| `authentication_after_click` | `investigate_authentication` | reported, clicking and endpoint users |

## Correlation logic

Framework links over a 24-hour window (`window_minutes: 1440`): `email_to_click` (a recipient's
endpoint or account reaches a domain the message carried after delivery), `campaign` (messages sharing
a campaign id, or a sender domain and a URL or attachment), `sign_in_to_activity` and the
shared-indicator, shared-user and shared-endpoint links.

The workflow hooks (`hooks.py`, pure, no adapter access) turn the records into facts, each carrying
the record ids it was computed from:

1. **Confirmed phishing message**: the gateway rates it MALICIOUS or SUSPICIOUS, or it carries a URL,
   domain (or parent domain) or attachment whose aggregate verdict is MALICIOUS or SUSPICIOUS or that an
   endpoint detected, or a `campaign` link ties it to a confirmed message (up to two gateway-rated
   siblings are cited).
2. **Phishing indicators**: domains (URL hosts, message domains, sender domains, incident domains) and
   attachment hashes of confirmed messages rated MALICIOUS or SUSPICIOUS; URLs rated so whose host is
   not under a listed domain (a domain block already covers those URLs).
3. **Clicks**: `email_to_click` links of a confirmed message whose DNS or network record reaches a
   listed domain, the host of a listed URL or a listed URL, attributed to the recipient (directly, or
   through an endpoint record that names the recipient).
4. **Compromised users**: clicking recipients with a successful sign-in after the click, a risk
   detection after the click, or an at-risk identity. Disabling is justified when the identity provider
   confirmed the compromise, or a post-click sign-in comes with high user risk or a HIGH or CRITICAL
   risk detection.
5. **Compromised endpoints**: endpoints with a MALICIOUS or SUSPICIOUS detection or process event that
   names a malicious attachment, or that happened on a clicking endpoint after the click.

## Risk calculation

Default category weights; caps, corroboration and penalties come from `config/thresholds.yaml`
(`docs/threat-scoring.md`). Each target is scored from the records its rule cites: the gateway's
message verdict (`email_verdict`), URL, domain, IP and attachment reputation (`reputation`, capped),
endpoint detections, DNS and network clicks with a verdict (`network_behaviour`), identity risk
detections and profile risk (`authentication_anomaly`), plus one workflow-derived
`authentication_anomaly` signal for a successful sign-in after a phishing click (severity 70, attributed
to the identity source and citing the sign-in and click records). Risk and confidence are separate
integers; the explanation (with the settings hash) is appended to every rationale. A failed expected
source lowers confidence; it never blocks a recommendation.

Thresholds (below them an action is listed as "considered, not proposed", never silently dropped):
risk 60 for quarantine, URL, domain, hash, session revocation and isolation; risk 70 for disabling an
account. Reputation alone is capped at 50, so an indicator is proposed only when a phishing message,
a click or an endpoint detection backs it.

## Containment recommendations

| Rule | Action (builder) | Target | When |
|---|---|---|---|
| `quarantine_phishing_message` | `quarantine_email` (`quarantine_email`; Secure Email verdict from `integrations.secure_email.options.quarantine_verdict`, Defender for Office 365 recipient from the message) | message id | a confirmed phishing message that is still delivered (inbox, junk or unknown) |
| `block_phishing_url` | `block_url` (`block_url`) | URL | a phishing URL whose host is not itself rated malicious |
| `block_phishing_domain` | `block_domain` (`block_domain_umbrella`) | domain | a domain of the confirmed messages rated MALICIOUS or SUSPICIOUS |
| `block_malicious_attachment` | `block_hash` (`block_hash`) | SHA-256 | an attachment rated MALICIOUS or SUSPICIOUS, or detected on an endpoint |
| `revoke_clicked_user_sessions` | `revoke_sessions` (`revoke_entra_sessions`) | user | a compromised user (see correlation 4); hand-off to account-takeover |
| `disable_compromised_user` | `disable_user` (`disable_entra_user`) | user | a compromised user where disabling is justified; hand-off to account-takeover |
| `isolate_compromised_endpoint` | `isolate_endpoint` (`isolate_secure_endpoint`) | hostname | a compromised endpoint managed by Secure Endpoint |
| `isolate_compromised_defender_endpoint` | `isolate_endpoint` (`isolate_defender_endpoint`) | hostname | a compromised endpoint managed by Defender for Endpoint |

Every recommendation carries numbered evidence that cites real investigation and enrichment records
(`EvidenceBuilder`), plus the target's MALICIOUS or SUSPICIOUS enrichment answers. Allow-listed targets
stay in the package as excluded with their reason (for example an owned domain); a URL on an owned
domain listed in `url_block_allowed_domains` can still be blocked. An action with no execution path is
reported as unrouted for manual handling.

### Hand-offs and items not proposed

- Hand-off to `account-takeover` for every recipient who signed in or was flagged by the identity provider after clicking.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed", "Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

Every action needs human approval before anything changes, including session revocation, the
quarantine and every block; AI and automation principals can never approve. ELEVATED approval (an
approver with the elevated role) applies when `PackageBuilder` finds a critical asset (for example a
privileged account by role or group, an executive endpoint, a production server) or a blast-radius cap
is exceeded (`max_messages` for quarantines, `max_indicators` for URL, domain and hash blocks,
`max_users`, `max_endpoints`). ELEVATED actions carry a visible warning in the decision card; they are
never skipped silently. The workflow never chooses an approval level itself.

## Containment execution

After approval the lifecycle executes the approved actions automatically through the execution guard,
native first: a Cisco XDR native response action when the operator configured its id, otherwise the
pinned or catalog-order product (Secure Email, then Defender for Office 365 for quarantine; Umbrella
for domains and URLs; Defender for Endpoint indicators for hashes; Entra for accounts; Secure Endpoint
or Defender for Endpoint for isolation, as the rule pins). Unselected actions are recorded as rejected
by the analyst and never executed. In dry run the package is simulated and nothing is executed.

## Verification

Verification is automatic after execution: Secure Email message status, Umbrella destination-list
read, Entra `accountEnabled` and `signInSessionsValidFromDateTime`, Defender for Endpoint machine
action status. Secure Endpoint isolation, Secure Endpoint file lists, Defender indicators and Defender
for Office 365 remediation have no VERIFIED read, so they report UNABLE_TO_VERIFY.

## Rollback

Restoration needs a separate human release approval and uses the temporary-control registry:

| Action | Rollback |
|---|---|
| `quarantine_email` | `release_email` (Secure Email move to inbox with the recorded verdict; Defender for Office 365 move to inbox) |
| `block_url` / `block_domain` | `unblock_url` / `unblock_domain` (Umbrella destination removal by id) |
| `block_hash` | `unblock_hash` |
| `disable_user` | `enable_user` |
| `isolate_endpoint` | `release_endpoint` |
| `revoke_sessions` | not reversible; the account-takeover review is the follow-up |

## Failure handling

- A failed or degraded source is listed (`degraded_sources`), lowers confidence and never blocks a
  recommendation backed by other evidence.
- A step whose subjects are missing is skipped with a note; a hook, rule or builder problem is noted,
  never a crash.
- A failed action is reported FAILED and the package result is PARTIALLY_CONTAINED; it is never retried
  silently and the incident needs remediation by a human.
- An action already in the desired state is ALREADY_CONTAINED; a message already quarantined by the
  gateway is not proposed again.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why the workflow responds |
|---|---|---|---|
| TA0001 Initial Access | T1566 Phishing | T1566.001 Spearphishing Attachment | quarantine the message, block the attachment hash |
| TA0001 Initial Access | T1566 Phishing | T1566.002 Spearphishing Link | quarantine the message, block the URL or domain |
| TA0002 Execution | T1204 User Execution | T1204.001 Malicious Link | a recipient clicked; block the destination, isolate an endpoint with post-click activity |
| TA0002 Execution | T1204 User Execution | T1204.002 Malicious File | a recipient opened the attachment; block the hash, isolate the endpoint |
| TA0001 Initial Access | T1078 Valid Accounts | T1078.004 Cloud Accounts | a successful Entra sign-in after the click; revoke sessions, disable where justified |

## Testing instructions

- Unit tests of the rules and hooks: `tests/workflows/phishing/`
  (`python -m pytest -q -p no:cacheprovider tests/workflows/phishing`).
- Simulation scenarios (dry run and simulated live through the orchestrator):
  `tests/fixtures/workflows/phishing/`
  (`python -m pytest -q -p no:cacheprovider tests/simulation/test_workflow_scenarios.py -k phishing`).
- One scenario by hand: `python tools/simulator/simulate.py --workflow phishing --scenario tp-approve-all --check`
  (add `--live` for the simulated live run).
- README check: `python tools/validation/check_workflow_readmes.py --workflow phishing`.

## Known limitations

- Click and post-click activity are interpreted only from typed DNS, network, endpoint and detection
  records; Cisco XDR sightings, Defender XDR hunting rows and Splunk rows stay generic records (citable,
  never scored), so in production a click often has to be confirmed by the analyst.
- Defender for Office 365 has no VERIFIED read API: it contributes no message records, and its quarantine
  needs the networkMessageId as target and exactly one recipient; a message with several recipients
  routed there needs manual handling.
- Defender for Office 365 remediation cannot be verified through an API (UNABLE_TO_VERIFY); Secure Email
  quarantine is verified through the VERIFIED status call.
- Revoking sign-in sessions is not reversible; release only records it, and the account-takeover
  workflow owns the follow-up review.
- Attachment hash blocking on Secure Endpoint file lists is UNVERIFIED: the block routes to Defender for
  Endpoint indicators or a configured Cisco XDR native action, otherwise it is reported unrouted for
  manual handling.
- Each delivered copy is one quarantine action; a large campaign produces many actions and exceeds the
  `max_messages` cap, which makes them ELEVATED (never dropped).
- A compromised internal sender is investigated and reported, but account actions on the sender belong
  to the account-takeover workflow (hand-off), not to this package.
