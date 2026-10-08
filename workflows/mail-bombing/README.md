# Mail bombing

Workflow `mail-bombing`, version 1.0.0, Phase 2 (`docs/architecture.md` section 14.5). Definition:
`src/xdr_response/workflows/mail_bombing/definition.py`; hooks: `src/xdr_response/workflows/mail_bombing/hooks.py`.
It replaces the legacy specification of the same id (its five scenarios are migrated as `legacy-*`
fixtures). Detection stays in the separate `cisco-xdr-mailbomb-detector` project; this workflow is the
response side.

## Purpose

Respond to an email or subscription bombing flood and treat it as **concealment**. A flood of sign-up
confirmations and newsletters is rarely the goal: it buries the messages the recipient must not notice
(a password reset or change, a security alert, a new sign-in or device, an MFA prompt, a wire transfer,
invoice or banking request, a DocuSign or Microsoft lure, an account recovery) and is often followed by
a fake IT-support call or chat that pushes a remote-access tool.

The workflow investigates and recommends automatically. It measures the flood (volume, time window,
sender distribution and domains, the targeted mailbox, message characteristics), searches the flood
window for the buried messages, checks the recipient's identity (Entra sign-ins, password and MFA
activity, new devices and risk detections, mailbox and forwarding rules) and endpoint telemetry, and
proposes a containment package: quarantine the flood, revoke sessions, disable the account, isolate the
endpoint, block malicious domains. It never executes anything: every action waits for a human decision
in the lifecycle orchestrator.

## Trigger

- **Webhook** (priority 200): an incident raised by `cisco-xdr-mailbomb-detector` (incident or trigger
  source `cisco-xdr-mailbomb-detector`). The detector's webhook payload is read from `incident.trigger`
  (top level, `trigger.detector`, or `trigger.legacy_context` for replayed legacy incidents): `event_type`
  (`mailbomb.detection`), `recipient`, `is_escalation` and `metrics` (`window_start`, `window_end`,
  `total_messages`, `unique_sender_domains`, `neutral_count`, `graymail_count`, `spam_count`,
  `malicious_count`, ...). This keeps the detector's incident shape described by the legacy README.
- **XDR incident rule** (priority 150): an incident tagged with technique T1667 (Email Bombing) that
  carries an `email_address` or `user` observable.
- **XDR incident rule** (priority 120): an incident whose title names an email, mail or subscription
  bomb or a mail flood, with an `email_address` or `user` observable.
- **Manual**: an analyst starts the workflow for an incident (`incident.workflow_id: mail-bombing`).

Legacy incidents tagged only with T1499 (Endpoint Denial of Service, a different technique) are not
matched by technique any more; they still match on the detector source or the title.

## Required integrations

- `secure_email`: the flood messages to the recipient (volume, senders, verdicts, subjects) and the
  buried messages of interest (`search_email_campaign`); executes the approved quarantine (message move,
  VERIFIED) and its release.
- `entra`: the recipient's profile, sign-ins, MFA events, risk detections and mailbox rules inside the
  flood window (`investigate_user`, `investigate_authentication`, `search_user_activity`); executes the
  approved session revocation and account disable (VERIFIED Graph calls).

Both are the expected sources of the risk calculation. A required integration that is disabled or
failing never blocks a recommendation that other evidence supports; the run notes it.

## Optional integrations

- `cisco_xdr`: user and endpoint context and verdicts from the XDR platform; native response routing.
- `microsoft_cloud`: Defender XDR alerts and hunting results about the recipient, the flood and the endpoint.
- `splunk`: mail gateway and identity logs indexed in the SIEM.
- `secure_endpoint`: detections and trajectory on the recipient's endpoint after the flood started.
- `defender_endpoint`: device facts and alerts on the recipient's endpoint after the flood started.
- `intune`: managed-device facts of the recipient's endpoint.
- `umbrella`: categorization of lure and flood domains that carry a threat verdict.
- `virustotal`: second opinion on domain reputation (public domains only; the disclosure policy applies).
- `alienvault_otx`: third opinion on domain reputation (public domains only; the disclosure policy applies).

## Input data

- The targeted mailbox: `incident.users`, `email_address` and `user` observables and the detector's
  `recipient` (used as the user principal name).
- One or more seed `email_message_id` observables (a message of the flood) for the flood search.
- Optional `hostname` observables (the recipient's device) and `domain` observables.
- Optional detector payload in `incident.trigger` (see Trigger). Its metrics gate the flood
  qualification; they are never evidence.

## Investigation steps

All steps are reads through the read-only adapter facade; a failing source is recorded as degraded and
the run continues.

1. `flood_messages`: `search_email_campaign` for every seed message id (up to 5): the messages of the
   flood with sender, sender domain, recipients, subject, received time, verdict, threat types and
   delivery location.
2. `recipient_profile`: `investigate_user` for every targeted mailbox (up to 5): profile, groups, roles,
   account state and risk level.
3. `recipient_sign_ins`: `investigate_authentication`: sign-ins (result, IP, country, device, risk),
   MFA events and risk detections.
4. `recipient_activity`: `search_user_activity`: mailbox and forwarding rules, role changes and other
   recent activity.
5. `recipient_endpoints`: `investigate_endpoint` for incident hostnames and hostnames named by earlier
   records: detections, process events, DNS queries and connections.
6. `domain_reputation`: `enrich_domain` for incident domains, domains of flood messages with a threat
   verdict and domains the endpoint resolved or contacted with a threat verdict (up to 25). Neutral
   newsletter senders are not looked up: no decision depends on them.

The hooks then compute, from the typed records only:

- **Flood window**: detector `window_start` / `window_end`, else the first and last observed message
  (at least 10 messages needed).
- **Flood qualification** (the legacy `quarantine_burst_messages` rule): at least 10 sender domains and at
  least 50 percent neutral or graymail, judged on the detector metrics when present, else on the observed
  messages. A spam or malicious storm does not qualify (Secure Email policies and the `phishing` workflow).
- **Buried messages**: messages inside the window whose subject names a credential topic (password reset or
  change, account recovery), a security alert (new sign-in, new login, new device), MFA or authentication,
  a payment topic (wire transfer, invoice, banking) or a DocuSign or Microsoft lure. They are kept out of
  the quarantine so the analyst and the user see them, unless the gateway rated them malicious.
- **Identity events** of the recipient at or after the window start: MFA events, risk detections,
  sign-ins with medium or high risk, a non-compliant device or a failed Conditional Access check, new
  mailbox rules and privileged role assignments, plus buried credential, security or MFA notifications.
- **Takeover indications**: a successful high-risk sign-in, an MFA approval after denied prompts or a new
  mailbox rule that deletes, moves, marks as read or forwards mail, inside the window.
- **Endpoint activity**: malicious or suspicious detections and process events at or after the window start.
- **Malicious domains**: domains rated malicious (or suspicious with a malicious flood message or endpoint
  traffic behind it) that a flood message carried or the endpoint contacted after the flood started.

## Correlation logic

The flood window anchors everything. Framework links (window 240 minutes) tie a successful sign-in to a
following mailbox rule (`sign_in_to_activity`), a flood message to a click on one of its domains
(`email_to_click`) and messages sharing a sender domain and URL (`campaign`). The workflow hooks add the
concealment view: buried messages, identity events, takeover indications and endpoint detections are
tied to the flood when they fall at or after the window start. An older detection on the same endpoint is
not tied to the flood and does not drive isolation. Correlation is context: a correlation failure never
blocks a recommendation.

## Risk calculation

Every target is scored separately from the records its rule cites (scoring engine, `docs/threat-scoring.md`);
risk and confidence are separate integers.

- A message of a qualifying flood carries a `campaign_association` pattern (severity 70; confidence 80 with
  detector metrics, 70 without). Its own gateway verdict is an `email_verdict` signal: a malicious lure
  scores higher, a neutral message lowers confidence by contradiction.
- The recipient carries `authentication_anomaly` patterns for identity events inside the flood window
  (severity 75), buried credential, security or MFA notifications (60) and takeover indications (85),
  next to the vendor risk detections and mailbox-rule signals of the framework.
- Endpoint detections and domain reputation use the framework signals; reputation alone is capped by the
  engine, and one vendor's word is never an aggregate malicious verdict.
- A failed expected source lowers confidence for the targets it concerns and never blocks other evidence.

Minimum risk per rule: quarantine 30, revoke 50, disable 60, isolate 60, block 50. An action under its
minimum is listed as "considered, not proposed" in the run notes, never dropped silently.

## Containment recommendations

| Rule | Action (builder) | When | Evidence |
|---|---|---|---|
| `quarantine_flood_messages` | `quarantine_email` (`quarantine_email`) | the flood qualifies; one action per neutral or graymail flood message that is not a buried message of interest, and per malicious message in the flood | the message record |
| `revoke_sessions_buried_identity_event` | `revoke_sessions` (`revoke_entra_sessions`) | an identity event or a buried credential, security or MFA notification inside the flood window | the identity records and notifications |
| `disable_account_on_takeover` | `disable_user` (`disable_entra_user`) | a takeover indication inside the flood window | the sign-in, MFA, mailbox-rule and risk records |
| `isolate_recipient_endpoint` | `isolate_endpoint` (catalog routing) | a malicious or suspicious endpoint detection at or after the window start | the detection and process records |
| `block_malicious_flood_domain` | `block_domain` (catalog routing) | a malicious domain in the flood or contacted by the endpoint after it started | the vendor enrichment, message and DNS records |

Every recommendation carries numbered evidence citing real investigation or enrichment records, a
rationale with the score explanation and the flood summary, and separate risk and confidence. The
buried messages are named in the rationale count and stay visible in the mailbox. The approver should
tell the user and the help desk that IT will never cold-call about the flood or ask for a remote-access
tool, a screen share or an MFA code; remote-access tooling goes to the `unauthorized-rmm` workflow and
a confirmed takeover to `account-takeover`.

### Hand-offs and items not proposed

- Not proposed, and listed as considered: buried messages of interest (security alerts, MFA or credential notices) kept in the mailbox for the analyst.
- Hand-offs: `account-takeover` for a recipient with takeover indications inside the flood window; `unauthorized-rmm` for an endpoint with malicious or suspicious activity after the flood (the fake help-desk follow-up); `phishing` when the storm carries malicious mail but is not a subscription bomb.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed", "Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

Every recommended action needs human approval before it runs, including session revocation (which
cannot be undone), the quarantine of neutral newsletter mail and every later release. AI and automation
principals can never approve. ELEVATED approval (a lead holding the elevated approver role, with a
visible warning on the decision card) applies when the target is a critical asset (for example a
break-glass or administrator mailbox, a Global Administrator role, an executive or production endpoint)
or when a blast-radius cap is exceeded (for example more flood messages than
`thresholds.blast_radius.max_messages`). Over the cap, every quarantine stays proposed and needs ELEVATED
approval; nothing is skipped silently. The workflow cannot choose or lower an approval level.

## Containment execution

After the human decision the lifecycle orchestrator executes the approved actions automatically through
the guarded action runner; the workflow never calls a state-changing method. Routing is native first
(Cisco XDR response actions configured by the operator), then the product adapter: quarantine through
Secure Email Threat Defense (message move to the quarantine folder; Defender for Office 365 remediation
when that is the enabled route), session revocation and account disable through Entra (Graph), isolation
through the enabled EDR, domain blocks through Umbrella destination lists or the enabled DNS route.
Unselected or rejected actions are recorded as rejected by the analyst and never executed. In dry run
nothing is executed and the package shows the `DRY RUN` lines.

## Verification

Verification is automatic after execution: Secure Email message status (`/v1/messages/status`) for the
quarantine, the Entra user (`accountEnabled`, `signInSessionsValidFromDateTime`) for disable and session
revocation, the EDR isolation state (Defender machine action; Secure Endpoint isolation reads are not
verified and report UNABLE_TO_VERIFY) and the destination list for the domain block. A result that cannot
be verified is reported as such and never counted as contained.

## Rollback

Quarantine, account disable, isolation and the domain block are temporary controls in the restoration
registry. Releasing them (message move back to the inbox, account enable, release from isolation,
removal from the destination list) needs a separate human release approval; nothing is released
automatically. Session revocation is not reversible: the user signs in again, and the help desk should
expect the extra prompt. Release from quarantine through Defender for Office 365 is UNVERIFIED, so a
quarantine executed there is released manually in the Defender portal.

## Failure handling

- A failing source (for example Secure Email unavailable during the flood search) is recorded as a
  degraded source; the other evidence still produces its recommendations (degraded-source scenario).
- A step whose expression or atomic fails is noted and skipped; partial results stay.
- An action that fails at the vendor is reported FAILED and never retried silently; the containment is
  PARTIALLY_CONTAINED (partial-failure scenario).
- An action without an execution path is reported as unrouted for manual handling, never dropped.
- Without typed flood messages (production today, see Known limitations) the quarantine is a manual step:
  run the recipient search in the Secure Email console (or the detector's ContainBurst workflow) and move
  the neutral and graymail messages of the window after reviewing the buried messages.

## MITRE mapping

| Tactic | Technique | Sub-technique | Why the workflow responds |
|---|---|---|---|
| TA0040 Impact | T1667 Email Bombing | | the flood itself; quarantine |
| TA0005 Defense Evasion | T1656 Impersonation | | the fake IT-support contact the flood prepares; warning, identity and endpoint checks |
| TA0006 Credential Access | T1621 Multi-Factor Authentication Request Generation | | MFA prompts inside the flood window; session revocation |
| TA0001 Initial Access | T1078 Valid Accounts | T1078.004 Cloud Accounts | risky or successful sign-ins to the Entra account during the flood; revocation and disable |
| TA0005 Defense Evasion | T1564 Hide Artifacts | T1564.008 Email Hiding Rules | mailbox rules created during the flood that hide or forward mail; disable |
| TA0011 Command and Control | T1219 Remote Access Tools | | remote-access tooling after the flood; isolation |
| TA0001 Initial Access | T1566 Phishing | | malicious lures hidden in the flood; domain block |

## Testing instructions

- Scenarios: `tests/fixtures/workflows/mail-bombing/` (the minimum set of 14.5.3, four `edge-*` cases and
  the five migrated `legacy-*` scenarios). They run automatically in dry run and simulated live through
  the orchestrator:
  `python -m pytest -q -p no:cacheprovider tests/simulation/test_workflow_scenarios.py -k mail-bombing`.
- Unit, lifecycle and simulation tests of the rules and hooks: `tests/workflows/mail_bombing/`
  (`python -m pytest -q -p no:cacheprovider tests/workflows/mail_bombing`).
- One scenario by hand: `python tools/simulator/simulate.py --workflow mail-bombing --scenario tp-approve-all`
  (add `--live` for a simulated live run, `--check` to assert the expectations).
- README and coverage: `python tools/validation/check_workflow_readmes.py --workflow mail-bombing`.
- The mail-bomb detector's synthetic replay data can drive the workflow end to end in a lab tenant.

## Known limitations

- The production flood search is not automatic yet: the Secure Email message search (VERIFIED) needs a
  search body with a time range and a recipient, which a static step option cannot carry, and its message
  fields are not documented in `docs/integrations.md`, so messages would only be generic records. Until the
  contract change lands, the analyst runs the recipient search in the Secure Email console (or the
  detector's ContainBurst workflow) and the quarantine rule proposes nothing without typed message records.
- The flood search needs a seed message id (an `email_message_id` observable); detector incidents carry
  the recipient and metrics only.
- Password resets and changes and MFA method registrations from the Entra directory audit log have no
  record kind and that read is not in `docs/integrations.md`; they are seen only as buried notification
  messages, sign-ins, MFA events and risk detections.
- Buried messages are recognised by subject keywords only; a buried message with another subject stays
  in the quarantine set and is listed in the evidence for the approver.
- Recipient addresses are used as user principal names; an alias or shared mailbox that differs from the
  UPN gets no identity results.
- Release from quarantine through Defender for Office 365 is UNVERIFIED; release is executed through Secure
  Email only, and session revocation cannot be undone.
- With detector metrics the flood qualification relies on the detector's counts for the whole burst; the
  quarantine set is limited to the messages the search returned.
