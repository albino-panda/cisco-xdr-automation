# Sample: phishing, release and restoration with one unconfirmed release

Workflow [`phishing`](../../workflows/phishing/README.md) 1.0.0 (Phase 2), scenario
`tests/fixtures/workflows/phishing/release-restoration.yaml`, simulated live. Fake lab data only;
nothing left the process. Regenerate it with:

```
python tools/simulator/simulate.py --workflow phishing --scenario release-restoration --live --check
```

<!-- simulate: --workflow phishing --scenario release-restoration --live --check -->
```text
Scenario phishing/release-restoration (SIMULATED LIVE): Same credential phishing campaign as tp-approve-all. After containment a separate human release decision restores every reversible control (messages released, blocks removed, account enabled, endpoint released); the session revocation is not reversible and has no control to release. Production parity: the block_hash recommendation stays UNROUTED (no enabled adapter has a VERIFIED write for it; shown for manual handling, never executed); isolate_endpoint and release_endpoint through secure_endpoint cannot be read back by the real adapters and end UNABLE_TO_VERIFY, so containment is PARTIALLY_CONTAINED, restoration is PARTIALLY_RESTORED and the incident stays AWAITING_RELEASE_APPROVAL.
workflow phishing 1.0.0: risk 100, confidence 99
rule quarantine_phishing_message: PROPOSED quarantine_email:<20260115.0900.4471@invoice-portal.example>
rule quarantine_phishing_message: PROPOSED quarantine_email:<20260115.0902.4472@invoice-portal.example>
rule block_phishing_domain: PROPOSED block_domain:invoice-portal.example
rule block_malicious_attachment: UNROUTED block_hash:1a2b3c4d5e6f7a8b9c0d1a2b3c4d5e6f7a8b9c0d1a2b3c4d5e6f7a8b9c0d1a2b
rule revoke_clicked_user_sessions: PROPOSED revoke_sessions:ap-clerk-01@example.com
rule disable_compromised_user: PROPOSED disable_user:ap-clerk-01@example.com
rule isolate_compromised_endpoint: PROPOSED isolate_endpoint:TH-LT-1047
note: hand-off: run account-takeover for ap-clerk-01@example.com: signed in or was flagged by the identity provider after clicking a phishing link; review the account's activity after the click (suggestion only; nothing is started)
note: rule block_malicious_attachment unrouted (block_hash 1a2b3c4d5e6f7a8b9c0d1a2b3c4d5e6f7a8b9c0d1a2b3c4d5e6f7a8b9c0d1a2b): no enabled adapter has a VERIFIED write for block_hash; manual handling required
note: not proposed: block_hash 1a2b3c4d5e6f7a8b9c0d1a2b3c4d5e6f7a8b9c0d1a2b3c4d5e6f7a8b9c0d1a2b (no enabled adapter has a VERIFIED write for block_hash)

=== Analyst decision card ===
HIGH INCIDENT  XDR-PH-0009
Credential phishing link and attachment delivered to finance
Endpoint: TH-LT-1047
User: ap-clerk-01@example.com
Risk 100/100 (CRITICAL)   Confidence 99%
Primary evidence:
  [1] entra: entra: sign-in success for ap-clerk-01@example.com from 198.51.100.77 (NL) to Office 365 Exchange Online at 2026-01-15T09:31:00Z, MFA satisfied
  [2] entra: entra: unfamiliar_location (HIGH) for ap-clerk-01@example.com
  [3] entra: entra: user ap-clerk-01@example.com, risk medium, enabled true, privileged false
  [4] microsoft_cloud: microsoft_cloud: TH-LT-1047 queried invoice-portal.example x3 (allowed)
  [5] secure_email: secure_email: message <20260115.0900.4471@invoice-portal.example> from billing@invoice-portal.example to 1 recipient(s), MALICIOUS, inbox
  [6] secure_email: secure_email: message <20260115.0902.4472@invoice-portal.example> from billing@invoice-portal.example to 1 recipient(s), UNKNOWN, inbox
  [7] secure_endpoint: secure_endpoint: HIGH detection 'Trojan.Downloader.Generic' (MALICIOUS) on TH-LT-1047
  [8] secure_endpoint: secure_endpoint: endpoint TH-LT-1047 (Windows 11), isolation not_isolated
  [9] secure_endpoint: secure_endpoint rates 1a2b3c4d5e6f... MALICIOUS (risk 90, confidence 85)
  [10] umbrella: umbrella rates https://invoice-portal.example/login/verify MALICIOUS (risk 90, confidence 85)
  ... 4 more evidence items in the full package
Blast radius: 1 endpoint, 1 user, 1 domain, 2 email messages
Recommended containment:
  [ ] quarantine_email <20260115.0900.4471@invoice-portal.example>  (STANDARD)  risk 100  confidence 100%  via secure_email     evidence [5, 7, 9, 10, 11, 12, 13, 14]
  [ ] quarantine_email <20260115.0902.4472@invoice-portal.example>  (STANDARD)  risk 100  confidence 100%  via secure_email     evidence [5, 6, 7, 9, 10, 11, 12, 13, 14]
  [ ] block_domain invoice-portal.example                           (STANDARD)  risk 74   confidence 95%   via umbrella         evidence [4, 5, 6, 11, 14]
  [ ] revoke_sessions ap-clerk-01@example.com                       (STANDARD)  risk 87   confidence 100%  via entra            evidence [1, 2, 3, 4, 5, 8, 11, 14]
  [ ] disable_user ap-clerk-01@example.com                          (STANDARD)  risk 87   confidence 100%  via entra            evidence [1, 2, 3, 4, 5, 8, 11, 14]
  [ ] isolate_endpoint TH-LT-1047                                   (STANDARD)  risk 100  confidence 100%  via secure_endpoint  evidence [4, 5, 6, 7, 8, 9, 11, 12, 14]
Package 00000000000000000000000000000001  workflow phishing 1.0.0  evidence sha256 e3a0f377cc30  approve before 2026-01-15T16:00:00Z
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]

Decision APPROVE_ALL; incident now PARTIALLY_CONTAINED

=== Containment result ===
CONTAINMENT RESULT  XDR-PH-0009
Overall: PARTIALLY_CONTAINED
Package 00000000000000000000000000000001  approval token 00000000000000000000000000000003
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  quarantine_email <20260115.0900.4471@invoice-portal.example>  via secure_email     verification VERIFIED          control registered
  [SUCCESS]  quarantine_email <20260115.0902.4472@invoice-portal.example>  via secure_email     verification VERIFIED          control registered
  [SUCCESS]  block_domain invoice-portal.example                           via umbrella         verification VERIFIED          control registered
  [SUCCESS]  revoke_sessions ap-clerk-01@example.com                       via entra            verification VERIFIED
  [SUCCESS]  disable_user ap-clerk-01@example.com                          via entra            verification VERIFIED          control registered
  [SUCCESS]  isolate_endpoint TH-LT-1047                                   via secure_endpoint  verification UNABLE_TO_VERIFY  control registered  ATTENTION
Attention:
  - Requires attention: isolate_endpoint TH-LT-1047 - verify manually (UNABLE_TO_VERIFY)
Temporary controls registered: 5 (release needs a separate release approval)

=== Restoration result ===
RESTORATION RESULT  XDR-PH-0009
Overall: PARTIALLY_RESTORED
Package 00000000000000000000000000000005  approval token 00000000000000000000000000000007
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  unblock_domain invoice-portal.example                      via umbrella         verification VERIFIED
  [SUCCESS]  enable_user ap-clerk-01@example.com                        via entra            verification VERIFIED
  [SUCCESS]  release_endpoint TH-LT-1047                                via secure_endpoint  verification UNABLE_TO_VERIFY  ATTENTION
  [SUCCESS]  release_email <20260115.0900.4471@invoice-portal.example>  via secure_email     verification VERIFIED
  [SUCCESS]  release_email <20260115.0902.4472@invoice-portal.example>  via secure_email     verification VERIFIED
Attention:
  - release_endpoint TH-LT-1047: verify manually; control kept RELEASE_FAILED
Simulated vendor state changes: 11
All scenario expectations met.
```

## How to read it

- **Most actions verify.** Secure Email (quarantine and release of each message), Umbrella (domain
  block and unblock) and Entra (revocation, disable, enable) have VERIFIED read-back endpoints and show
  `verification VERIFIED`.
- **The endpoint isolation and its release cannot be confirmed.** The real Secure Endpoint adapter
  cannot read the isolation state back, so `isolate_endpoint` and `release_endpoint` end
  `UNABLE_TO_VERIFY` with `ATTENTION`. Containment is `PARTIALLY_CONTAINED` and restoration
  `PARTIALLY_RESTORED`: the isolation control is kept as `RELEASE_FAILED` for a human to check, and the
  incident stays in `AWAITING_RELEASE_APPROVAL`.
- **`UNROUTED` hash block.** The attachment hash has evidence but no enabled adapter with a VERIFIED
  hash-block write; it is listed for manual handling and never executed.
- **Two separate human approvals**, as in every release: the release package lists only the controls
  the automation registered (two messages, the domain block, the disable and the isolation), and needs
  its own release token. Session revocation is not reversible and has nothing to release.
