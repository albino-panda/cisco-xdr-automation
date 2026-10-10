# Sample: credential dumping, hash block on Defender for Endpoint

Workflow [`credential-dumping`](../../workflows/credential-dumping/README.md) 3.0.0 (Phase 3), scenario
`tests/fixtures/workflows/credential-dumping/edge-defender-hash-block.yaml`, simulated live. The
tenant runs Microsoft Defender for Endpoint for file indicators next to Secure Endpoint. Compare it with
[credential-dumping-elevated.md](credential-dumping-elevated.md), where Secure Endpoint is the only
endpoint product and the hash block stays UNROUTED. Fake lab data only; nothing left the process.
Regenerate it with:

```
python tools/simulator/simulate.py --workflow credential-dumping --scenario edge-defender-hash-block --live --check
```

<!-- simulate: --workflow credential-dumping --scenario edge-defender-hash-block --live --check -->
```text
Scenario credential-dumping/edge-defender-hash-block (SIMULATED LIVE): Edge case (same facts as tp-approve-all): the tenant also runs Microsoft Defender for Endpoint for file indicators, while Secure Endpoint still manages the workstation. The real Secure Endpoint adapter cannot block hashes, so the tool hash block routes to Defender for Endpoint (native-first order, then the first adapter with a VERIFIED write) and is executed after the lead's approval; Defender cannot read the indicator back, so it ends UNABLE_TO_VERIFY, like the Secure Endpoint isolation, and containment is PARTIALLY_CONTAINED. The revocations and the disable verify through Entra.
workflow credential-dumping 3.0.0: risk 100, confidence 90
rule isolate_credential_host_secure_endpoint: PROPOSED isolate_endpoint:TH-LT-1047
rule revoke_exposed_sessions: PROPOSED revoke_sessions:it.support@example.com
rule revoke_exposed_sessions: PROPOSED revoke_sessions:jsmith@example.com
rule disable_exposed_account: PROPOSED disable_user:it.support@example.com
rule block_credential_tool_hash: PROPOSED block_hash:d00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeed
note: manual step: credential-reset:TH-LT-1047: reset the credentials of every account exposed on TH-LT-1047 (privileged and service accounts first), rotate the endpoint's local administrator credential and service secrets, review MFA methods, and rebuild the endpoint before release; credential reset has no VERIFIED automated action
note: hand-off: run account-takeover for it.support@example.com, jsmith@example.com: credentials of these accounts were exposed on TH-LT-1047 where credential access is confirmed: review their sign-ins, MFA and cloud activity for use of the stolen credentials (suggestion only; nothing is started)
note: critical asset: revoke_sessions it.support@example.com needs ELEVATED approval (WARNING: ELEVATED APPROVAL REQUIRED - revoke_sessions on Privileged account it.support@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.)
note: critical asset: disable_user it.support@example.com needs ELEVATED approval (WARNING: ELEVATED APPROVAL REQUIRED - disable_user on Privileged account it.support@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.)

=== Analyst decision card ===
CRITICAL INCIDENT  XDR-CD-0001-DH
Credential theft behaviour on TH-LT-1047
Endpoint: TH-LT-1047
Users: it.support@example.com, jsmith@example.com
Risk 100/100 (CRITICAL)   Confidence 90%
Primary evidence:
  [1] entra: entra: user it.support@example.com, risk medium, enabled true, privileged true
  [2] secure_endpoint: secure_endpoint: CRITICAL detection 'Credential theft - LSASS memory read' (MALICIOUS) on TH-LT-1047
  [3] secure_endpoint: secure_endpoint: d00dfeedd00d... seen on 1 endpoint(s), MALICIOUS
  [4] secure_endpoint: secure_endpoint: endpoint TH-LT-1047 (Windows 11), isolation not_isolated
  [5] secure_endpoint: secure_endpoint: process_start credtool.exe on TH-LT-1047 at 2026-01-15T11:39:00Z (x1)
  [6] secure_endpoint: secure_endpoint rates d00dfeedd00d... MALICIOUS (risk 90, confidence 85)
  [7] virustotal: virustotal rates d00dfeedd00d... MALICIOUS (risk 90, confidence 85)
Blast radius: 1 endpoint, 2 users, 1 file hash
Recommended containment:
  [ ] isolate_endpoint TH-LT-1047                                                  (STANDARD)  risk 100  confidence 90%  via secure_endpoint    evidence [2, 3, 4, 5, 6, 7]
  [ ] revoke_sessions it.support@example.com                                       (ELEVATED)  risk 100  confidence 90%  via entra              evidence [2, 3, 4, 5, 6, 7]
  [ ] revoke_sessions jsmith@example.com                                           (STANDARD)  risk 100  confidence 90%  via entra              evidence [2, 3, 4, 5, 6, 7]
  [ ] disable_user it.support@example.com                                          (ELEVATED)  risk 100  confidence 90%  via entra              evidence [1, 2, 3, 4, 5, 6, 7]
  [ ] block_hash d00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeed  (STANDARD)  risk 100  confidence 90%  via defender_endpoint  evidence [2, 3, 6, 7]
WARNING: ELEVATED APPROVAL REQUIRED
  Action: revoke_sessions it.support@example.com
  Asset: it.support@example.com (privileged_account)
  Role: Administrator or break-glass account
  Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Detail: revoke_sessions on Privileged account it.support@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Requires an approver holding the elevated approval role. The action is not blocked.
WARNING: ELEVATED APPROVAL REQUIRED
  Action: disable_user it.support@example.com
  Asset: it.support@example.com (privileged_account)
  Role: Administrator or break-glass account
  Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Detail: disable_user on Privileged account it.support@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Requires an approver holding the elevated approval role. The action is not blocked.
Package 00000000000000000000000000000001  workflow credential-dumping 3.0.0  evidence sha256 7ed1fb8dcb0a  approve before 2026-01-15T16:00:00Z
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]

Decision APPROVE_ALL; incident now PARTIALLY_CONTAINED

=== Containment result ===
CONTAINMENT RESULT  XDR-CD-0001-DH
Overall: PARTIALLY_CONTAINED
Package 00000000000000000000000000000001  approval token 00000000000000000000000000000003
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  isolate_endpoint TH-LT-1047                                                  via secure_endpoint    verification UNABLE_TO_VERIFY  control registered  ATTENTION
  [SUCCESS]  revoke_sessions it.support@example.com                                       via entra              verification VERIFIED
  [SUCCESS]  revoke_sessions jsmith@example.com                                           via entra              verification VERIFIED
  [SUCCESS]  disable_user it.support@example.com                                          via entra              verification VERIFIED          control registered
  [SUCCESS]  block_hash d00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeed  via defender_endpoint  verification UNABLE_TO_VERIFY  control registered  ATTENTION
Attention:
  - Requires attention: isolate_endpoint TH-LT-1047 - verify manually (UNABLE_TO_VERIFY)
  - Requires attention: block_hash d00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeed - verify manually (UNABLE_TO_VERIFY)
Temporary controls registered: 3 (release needs a separate release approval)
Simulated vendor state changes: 5
All scenario expectations met.
```

## How to read it

- **Routing follows the real adapters.** The router tries the native Cisco XDR response action first,
  then the first enabled adapter with a VERIFIED write for the action (architecture 4.2). The real
  `SecureEndpointAdapter` has no VERIFIED hash-block write, so `block_hash` goes to
  `defender_endpoint` (file indicator). The isolation stays on `secure_endpoint`, which manages the
  workstation. The simulated adapters can do exactly what the real ones can, and nothing more
  (architecture 14.14.3).
- **Two results are `UNABLE_TO_VERIFY`.** Neither the Secure Endpoint isolation state nor the Defender
  indicator can be read back through a VERIFIED endpoint, so automatic verification cannot confirm them.
  Both rows carry `ATTENTION` and an `Attention:` line telling the analyst to verify by hand. With
  `unable_to_verify_counts_as_contained: false` (the default in
  [`config/thresholds.yaml`](../../config/thresholds.yaml)) the overall result is `PARTIALLY_CONTAINED`,
  not `CONTAINED`. The actions did execute, and each one is registered as a temporary control.
- **Identity actions verify.** The revocations and the disable go through Entra, which can read them
  back, so they are `VERIFIED`.
- **Approval is unchanged.** `it.support@example.com` is a privileged account: its revocation and
  disable are `ELEVATED` with a visible warning, and the lab `lead` approves. Nothing ran before the
  approval (`Simulated vendor state changes: 5` counts the five approved writes).
