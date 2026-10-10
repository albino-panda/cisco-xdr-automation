# Sample: credential dumping, ELEVATED approval on a privileged account

Workflow [`credential-dumping`](../../workflows/credential-dumping/README.md) 3.0.0 (Phase 3), scenario
`tests/fixtures/workflows/credential-dumping/critical-asset-elevated.yaml`, simulated live. The
simulator generated this output with simulated adapters only: fake lab data, nothing left the process.
Regenerate it with:

```
python tools/simulator/simulate.py --workflow credential-dumping --scenario critical-asset-elevated --live --check
```

<!-- simulate: --workflow credential-dumping --scenario critical-asset-elevated --live --check -->
```text
Scenario credential-dumping/critical-asset-elevated (SIMULATED LIVE): LSASS memory is read on an operations workstation where a member of Domain Admins is logged on next to a standard user. The revocation and disable of the Domain Admins member need ELEVATED approval with a visible privileged-account warning (never skipped): an analyst alone cannot approve the package and the lead approves. The workstation isolation, the standard user's revocation and the tool hash block need standard approval. Production parity: the block_hash recommendation stays UNROUTED (no enabled adapter has a VERIFIED write for it; shown for manual handling, never executed); isolate_endpoint through secure_endpoint cannot be read back by the real adapter and ends UNABLE_TO_VERIFY, so containment is PARTIALLY_CONTAINED.
workflow credential-dumping 3.0.0: risk 100, confidence 90
rule isolate_credential_host_secure_endpoint: PROPOSED isolate_endpoint:TH-LT-3388
rule revoke_exposed_sessions: PROPOSED revoke_sessions:dokafor@example.com
rule revoke_exposed_sessions: PROPOSED revoke_sessions:ops.lead@example.com
rule disable_exposed_account: PROPOSED disable_user:ops.lead@example.com
rule block_credential_tool_hash: UNROUTED block_hash:d00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeed
note: manual step: credential-reset:TH-LT-3388: reset the credentials of every account exposed on TH-LT-3388 (privileged and service accounts first), rotate the endpoint's local administrator credential and service secrets, review MFA methods, and rebuild the endpoint before release; credential reset has no VERIFIED automated action
note: hand-off: run account-takeover for dokafor@example.com, ops.lead@example.com: credentials of these accounts were exposed on TH-LT-3388 where credential access is confirmed: review their sign-ins, MFA and cloud activity for use of the stolen credentials (suggestion only; nothing is started)
note: critical asset: revoke_sessions ops.lead@example.com needs ELEVATED approval (WARNING: ELEVATED APPROVAL REQUIRED - revoke_sessions on Privileged account ops.lead@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.)
note: critical asset: disable_user ops.lead@example.com needs ELEVATED approval (WARNING: ELEVATED APPROVAL REQUIRED - disable_user on Privileged account ops.lead@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.)
note: rule block_credential_tool_hash unrouted (block_hash d00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeed): no enabled adapter has a VERIFIED write for block_hash; manual handling required
note: not proposed: block_hash d00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeed (no enabled adapter has a VERIFIED write for block_hash)

=== Analyst decision card ===
CRITICAL INCIDENT  XDR-CD-0006
Credential theft behaviour on TH-LT-3388
Endpoint: TH-LT-3388
Users: dokafor@example.com, ops.lead@example.com
Risk 100/100 (CRITICAL)   Confidence 90%
Primary evidence:
  [1] entra: entra: user ops.lead@example.com, risk medium, enabled true, privileged false
  [2] secure_endpoint: secure_endpoint: CRITICAL detection 'Suspicious read of LSASS process memory' (MALICIOUS) on TH-LT-3388
  [3] secure_endpoint: secure_endpoint: d00dfeedd00d... seen on 1 endpoint(s), MALICIOUS
  [4] secure_endpoint: secure_endpoint: endpoint TH-LT-3388 (Windows 11), isolation not_isolated
  [5] secure_endpoint: secure_endpoint rates d00dfeedd00d... MALICIOUS (risk 90, confidence 85)
  [6] virustotal: virustotal rates d00dfeedd00d... MALICIOUS (risk 90, confidence 85)
Blast radius: 1 endpoint, 2 users
Recommended containment:
  [ ] isolate_endpoint TH-LT-3388           (STANDARD)  risk 100  confidence 90%  via secure_endpoint  evidence [2, 3, 4, 5, 6]
  [ ] revoke_sessions dokafor@example.com   (STANDARD)  risk 100  confidence 90%  via entra            evidence [2, 3, 4, 5, 6]
  [ ] revoke_sessions ops.lead@example.com  (ELEVATED)  risk 100  confidence 90%  via entra            evidence [2, 3, 4, 5, 6]
  [ ] disable_user ops.lead@example.com     (ELEVATED)  risk 100  confidence 90%  via entra            evidence [1, 2, 3, 4, 5, 6]
WARNING: ELEVATED APPROVAL REQUIRED
  Action: revoke_sessions ops.lead@example.com
  Asset: ops.lead@example.com (privileged_account)
  Role: Administrator or break-glass account
  Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Detail: revoke_sessions on Privileged account ops.lead@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Requires an approver holding the elevated approval role. The action is not blocked.
WARNING: ELEVATED APPROVAL REQUIRED
  Action: disable_user ops.lead@example.com
  Asset: ops.lead@example.com (privileged_account)
  Role: Administrator or break-glass account
  Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Detail: disable_user on Privileged account ops.lead@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Requires an approver holding the elevated approval role. The action is not blocked.
Package 00000000000000000000000000000001  workflow credential-dumping 3.0.0  evidence sha256 8e8829596865  approve before 2026-01-15T16:00:00Z
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]

Decision APPROVE_ALL; incident now PARTIALLY_CONTAINED

=== Containment result ===
CONTAINMENT RESULT  XDR-CD-0006
Overall: PARTIALLY_CONTAINED
Package 00000000000000000000000000000001  approval token 00000000000000000000000000000003
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  isolate_endpoint TH-LT-3388           via secure_endpoint  verification UNABLE_TO_VERIFY  control registered  ATTENTION
  [SUCCESS]  revoke_sessions dokafor@example.com   via entra            verification VERIFIED
  [SUCCESS]  revoke_sessions ops.lead@example.com  via entra            verification VERIFIED
  [SUCCESS]  disable_user ops.lead@example.com     via entra            verification VERIFIED          control registered
Attention:
  - Requires attention: isolate_endpoint TH-LT-3388 - verify manually (UNABLE_TO_VERIFY)
Temporary controls registered: 2 (release needs a separate release approval)
Simulated vendor state changes: 4
All scenario expectations met.
```

## How to read it

- **The critical asset is shown, not skipped.** `ops.lead@example.com` is in the `Domain Admins` group
  in the identity record of the scenario, which matches the privileged-account class in
  [`config/critical-assets.yaml`](../../config/critical-assets.yaml). Its `revoke_sessions` and
  `disable_user` stay in the package as `ELEVATED`, and the card prints one
  `WARNING: ELEVATED APPROVAL REQUIRED` block per action with the asset, role and potential impact.
  The other actions are `STANDARD`.
- **Who approved.** The scenario's approver is the lab `lead`, who holds the elevated approval role
  (`xdr-elevated-approver` in [`config/thresholds.yaml`](../../config/thresholds.yaml)). Because the
  scenario is tagged `critical_asset`, `--check` also asserts that the lab `analyst` alone is refused
  for this package.
- **The hash block is `UNROUTED`, not dropped.** Secure Endpoint is the only endpoint product in this
  scenario, and the real `SecureEndpointAdapter` has no VERIFIED hash-block write (its file-list
  endpoints are UNVERIFIED in [`docs/integrations.md`](../integrations.md)). The rule outcome is
  `UNROUTED`, the notes say `manual handling required`, and the hash is not in the package: it is
  never executed. The analyst blocks it by hand in a product that can, or enables one the router can
  use (see [credential-dumping-defender-hash-block.md](credential-dumping-defender-hash-block.md)).
- **Manual step and hand-off.** Resetting the exposed credentials has no VERIFIED automated action, so
  it is a manual step for the analyst. The hand-off to `account-takeover` is a suggestion only:
  nothing is started.
- **After the approval.** The approved actions ran automatically and were verified automatically. The
  Entra revocations and the disable read back as `VERIFIED`. The isolation executed, but the real
  Secure Endpoint adapter cannot read the isolation state back (UNVERIFIED endpoint), so it is
  `UNABLE_TO_VERIFY` with `ATTENTION`: the analyst confirms it in the Secure Endpoint console. One
  unconfirmed action makes the overall result `PARTIALLY_CONTAINED`
  (`unable_to_verify_counts_as_contained: false`). Isolation and the disable are registered as
  temporary controls (`Temporary controls registered: 2`); session revocation creates no control.
  Releasing those controls needs a separate human release approval. This scenario has no release step.
- **`Simulated vendor state changes: 4`** counts the four approved writes. None happened before the
  approval.
