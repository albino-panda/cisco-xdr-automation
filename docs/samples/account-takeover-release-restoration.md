# Sample: account takeover, release and restoration that verify end to end

Workflow [`account-takeover`](../../workflows/account-takeover/README.md) 2.0.0 (Phase 2), scenario
`tests/fixtures/workflows/account-takeover/release-restoration.yaml`, simulated live. Fake lab data
only; nothing left the process. Regenerate it with:

```
python tools/simulator/simulate.py --workflow account-takeover --scenario release-restoration --live --check
```

<!-- simulate: --workflow account-takeover --scenario release-restoration --live --check -->
```text
Scenario account-takeover/release-restoration (SIMULATED LIVE): A privileged-free account that the attacker used again after an earlier revocation: the analyst approves revoke, disable and block; all execute and verify. After the help desk reset the password and re-registered MFA, a separate human release decision re-enables the account and removes the IP block. Session revocation is not reversible and has no control to release.
workflow account-takeover 2.0.0: risk 82, confidence 82
rule revoke_compromised_sessions: PROPOSED revoke_sessions:bdiaz@example.com
rule disable_compromised_account: PROPOSED disable_user:bdiaz@example.com
rule block_attacker_ip: PROPOSED block_ip:198.51.100.199
note: step user_endpoints: no investigate_endpoint subject in the incident or earlier results

=== Analyst decision card ===
HIGH INCIDENT  XDR-ATO-0009
Repeat risky sign-in for bdiaz@example.com after session revocation
Endpoint: none
User: bdiaz@example.com
Risk 82/100 (CRITICAL)   Confidence 82%
Primary evidence:
  [1] cisco_xdr: cisco_xdr rates 198.51.100.199 MALICIOUS (risk 90, confidence 80)
  [2] entra: entra: sign-in success for bdiaz@example.com from 198.51.100.199 (NG) to Office 365 Exchange Online at 2026-01-15T10:15:00Z, MFA satisfied
  [3] entra: entra: user bdiaz@example.com, risk medium, enabled true, privileged false
Blast radius: 1 user, 1 IP address
Recommended containment:
  [ ] revoke_sessions bdiaz@example.com  (STANDARD)  risk 82  confidence 85%  via entra   evidence [1, 2, 3]
  [ ] disable_user bdiaz@example.com     (STANDARD)  risk 82  confidence 85%  via entra   evidence [1, 2, 3]
  [ ] block_ip 198.51.100.199            (STANDARD)  risk 68  confidence 75%  via meraki  evidence [1, 2]
Package 00000000000000000000000000000001  workflow account-takeover 2.0.0  evidence sha256 0506d598823f  approve before 2026-01-15T16:00:00Z
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]

Decision APPROVE_ALL; incident now CONTAINED

=== Containment result ===
CONTAINMENT RESULT  XDR-ATO-0009
Overall: CONTAINED
Package 00000000000000000000000000000001  approval token 00000000000000000000000000000003
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  revoke_sessions bdiaz@example.com  via entra   verification VERIFIED
  [SUCCESS]  disable_user bdiaz@example.com     via entra   verification VERIFIED  control registered
  [SUCCESS]  block_ip 198.51.100.199            via meraki  verification VERIFIED  control registered
Temporary controls registered: 2 (release needs a separate release approval)

=== Restoration result ===
RESTORATION RESULT  XDR-ATO-0009
Overall: RESTORED
Package 00000000000000000000000000000005  approval token 00000000000000000000000000000007
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  unblock_ip 198.51.100.199      via meraki  verification VERIFIED
  [SUCCESS]  enable_user bdiaz@example.com  via entra   verification VERIFIED
Simulated vendor state changes: 5
All scenario expectations met.
```

## How to read it

- **Every action can be read back.** Entra (revocation, disable, enable) and Meraki (IP block and
  unblock) have VERIFIED read-back endpoints, so automatic verification confirms each action:
  `verification VERIFIED`, `Overall: CONTAINED`, then `Overall: RESTORED`.
- **Two separate human approvals.** The analyst approved the containment package; the release package
  (`00000000000000000000000000000005`) needed its own human release approval and its own token
  (`...0007`). The release package lists only the controls the automation registered for this incident:
  the disable and the IP block.
- **Session revocation has nothing to release.** `revoke_sessions` is not reversible and registers no
  control, so the restoration table has two rows: `unblock_ip` and `enable_user`.
- **Before the release.** The scenario models the help desk resetting the password and re-registering
  MFA before the release decision. That is a human step outside the automation: a password or MFA reset
  has no VERIFIED write (see the known gaps in [docs/architecture.md](../architecture.md) section 15).
- **`Simulated vendor state changes: 5`** counts three containment writes and two restoration writes.
