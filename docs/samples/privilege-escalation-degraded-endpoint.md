# Sample: privilege escalation with the endpoint source down

Workflow [`privilege-escalation`](../../workflows/privilege-escalation/README.md) 2.0.0 (Phase 5),
scenario `tests/fixtures/workflows/privilege-escalation/degraded-endpoint-identity-backed.yaml`,
simulated live. Fake lab data only; nothing left the process. Regenerate it with:

```
python tools/simulator/simulate.py --workflow privilege-escalation --scenario degraded-endpoint-identity-backed --live --check
```

<!-- simulate: --workflow privilege-escalation --scenario degraded-endpoint-identity-backed --live --check -->
```text
Scenario privilege-escalation/degraded-endpoint-identity-backed (SIMULATED LIVE): Owner rule (architecture 14.14): a failed source never blocks what other evidence backs. Secure Endpoint is unavailable, so the exploit detection on TH-LT-1047 and its payload rating are missing and the endpoint cannot be isolated. The Entra records still show jsmith (named by the incident) assigning User Administrator to svc-sync-temp, an account with no sign-in before the grant. The grant is treated as suspicious, not confirmed: the role removal, both revocations and the disable of the staged account are still proposed with the failed source in their rationale; the isolation rests on endpoint evidence only and is not invented. Secure Endpoint is listed as degraded.
workflow privilege-escalation 2.0.0: risk 85, confidence 75
rule remove_unauthorized_role: PROPOSED remove_privileged_role:svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1
rule revoke_escalation_sessions: PROPOSED revoke_sessions:jsmith@example.com
rule revoke_escalation_sessions: PROPOSED revoke_sessions:svc-sync-temp@example.com
rule disable_escalation_identity: PROPOSED disable_user:svc-sync-temp@example.com
note: considered, not proposed: disable_user:jsmith@example.com: involved in an anomalous privilege change but no compromise indicator of its own (the endpoint read failed for TH-LT-1047 (secure_endpoint), so the escalation the incident reports for jsmith@example.com could not be checked: the grant is treated as suspicious, not confirmed): only the session revocation (and the privilege removal) is proposed; the approver decides on disabling it
note: critical asset: remove_privileged_role svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1 needs ELEVATED approval (WARNING: ELEVATED APPROVAL REQUIRED - remove_privileged_role on Service account svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1 (role: Non-interactive application or service account). Potential impact: Disabling a service account can stop the applications and scheduled jobs that use it.; WARNING: ELEVATED APPROVAL REQUIRED - remove_privileged_role on Privi
note: critical asset: revoke_sessions svc-sync-temp@example.com needs ELEVATED approval (WARNING: ELEVATED APPROVAL REQUIRED - revoke_sessions on Service account svc-sync-temp@example.com (role: Non-interactive application or service account). Potential impact: Disabling a service account can stop the applications and scheduled jobs that use it.; WARNING: ELEVATED APPROVAL REQUIRED - revoke_sessions on Privileged account svc-sync-temp@example.com (role: Administrator or break-glass account). Potential
note: critical asset: disable_user svc-sync-temp@example.com needs ELEVATED approval (WARNING: ELEVATED APPROVAL REQUIRED - disable_user on Service account svc-sync-temp@example.com (role: Non-interactive application or service account). Potential impact: Disabling a service account can stop the applications and scheduled jobs that use it.; WARNING: ELEVATED APPROVAL REQUIRED - disable_user on Privileged account svc-sync-temp@example.com (role: Administrator or break-glass account). Potential impact: 
note: needs investigation, not proposed: isolate_endpoint:TH-LT-1047: not assessed: secure_endpoint failed for investigate_endpoint TH-LT-1047 and no source that answered holds a record about it; the evidence for it would come from a failed source: re-run when the source recovers, or decide by hand
note: degraded source: secure_endpoint (UNAVAILABLE) failed for investigate_endpoint TH-LT-1047
note: degraded source: secure_endpoint (UNAVAILABLE) failed for enrich_hash 7d1a0c3e9b4f2a6810c5e7d93b2f4a6c8e1d0b3a5c7e9f2d4b6a8c0e2f4a6b8c

=== Analyst decision card ===
HIGH INCIDENT  XDR-PE-0014
Exploit prevention alert followed by an unapproved role assignment on TH-LT-1047
Endpoint: none
Users: jsmith@example.com, svc-sync-temp@example.com
Risk 85/100 (CRITICAL)   Confidence 75%
Primary evidence:
  [1] entra: entra: role User Administrator assigned for svc-sync-temp@example.com by jsmith@example.com
  [2] entra: entra: user jsmith@example.com, risk medium, enabled true, privileged false
  [3] entra: entra: user svc-sync-temp@example.com, risk none, enabled true, privileged true
Blast radius: 2 users
Recommended containment:
  [ ] remove_privileged_role svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1  (ELEVATED)  risk 85  confidence 75%  via entra  evidence [1]
  [ ] revoke_sessions jsmith@example.com                                                     (STANDARD)  risk 75  confidence 75%  via entra  evidence [1, 2]
  [ ] revoke_sessions svc-sync-temp@example.com                                              (ELEVATED)  risk 85  confidence 75%  via entra  evidence [1, 3]
  [ ] disable_user svc-sync-temp@example.com                                                 (ELEVATED)  risk 85  confidence 75%  via entra  evidence [1, 3]
WARNING: ELEVATED APPROVAL REQUIRED
  Action: remove_privileged_role svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1
  Asset: svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1 (service_account)
  Role: Non-interactive application or service account
  Potential impact: Disabling a service account can stop the applications and scheduled jobs that use it.
  Detail: remove_privileged_role on Service account svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1 (role: Non-interactive application or service account). Potential impact: Disabling a service account can stop the applications and scheduled jobs that use it.
  Requires an approver holding the elevated approval role. The action is not blocked.
WARNING: ELEVATED APPROVAL REQUIRED
  Action: remove_privileged_role svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1
  Asset: svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1 (privileged_account)
  Role: Administrator or break-glass account
  Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Detail: remove_privileged_role on Privileged account svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1 (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Requires an approver holding the elevated approval role. The action is not blocked.
WARNING: ELEVATED APPROVAL REQUIRED
  Action: revoke_sessions svc-sync-temp@example.com
  Asset: svc-sync-temp@example.com (service_account)
  Role: Non-interactive application or service account
  Potential impact: Disabling a service account can stop the applications and scheduled jobs that use it.
  Detail: revoke_sessions on Service account svc-sync-temp@example.com (role: Non-interactive application or service account). Potential impact: Disabling a service account can stop the applications and scheduled jobs that use it.
  Requires an approver holding the elevated approval role. The action is not blocked.
WARNING: ELEVATED APPROVAL REQUIRED
  Action: revoke_sessions svc-sync-temp@example.com
  Asset: svc-sync-temp@example.com (privileged_account)
  Role: Administrator or break-glass account
  Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Detail: revoke_sessions on Privileged account svc-sync-temp@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Requires an approver holding the elevated approval role. The action is not blocked.
WARNING: ELEVATED APPROVAL REQUIRED
  Action: disable_user svc-sync-temp@example.com
  Asset: svc-sync-temp@example.com (service_account)
  Role: Non-interactive application or service account
  Potential impact: Disabling a service account can stop the applications and scheduled jobs that use it.
  Detail: disable_user on Service account svc-sync-temp@example.com (role: Non-interactive application or service account). Potential impact: Disabling a service account can stop the applications and scheduled jobs that use it.
  Requires an approver holding the elevated approval role. The action is not blocked.
WARNING: ELEVATED APPROVAL REQUIRED
  Action: disable_user svc-sync-temp@example.com
  Asset: svc-sync-temp@example.com (privileged_account)
  Role: Administrator or break-glass account
  Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Detail: disable_user on Privileged account svc-sync-temp@example.com (role: Administrator or break-glass account). Potential impact: Disabling an administrator or break-glass account can remove the ability to recover the tenant.
  Requires an approver holding the elevated approval role. The action is not blocked.
Package 00000000000000000000000000000001  workflow privilege-escalation 2.0.0  evidence sha256 b761b9c72912  approve before 2026-01-15T16:00:00Z
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]

Decision APPROVE_ALL; incident now CONTAINED

=== Containment result ===
CONTAINMENT RESULT  XDR-PE-0014
Overall: CONTAINED
Package 00000000000000000000000000000001  approval token 00000000000000000000000000000003
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  remove_privileged_role svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1  via entra  verification VERIFIED  control registered
  [SUCCESS]  revoke_sessions jsmith@example.com                                                     via entra  verification VERIFIED
  [SUCCESS]  revoke_sessions svc-sync-temp@example.com                                              via entra  verification VERIFIED
  [SUCCESS]  disable_user svc-sync-temp@example.com                                                 via entra  verification VERIFIED  control registered
Temporary controls registered: 2 (release needs a separate release approval)
Simulated vendor state changes: 4
All scenario expectations met.
```

## How to read it

- **Owner rule: a failed source never blocks what other evidence backs** (architecture 14.14.1). Secure
  Endpoint is unavailable for every read, so the exploit detection and the payload rating that the full
  scenario (`tp-approve-all`) relies on are missing. The Entra records still show the role grant to an
  account with no prior sign-in. The workflow treats the grant as suspicious, not confirmed, and still
  proposes the role removal, both revocations and the disable of the staged account. Each rationale
  says that the endpoint read failed.
- **Nothing is invented.** The isolation rests on endpoint evidence only, so it is not proposed. It is
  listed as `needs investigation, not proposed: isolate_endpoint:TH-LT-1047`, naming the failed source:
  the analyst re-runs the investigation when Secure Endpoint recovers, or decides by hand. The account
  that made the grant is revoked but not disabled; that is shown as `considered` with the failed source
  named.
- **Scores reflect the missing source.** The persistence signal of a degraded grant is SUSPICIOUS
  (severity 60, never MALICIOUS), and the failed expected source lowers confidence.
- **Approval is unchanged.** The actions on the service account are ELEVATED with a visible warning,
  and the lead approves. Execution and verification follow the approval automatically; every action
  here goes through Entra, which can read it back, so all four are `VERIFIED` and the result is
  `CONTAINED`.
