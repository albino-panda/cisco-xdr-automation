# Sample: ransomware containment, release and restoration

Workflow [`ransomware`](../../workflows/ransomware/README.md) 2.0.0 (Phase 2), scenario
`tests/fixtures/workflows/ransomware/release-restoration.yaml`, simulated live. Fake lab data only;
nothing left the process. Regenerate it with:

```
python tools/simulator/simulate.py --workflow ransomware --scenario release-restoration --live --check
```

<!-- simulate: --workflow ransomware --scenario release-restoration --live --check -->
```text
Scenario ransomware/release-restoration (SIMULATED LIVE): Approve and contain a kiosk with no signed-in account, then a separate human release decision (after reimaging) restores both controls: the isolation is released and the hash unblocked. Production parity: the block_hash recommendation stays UNROUTED (no enabled adapter has a VERIFIED write for it; shown for manual handling, never executed); isolate_endpoint and release_endpoint through secure_endpoint cannot be read back by the real adapters and end UNABLE_TO_VERIFY, so containment is PARTIALLY_CONTAINED, restoration is RESTORATION_FAILED and the incident stays AWAITING_RELEASE_APPROVAL.
workflow ransomware 2.0.0: risk 100, confidence 95
rule isolate_affected_hosts: PROPOSED isolate_endpoint:TH-KS-0204
rule isolate_payload_hosts: DUPLICATE isolate_endpoint:TH-KS-0204
rule block_payload_hash: UNROUTED block_hash:5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f
note: step lateral_targets: no investigate_endpoint subject in the incident or earlier results
note: step users: no investigate_user subject in the incident or earlier results
note: step authentication: no investigate_authentication subject in the incident or earlier results
note: step email_origin: no investigate_email subject in the incident or earlier results
note: step email_campaign: no search_email_campaign subject in the incident or earlier results
note: step domain_reputation: no enrich_domain subject in the incident or earlier results
note: step url_reputation: no enrich_url subject in the incident or earlier results
note: step ip_reputation: no enrich_ip subject in the incident or earlier results
note: step domain_scope: no search_domain_enterprise subject in the incident or earlier results
note: rule block_payload_hash unrouted (block_hash 5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f): no enabled adapter has a VERIFIED write for block_hash; manual handling required
note: not proposed: block_hash 5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f (no enabled adapter has a VERIFIED write for block_hash)

=== Analyst decision card ===
CRITICAL INCIDENT  XDR-RW-0009
Ransomware detected on kiosk TH-KS-0204
Endpoint: TH-KS-0204
User: none
Risk 100/100 (CRITICAL)   Confidence 95%
Primary evidence:
  [1] secure_endpoint: secure_endpoint: 5e8a1c3f5e8a... seen on 1 endpoint(s), MALICIOUS
  [2] secure_endpoint: secure_endpoint: CRITICAL detection 'Ransomware.Generic' (MALICIOUS) on TH-KS-0204
  [3] secure_endpoint: secure_endpoint: endpoint TH-KS-0204 (Windows 11), isolation not_isolated
  [4] secure_endpoint: secure_endpoint rates 5e8a1c3f5e8a... MALICIOUS (risk 95, confidence 90)
  [5] virustotal: virustotal rates 5e8a1c3f5e8a... MALICIOUS (risk 95, confidence 90)
Blast radius: 1 endpoint
Recommended containment:
  [ ] isolate_endpoint TH-KS-0204  (STANDARD)  risk 100  confidence 95%  via secure_endpoint  evidence [1, 2, 3, 4, 5]
Package 00000000000000000000000000000001  workflow ransomware 2.0.0  evidence sha256 2e05fd003ffb  approve before 2026-01-15T16:00:00Z
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]

Decision APPROVE_ALL; incident now PARTIALLY_CONTAINED

=== Containment result ===
CONTAINMENT RESULT  XDR-RW-0009
Overall: PARTIALLY_CONTAINED
Package 00000000000000000000000000000001  approval token 00000000000000000000000000000003
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  isolate_endpoint TH-KS-0204  via secure_endpoint  verification UNABLE_TO_VERIFY  control registered  ATTENTION
Attention:
  - Requires attention: isolate_endpoint TH-KS-0204 - verify manually (UNABLE_TO_VERIFY)
Temporary controls registered: 1 (release needs a separate release approval)

=== Restoration result ===
RESTORATION RESULT  XDR-RW-0009
Overall: RESTORATION_FAILED
Package 00000000000000000000000000000005  approval token 00000000000000000000000000000007
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  release_endpoint TH-KS-0204  via secure_endpoint  verification UNABLE_TO_VERIFY  ATTENTION
Attention:
  - release_endpoint TH-KS-0204: verify manually; control kept RELEASE_FAILED
Simulated vendor state changes: 2
All scenario expectations met.
```

## How to read it

- **Two separate human approvals.** The containment ran only after the analyst approved the package.
  The release ran only after a separate release approval of the release package that the restoration
  planner built from the registered temporary controls. A containment token can never authorize a
  release, and a release token can never authorize containment.
- **What production can and cannot confirm.** The kiosk runs Secure Endpoint only. The isolation and
  the release both executed (`SUCCESS`), but the real Secure Endpoint adapter cannot read the
  isolation state back (the isolation GET is UNVERIFIED in [`docs/integrations.md`](../integrations.md)),
  so both end `UNABLE_TO_VERIFY` with `ATTENTION`. Containment is therefore `PARTIALLY_CONTAINED`.
- **Why the restoration says `RESTORATION_FAILED`.** A release that cannot be confirmed is not counted
  as restored: the control is kept as `RELEASE_FAILED` and the incident stays in
  `AWAITING_RELEASE_APPROVAL` until a human checks the endpoint in the console. The release did
  execute; "failed" here means "not confirmed", and nothing is retried automatically. For a release
  that the adapters can confirm, see
  [account-takeover-release-restoration.md](account-takeover-release-restoration.md).
- **The hash block is `UNROUTED`.** No enabled adapter has a VERIFIED hash-block write, so the payload
  hash is listed for manual handling and is not in the package; there is nothing to unblock.
