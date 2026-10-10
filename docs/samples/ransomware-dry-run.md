# Sample: ransomware, dry run

Workflow [`ransomware`](../../workflows/ransomware/README.md) 2.0.0 (Phase 2), scenario
`tests/fixtures/workflows/ransomware/dry-run.yaml`. The simulator generated this output with simulated
adapters only: fake lab data, nothing left the process. Regenerate it with:

```
python tools/simulator/simulate.py --workflow ransomware --scenario dry-run --check
```

<!-- simulate: --workflow ransomware --scenario dry-run --check -->
```text
Scenario ransomware/dry-run (DRY RUN): Dry run: the package is proposed and simulated; nothing changes at any vendor and the incident stays AWAITING_APPROVAL after the (simulated) approval. Production parity: the block_hash recommendation stays UNROUTED (no enabled adapter has a VERIFIED write for it; shown for manual handling, never executed).
workflow ransomware 2.0.0: risk 100, confidence 88
rule isolate_affected_hosts: PROPOSED isolate_endpoint:TH-LT-1047
rule isolate_payload_hosts: DUPLICATE isolate_endpoint:TH-LT-1047
rule block_payload_hash: UNROUTED block_hash:5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f
rule revoke_affected_user_sessions: PROPOSED revoke_sessions:jsmith@example.com
note: step lateral_targets: no investigate_endpoint subject in the incident or earlier results
note: step email_origin: no investigate_email subject in the incident or earlier results
note: step email_campaign: no search_email_campaign subject in the incident or earlier results
note: step domain_reputation: no enrich_domain subject in the incident or earlier results
note: step url_reputation: no enrich_url subject in the incident or earlier results
note: step ip_reputation: no enrich_ip subject in the incident or earlier results
note: step domain_scope: no search_domain_enterprise subject in the incident or earlier results
note: rule block_payload_hash unrouted (block_hash 5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f): no enabled adapter has a VERIFIED write for block_hash; manual handling required
note: not proposed: block_hash 5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f5e8a1c3f (no enabled adapter has a VERIFIED write for block_hash)

=== Analyst decision card ===
CRITICAL INCIDENT  XDR-RW-0008
Ransomware detected on TH-LT-1047
DRY RUN package: approval is simulated; no containment actions will be executed.
Endpoint: TH-LT-1047
User: jsmith@example.com
Risk 100/100 (CRITICAL)   Confidence 88%
Primary evidence:
  [1] entra: entra: user jsmith@example.com, risk low, enabled true, privileged false
  [2] secure_endpoint: secure_endpoint: 5e8a1c3f5e8a... seen on 1 endpoint(s), MALICIOUS
  [3] secure_endpoint: secure_endpoint: CRITICAL detection 'Ransomware.Generic' (MALICIOUS) on TH-LT-1047
  [4] secure_endpoint: secure_endpoint: endpoint TH-LT-1047 (Windows 11), isolation not_isolated
  [5] secure_endpoint: secure_endpoint rates 5e8a1c3f5e8a... MALICIOUS (risk 95, confidence 90)
  [6] virustotal: virustotal rates 5e8a1c3f5e8a... MALICIOUS (risk 95, confidence 90)
Blast radius: 1 endpoint, 1 user
Recommended containment:
  [ ] isolate_endpoint TH-LT-1047         (STANDARD)  risk 100  confidence 95%  via secure_endpoint  evidence [2, 3, 4, 5, 6]
  [ ] revoke_sessions jsmith@example.com  (STANDARD)  risk 95   confidence 80%  via entra            evidence [1, 3, 4]
Package 00000000000000000000000000000001  workflow ransomware 2.0.0  evidence sha256 b46011542c1a  approve before 2026-01-15T16:00:00Z
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]

=== Containment preview (dry run) ===
DRY RUN
Would isolate: TH-LT-1047
Would revoke sessions: jsmith@example.com
No containment actions executed.

Decision APPROVE_ALL; incident now AWAITING_APPROVAL
Simulated vendor state changes: 0
All scenario expectations met.
```

## How to read it

- **Header lines (before the card).** The simulator prints the scenario, the workflow result
  (`risk 100, confidence 88`: two separate scores), one line per recommendation rule and the run
  notes. `DUPLICATE` means a second rule proposed the same `isolate_endpoint:TH-LT-1047`; the two
  proposals were merged into one action. The `no ... subject` notes are investigation steps that had
  nothing to look up in this incident (no email, URL or IP observable). They are not errors.
- **`UNROUTED` is a recommendation for manual handling.** `block_payload_hash` found a malicious
  payload hash, but no enabled adapter in this scenario has a VERIFIED hash-block write (the Secure
  Endpoint file-list endpoints are UNVERIFIED). The hash is listed in the notes
  (`manual handling required`, `not proposed`) and is not in the package, so it is never executed and
  the preview does not show it. It is not dropped silently.
- **Primary evidence.** Each item is numbered and names the integration that produced the record.
  Every recommended action lists the evidence numbers it rests on (`evidence [2, 3, 4, 5, 6]`). The
  evidence builder can only cite records of this run, so nothing on the card is invented.
- **Risk and confidence.** The card shows them separately for the incident (`Risk 100/100 (CRITICAL)
  Confidence 88%`) and for each action. The risk band comes from `scoring.bands` in
  [`config/thresholds.yaml`](../../config/thresholds.yaml).
- **Approval level.** Both actions are `STANDARD`: no critical asset is involved. `revoke_sessions`
  waits for the same human approval as the isolation.
- **Dry run.** The card says `DRY RUN package`. The containment preview lists what would happen
  (`Would isolate: TH-LT-1047`) and ends with `No containment actions executed.` The simulated
  approval in the scenario leaves the incident in `AWAITING_APPROVAL`, and
  `Simulated vendor state changes: 0` confirms that no write reached any adapter. The guard refuses
  every write in dry run, even with a valid token.
- **`All scenario expectations met.`** `--check` compared the run with the `expect` block of the
  scenario and the implicit assertions (zero state changes before the decision, evidence citing the
  records of the run, AI and automation approvers refused, intact audit chain).
