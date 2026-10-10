# Sample: threat intelligence sweep with a degraded source

Workflow [`threat-intel-sweep`](../../workflows/threat-intel-sweep/README.md) 1.0.0 (Phase 5), scenario
`tests/fixtures/workflows/threat-intel-sweep/degraded-source.yaml`, simulated live. The simulator
generated this output with simulated adapters only: fake lab data, nothing left the process.
Regenerate it with:

```
python tools/simulator/simulate.py --workflow threat-intel-sweep --scenario degraded-source --live --check
```

<!-- simulate: --workflow threat-intel-sweep --scenario degraded-source --live --check -->
```text
Scenario threat-intel-sweep/degraded-source (SIMULATED LIVE): Same sweep as tp-approve-all, but Secure Email Threat Defense (an expected source) is unavailable for every read. The run lists it as degraded and still recommends the whole package: the Defender XDR hunting row names the delivered message and the rated URL and domain it carries, so the message quarantine stands on that evidence. Without Secure Email's MALICIOUS message verdict the sender is rated by Cisco XDR alone (SUSPICIOUS), so the sender is shown as considered instead of a manual block step. Confidence drops; nothing is blocked by the outage. Production parity: the block_hash and quarantine_file recommendations stay UNROUTED (no enabled adapter has a VERIFIED write for them; shown for manual handling, never executed); isolate_endpoint through secure_endpoint cannot be read back by the real adapter and ends UNABLE_TO_VERIFY, so containment is PARTIALLY_CONTAINED.
workflow threat-intel-sweep 1.0.0: risk 85, confidence 57
rule block_swept_hash: UNROUTED block_hash:7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5
rule block_swept_domain: PROPOSED block_domain:update-relay.test
rule block_swept_ip: PROPOSED block_ip:198.51.100.77
rule block_swept_url: PROPOSED block_url:https://update-relay.test/dl/invoice-viewer
rule isolate_affected_endpoint_secure_endpoint: PROPOSED isolate_endpoint:TH-LT-1047
rule quarantine_swept_file: UNROUTED quarantine_file:TH-LT-1047/7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5
rule quarantine_swept_file: UNROUTED quarantine_file:TH-LT-2210/7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5
rule quarantine_carrier_message: PROPOSED quarantine_email:etd-tis-0001
rule revoke_sessions_signed_in_from_indicator: PROPOSED revoke_sessions:mlopez@example.com
note: considered, not proposed: block_sender:billing@invoice-notice.example: rated SUSPICIOUS only (one vendor alone is never MALICIOUS); 1 hit(s) (1 message(s)): the indicator is not blocked and no action rests on it alone; a human decides; degraded: secure_email failed for enrich_email_address billing@invoice-notice.example: assessed without its evidence
note: hand-off: run malware for 7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5: a rated file indicator is on endpoints: trace its process tree, origin and connections and scope it across the estate (suggestion only; nothing is started)
note: hand-off: run c2 for TH-LT-1047: the endpoint reached a rated network indicator: review its connections, DNS lookups and the process behind them (suggestion only; nothing is started)
note: hand-off: run phishing for jsmith@example.com: the mailbox received a delivered message carrying a rated indicator: review clicks, replies and the rest of the campaign (suggestion only; nothing is started)
note: hand-off: run account-takeover for mlopez@example.com: the account signed in successfully from a rated indicator: review the account for takeover (suggestion only; nothing is started)
note: rule block_swept_hash unrouted (block_hash 7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5): no enabled adapter has a VERIFIED write for block_hash; manual handling required
note: rule quarantine_swept_file unrouted (quarantine_file TH-LT-1047/7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5): no enabled adapter has a VERIFIED write for quarantine_file; manual handling required
note: rule quarantine_swept_file unrouted (quarantine_file TH-LT-2210/7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5): no enabled adapter has a VERIFIED write for quarantine_file; manual handling required
note: degraded source: secure_email (UNAVAILABLE) failed for enrich_email_address billing@invoice-notice.example
note: degraded source: secure_email (UNAVAILABLE) failed for investigate_email etd-tis-0001
note: degraded source: secure_email (UNAVAILABLE) failed for search_email_campaign etd-tis-0001
note: not proposed: block_hash 7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5 (no enabled adapter has a VERIFIED write for block_hash)
note: not proposed: quarantine_file TH-LT-1047/7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5 (no enabled adapter has a VERIFIED write for quarantine_file)
note: not proposed: quarantine_file TH-LT-2210/7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5 (no enabled adapter has a VERIFIED write for quarantine_file)

=== Analyst decision card ===
HIGH INCIDENT  XDR-TIS-0005
IOC sweep: high-confidence indicators from the threat intelligence feed
Endpoint: TH-LT-1047
User: mlopez@example.com
Risk 85/100 (CRITICAL)   Confidence 57%
Primary evidence:
  [1] cisco_xdr: cisco_xdr rates 198.51.100.77 MALICIOUS (risk 85, confidence 80)
  [2] cisco_xdr: cisco_xdr rates 7e3a91c57e3a... MALICIOUS (risk 90, confidence 85)
  [3] cisco_xdr: cisco_xdr rates https://update-relay.test/dl/invoice-viewer MALICIOUS (risk 85, confidence 80)
  [4] cisco_xdr: cisco_xdr rates update-relay.test MALICIOUS (risk 85, confidence 80)
  [5] microsoft_cloud: microsoft_cloud: TH-LT-1047 queried update-relay.test x3 (allowed)
  [6] microsoft_cloud: microsoft_cloud: message etd-tis-0001 from billing@invoice-notice.example to 1 recipient(s), UNKNOWN, inbox
  [7] microsoft_cloud: microsoft_cloud: sign-in success for mlopez@example.com from 198.51.100.77 (ZZ) to Office 365 Exchange Online at 2026-01-15T07:42:00Z, MFA satisfied
  [8] secure_endpoint: secure_endpoint: 7e3a91c57e3a... seen on 2 endpoint(s), MALICIOUS
  [9] secure_endpoint: secure_endpoint: HIGH detection 'Sample.Loader.InvoiceViewer' (MALICIOUS) on TH-LT-1047
  [10] secure_endpoint: secure_endpoint: process_start invoice-viewer.exe on TH-LT-1047 at 2026-01-14T09:15:00Z (x1)
  ... 4 more evidence items in the full package
Blast radius: 1 endpoint, 1 user, 1 domain, 1 URL, 1 IP address, 1 email message
Recommended containment:
  [ ] block_domain update-relay.test                         (STANDARD)  risk 50  confidence 50%  via umbrella         evidence [4, 5, 6, 12]
  [ ] block_ip 198.51.100.77                                 (STANDARD)  risk 50  confidence 50%  via meraki           evidence [1, 5, 7, 11]
  [ ] block_url https://update-relay.test/dl/invoice-viewer  (STANDARD)  risk 50  confidence 50%  via umbrella         evidence [3, 6, 14]
  [ ] isolate_endpoint TH-LT-1047                            (STANDARD)  risk 85  confidence 95%  via secure_endpoint  evidence [1, 2, 4, 5, 8, 9, 10, 11, 12, 13]
  [ ] quarantine_email etd-tis-0001                          (STANDARD)  risk 50  confidence 45%  via secure_email     evidence [3, 4, 6, 12, 14]
  [ ] revoke_sessions mlopez@example.com                     (STANDARD)  risk 50  confidence 50%  via entra            evidence [1, 7, 11]
Package 00000000000000000000000000000001  workflow threat-intel-sweep 1.0.0  evidence sha256 91f8ffccaacf  approve before 2026-01-15T16:00:00Z
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]

Decision APPROVE_ALL; incident now PARTIALLY_CONTAINED

=== Containment result ===
CONTAINMENT RESULT  XDR-TIS-0005
Overall: PARTIALLY_CONTAINED
Package 00000000000000000000000000000001  approval token 00000000000000000000000000000003
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  block_domain update-relay.test                         via umbrella         verification VERIFIED          control registered
  [SUCCESS]  block_ip 198.51.100.77                                 via meraki           verification VERIFIED          control registered
  [SUCCESS]  block_url https://update-relay.test/dl/invoice-viewer  via umbrella         verification VERIFIED          control registered
  [SUCCESS]  isolate_endpoint TH-LT-1047                            via secure_endpoint  verification UNABLE_TO_VERIFY  control registered  ATTENTION
  [SUCCESS]  quarantine_email etd-tis-0001                          via secure_email     verification VERIFIED          control registered
  [SUCCESS]  revoke_sessions mlopez@example.com                     via entra            verification VERIFIED
Attention:
  - Requires attention: isolate_endpoint TH-LT-1047 - verify manually (UNABLE_TO_VERIFY)
Temporary controls registered: 5 (release needs a separate release approval)
Simulated vendor state changes: 6
All scenario expectations met.
```

## How to read it

- **A failed source does not block the recommendation.** The scenario makes Secure Email Threat
  Defense (`secure_email`) unavailable for every read. The run reports it in three
  `degraded source` notes and still recommends the package from the evidence of the other sources.
  Confidence drops to 57 (risk 85). The fault is injected on read operations only, which is why the
  approved `quarantine_email` still succeeds in this simulation.
- **One vendor alone is never MALICIOUS.** Without the Secure Email message verdict, Cisco XDR alone
  rates the sender `SUSPICIOUS`. The sender block is listed as `considered, not proposed`, with the
  failed source named (`degraded: secure_email failed ...`), and no action rests on that rating alone.
- **`UNROUTED` recommendations.** The hash block and the two file quarantines have evidence, but no
  enabled adapter has a VERIFIED write for them (`block_hash` would need Defender for Endpoint or a
  native Cisco XDR route; `quarantine_file` has no VERIFIED write anywhere). They are listed for manual
  handling and never executed.
- **Evidence.** The card shows the first ten numbered evidence items and says how many more are in the
  full package (`... 4 more evidence items`). Every action cites evidence numbers from the same package.
- **Hand-offs** to `malware`, `c2`, `phishing` and `account-takeover` are suggestions for the analyst.
  Nothing is started.
- **After the approval.** The lab `analyst` approved the six actions (all `STANDARD`). They ran
  automatically. The Umbrella, Meraki, Secure Email and Entra actions read back as `VERIFIED`; the
  Secure Endpoint isolation cannot be read back (`UNABLE_TO_VERIFY`, `ATTENTION`), so the overall result
  is `PARTIALLY_CONTAINED`. Five actions became temporary controls (`revoke_sessions` creates none);
  releasing them needs a separate human release approval.
