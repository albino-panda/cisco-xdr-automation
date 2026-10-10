# Sample analyst output

What an analyst sees: the decision card, the containment preview or result, the restoration result,
and the simulator's notes. The simulator generated every sample from a workflow scenario in
`tests/fixtures/workflows/`. It uses simulated adapters, the real approval engine and the real execution
guard. All data is fake lab data, and nothing leaves the process.

| Sample | Workflow (phase) | Mode | What it shows |
|---|---|---|---|
| [ransomware-dry-run.md](ransomware-dry-run.md) | `ransomware` 2.0.0 (2) | dry run | numbered evidence, separate risk and confidence, an `UNROUTED` hash block listed for manual handling, the `DRY RUN` preview (`Would isolate: TH-LT-1047`), zero vendor state changes |
| [ransomware-release-restoration.md](ransomware-release-restoration.md) | `ransomware` 2.0.0 (2) | simulated live | a Secure Endpoint-only kiosk: isolation and release execute but cannot be read back (`UNABLE_TO_VERIFY`), so containment is `PARTIALLY_CONTAINED` and the restoration table says `RESTORATION_FAILED` (not confirmed) |
| [account-takeover-release-restoration.md](account-takeover-release-restoration.md) | `account-takeover` 2.0.0 (2) | simulated live | containment and a separate release approval where every action reads back: `CONTAINED`, then a `RESTORED` restoration table |
| [phishing-release-restoration.md](phishing-release-restoration.md) | `phishing` 1.0.0 (2) | simulated live | a mixed release: messages, domain block and account verify; the endpoint release is `UNABLE_TO_VERIFY`, so restoration is `PARTIALLY_RESTORED` |
| [credential-dumping-elevated.md](credential-dumping-elevated.md) | `credential-dumping` 3.0.0 (3) | simulated live | a privileged account in the blast radius: ELEVATED approval with a visible warning per action, a manual step, a hand-off, an `UNROUTED` hash block, `PARTIALLY_CONTAINED` after the lead's approval |
| [credential-dumping-defender-hash-block.md](credential-dumping-defender-hash-block.md) | `credential-dumping` 3.0.0 (3) | simulated live | with Defender for Endpoint enabled the hash block routes there and executes; Defender indicators and Secure Endpoint isolation both end `UNABLE_TO_VERIFY` |
| [threat-intel-sweep-degraded-source.md](threat-intel-sweep-degraded-source.md) | `threat-intel-sweep` 1.0.0 (5) | simulated live | an unavailable source reported as degraded while the other sources still back the package; a single-vendor rating shown as considered, not proposed |
| [privilege-escalation-degraded-endpoint.md](privilege-escalation-degraded-endpoint.md) | `privilege-escalation` 2.0.0 (5) | simulated live | owner rule: the endpoint source is down and the identity evidence still backs the role removal, revocations and disable; the isolation is listed as "needs investigation", not invented |
| [malware-more-investigation.md](malware-more-investigation.md) | `malware` 2.0.0 (2) | simulated live | the `REQUEST_MORE_INVESTIGATION` decision: no token, nothing executed, back to `NOT_STARTED` |

**The simulated adapters do what the real adapters do, and nothing more** (architecture 14.14.3). Each
simulated adapter takes its state-changing actions and its read-backs from the real adapter's
capability manifest. So the samples show production outcomes:

- `UNROUTED`: no enabled adapter has a VERIFIED write for the action. The recommendation is shown with
  its evidence for manual handling and is never executed. Examples: `block_hash` in a Secure
  Endpoint-only tenant, `terminate_process` and `quarantine_file` everywhere.
- `UNABLE_TO_VERIFY`: the action executed, but its read-back endpoint is UNVERIFIED (Secure Endpoint
  isolation, Defender for Endpoint indicators, every native Cisco XDR action, Defender for Office 365
  email actions, the Intune remote lock). The row carries `ATTENTION`, the analyst confirms it by hand,
  and the overall result is `PARTIALLY_CONTAINED` (or `PARTIALLY_RESTORED` / `RESTORATION_FAILED`)
  while `unable_to_verify_counts_as_contained` is false.

The list of what the real adapters cannot do, and what would close each gap, is in
[architecture section 15](../architecture.md#15-known-gaps-and-owner-decisions).

**Other workflows.** The samples cover 7 of the 22 workflows. Any workflow scenario can be shown the
same way, for example `python tools/simulator/simulate.py --workflow <id> --scenario tp-approve-all --live --check`;
`python tools/simulator/simulate.py --list-workflows` lists every workflow and its scenarios
(`tp-approve-all`, `tp-reject`, `more-investigation`, `degraded-source`, `release-restoration`, ...).

## Regenerate

The output is deterministic: the simulator uses a fixed clock and fixed ids. Each sample names its
command, and an HTML comment above its output block holds the simulator arguments.
`tests/simulation/test_docs_samples.py` runs each command and fails when a sample's output block no
longer matches the simulator. After an intended change to the card or a workflow, run the command and
paste the new output into the block.

In workflow-scenario mode (`--workflow`) the analyst decision, the approvers and the release come
from the scenario file. `--decision`, `--approver`, `--no-release` and `--audit-out` apply only to the
bundled incident scenarios (`simulate.py ransomware`, ...). To watch a refusal, use a bundled scenario,
for example `python tools/simulator/simulate.py ransomware_domain_controller --live --approver analyst`.

To see a release and restoration for a workflow, run its `release-restoration` scenario:

```
python tools/simulator/simulate.py --workflow account-takeover --scenario release-restoration --live --check
```
