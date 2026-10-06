# Simulator

Runs a fixture incident through the whole `xdr_response` lifecycle against the simulated adapter
environment (`xdr_response.integrations.simulated`). Nothing leaves the process: no HTTP, an
in-memory audit trail, control registry and token ledger, and lab approvers with random credentials
created per run.

```
python tools/simulator/simulate.py --list
python tools/simulator/simulate.py ransomware                  # dry run (default)
python tools/simulator/simulate.py ransomware --live           # simulated-live execution
python tools/simulator/simulate.py phishing --live --decision APPROVE_ALL
python tools/simulator/simulate.py ransomware_domain_controller --live --approver analyst   # refused: ELEVATED
python tools/simulator/simulate.py account_takeover --live --check --audit-out var/sim/audit.jsonl
```

Output, in order:

1. the analyst decision card (evidence, risk and confidence, blast radius, ELEVATED warnings);
2. the containment result: the `DRY RUN` block (`Would isolate: TH-LT-1047`) in dry-run mode, or
   the per-action results with verification in simulated-live mode;
3. the release package checklist and, after the simulated release approval, the restoration result
   (simulated-live only; a dry run creates no temporary controls);
4. the audit-chain verification and the number of simulated vendor state changes.

The approvals are real: the simulator calls the production `ApprovalEngine`, which issues HMAC
tokens only to authenticated HUMAN principals (`analyst`, `lead`). The `automation` and `ai` aliases
exist so you can watch them being refused. Every simulated write still goes through the execution
guard.

## Scenarios

Scenario files live in `tests/fixtures/incidents/` and are shared with `tests/simulation/`:

| Scenario | What it shows |
|---|---|
| `ransomware` | TH-LT-1047 isolation, hash, C2 domain and IP blocks; approve all; release and restore |
| `phishing` | email quarantine, URL and domain blocks, session revocation; APPROVE_SELECTED rejects disabling the account |
| `account_takeover` | disable user and revoke sessions; the attacker IP is already blocked (ALREADY_CONTAINED, no control) |
| `ransomware_domain_controller` | TH-DC-02 needs ELEVATED approval (lead); TH-DC-01 is allow-listed and excluded |

A scenario has `incident`, `environment` (`reputations` with optional `integrations`, `findings`,
`preexisting` controls, `faults`, `health`, `invalid_targets`), `analyst` and `release` decisions
(`decision`, `approvers`, `select`, `comment`) and an `expect` block checked by `--check`.

Exit codes: 0 completed (and expectations met with `--check`), 1 expectations not met or a decision
refused, 2 usage error.
