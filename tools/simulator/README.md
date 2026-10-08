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

A scenario has `incident`, `environment` (`reputations` with optional `integrations`, `categories`
and `first_seen` (ISO 8601 with offset; both reported in the enrichment evidence), `findings`,
`preexisting` controls, `faults`, `health`, `invalid_targets`), `analyst` and `release` decisions
(`decision`, `approvers`, `select`, `comment`) and an `expect` block checked by `--check`.

Exit codes: 0 completed (and expectations met with `--check`), 1 expectations not met or a decision
refused, 2 usage error.

## Workflow scenarios (Phase 1)

Workflow scenarios live in `tests/fixtures/workflows/<workflow id>/<name>.yaml` (format and minimum
set: `docs/architecture.md` 14.5.2 and 14.5.3). They run through the workflow framework: the incident
is routed to its workflow, investigated with typed records that the simulated adapters serve, scored
and recommended; the analyst decision and the release are played from the scenario.

```
python tools/simulator/simulate.py --list-workflows
python tools/simulator/simulate.py --workflow ransomware                      # every scenario, dry run
python tools/simulator/simulate.py --workflow ransomware --scenario tp-approve-all --live --check
```

`--check` asserts the scenario's `expect` block plus the implicit assertions every scenario gets:
zero state-changing calls and zero guard denials before the analyst decision, evidence that cites
the run's records, separate risk and confidence, ELEVATED with a warning for every critical asset
(and an analyst alone refused on a `critical_asset` scenario), AI and automation principals refused,
an intact audit chain and no rule or hook error. A scenario whose `mode` excludes the chosen mode is
skipped.

Modules: `workflow_scenario.py` (`WorkflowScenario`, `load_workflow_scenario`,
`discover_workflow_scenarios`, `WorkflowScenarioRun`, `check_coverage`). `ScenarioRun` accepts
`workflows=` (a `WorkflowCatalog`) and `observers=` (lifecycle observers) for the runtime. The
tests-only sample workflow and its scenarios are in `tests/fixtures/sample_workflows/`.

When several scenarios are selected (no `--scenario`), each one runs in its own child process: the
execution guard allows one runtime per process because its approval verifier slot is sealed.

## Legacy replay (Phase 1)

The legacy specs (`workflows/<id>/scenarios/*.yaml`) replay through the runtime in **dry run only**
(`docs/architecture.md` 14.3.8 and 14.9.1). The legacy plan is built by `engine/xdr_plan`, bridged to
proposals by `xdr_response.lifecycle.plan_bridge` (evidence cites the legacy results), packaged by
`PackageBuilder` (allow-lists, ELEVATED for protected assets, blast-radius caps from the scenario's
guardrails) and simulated. Nothing is approved and nothing is executed.

```
python tools/simulator/simulate.py --legacy web-attacks                     # every scenario of the workflow
python tools/simulator/simulate.py --legacy web-attacks 01-confirmed-web-shell --check
```

`--check` compares the package with the scenario's `expect` block (planned actions in the package,
`elevated: true` as ELEVATED with a warning, skipped actions absent, `escalate` as a blast-radius
warning) and fails on any state-changing call or guard denial. `tests/simulation/test_legacy_replay.py`
replays all of them.
