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

**Production parity** (`docs/architecture.md` 14.14.3). Each simulated adapter does exactly what the
real adapter of the same integration supports and verifies: its actions and read-backs are derived
from the real manifest (`xdr_response.integrations.<name>.manifest.MANIFEST`, VERIFIED endpoints only),
so the lab cannot drift from production and there is no lab-only mode. Consequences you will see:
the Secure Endpoint isolation and release run but cannot be read back (`UNABLE_TO_VERIFY`, so the
run is `PARTIALLY_CONTAINED` and a release keeps the control `RELEASE_FAILED` until a human checks
it); a hash block runs only where Defender for Endpoint is in the suite (Secure Endpoint cannot block
hashes) and is otherwise reported UNROUTED; `terminate_process`, `quarantine_file`,
`remove_persistence`, `reset_password`, `reset_mfa`, `revoke_app_credentials` and
`remove_application` have no VERIFIED write anywhere and are always reported UNROUTED (shown for
manual handling, never executed). `--production-parity` is still accepted and changes nothing.

## Scenarios

Scenario files live in `tests/fixtures/incidents/` and are shared with `tests/simulation/`:

| Scenario | What it shows |
|---|---|
| `ransomware` | TH-LT-1047 isolation, C2 domain and IP blocks (the hash block is not proposed: no adapter in the default suite has a hash-block write); approve all; `PARTIALLY_CONTAINED` and `PARTIALLY_RESTORED` because the Secure Endpoint isolation and release are `UNABLE_TO_VERIFY` |
| `phishing` | email quarantine, URL and domain blocks, session revocation; APPROVE_SELECTED rejects disabling the account |
| `account_takeover` | disable user and revoke sessions; the attacker IP is already blocked (ALREADY_CONTAINED, no control) |
| `ransomware_domain_controller` | TH-DC-02 needs ELEVATED approval (lead); TH-DC-01 is allow-listed and excluded; isolation and release are `UNABLE_TO_VERIFY` (`PARTIALLY_CONTAINED`, `RESTORATION_FAILED` until checked by hand) |

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
python tools/simulator/simulate.py --all-workflows --check                     # every workflow, dry run
python tools/simulator/simulate.py --all-workflows --live --check              # every workflow, simulated live
```

`--check` asserts the scenario's `expect` block plus the implicit assertions every scenario gets:
zero state-changing calls and zero guard denials before the analyst decision, evidence that cites
the run's records, separate risk and confidence, ELEVATED with a warning for every critical asset
(and an analyst alone refused on a `critical_asset` scenario), AI and automation principals refused,
an intact audit chain and no rule or hook error; after a REJECT or REQUEST_MORE_INVESTIGATION
decision no token, no state change and no control, the decided package can no longer be approved,
and REQUEST_MORE_INVESTIGATION leaves the incident NOT_STARTED. A scenario whose `mode` excludes the
chosen mode is skipped.

The minimum set (`check_coverage`) requires every scenario of 14.5.3 plus `more-investigation.yaml`,
every tag of the vocabulary (`more_investigation` included; only `legacy` is optional) and every rule
expected in some scenario. A rule whose action no real adapter can execute counts as covered when a
scenario expects it UNROUTED; an executable action must be proposed somewhere (for example through a
suite with Defender for Endpoint for hash blocks).

Modules: `workflow_scenario.py` (`WorkflowScenario`, `load_workflow_scenario`,
`discover_workflow_scenarios`, `WorkflowScenarioRun`, `check_coverage`). `ScenarioRun` accepts
`workflows=` (a `WorkflowCatalog`) and `observers=` (lifecycle observers) for the runtime. The
tests-only sample workflow and its scenarios are in `tests/fixtures/sample_workflows/`.

When several scenarios are selected (no `--scenario`), each one runs in its own child process: the
execution guard allows one runtime per process because its approval verifier slot is sealed.

`--all-workflows` runs every scenario of every discovered workflow in the selected mode and prints a
summary line (`<n> scenario run(s) over <m> workflow(s) (dry run): OK`); CI runs it in both modes.

In workflow-scenario mode the analyst decision, the approvers and the release come from the scenario
file; `--decision`, `--approver`, `--no-release` and `--audit-out` apply only to the bundled incident
scenarios. Sample output for three workflows, regenerated from these commands, is in
[docs/samples](../../docs/samples/README.md).

## Scenarios from the retired spec layer

The 0.1.0 plan-rule specs and their dry-run replay were retired after Phase 5 (`docs/architecture.md`
14.4.3). Each of their scenarios lives on as a `legacy-*` workflow scenario, for example:

```
python tools/simulator/simulate.py --workflow web-attacks --scenario legacy-01-confirmed-web-shell --check
```
