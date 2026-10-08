# Workflow scenarios

One directory per migrated workflow: `tests/fixtures/workflows/<workflow id>/<name>.yaml`. The
directory name must be a discovered workflow id; the file stem must equal the scenario `name`.
Scenarios are found automatically (`discover_workflow_scenarios()` in
`tools/simulator/workflow_scenario.py`), so no test file lists them.

- Format: `docs/architecture.md` 14.5.2 (`schema: 1`, closed tag vocabulary, typed `records` served
  by simulated adapters, lab-only `config` overrides without approval keys, `expect` block).
- Minimum set per workflow: 14.5.3 (`tp-approve-all`, `tp-approve-selected`, `tp-reject`,
  `benign-no-action`, `degraded-source`, `critical-asset-elevated`, `partial-failure`, `dry-run`,
  `release-restoration`, at least two `edge-<slug>`, one `legacy-<NN>-<slug>` per legacy scenario).
- Every scenario runs in `tests/simulation/test_workflow_scenarios.py` in each of its modes, with the
  implicit safety assertions of 14.5.3 that a scenario cannot switch off.
- Run one: `python tools/simulator/simulate.py --workflow <id> --scenario <name> [--live] --check`.

All data is fake: `example.com`, `*.example`, `*.test`, documentation IP ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), fake 64-hex hashes, hosts like `TH-LT-1047`, users like
`jsmith@example.com`. A complete example is the tests-only sample workflow in
`tests/fixtures/sample_workflows/scenarios/sample-malware/`.
