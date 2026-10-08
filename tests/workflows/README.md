# Workflow unit tests

One directory per migrated workflow: `tests/workflows/<x_snake>/test_*.py` (`<x_snake>` is the
workflow id with `-` replaced by `_`), owned by that workflow's agent (`docs/architecture.md`
14.5.1). They test the workflow's own rules and hooks; the framework itself is tested in
`tests/unit/workflows/`, and every scenario of the workflow runs automatically in
`tests/simulation/test_workflow_scenarios.py`.

Useful helpers: `tests/fixtures/sample_workflows/lab.py` (`make_lab()` builds a simulated read-only
lab with a `WorkflowRunner`; `Lab.typed(...)` registers typed records) and
`tests.fixtures.sample_workflows.lab.make_incident`.

A workflow is done (14.5.4) when its definition imports and validates,
`python tools/validation/check_workflow_readmes.py --workflow <X>` passes,
`python -m pytest -q -p no:cacheprovider tests/workflows/<x_snake> tests/simulation/test_workflow_scenarios.py -k <X>`
passes and the read-zone safety tests (`tests/safety/test_read_zone.py`) pass.
