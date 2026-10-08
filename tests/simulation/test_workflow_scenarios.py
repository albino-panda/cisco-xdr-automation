"""Every workflow scenario through the full lifecycle, in each of its modes (architecture 14.3.9, 14.5.3).

Scenarios are discovered (``tests/fixtures/workflows/<workflow id>/*.yaml`` plus the tests-only sample
workflow's scenarios); this file never lists workflows or scenarios, so workflow agents never edit it.
Each run must meet its ``expect`` block and the implicit assertions: zero state-changing calls and
zero guard denials before the analyst decision, evidence that cites the run's records, separate risk
and confidence, ELEVATED with a warning for every critical asset (and an analyst alone refused on a
``critical_asset`` scenario), AI and automation principals refused, an intact audit chain and no rule
or hook error.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.sample_workflows import SAMPLE_PACKAGE, SAMPLE_SCENARIO_DIR
from tools.simulator.workflow_scenario import (
    WorkflowScenarioRun,
    check_coverage,
    discover_workflow_scenarios,
    load_workflow_scenario,
)
from xdr_response import guard
from xdr_response.workflows.discovery import WorkflowCatalog, discover_workflows
from xdr_response.workflows.runner import RuleOutcomeStatus

PRODUCTION = discover_workflows()
SAMPLE = discover_workflows(SAMPLE_PACKAGE)


def _cases(catalog: WorkflowCatalog, scenarios: dict[str, list[Path]], label: str) -> list:
    cases = []
    for workflow_id, paths in scenarios.items():
        for path in paths:
            for live in load_workflow_scenario(path).modes():
                mode = "live" if live else "dry_run"
                cases.append(pytest.param(catalog, path, live, id=f"{label}:{workflow_id}/{path.stem}[{mode}]"))
    return cases


PRODUCTION_SCENARIOS = discover_workflow_scenarios(catalog=PRODUCTION)
SAMPLE_SCENARIOS = discover_workflow_scenarios(SAMPLE_SCENARIO_DIR, catalog=SAMPLE)
CASES = _cases(PRODUCTION, PRODUCTION_SCENARIOS, "workflow") + _cases(SAMPLE, SAMPLE_SCENARIOS, "sample")


@pytest.mark.parametrize("catalog, path, live", CASES)
def test_scenario(catalog: WorkflowCatalog, path: Path, live: bool):
    run = WorkflowScenarioRun(load_workflow_scenario(path), live=live, catalog=catalog).play()
    assert run.workflow_run is not None, "the incident must run through its workflow"
    assert run.check() == []
    assert run.implicit_problems() == []
    if not live:
        assert run.environment.state_changing_calls() == []
        assert run.runtime.registry.list() == []


@pytest.mark.parametrize("workflow_id", sorted(PRODUCTION.ids()))
def test_every_production_workflow_meets_the_minimum_scenario_set(workflow_id: str):
    paths = PRODUCTION_SCENARIOS.get(workflow_id, [])
    scenarios = [load_workflow_scenario(p) for p in paths]
    assert check_coverage(workflow_id, scenarios, PRODUCTION.get(workflow_id).definition) == []


def test_the_sample_workflow_proposes_every_rule_somewhere():
    workflow = SAMPLE.get("sample-malware")
    scenarios = [load_workflow_scenario(p) for p in SAMPLE_SCENARIOS["sample-malware"]]
    proposed: set[str] = set()
    for scenario in scenarios:
        run = WorkflowScenarioRun(scenario, live=False, catalog=SAMPLE)
        run.detect()
        proposed |= {o.rule_id for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.PROPOSED)}
        guard._reset_for_test_harness()  # one runtime per process: reset between the runs of this test
    assert check_coverage("sample-malware", scenarios, workflow.definition, proposed_rules=proposed) == []


def test_the_sample_covers_every_scenario_category():
    tags = {t for path in SAMPLE_SCENARIOS["sample-malware"] for t in load_workflow_scenario(path).tags}
    assert {"true_positive", "approve_all", "approve_selected", "reject", "benign", "degraded_source",
            "critical_asset", "partial_failure", "dry_run", "release", "edge_case"} <= tags
