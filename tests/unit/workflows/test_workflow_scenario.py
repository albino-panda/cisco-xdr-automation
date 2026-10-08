"""Scenario fixture loader, discovery and coverage (architecture 14.5.2, 14.5.3)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from tests.fixtures.sample_workflows import SAMPLE_SCENARIO_DIR
from tests.fixtures.sample_workflows.sample_malware.definition import WORKFLOW
from tools.simulator.workflow_scenario import (
    REQUIRED_SCENARIOS,
    SCENARIO_TAGS,
    WorkflowScenario,
    check_coverage,
    discover_workflow_scenarios,
    load_workflow_scenario,
    workflow_settings,
)

SAMPLE_DIR = SAMPLE_SCENARIO_DIR / "sample-malware"


def _raw(name: str = "tp-approve-all") -> dict[str, Any]:
    return yaml.safe_load((SAMPLE_DIR / f"{name}.yaml").read_text(encoding="utf-8"))


def _write(tmp_path: Path, data: dict[str, Any], *, directory: str = "sample-malware", stem: str | None = None) -> Path:
    folder = tmp_path / directory
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{stem or data['name']}.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _all() -> list[WorkflowScenario]:
    return [load_workflow_scenario(p) for p in sorted(SAMPLE_DIR.glob("*.yaml"))]


def test_every_sample_scenario_loads():
    scenarios = _all()
    assert {s.name for s in scenarios} >= set(REQUIRED_SCENARIOS)
    tp = load_workflow_scenario(SAMPLE_DIR / "tp-approve-all.yaml")
    assert tp.schema_version == 1 and tp.workflow == "sample-malware" and tp.modes() == (False, True)
    assert tp.incident.workflow_version == "0.0.0"  # assigned by the catalog when the incident is opened
    assert tp.environment.records[0].finding()["xdr_integration"] == "secure_endpoint"
    assert "records" not in tp.environment.phase0()


def test_discovery_maps_directories_to_catalog_ids(sample_catalog, tmp_path):
    found = discover_workflow_scenarios(SAMPLE_SCENARIO_DIR, catalog=sample_catalog)
    assert list(found) == ["sample-malware"] and found["sample-malware"] == sorted(SAMPLE_DIR.glob("*.yaml"))
    (tmp_path / "not-a-workflow").mkdir()
    with pytest.raises(ValueError, match="not a workflow id"):
        discover_workflow_scenarios(tmp_path, catalog=sample_catalog)
    assert discover_workflow_scenarios(tmp_path / "missing", catalog=sample_catalog) == {}


def test_name_and_directory_must_match_the_file(tmp_path):
    with pytest.raises(ValueError, match="must equal the file stem"):
        load_workflow_scenario(_write(tmp_path, _raw(), stem="renamed"))
    with pytest.raises(ValueError, match="must equal the directory"):
        load_workflow_scenario(_write(tmp_path, _raw(), directory="other-flow"))


@pytest.mark.parametrize("change, match", [
    ({"schema": 2}, "Input should be 1"),
    ({"tags": ["true_positive", "nice"]}, "unknown tags"),
    ({"mode": "sometimes"}, "Input should be"),
    ({"config": {"runtime": {"dry_run": False}}}, "may only override"),
    ({"config": {"thresholds": {"approval": {"auto_approve": True}}}}, "forbidden approval keys"),
    ({"config": {"allowlists": {"requires_approval": False}}}, "forbidden approval keys"),
    ({"suite": {"secure_endpoint": ["robots"]}}, "unknown simulated families"),
    ({"suite": {"acme": ["endpoint"]}}, "unknown integration"),
    ({"tags": ["legacy"]}, "legacy_source is required"),
    ({"tags": ["dry_run"]}, "must use mode: dry_run"),
    ({"surprise": 1}, "Extra inputs"),
])
def test_invalid_scenarios_are_refused(change, match):
    with pytest.raises(ValidationError, match=match):
        WorkflowScenario.model_validate({**_raw(), **change})


def test_incident_workflow_must_be_the_scenario_workflow():
    data = _raw()
    data["incident"] = {**data["incident"], "workflow_id": "other"}
    with pytest.raises(ValidationError, match="must equal workflow"):
        WorkflowScenario.model_validate(data)


def test_typed_records_are_checked_against_the_suite():
    data = _raw()
    record = dict(data["environment"]["records"][0])
    for bad, match in (({**record, "integration": "entra"}, "the suite has"),
                       ({**record, "atomic": "investigate_user"}, "does not serve investigate_user"),
                       ({**record, "record": {**record["record"], "record_id": "rec_x"}}, "never carry"),
                       ({**record, "record": {"hostname": "TH-LT-1047"}}, "needs a 'kind'")):
        with pytest.raises(ValidationError, match=match):
            WorkflowScenario.model_validate({**data, "environment": {**data["environment"], "records": [bad]}})


def test_config_overrides_are_deep_merged_over_the_repository_policy():
    scenario = load_workflow_scenario(SAMPLE_DIR / "edge-allowlisted-hash.yaml")
    settings = workflow_settings(scenario, dry_run=True)
    assert settings.allowlists.never_block["hashes"] == ["4a6e1b3c" * 8]
    assert settings.allowlists.never_block["endpoints"] == ["TH-DC-01"]  # repository value kept
    assert settings.runtime.dry_run is True and settings.integration("secure_endpoint").enabled
    assert not settings.integration("entra").enabled


def test_the_sample_workflow_meets_the_minimum_scenario_set():
    assert check_coverage("sample-malware", _all(), WORKFLOW) == []
    assert check_coverage("sample-malware", _all(), WORKFLOW,
                          proposed_rules=["isolate_infected_endpoint", "block_malicious_hash"]) == []


def test_coverage_reports_every_gap():
    scenarios = [s for s in _all() if s.name not in ("tp-reject", "edge-already-isolated", "edge-allowlisted-hash")]
    problems = check_coverage("sample-malware", scenarios, WORKFLOW, proposed_rules=["isolate_infected_endpoint"])
    assert "sample-malware: missing scenario tp-reject.yaml" in problems
    assert any("edge-<slug>.yaml" in p for p in problems)
    assert any("no scenario carries tags ['reject']" in p for p in problems)
    assert "sample-malware: rule block_malicious_hash is PROPOSED in no scenario" in problems
    benign_free = [s for s in _all() if "benign" not in s.tags]
    assert any("benign or below-threshold" in p for p in check_coverage("sample-malware", benign_free, WORKFLOW))


def test_legacy_scenarios_must_be_migrated(tmp_path):
    legacy = tmp_path / "workflows" / "malware" / "scenarios"
    legacy.mkdir(parents=True)
    (legacy / "01-dropper.yaml").write_text("name: x\n", encoding="utf-8")
    definition = WORKFLOW.model_copy(update={"legacy_id": "malware"})
    problems = check_coverage("sample-malware", _all(), definition, legacy_root=tmp_path / "workflows")
    assert problems == ["sample-malware: legacy scenario workflows/malware/scenarios/01-dropper.yaml is not migrated "
                        "(legacy-<NN>-<slug>.yaml)"]
    migrated = WorkflowScenario.model_validate({**_raw(), "name": "legacy-01-dropper", "tags": ["legacy"],
                                                "legacy_source": "workflows/malware/scenarios/01-dropper.yaml"})
    assert check_coverage("sample-malware", [*_all(), migrated], definition, legacy_root=tmp_path / "workflows") == []


def test_the_tag_vocabulary_is_closed():
    assert len(SCENARIO_TAGS) == 13 and "legacy" in SCENARIO_TAGS


def test_the_implicit_assertions_report_violations(sample_catalog):
    from tools.simulator.workflow_scenario import WorkflowScenarioRun

    run = WorkflowScenarioRun(load_workflow_scenario(SAMPLE_DIR / "critical-asset-elevated.yaml"), live=False,
                              catalog=sample_catalog).play()
    assert run.implicit_problems() == []
    assert run.probe.refused == {"ai": True, "automation": True}
    assert run.probe.elevated_refused_for_analyst is True
    run.probe.state_changes, run.probe.guard_denials = 1, 2
    run.probe.refused["ai"] = False
    run.probe.elevated_refused_for_analyst = False
    problems = run.implicit_problems()
    assert "1 state-changing call(s) before the analyst decision" in problems
    assert "2 guard denial(s) before the analyst decision" in problems
    assert "principal 'ai' was able to approve a package" in problems
    assert "an APPROVE_ALL by 'analyst' alone was not refused on an ELEVATED package" in problems
