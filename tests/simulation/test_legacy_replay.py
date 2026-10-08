"""Phase 1 exit criterion (section 12, 14.7.1 item 3): every legacy scenario replays through the new runtime.

Every remaining ``workflows/<id>/scenarios/*.yaml`` is discovered (this file lists no workflow or
scenario): the legacy plan is built, bridged to proposals with evidence citing the legacy results,
and run through a real Phase 0 runtime in dry run (``PackageBuilder`` then the ``DryRunSimulator``).
Each replay must match the scenario's ``expect`` block and make zero state-changing calls, zero
guard denials and no temporary control. Nothing is approved and nothing is executed.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tools.simulator.legacy_replay import legacy_scenarios, replay_legacy_scenario
from xdr_plan import repo
from xdr_response.models import ApprovalLevel

REPO = Path(__file__).resolve().parents[2]
CASES = legacy_scenarios()


@pytest.mark.parametrize("workflow_id, path", [pytest.param(w, p, id=f"{w}/{p.stem}") for w, p in CASES])
def test_legacy_scenario_replays_in_dry_run(workflow_id: str, path: Path):
    replay = replay_legacy_scenario(workflow_id, path)
    assert replay.mismatches == []
    assert replay.run.environment.state_changing_calls() == []
    assert replay.run.runtime.registry.list() == []
    package = replay.package
    if package is None:
        assert not replay.bridge.proposals
        return
    assert package.dry_run
    assert package.workflow_version == "legacy"
    text = replay.dry_run_text()
    assert text.startswith("DRY RUN")
    for action in package.actions:
        assert action.evidence, "every action carries numbered evidence"
        if action.approval_level is ApprovalLevel.ELEVATED:
            assert action.warnings, "ELEVATED is always shown with a warning"


def test_every_legacy_scenario_is_replayed():
    on_disk = sorted((REPO / "workflows").glob("*/scenarios/*.yaml"))
    assert sorted(p for _, p in CASES) == on_disk
    assert len(CASES) == sum(len(repo.scenario_paths(w)) for w in repo.workflow_ids())


def test_no_scenario_asserts_requires_approval_false():
    offenders = []
    for path in sorted((REPO / "workflows").glob("*/scenarios/*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for action in (data.get("expect") or {}).get("actions") or ():
            if action.get("requires_approval", True) is not True:
                offenders.append(f"{path.relative_to(REPO).as_posix()}: {action}")
    assert offenders == []
