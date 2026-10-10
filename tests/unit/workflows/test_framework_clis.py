"""Framework-owned command-line tools: the workflow mode of simulate.py, validate_config.py and
check_endpoints.py (architecture 14.3.9, 13.2)."""
from __future__ import annotations

import io
import shutil
from pathlib import Path

from tests.fixtures.sample_workflows import SAMPLE_PACKAGE, SAMPLE_SCENARIO_DIR
from tools.simulator import simulate
from tools.validation import check_endpoints, validate_config
from xdr_response import guard
from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType, EndpointStatus, OperationKind

REPO = Path(__file__).resolve().parents[3]
SAMPLE_ARGS = ["--package", SAMPLE_PACKAGE, "--scenario-root", str(SAMPLE_SCENARIO_DIR)]


def _simulate(*args: str) -> tuple[int, str]:
    out = io.StringIO()
    return simulate.main([*args, *SAMPLE_ARGS], out=out), out.getvalue()


def test_list_workflows_shows_ids_and_scenarios():
    code, text = _simulate("--list-workflows")
    assert code == simulate.EXIT_OK
    assert text.startswith("sample-malware 1.0.0: benign-no-action, critical-asset-elevated")


def test_a_workflow_scenario_runs_in_dry_run_by_default_and_checks():
    code, text = _simulate("--workflow", "sample-malware", "--scenario", "dry-run", "--check")
    assert code == simulate.EXIT_OK, text
    assert "Scenario sample-malware/dry-run (DRY RUN)" in text
    assert "rule isolate_infected_endpoint: PROPOSED isolate_endpoint:TH-LT-1047" in text
    assert "Would isolate: TH-LT-1047" in text and "Simulated vendor state changes: 0" in text
    assert text.rstrip().endswith("All scenario expectations met.")


def test_live_mode_skips_dry_run_only_scenarios_and_runs_live_ones():
    code, text = _simulate("--workflow", "sample-malware", "--scenario", "dry-run", "--live")
    assert code == simulate.EXIT_OK and "skipped (mode dry_run)" in text
    guard._reset_for_test_harness()
    code, text = _simulate("--workflow", "sample-malware", "--scenario", "partial-failure", "--live", "--check")
    assert code == simulate.EXIT_OK, text
    assert "PARTIALLY_CONTAINED" in text and "Simulated vendor state changes: 2" in text  # the failed call counts


def test_failed_expectations_and_usage_errors(tmp_path):
    scenarios = tmp_path / "scenarios"
    shutil.copytree(SAMPLE_SCENARIO_DIR, scenarios)
    path = scenarios / "sample-malware" / "tp-reject.yaml"
    path.write_text(path.read_text(encoding="utf-8").replace("controls: 0", "controls: 3"), encoding="utf-8")
    out = io.StringIO()
    code = simulate.main(["--workflow", "sample-malware", "--scenario", "tp-reject", "--live", "--check",
                          "--package", SAMPLE_PACKAGE, "--scenario-root", str(scenarios)], out=out)
    assert code == simulate.EXIT_FAILED and "EXPECTATION FAILED: 0 temporary controls != expected 3" in out.getvalue()
    assert _simulate("--workflow", "ransomware")[0] == simulate.EXIT_USAGE
    assert _simulate("--workflow", "sample-malware", "--scenario", "nope")[0] == simulate.EXIT_USAGE


def test_validate_config_accepts_the_repository_config_and_refuses_bypass_keys(tmp_path):
    out = io.StringIO()
    assert validate_config.main(["--config-dir", str(REPO / "config")], out=out) == validate_config.EXIT_OK
    assert "valid" in out.getvalue() and "dry_run=True" in out.getvalue()
    config = tmp_path / "config"
    shutil.copytree(REPO / "config", config)
    thresholds = config / "thresholds.yaml"
    thresholds.write_text(thresholds.read_text(encoding="utf-8") + "\nauto_approve: true\n", encoding="utf-8")
    out = io.StringIO()
    assert validate_config.main(["--config-dir", str(config)], out=out) == validate_config.EXIT_INVALID
    assert out.getvalue().startswith("INVALID:") and "auto_approve" in out.getvalue()
    assert validate_config.main(["--config-dir", str(tmp_path / "missing")], out=io.StringIO()) == 1


def test_check_endpoints_is_consistent_for_every_shipped_manifest():
    out = io.StringIO()
    assert check_endpoints.main([], out=out) == check_endpoints.EXIT_OK
    assert out.getvalue().strip() == "16 manifest(s) consistent with integrations.md"
    out = io.StringIO()
    assert check_endpoints.main(["--integration", "entra", "--list"], out=out) == check_endpoints.EXIT_OK
    assert "entra" in out.getvalue() and "VERIFIED" in out.getvalue()


def test_check_endpoints_reports_inconsistent_manifests():
    manifest = CapabilityManifest.model_construct(
        integration="meraki", display_name="x", supported_actions=frozenset({ActionType.BLOCK_IP}),
        operations=(OperationSpec(name="probe", kind=OperationKind.READ, status=EndpointStatus.VERIFIED, method="GET",
                                  source="https://docs.example/not-listed"),
                    OperationSpec.model_construct(name="later", kind=OperationKind.READ,
                                                  status=EndpointStatus.UNVERIFIED, method=None, path=None,
                                                  source="https://docs.example/x", action_types=())))
    problems = check_endpoints.check_manifest(manifest, docs="nothing here")
    assert problems == ["meraki.probe: source 'https://docs.example/not-listed' is not listed in docs/integrations.md",
                        "meraki.later: only VERIFIED operations cite sources",
                        "meraki: supports block_ip without a VERIFIED state-changing operation"]


def test_the_legacy_replay_option_is_retired():
    """14.4.3: the legacy replay and its ``--legacy`` option were deleted with the plan engine."""
    assert not hasattr(simulate, "run_legacy_cli")
    for workflow in ("web-attacks", "no-such-workflow"):
        assert simulate.main(["--legacy", workflow], out=io.StringIO()) == simulate.EXIT_USAGE, workflow


def test_all_workflows_runs_every_scenario_in_the_selected_mode():
    """``--all-workflows`` (the CI simulator loop) runs every discovered scenario, each in a child process."""
    expected = len(list((SAMPLE_SCENARIO_DIR / "sample-malware").glob("*.yaml")))
    code, text = _simulate("--all-workflows", "--check")
    assert code == simulate.EXIT_OK, text
    assert f"{expected} scenario run(s) over 1 workflow(s) (dry run): OK" in text
    assert "(SIMULATED LIVE)" not in text
    code, text = _simulate("--all-workflows", "--live", "--check")
    assert code == simulate.EXIT_OK, text
    assert f"{expected} scenario run(s) over 1 workflow(s) (simulated live): OK" in text
    assert "(DRY RUN)" not in text


def test_several_scenarios_run_in_child_processes():
    """The guard seals its verifier per process: a second runtime in-process would be refused."""
    out = io.StringIO()
    code = simulate._run_isolated([["--workflow", "sample-malware", "--scenario", "dry-run", "--check", *SAMPLE_ARGS],
                                   ["--workflow", "sample-malware", "--scenario", "benign-no-action", "--check",
                                    *SAMPLE_ARGS]], out)
    text = out.getvalue()
    assert code == simulate.EXIT_OK, text
    assert text.count("All scenario expectations met.") == 2
