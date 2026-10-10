"""Production parity of the simulated lab, end to end (architecture 14.14.3).

The simulated adapters derive what they execute and verify from the real manifests
(``tests/unit/integrations/test_simulated_parity.py`` pins the manifests). These tests check the
consequence on real workflow runs: every workflow's ``tp-approve-all`` and ``release-restoration``
scenario, played live and approved by humans, is honest:

* each action in the package runs through an integration whose real adapter supports it; anything
  else is UNROUTED (shown for manual handling), never executed;
* a containment or restoration result is VERIFIED only where the real adapter reads it back;
* a run with an UNABLE_TO_VERIFY action is never reported CONTAINED or RESTORED (default thresholds);
* the simulator prints no lab-only section and ``--production-parity`` (kept for old command lines)
  changes nothing.

Fake lab data only; nothing leaves the process.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

from tools.simulator.scenario import REPO_ROOT
from tools.simulator.workflow_scenario import WorkflowScenarioRun, load_workflow_scenario
from xdr_response import guard
from xdr_response.integrations.simulated import production_manifest
from xdr_response.models import ContainmentOverall, RestorationOverall, VerificationStatus
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.runner import RuleOutcomeStatus

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "workflows"
CATALOG = discover_workflows()
CASES = [pytest.param(w, s, id=f"{w}/{s}") for w in CATALOG.ids() for s in ("tp-approve-all", "release-restoration")
         if (FIXTURES / w / f"{s}.yaml").exists()]


def _play(workflow: str, scenario: str) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(load_workflow_scenario(FIXTURES / workflow / f"{scenario}.yaml"), live=True,
                               catalog=CATALOG).play(probe=False)


@pytest.mark.parametrize("workflow, scenario", CASES)
def test_live_run_is_honest_about_production(workflow: str, scenario: str):
    run = _play(workflow, scenario)
    try:
        problems: list[str] = []
        package = run.detection.package
        for action in package.actions if package else ():
            real = production_manifest(action.integration or "")
            if real is None or action.action_type not in real.supported_actions:
                problems.append(f"{action.action_type.value} {action.target} routed to {action.integration}, "
                                "whose real adapter cannot execute it")
        for outcome in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED):
            assert outcome.detail, f"{outcome.selector}: an unrouted recommendation says why"
        reports = [(label, r) for label, r in (("containment", run.decision.report if run.decision else None),
                                               ("restoration", run.release_result.report if run.release_result
                                                else None)) if r is not None]
        for label, report in reports:
            unverifiable = False
            for result in report.results:
                real = production_manifest(result.integration or "")
                status = result.verification.status if result.verification else None
                if status is VerificationStatus.VERIFIED and (
                        real is None or result.action_type not in real.verifiable_actions):
                    problems.append(f"{label}: {result.action_type.value} {result.target} VERIFIED although the "
                                    f"real {result.integration} adapter cannot read it back")
                if real is not None and result.action_type not in real.supported_actions:
                    problems.append(f"{label}: {result.action_type.value} ran on {result.integration}")
                unverifiable = unverifiable or status is VerificationStatus.UNABLE_TO_VERIFY
            if unverifiable and report.overall in (ContainmentOverall.CONTAINED, RestorationOverall.RESTORED):
                problems.append(f"{label}: an UNABLE_TO_VERIFY action was reported {report.overall.value}")
        assert problems == []
    finally:
        guard._reset_for_test_harness()


def test_secure_endpoint_isolation_is_unable_to_verify_and_partially_contained():
    """The concrete case the review named: the lab no longer reports a Secure Endpoint isolation VERIFIED."""
    run = _play("credential-dumping", "tp-approve-all")
    try:
        results = {(r.action_type.value, r.integration): r for r in run.decision.report.results}
        isolation = results[("isolate_endpoint", "secure_endpoint")]
        assert isolation.verification.status is VerificationStatus.UNABLE_TO_VERIFY
        assert run.decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED
        assert not any(a.action_type.value == "block_hash" for a in run.detection.package.actions)
        unrouted = {o.selector.partition(":")[0] for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)}
        assert "block_hash" in unrouted
    finally:
        guard._reset_for_test_harness()


def _simulate(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(REPO_ROOT / "tools" / "simulator" / "simulate.py"), *args],
                          capture_output=True, text=True, encoding="utf-8", cwd=str(REPO_ROOT), timeout=300)


def test_simulator_has_no_lab_only_mode():
    base = ["--workflow", "credential-dumping", "--scenario", "critical-asset-elevated", "--live", "--check"]
    plain, legacy_flag = _simulate(*base), _simulate(*base, "--production-parity")
    assert plain.returncode == 0, plain.stdout[-2000:] + plain.stderr[-2000:]
    assert legacy_flag.returncode == 0, legacy_flag.stdout[-2000:] + legacy_flag.stderr[-2000:]
    assert plain.stdout == legacy_flag.stdout
    assert "Lab-only capability" not in plain.stdout
    assert "UNABLE_TO_VERIFY" in plain.stdout and "UNROUTED" in plain.stdout
