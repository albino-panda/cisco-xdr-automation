"""Dry run never reaches a state-changing call, for every fixture incident."""
from __future__ import annotations

import io

import pytest

from tools.simulator import simulate
from tools.simulator.scenario import ScenarioRun, list_scenarios, load_scenario
from xdr_response import guard
from xdr_response.dryrun import render_dry_run
from xdr_response.errors import DryRunViolationError
from xdr_response.models import ActionRequest, ActionResultStatus, AuditEventType, IncidentState, SkipReason
from xdr_response.reporting import render_decision_card

SCENARIOS = list_scenarios()


def test_the_four_fixture_incidents_are_bundled():
    assert set(SCENARIOS) >= {"ransomware", "phishing", "account_takeover", "ransomware_domain_controller"}


@pytest.mark.parametrize("name", SCENARIOS)
def test_dry_run_produces_no_state_changes(name):
    run = ScenarioRun(load_scenario(name), live=False)
    assert guard.is_dry_run()
    detection = run.detect()
    assert detection.package is not None and detection.package.dry_run
    text = render_dry_run(detection.dry_run_report)
    lines = text.splitlines()
    assert lines[0] == "DRY RUN" and lines[-1] == "No containment actions executed."
    assert len(lines) == len(detection.package.actions) + 2

    decision = run.decide(approvers=list(run.scenario.analyst.get("approvers") or ["analyst"]))
    assert decision.report.dry_run and decision.report.overall is None
    granted = set(decision.outcome.decision.approved_action_keys)
    for r in decision.report.results:  # the preview shows what the live run would do with this token
        if r.idempotency_key in granted:
            assert r.status is ActionResultStatus.DRY_RUN
        else:
            assert r.status is ActionResultStatus.SKIPPED and r.skip_reason is SkipReason.REJECTED_BY_ANALYST
    assert decision.incident.state is IncidentState.AWAITING_APPROVAL  # simulated, not advanced
    assert run.environment.state_changing_calls() == []
    assert run.runtime.registry.list() == []
    events = {r.event_type for r in run.runtime.audit.records()}
    assert AuditEventType.DRY_RUN_SIMULATION in events
    assert AuditEventType.ACTION_STARTED not in events and AuditEventType.CONTROL_REGISTERED not in events


def test_dry_run_lines_match_the_brief_format():
    run = ScenarioRun(load_scenario("ransomware"), live=False)
    detection = run.detect()
    assert "Would isolate: TH-LT-1047" in render_dry_run(detection.dry_run_report).splitlines()


def test_a_valid_token_is_still_refused_by_the_guard_in_dry_run():
    run = ScenarioRun(load_scenario("ransomware"), live=False)
    package = run.detect().package
    decision = run.decide()
    action = package.action(f"{run.incident_id}:isolate_endpoint:TH-LT-1047")
    request = ActionRequest.from_recommendation(action)
    with pytest.raises(DryRunViolationError):
        with guard.authorized(decision.outcome.token, request):
            pass  # pragma: no cover
    with pytest.raises(DryRunViolationError):
        run.runtime.adapters.get("secure_endpoint").execute(request)
    assert run.environment.state_changing_calls() == []


def test_packages_proposed_in_dry_run_stay_simulated_after_dry_run_is_switched_off():
    run = ScenarioRun(load_scenario("ransomware"), live=False)
    package = run.detect().package
    guard.configure(dry_run=False)
    report = run.runtime.executor.execute(package, None)
    assert report.dry_run and run.environment.state_changing_calls() == []


@pytest.mark.parametrize("name", SCENARIOS)
def test_decision_cards_show_evidence_scores_and_buttons(name):
    run = ScenarioRun(load_scenario(name), live=False)
    package = run.detect().package
    card = render_decision_card(package, incident_title=run.scenario.incident.title)
    assert "[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]" in card
    assert "[1] " in card and "Risk " in card and "Confidence " in card
    for action in package.actions:
        assert f"{action.action_type.value} {action.target}" in card
    if any(a.approval_level.value == "ELEVATED" for a in package.actions):
        assert "WARNING: ELEVATED APPROVAL REQUIRED" in card


# ---------------------------------------------------------------------- CLI --
@pytest.mark.parametrize("name", SCENARIOS)
def test_cli_live_runs_meet_scenario_expectations(name):
    out = io.StringIO()
    assert simulate.main([name, "--live", "--check"], out=out) == simulate.EXIT_OK
    text = out.getvalue()
    for section in ("=== Analyst decision card ===", "=== Containment result ===", "=== Release package ===",
                    "=== Restoration result ===", "chain intact", "All scenario expectations met."):
        assert section in text


def test_cli_dry_run_prints_card_dry_run_block_and_no_release():
    out = io.StringIO()
    assert simulate.main(["ransomware"], out=out) == simulate.EXIT_OK
    text = out.getvalue()
    assert "Would isolate: TH-LT-1047" in text and "No containment actions executed." in text
    assert "a dry run creates no temporary controls" in text
    assert "Simulated vendor state changes: 0 (dry run)" in text


def test_cli_reject_and_usage_errors(tmp_path):
    out = io.StringIO()
    assert simulate.main(["phishing", "--live", "--decision", "REJECT"], out=out) == simulate.EXIT_OK
    assert "incident now CLOSED" in out.getvalue()
    assert simulate.main(["no-such-scenario"], out=io.StringIO()) == simulate.EXIT_USAGE
    assert simulate.main([], out=io.StringIO()) == simulate.EXIT_USAGE
    listing = io.StringIO()
    assert simulate.main(["--list"], out=listing) == simulate.EXIT_OK
    assert "ransomware" in listing.getvalue().split()


def test_cli_refuses_a_non_human_approver_and_writes_a_verifiable_audit(tmp_path):
    out = io.StringIO()
    assert simulate.main(["ransomware", "--live", "--approver", "ai"], out=out) == simulate.EXIT_FAILED
    # One runtime per process: the first build_runtime sealed the guard's verifier slot. The CLI is
    # normally one process per run; here the harness reset stands in for a fresh process.
    guard._reset_for_test_harness()
    audit = tmp_path / "audit.jsonl"
    assert simulate.main(["ransomware", "--live", "--audit-out", str(audit)], out=io.StringIO()) == 0
    from xdr_response.audit.verify import verify_chain

    assert verify_chain(audit).ok
