"""Safety tests: a failed or degraded source never blocks what other evidence backs (architecture 14.14).

Owner rule: investigation and recommendation are automatic, and a failed or degraded source must not
block a recommendation backed by other evidence; nothing is dropped silently. The per-phase safety
files check every integration of each workflow's ``tp-approve-all`` scenario
(``test_a_failed_source_does_not_block_actions_backed_by_other_sources``). This file adds:

* the concrete cases the completeness review found, with the outcome each must now have (proposed
  on the surviving evidence, or shown below threshold / considered with the failed source named);
* a sweep over **every** workflow scenario that proposes a package, failing each of the workflow's
  expected sources in turn (:func:`tests.fixtures.degraded.degradation_findings`);
* the cases where the failed source held the **only** evidence about a target the degraded run still
  knows (the incident names it, or a read was about it): the action may not be proposed, but it is
  shown as "needs investigation" with the failed source named, in the notes, the summary and the
  analyst notification, never dropped silently;
* the runner's framework guarantees: a withheld action names the failed read, a degraded-source
  entry is never a proposal and never touches an allow-listed target, and nothing it adds cites a
  record the run does not hold;
* the check itself: with the degraded-source accounting switched off, the sweep reports the loss.

Fake data only (example.com, *.test, documentation IPs, fake hashes, hosts like TH-LT-1047).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
import yaml

from tests.fixtures.degraded import degradation_findings, with_failed_source
from tools.simulator.scenario import REPO_ROOT
from tools.simulator.workflow_scenario import WorkflowScenario, WorkflowScenarioRun
from xdr_response import guard
from xdr_response.workflows import runner as runner_module
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.runner import RuleOutcomeStatus

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "workflows"
CATALOG = discover_workflows()


def _raw(workflow: str, name: str = "tp-approve-all") -> dict[str, Any]:
    with (FIXTURES / workflow / f"{name}.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _detect(data: Mapping[str, Any], workflow: str, name: str = "tp-approve-all") -> WorkflowScenarioRun:
    scenario = WorkflowScenario.model_validate({**data, "path": FIXTURES / workflow / f"{name}.yaml"})
    run = WorkflowScenarioRun(scenario, live=False, catalog=CATALOG)
    run.detect()
    guard._reset_for_test_harness()
    return run


def _degraded(workflow: str, failed: str, name: str = "tp-approve-all") -> WorkflowScenarioRun:
    return _detect(with_failed_source(_raw(workflow, name), failed), workflow, name)


def _proposed(run: WorkflowScenarioRun) -> set[str]:
    package = run.detection.package
    return {f"{a.action_type.value}:{a.target}" for a in package.actions} if package else set()


def _considered(run: WorkflowScenarioRun) -> dict[str, str]:
    return {c.subject: c.reason for c in run.workflow_run.considered if not c.manual}


def _outcome(run: WorkflowScenarioRun, selector: str) -> Any:
    return next((o for o in run.workflow_run.outcomes if o.selector == selector), None)


def _needs(run: WorkflowScenarioRun) -> dict[str, Any]:
    return {n.subject: n for n in run.workflow_run.needs_investigation}


# --------------------------------------------------------------- the review's concrete cases --
def test_privilege_escalation_endpoint_outage_keeps_the_identity_backed_actions():
    """Secure Endpoint down: the Entra role assignment (to an account with no prior sign-in) still backs
    the role removal, both revocations and the disable of the staged account; the rationale says the
    endpoint could not be checked. The isolation (endpoint evidence only) is not invented."""
    run = _degraded("privilege-escalation", "secure_endpoint")
    proposed = _proposed(run)
    role = "remove_privileged_role:svc-sync-temp@example.com/00000000-0000-4000-8000-0000000000a1"
    for selector in (role, "revoke_sessions:jsmith@example.com", "revoke_sessions:svc-sync-temp@example.com",
                     "disable_user:svc-sync-temp@example.com"):
        assert selector in proposed, f"{selector} blocked by the failed endpoint source"
    assert "isolate_endpoint:TH-LT-1047" not in proposed
    action = next(a for a in run.detection.package.actions if f"{a.action_type.value}:{a.target}" == role)
    assert "secure_endpoint" in action.rationale and "suspicious, not confirmed" in action.rationale
    assert run.workflow_run.risk_score > 0
    assert "secure_endpoint" in run.workflow_run.degraded_sources()


def test_exfiltration_endpoint_outage_still_assesses_the_incident_account():
    """Secure Endpoint down: the transfer cannot be read, but the account the incident names is still
    assessed on its Entra records: its sessions are revoked, and the disable is shown as considered
    with the failed source named (this workflow disables an account that drives a transfer)."""
    run = _degraded("exfiltration", "secure_endpoint")
    assert "revoke_sessions:jsmith@example.com" in _proposed(run)
    reason = _considered(run)["disable_user:jsmith@example.com"]
    assert "secure_endpoint" in reason and "could not be checked" in reason
    action = next(a for a in run.detection.package.actions if a.action_type.value == "revoke_sessions")
    assert "secure_endpoint" in action.rationale


def test_threat_intel_sweep_xdr_outage_shows_every_indicator_and_account():
    """Cisco XDR down: the indicators fall to a single rating (SUSPICIOUS only, never blocked on one
    vendor), and every one of them, and the account that signed in from the IP, is shown with Cisco XDR
    named instead of disappearing."""
    run = _degraded("threat-intel-sweep", "cisco_xdr")
    considered = _considered(run)
    for selector in ("block_domain:update-relay.test", "block_ip:198.51.100.77",
                     "block_url:https://update-relay.test/dl/invoice-viewer", "revoke_sessions:mlopez@example.com"):
        assert selector in considered, f"{selector} vanished"
        assert "cisco_xdr" in considered[selector], f"{selector}: the failed source is not named"


def test_suspicious_authentication_xdr_outage_reports_scores_and_the_failed_source():
    """Cisco XDR enrichment down: the account actions are evaluated on the Entra and HIBP evidence and
    reported below threshold with their scores and the failed source; the IP block (which needs a
    rating) is shown as considered, never dropped."""
    run = _degraded("suspicious-authentication", "cisco_xdr")
    for selector in ("revoke_sessions:jsmith@example.com", "disable_user:jsmith@example.com"):
        outcome = _outcome(run, selector)
        assert outcome is not None and outcome.status is RuleOutcomeStatus.BELOW_THRESHOLD
        assert outcome.risk_score > 0 and "cisco_xdr" in outcome.detail
    assert "cisco_xdr" in _considered(run)["block_ip:203.0.113.145"]
    summary = run.workflow_run.summary()
    assert any("cisco_xdr" in line for line in summary.below_threshold)


@pytest.mark.parametrize("failed", ["secure_endpoint", "microsoft_cloud", "secure_email"])
def test_phishing_source_outage_keeps_the_identity_actions(failed: str):
    """The endpoint (who used the clicking device), the click search or the message itself failed: the
    account the incident names is assessed on its Entra sign-in, risk detection and profile, and its
    revocation and disable are still proposed, with the unverified click and the failed source in the
    rationale."""
    run = _degraded("phishing", failed)
    proposed = _proposed(run)
    assert {"revoke_sessions:ap-clerk-01@example.com", "disable_user:ap-clerk-01@example.com"} <= proposed
    action = next(a for a in run.detection.package.actions if a.action_type.value == "revoke_sessions")
    assert failed in action.rationale and "could not be checked" in action.rationale


def test_phishing_identity_outage_shows_the_account_actions():
    """Entra down: no sign-in or risk record exists for the account, so nothing is proposed for it, and
    both account actions are shown as considered with Entra named."""
    run = _degraded("phishing", "entra")
    considered = _considered(run)
    for selector in ("revoke_sessions:ap-clerk-01@example.com", "disable_user:ap-clerk-01@example.com"):
        assert "entra" in considered[selector]


def test_click_evidence_cites_the_rating_that_makes_it_a_phishing_click():
    """A clicking recipient's actions rest on the click reaching a rated indicator: the rating records
    are cited, so failing that rating source is visible in the evidence (no hidden dependency)."""
    run = _detect(_raw("phishing"), "phishing")
    wf = run.workflow_run
    action = next(a for a in run.detection.package.actions if a.action_type.value == "revoke_sessions")
    sources = {wf.index.get(e.data["record_id"]).integration for e in action.evidence}
    assert {"umbrella", "virustotal"} & sources


# ------------------------------------- the failed source held the only evidence (never silent) --
def test_exfiltration_endpoint_outage_shows_the_incident_destinations_as_needs_investigation():
    """Secure Endpoint down: the transfer records were the only evidence for the destination blocks (no
    reputation source rates them). The incident names both destinations, so they are shown as needing
    investigation with Secure Endpoint named, in the notes and the summary; never proposed on no
    evidence and never dropped silently."""
    run = _degraded("exfiltration", "secure_endpoint")
    needs = _needs(run)
    for selector in ("block_domain:files-drop.test", "block_ip:203.0.113.145"):
        assert selector not in _proposed(run)
        assert selector in needs, f"{selector} vanished"
        assert "secure_endpoint" in needs[selector].failed and "secure_endpoint" in needs[selector].reason
    summary = run.workflow_run.summary()
    assert {line.split(": ", 1)[0] for line in summary.needs_investigation} >= {
        "block_domain:files-drop.test", "block_ip:203.0.113.145"}
    assert any(n.startswith("needs investigation, not proposed: block_ip:203.0.113.145")
               for n in run.workflow_run.notes)


def test_needs_investigation_reaches_the_analyst_notification():
    """The needs-investigation list is rendered in the analyst-facing notification of the lifecycle."""
    run = _degraded("exfiltration", "secure_endpoint")
    bodies = "\n".join(d.body for d in run.outbox.drafts)
    assert "Needs investigation" in bodies and "files-drop.test" in bodies


def test_mfa_fatigue_identity_outage_shows_the_sign_in_address_as_needs_investigation():
    """Entra down: the sign-in records were the only evidence for blocking the prompt source address. The
    address is enriched (no rating), so the block is shown as needing investigation with Entra named."""
    run = _degraded("mfa-fatigue", "entra")
    item = _needs(run).get("block_ip:203.0.113.80")
    assert item is not None and "entra" in item.failed and "entra" in item.reason
    assert "block_ip:203.0.113.80" not in _proposed(run)


@pytest.mark.parametrize("workflow, url", [
    ("web-attacks", "https://shop.example.net/upload"),
    ("vulnerability-exploitation", "https://portal.example.net/remote/upload"),
])
def test_incident_url_that_no_step_could_read_is_shown_as_needs_investigation(workflow: str, url: str):
    """Secure Endpoint down: the URL the incident names is never read (the step takes its subjects from the
    failed endpoint records), and its block is shown as needing investigation with Secure Endpoint named."""
    run = _degraded(workflow, "secure_endpoint")
    item = _needs(run).get(f"block_url:{url}")
    assert item is not None and "secure_endpoint" in item.failed
    assert "not investigated" in item.reason
    assert f"block_url:{url}" not in _proposed(run)


def test_no_evidence_outcome_in_a_degraded_run_names_the_failed_sources():
    """Password spray with Cisco XDR already down, then Entra fails: the source-address block has no record
    to cite. Its NO_EVIDENCE outcome says it was decided in a degraded run, and the action is shown as
    needing investigation with Entra named."""
    run = _degraded("password-spray", "entra", "degraded-source")
    outcome = _outcome(run, "block_ip:198.51.100.77")
    assert outcome is not None and outcome.status is RuleOutcomeStatus.NO_EVIDENCE
    assert "degraded run" in outcome.detail and "entra" in outcome.detail
    assert "entra" in _needs(run)["block_ip:198.51.100.77"].failed


@pytest.mark.parametrize("workflow", [w for w in CATALOG.ids() if (FIXTURES / w / "tp-approve-all.yaml").exists()])
def test_a_healthy_run_has_nothing_that_needs_investigation(workflow: str):
    """The needs-investigation list belongs to degraded runs only: with every source answering it is empty."""
    run = _detect(_raw(workflow), workflow)
    assert run.workflow_run.degraded_sources() == ()
    assert run.workflow_run.needs_investigation == ()
    assert run.workflow_run.summary().needs_investigation == ()


def test_the_sweep_reports_a_silent_drop(monkeypatch):
    """Self-check of the sweep: with the runner's degraded-source accounting switched off, failing Secure
    Endpoint in exfiltration silently loses the destination blocks, and the check reports exactly that."""
    monkeypatch.setattr(runner_module.WorkflowRunner, "_degraded_accounting", lambda self, state: None)
    findings = degradation_findings(_raw("exfiltration"), "secure_endpoint",
                                    lambda data: _detect(data, "exfiltration"))
    assert any(f.startswith("block_domain:files-drop.test") and "vanished" in f for f in findings), findings
    assert any(f.startswith("block_ip:203.0.113.145") and "vanished" in f for f in findings), findings


# ------------------------------------------------------------------- framework guarantees --
def test_degraded_source_entries_are_never_proposals_and_cite_real_records():
    """Every workflow, every expected source failed: what the runner adds for the degraded source is a
    considered entry citing records of the run, or a needs-investigation entry that names the failed
    source and cites only records of the run; never a proposal and never an allow-listed target."""
    problems = []
    for entry in (CATALOG.get(i) for i in CATALOG.ids()):
        workflow = entry.id
        if not (FIXTURES / workflow / "tp-approve-all.yaml").exists():
            continue
        for failed in entry.definition.expected_sources():
            run = _degraded(workflow, failed)
            wf = run.workflow_run
            proposed = _proposed(run)
            for item in wf.considered:
                unknown = [i for i in item.record_ids if i not in wf.index]
                if not item.record_ids or unknown:
                    problems.append(f"{workflow}:{failed}: {item.subject} cites {unknown or 'nothing'}")
                if item.subject in proposed and not item.manual:
                    problems.append(f"{workflow}:{failed}: {item.subject} is both considered and proposed")
            package = run.detection.package
            excluded = {f"{t.action_type.value}:{t.target}" for t in package.excluded_targets} if package else set()
            for item in wf.needs_investigation:
                unknown = [i for i in item.record_ids if i not in wf.index]
                if unknown:
                    problems.append(f"{workflow}:{failed}: needs-investigation {item.subject} cites {unknown}")
                if item.subject in proposed or item.subject in excluded:
                    problems.append(f"{workflow}:{failed}: needs-investigation {item.subject} is also in the package")
                if failed not in item.failed or not set(item.failed) <= set(wf.degraded_sources()):
                    problems.append(f"{workflow}:{failed}: needs-investigation {item.subject} names {item.failed}")
    assert problems == []


def test_withheld_actions_of_a_degraded_run_name_the_failed_source_in_the_summary():
    """The analyst summary of a degraded run lists the failed source and every withheld action that the
    failed read concerned names it (considered lines and below-threshold lines)."""
    run = _degraded("account-takeover", "cisco_xdr")
    summary = run.workflow_run.summary()
    assert "cisco_xdr" in summary.degraded_sources
    lines = [line for line in summary.considered if line.startswith("block_ip:203.0.113.145")]
    assert lines and "cisco_xdr" in lines[0]


# ------------------------------------------------------------------------ the full sweep --
def _sweep_cases() -> list[Any]:
    out = []
    for entry in (CATALOG.get(i) for i in CATALOG.ids()):
        expected = entry.definition.expected_sources()
        for path in sorted((FIXTURES / entry.id).glob("*.yaml")) if (FIXTURES / entry.id).is_dir() else ():
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not (data.get("expect") or {}).get("package"):
                continue
            suite = WorkflowScenario.model_validate({**data, "path": path}).effective_suite()
            for failed in sorted(set(expected) & set(suite)):
                out.append(pytest.param(entry.id, path.stem, failed, id=f"{entry.id}/{path.stem}:{failed}"))
    return out


@pytest.mark.parametrize("workflow, name, failed", _sweep_cases())
def test_every_scenario_survives_the_failure_of_each_expected_source(workflow: str, name: str, failed: str):
    findings = degradation_findings(_raw(workflow, name), failed, lambda data: _detect(data, workflow, name))
    assert findings == [], f"{workflow}/{name}: failing {failed}: {findings}"
