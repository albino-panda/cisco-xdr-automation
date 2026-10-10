"""Persistence hooks: facts, item links and manual steps computed from the run's own records (simulated lab)."""
from __future__ import annotations

import json
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.atomics.records import PersistenceItemRecord
from xdr_response.models import ActionType, Observable, ObservableType, Verdict
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.persistence import HOOKS, WORKFLOW
from xdr_response.workflows.persistence.hooks import is_browser_extension, mechanism_label, removal_step
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

HOST = "TH-LT-1047"
SHA = "0dd5a1e5" * 8
OTHER = "2bad2bad" * 8
SUITE = {"secure_endpoint": ("endpoint",), "virustotal": ("intel",)}


def _lab() -> Lab:
    return make_lab(SUITE)


def _endpoint(lab: Lab, host: str = HOST, **extra: Any) -> None:
    fields = {"connector_guid": "00000000-0000-4000-8000-000000001047", "groups": ["Workstations"],
              "isolation_capable": True, "isolation_state": "not_isolated", **extra}
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host, **fields)


def _item(lab: Lab, *, host: str = HOST, item_id: str = "run-odsync", mechanism: str = "run_key",
          name: str = "HKCU Run value OneDriveSync", sha: str | None = SHA, **extra: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="persistence_item", endpoint=host,
              item_id=item_id, mechanism=mechanism, name=name, sha256=sha, **extra)


def _detection(lab: Lab, *, sha: str | None = SHA, status: str = "active", verdict: str = "MALICIOUS",
               host: str = HOST, detection_id: str = "det-1") -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", detection_id=detection_id,
              name="Sample.Backdoor.Persist", verdict=verdict, severity="HIGH", endpoint=host, sha256=sha,
              status=status, first_seen="2026-01-15T11:41:00Z")


def _event(lab: Lab, event_id: str, event_type: str, minute: int, *, sha: str = SHA, host: str = HOST,
           **extra: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=event_id,
              endpoint=host, timestamp=f"2026-01-15T11:{minute:02d}:00Z", event_type=event_type, sha256=sha, **extra)


def _prevalence(lab: Lab, count: int, *, sha: str = SHA, verdict: str = "MALICIOUS", hosts: tuple[str, ...] = (HOST,)):
    lab.typed("search_hash_enterprise", sha, "secure_endpoint", kind="hash_prevalence", sha256=sha,
              verdict=verdict, prevalence=count, endpoints=list(hosts))


def _reputation(lab: Lab, sha: str = SHA, verdict: Verdict = Verdict.MALICIOUS,
                integrations: tuple[str, ...] = ("secure_endpoint", "virustotal")) -> None:
    lab.environment.set_reputation(ObservableType.SHA256, sha, verdict, risk_score=90 if verdict is Verdict.MALICIOUS
                                   else 0, confidence=85, integrations=list(integrations))


def _run(lab: Lab, *observables: tuple[ObservableType, str]) -> WorkflowRun:
    incident = make_incident(*(observables or ((ObservableType.HOSTNAME, HOST),)), workflow_id="persistence",
                             title=f"New Run key value on {HOST}")
    return lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)


def _view(run: WorkflowRun, *observables: tuple[ObservableType, str]) -> RunView:
    incident = make_incident(*(observables or ((ObservableType.HOSTNAME, HOST),)), workflow_id="persistence")
    return RunView(workflow=WORKFLOW, incident=incident, results=run.results, index=run.index,
                   correlation=run.correlation, blast_radius=run.blast_radius)


def _facts(run: WorkflowRun) -> dict[str, Any]:
    facts = dict(HOOKS.facts(_view(run)))
    json.dumps(facts, allow_nan=False)  # the runner requires JSON facts
    return facts


def _infected(lab: Lab, *, status: str = "active", ended: bool = False) -> None:
    _endpoint(lab)
    _item(lab)
    _detection(lab, status=status)
    _event(lab, "evt-1", "process_start", 40, pid=4242, process_name="odsync.exe")
    if ended:
        _event(lab, "evt-2", "process_end", 45, pid=4242, process_name="odsync.exe")
    _prevalence(lab, 1)
    _reputation(lab)


def _proposed(run: WorkflowRun) -> set[str]:
    """Recommended actions: proposed, or UNROUTED (the simulated adapters do only what the real ones do,
    so e.g. a process termination or a Secure Endpoint hash block has no executor; it is still recommended)."""
    return ({f"{p.action_type.value}:{p.target}" for p in run.proposals}
            | {o.selector for o in run.outcomes_with(RuleOutcomeStatus.UNROUTED)})


def _considered(run: WorkflowRun) -> dict[str, Any]:
    return {c.subject: c for c in run.considered}


# --------------------------------------------------------------------------------------------- facts --
def test_an_executing_malicious_run_key_gives_every_fact_with_its_records():
    lab = _lab()
    _infected(lab)
    run = _run(lab)
    facts = _facts(run)
    (item,) = facts["items"]
    assert item["target"] == f"{HOST}/run-odsync" and item["malicious"] and item["label"] == "Run key value"
    (sha_fact,) = facts["hashes"]
    assert sha_fact["malicious"] and sha_fact["persisted"] and sha_fact["prevalence"] == 1
    assert "endpoint detection" in sha_fact["basis"] and "enrichment" in sha_fact["basis"]
    assert set(facts["isolate"]) == {HOST}
    assert "active detection" in facts["isolate"][HOST]["summary"]
    (running,) = facts["running"]
    assert running["target"] == f"{HOST}/4242" and "Run key value" in running["launched_by"]
    every_id = [*item["record_ids"], *sha_fact["record_ids"], *facts["isolate"][HOST]["record_ids"],
                *running["record_ids"]]
    assert every_id and all(rid in run.index for rid in every_id)
    assert _proposed(run) == {f"isolate_endpoint:{HOST}", f"terminate_process:{HOST}/4242", f"block_hash:{SHA}"}
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)


def test_the_manual_removal_step_is_a_manual_consideration_with_the_item_record():
    lab = _lab()
    _infected(lab)
    run = _run(lab)
    step = _considered(run)[f"remove_persistence:{HOST}/run-odsync"]
    assert step.manual and "no VERIFIED vendor write removes persistence" in step.reason
    assert "Run or RunOnce" in step.reason
    item_ids = {r.record_id for r in run.index.records() if isinstance(r, PersistenceItemRecord)}
    assert item_ids <= set(step.record_ids)
    assert any(n.startswith(f"manual step: remove_persistence:{HOST}/run-odsync") for n in run.notes)
    # never an automated action: nothing in the run targets remove_persistence
    assert all(o.action_type is not ActionType.REMOVE_PERSISTENCE for o in run.outcomes)


def test_a_dormant_item_blocks_the_binary_but_does_not_isolate():
    lab = _lab()
    _endpoint(lab)
    _item(lab, mechanism="scheduled_task", item_id="task-weekly", name="UpdateCheckWeekly")
    _detection(lab, sha=None, verdict="SUSPICIOUS")
    _prevalence(lab, 1)
    _reputation(lab)
    run = _run(lab)
    assert _proposed(run) == {f"block_hash:{SHA}"}
    dormant = _considered(run)[f"isolate_endpoint:{HOST}"]
    assert not dormant.manual and "dormant" in dormant.reason
    assert _considered(run)[f"remove_persistence:{HOST}/task-weekly"].manual


def test_a_remediated_detection_and_an_ended_process_are_not_containment():
    lab = _lab()
    _infected(lab, status="resolved", ended=True)
    run = _run(lab)
    facts = _facts(run)
    assert facts["isolate"] == {} and facts["running"] == []
    assert _proposed(run) == {f"block_hash:{SHA}"}
    assert f"isolate_endpoint:{HOST}" in _considered(run)


def test_an_ended_process_is_not_terminated_but_the_active_detection_still_isolates():
    lab = _lab()
    _infected(lab, ended=True)
    run = _run(lab)
    assert _proposed(run) == {f"isolate_endpoint:{HOST}", f"block_hash:{SHA}"}


def test_a_malicious_item_launching_a_clean_system_binary_never_blocks_or_terminates_it():
    lab = _lab()
    _endpoint(lab)
    _item(lab, mechanism="scheduled_task", item_id="task-sync", name="SyncProfileDaily", sha=OTHER,
          verdict="MALICIOUS")
    _detection(lab, sha=None)
    _event(lab, "evt-1", "process_start", 40, sha=OTHER, pid=6120, process_name="scripthost.exe")
    _prevalence(lab, 4200, sha=OTHER, verdict="CLEAN")
    _reputation(lab, OTHER, Verdict.CLEAN)
    run = _run(lab)
    facts = _facts(run)
    (item,) = facts["items"]
    assert item["malicious"] and item["basis"] == "item rated malicious by the endpoint source"
    assert not facts["hashes"][0]["malicious"] and facts["running"] == []
    assert _proposed(run) == {f"isolate_endpoint:{HOST}"}


def test_a_widespread_malicious_binary_is_considered_not_blocked():
    lab = _lab()
    _endpoint(lab)
    _item(lab)
    _detection(lab)
    _prevalence(lab, 40)
    _reputation(lab)
    run = _run(lab)
    assert f"block_hash:{SHA}" not in _proposed(run)
    withheld = _considered(run)[f"block_hash:{SHA}"]
    assert "40 endpoints" in withheld.reason and not withheld.manual
    assert f"isolate_endpoint:{HOST}" in _proposed(run)


def test_an_unrated_item_is_left_for_review_and_a_clean_one_is_silent():
    lab = _lab()
    _endpoint(lab)
    _item(lab, item_id="run-unknown", sha=OTHER)
    _item(lab, item_id="svc-clean", mechanism="service", name="ExampleVendorUpdateSvc", sha=SHA)
    _prevalence(lab, 812, verdict="CLEAN")
    _reputation(lab, SHA, Verdict.CLEAN)
    run = _run(lab)
    considered = _considered(run)
    review = considered[f"remove_persistence:{HOST}/run-unknown"]
    assert not review.manual and "not rated by any source" in review.reason
    assert f"remove_persistence:{HOST}/svc-clean" not in considered
    assert _proposed(run) == set()


def test_an_incident_hash_without_verdict_and_without_item_is_considered():
    lab = _lab()
    _infected(lab)
    _prevalence(lab, 0, sha=OTHER, verdict="UNKNOWN", hosts=())
    run = _run(lab, (ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, OTHER))
    assert f"block_hash:{OTHER}" in _considered(run)
    assert f"block_hash:{OTHER}" not in _proposed(run)


def test_a_critical_endpoint_is_named_in_the_manual_step():
    lab = _lab()
    _endpoint(lab, host="DC-01", groups=["Domain Controllers"])
    _item(lab, host="DC-01", item_id="task-inv", mechanism="scheduled_task", name="NightlyInventory")
    _detection(lab, host="DC-01")
    _prevalence(lab, 1, hosts=("DC-01",))
    _reputation(lab)
    run = _run(lab, (ObservableType.HOSTNAME, "DC-01"))
    step = _considered(run)["remove_persistence:DC-01/task-inv"]
    assert step.manual and "critical asset (domain_controller)" in step.reason
    assert "isolate_endpoint:DC-01" in _proposed(run)


def test_a_fleet_wide_service_isolates_every_executing_endpoint_found_by_prevalence():
    lab = _lab()
    hosts = ("WS-OPS-101", "WS-OPS-102", "WS-OPS-103")
    for host in hosts:
        _endpoint(lab, host=host)
        _item(lab, host=host, item_id="svc-wth", mechanism="service", name="WinTelemetryHost")
        _detection(lab, host=host, detection_id=f"det-{host}")
    _prevalence(lab, 3, hosts=hosts)
    _reputation(lab)
    run = _run(lab, (ObservableType.SHA256, SHA), (ObservableType.HOSTNAME, hosts[0]))
    assert _proposed(run) == {f"block_hash:{SHA}", *(f"isolate_endpoint:{h}" for h in hosts)}
    manual = {c.subject for c in run.considered if c.manual}
    assert manual == {f"remove_persistence:{h}/svc-wth" for h in hosts}


# --------------------------------------------------------------------------------------------- links --
def test_item_links_tie_the_item_to_its_binary_and_execution_events():
    lab = _lab()
    _infected(lab)
    run = _run(lab)
    links = [link for link in HOOKS.correlate(_view(run)) if link.kind is LinkKind.WORKFLOW]
    (link,) = links
    assert link.origin == "workflow:persistence"
    assert {e.value for e in link.entities} == {HOST, SHA}
    assert len(link.record_ids) == 2 and all(rid in run.index for rid in link.record_ids)
    assert "1 execution event(s)" in link.note
    assert any(c.origin == "workflow:persistence" for c in run.correlation.links)


# ------------------------------------------------------------------------------------------- helpers --
def _record(mechanism: str, name: str, path: str | None = None) -> PersistenceItemRecord:
    return PersistenceItemRecord(integration="secure_endpoint", atomic="investigate_endpoint",
                                 subject=Observable(type=ObservableType.HOSTNAME, value=HOST), endpoint=HOST,
                                 item_id="x-1", mechanism=mechanism, name=name, path=path)


@pytest.mark.parametrize("mechanism, label, step", [
    ("run_key", "Run key value", "Run or RunOnce"),
    ("startup_folder", "startup folder item", "startup folder"),
    ("scheduled_task", "scheduled task", "scheduled task"),
    ("service", "Windows service", "service"),
    ("wmi_subscription", "WMI event subscription", "filter, consumer and binding"),
    ("launch_agent", "launch agent", "launch agent"),
    ("cron", "cron job", "cron entry"),
    ("browser_extension", "browser extension", "browser policy"),
    ("other", "persistence item", "persistence item"),
])
def test_every_mechanism_has_a_label_and_a_removal_step(mechanism: str, label: str, step: str):
    record = _record(mechanism, "Example item")
    assert mechanism_label(record) == label and step in removal_step(record)
    assert is_browser_extension(record) is (mechanism == "browser_extension")


@pytest.mark.parametrize("path, name", [
    ("C:/Users/rpatel/AppData/Local/Browser/User Data/Default/Extensions/abc/1.0/x.crx", "PDF helper"),
    (None, "PDF Helper browser extension"),
    ("/home/user/.browser/profile/extensions/helper.xpi", "helper"),
])
def test_browser_extensions_are_recognised_for_mechanism_other_by_path_or_name(path: str | None, name: str):
    record = _record("other", name, path)
    assert is_browser_extension(record) and mechanism_label(record) == "browser extension"
    assert "browser policy" in removal_step(record)
    assert not is_browser_extension(_record("service", name, path))


def test_hooks_never_fail_on_an_empty_run():
    lab = _lab()
    run = _run(lab)
    view = _view(run)
    assert HOOKS.facts(view) == {"hashes": [], "items": [], "isolate": {}, "running": []}
    assert list(HOOKS.considered(view)) == [] and list(HOOKS.correlate(view)) == []
    assert run.proposals == ()
