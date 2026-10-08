"""Suspicious PowerShell hooks: facts, links, considered items and hand-offs from the run's own records.

Simulated read-only lab, fake data only. Command lines are never needed: the workflow judges a system
binary by what the vendor reports and by what the process wrote, started and contacted.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.models import ObservableType, Verdict
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.malicious_powershell import HOOKS, WORKFLOW
from xdr_response.workflows.malicious_powershell.hooks import destinations_of, lolbin_name, public_ipv4
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

HOST = "TH-LT-1047"
OTHER = "TH-LT-1048"
PAYLOAD = "c0ffee00" * 8
IMAGE = "a1a1b2b2" * 8
GUID = "00000000-0000-4000-8000-000000001047"
SUITE = {"secure_endpoint": ("endpoint",), "virustotal": ("intel",), "umbrella": ("network",),
         "meraki": ("network",)}


def _lab() -> Lab:
    return make_lab(SUITE)


def _endpoint(lab: Lab, host: str = HOST, guid: str = GUID, **extra: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host, connector_guid=guid,
              groups=["Workstations"], isolation_capable=True, isolation_state="not_isolated", **extra)


def _event(lab: Lab, event_id: str, event_type: str, minute: int, *, host: str = HOST, **extra: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=event_id, endpoint=host,
              timestamp=f"2026-01-15T11:{minute:02d}:00Z", event_type=event_type, **extra)


def _powershell(lab: Lab, *, pid: int = 4242, host: str = HOST, parent: str = "winword.exe", name: str = "powershell.exe",
                minute: int = 30) -> None:
    _event(lab, f"evt-{host}-{pid}-start", "process_start", minute, host=host, process_name=name, pid=pid,
           parent_process_name=parent, parent_pid=1180, sha256=IMAGE)


def _write(lab: Lab, *, pid: int = 4242, sha: str = PAYLOAD, origin: str | None = "cdn-update.test",
           host: str = HOST, name: str = "powershell.exe") -> None:
    extra = {"domain": origin} if origin else {}
    _event(lab, f"evt-{host}-{pid}-write", "file_create", 31, host=host, process_name=name, pid=pid, sha256=sha,
           **extra)


def _detection(lab: Lab, *, verdict: str = "MALICIOUS", process: str | None = "powershell.exe", sha: str | None = None,
               host: str = HOST, status: str = "active", techniques: tuple[str, ...] = ("T1059.001",)) -> None:
    extra: dict[str, Any] = {}
    if process:
        extra["process_name"] = process
    if sha:
        extra["sha256"] = sha
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", detection_id=f"det-{host}-{verdict}",
              name="Sample.ScriptDownloader.Generic", verdict=verdict, severity="HIGH", endpoint=host, status=status,
              mitre_techniques=list(techniques), **extra)


def _connection(lab: Lab, *, ip: str | None = None, domain: str | None = None, url: str | None = None,
                verdict: str | None = None, name: str = "powershell.exe", host: str = HOST) -> None:
    extra: dict[str, Any] = {k: v for k, v in (("remote_ip", ip), ("domain", domain), ("url", url), ("verdict", verdict))
                             if v}
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="network_connection", endpoint=host,
              remote_port=443, direction="outbound", process_name=name, sha256=IMAGE,
              first_seen="2026-01-15T11:32:00Z", **extra)


def _malicious(lab: Lab, otype: ObservableType, value: str, integrations: tuple[str, ...] = ("virustotal", "umbrella"),
               verdict: Verdict = Verdict.MALICIOUS) -> None:
    lab.environment.set_reputation(otype, value, verdict, risk_score=85, confidence=80, integrations=list(integrations))


def _run(lab: Lab, *observables: tuple[ObservableType, str]) -> WorkflowRun:
    incident = make_incident(*(observables or ((ObservableType.HOSTNAME, HOST),)), workflow_id="malicious-powershell",
                             title=f"PowerShell alert on {HOST}")
    return lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)


def _view(run: WorkflowRun) -> RunView:
    return RunView(workflow=WORKFLOW, incident=make_incident(workflow_id="malicious-powershell"), results=run.results,
                   index=run.index, correlation=run.correlation, blast_radius=run.blast_radius)


def _facts(run: WorkflowRun) -> dict[str, Any]:
    facts = dict(HOOKS.facts(_view(run)))
    json.dumps(facts, allow_nan=False)  # the runner requires JSON facts
    return facts


def _selectors(run: WorkflowRun) -> set[str]:
    return {f"{p.action_type.value}:{p.target}" for p in run.proposals}


def _considered(run: WorkflowRun) -> dict[str, str]:
    return {c.subject: c.reason for c in run.considered}


def _payload_run(lab: Lab, *, running: bool = True) -> None:
    _endpoint(lab)
    _powershell(lab)
    _detection(lab)
    _write(lab)
    _event(lab, "evt-child", "process_start", 32, process_name="update_helper.exe", pid=5120, parent_pid=4242,
           parent_process_name="powershell.exe", sha256=PAYLOAD)
    if not running:
        _event(lab, "evt-end", "process_end", 40, process_name="powershell.exe", pid=4242)
    _connection(lab, ip="198.51.100.77", verdict="MALICIOUS")
    _malicious(lab, ObservableType.SHA256, PAYLOAD, ("secure_endpoint", "virustotal"))
    _malicious(lab, ObservableType.DOMAIN, "cdn-update.test")


# ------------------------------------------------------------------- helpers --
@pytest.mark.parametrize("value, expected", [
    ("powershell.exe", "powershell"), ("C:/Windows/System32/WindowsPowerShell/v1.0/PowerShell.EXE", "powershell"),
    ("C:\\Windows\\System32\\rundll32.exe", "rundll32"), ("pwsh", "pwsh"), ("MSHTA.EXE", "mshta"),
    ("powershell_helper.exe", None), ("explorer.exe", None), (None, None), ("", None),
])
def test_lolbin_name(value, expected):
    assert lolbin_name(value) == expected


@pytest.mark.parametrize("value, expected", [
    ("198.51.100.77", "198.51.100.77"), ("10.0.0.5", None), ("192.168.1.10", None), ("127.0.0.1", None),
    ("::ffff:10.0.0.5", None), ("2001:db8::1", None), ("not-an-ip", None), (None, None),
])
def test_public_ipv4(value, expected):
    assert public_ipv4(value) == expected


# --------------------------------------------------------------------- facts --
def test_malicious_run_facts_and_full_package():
    lab = _lab()
    _payload_run(lab)
    run = _run(lab)
    facts = _facts(run)
    [ps] = facts["runs"]
    assert ps["malicious"] and ps["payloads"] == [PAYLOAD] and not ps["ended"]
    assert "retrieved or started malicious payload" in ps["basis"]
    assert "reported techniques T1059.001" in ps["basis"]
    assert [t["target"] for t in facts["terminate"]] == [f"{HOST}/4242"]
    assert set(facts["isolate"]) == {HOST}
    assert [p["sha256"] for p in facts["payloads"]] == [PAYLOAD]
    destinations = {(d["type"], d["value"]): d for d in facts["destinations"]}
    assert destinations[("domain", "cdn-update.test")]["enrichment_verdict"] == "MALICIOUS"
    assert destinations[("ip", "198.51.100.77")]["contact_verdict"] == "MALICIOUS"
    for fact in (*facts["terminate"], *facts["isolate"].values(), *facts["payloads"], *facts["destinations"]):
        assert fact["record_ids"] and all(i in run.index for i in fact["record_ids"])
    assert _selectors(run) == {f"terminate_process:{HOST}/4242", f"isolate_endpoint:{HOST}", f"block_hash:{PAYLOAD}",
                               "block_domain:cdn-update.test", "block_ip:198.51.100.77"}
    for proposal in run.proposals:
        assert proposal.evidence and all(e.data["record_id"] in run.index for e in proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)


def test_the_system_binary_image_is_never_a_payload():
    lab = _lab()
    _payload_run(lab)
    facts = _facts(_run(lab))
    assert IMAGE not in [p["sha256"] for p in facts["payloads"]]
    assert all(IMAGE not in r["payloads"] for r in facts["runs"])


def test_use_of_powershell_alone_is_not_malicious():
    lab = _lab()
    _endpoint(lab)
    _powershell(lab, parent="mgmt_agent.exe")
    _connection(lab, domain="inventory.corp.example.com", verdict="CLEAN")
    run = _run(lab)
    facts = _facts(run)
    assert [r["malicious"] for r in facts["runs"]] == [False]
    assert facts["terminate"] == [] and facts["isolate"] == {} and facts["payloads"] == []
    assert run.proposals == ()
    reason = _considered(run)[f"terminate_process:{HOST}/4242"]
    assert "alone is not malicious" in reason


def test_a_suspicious_vendor_characteristic_alone_is_not_malicious():
    lab = _lab()
    _endpoint(lab)
    _powershell(lab, parent="mgmt_agent.exe")
    _detection(lab, verdict="SUSPICIOUS", techniques=("T1027",))
    run = _run(lab)
    assert run.proposals == ()
    reason = _considered(run)[f"terminate_process:{HOST}/4242"]
    assert "SUSPICIOUS detection (reported techniques T1027)" in reason


def test_a_malicious_vendor_detection_of_the_process_is_enough_to_terminate():
    lab = _lab()
    _endpoint(lab)
    _powershell(lab)
    _detection(lab, techniques=("T1059.001", "T1027"))
    run = _run(lab)
    assert f"terminate_process:{HOST}/4242" in _selectors(run)
    # no payload, no malicious destination: the endpoint is not isolated on the detection of the process alone
    assert f"isolate_endpoint:{HOST}" not in _selectors(run)


def test_contact_without_payload_blocks_the_destination_only():
    lab = _lab()
    _endpoint(lab)
    _powershell(lab)
    _event(lab, "evt-net", "network", 31, process_name="powershell.exe", pid=4242, domain="stage-loader.test")
    _malicious(lab, ObservableType.DOMAIN, "stage-loader.test")
    run = _run(lab)
    assert _selectors(run) == {"block_domain:stage-loader.test"}
    assert "no malicious payload landed" in _considered(run)[f"terminate_process:{HOST}/4242"]


def test_malicious_destination_with_a_host_detection_isolates_and_terminates():
    lab = _lab()
    _endpoint(lab)
    _powershell(lab)
    _detection(lab, process="payload_stage.exe")  # detection of something else on the host
    _connection(lab, ip="198.51.100.45", verdict="MALICIOUS")
    run = _run(lab)
    assert {f"isolate_endpoint:{HOST}", f"terminate_process:{HOST}/4242", "block_ip:198.51.100.45"} <= _selectors(run)


@pytest.mark.parametrize("connection_pid, terminated", [
    (5151, {f"{HOST}/5151"}),                    # the connection names its process: only that run contacted it
    (None, {f"{HOST}/4242", f"{HOST}/5151"}),    # no process id: both runs of the image share the connection
])
def test_a_connection_process_id_attributes_it_to_one_run(connection_pid: int | None, terminated: set[str]):
    lab = _lab()
    _endpoint(lab)
    _powershell(lab, pid=4242)
    _powershell(lab, pid=5151, minute=33)
    _detection(lab, process="payload_stage.exe")
    extra = {"pid": connection_pid} if connection_pid is not None else {}
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="network_connection", endpoint=HOST,
              remote_ip="198.51.100.45", remote_port=443, direction="outbound", process_name="powershell.exe",
              sha256=IMAGE, verdict="MALICIOUS", first_seen="2026-01-15T11:34:00Z", **extra)
    run = _run(lab)
    assert {s.split(":", 1)[1] for s in _selectors(run) if s.startswith("terminate_process:")} == terminated


def test_an_ended_process_is_not_terminated_and_is_listed():
    lab = _lab()
    _payload_run(lab, running=False)
    run = _run(lab)
    assert f"terminate_process:{HOST}/4242" not in _selectors(run)
    assert f"isolate_endpoint:{HOST}" in _selectors(run)
    assert "already ended" in _considered(run)[f"terminate_process:{HOST}/4242"]


def test_a_resolved_detection_does_not_count():
    lab = _lab()
    _endpoint(lab)
    _powershell(lab)
    _detection(lab, status="resolved")
    run = _run(lab)
    assert run.proposals == ()


def test_widespread_payload_is_not_blocked_but_listed():
    lab = _lab()
    _payload_run(lab)
    hosts = [f"TH-LT-{n}" for n in range(2000, 2012)]
    lab.typed("search_hash_enterprise", PAYLOAD, "secure_endpoint", kind="hash_prevalence", sha256=PAYLOAD,
              verdict="MALICIOUS", prevalence=len(hosts), endpoints=hosts)
    run = _run(lab)
    assert f"block_hash:{PAYLOAD}" not in _selectors(run)
    assert "more than 10" in _considered(run)[f"block_hash:{PAYLOAD}"]


def test_the_image_hash_named_by_a_detection_is_listed_never_blocked():
    lab = _lab()
    _payload_run(lab)
    _detection(lab, sha=IMAGE, verdict="SUSPICIOUS")
    run = _run(lab, (ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, IMAGE))
    assert f"block_hash:{IMAGE}" not in _selectors(run)
    assert "system binary powershell" in _considered(run)[f"block_hash:{IMAGE}"]


def test_suspicious_domain_is_blocked_only_when_a_malicious_payload_came_with_it():
    lab = _lab()
    _payload_run(lab)
    _connection(lab, domain="media-cdn.test")
    _malicious(lab, ObservableType.DOMAIN, "media-cdn.test", ("umbrella",), verdict=Verdict.SUSPICIOUS)
    assert "block_domain:media-cdn.test" in _selectors(_run(lab))

    clean = _lab()
    _endpoint(clean)
    _powershell(clean)
    _connection(clean, domain="media-cdn.test")
    _malicious(clean, ObservableType.DOMAIN, "media-cdn.test", ("umbrella",), verdict=Verdict.SUSPICIOUS)
    assert _run(clean).proposals == ()


def test_other_endpoints_holding_the_payload_are_investigated_and_isolated():
    lab = _lab()
    _payload_run(lab)
    _endpoint(lab, OTHER, "00000000-0000-4000-8000-000000001048")
    lab.typed("search_hash_enterprise", PAYLOAD, "secure_endpoint", kind="hash_prevalence", sha256=PAYLOAD,
              verdict="MALICIOUS", prevalence=2, endpoints=[HOST, OTHER])
    run = _run(lab)
    assert {f"isolate_endpoint:{HOST}", f"isolate_endpoint:{OTHER}"} <= _selectors(run)
    assert any(r.atomic == "investigate_endpoint" and r.subject.value == OTHER for r in run.results)


def test_proxy_binary_and_url_block():
    lab = _lab()
    _endpoint(lab)
    _powershell(lab, pid=3100, name="mshta.exe", parent="browser.exe")
    _connection(lab, url="https://media-cdn.test/view/doc", name="mshta.exe")
    _write(lab, pid=3100, origin=None, name="mshta.exe")
    _malicious(lab, ObservableType.SHA256, PAYLOAD, ("secure_endpoint", "virustotal"))
    _malicious(lab, ObservableType.URL, "https://media-cdn.test/view/doc", ("virustotal",))
    run = _run(lab)
    selectors = _selectors(run)
    assert {f"terminate_process:{HOST}/3100", f"isolate_endpoint:{HOST}", f"block_hash:{PAYLOAD}"} <= selectors
    # one vendor's MALICIOUS answer is only an aggregate SUSPICIOUS verdict; the URL is still blocked
    # because the process that contacted it retrieved a malicious payload (payload confirmed)
    assert f"block_url:https://media-cdn.test/view/doc" in selectors


def test_handoffs_to_malware_and_persistence():
    lab = _lab()
    _payload_run(lab)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="persistence_item", endpoint=HOST,
              item_id="runkey-1", mechanism="run_key", name="HelperUpdate", sha256=PAYLOAD, verdict="MALICIOUS")
    run = _run(lab)
    handoffs = {h.workflow_id: h for h in run.handoffs}
    assert set(handoffs) == {"malware", "persistence"}
    assert handoffs["malware"].subjects == (PAYLOAD,)
    assert handoffs["persistence"].subjects == (HOST,)
    for handoff in handoffs.values():
        assert all(i in run.index for i in handoff.record_ids)


def test_no_handoff_without_a_malicious_run():
    lab = _lab()
    _endpoint(lab)
    _powershell(lab)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="persistence_item", endpoint=HOST,
              item_id="runkey-2", mechanism="run_key", name="Vendor", verdict="SUSPICIOUS")
    assert _run(lab).handoffs == ()


def test_workflow_links_cite_run_records():
    lab = _lab()
    _payload_run(lab)
    run = _run(lab)
    links = [l for l in run.correlation.links if l.kind is LinkKind.WORKFLOW]
    assert links
    for link in links:
        assert link.origin == "workflow:malicious-powershell"
        assert all(i in run.index for i in link.record_ids)
    notes = " ".join(l.note for l in links)
    assert "contacted cdn-update.test" in notes or "contacted 198.51.100.77" in notes
    assert "wrote or started" in notes


def test_destinations_of_only_reads_process_and_connection_records():
    lab = _lab()
    _payload_run(lab)
    run = _run(lab)
    for record in run.index.records():
        found = destinations_of(record)
        if str(record.kind) not in ("process_event", "network_connection"):
            assert found == []
        for kind, _value in found:
            assert kind in ("domain", "url", "ip")
