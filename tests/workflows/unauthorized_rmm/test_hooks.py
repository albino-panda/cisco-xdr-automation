"""unauthorized-rmm hooks: tools, sessions, destinations, considerations and hand-offs computed from the
run's own records (simulated read-only lab; nothing state-changing is ever called)."""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.config import Settings
from xdr_response.models import ObservableType, Verdict
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun, WorkflowRunner
from xdr_response.workflows.unauthorized_rmm import HOOKS, WORKFLOW

HOST = "TH-LT-1047"
SHA = "a11d35c0" * 8
APPROVED_SHA = "1" * 64  # the repository config's approved_rmm example (Example RMM)
RELAY = "relay-01.anydesk-relay.test"
LURE = "get-remote-support.test"
PEER = "198.51.100.45"
SUITE = {"secure_endpoint": ("endpoint",), "umbrella": ("network",), "virustotal": ("intel",),
         "meraki": ("network",), "entra": ("identity",)}


def _lab(settings: Settings | None = None) -> Lab:
    lab = make_lab(SUITE)
    if settings is not None:
        lab = replace(lab, settings=settings, runner=WorkflowRunner(lab.adapters, settings, clock=lab.clock))
    return lab


def _endpoint(lab: Lab, host: str = HOST, **extra: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host,
              connector_guid="00000000-0000-4000-8000-000000001047", groups=["Workstations"],
              users=["jsmith@example.com"], isolation_capable=True, isolation_state="not_isolated", **extra)


def _detection(lab: Lab, *, sha: str = SHA, verdict: str = "SUSPICIOUS", host: str = HOST,
               process: str = "AnyDesk.exe", name: str = "PUA.RemoteAccess.AnyDesk") -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", detection_id=f"det-{host}-{sha[:4]}",
              name=name, category="RemoteAccessTool", verdict=verdict, severity="HIGH", endpoint=host,
              sha256=sha, process_name=process, mitre_techniques=["T1219.002"], status="active",
              first_seen="2026-01-15T11:20:00Z")


def _start(lab: Lab, *, sha: str = SHA, pid: int = 7311, host: str = HOST, process: str = "AnyDesk.exe",
           minute: int = 20) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=f"evt-{host}-{pid}",
              endpoint=host, timestamp=f"2026-01-15T11:{minute:02d}:00Z", event_type="process_start",
              process_name=process, pid=pid, sha256=sha)


def _end(lab: Lab, *, sha: str = SHA, pid: int = 7311, host: str = HOST) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=f"end-{host}-{pid}",
              endpoint=host, timestamp="2026-01-15T11:55:00Z", event_type="process_end",
              process_name="AnyDesk.exe", pid=pid, sha256=sha)


def _installer(lab: Lab, domain: str = LURE) -> None:
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="process_event", event_id="evt-dl-1",
              endpoint=HOST, timestamp="2026-01-15T11:18:00Z", event_type="file_create", process_name="browser.exe",
              domain=domain, sha256=SHA)


def _session(lab: Lab, *, domain: str | None = RELAY, ip: str | None = PEER, sha: str = SHA,
             direction: str = "outbound", action: str = "allowed", verdict: str = "UNKNOWN",
             process: str = "AnyDesk.exe") -> None:
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="network_connection", endpoint=HOST,
              domain=domain, remote_ip=ip, remote_port=443, direction=direction, process_name=process, sha256=sha,
              action=action, verdict=verdict, first_seen="2026-01-15T11:21:00Z", last_seen="2026-01-15T11:50:00Z")


def _prevalence(lab: Lab, *, sha: str = SHA, count: int = 1, signer: str | None = None,
                file_name: str = "AnyDesk.exe") -> None:
    lab.typed("search_hash_enterprise", sha, "secure_endpoint", kind="hash_prevalence", sha256=sha,
              file_name=file_name, prevalence=count, endpoints=[HOST], signer=signer)


def _rate(lab: Lab, otype: ObservableType, value: str, verdict: Verdict = Verdict.MALICIOUS) -> None:
    lab.environment.set_reputation(otype, value, verdict, risk_score=80 if verdict is Verdict.MALICIOUS else 0,
                                   confidence=75, integrations=["virustotal", "umbrella"])


def _attack(lab: Lab, *, prevalence: int = 1) -> None:
    """The fake help-desk pattern of tp-approve-all: flagged AnyDesk, lure download, rated peer."""
    _endpoint(lab)
    _detection(lab)
    _installer(lab)
    _start(lab)
    _session(lab)
    _prevalence(lab, count=prevalence, signer="Example Remote Desktop Vendor")
    _rate(lab, ObservableType.DOMAIN, LURE)
    _rate(lab, ObservableType.IP, PEER)


def _run(lab: Lab, *observables: tuple[ObservableType, str], users: tuple[str, ...] = ()) -> WorkflowRun:
    incident = make_incident(*(observables or ((ObservableType.HOSTNAME, HOST),)), workflow_id="unauthorized-rmm",
                             title=f"Remote access tool on {HOST}", users=users)
    run = lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)
    assert not [n for n in run.notes if n.startswith("hook ")], run.notes  # hooks never fail on lab data
    return run


def _facts(run: WorkflowRun) -> dict[str, Any]:
    view = RunView(workflow=WORKFLOW, incident=make_incident(workflow_id="unauthorized-rmm"), results=run.results,
                   index=run.index, correlation=run.correlation, blast_radius=run.blast_radius)
    facts = dict(HOOKS.facts(view))
    json.dumps(facts, allow_nan=False)  # the runner requires JSON facts
    return facts


def _selectors(run: WorkflowRun) -> set[str]:
    return {f"{p.action_type.value}:{p.target}" for p in run.proposals}


def _considered(run: WorkflowRun, *, manual: bool = False) -> set[str]:
    return {c.subject for c in run.considered if c.manual is manual}


def _keys(node: Any) -> set[str]:
    if isinstance(node, dict):
        return {str(k).lower() for k in node} | {k for v in node.values() for k in _keys(v)}
    if isinstance(node, list):
        return {k for v in node for k in _keys(v)}
    return set()


def test_facts_of_the_fake_help_desk_pattern():
    lab = _lab()
    _attack(lab)
    run = _run(lab)
    facts = _facts(run)
    [tool] = facts["tools"]
    assert (tool["name"], tool["sha256"], tool["flagged"], tool["widespread"]) == ("AnyDesk", SHA, True, False)
    assert tool["signers"] == ["Example Remote Desktop Vendor"] and tool["endpoints"] == [HOST]
    assert "PUA.RemoteAccess.AnyDesk" in tool["basis"]
    [session] = facts["sessions"]
    assert session["hostname"] == HOST and session["untrusted"] and f"peer {PEER} rated" in session["basis"]
    assert session["connector_guid"] == "00000000-0000-4000-8000-000000001047"
    assert [r["target"] for r in facts["running"]] == [f"{HOST}/7311"]
    destinations = {(d["type"], d["value"]): d for d in facts["destinations"]}
    assert destinations[("domain", RELAY)]["session"] and not destinations[("domain", RELAY)]["rated"]
    assert destinations[("domain", LURE)]["installer"] and destinations[("domain", LURE)]["rated"]
    assert destinations[("ip", PEER)]["rated"]
    for fact in (tool, session, *facts["running"], *facts["destinations"]):
        assert fact["record_ids"] and all(i in run.index for i in fact["record_ids"])
    assert not _keys(facts) & APPROVAL_LIKE_KEYS


def test_the_full_package_is_proposed_with_evidence_from_the_run():
    lab = _lab()
    _attack(lab)
    run = _run(lab)
    assert _selectors(run) == {f"terminate_process:{HOST}/7311", f"block_hash:{SHA}", f"block_domain:{RELAY}",
                               f"block_domain:{LURE}", f"block_ip:{PEER}", f"isolate_endpoint:{HOST}"}
    for proposal in run.proposals:
        assert proposal.evidence and all(e.data["record_id"] in run.index for e in proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
        assert proposal.risk_score >= 40
    isolation = next(p for p in run.proposals if p.action_type.value == "isolate_endpoint")
    assert isolation.params.get("connector_guid") == "00000000-0000-4000-8000-000000001047"
    assert _considered(run, manual=True) == {f"uninstall AnyDesk on {HOST}"}
    assert run.handoffs == ()


def test_an_unflagged_tool_is_never_treated_as_malicious():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, verdict="CLEAN")  # the endpoint product reports the tool as allowed by policy
    _start(lab)
    _session(lab)
    _prevalence(lab, count=640)
    run = _run(lab)
    facts = _facts(run)
    [tool] = facts["tools"]
    assert not tool["flagged"] and tool["basis"] == "not flagged by any detection or reputation source"
    assert run.proposals == () and not run.outcomes
    assert _considered(run) == {"rmm_tool:AnyDesk"}
    assert _considered(run, manual=True) == set()


def test_an_ended_tool_has_no_session_and_nothing_running():
    lab = _lab()
    _attack(lab)
    _end(lab)
    run = _run(lab)
    facts = _facts(run)
    assert facts["running"] == [] and facts["sessions"] == []
    selectors = _selectors(run)
    assert f"isolate_endpoint:{HOST}" not in selectors and f"terminate_process:{HOST}/7311" not in selectors
    assert {f"block_hash:{SHA}", f"block_domain:{RELAY}"} <= selectors


def test_a_session_to_the_organisations_own_network_is_not_external():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, verdict="MALICIOUS")
    _start(lab)
    _session(lab, domain=None, ip="10.20.0.15", direction="inbound")
    run = _run(lab)
    facts = _facts(run)
    assert facts["sessions"] == [] and facts["destinations"] == []
    assert f"isolate_endpoint:{HOST}" not in _selectors(run)


def test_an_untrusted_session_without_a_rated_peer_needs_a_malicious_detection():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, verdict="SUSPICIOUS")
    _start(lab)
    _session(lab)
    run = _run(lab)
    assert not _facts(run)["sessions"][0]["untrusted"]
    assert f"isolate_endpoint:{HOST}" not in _selectors(run)
    assert {f"isolate_endpoint:{HOST}", f"block_ip:{PEER}"} <= _considered(run)

    lab = _lab()
    _endpoint(lab)
    _detection(lab, verdict="MALICIOUS", name="RemoteAccess.SessionFromUntrustedOperator")
    _start(lab)
    _session(lab)
    run = _run(lab)
    [session] = _facts(run)["sessions"]
    assert session["untrusted"] and "MALICIOUS" in session["basis"]
    assert f"isolate_endpoint:{HOST}" in _selectors(run)


def test_a_widespread_tool_gets_no_fleet_wide_block():
    lab = _lab()
    _attack(lab, prevalence=180)
    run = _run(lab)
    [tool] = _facts(run)["tools"]
    assert tool["widespread"] and tool["prevalence"] == 180
    selectors = _selectors(run)
    assert f"block_hash:{SHA}" not in selectors and f"block_domain:{RELAY}" not in selectors
    assert {f"block_hash:{SHA}", f"block_domain:{RELAY}"} <= _considered(run)
    assert {f"isolate_endpoint:{HOST}", f"terminate_process:{HOST}/7311", f"block_ip:{PEER}"} <= selectors


def test_an_approved_tool_is_excluded_or_withheld_by_the_framework():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha=APPROVED_SHA, verdict="MALICIOUS", process="ExampleRmmAgent.exe",
               name="RemoteAccess.SessionFromUntrustedOperator")
    _start(lab, sha=APPROVED_SHA, pid=4410, process="ExampleRmmAgent.exe")
    _session(lab, domain="rmm.example.net", ip="198.51.100.121", sha=APPROVED_SHA, process="ExampleRmmAgent.exe")
    run = _run(lab)
    statuses = {o.selector: o.status for o in run.outcomes}
    assert statuses[f"terminate_process:{HOST}/4410"] is RuleOutcomeStatus.ALLOWLISTED
    built = {f"{b.action_type.value}:{b.target}": b for b in run.built}
    assert built[f"block_hash:{APPROVED_SHA}"].excluded_reason == "allowlists.approved_rmm: Example RMM"
    assert built["block_domain:rmm.example.net"].excluded_reason == "allowlists.approved_rmm: Example RMM"
    assert f"isolate_endpoint:{HOST}" in _selectors(run)  # the session is what matters


def test_a_new_build_signed_by_the_approved_signer_is_withheld():
    lab = _lab()
    other = "e1" * 32
    _endpoint(lab)
    _detection(lab, sha=other, process="ExampleRmmAgent.exe")
    _start(lab, sha=other, pid=3220, process="ExampleRmmAgent.exe")
    _prevalence(lab, sha=other, count=3, signer="Example RMM Vendor Inc.", file_name="ExampleRmmAgent.exe")
    run = _run(lab)
    statuses = {o.selector: o.status for o in run.outcomes}
    assert statuses[f"block_hash:{other}"] is RuleOutcomeStatus.ALLOWLISTED
    assert statuses[f"terminate_process:{HOST}/3220"] is RuleOutcomeStatus.ALLOWLISTED
    assert run.proposals == ()


def test_an_unrated_installer_source_is_considered_not_blocked():
    lab = _lab()
    _endpoint(lab)
    _detection(lab)
    _installer(lab, domain="download.vendor-site.test")
    _start(lab)
    run = _run(lab)
    assert "block_domain:download.vendor-site.test" not in _selectors(run)
    assert "block_domain:download.vendor-site.test" in _considered(run)


def test_dns_queries_with_a_remote_access_category_name_the_relay():
    lab = _lab()
    _endpoint(lab)
    _detection(lab)
    _start(lab)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="dns_query", endpoint=HOST,
              domain="broker.fictidesk.example", categories=["Remote Access"], count=4,
              first_seen="2026-01-15T11:21:00Z")
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="dns_query", endpoint=HOST,
              domain="news.example.org", categories=["News"], count=2, first_seen="2026-01-15T11:22:00Z")
    run = _run(lab)
    values = {d["value"] for d in _facts(run)["destinations"]}
    assert values == {"broker.fictidesk.example"}
    assert "block_domain:broker.fictidesk.example" in _selectors(run)


def test_persistence_and_compromised_user_are_handed_off():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha="a7e2" * 16, process="AteraAgent.exe", name="PUA.RemoteAccess.Atera")
    _start(lab, sha="a7e2" * 16, pid=5120, process="AteraAgent.exe")
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="persistence_item", endpoint=HOST,
              item_id="svc-ateraagent", mechanism="service", name="AteraAgent",
              path="C:\\Program Files\\ATERA Networks\\AteraAgent\\AteraAgent.exe", sha256="a7e2" * 16)
    lab.typed("investigate_user", "jsmith@example.com", "entra", kind="user_profile", user="jsmith@example.com",
              risk_level="high", risk_state="at_risk")
    run = _run(lab, (ObservableType.HOSTNAME, HOST), users=("jsmith@example.com",))
    handoffs = {h.workflow_id: h for h in run.handoffs}
    assert set(handoffs) == {"persistence", "account-takeover"}
    assert handoffs["persistence"].subjects == (HOST,)
    assert handoffs["account-takeover"].subjects == ("jsmith@example.com",)
    for handoff in run.handoffs:
        assert handoff.record_ids and all(i in run.index for i in handoff.record_ids)


def test_no_account_handoff_without_a_compromise_record():
    lab = _lab()
    _attack(lab)
    lab.typed("investigate_user", "jsmith@example.com", "entra", kind="user_profile", user="jsmith@example.com",
              risk_level="medium")
    run = _run(lab, (ObservableType.HOSTNAME, HOST), users=("jsmith@example.com",))
    assert run.handoffs == ()


def test_session_and_installer_links_cite_the_run_records():
    lab = _lab()
    _attack(lab)
    run = _run(lab)
    links = [link for link in run.correlation.links if link.kind is LinkKind.WORKFLOW]
    notes = sorted(link.note.split(":")[0] for link in links)
    assert notes == ["installer origin", "remote session"]  # one link per record (peer domain first)
    for link in links:
        assert link.origin == "workflow:unauthorized-rmm"
        assert all(i in run.index for i in link.record_ids)


def test_dry_run_and_live_runs_compute_the_same_facts():
    dry_lab, live_lab = _lab(), _lab()
    _attack(dry_lab)
    _attack(live_lab)
    incident = make_incident((ObservableType.HOSTNAME, HOST), workflow_id="unauthorized-rmm")
    dry = dry_lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)
    live = live_lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=False)
    assert [(p.action_type, p.target, p.risk_score, p.confidence_score) for p in dry.proposals] == \
           [(p.action_type, p.target, p.risk_score, p.confidence_score) for p in live.proposals]
    assert dry_lab.environment.state_changing_calls() == [] and live_lab.environment.state_changing_calls() == []
