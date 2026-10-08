"""c2 hooks: destinations, hosts, processes, considerations, hand-offs and links computed from the run's
own records (simulated read-only lab; nothing state-changing is ever called)."""
from __future__ import annotations

import json
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.models import Incident, ObservableType, Verdict
from xdr_response.workflows.c2 import HOOKS, WORKFLOW
from xdr_response.workflows.c2.hooks import is_c2_category, ipv4
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

HOST = "TH-LT-1047"
OTHER = "TH-LT-2210"
SHA = "c2be4c0d" * 8
DOMAIN = "beacon-gate.test"
IP = "198.51.100.45"
URL = "https://beacon-gate.test/api/checkin"
SUITE = {"secure_endpoint": ("endpoint",), "umbrella": ("network",), "virustotal": ("intel",),
         "meraki": ("network",), "microsoft_cloud": ("network",)}
_O = ObservableType


def _lab() -> Lab:
    return make_lab(SUITE)


def _endpoint(lab: Lab, host: str = HOST, **extra: Any) -> None:
    fields = {"connector_guid": "00000000-0000-4000-8000-000000001047", "groups": ["Workstations"],
              "users": ["jsmith@example.com"], "isolation_capable": True, "isolation_state": "not_isolated", **extra}
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host, **fields)


def _detection(lab: Lab, host: str = HOST, *, verdict: str = "MALICIOUS", status: str = "active",
               sha: str | None = SHA, process: str | None = "svc_update.exe") -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", detection_id=f"det-{host}-{verdict}",
              name="Sample.C2.Beacon", verdict=verdict, severity="HIGH", endpoint=host, status=status,
              sha256=sha, process_name=process, first_seen="2026-01-15T10:05:00Z")


def _dns(lab: Lab, host: str = HOST, domain: str = DOMAIN, *, count: int = 60, ips: list[str] | None = None,
         categories: list[str] | None = None, verdict: str = "UNKNOWN") -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="dns_query", endpoint=host, domain=domain,
              query_type="A", response_ips=ips or [], count=count, categories=categories or [], verdict=verdict,
              first_seen="2026-01-15T10:00:00Z", last_seen="2026-01-15T11:00:00Z")


def _connection(lab: Lab, host: str = HOST, ip: str = IP, *, domain: str | None = DOMAIN, url: str | None = None,
                pid: int | None = 3120, sha: str | None = SHA, verdict: str = "UNKNOWN", count: int = 60,
                process: str = "svc_update.exe", direction: str = "outbound") -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="network_connection", endpoint=host,
              remote_ip=ip, remote_port=443, protocol="tcp", direction=direction, domain=domain, url=url,
              process_name=process, pid=pid, sha256=sha, count=count, verdict=verdict,
              first_seen="2026-01-15T10:00:00Z", last_seen="2026-01-15T11:00:00Z")


def _start(lab: Lab, host: str = HOST, *, pid: int = 3120, sha: str | None = SHA, verdict: str = "UNKNOWN") -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=f"evt-{host}-{pid}",
              endpoint=host, timestamp="2026-01-15T09:58:00Z", event_type="process_start",
              process_name="svc_update.exe", pid=pid, sha256=sha, verdict=verdict)


def _end(lab: Lab, host: str = HOST, *, pid: int = 3120) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=f"end-{host}-{pid}",
              endpoint=host, timestamp="2026-01-15T11:30:00Z", event_type="process_end",
              process_name="svc_update.exe", pid=pid, sha256=SHA)


def _rate(lab: Lab, otype: ObservableType, value: str, verdict: Verdict, integrations: list[str]) -> None:
    lab.environment.set_reputation(otype, value, verdict, risk_score=85 if verdict is Verdict.MALICIOUS else 50,
                                   confidence=80, integrations=integrations)


def _malicious_domain(lab: Lab, domain: str = DOMAIN) -> None:
    _rate(lab, _O.DOMAIN, domain, Verdict.MALICIOUS, ["umbrella", "virustotal"])


_INCIDENTS: dict[str, Incident] = {}  # run incident id -> the incident it ran for (views see the same one)


def _run(lab: Lab, *observables: tuple[ObservableType, str], **extra: Any) -> WorkflowRun:
    incident = make_incident(*(observables or ((_O.HOSTNAME, HOST), (_O.DOMAIN, DOMAIN))), workflow_id="c2",
                             title=f"Periodic HTTPS beaconing from {HOST}", **extra)
    _INCIDENTS[incident.incident_id] = incident
    return lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)


def _view(run: WorkflowRun) -> RunView:
    return RunView(workflow=WORKFLOW, incident=_INCIDENTS[run.incident_id], results=run.results,
                   index=run.index, correlation=run.correlation, blast_radius=run.blast_radius)


def _facts(run: WorkflowRun) -> dict[str, Any]:
    facts = dict(HOOKS.facts(_view(run)))
    json.dumps(facts, allow_nan=False)  # the runner requires JSON facts
    return facts


def _destination(facts: dict[str, Any], kind: str, value: str) -> dict[str, Any]:
    return next(d for d in facts["destinations"] if (d["type"], d["value"]) == (kind, value))


def _host(facts: dict[str, Any], host: str) -> dict[str, Any]:
    return next(h for h in facts["hosts"] if h["hostname"] == host)


def _proposed(run: WorkflowRun) -> set[str]:
    return {o.selector for o in run.outcomes_with(RuleOutcomeStatus.PROPOSED)}


def _considered(run: WorkflowRun) -> dict[str, bool]:
    return {c.subject: c.manual for c in run.considered}


# ------------------------------------------------------------------ helpers --
@pytest.mark.parametrize("category, expected", [
    ("Command and Control", True), ("command & control", True), ("Botnet C2", True), ("C2", True),
    ("Malware", False), ("Newly Seen Domains", False), ("c2c-marketplace", False), ("abc2", False), (None, False)])
def test_c2_categories_are_recognised_by_name_only(category, expected):
    assert is_c2_category(category) is expected


def test_ipv4_accepts_any_ipv4_and_refuses_ipv6_or_text():
    assert ipv4(" 198.51.100.45 ") == IP and ipv4("10.20.30.40") == "10.20.30.40"
    assert ipv4("2001:db8::1") is None and ipv4("beacon-gate.test") is None and ipv4(None) is None


# --------------------------------------------------------------- full case --
def test_a_beaconing_workstation_gets_the_full_package_and_a_malware_handoff():
    lab = _lab()
    _endpoint(lab)
    _detection(lab)
    _start(lab)
    _dns(lab, ips=[IP], categories=["Command and Control"])
    _connection(lab, url=URL, verdict="MALICIOUS")
    _malicious_domain(lab)
    _rate(lab, _O.URL, URL, Verdict.MALICIOUS, ["umbrella", "virustotal"])
    _rate(lab, _O.SHA256, SHA, Verdict.MALICIOUS, ["secure_endpoint", "virustotal"])
    run = _run(lab)
    assert _proposed(run) == {f"block_domain:{DOMAIN}", f"block_ip:{IP}", f"block_url:{URL}",
                              f"isolate_endpoint:{HOST}", f"terminate_process:{HOST}/3120"}
    assert run.considered == ()
    assert [(h.workflow_id, h.subjects) for h in run.handoffs] == [("malware", (SHA,))]
    facts = _facts(run)
    domain = _destination(facts, "domain", DOMAIN)
    assert domain["rated"] and domain["malicious"] and domain["c2_category"] and domain["beacon"]
    assert "60 contacts from TH-LT-1047, about every 61 s" in domain["beacon_text"] and domain["endpoints"] == [HOST]
    host = _host(facts, HOST)
    assert host["isolate"] and host["connector_guid"] and "active detection" in host["basis"]
    process = facts["processes"][0]
    assert process["target"] == f"{HOST}/3120" and process["malicious_hashes"] == [SHA]
    # every fact cites only records the run produced
    for item in [*facts["destinations"], *facts["hosts"], *facts["processes"]]:
        assert item["record_ids"] and set(item["record_ids"]) <= set(run.index.ids())


# ----------------------------------------------------------- destinations --
def test_a_suspicious_domain_is_blocked_only_with_a_c2_category():
    lab = _lab()
    _endpoint(lab)
    _dns(lab, "TH-LT-1047", "qx7kz2vbn4.test", count=14, categories=["Command and Control", "Newly Seen Domains"])
    _dns(lab, "TH-LT-1047", "mpl0r8tyw1.test", count=2, categories=["Newly Seen Domains"])
    _rate(lab, _O.DOMAIN, "qx7kz2vbn4.test", Verdict.SUSPICIOUS, ["umbrella", "virustotal"])
    _rate(lab, _O.DOMAIN, "mpl0r8tyw1.test", Verdict.SUSPICIOUS, ["umbrella"])
    run = _run(lab, (_O.HOSTNAME, HOST))
    assert _proposed(run) == {"block_domain:qx7kz2vbn4.test"}
    assert _considered(run) == {"block_domain:mpl0r8tyw1.test": False}
    facts = _facts(run)
    assert _destination(facts, "domain", "qx7kz2vbn4.test")["rating"] == "SUSPICIOUS"
    assert not _host(facts, HOST)["isolate"]  # no MALICIOUS destination: never isolated on a SUSPICIOUS one


def test_periodicity_alone_never_rates_a_destination_but_is_shown():
    lab = _lab()
    _endpoint(lab)
    _dns(lab, domain="cdn-sync.test", count=95, ips=["198.51.100.140"])
    _connection(lab, ip="198.51.100.140", domain="cdn-sync.test", count=95, sha=None, pid=7710, process="helper.exe")
    run = _run(lab, (_O.HOSTNAME, HOST))
    assert _proposed(run) == set()
    assert _considered(run) == {"block_domain:cdn-sync.test": False, "block_ip:198.51.100.140": False}
    assert all("periodicity alone never blocks" in c.reason for c in run.considered)


def test_a_beacon_to_a_clean_service_is_not_even_considered():
    lab = _lab()
    _endpoint(lab)
    _dns(lab, domain="telemetry.saas-vendor.test", count=12, ips=["198.51.100.20"])
    _connection(lab, ip="198.51.100.20", domain="telemetry.saas-vendor.test", count=12, sha=None, pid=2040,
                process="agent_update.exe")
    _rate(lab, _O.DOMAIN, "telemetry.saas-vendor.test", Verdict.CLEAN, ["umbrella", "virustotal"])
    run = _run(lab, (_O.HOSTNAME, HOST))
    assert _proposed(run) == set() and run.considered == ()
    assert _destination(_facts(run), "ip", "198.51.100.20")["clean_names"] == ["telemetry.saas-vendor.test"]


def test_a_cdn_address_that_also_serves_a_clean_domain_is_not_blocked_by_ip():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha=None, process=None)
    _dns(lab, domain="static-assets.test", ips=["198.51.100.80"])
    _dns(lab, domain="cdn-portal.test", count=3, ips=["198.51.100.80"])
    _connection(lab, ip="198.51.100.80", domain="static-assets.test", pid=None, sha=None, verdict="MALICIOUS")
    _malicious_domain(lab, "static-assets.test")
    _rate(lab, _O.DOMAIN, "cdn-portal.test", Verdict.CLEAN, ["umbrella", "virustotal"])
    run = _run(lab, (_O.HOSTNAME, HOST), (_O.DOMAIN, "static-assets.test"))
    assert _proposed(run) == {"block_domain:static-assets.test", f"isolate_endpoint:{HOST}"}
    assert _considered(run) == {"block_ip:198.51.100.80": False}
    reason = run.considered[0].reason
    assert "cdn-portal.test" in reason and "shared hosting or CDN" in reason
    ip = _destination(_facts(run), "ip", "198.51.100.80")
    assert ip["rated"] and ip["shared"] and ip["shared_record_ids"]


def test_an_address_the_incident_source_lists_as_shared_is_not_blocked_by_ip():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha=None, process=None)
    _connection(lab, ip="198.51.100.80", domain="static-assets.test", pid=None, sha=None, verdict="MALICIOUS")
    _malicious_domain(lab, "static-assets.test")
    trigger = {"shared_infrastructure_ips": ["198.51.100.80"]}
    run = _run(lab, (_O.HOSTNAME, HOST), (_O.DOMAIN, "static-assets.test"), trigger=trigger)
    assert "block_ip:198.51.100.80" not in _proposed(run)
    assert _considered(run) == {"block_ip:198.51.100.80": False}
    assert "incident source lists it" in run.considered[0].reason


def test_an_internal_relay_is_proposed_and_left_to_the_allow_list_to_exclude_visibly():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha=None, process=None)
    _connection(lab, ip="10.20.30.40", domain=None, pid=None, sha=None, verdict="MALICIOUS")
    run = _run(lab, (_O.HOSTNAME, HOST), (_O.IP, "10.20.30.40"))
    built = {(b.action_type.value, b.target): b for b in run.built}
    assert "block_ip:10.20.30.40" in _proposed(run)
    assert "non-public address" in (built[("block_ip", "10.20.30.40")].excluded_reason or "")


def test_inbound_and_internal_connections_are_not_destinations():
    lab = _lab()
    _endpoint(lab)
    _connection(lab, ip="198.51.100.9", domain=None, direction="inbound", verdict="MALICIOUS")
    _connection(lab, ip="198.51.100.10", domain=None, direction="internal", verdict="MALICIOUS")
    run = _run(lab, (_O.HOSTNAME, HOST))
    values = {d["value"] for d in _facts(run)["destinations"]}
    assert "198.51.100.9" not in values and "198.51.100.10" not in values
    assert _proposed(run) == set()


# ------------------------------------------------------------------ hosts --
def test_an_endpoint_that_reached_c2_without_its_own_malicious_activity_is_only_considered():
    lab = _lab()
    _endpoint(lab)
    _dns(lab, count=1)
    _malicious_domain(lab)
    run = _run(lab)
    assert _proposed(run) == {f"block_domain:{DOMAIN}"}
    assert _considered(run) == {f"isolate_endpoint:{HOST}": False}
    assert not _host(_facts(run), HOST)["isolate"]


def test_a_resolved_detection_is_not_malicious_activity():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, status="resolved")
    _dns(lab)
    _malicious_domain(lab)
    run = _run(lab)
    assert f"isolate_endpoint:{HOST}" not in _proposed(run)


def test_the_incident_naming_the_endpoint_and_the_destination_ties_them_without_typed_contacts():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha=None, process=None)
    _malicious_domain(lab)
    run = _run(lab)
    assert _proposed(run) == {f"block_domain:{DOMAIN}", f"isolate_endpoint:{HOST}"}
    assert "the incident names the endpoint" in _host(_facts(run), HOST)["basis"]


def test_an_endpoint_that_cannot_be_isolated_is_a_manual_step_never_silently_skipped():
    lab = _lab()
    _endpoint(lab, isolation_capable=False)
    _detection(lab, sha=None, process=None)
    _dns(lab)
    _malicious_domain(lab)
    run = _run(lab)
    assert f"isolate_endpoint:{HOST}" not in _proposed(run)
    assert _considered(run) == {f"isolate_endpoint:{HOST}": True}
    assert "network by hand" in run.considered[0].reason


def test_other_endpoints_found_by_the_enterprise_search_are_investigated():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha=None, process=None)
    _dns(lab)
    lab.typed("search_domain_enterprise", DOMAIN, "microsoft_cloud", kind="dns_query", endpoint=OTHER, domain=DOMAIN,
              query_type="A", count=40, first_seen="2026-01-15T10:10:00Z")
    _endpoint(lab, OTHER, connector_guid="00000000-0000-4000-8000-000000002210")
    _detection(lab, OTHER, sha=None, process=None)
    _malicious_domain(lab)
    run = _run(lab)
    assert _proposed(run) == {f"block_domain:{DOMAIN}", f"isolate_endpoint:{HOST}", f"isolate_endpoint:{OTHER}"}
    assert any(r.atomic == "search_domain_enterprise" for r in run.results)


# -------------------------------------------------------------- processes --
def test_an_ended_process_is_not_terminated():
    lab = _lab()
    _endpoint(lab)
    _detection(lab)
    _start(lab)
    _end(lab)
    _connection(lab, verdict="MALICIOUS")
    _malicious_domain(lab)
    run = _run(lab)
    assert not any(s.startswith("terminate_process:") for s in _proposed(run))
    assert _facts(run)["processes"] == []


def test_an_unflagged_process_on_a_c2_connection_is_considered_not_terminated():
    lab = _lab()
    _endpoint(lab)
    _dns(lab)
    _connection(lab, sha=None, pid=5120, process="browser.exe")
    _malicious_domain(lab)
    run = _run(lab)
    assert not any(s.startswith("terminate_process:") for s in _proposed(run))
    assert _considered(run).get(f"terminate_process:{HOST}/5120") is False
    assert run.handoffs == ()


def test_a_flagged_process_without_a_hash_is_terminated_but_not_handed_off():
    lab = _lab()
    _endpoint(lab)
    _start(lab, sha=None, verdict="MALICIOUS")
    _connection(lab, sha=None)
    _malicious_domain(lab)
    run = _run(lab)
    assert f"terminate_process:{HOST}/3120" in _proposed(run)
    assert f"isolate_endpoint:{HOST}" in _proposed(run)  # a malicious process event is malicious activity
    assert run.handoffs == ()


# ------------------------------------------------------------------ links --
def test_beacon_and_resolution_links_are_workflow_links_citing_run_records():
    lab = _lab()
    _endpoint(lab)
    _dns(lab, ips=[IP])
    _connection(lab)
    _malicious_domain(lab)
    run = _run(lab)
    links = list(HOOKS.correlate(_view(run)))
    assert links and all(link.kind is LinkKind.WORKFLOW and link.origin == "workflow:c2" for link in links)
    notes = {link.note for link in links}
    assert f"beacon: {HOST} reached {DOMAIN}" in notes and f"resolution: {DOMAIN} resolved to {IP}" in notes
    for link in links:
        for record_id in link.record_ids:
            assert record_id in run.index
    assert not any("hook links ignored" in n for n in run.notes)


def test_hooks_never_fail_on_an_empty_run():
    lab = _lab()
    run = _run(lab, (_O.HOSTNAME, HOST))
    assert _facts(run) == {"destinations": [], "hosts": [], "processes": []}
    assert run.considered == () and run.handoffs == ()
    assert not any(o.status is RuleOutcomeStatus.ERROR for o in run.outcomes)
