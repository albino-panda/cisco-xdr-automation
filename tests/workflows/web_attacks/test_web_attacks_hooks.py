"""web-attacks hooks: sources, servers, URLs, considerations, hand-offs and links computed from the run's
own records (simulated read-only lab; nothing state-changing is ever called)."""
from __future__ import annotations

import json
from typing import Any

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.atomics.records import DetectionRecord
from xdr_response.models import Incident, ObservableType, Severity, Verdict
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun
from xdr_response.workflows.web_attacks import HOOKS, WORKFLOW
from xdr_response.workflows.web_attacks.hooks import ipv4, is_exploit_detection, is_web_shell_detection

HOST = "WEB-SHOP-01"
OTHER = "WEB-SHOP-02"
SRC = "203.0.113.145"
SCANNER = "192.0.2.140"
SHA = "5be11a7e" * 8
URL = "https://shop.example.net/upload"
ADMIN = "https://shop.example.net/admin"
SUITE = {"secure_endpoint": ("endpoint",), "cisco_xdr": ("intel",), "virustotal": ("intel",),
         "umbrella": ("network",), "meraki": ("network",), "microsoft_cloud": ("network",)}
_O = ObservableType


def _lab() -> Lab:
    return make_lab(SUITE)


def _server(lab: Lab, host: str = HOST, **extra: Any) -> None:
    fields = {"connector_guid": "00000000-0000-4000-8000-000000000101", "groups": ["Web Servers"],
              "ip_addresses": ["198.51.100.10"], "isolation_capable": True, "isolation_state": "not_isolated", **extra}
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host, **fields)


def _request(lab: Lab, host: str = HOST, src: str = SRC, url: str | None = URL, *, verdict: str = "MALICIOUS",
             action: str = "allowed", minute: int = 40, count: int = 3) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="network_connection", endpoint=host,
              remote_ip=src, local_ip="198.51.100.10", protocol="tcp", direction="inbound", url=url,
              process_name="w3wp.exe", count=count, action=action, verdict=verdict,
              first_seen=f"2026-01-15T09:{minute:02d}:00Z", last_seen=f"2026-01-15T09:{minute + 1:02d}:00Z")


def _web_shell(lab: Lab, host: str = HOST, *, verdict: str = "MALICIOUS", status: str = "active",
               sha: str | None = SHA, techniques: tuple[str, ...] = ("T1505.003",),
               name: str = "Web shell file written to web root", category: str | None = None) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection",
              detection_id=f"det-{host}-{verdict}-{status}-{name[:8]}", name=name, verdict=verdict, severity="HIGH",
              category=category, endpoint=host, sha256=sha, mitre_techniques=list(techniques), status=status,
              first_seen="2026-01-15T09:43:00Z")


def _exploit(lab: Lab, host: str = HOST, *, verdict: str = "MALICIOUS") -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", detection_id=f"det-exploit-{host}",
              name="Exploit of public-facing application", verdict=verdict, severity="HIGH", endpoint=host,
              mitre_techniques=["T1190"], status="active", first_seen="2026-01-15T09:43:00Z")


def _rate(lab: Lab, otype: ObservableType, value: str, verdict: Verdict, integrations: list[str] | None = None) -> None:
    lab.environment.set_reputation(otype, value, verdict, risk_score=85 if verdict is Verdict.MALICIOUS else 55,
                                   confidence=80, integrations=integrations or ["cisco_xdr", "virustotal"])


_INCIDENTS: dict[str, Incident] = {}  # run incident id -> the incident it ran for (views see the same one)


def _run(lab: Lab, *observables: tuple[ObservableType, str], **extra: Any) -> WorkflowRun:
    incident = make_incident(*(observables or ((_O.HOSTNAME, HOST), (_O.IP, SRC))), workflow_id="web-attacks",
                             title="Web shell detected on WEB-SHOP-01", **extra)
    _INCIDENTS[incident.incident_id] = incident
    return lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)


def _view(run: WorkflowRun) -> RunView:
    return RunView(workflow=WORKFLOW, incident=_INCIDENTS[run.incident_id], results=run.results,
                   index=run.index, correlation=run.correlation, blast_radius=run.blast_radius)


def _facts(run: WorkflowRun) -> dict[str, Any]:
    facts = dict(HOOKS.facts(_view(run)))
    json.dumps(facts, allow_nan=False)  # the runner requires JSON facts
    return facts


def _source(facts: dict[str, Any], ip: str) -> dict[str, Any]:
    return next(s for s in facts["sources"] if s["ip"] == ip)


def _server_fact(facts: dict[str, Any], host: str = HOST) -> dict[str, Any]:
    return next(s for s in facts["servers"] if s["hostname"] == host)


def _url_fact(facts: dict[str, Any], url: str = URL) -> dict[str, Any]:
    return next(u for u in facts["urls"] if u["url"] == url)


def _proposed(run: WorkflowRun) -> set[str]:
    return {o.selector for o in run.outcomes_with(RuleOutcomeStatus.PROPOSED)}


def _considered(run: WorkflowRun) -> dict[str, bool]:
    return {c.subject: c.manual for c in run.considered}


def _confirmed_web_shell_lab() -> Lab:
    lab = _lab()
    _server(lab)
    _request(lab)
    _web_shell(lab)
    _rate(lab, _O.IP, SRC, Verdict.MALICIOUS)
    _rate(lab, _O.SHA256, SHA, Verdict.MALICIOUS)
    return lab


# ------------------------------------------------------------------ helpers --
def test_detection_classifiers_use_the_vendor_technique_name_or_category():
    def detection(**fields: Any) -> DetectionRecord:
        return DetectionRecord(integration="secure_endpoint", atomic="investigate_endpoint",
                               subject={"type": "hostname", "value": HOST}, verdict=Verdict.MALICIOUS,
                               severity=Severity.HIGH, endpoint=HOST, **fields)
    assert is_web_shell_detection(detection(name="Generic.Detection", mitre_techniques=("t1505.003",)))
    assert is_web_shell_detection(detection(name="ASPX WebShell dropped"))
    assert is_web_shell_detection(detection(name="Generic.Detection", category="Web Shell"))
    assert not is_web_shell_detection(detection(name="Generic.Detection", mitre_techniques=("T1505",)))
    assert is_exploit_detection(detection(name="Generic.Detection", mitre_techniques=("T1190",)))
    assert is_exploit_detection(detection(name="Generic.Detection", category="Exploit Prevention"))
    assert not is_exploit_detection(detection(name="Exploit-looking name only"))  # names never decide
    assert ipv4("203.0.113.145") == "203.0.113.145" and ipv4("2001:db8::1") is None and ipv4("bad") is None


# ----------------------------------------------------------------- servers --
def test_a_confirmed_web_shell_isolates_the_server_and_blocks_source_and_url():
    lab = _confirmed_web_shell_lab()
    run = _run(lab, (_O.HOSTNAME, HOST), (_O.IP, SRC), (_O.URL, URL))
    facts = _facts(run)
    server = _server_fact(facts)
    assert server["web_shell"] and server["isolate"] and server["web_shell_hashes"] == [SHA]
    assert server["attackers"] == [SRC] and "attacked by 203.0.113.145" in server["source_text"]
    assert all(i in run.index for i in server["record_ids"])
    assert _proposed(run) == {f"block_ip:{SRC}", f"block_url:{URL}", f"isolate_endpoint:{HOST}"}
    assert _considered(run) == {f"waf-virtual-patch:{URL}": True, f"review-web-root:{HOST}": True}
    assert lab.environment.state_changing_calls() == []


def test_isolation_evidence_cites_the_web_shell_detection_and_the_attack_request():
    run = _run(_confirmed_web_shell_lab())
    proposal = next(p for p in run.proposals if p.action_type.value == "isolate_endpoint")
    kinds = {run.index.get(e.data["record_id"]).kind.value for e in proposal.evidence}
    assert {"detection", "network_connection"} <= kinds
    assert "confirmed web shell" in proposal.rationale


def test_a_suspicious_or_resolved_web_shell_detection_never_isolates_and_is_considered():
    for kwargs in ({"verdict": "SUSPICIOUS"}, {"status": "resolved"}):
        lab = _lab()
        _server(lab)
        _web_shell(lab, **kwargs)
        run = _run(lab, (_O.HOSTNAME, HOST))
        server = _server_fact(_facts(run))
        assert not server["web_shell"] and not server["isolate"], kwargs
        assert not any(s.startswith("isolate_endpoint:") for s in _proposed(run)), kwargs
        assert _considered(run) == {f"isolate_endpoint:{HOST}": False}, kwargs


def test_an_exploit_without_a_web_shell_blocks_the_url_but_never_isolates():
    lab = _lab()
    _server(lab)
    _request(lab)
    _exploit(lab)
    _rate(lab, _O.IP, SRC, Verdict.MALICIOUS)
    run = _run(lab)
    facts = _facts(run)
    assert _server_fact(facts)["exploited"] and not _server_fact(facts)["isolate"]
    assert _url_fact(facts)["exploited"]
    assert _proposed(run) == {f"block_ip:{SRC}", f"block_url:{URL}"}
    considered = _considered(run)
    assert considered[f"isolate_endpoint:{HOST}"] is False and considered[f"waf-virtual-patch:{URL}"] is True
    assert f"review-web-root:{HOST}" not in considered


def test_an_unisolatable_or_unmanaged_web_shell_server_is_a_manual_step():
    for extra in ({"isolation_capable": False}, {"connector_guid": None}):
        lab = _confirmed_web_shell_lab()
        _server(lab, "WEB-APPL-01", **extra)
        _web_shell(lab, "WEB-APPL-01")
        run = _run(lab, (_O.HOSTNAME, "WEB-APPL-01"), (_O.IP, SRC))
        assert "isolate_endpoint:WEB-APPL-01" not in _proposed(run), extra
        assert _considered(run)["isolate_endpoint:WEB-APPL-01"] is True, extra


# ----------------------------------------------------------------- sources --
def test_a_source_is_rated_by_enrichment_or_by_a_malicious_request_verdict():
    lab = _lab()
    _server(lab)
    _request(lab, src="198.51.100.71", verdict="MALICIOUS", url=ADMIN)   # no enrichment, flagged request
    _request(lab, src="198.51.100.72", verdict="UNKNOWN", url=ADMIN, minute=44)  # SUSPICIOUS reputation
    _request(lab, src="198.51.100.73", verdict="UNKNOWN", url=ADMIN, minute=46)  # nothing rates it
    _rate(lab, _O.IP, "198.51.100.72", Verdict.SUSPICIOUS, ["cisco_xdr"])
    run = _run(lab, (_O.HOSTNAME, HOST))
    facts = _facts(run)
    assert _source(facts, "198.51.100.71")["rated"] and _source(facts, "198.51.100.72")["rated"]
    assert not _source(facts, "198.51.100.73")["rated"]
    assert _proposed(run) == {"block_ip:198.51.100.71", "block_ip:198.51.100.72"}


def test_suspicious_requests_alone_never_block_the_source_and_are_considered():
    lab = _lab()
    _server(lab)
    _request(lab, src=SCANNER, url=ADMIN, verdict="SUSPICIOUS")
    run = _run(lab, (_O.HOSTNAME, HOST))
    assert not _source(_facts(run), SCANNER)["rated"]
    assert _proposed(run) == set()
    assert _considered(run) == {f"block_ip:{SCANNER}": False, f"block_url:{ADMIN}": False}


def test_an_authorised_scanner_listed_by_the_incident_source_is_considered_not_blocked():
    lab = _lab()
    _server(lab)
    _rate(lab, _O.IP, SCANNER, Verdict.SUSPICIOUS, ["cisco_xdr"])
    run = _run(lab, (_O.HOSTNAME, HOST), (_O.IP, SCANNER), trigger={"authorized_scanners": [SCANNER]})
    source = _source(_facts(run), SCANNER)
    assert source["rated"] and source["authorized"]
    assert _proposed(run) == set()
    assert _considered(run) == {f"block_ip:{SCANNER}": False}


def test_ipv6_sources_are_not_handled():
    lab = _lab()
    _server(lab)
    _request(lab, src="2001:db8::45", url=ADMIN)
    run = _run(lab, (_O.HOSTNAME, HOST))
    assert _facts(run)["sources"] == [] and _proposed(run) == set()


# -------------------------------------------------------------------- urls --
def test_scanning_alone_never_blocks_the_url_or_isolates():
    lab = _lab()
    _server(lab)
    _request(lab, src=SCANNER, url=ADMIN, verdict="MALICIOUS", count=60)
    run = _run(lab, (_O.HOSTNAME, HOST))
    facts = _facts(run)
    assert not _url_fact(facts, ADMIN)["exploited"] and _url_fact(facts, ADMIN)["record_ids"] == []
    assert _proposed(run) == {f"block_ip:{SCANNER}"}
    assert _considered(run) == {f"block_url:{ADMIN}": False}


def test_a_blocked_request_does_not_make_the_url_exploited_unless_the_incident_names_both():
    lab = _lab()
    _server(lab)
    _request(lab, action="blocked")
    _web_shell(lab)
    _rate(lab, _O.IP, SRC, Verdict.MALICIOUS)
    run = _run(lab, (_O.HOSTNAME, HOST), (_O.IP, SRC))
    assert not _url_fact(_facts(run))["exploited"]
    assert f"block_url:{URL}" not in _proposed(run)
    named = _run(lab, (_O.HOSTNAME, HOST), (_O.IP, SRC), (_O.URL, URL), incident_id="XDR-WEB-9002")
    url = _url_fact(_facts(named))
    assert url["exploited"] and "the incident names the URL and WEB-SHOP-01" in url["basis"]
    assert f"block_url:{URL}" in _proposed(named)


def test_benign_traffic_to_a_compromised_server_never_blocks_its_paths():
    lab = _confirmed_web_shell_lab()
    _request(lab, src="198.51.100.60", url="https://shop.example.net/healthz", verdict="UNKNOWN", minute=30)
    _rate(lab, _O.IP, "198.51.100.60", Verdict.CLEAN)
    run = _run(lab, (_O.HOSTNAME, HOST), (_O.IP, SRC))
    assert not _url_fact(_facts(run), "https://shop.example.net/healthz")["exploited"]
    assert "block_url:https://shop.example.net/healthz" not in _proposed(run)
    assert "block_ip:198.51.100.60" not in _proposed(run)


# --------------------------------------------------------------- hand-offs --
def test_the_web_shell_hash_is_handed_off_to_malware_and_nothing_else():
    run = _run(_confirmed_web_shell_lab())
    assert [(h.workflow_id, h.subjects) for h in run.handoffs] == [("malware", (SHA,))]
    lab = _lab()
    _server(lab)
    _web_shell(lab, verdict="SUSPICIOUS")
    assert _run(lab, (_O.HOSTNAME, HOST)).handoffs == ()


def test_a_second_server_found_by_the_source_sightings_is_investigated_and_isolated():
    lab = _confirmed_web_shell_lab()
    lab.typed("search_ip_enterprise", SRC, "microsoft_cloud", kind="network_connection", endpoint=OTHER,
              remote_ip=SRC, local_ip="198.51.100.11", protocol="tcp", direction="inbound", url=URL,
              count=2, action="allowed", verdict="MALICIOUS", first_seen="2026-01-15T09:50:00Z")
    _server(lab, OTHER, connector_guid="00000000-0000-4000-8000-000000000102")
    _web_shell(lab, OTHER)
    run = _run(lab)
    assert {f"isolate_endpoint:{HOST}", f"isolate_endpoint:{OTHER}"} <= _proposed(run)
    assert [(h.workflow_id, h.subjects) for h in run.handoffs] == [("malware", (SHA,))]


# ------------------------------------------------------------------- links --
def test_attack_request_and_web_shell_links_cite_the_run_records():
    run = _run(_confirmed_web_shell_lab(), (_O.HOSTNAME, HOST), (_O.IP, SRC))
    links = HOOKS.correlate(_view(run))
    notes = sorted(link.note for link in links)
    assert any(n.startswith(f"attack request: {SRC} reached {HOST}") for n in notes)
    assert any(n.startswith(f"web shell: {HOST} holds") for n in notes)
    for link in links:
        assert link.kind is LinkKind.WORKFLOW and link.origin == "workflow:web-attacks"
        assert all(i in run.index for i in link.record_ids)
    request_link = next(link for link in links if link.note.startswith("attack request"))
    assert {e.kind.value for e in request_link.entities} == {"IP", "ENDPOINT", "URL"}


def test_every_fact_and_consideration_cites_records_of_the_run():
    run = _run(_confirmed_web_shell_lab(), (_O.HOSTNAME, HOST), (_O.IP, SRC), (_O.URL, URL))
    facts = _facts(run)
    for group in ("sources", "servers", "urls"):
        for item in facts[group]:
            assert all(i in run.index for i in item["record_ids"]), (group, item)
    for consideration in run.considered:
        assert consideration.record_ids and all(i in run.index for i in consideration.record_ids)
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)
    assert not [n for n in run.notes if n.startswith("hook ")]
