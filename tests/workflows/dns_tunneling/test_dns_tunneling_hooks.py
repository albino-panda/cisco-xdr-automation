"""dns-tunneling hooks: tunnels, clients, processes, signals, links and considerations computed from the
run's own records (simulated read-only lab; nothing state-changing is ever called)."""
from __future__ import annotations

import json
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.models import ObservableType, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS
from xdr_response.workflows.dns_tunneling import HOOKS, WORKFLOW
from xdr_response.workflows.dns_tunneling.hooks import (
    PATTERN_SEVERITY,
    is_dns_server,
    label_entropy,
    names_tunnel,
    parent_of,
    registrable_domain,
)
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

HOST = "TH-LT-1047"
GUID = "00000000-0000-4000-8000-000000001047"
PARENT = "cdn-update.test"
LABEL = "4f2a9c1e7b0d5e8a3c6f9b2d4e7a1c3f5b8d0e2a4c6f8b1d"
SHA = "d7c3a9e1" * 8
APPROVED_SHA = "2" * 64  # the repository config's approved_dns_tools example (Example DNS diagnostics)
SUITE = {"secure_endpoint": ("endpoint",), "umbrella": ("network",), "splunk": ("network",),
         "virustotal": ("intel",)}


# ------------------------------------------------------------------ helpers --
def _lab() -> Lab:
    return make_lab(SUITE)


def _endpoint(lab: Lab, host: str = HOST, *, capable: bool | None = True, guid: str | None = GUID,
              groups: tuple[str, ...] = ("Workstations",)) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host, connector_guid=guid,
              groups=list(groups), users=["jsmith@example.com"], isolation_capable=capable,
              isolation_state="not_isolated")


def _query(lab: Lab, *, host: str = HOST, process: str = "updsvc.exe", name: str = f"{LABEL}.a81c.{PARENT}",
           count: int = 18432, pid: int | None = 4242, sha: str | None = SHA, event: str = "q-1",
           minute: int = 6) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=f"{host}-{event}",
              endpoint=host, timestamp=f"2026-01-15T10:{minute:02d}:00Z", event_type="network",
              process_name=process, pid=pid, sha256=sha, domain=name, count=count)


def _end(lab: Lab, *, host: str = HOST, pid: int = 4242) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=f"{host}-end-{pid}",
              endpoint=host, timestamp="2026-01-15T11:50:00Z", event_type="process_end", process_name="updsvc.exe",
              pid=pid, sha256=SHA)


def _dns(lab: Lab, *, domain: str = PARENT, count: int = 18432, unique: int | None = 18432,
         longest: int | None = 48, query_type: str | None = "TXT", categories: tuple[str, ...] = ("DNS Tunneling VPN",),
         endpoint: str | None = HOST, subject: str = PARENT) -> None:
    lab.typed("search_domain_enterprise", subject, "splunk", kind="dns_query", endpoint=endpoint, domain=domain,
              query_type=query_type, count=count, unique_subdomains=unique, max_label_length=longest,
              categories=list(categories), action="allowed", first_seen="2026-01-15T10:06:00Z",
              last_seen="2026-01-15T11:42:00Z")


def _rate(lab: Lab, value: str = PARENT, verdict: Verdict = Verdict.MALICIOUS) -> None:
    lab.environment.set_reputation(ObservableType.DOMAIN, value, verdict,
                                   risk_score=85 if verdict is Verdict.MALICIOUS else 0, confidence=80,
                                   integrations=["virustotal", "umbrella"])


def _tunnel(lab: Lab) -> None:
    """The tp-approve-all pattern: rated parent in the tunneling category, one unknown client process."""
    _endpoint(lab)
    _query(lab)
    _dns(lab)
    _rate(lab)


def _run(lab: Lab, *observables: tuple[ObservableType, str]) -> WorkflowRun:
    obs = observables or ((ObservableType.DOMAIN, PARENT), (ObservableType.HOSTNAME, HOST))
    incident = make_incident(*obs, workflow_id="dns-tunneling", title=f"DNS tunneling from {HOST}")
    run = lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)
    assert not [n for n in run.notes if n.startswith("hook ")], run.notes  # hooks never fail on lab data
    return run


def _view(run: WorkflowRun) -> RunView:
    return RunView(workflow=WORKFLOW, incident=make_incident(workflow_id="dns-tunneling"), results=run.results,
                   index=run.index, correlation=run.correlation, blast_radius=run.blast_radius)


def _facts(run: WorkflowRun) -> dict[str, Any]:
    facts = dict(HOOKS.facts(_view(run)))
    json.dumps(facts, allow_nan=False)  # the runner requires JSON facts
    return facts


def _selectors(run: WorkflowRun) -> set[str]:
    """Recommended actions: proposed, or UNROUTED (the simulated adapters do only what the real ones do,
    so e.g. a process termination or a Secure Endpoint hash block has no executor; it is still recommended)."""
    return ({f"{p.action_type.value}:{p.target}" for p in run.proposals}
            | {o.selector for o in run.outcomes_with(RuleOutcomeStatus.UNROUTED)})


def _considered(run: WorkflowRun, *, manual: bool = False) -> set[str]:
    return {c.subject for c in run.considered if c.manual is manual}


def _keys(node: Any) -> set[str]:
    if isinstance(node, dict):
        return {str(k).lower() for k in node} | {k for v in node.values() for k in _keys(v)}
    if isinstance(node, list):
        return {k for v in node for k in _keys(v)}
    return set()


# ------------------------------------------------------------- pure helpers --
@pytest.mark.parametrize("name, expected", [
    ("a1.b2.cdn-update.test", "cdn-update.test"), ("cdn-update.test", "cdn-update.test"),
    ("x.y.example.co.uk", "example.co.uk"), ("deep.a.b.example.com.au", "example.com.au"),
    ("example.uk", "example.uk"), ("HOST.EXAMPLE.TEST.", "example.test"), ("", ""),
])
def test_registrable_domain(name, expected):
    assert registrable_domain(name) == expected


def test_parent_of_prefers_the_shortest_known_parent_and_falls_back_to_the_registrable_domain():
    known = ["cdn-update.test", "a81c.cdn-update.test", "t.example.net"]
    assert parent_of(f"{LABEL}.a81c.cdn-update.test", known) == "cdn-update.test"
    assert parent_of("q1.t.example.net", known) == "t.example.net"
    assert parent_of("img01.cdn-assets.example", known) == "cdn-assets.example"
    assert parent_of("intranet", known) is None and parent_of(None, known) is None


def test_label_entropy_separates_random_labels_from_words():
    assert label_entropy("") == 0.0
    assert label_entropy("aaaaaaaaaaaa") == 0.0
    assert label_entropy(LABEL) > 3.5
    assert label_entropy("mailserver") < 3.5
    assert label_entropy("AbAb") == label_entropy("abab") == 1.0


@pytest.mark.parametrize("name, expected", [
    ("dns.exe", True), ("C:\\Windows\\System32\\dns.exe", True), ("/usr/sbin/named", True), ("unbound", True),
    ("dnsmasq", True), ("updsvc.exe", False), ("nslookup.exe", False), ("", False), (None, False),
])
def test_is_dns_server(name, expected):
    assert is_dns_server(name) is expected


@pytest.mark.parametrize("text, expected", [
    ("Suspicious DNS tunnel detected", True), ("Behavior:DnsTunnel", True), ("dns-tunnel.generic", True),
    ("Trojan.Generic", False), ("", False), (None, False),
])
def test_names_tunnel(text, expected):
    assert names_tunnel(text) is expected


# -------------------------------------------------------------------- facts --
def test_facts_of_a_confirmed_tunnel():
    lab = _lab()
    _tunnel(lab)
    _query(lab, process="browser.exe", name="intranet.example.com", count=210, pid=2210, sha=None, event="q-2")
    run = _run(lab)
    facts = _facts(run)
    [tunnel] = facts["tunnels"]  # the browser's intranet lookup shows no tunnel indication and is left out
    assert tunnel["domain"] == PARENT and tunnel["confirmed"] and tunnel["rated"] and tunnel["malicious"]
    assert tunnel["volume"] == 18432 and tunnel["unique_subdomains"] == 18432 and tunnel["max_label_length"] == 48
    assert tunnel["entropy"] is not None and tunnel["entropy"] >= 3.5
    assert tunnel["indicators"] == ["volume", "subdomain variation", "long labels", "label entropy",
                                    "data record types"]
    assert tunnel["clients"] == [HOST] and tunnel["resolvers"] == [] and tunnel["client_hashes"] == [SHA]
    assert "reputation MALICIOUS" in tunnel["basis"] and "category DNS Tunneling VPN" in tunnel["basis"]
    assert "18432 queries" in tunnel["transfer_text"] and "per min" in tunnel["transfer_text"]
    [client] = facts["clients"]
    assert (client["hostname"], client["connector_guid"], client["isolation_capable"]) == (HOST, GUID, True)
    assert client["binaries"] == [SHA] and client["processes"] == ["updsvc.exe"]
    [process] = facts["processes"]
    assert process["target"] == f"{HOST}/4242" and process["domains"] == [PARENT]
    for fact in (tunnel, client, process):
        assert fact["record_ids"] and all(i in run.index for i in fact["record_ids"])
    assert not _keys(facts) & APPROVAL_LIKE_KEYS


def test_the_package_cites_the_run_and_scores_separately():
    lab = _lab()
    _tunnel(lab)
    run = _run(lab)
    assert _selectors(run) == {f"block_domain:{PARENT}", f"terminate_process:{HOST}/4242", f"isolate_endpoint:{HOST}"}
    for proposal in run.proposals:
        assert proposal.evidence and all(e.data["record_id"] in run.index for e in proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
        assert proposal.risk_score >= 40
    isolation = next(p for p in run.proposals if p.action_type.value == "isolate_endpoint")
    assert isolation.params.get("connector_guid") == GUID
    assert _considered(run, manual=True) == {f"remove tunnel client on {HOST}", f"assess data sent through {PARENT}"}
    assert _considered(run) == set() and run.handoffs == ()


def test_many_subdomains_give_one_tunnel_and_one_block():
    lab = _lab()
    _endpoint(lab)
    for i in range(5):
        _query(lab, name=f"{LABEL[:20 + i]}.{PARENT}", count=3000, event=f"q-{i}", minute=6 + i)
    _dns(lab)
    _rate(lab)
    run = _run(lab)
    facts = _facts(run)
    assert [t["domain"] for t in facts["tunnels"]] == [PARENT]
    assert [p for p in _selectors(run) if p.startswith("block_domain:")] == [f"block_domain:{PARENT}"]
    assert facts["tunnels"][0]["volume"] == 18432  # the largest view, never the sum of views


def test_a_clean_rated_parent_is_never_blocked_and_is_shown():
    lab = _lab()
    _tunnel(lab)
    _rate(lab, verdict=Verdict.CLEAN)
    run = _run(lab)
    facts = _facts(run)
    assert not facts["tunnels"][0]["confirmed"] and facts["clients"] == [] and facts["processes"] == []
    assert run.proposals == () and not run.outcomes
    assert _considered(run) == {f"block_domain:{PARENT}"}
    assert "rated CLEAN" in next(c.reason for c in run.considered)


def test_the_legacy_rule_category_and_volume_confirms_an_unrated_parent_but_low_volume_does_not():
    lab = _lab()
    _endpoint(lab)
    _query(lab, name=f"3a7f.{PARENT}", count=1200, sha=None, pid=None)
    _dns(lab, count=1200, unique=None, longest=None, query_type=None)
    run = _run(lab)
    tunnel = _facts(run)["tunnels"][0]
    assert tunnel["confirmed"] and not tunnel["rated"] and tunnel["pattern"]
    assert f"block_domain:{PARENT}" in _selectors(run)

    lab = _lab()
    _endpoint(lab)
    _query(lab, name=f"hc.{PARENT}", count=40, sha=None, pid=None)
    _dns(lab, count=40, unique=None, longest=None, query_type=None)
    run = _run(lab)
    assert not _facts(run)["tunnels"][0]["confirmed"]
    assert run.proposals == () and _considered(run) == {f"block_domain:{PARENT}"}


def test_the_tunneling_category_from_reputation_confirms_the_parent_and_is_cited():
    """The real-adapter path (14.12.3): Umbrella reports the category on its enrichment answer, not on DNS rows."""
    lab = _lab()
    _endpoint(lab)
    _query(lab, name=f"3a7f.{PARENT}", count=1200, sha=None, pid=None)
    _dns(lab, count=1200, unique=None, longest=None, query_type=None, categories=())
    lab.environment.set_reputation(ObservableType.DOMAIN, PARENT, Verdict.UNKNOWN, integrations=["umbrella"],
                                   categories=["DNS Tunneling VPN"])
    run = _run(lab)
    tunnel = _facts(run)["tunnels"][0]
    assert tunnel["confirmed"] and tunnel["tunnel_category"] and not tunnel["rated"]
    block = next(p for p in run.proposals if p.action_type.value == "block_domain")
    assert "enrichment" in {e.data["kind"] for e in block.evidence}  # the categorizing answer is cited


def test_a_behaviour_profile_confirms_a_parent_without_reputation_or_category():
    lab = _lab()
    _endpoint(lab)
    _query(lab)
    _dns(lab, count=3100, unique=2400, longest=57, categories=())
    run = _run(lab)
    tunnel = _facts(run)["tunnels"][0]
    assert tunnel["confirmed"] and tunnel["pattern"] and not tunnel["tunnel_category"]
    assert tunnel["indicator_count"] == 5
    assert _selectors(run) == {f"block_domain:{PARENT}", f"terminate_process:{HOST}/4242", f"isolate_endpoint:{HOST}"}


def test_two_indicators_are_not_a_tunnel():
    lab = _lab()
    _endpoint(lab)
    _query(lab, process="browser.exe", name=f"img01.{PARENT}", count=5200, sha=None)
    _dns(lab, count=5200, unique=640, longest=8, query_type="A", categories=())
    run = _run(lab)
    tunnel = _facts(run)["tunnels"][0]
    assert tunnel["indicators"] == ["volume", "subdomain variation"] and not tunnel["confirmed"]
    assert run.proposals == () and _considered(run) == {f"block_domain:{PARENT}"}


def test_a_suspicious_rating_alone_is_not_a_tunnel():
    lab = _lab()
    _endpoint(lab)
    _query(lab, name=f"a.{PARENT}", count=20)
    _rate(lab, verdict=Verdict.SUSPICIOUS)
    run = _run(lab)
    assert not _facts(run)["tunnels"][0]["confirmed"]
    assert run.proposals == () and _considered(run) == {f"block_domain:{PARENT}"}


def test_a_tunneling_detection_tied_to_the_querying_process_confirms_the_parent():
    lab = _lab()
    _endpoint(lab)
    _query(lab, name=f"a1.{PARENT}", count=50)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="detection", detection_id="det-dns-1",
              name="Behavior:DnsTunnel.A", verdict="SUSPICIOUS", severity="HIGH", endpoint=HOST, sha256=SHA,
              process_name="updsvc.exe", mitre_techniques=["T1071.004"], status="active")
    run = _run(lab)
    tunnel = _facts(run)["tunnels"][0]
    assert tunnel["confirmed"] and tunnel["detections"] == ["Behavior:DnsTunnel.A"]
    assert {f"block_domain:{PARENT}", f"isolate_endpoint:{HOST}"} <= _selectors(run)


def test_a_detection_on_another_process_does_not_tie():
    lab = _lab()
    _endpoint(lab)
    _query(lab, name=f"a1.{PARENT}", count=50)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="detection", detection_id="det-dns-2",
              name="Behavior:DnsTunnel.A", verdict="SUSPICIOUS", severity="HIGH", endpoint=HOST,
              sha256="0" * 63 + "1", process_name="other.exe", mitre_techniques=["T1572"], status="active")
    run = _run(lab)
    assert not _facts(run)["tunnels"][0]["confirmed"] and run.proposals == ()


def test_a_forwarding_resolver_is_never_isolated_or_terminated():
    lab = _lab()
    _endpoint(lab, "NS-02", groups=("DNS Servers",))
    _query(lab, host="NS-02", process="dns.exe", pid=1880, sha=None)
    _dns(lab, endpoint="NS-02")
    _rate(lab)
    run = _run(lab, (ObservableType.DOMAIN, PARENT), (ObservableType.HOSTNAME, "NS-02"))
    facts = _facts(run)
    assert facts["clients"] == [] and facts["processes"] == [] and facts["tunnels"][0]["resolvers"] == ["NS-02"]
    assert _selectors(run) == {f"block_domain:{PARENT}"}
    assert _considered(run) == {"isolate_endpoint:NS-02"}
    assert _considered(run, manual=True) == {f"assess data sent through {PARENT}", "find the client behind NS-02"}


def test_the_client_behind_the_resolver_comes_from_the_resolver_log():
    lab = _lab()
    _endpoint(lab, "NS-02", groups=("DNS Servers",))
    _query(lab, host="NS-02", process="dns.exe", pid=1880, sha=None)
    _dns(lab, endpoint="NS-02")
    _dns(lab, domain=f"7d1e44c0.{PARENT}", count=6400, unique=None, longest=None, endpoint="WS-0217")
    _endpoint(lab, "WS-0217", guid="00000000-0000-4000-8000-000000000217")
    _query(lab, host="WS-0217", process="svc-helper.exe", name=f"7d1e44c0.{PARENT}", count=6400, pid=None, sha=None)
    _rate(lab)
    run = _run(lab, (ObservableType.DOMAIN, PARENT), (ObservableType.HOSTNAME, "NS-02"))
    assert _selectors(run) == {f"block_domain:{PARENT}", "isolate_endpoint:WS-0217"}
    assert _considered(run) == {"isolate_endpoint:NS-02"}
    assert "find the client behind NS-02" not in _considered(run, manual=True)
    assert _facts(run)["tunnels"][0]["volume"] == 18432  # resolver aggregate and client rows are one traffic


def test_endpoints_that_cannot_be_isolated_or_are_seen_only_in_dns_logs_are_considered():
    lab = _lab()
    _tunnel(lab)
    _endpoint(lab, "KIOSK-07", capable=False, guid="00000000-0000-4000-8000-0000000000c7")
    _query(lab, host="KIOSK-07", process="svc-helper.exe", name=f"e04d.{PARENT}", count=200, pid=None, sha=None)
    _endpoint(lab, "TH-LT-1099", guid=None)
    _query(lab, host="TH-LT-1099", process="svc-helper.exe", name=f"e05d.{PARENT}", count=200, pid=None, sha=None)
    _dns(lab, domain=f"e06d.{PARENT}", count=90, unique=None, longest=None, endpoint="TH-LT-1200")
    run = _run(lab, (ObservableType.DOMAIN, PARENT), (ObservableType.HOSTNAME, HOST),
               (ObservableType.HOSTNAME, "KIOSK-07"), (ObservableType.HOSTNAME, "TH-LT-1099"))
    assert _considered(run) == {"isolate_endpoint:KIOSK-07", "isolate_endpoint:TH-LT-1099",
                                "isolate_endpoint:TH-LT-1200"}
    selectors = _selectors(run)
    assert f"isolate_endpoint:{HOST}" in selectors
    assert not {"isolate_endpoint:KIOSK-07", "isolate_endpoint:TH-LT-1099", "isolate_endpoint:TH-LT-1200"} & selectors


def test_an_ended_process_is_not_terminated_but_the_client_is_isolated():
    lab = _lab()
    _tunnel(lab)
    _end(lab)
    run = _run(lab)
    assert _facts(run)["processes"] == []
    assert _selectors(run) == {f"block_domain:{PARENT}", f"isolate_endpoint:{HOST}"}


def test_an_approved_dns_tool_is_withheld_by_the_framework_and_shown():
    lab = _lab()
    _endpoint(lab, "TH-LT-2050", guid="00000000-0000-4000-8000-000000002050")
    _query(lab, host="TH-LT-2050", process="dnsdiag.exe", name=f"{LABEL}.probe.{PARENT}", pid=5120, sha=APPROVED_SHA)
    _dns(lab, endpoint=None)
    run = _run(lab, (ObservableType.DOMAIN, PARENT), (ObservableType.HOSTNAME, "TH-LT-2050"))
    statuses = {(o.rule_id, o.status) for o in run.outcomes}
    assert ("terminate_tunnel_process", RuleOutcomeStatus.ALLOWLISTED) in statuses
    assert ("isolate_tunnel_client_secure_endpoint", RuleOutcomeStatus.ALLOWLISTED) in statuses
    assert ("block_tunnel_parent_domain", RuleOutcomeStatus.ALLOWLISTED) in statuses  # unrated: rests on the tool
    assert run.proposals == ()
    assert _considered(run) >= {"terminate_process:TH-LT-2050/5120", "isolate_endpoint:TH-LT-2050",
                                f"block_domain:{PARENT}"}


def test_a_rated_parent_is_blocked_even_when_only_an_approved_tool_queried_it():
    lab = _lab()
    _endpoint(lab, "TH-LT-2050", guid="00000000-0000-4000-8000-000000002050")
    _query(lab, host="TH-LT-2050", process="dnsdiag.exe", name=f"{LABEL}.probe.{PARENT}", pid=5120, sha=APPROVED_SHA)
    _dns(lab, endpoint=None)
    _rate(lab)
    run = _run(lab, (ObservableType.DOMAIN, PARENT), (ObservableType.HOSTNAME, "TH-LT-2050"))
    assert _selectors(run) == {f"block_domain:{PARENT}"}


def test_a_hashless_process_is_never_treated_as_approved():
    lab = _lab()
    _endpoint(lab)
    _query(lab, process="dnsdiag.exe", sha=None)
    _dns(lab)
    run = _run(lab)
    assert _facts(run)["clients"][0]["binaries"] == ["name:dnsdiag.exe"]
    assert _selectors(run) == {f"block_domain:{PARENT}", f"terminate_process:{HOST}/4242", f"isolate_endpoint:{HOST}"}


# ------------------------------------------------------------ signals, links --
def test_pattern_signals_cite_their_records_and_are_attributed_to_their_source():
    lab = _lab()
    _tunnel(lab)
    run = _run(lab)
    signals = list(HOOKS.derive_signals(_view(run)))
    assert signals
    by_subject: dict[tuple[str, str], set[str]] = {}
    for signal in signals:
        assert signal.origin == "workflow:dns-tunneling" and signal.category is SignalCategory.NETWORK_BEHAVIOUR
        assert signal.verdict is Verdict.SUSPICIOUS and signal.severity == PATTERN_SEVERITY
        cited = run.index.require(signal.record_ids)
        assert {r.integration for r in cited} == {signal.integration}
        by_subject.setdefault((signal.observable.type.value, signal.observable.value), set()).add(signal.integration)
    assert by_subject[("domain", PARENT)] == {"splunk", "secure_endpoint"}
    assert by_subject[("hostname", HOST)] == {"secure_endpoint"}
    assert by_subject[("process", f"{HOST}/4242")] == {"secure_endpoint"}
    assert not [n for n in run.notes if "signal ignored" in n]


def test_no_pattern_signal_without_a_confirmed_tunnel():
    lab = _lab()
    _tunnel(lab)
    _rate(lab, verdict=Verdict.CLEAN)
    run = _run(lab)
    assert list(HOOKS.derive_signals(_view(run))) == []


def test_client_links_join_endpoint_binary_and_parent():
    lab = _lab()
    _tunnel(lab)
    run = _run(lab)
    links = [link for link in run.correlation.links if link.kind is LinkKind.WORKFLOW]
    assert len(links) == 1
    [link] = links
    assert {(e.kind.value, e.value) for e in link.entities} == {("ENDPOINT", HOST), ("DOMAIN", PARENT), ("HASH", SHA)}
    assert link.origin == "workflow:dns-tunneling" and all(i in run.index for i in link.record_ids)


def test_hooks_never_fail_on_an_empty_run():
    lab = _lab()
    run = _run(lab)
    assert _facts(run) == {"tunnels": [], "clients": [], "processes": []}
    assert run.proposals == () and run.considered == ()
