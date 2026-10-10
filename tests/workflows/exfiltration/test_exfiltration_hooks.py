"""exfiltration hooks: destinations, sources, actors, signals, links, considerations and hand-offs computed
from the run's own records (simulated read-only lab; nothing state-changing is ever called)."""
from __future__ import annotations

import json
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.atomics.records import DetectionRecord
from xdr_response.models import Incident, ObservableType, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS
from xdr_response.workflows.exfiltration import HOOKS, WORKFLOW
from xdr_response.workflows.exfiltration.definition import LARGE_TRANSFER_BYTES
from xdr_response.workflows.exfiltration.hooks import (
    format_bytes,
    is_archive,
    names_exfiltration,
    names_insider,
    public_ipv4,
)
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

HOST = "TH-LT-1047"
USER = "jsmith@example.com"
GUID = "00000000-0000-4000-8000-000000001047"
DROP = "files-drop.test"
DROP_IP = "203.0.113.145"
GIB = 1024 ** 3
SUITE = {"secure_endpoint": ("endpoint",), "umbrella": ("network",), "meraki": ("network",),
         "virustotal": ("intel",), "entra": ("identity",), "microsoft_cloud": ("network",)}


def _lab(suite: dict[str, tuple[str, ...]] | None = None) -> Lab:
    return make_lab(suite or SUITE)


def _endpoint(lab: Lab, host: str = HOST, *, user: str = USER, **extra: Any) -> None:
    fields = {"connector_guid": GUID, "groups": ["Finance Workstations"], "users": [user], "isolation_capable": True,
              "isolation_state": "not_isolated", **extra}
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host, **fields)


def _upload(lab: Lab, *, host: str = HOST, user: str | None = USER, domain: str | None = DROP,
            ip: str | None = DROP_IP, size: int = 4 * GIB, last: str = "2026-01-15T11:52:00Z",
            direction: str = "outbound", action: str = "allowed", verdict: str = "UNKNOWN", port: int = 443,
            integration: str = "secure_endpoint") -> None:
    lab.typed("investigate_endpoint", host, integration, kind="network_connection", endpoint=host, user=user,
              domain=domain, remote_ip=ip, remote_port=port, protocol="tcp", direction=direction,
              process_name="browser.exe", bytes_out=size, count=10, action=action, verdict=verdict,
              first_seen="2026-01-15T10:02:00Z", last_seen=last)


def _dns(lab: Lab, domain: str = DROP, *, host: str = HOST, categories: tuple[str, ...] = ("Newly Seen Domains",),
         **extra: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="dns_query", endpoint=host, domain=domain,
              query_type="A", count=4, categories=list(categories), action="allowed",
              first_seen="2026-01-15T10:01:00Z", **extra)


def _archive(lab: Lab, *, host: str = HOST, at: str = "2026-01-15T09:58:00Z") -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=f"evt-zip-{host}",
              endpoint=host, timestamp=at, event_type="file_create", process_name="archiver.exe",
              file_path="C:\\Users\\jsmith\\AppData\\Local\\Temp\\q4-invoices.zip", user=USER)


def _profile(lab: Lab, user: str = USER, *, risk: str = "high", groups: tuple[str, ...] = ("Finance",)) -> None:
    lab.typed("investigate_user", user, "entra", kind="user_profile", user=user, groups=list(groups),
              risk_level=risk, risk_state="at_risk" if risk in ("medium", "high") else "none", account_enabled=True)


def _anomaly(lab: Lab, user: str = USER, *, severity: str = "MEDIUM", kind: str = "unfamiliar_location") -> None:
    lab.typed("investigate_user", user, "entra", kind="anomaly", anomaly_id=f"an-{user}-{kind}", anomaly_type=kind,
              severity=severity, user=user, ip="198.51.100.77", first_seen="2026-01-15T09:40:00Z")


def _detection(lab: Lab, *, name: str, category: str, verdict: str = "SUSPICIOUS", user: str | None = USER,
               host: str = HOST, techniques: tuple[str, ...] = (), integration: str = "secure_endpoint",
               status: str = "active") -> None:
    lab.typed("investigate_endpoint", host, integration, kind="detection", detection_id=f"det-{name}-{user}",
              name=name, category=category, verdict=verdict, severity="HIGH", endpoint=host, user=user,
              mitre_techniques=list(techniques), status=status, first_seen="2026-01-15T11:00:00Z")


def _reach(lab: Lab, value: str, hosts: int, *, kind: str = "ip") -> None:
    atomic = "search_ip_enterprise" if kind == "ip" else "search_domain_enterprise"
    for n in range(hosts):
        record: dict[str, Any] = {"kind": "network_connection", "endpoint": f"TH-WS-{2000 + n}",
                                  "remote_port": 443, "direction": "outbound", "action": "allowed",
                                  "first_seen": "2026-01-15T08:00:00Z"}
        record["remote_ip" if kind == "ip" else "domain"] = value
        lab.typed(atomic, value, "microsoft_cloud", **record)


def _rate(lab: Lab, otype: ObservableType, value: str, verdict: Verdict = Verdict.MALICIOUS) -> None:
    lab.environment.set_reputation(otype, value, verdict, risk_score=85 if verdict is Verdict.MALICIOUS else 0,
                                   confidence=80, integrations=["umbrella", "virustotal"])


def _incident(*observables: tuple[ObservableType, str], users: tuple[str, ...] = (USER,)) -> Incident:
    return make_incident(*(observables or ((ObservableType.HOSTNAME, HOST),)), workflow_id="exfiltration",
                         title=f"Large outbound transfer from {HOST}", users=users)


def _run(lab: Lab, *observables: tuple[ObservableType, str], users: tuple[str, ...] = (USER,)) -> WorkflowRun:
    run = lab.runner.run(WORKFLOW, HOOKS, _incident(*observables, users=users), dry_run=True)
    assert not [n for n in run.notes if n.startswith("hook ")], run.notes  # hooks never fail on lab data
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)
    return run


def _view(run: WorkflowRun, *observables: tuple[ObservableType, str], users: tuple[str, ...] = (USER,)) -> RunView:
    return RunView(workflow=WORKFLOW, incident=_incident(*observables, users=users), results=run.results,
                   index=run.index, correlation=run.correlation, blast_radius=run.blast_radius)


def _facts(run: WorkflowRun, *observables: tuple[ObservableType, str],
           users: tuple[str, ...] = (USER,)) -> dict[str, Any]:
    facts = dict(HOOKS.facts(_view(run, *observables, users=users)))
    json.dumps(facts, allow_nan=False)  # the runner requires JSON facts
    return facts


def _destinations(facts: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(d["type"], d["value"]): d for d in facts["destinations"]}


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


def _compromised_upload(lab: Lab) -> None:
    _endpoint(lab)
    _archive(lab)
    _upload(lab)
    _dns(lab)
    _profile(lab)
    _anomaly(lab)


# ------------------------------------------------------------------ helpers --
def test_helpers():
    assert format_bytes(0) == "0 bytes" and format_bytes(512) == "512 bytes"
    assert format_bytes(4831838208) == "4.5 GiB" and format_bytes(LARGE_TRANSFER_BYTES) == "100.0 MiB"
    assert public_ipv4("203.0.113.145") == "203.0.113.145"
    assert public_ipv4("10.20.30.40") is None and public_ipv4("::ffff:10.0.0.1") is None
    assert public_ipv4("2001:db8::1") is None and public_ipv4("files-drop.test") is None and public_ipv4(None) is None
    assert is_archive("C:\\Temp\\export.7z") and is_archive("/tmp/out.TAR.GZ") and not is_archive("report.docx")
    base = {"record_id": None, "integration": "secure_endpoint", "atomic": "investigate_endpoint",
            "subject": {"type": "hostname", "value": HOST}, "verdict": "SUSPICIOUS", "severity": "HIGH",
            "endpoint": HOST}
    by_technique = DetectionRecord.model_validate({**base, "name": "Generic alert", "mitre_techniques": ["T1048.003"]})
    by_word = DetectionRecord.model_validate({**base, "name": "Possible data exfiltration", "category": "Network"})
    insider = DetectionRecord.model_validate({**base, "name": "Departing user activity", "category": "InsiderRisk"})
    other = DetectionRecord.model_validate({**base, "name": "Trojan.Generic", "mitre_techniques": ["T1204.002"]})
    assert names_exfiltration(by_technique) and names_exfiltration(by_word) and not names_exfiltration(other)
    assert names_insider(insider) and not names_insider(by_word)


# ------------------------------------------------------------------- facts --
def test_facts_of_a_compromised_account_uploading_to_an_unknown_drop():
    lab = _lab()
    _compromised_upload(lab)
    run = _run(lab)
    facts = _facts(run)
    destinations = _destinations(facts)
    domain, ip = destinations[("domain", DROP)], destinations[("ip", DROP_IP)]
    for fact in (domain, ip):
        assert fact["upload"] and fact["large"] and fact["ongoing"] and fact["blockable"]
        assert not fact["rated"] and not fact["clean"] and fact["prevalence"] == 1 and not fact["shared"]
        assert fact["volume_text"] == "4.0 GiB" and fact["sources"] == [HOST] and fact["users"] == [USER]
    assert domain["new"] and "newly seen" in domain["basis"] and not ip["new"]
    [source] = facts["sources"]
    assert source["hostname"] == HOST and source["ongoing"] and source["exfil"] and source["isolate"]
    assert source["staging"] and f"account {USER} compromised" in source["basis"]
    assert source["connector_guid"] == GUID and source["volume_text"] == "4.0 GiB"
    [actor] = facts["actors"]
    assert actor["user"] == USER and actor["compromised"] and not actor["insider"]
    assert "identity risk high" in actor["basis"] and actor["transfer_text"] == f"4.0 GiB to {DROP_IP}, {DROP}"
    for fact in (domain, ip, source, actor):
        assert fact["record_ids"] and all(i in run.index for i in fact["record_ids"])
    assert not _keys(facts) & APPROVAL_LIKE_KEYS


def test_the_full_package_is_proposed_with_evidence_from_the_run():
    lab = _lab()
    _compromised_upload(lab)
    run = _run(lab)
    assert _selectors(run) == {f"block_domain:{DROP}", f"block_ip:{DROP_IP}", f"isolate_endpoint:{HOST}",
                               f"revoke_sessions:{USER}", f"disable_user:{USER}"}
    for proposal in run.proposals:
        assert proposal.evidence and all(e.data["record_id"] in run.index for e in proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
        assert proposal.risk_score >= 40
    isolation = next(p for p in run.proposals if p.action_type.value == "isolate_endpoint")
    assert isolation.params.get("connector_guid") == GUID
    kinds = {e.data["kind"] for e in isolation.evidence}
    assert {"network_connection", "process_event", "user_profile", "endpoint"} <= kinds  # staging is cited
    assert _considered(run) == set()
    assert _considered(run, manual=True) == {f"assess data exposure from {HOST}"}
    [handoff] = run.handoffs
    assert handoff.workflow_id == "account-takeover" and handoff.subjects == (USER,)
    assert all(i in run.index for i in handoff.record_ids)


def test_transfer_signals_are_attributed_to_the_source_of_the_cited_records():
    lab = _lab()
    _compromised_upload(lab)
    run = _run(lab)
    assert run.signals
    for signal in run.signals:
        assert signal.origin == "workflow:exfiltration" and signal.category is SignalCategory.NETWORK_BEHAVIOUR
        assert signal.verdict is Verdict.SUSPICIOUS and signal.integration == "secure_endpoint"
        assert all(run.index.get(i).integration == "secure_endpoint" for i in signal.record_ids)
    observed = {(s.observable.type, s.observable.value) for s in run.signals}
    assert observed == {(ObservableType.DOMAIN, DROP), (ObservableType.IP, DROP_IP),
                        (ObservableType.HOSTNAME, HOST), (ObservableType.USER, USER)}


def test_transfer_and_staging_links_cite_their_records():
    lab = _lab()
    _compromised_upload(lab)
    run = _run(lab)
    links = [l for l in run.correlation.links if l.kind is LinkKind.WORKFLOW]
    notes = {l.note.split(":", 1)[0] for l in links}
    assert notes == {"transfer", "staging"}
    for link in links:
        assert link.origin == "workflow:exfiltration" and all(i in run.index for i in link.record_ids)


# ------------------------------------------------------------- destinations --
def test_a_clean_destination_is_never_blocked_but_shown_as_considered():
    lab = _lab()
    _endpoint(lab)
    _upload(lab, domain="vault.backup-service.test", ip=None)
    _rate(lab, ObservableType.DOMAIN, "vault.backup-service.test", Verdict.CLEAN)
    _profile(lab, risk="none")
    run = _run(lab)
    [fact] = _facts(run)["destinations"]
    assert fact["clean"] and not fact["blockable"]
    assert run.proposals == ()
    assert _considered(run) == {"block_domain:vault.backup-service.test"}
    assert _considered(run, manual=True) == set()  # nothing points at exfiltration


def test_a_small_unrated_upload_is_not_a_block_candidate():
    lab = _lab()
    _endpoint(lab)
    _upload(lab, domain="api.partner.test", ip=None, size=2 * 1024 * 1024)
    _profile(lab, risk="none")
    run = _run(lab)
    [fact] = _facts(run)["destinations"]
    assert not fact["large"] and not fact["blockable"]
    assert run.proposals == ()


@pytest.mark.parametrize("categories", [("Online Storage and Backup",), ("File Transfer Services",),
                                        ("Newly Seen Domains",)])
def test_a_small_upload_to_new_or_storage_destinations_is_a_block_candidate(categories: tuple[str, ...]):
    lab = _lab()
    _endpoint(lab)
    _upload(lab, domain="drop.storage.test", ip=None, size=2 * 1024 * 1024)
    _dns(lab, "drop.storage.test", categories=categories)
    _profile(lab, risk="none")
    run = _run(lab)
    assert _selectors(run) == {"block_domain:drop.storage.test"}
    proposal = run.proposals[0]
    assert "dns_query" in {e.data["kind"] for e in proposal.evidence}  # the categorizing record is cited


@pytest.mark.parametrize("categories, first_seen", [(("Online Storage and Backup",), None),
                                                    ((), "2026-01-10T08:00:00+00:00")])
def test_vendor_categories_and_first_seen_from_enrichment_make_a_block_candidate_and_are_cited(
        categories: tuple[str, ...], first_seen: str | None):
    """The real-adapter path (14.12.3): the category or first-seen time comes from the enrichment record."""
    lab = _lab()
    _endpoint(lab)
    _upload(lab, domain="drop.storage.test", ip=None, size=2 * 1024 * 1024)
    lab.environment.set_reputation(ObservableType.DOMAIN, "drop.storage.test", Verdict.UNKNOWN,
                                   integrations=["umbrella"], categories=categories, first_seen=first_seen)
    _profile(lab, risk="none")
    run = _run(lab)
    [fact] = _facts(run)["destinations"]
    assert not fact["rated"] and (fact["cloud_storage"] or fact["new"])
    assert _selectors(run) == {"block_domain:drop.storage.test"}
    kinds = {e.data["kind"] for e in run.proposals[0].evidence}
    assert "enrichment" in kinds  # the record that reported the category or first-seen time is cited


def test_a_shared_destination_is_not_blocked_unless_reputation_rates_the_domain():
    lab = _lab()
    _endpoint(lab)
    _upload(lab, domain="cdn.shared.test", ip="198.51.100.200")
    _reach(lab, "198.51.100.200", 4)
    _reach(lab, "cdn.shared.test", 4, kind="domain")
    _profile(lab, risk="none")
    run = _run(lab)
    destinations = _destinations(_facts(run))
    assert destinations[("ip", "198.51.100.200")]["prevalence"] == 5 and destinations[("ip", "198.51.100.200")]["shared"]
    assert run.proposals == ()
    assert _considered(run) >= {"block_ip:198.51.100.200", "block_domain:cdn.shared.test"}
    reach = next(c for c in run.considered if c.subject == "block_ip:198.51.100.200")
    assert len(reach.record_ids) == 5  # the transfer and the four enterprise-search sightings

    rated = _lab()
    _endpoint(rated)
    _upload(rated, domain="cdn.shared.test", ip="198.51.100.200")
    _reach(rated, "198.51.100.200", 4)
    _reach(rated, "cdn.shared.test", 4, kind="domain")
    _rate(rated, ObservableType.DOMAIN, "cdn.shared.test")
    _rate(rated, ObservableType.IP, "198.51.100.200")
    _profile(rated, risk="none")
    run = _run(rated)
    # a rated shared IP stays unblocked; the rated domain also makes the running transfer exfiltration
    assert _selectors(run) == {"block_domain:cdn.shared.test", f"isolate_endpoint:{HOST}"}
    assert "block_ip:198.51.100.200" in _considered(run)


def test_an_internal_relay_is_never_a_destination_but_is_shown():
    lab = _lab()
    _endpoint(lab)
    _upload(lab, domain=None, ip="192.0.2.40", direction="internal")
    _upload(lab, domain=None, ip="10.20.30.40")
    _profile(lab)
    _anomaly(lab)
    run = _run(lab)
    assert _facts(run)["destinations"] == []
    assert _considered(run) == {"block_ip:192.0.2.40", "block_ip:10.20.30.40"}
    assert not any(p.action_type.value == "block_ip" for p in run.proposals)


def test_blocked_connections_are_not_transfers():
    lab = _lab()
    _endpoint(lab)
    _upload(lab, action="blocked")
    _profile(lab, risk="none")
    run = _run(lab)
    assert not any(d["upload"] for d in _facts(run)["destinations"])
    assert run.proposals == () and run.signals == ()


@pytest.mark.parametrize("subdomains, label, abnormal", [(49, 30, False), (50, None, True), (None, 40, True),
                                                         (10, 39, False)])
def test_abnormal_dns_thresholds(subdomains: int | None, label: int | None, abnormal: bool):
    lab = _lab()
    _endpoint(lab)
    _dns(lab, "sync-telemetry.test", categories=(), unique_subdomains=subdomains, max_label_length=label,
         last_seen="2026-01-15T11:58:00Z")
    _profile(lab, risk="none")
    run = _run(lab)
    destinations = _destinations(_facts(run))
    if abnormal:
        assert destinations[("domain", "sync-telemetry.test")]["abnormal_dns"]
        assert _selectors(run) == {"block_domain:sync-telemetry.test"}
        assert _considered(run) == {f"isolate_endpoint:{HOST}"}
    else:
        assert ("domain", "sync-telemetry.test") not in destinations
        assert run.proposals == ()


# ------------------------------------------------------------------ sources --
def test_a_finished_transfer_blocks_the_rated_destination_but_does_not_isolate():
    lab = _lab()
    _endpoint(lab)
    _upload(lab, last="2026-01-15T00:05:00Z")
    _rate(lab, ObservableType.DOMAIN, DROP)
    _profile(lab, risk="low")
    run = _run(lab)
    [source] = _facts(run)["sources"]
    assert source["exfil"] and not source["ongoing"] and not source["isolate"]
    assert _selectors(run) == {f"block_domain:{DROP}", f"block_ip:{DROP_IP}"}
    assert _considered(run) == {f"isolate_endpoint:{HOST}"}
    assert run.handoffs == ()


def test_ongoing_window_is_thirty_minutes_before_the_incident():
    for last, ongoing in (("2026-01-15T11:30:00Z", True), ("2026-01-15T11:29:00Z", False)):
        lab = _lab()
        _endpoint(lab)
        _upload(lab, last=last)
        _rate(lab, ObservableType.DOMAIN, DROP)
        _profile(lab, risk="none")
        run = _run(lab)
        [source] = _facts(run)["sources"]
        assert source["ongoing"] is ongoing
        assert (f"isolate_endpoint:{HOST}" in _selectors(run)) is ongoing


def test_an_ongoing_unrated_transfer_without_evidence_is_not_isolated():
    lab = _lab()
    _endpoint(lab)
    _upload(lab)
    _profile(lab, risk="none")
    run = _run(lab)
    assert _selectors(run) == {f"block_domain:{DROP}", f"block_ip:{DROP_IP}"}
    assert _considered(run) == {f"isolate_endpoint:{HOST}"}


def test_an_exfiltration_detection_isolates_the_running_source():
    lab = _lab()
    _endpoint(lab)
    _upload(lab)
    _detection(lab, name="Suspicious large upload", category="Exfiltration", techniques=("T1567.002",))
    _profile(lab, risk="none")
    run = _run(lab)
    assert f"isolate_endpoint:{HOST}" in _selectors(run)
    isolation = next(p for p in run.proposals if p.action_type.value == "isolate_endpoint")
    assert "detection" in {e.data["kind"] for e in isolation.evidence}

    resolved = _lab()
    _endpoint(resolved)
    _upload(resolved)
    _detection(resolved, name="Suspicious large upload", category="Exfiltration", status="resolved")
    _profile(resolved, risk="none")
    assert f"isolate_endpoint:{HOST}" not in _selectors(_run(resolved))


def test_a_source_without_an_isolation_capable_record_is_shown():
    lab = _lab()
    _endpoint(lab, connector_guid=None, isolation_capable=False)
    _upload(lab)
    _rate(lab, ObservableType.DOMAIN, DROP)
    _profile(lab, risk="none")
    run = _run(lab)
    assert f"isolate_endpoint:{HOST}" not in _selectors(run)
    assert f"isolate_endpoint:{HOST}" in _considered(run)


def test_a_defender_managed_source_is_isolated_through_defender_only():
    suite = {**SUITE, "defender_endpoint": ("endpoint",)}
    lab = _lab(suite)
    lab.typed("investigate_endpoint", HOST, "defender_endpoint", kind="endpoint", hostname=HOST,
              mde_machine_id="1047aa00bb11cc22dd33ee44ff5566778899aabb", users=[USER], isolation_capable=True)
    _upload(lab, integration="defender_endpoint")
    _rate(lab, ObservableType.DOMAIN, DROP)
    _profile(lab, risk="none")
    run = _run(lab)
    statuses = {o.rule_id: o.status for o in run.outcomes}
    assert statuses["isolate_source_defender_endpoint"] is RuleOutcomeStatus.PROPOSED
    assert "isolate_source_secure_endpoint" not in statuses  # no connector: the rule's `when` is false
    isolation = next(p for p in run.proposals if p.action_type.value == "isolate_endpoint")
    assert isolation.params["integration"] == "defender_endpoint"


# ------------------------------------------------------------------- actors --
@pytest.mark.parametrize("risk, anomaly, compromised", [
    ("high", None, True), ("medium", "MEDIUM", True), ("medium", None, False), ("low", "HIGH", True),
    ("low", "MEDIUM", False), ("none", None, False)])
def test_compromise_assessment(risk: str, anomaly: str | None, compromised: bool):
    lab = _lab()
    _endpoint(lab)
    _upload(lab)
    _profile(lab, risk=risk)
    if anomaly:
        _anomaly(lab, severity=anomaly)
    run = _run(lab)
    [actor] = _facts(run)["actors"]
    assert actor["compromised"] is compromised
    selectors = _selectors(run)
    assert (f"disable_user:{USER}" in selectors) is compromised
    assert (f"revoke_sessions:{USER}" in selectors) is compromised
    assert bool(run.handoffs) is compromised


def test_an_insider_decision_never_spreads_to_other_accounts():
    lab = _lab()
    _endpoint(lab, user="a.khan@example.com")
    _upload(lab, user="a.khan@example.com", last="2026-01-14T18:10:00Z")
    _rate(lab, ObservableType.DOMAIN, DROP, Verdict.CLEAN)
    _rate(lab, ObservableType.IP, DROP_IP, Verdict.CLEAN)
    _detection(lab, name="Insider risk: data theft by departing user", category="InsiderRisk",
               user="a.khan@example.com")
    _profile(lab, "a.khan@example.com", risk="none")
    _profile(lab, "b.ortiz@example.com", risk="none")
    run = _run(lab, (ObservableType.HOSTNAME, HOST), users=("a.khan@example.com", "b.ortiz@example.com"))
    assert _selectors(run) == {"revoke_sessions:a.khan@example.com", "disable_user:a.khan@example.com"}
    statuses = {o.rule_id: o.status for o in run.outcomes}
    assert statuses["disable_insider_actor"] is RuleOutcomeStatus.PROPOSED
    assert "disable_compromised_actor" not in statuses
    assert run.handoffs == ()  # insider risk is not an account compromise
    assert _considered(run) == {f"block_domain:{DROP}", f"block_ip:{DROP_IP}", f"isolate_endpoint:{HOST}"}


def test_an_unassessed_account_is_shown_and_never_guessed():
    lab = _lab()
    _endpoint(lab)
    _upload(lab)
    lab.environment.inject("UNAVAILABLE", integration="entra", operation="investigate", times=10)
    run = _run(lab)
    assert run.degraded_sources() == ("entra",)
    assert _selectors(run) == {f"block_domain:{DROP}", f"block_ip:{DROP_IP}"}
    assert _considered(run) == {f"isolate_endpoint:{HOST}", f"revoke_sessions:{USER}", f"disable_user:{USER}"}
    isolation = next(c for c in run.considered if c.subject == f"isolate_endpoint:{HOST}")
    assert "entra failed" in isolation.reason


def test_hooks_contribute_nothing_without_transfers():
    lab = _lab()
    _endpoint(lab)
    _profile(lab)
    run = _run(lab)
    facts = _facts(run)
    assert facts == {"destinations": [], "sources": [], "actors": []}
    assert run.proposals == () and run.considered == () and run.handoffs == () and run.signals == ()
