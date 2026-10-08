"""Ransomware hooks: facts and signals come only from the run's records (fake lab data)."""
from __future__ import annotations

from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_lab
from xdr_response.models import Incident, Observable, ObservableType, Severity, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.ransomware import HOOKS, WORKFLOW
from xdr_response.workflows.ransomware.hooks import MASS_FILE_EVENTS, WIDESPREAD_PREVALENCE
from xdr_response.workflows.runner import WorkflowRun
from tools.simulator.scenario import SIM_NOW

SUITE = {"secure_endpoint": ("endpoint",), "entra": ("identity",), "umbrella": ("network",),
         "secure_email": ("email",), "virustotal": ("intel",)}
HOST = "TH-LT-1047"
PEER = "TH-LT-1052"
PAYLOAD = "3c7a9e0d" * 8
COMMON = "7b9d1f3a" * 8
USER = "jsmith@example.com"
_O = ObservableType


def _incident(*observables: tuple[ObservableType, str], users: tuple[str, ...] = ()) -> Incident:
    obs = observables or ((_O.HOSTNAME, HOST),)
    return Incident(incident_id="XDR-RW-9001", title="Ransomware detected on TH-LT-1047", severity=Severity.CRITICAL,
                    created_at=SIM_NOW, workflow_id="ransomware", workflow_version=WORKFLOW.version,
                    observables=tuple(Observable(type=t, value=v) for t, v in obs), users=users)


def _lab() -> Lab:
    return make_lab(SUITE)


def _endpoint(lab: Lab, host: str = HOST, **extra: Any) -> None:
    fields: dict[str, Any] = {"isolation_capable": True, "isolation_state": "not_isolated", **extra}
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host,
              connector_guid="00000000-0000-4000-8000-00000000" + host[-4:], **fields)


def _detection(lab: Lab, host: str = HOST, *, verdict: str = "MALICIOUS", name: str = "Ransomware.Generic",
               **extra: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", detection_id=f"det-{host}-{name}",
              name=name, verdict=verdict, severity="CRITICAL", endpoint=host, **extra)


def _event(lab: Lab, ident: str, *, host: str = HOST, **fields: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="process_event", event_id=ident, endpoint=host,
              timestamp="2026-01-15T11:30:00Z", **fields)


def _prevalence(lab: Lab, sha: str, prevalence: int, hosts: list[str], verdict: str = "MALICIOUS") -> None:
    lab.typed("search_hash_enterprise", sha, "secure_endpoint", kind="hash_prevalence", sha256=sha, verdict=verdict,
              prevalence=prevalence, endpoints=hosts)


def _rep(lab: Lab, otype: ObservableType, value: str, verdict: Verdict = Verdict.MALICIOUS,
         integrations: tuple[str, ...] = ("secure_endpoint", "virustotal")) -> None:
    lab.environment.set_reputation(otype, value, verdict, risk_score=90, confidence=85, integrations=list(integrations))


def _run(lab: Lab, incident: Incident | None = None) -> tuple[WorkflowRun, dict[str, Any]]:
    run = lab.runner.run(WORKFLOW, HOOKS, incident or _incident(), dry_run=True)
    view = RunView(workflow=WORKFLOW, incident=incident or _incident(), results=run.results, index=run.index,
                   correlation=run.correlation, blast_radius=run.blast_radius)
    return run, dict(HOOKS.facts(view))


def _proposed(run: WorkflowRun) -> set[str]:
    return {f"{p.action_type.value}:{p.target}" for p in run.proposals}


# ------------------------------------------------------------- affected hosts --
def test_a_malicious_detection_makes_the_host_affected_and_cites_it():
    lab = _lab()
    _endpoint(lab, users=[USER])
    _detection(lab, user=USER)
    run, facts = _run(lab)
    ids = facts["affected_hosts"][HOST]
    kinds = {str(run.index.get(i).kind) for i in ids}
    assert kinds == {"detection", "endpoint"}
    assert "isolate_endpoint:TH-LT-1047" in _proposed(run)


def test_a_suspicious_detection_alone_never_isolates():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, verdict="SUSPICIOUS", name="Mass file modification over SMB")
    run, facts = _run(lab)
    assert facts["affected_hosts"] == {}
    assert run.proposals == ()


def test_mass_modification_needs_recovery_inhibition_on_the_same_host():
    lab = _lab()
    _endpoint(lab)
    _event(lab, "mass", event_type="file_modify", process_name="tool.exe", verdict="SUSPICIOUS",
           count=MASS_FILE_EVENTS)
    run, facts = _run(lab)
    assert facts["mass_modification_hosts"] == [HOST] and facts["recovery_inhibition_hosts"] == []
    assert facts["affected_hosts"] == {} and run.proposals == ()


def test_mass_modification_with_recovery_inhibition_is_ransomware_behaviour():
    lab = _lab()
    _endpoint(lab)
    _event(lab, "mass", event_type="file_rename", process_name="tool.exe", verdict="SUSPICIOUS", count=2500)
    _event(lab, "vss", event_type="process_start", process_name="C:/Windows/System32/vssadmin.exe",
           verdict="SUSPICIOUS")
    run, facts = _run(lab)
    assert facts["recovery_inhibition_hosts"] == [HOST]
    assert HOST in facts["affected_hosts"]
    pattern = [s for s in run.signals if s.category is SignalCategory.ENDPOINT_DETECTION]
    assert len(pattern) == 1 and pattern[0].verdict is Verdict.MALICIOUS and pattern[0].origin == "workflow:ransomware"
    assert set(pattern[0].record_ids) <= set(run.index.ids())
    assert _proposed(run) == {"isolate_endpoint:TH-LT-1047"}


def test_an_unflagged_mass_modification_below_the_threshold_is_ignored():
    lab = _lab()
    _endpoint(lab)
    _event(lab, "mass", event_type="file_modify", process_name="tool.exe", verdict="CLEAN", count=50_000)
    _event(lab, "few", event_type="file_modify", process_name="tool.exe", verdict="SUSPICIOUS",
           count=MASS_FILE_EVENTS - 1)
    _event(lab, "vss", event_type="process_start", process_name="vssadmin.exe", verdict="SUSPICIOUS")
    _run_facts = _run(lab)[1]
    assert _run_facts["mass_modification_hosts"] == [] and _run_facts["affected_hosts"] == {}


def test_a_recovery_tool_without_a_vendor_flag_is_not_recovery_inhibition():
    lab = _lab()
    _endpoint(lab)
    _event(lab, "vss", event_type="process_start", process_name="vssadmin.exe", verdict="UNKNOWN")
    assert _run(lab)[1]["recovery_inhibition_hosts"] == []


def test_a_forbidden_isolation_is_not_proposed():
    lab = _lab()
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST,
              connector_guid="00000000-0000-4000-8000-000000001047", isolation_capable=False)
    _detection(lab)
    run, facts = _run(lab)
    assert HOST in facts["affected_hosts"]
    assert "isolate_endpoint:TH-LT-1047" not in _proposed(run)


# ------------------------------------------------------------------- payload --
def test_payload_hosts_hashes_and_the_prevalence_gate():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha256=PAYLOAD)
    _endpoint(lab, PEER)
    _rep(lab, _O.SHA256, PAYLOAD)
    _rep(lab, _O.SHA256, COMMON)
    _prevalence(lab, PAYLOAD, 2, [HOST, PEER])
    _prevalence(lab, COMMON, WIDESPREAD_PREVALENCE + 1, [HOST, "TH-LT-1099"])
    run, facts = _run(lab, _incident((_O.HOSTNAME, HOST), (_O.SHA256, COMMON)))
    assert set(facts["payload_hosts"]) == {HOST, PEER}
    assert set(facts["blockable_hashes"]) == {PAYLOAD}
    assert facts["widespread_hashes"] == [COMMON]
    assert facts["payload_hashes"][COMMON]["widespread"] is True
    assert facts["payload_hashes"][PAYLOAD]["prevalence"] == 2
    proposed = _proposed(run)
    assert {"isolate_endpoint:TH-LT-1047", "isolate_endpoint:TH-LT-1052", f"block_hash:{PAYLOAD}"} <= proposed
    assert f"block_hash:{COMMON}" not in proposed and "isolate_endpoint:TH-LT-1099" not in proposed
    spread = [s for s in run.signals if s.category is SignalCategory.LATERAL_MOVEMENT]
    assert {s.observable.value for s in spread} == {HOST, PEER}


def test_a_hash_without_a_reputation_verdict_is_not_blocked_but_its_host_is_isolated():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha256=PAYLOAD)  # behavioural verdict only, no reputation answer
    run, facts = _run(lab, _incident((_O.HOSTNAME, HOST), (_O.SHA256, PAYLOAD)))
    assert facts["blockable_hashes"] == {}
    assert _proposed(run) == {"isolate_endpoint:TH-LT-1047"}


def test_unknown_prevalence_still_blocks_and_says_so():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha256=PAYLOAD)
    _rep(lab, _O.SHA256, PAYLOAD)
    run, facts = _run(lab)
    assert facts["payload_hashes"][PAYLOAD]["prevalence"] is None
    block = next(p for p in run.proposals if p.target == PAYLOAD)
    assert "prevalence unknown" in block.rationale


# --------------------------------------------------------------------- users --
def test_affected_and_compromised_users():
    lab = _lab()
    _endpoint(lab, users=[USER, "svc_backup"])  # a non-UPN account name is never an Entra target
    _detection(lab, user=USER)
    lab.typed("investigate_user", USER, "entra", kind="user_profile", user=USER, risk_level="high")
    lab.typed("investigate_user", USER, "entra", kind="anomaly", anomaly_id="risk-1", anomaly_type="unfamiliar_location",
              severity="HIGH", user=USER)
    run, facts = _run(lab, _incident(users=(USER,)))
    assert set(facts["affected_users"]) == {USER}
    assert set(facts["compromised_users"]) == {USER}
    assert {f"revoke_sessions:{USER}", f"disable_user:{USER}"} <= _proposed(run)


def test_high_risk_without_a_risk_detection_is_not_compromised():
    lab = _lab()
    _endpoint(lab, users=[USER])
    _detection(lab)
    lab.typed("investigate_user", USER, "entra", kind="user_profile", user=USER, risk_level="high")
    run, facts = _run(lab)
    assert facts["compromised_users"] == {}
    assert f"revoke_sessions:{USER}" in _proposed(run) and f"disable_user:{USER}" not in _proposed(run)


# -------------------------------------------------------------- destinations --
def test_a_destination_needs_a_contact_or_the_incident():
    lab = _lab()
    _endpoint(lab)
    _detection(lab)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="dns_query", endpoint=HOST,
              domain="cdn-update.test", count=3)
    _rep(lab, _O.DOMAIN, "cdn-update.test", integrations=("umbrella", "virustotal"))
    _rep(lab, _O.DOMAIN, "other-infra.test", integrations=("umbrella", "virustotal"))
    run, facts = _run(lab)
    assert set(facts["blockable_domains"]) == {"cdn-update.test"}  # other-infra.test was never seen
    contact = [s for s in run.signals if s.category is SignalCategory.NETWORK_BEHAVIOUR]
    assert [s.observable.value for s in contact] == ["cdn-update.test"]
    assert "block_domain:cdn-update.test" in _proposed(run)


def test_a_clean_contacted_domain_is_not_blocked():
    lab = _lab()
    _endpoint(lab)
    _detection(lab)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="dns_query", endpoint=HOST,
              domain="updates.example.net", count=3)
    _rep(lab, _O.DOMAIN, "updates.example.net", Verdict.CLEAN, integrations=("umbrella", "virustotal"))
    run, facts = _run(lab)
    assert facts["blockable_domains"] == {}
    assert not any(p.action_type.value == "block_domain" for p in run.proposals)


# ------------------------------------------------------------------ lateral --
def test_related_endpoints_are_scoped_not_isolated():
    lab = _lab()
    _endpoint(lab)
    _detection(lab)
    lab.typed("search_related_endpoints", HOST, "secure_endpoint", kind="endpoint", hostname="TH-LT-1060")
    _endpoint(lab, "TH-LT-1060")
    run, facts = _run(lab)
    assert list(facts["lateral_targets"]) == ["TH-LT-1060"]
    assert _proposed(run) == {"isolate_endpoint:TH-LT-1047"}


# -------------------------------------------------------------------- safety --
def test_facts_are_json_and_every_cited_id_is_a_record_of_the_run():
    lab = _lab()
    _endpoint(lab, users=[USER])
    _detection(lab, sha256=PAYLOAD, user=USER)
    _rep(lab, _O.SHA256, PAYLOAD)
    _prevalence(lab, PAYLOAD, 1, [HOST])
    run, facts = _run(lab)
    known = set(run.index.ids())
    for key in ("affected_hosts", "payload_hosts", "blockable_hashes", "affected_users", "compromised_users",
                "blockable_domains", "blockable_urls", "blockable_ips", "lateral_targets"):
        for ids in facts[key].values():
            assert ids and set(ids) <= known, key
    for signal in run.signals:
        cited = run.index.require(signal.record_ids)
        assert signal.integration in {r.integration for r in cited}
    assert not [n for n in run.notes if n.startswith("hook ")]


def test_an_empty_run_gives_empty_facts_and_no_signal():
    lab = _lab()
    run, facts = _run(lab, _incident((_O.HOSTNAME, "TH-LT-0001"),))
    assert run.proposals == () and run.signals == ()
    assert all(not value for value in facts.values())


@pytest.mark.parametrize("dry_run", [True, False])
def test_the_hooks_never_touch_a_vendor(dry_run: bool):
    lab = make_lab(SUITE, dry_run=dry_run)
    _endpoint(lab, users=[USER])
    _detection(lab, user=USER, sha256=PAYLOAD)
    _rep(lab, _O.SHA256, PAYLOAD)
    lab.runner.run(WORKFLOW, HOOKS, _incident(users=(USER,)), dry_run=dry_run)
    assert lab.environment.state_changing_calls() == []


# ------------------------------------------------- considered, not proposed (14.10.1) --
def test_a_host_whose_policy_forbids_isolation_is_reported_never_silently_skipped():
    lab = _lab()
    _endpoint(lab, isolation_capable=False)
    _detection(lab)
    run, _ = _run(lab)
    assert "isolate_endpoint:TH-LT-1047" not in _proposed(run)
    item = next(c for c in run.considered if c.subject == f"isolate_endpoint:{HOST}")
    assert "does not allow isolation" in item.reason and not item.manual
    assert {str(run.index.get(i).kind) for i in item.record_ids} == {"detection", "endpoint"}
    assert any(line.startswith(f"isolate_endpoint:{HOST}: the endpoint's policy") for line in run.summary().considered)


def test_widespread_and_unrated_hashes_are_reported_as_considered():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha256=PAYLOAD)
    _rep(lab, _O.SHA256, PAYLOAD)
    _prevalence(lab, PAYLOAD, WIDESPREAD_PREVALENCE + 10, [HOST])
    _event(lab, "odd", event_type="process_start", process_name="helper.exe", sha256=COMMON, verdict="UNKNOWN")
    run, facts = _run(lab, _incident((_O.HOSTNAME, HOST), (_O.SHA256, PAYLOAD), (_O.SHA256, COMMON)))
    assert facts["widespread_hashes"] == [PAYLOAD] and f"block_hash:{PAYLOAD}" not in _proposed(run)
    reasons = {c.subject: c.reason for c in run.considered}
    assert f"seen on {WIDESPREAD_PREVALENCE + 10} endpoints" in reasons[f"block_hash:{PAYLOAD}"]
    assert reasons[f"block_hash:{COMMON}"] == "no reputation verdict: not blocked"
    assert all(set(c.record_ids) <= set(run.index.ids()) for c in run.considered)
