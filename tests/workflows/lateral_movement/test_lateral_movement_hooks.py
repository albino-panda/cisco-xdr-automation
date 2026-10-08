"""Lateral-movement hooks: the movement graph, facts, links and signals come only from the run's records.

Every test builds a small simulated lab (fake data, no network), runs the real workflow runner over the
definition and checks what the hooks derived and what the rules proposed. Nothing here executes or
approves anything: the runner only reads.
"""
from __future__ import annotations

import json
from typing import Any

from tests.fixtures.sample_workflows.lab import Lab, make_lab
from tools.simulator.scenario import SIM_NOW
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.models import Incident, Observable, ObservableType, OperationKind, Severity, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.lateral_movement import HOOKS, WORKFLOW
from xdr_response.workflows.lateral_movement.hooks import JUMP_HOST_MARKERS, LATERAL_PORTS, WIDESPREAD_PREVALENCE
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

SUITE = {"secure_endpoint": ("endpoint",), "entra": ("identity",), "umbrella": ("network",),
         "meraki": ("network",), "virustotal": ("intel",)}
SRC, DST, OTHER = "TH-LT-1047", "TH-SRV-0310", "TH-LT-1052"
SRC_IP, DST_IP, OTHER_IP = "198.51.100.47", "198.51.100.31", "198.51.100.52"
USER = "jsmith@example.com"
TOOL = "8b3f5a7c" * 8
_O = ObservableType


def _incident(*hosts: str, users: tuple[str, ...] = (USER,), extra: tuple[tuple[ObservableType, str], ...] = ()
              ) -> Incident:
    observables = [Observable(type=_O.HOSTNAME, value=h) for h in (hosts or (SRC, DST))]
    observables += [Observable(type=t, value=v) for t, v in extra]
    return Incident(incident_id="XDR-LM-9001", title="Lateral movement from TH-LT-1047", severity=Severity.HIGH,
                    created_at=SIM_NOW, workflow_id="lateral-movement", workflow_version=WORKFLOW.version,
                    observables=tuple(observables), users=users)


def _lab() -> Lab:
    return make_lab(SUITE)


def _endpoint(lab: Lab, host: str, ip: str, **extra: Any) -> None:
    fields: dict[str, Any] = {"isolation_capable": True, "isolation_state": "not_isolated", "groups": ["Workstations"],
                              **extra}
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host, ip_addresses=[ip],
              connector_guid="00000000-0000-4000-8000-00000000" + host[-4:], **fields)


def _detection(lab: Lab, host: str, *, verdict: str = "MALICIOUS", name: str = "Remote service creation burst",
               **extra: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", detection_id=f"det-{host}-{name}",
              name=name, verdict=verdict, severity="HIGH", endpoint=host, **extra)


def _connection(lab: Lab, host: str, remote_ip: str, port: int = 445, *, direction: str = "internal",
                user: str | None = USER, verdict: str = "UNKNOWN", process: str | None = "svc_push.exe") -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="network_connection", endpoint=host,
              remote_ip=remote_ip, remote_port=port, protocol="tcp", direction=direction, user=user,
              process_name=process, verdict=verdict, first_seen="2026-01-15T11:20:00Z")


def _profile(lab: Lab, user: str = USER, **extra: Any) -> None:
    fields: dict[str, Any] = {"risk_level": "low", "risk_state": "none", "account_enabled": True,
                              "groups": ["Finance Users"], **extra}
    lab.typed("investigate_user", user, "entra", kind="user_profile", user=user, **fields)


def _run(lab: Lab, incident: Incident | None = None) -> tuple[WorkflowRun, dict[str, Any]]:
    incident = incident or _incident()
    run = lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)
    view = RunView(workflow=WORKFLOW, incident=incident, results=run.results, index=run.index,
                   correlation=run.correlation, blast_radius=run.blast_radius)
    return run, dict(HOOKS.facts(view))


def _proposed(run: WorkflowRun) -> set[str]:
    return {f"{p.action_type.value}:{p.target}" for p in run.proposals}


def _considered(run: WorkflowRun, *, manual: bool = False) -> set[str]:
    return {c.subject for c in run.considered if c.manual is manual}


def _pivot(lab: Lab, *, destination_malicious: bool = True) -> None:
    """SRC (quiet) reaches DST over SMB; DST has a malicious detection when asked."""
    _endpoint(lab, SRC, SRC_IP, users=[USER])
    _endpoint(lab, DST, DST_IP, groups=["Application Servers"])
    _connection(lab, SRC, DST_IP)
    if destination_malicious:
        _detection(lab, DST, name="Service created from file dropped over SMB", user=USER)
    _profile(lab)


# --------------------------------------------------------------- movement graph --
def test_an_internal_connection_on_a_remote_service_port_is_a_movement_edge_resolved_by_address():
    lab = _lab()
    _pivot(lab)
    run, facts = _run(lab)
    edges = facts["edges"]
    assert len(edges) == 1
    edge = edges[0]
    assert (edge["source"], edge["destination"], edge["protocol"], edge["port"]) == (SRC, DST, "SMB", 445)
    assert edge["users"] == [USER] and edge["processes"] == ["svc_push.exe"] and edge["confirmed"] is True
    assert set(edge["record_ids"]) <= set(run.index.ids())
    assert facts["movement_confirmed"] is True


def test_an_inbound_record_makes_the_peer_the_source():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _endpoint(lab, DST, DST_IP)
    _connection(lab, DST, SRC_IP, 3389, direction="inbound", process="svchost.exe")
    _detection(lab, DST, user=USER)
    _profile(lab)
    _run_result, facts = _run(lab)
    edge = facts["edges"][0]
    assert (edge["source"], edge["destination"], edge["protocol"]) == (SRC, DST, "RDP")
    assert edge["processes"] == []  # the listener on the destination is not the responsible process
    assert SRC in facts["movement_sources"]


def test_ports_outside_the_remote_service_list_are_not_movement():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _endpoint(lab, DST, DST_IP)
    _connection(lab, SRC, DST_IP, 443)
    _detection(lab, DST)
    run, facts = _run(lab)
    assert 443 not in LATERAL_PORTS and facts["edges"] == []
    assert facts["movement_sources"] == {} and _proposed(run) == {f"isolate_endpoint:{DST}"}


def test_an_outbound_remote_desktop_session_to_a_public_address_is_not_lateral_movement():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _detection(lab, SRC)
    _connection(lab, SRC, "203.0.113.90", 3389, direction="outbound")
    _run_result, facts = _run(lab, _incident(SRC))
    assert facts["edges"] == [] and facts["unresolved_peers"] == {}


def test_an_address_two_hosts_claim_stays_unresolved_and_becomes_a_manual_step():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _detection(lab, SRC, user=USER)
    _endpoint(lab, DST, DST_IP)
    _endpoint(lab, OTHER, DST_IP)  # DHCP reuse: the address is ambiguous
    _connection(lab, SRC, DST_IP)
    _profile(lab)
    run, facts = _run(lab, _incident(SRC, DST, OTHER))
    assert facts["edges"][0]["destination"] == DST_IP
    assert facts["unresolved_peers"] == {DST_IP: facts["edges"][0]["record_ids"]}
    assert _considered(run, manual=True) == {f"lateral peer {DST_IP}"}
    assert f"isolate_endpoint:{DST}" not in _proposed(run) and f"isolate_endpoint:{OTHER}" not in _proposed(run)


def test_the_peer_lookup_finds_a_destination_the_incident_does_not_name():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _detection(lab, SRC, user=USER)
    _connection(lab, SRC, DST_IP)
    lab.typed("search_related_endpoints", SRC, "secure_endpoint", kind="endpoint", hostname=DST,
              ip_addresses=[DST_IP])
    _endpoint(lab, DST, DST_IP)
    _detection(lab, DST, name="Service created from file dropped over SMB")
    _profile(lab)
    run, facts = _run(lab, _incident(SRC))
    assert {r.subject.value for r in run.results if r.atomic == "investigate_endpoint"} == {SRC, DST}
    assert set(facts["compromised_hosts"]) == {SRC, DST}
    assert {f"isolate_endpoint:{SRC}", f"isolate_endpoint:{DST}"} <= _proposed(run)


# ------------------------------------------------------------ hosts and roles --
def test_a_quiet_source_of_confirmed_movement_is_isolated_with_edge_and_confirming_evidence():
    lab = _lab()
    _pivot(lab)
    run, facts = _run(lab)
    assert set(facts["compromised_hosts"]) == {DST}
    ids = facts["movement_sources"][SRC]
    kinds = {str(run.index.get(i).kind) for i in ids}
    assert kinds == {"network_connection", "detection", "endpoint"}
    assert _proposed(run) == {f"isolate_endpoint:{SRC}", f"isolate_endpoint:{DST}", f"revoke_sessions:{USER}"}
    source = next(p for p in run.proposals if p.target == SRC)
    assert "origin of confirmed movement" in source.rationale and "SMB" in source.rationale
    assert {e.data["record_id"] for e in source.evidence} >= set(facts["edges"][0]["record_ids"])


def test_movement_that_nothing_confirms_proposes_nothing_and_considers_nothing():
    lab = _lab()
    _pivot(lab, destination_malicious=False)
    run, facts = _run(lab)
    assert facts["movement_confirmed"] is False and facts["edges"][0]["confirmed"] is False
    assert run.proposals == () and run.considered == ()


def test_a_suspicious_east_west_connection_alone_is_considered_not_isolated():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _endpoint(lab, DST, DST_IP)
    _connection(lab, SRC, DST_IP, verdict="SUSPICIOUS")
    _profile(lab)
    run, facts = _run(lab)
    assert facts["edges"][0]["suspicious"] is True and facts["movement_sources"] == {}
    assert run.proposals == () and _considered(run) == {f"isolate_endpoint:{SRC}"}


def test_a_malicious_east_west_connection_confirms_the_edge_on_its_own():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _endpoint(lab, DST, DST_IP)
    _connection(lab, SRC, DST_IP, verdict="MALICIOUS")
    _profile(lab)
    run, facts = _run(lab)
    assert facts["edges"][0]["confirmed"] is True and SRC in facts["movement_sources"]
    assert facts["clean_targets"] == {DST: facts["clean_targets"][DST]}
    assert f"isolate_endpoint:{SRC}" in _proposed(run) and _considered(run) == {f"isolate_endpoint:{DST}"}


def test_a_target_without_activity_of_its_own_is_only_considered():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _detection(lab, SRC, user=USER)
    _endpoint(lab, OTHER, OTHER_IP)
    _connection(lab, SRC, OTHER_IP, 3389, process="mstsc.exe")
    _profile(lab)
    run, facts = _run(lab, _incident(SRC, OTHER))
    assert list(facts["clean_targets"]) == [OTHER]
    assert f"isolate_endpoint:{OTHER}" not in _proposed(run)
    item = next(c for c in run.considered if c.subject == f"isolate_endpoint:{OTHER}")
    assert "RDP" in item.reason and set(item.record_ids) <= set(run.index.ids())


def test_a_quiet_admin_jump_host_is_considered_and_its_account_revoked():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP, groups=["Admin Jump Hosts"])
    _endpoint(lab, DST, DST_IP)
    _connection(lab, SRC, DST_IP, 5985)
    _detection(lab, DST, user=USER)
    _profile(lab)
    run, facts = _run(lab)
    assert any(m in "admin jump hosts" for m in JUMP_HOST_MARKERS)
    assert facts["jump_hosts"] == [SRC] and facts["movement_sources"] == {}
    assert _proposed(run) == {f"isolate_endpoint:{DST}", f"revoke_sessions:{USER}"}
    item = next(c for c in run.considered if c.subject == f"isolate_endpoint:{SRC}")
    assert "jump host" in item.reason and not item.manual


def test_a_jump_host_with_malicious_activity_of_its_own_is_isolated():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP, tags=["bastion"])
    _detection(lab, SRC, user=USER)
    _endpoint(lab, DST, DST_IP)
    _connection(lab, SRC, DST_IP, 5985)
    _profile(lab)
    run, facts = _run(lab)
    assert facts["jump_hosts"] == [] and SRC in facts["compromised_hosts"]
    assert f"isolate_endpoint:{SRC}" in _proposed(run)


def test_a_host_whose_policy_forbids_isolation_is_considered():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP, isolation_capable=False)
    _detection(lab, SRC, user=USER)
    _profile(lab)
    run, _facts = _run(lab, _incident(SRC))
    assert f"isolate_endpoint:{SRC}" not in _proposed(run)
    assert f"isolate_endpoint:{SRC}" in _considered(run)


def test_remote_execution_names_the_responsible_process_on_the_destination():
    lab = _lab()
    _pivot(lab)
    for ident, parent, process in (("svc", "services.exe", "svc_helper.exe"), ("wmi", "WmiPrvSE.exe", "tool_a.exe"),
                                   ("wsm", "wsmprovhost.exe", "tool_b.exe")):
        lab.typed("investigate_endpoint", DST, "secure_endpoint", kind="process_event", event_id=f"evt-{ident}",
                  endpoint=DST, timestamp="2026-01-15T11:21:00Z", event_type="process_start", process_name=process,
                  parent_process_name=parent)
    run, facts = _run(lab)
    vias = {(x["process"], x["via"]) for x in facts["remote_execution"][DST]}
    assert vias == {("svc_helper.exe", "remote service"), ("tool_a.exe", "WMI"), ("tool_b.exe", "WinRM")}
    target = next(p for p in run.proposals if p.target == DST)
    assert "tool_a.exe via WMI" in target.rationale


# ----------------------------------------------------------------- transferred tool --
def test_a_transferred_tool_makes_its_holders_compromised_and_is_blocked():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _endpoint(lab, DST, DST_IP)
    _connection(lab, SRC, DST_IP)
    lab.environment.set_reputation(_O.SHA256, TOOL, Verdict.MALICIOUS, risk_score=90, confidence=85,
                                   integrations=["secure_endpoint", "virustotal"])
    lab.typed("search_hash_enterprise", TOOL, "secure_endpoint", kind="hash_prevalence", sha256=TOOL,
              verdict="MALICIOUS", prevalence=1, endpoints=[DST])
    _profile(lab)
    run, facts = _run(lab, _incident(SRC, DST, extra=((_O.SHA256, TOOL),)))
    assert list(facts["tool_hosts"]) == [DST] and list(facts["blockable_hashes"]) == [TOOL]
    assert SRC in facts["movement_sources"]
    assert _proposed(run) == {f"isolate_endpoint:{SRC}", f"isolate_endpoint:{DST}", f"block_hash:{TOOL}",
                              f"revoke_sessions:{USER}"}


def test_a_widespread_tool_is_considered_not_blocked():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _detection(lab, SRC, sha256=TOOL)
    lab.environment.set_reputation(_O.SHA256, TOOL, Verdict.MALICIOUS, risk_score=90, confidence=85,
                                   integrations=["secure_endpoint", "virustotal"])
    lab.typed("search_hash_enterprise", TOOL, "secure_endpoint", kind="hash_prevalence", sha256=TOOL,
              verdict="MALICIOUS", prevalence=WIDESPREAD_PREVALENCE + 1, endpoints=[SRC])
    run, facts = _run(lab, _incident(SRC, users=()))
    assert facts["widespread_hashes"] == [TOOL] and facts["blockable_hashes"] == {}
    assert f"block_hash:{TOOL}" not in _proposed(run) and f"block_hash:{TOOL}" in _considered(run)


def test_a_hash_a_malicious_detection_names_without_reputation_is_considered():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _detection(lab, SRC, sha256=TOOL)
    run, _facts = _run(lab, _incident(SRC, users=()))
    assert f"block_hash:{TOOL}" in _considered(run) and f"block_hash:{TOOL}" not in _proposed(run)


# ------------------------------------------------------------------------ accounts --
def test_the_movement_account_is_revoked_but_not_disabled_without_identity_evidence():
    lab = _lab()
    _pivot(lab)
    run, facts = _run(lab)
    assert list(facts["movement_accounts"]) == [USER] and facts["compromised_accounts"] == {}
    assert f"revoke_sessions:{USER}" in _proposed(run) and f"disable_user:{USER}" not in _proposed(run)
    assert run.handoffs == ()


def test_a_high_risk_movement_account_is_disabled_and_handed_off():
    lab = _lab()
    _pivot(lab)
    lab.typed("investigate_user", USER, "entra", kind="anomaly", anomaly_id="risk-1", anomaly_type="new_device",
              severity="MEDIUM", user=USER)
    run, facts = _run(lab)
    assert USER in facts["compromised_accounts"]
    assert f"disable_user:{USER}" in _proposed(run)
    assert [(h.workflow_id, h.subjects) for h in run.handoffs] == [("account-takeover", (USER,))]


def test_a_sign_in_from_a_malicious_address_compromises_the_account_and_the_address_is_blocked():
    lab = _lab()
    _pivot(lab)
    address = "203.0.113.145"
    lab.environment.set_reputation(_O.IP, address, Verdict.MALICIOUS, risk_score=80, confidence=75,
                                   integrations=["umbrella", "meraki"])
    lab.typed("investigate_authentication", USER, "entra", kind="sign_in", sign_in_id="si-1", user=USER,
              timestamp="2026-01-15T10:00:00Z", ip=address, result="success")
    run, facts = _run(lab)
    assert USER in facts["compromised_accounts"] and address in facts["blockable_ips"]
    sign_in = [i for i in facts["blockable_ips"][address] if str(run.index.get(i).kind) == "sign_in"]
    assert sign_in
    assert {f"disable_user:{USER}", f"block_ip:{address}"} <= _proposed(run)


def test_an_address_an_investigated_host_owns_is_never_proposed_for_a_block():
    lab = _lab()
    _pivot(lab)
    lab.environment.set_reputation(_O.IP, SRC_IP, Verdict.MALICIOUS, risk_score=80, confidence=75,
                                   integrations=["umbrella", "meraki"])
    run, facts = _run(lab, _incident(SRC, DST, extra=((_O.IP, SRC_IP),)))
    assert facts["blockable_ips"] == {} and not any(p.action_type.value == "block_ip" for p in run.proposals)


def test_a_privileged_movement_account_keeps_its_groups_for_the_critical_asset_policy():
    lab = _lab()
    _endpoint(lab, SRC, SRC_IP)
    _endpoint(lab, DST, DST_IP)
    _connection(lab, SRC, DST_IP)
    _detection(lab, DST, user=USER)
    _profile(lab, groups=["Domain Admins"])
    run, _facts = _run(lab)
    revoke = next(p for p in run.proposals if p.action_type.value == "revoke_sessions")
    assert revoke.asset is not None and "Domain Admins" in revoke.asset.groups


def test_a_credential_access_detection_hands_the_host_off_to_credential_dumping():
    lab = _lab()
    _pivot(lab)
    _detection(lab, DST, name="Credential theft tool detected", category="CredentialAccess")
    run, _facts = _run(lab)
    assert ("credential-dumping", (DST,)) in [(h.workflow_id, h.subjects) for h in run.handoffs]


# ------------------------------------------------------------- links and signals --
def test_every_edge_becomes_a_workflow_link_with_both_hosts_and_the_account():
    lab = _lab()
    _pivot(lab)
    run, facts = _run(lab)
    links = [link for link in run.correlation.links if link.kind is LinkKind.WORKFLOW]
    assert len(links) == 1 and links[0].origin == "workflow:lateral-movement"
    assert {(e.kind.value, e.value) for e in links[0].entities} == {("ENDPOINT", SRC), ("ENDPOINT", DST),
                                                                   ("USER", USER)}
    assert set(links[0].record_ids) == set(facts["edges"][0]["record_ids"])


def test_signals_are_lateral_movement_and_cite_only_run_records():
    lab = _lab()
    _pivot(lab)
    run, _facts = _run(lab)
    lateral = [s for s in run.signals if s.category is SignalCategory.LATERAL_MOVEMENT]
    assert {(s.observable.type, s.observable.value) for s in lateral} == {(_O.HOSTNAME, SRC), (_O.USER, USER)}
    for signal in lateral:
        assert signal.origin == "workflow:lateral-movement" and signal.verdict is Verdict.SUSPICIOUS
        assert set(signal.record_ids) <= set(run.index.ids())
        assert signal.integration in {run.index.get(i).integration for i in signal.record_ids}


def test_risk_and_confidence_are_separate_integers_for_every_proposal():
    lab = _lab()
    _pivot(lab)
    run, _facts = _run(lab)
    for proposal in run.proposals:
        assert isinstance(proposal.risk_score, int) and isinstance(proposal.confidence_score, int)
        assert proposal.evidence and all(e.data["record_id"] in run.index for e in proposal.evidence)
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)


def test_facts_are_json_and_always_carry_every_key():
    lab = _lab()
    _run_result, facts = _run(lab, _incident(SRC, users=()))
    json.dumps(facts)
    assert set(facts) == {"compromised_hosts", "movement_sources", "clean_targets", "jump_hosts", "tool_hashes",
                          "blockable_hashes", "widespread_hashes", "tool_hosts", "movement_accounts",
                          "compromised_accounts", "blockable_ips", "edges", "remote_execution", "unresolved_peers",
                          "host_summary", "account_summary", "movement_confirmed"}


def test_the_hooks_only_read():
    lab = _lab()
    _pivot(lab)
    _run(lab)
    assert [c for c in lab.environment.calls if c.kind is OperationKind.STATE_CHANGING] == []
