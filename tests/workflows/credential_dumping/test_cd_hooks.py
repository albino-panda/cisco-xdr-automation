"""Credential-dumping hooks: facts, considerations, manual steps, hand-offs and exposure links (simulated lab).

Every fact is computed from the run's own records and carries their ids; nothing here reaches a
vendor, scores a target or chooses an approval level.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.models import ObservableType, Verdict
from xdr_response.models.enums import HealthStatus
from xdr_response.workflows.credential_dumping import HOOKS, WORKFLOW
from xdr_response.workflows.credential_dumping.hooks import (
    CREDENTIAL_DUMPING,
    LSASS,
    NTDS,
    SAM,
    credential_behaviours,
)
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

HOST = "TH-LT-1047"
TOOL = "d00dfeed" * 8
OTHER = "0b5e55ed" * 8
GUID = "00000000-0000-4000-8000-000000001047"
SUITE = {"secure_endpoint": ("endpoint",), "entra": ("identity",), "virustotal": ("intel",)}


# ----------------------------------------------------------------- behaviours --
@pytest.mark.parametrize("texts, techniques, expected", [
    (["Suspicious read of LSASS process memory"], [], (LSASS,)),
    (["Endpoint alert"], ["T1003.001"], (LSASS,)),
    (["SAM registry hive export"], [], (SAM,)),
    (["Security Account Manager access"], [], (SAM,)),
    (["Endpoint alert"], ["t1003.002"], (SAM,)),
    (["Unexpected copy of the directory database"], [], (NTDS,)),
    (["ntds.dit read"], [], (NTDS,)),
    (["Endpoint alert"], ["T1003.003"], (NTDS,)),
    (["Credential theft tool"], [], (CREDENTIAL_DUMPING,)),
    (["Endpoint alert", "CredentialAccess"], [], (CREDENTIAL_DUMPING,)),
    (["Endpoint alert"], ["T1003"], (CREDENTIAL_DUMPING,)),
    (["Endpoint alert"], ["T1003.006"], (CREDENTIAL_DUMPING,)),
    (["LSASS and SAM access", "CredentialAccess"], ["T1003.003"], (LSASS, SAM, NTDS)),
])
def test_credential_behaviours_come_from_vendor_text_and_reported_ids(texts, techniques, expected):
    assert credential_behaviours(texts, techniques) == expected


@pytest.mark.parametrize("texts, techniques", [
    (["Sample.Trojan.Generic", "Malware"], ["T1204.002"]),
    (["Samba share enumerated"], []),  # 'sam' only as a whole word
    ([None, ""], []),
])
def test_unrelated_detections_are_not_credential_dumping(texts, techniques):
    assert credential_behaviours(texts, techniques) == ()


# ------------------------------------------------------------------- the lab --
def _lab() -> Lab:
    return make_lab(SUITE)


def _endpoint(lab: Lab, host: str = HOST, *, users: tuple[str, ...] = ("jsmith@example.com",), **extra: Any) -> None:
    fields = {"connector_guid": GUID, "groups": ["Workstations"], "isolation_capable": True,
              "isolation_state": "not_isolated", "ip_addresses": ["198.51.100.47"], **extra}
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host, users=list(users),
              **fields)


def _detection(lab: Lab, *, host: str = HOST, verdict: str = "MALICIOUS", sha: str | None = TOOL,
               name: str = "Credential theft - LSASS memory read", techniques: tuple[str, ...] = ("T1003.001",),
               user: str | None = None, ident: str = "det-1") -> None:
    fields: dict[str, Any] = {"detection_id": f"{ident}-{host}", "name": name, "category": "CredentialAccess",
                              "verdict": verdict, "severity": "CRITICAL", "endpoint": host,
                              "mitre_techniques": list(techniques), "status": "active"}
    if sha:
        fields["sha256"] = sha
    if user:
        fields["user"] = user
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", **fields)


def _prevalence(lab: Lab, sha: str = TOOL, *, verdict: str = "MALICIOUS", count: int = 1,
                endpoints: tuple[str, ...] = (HOST,)) -> None:
    lab.typed("search_hash_enterprise", sha, "secure_endpoint", kind="hash_prevalence", sha256=sha, verdict=verdict,
              prevalence=count, endpoints=list(endpoints))


def _reputation(lab: Lab, sha: str = TOOL, verdict: Verdict = Verdict.MALICIOUS) -> None:
    risk = 90 if verdict is Verdict.MALICIOUS else 0
    lab.environment.set_reputation(ObservableType.SHA256, sha, verdict, risk_score=risk, confidence=85,
                                   integrations=["secure_endpoint", "virustotal"])


def _profile(lab: Lab, user: str, **fields: Any) -> None:
    lab.typed("investigate_user", user, "entra", kind="user_profile", user=user,
              **{"risk_level": "low", "risk_state": "none", "account_enabled": True, **fields})


def _run(lab: Lab, *observables: tuple[ObservableType, str], users: tuple[str, ...] = ()) -> WorkflowRun:
    incident = make_incident(*(observables or ((ObservableType.HOSTNAME, HOST),)), workflow_id="credential-dumping",
                             title=f"Credential theft behaviour on {HOST}", users=users)
    return lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)


def _view(run: WorkflowRun) -> RunView:
    incident = make_incident(workflow_id="credential-dumping")
    return RunView(workflow=WORKFLOW, incident=incident, results=run.results, index=run.index,
                   correlation=run.correlation, blast_radius=run.blast_radius)


def _facts(run: WorkflowRun) -> dict[str, Any]:
    facts = dict(HOOKS.facts(_view(run)))
    json.dumps(facts, allow_nan=False)  # the runner requires JSON facts
    return facts


def _proposed(run: WorkflowRun) -> set[str]:
    return {o.selector for o in run.outcomes_with(RuleOutcomeStatus.PROPOSED)}


def _considered(run: WorkflowRun) -> dict[str, str]:
    return {c.subject: c.reason for c in run.considered if not c.manual}


def _manual(run: WorkflowRun) -> set[str]:
    return {c.subject for c in run.considered if c.manual}


# --------------------------------------------------------------- confirmation --
def test_a_malicious_credential_detection_confirms_access_and_exposes_the_logged_on_accounts():
    lab = _lab()
    _endpoint(lab, users=("jsmith@example.com", "it.support@example.com"))
    _detection(lab, user="jsmith@example.com")
    _prevalence(lab)
    _reputation(lab)
    _profile(lab, "jsmith@example.com")
    _profile(lab, "it.support@example.com", roles=["Helpdesk Administrator"], privileged=True)
    run = _run(lab, (ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, TOOL))
    facts = _facts(run)
    (host,) = facts["credential_hosts"]
    assert host["hostname"] == HOST and host["connector_guid"] == GUID and host["behaviours"] == [LSASS]
    assert host["users"] == ["it.support@example.com", "jsmith@example.com"] and not host["domain_controller"]
    assert set(host["record_ids"]) <= set(run.index.ids()) and host["record_ids"]
    users = {u["user"]: u for u in facts["exposed_users"]}
    assert set(users) == {"jsmith@example.com", "it.support@example.com"}
    assert users["it.support@example.com"]["disable"] and not users["jsmith@example.com"]["disable"]
    assert "not privileged" in users["jsmith@example.com"]["summary"]
    assert _proposed(run) == {f"isolate_endpoint:{HOST}", "revoke_sessions:jsmith@example.com",
                              "revoke_sessions:it.support@example.com", "disable_user:it.support@example.com",
                              f"block_hash:{TOOL}"}
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)


def test_every_proposal_cites_only_records_of_the_run():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, user="jsmith@example.com")
    _prevalence(lab)
    _reputation(lab)
    _profile(lab, "jsmith@example.com")
    run = _run(lab)
    assert run.proposals
    for proposal in run.proposals:
        assert proposal.evidence
        assert all(item.data["record_id"] in run.index for item in proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int


def test_a_malicious_tool_file_on_the_endpoint_confirms_access_without_a_malicious_detection():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, verdict="UNKNOWN", sha=None, name="Unsigned process opened a handle to LSASS")
    _prevalence(lab)
    _reputation(lab)
    run = _run(lab, (ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, TOOL))
    (host,) = _facts(run)["credential_hosts"]
    assert host["behaviours"] == [LSASS]  # the unknown detection on a confirmed host names the behaviour
    assert "malicious tool file" in host["summary"]
    assert f"isolate_endpoint:{HOST}" in _proposed(run)


def test_suspicious_activity_alone_is_considered_never_contained():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, verdict="SUSPICIOUS", sha=None, name="Unsigned process opened a handle to LSASS")
    run = _run(lab)
    facts = _facts(run)
    assert facts["credential_hosts"] == [] and facts["exposed_users"] == []
    assert run.proposals == ()
    considered = _considered(run)
    assert "not confirmed" in considered[f"isolate_endpoint:{HOST}"]
    assert _manual(run) == set() and run.handoffs == ()


def test_clean_activity_of_an_approved_agent_is_considered_with_its_verdict():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, verdict="CLEAN", sha=OTHER, name="LSASS memory read by endpoint protection agent")
    _prevalence(lab, OTHER, verdict="CLEAN", count=4200)
    _reputation(lab, OTHER, Verdict.CLEAN)
    run = _run(lab, (ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, OTHER))
    assert run.proposals == ()
    considered = _considered(run)
    assert "rated CLEAN" in considered[f"isolate_endpoint:{HOST}"]
    assert "reputation CLEAN" in considered[f"block_hash:{OTHER}"]


def test_unrelated_malicious_detection_is_not_credential_dumping():
    lab = _lab()
    _endpoint(lab)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="detection", detection_id="det-x",
              name="Sample.Trojan.Generic", category="Malware", verdict="MALICIOUS", severity="HIGH", endpoint=HOST)
    run = _run(lab)
    assert _facts(run)["credential_hosts"] == [] and run.proposals == ()


# --------------------------------------------------------------------- hashes --
def test_a_misused_system_binary_is_never_blocked_but_the_endpoint_is_contained():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha=OTHER, name="LSASS memory dump by a system utility", user="jsmith@example.com")
    _prevalence(lab, OTHER, verdict="CLEAN", count=5100)
    _reputation(lab, OTHER, Verdict.CLEAN)
    _profile(lab, "jsmith@example.com")
    run = _run(lab)
    assert _proposed(run) == {f"isolate_endpoint:{HOST}", "revoke_sessions:jsmith@example.com"}
    assert "reputation CLEAN" in _considered(run)[f"block_hash:{OTHER}"]


def test_a_hash_named_only_by_a_behaviour_detection_is_not_blocked():
    lab = _lab()
    _endpoint(lab)
    _detection(lab, sha=OTHER)
    run = _run(lab)
    (entry,) = [h for h in _facts(run)["hashes"] if h["sha256"] == OTHER]
    assert entry["named_by_behaviour"] and not entry["file_malicious"] and not entry["blockable"]
    assert "behaviour detection" in _considered(run)[f"block_hash:{OTHER}"]
    assert f"isolate_endpoint:{HOST}" in _proposed(run)


def test_a_widespread_malicious_tool_is_not_blocked_and_confirms_only_named_endpoints():
    lab = _lab()
    _endpoint(lab)
    _detection(lab)
    _prevalence(lab, count=40, endpoints=(HOST, "TH-LT-2001", "TH-LT-2002"))
    _reputation(lab)
    run = _run(lab, (ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, TOOL))
    facts = _facts(run)
    assert [h["hostname"] for h in facts["credential_hosts"]] == [HOST]
    (entry,) = facts["hashes"]
    assert entry["widespread"] and not entry["blockable"]
    assert "more than 10" in _considered(run)[f"block_hash:{TOOL}"]
    assert f"block_hash:{TOOL}" not in _proposed(run)


def test_a_rare_malicious_tool_confirms_the_other_endpoints_that_hold_it():
    lab = _lab()
    _endpoint(lab)
    _detection(lab)
    _endpoint(lab, "TH-LT-2001", users=("akim@example.com",), connector_guid="00000000-0000-4000-8000-000000002001")
    _prevalence(lab, count=2, endpoints=(HOST, "TH-LT-2001"))
    _reputation(lab)
    run = _run(lab, (ObservableType.HOSTNAME, HOST), (ObservableType.SHA256, TOOL))
    assert {h["hostname"] for h in _facts(run)["credential_hosts"]} == {HOST, "TH-LT-2001"}
    assert {f"isolate_endpoint:{HOST}", "isolate_endpoint:TH-LT-2001", "revoke_sessions:akim@example.com",
            f"block_hash:{TOOL}"} <= _proposed(run)


# --------------------------------------------------------------------- accounts --
def test_a_privileged_account_by_policy_or_role_is_disabled():
    lab = _lab()
    _endpoint(lab, users=("ops.lead@example.com", "sec.ops@example.com"))
    _detection(lab, sha=None)
    _profile(lab, "ops.lead@example.com", groups=["Domain Admins"])
    _profile(lab, "sec.ops@example.com", roles=["Security Administrator"])
    run = _run(lab)
    users = {u["user"]: u for u in _facts(run)["exposed_users"]}
    assert users["ops.lead@example.com"]["privileged"] and users["sec.ops@example.com"]["privileged"]
    assert "Security Administrator" in users["sec.ops@example.com"]["disable_summary"]
    assert {"disable_user:ops.lead@example.com", "disable_user:sec.ops@example.com"} <= _proposed(run)


def test_an_account_the_identity_provider_flags_compromised_is_disabled_and_cites_the_risk_detection():
    lab = _lab()
    _endpoint(lab, users=("pwhite@example.com",))
    _detection(lab, sha=None)
    _profile(lab, "pwhite@example.com", risk_level="high", risk_state="at_risk")
    lab.typed("investigate_user", "pwhite@example.com", "entra", kind="anomaly", anomaly_id="risk-1",
              anomaly_type="unfamiliar_location", severity="HIGH", user="pwhite@example.com", ip="203.0.113.140")
    run = _run(lab)
    (user,) = _facts(run)["exposed_users"]
    assert user["compromised"] and user["disable"]
    anomaly_ids = {r.record_id for r in run.index.records() if str(r.kind) == "anomaly"}
    assert anomaly_ids and anomaly_ids <= set(user["disable_record_ids"])
    assert "disable_user:pwhite@example.com" in _proposed(run)


def test_a_user_only_named_by_the_incident_is_not_exposed():
    lab = _lab()
    _endpoint(lab, users=("jsmith@example.com",))
    _detection(lab, sha=None)
    _profile(lab, "jsmith@example.com")
    _profile(lab, "bob.martin@example.com", roles=["Global Administrator"])
    run = _run(lab, users=("bob.martin@example.com",))
    assert [u["user"] for u in _facts(run)["exposed_users"]] == ["jsmith@example.com"]
    assert not any("bob.martin" in s for s in _proposed(run))


def test_identity_outage_keeps_the_revocation_and_lists_the_disable_as_considered():
    lab = _lab()
    _endpoint(lab, users=("it.support@example.com",))
    _detection(lab, sha=None)
    _profile(lab, "it.support@example.com", roles=["Helpdesk Administrator"], privileged=True)
    lab.environment.set_health("entra", HealthStatus.UNAVAILABLE)
    lab.environment.inject("UNAVAILABLE", integration="entra", operation="investigate", times=10)
    run = _run(lab)
    assert "entra" in run.degraded_sources()
    (user,) = _facts(run)["exposed_users"]
    assert not user["assessed"] and not user["disable"]
    assert "revoke_sessions:it.support@example.com" in _proposed(run)
    assert "disable_user:it.support@example.com" not in _proposed(run)
    assert "entra" in _considered(run)["disable_user:it.support@example.com"]


# ----------------------------------------------------------- domain controller --
def test_a_domain_controller_gets_the_domain_wide_manual_step_and_its_accounts_stay_proposed():
    lab = _lab()
    _endpoint(lab, "DC-02", users=("infra.admin@example.com",), groups=["Domain Controllers"],
              connector_guid="00000000-0000-4000-8000-0000000000d2")
    _detection(lab, host="DC-02", sha=None, name="Unexpected copy of the directory database",
               techniques=("T1003.003",))
    _profile(lab, "infra.admin@example.com", groups=["Domain Admins"])
    run = _run(lab, (ObservableType.HOSTNAME, "DC-02"))
    facts = _facts(run)
    assert facts["domain_controllers"] == ["DC-02"]
    assert "domain controller" in facts["credential_hosts"][0]["summary"]
    assert _manual(run) == {"domain-credential-reset:DC-02"}
    assert _proposed(run) == {"isolate_endpoint:DC-02", "revoke_sessions:infra.admin@example.com",
                              "disable_user:infra.admin@example.com"}
    built = {f"{b.action_type.value}:{b.target}": b for b in run.built}
    assert built["isolate_endpoint:DC-02"].warnings  # preview; PackageBuilder decides ELEVATED


def test_ntds_access_marks_a_domain_controller_even_without_the_critical_asset_class():
    lab = _lab()
    _endpoint(lab, "TH-SRV-0009", users=(), groups=["Servers"])
    _detection(lab, host="TH-SRV-0009", sha=None, name="ntds database copied", techniques=())
    run = _run(lab, (ObservableType.HOSTNAME, "TH-SRV-0009"))
    assert _facts(run)["credential_hosts"][0]["domain_controller"]
    assert _manual(run) == {"domain-credential-reset:TH-SRV-0009"}


# ----------------------------------------------------------- isolation limits --
def test_an_endpoint_whose_policy_forbids_isolation_is_considered():
    lab = _lab()
    _endpoint(lab, isolation_capable=False)
    _detection(lab, sha=None)
    run = _run(lab)
    assert f"isolate_endpoint:{HOST}" not in _proposed(run)
    assert "forbids isolation" in _considered(run)[f"isolate_endpoint:{HOST}"]
    assert _manual(run) == {f"credential-reset:{HOST}"}


def test_an_endpoint_unknown_to_both_edr_products_is_considered():
    lab = _lab()
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST,
              users=["jsmith@example.com"], isolation_state="unknown")
    _detection(lab, sha=None)
    run = _run(lab)
    assert f"isolate_endpoint:{HOST}" not in _proposed(run)
    assert "isolate it by hand" in _considered(run)[f"isolate_endpoint:{HOST}"]
    assert "revoke_sessions:jsmith@example.com" in _proposed(run)


# ------------------------------------------------------ hand-offs and links --
def test_exposed_accounts_are_handed_off_to_account_takeover_with_records():
    lab = _lab()
    _endpoint(lab, users=("jsmith@example.com", "it.support@example.com"))
    _detection(lab, sha=None)
    run = _run(lab)
    (handoff,) = run.handoffs
    assert handoff.workflow_id == "account-takeover"
    assert set(handoff.subjects) == {"jsmith@example.com", "it.support@example.com"}
    assert handoff.record_ids and set(handoff.record_ids) <= set(run.index.ids())
    assert any(n.startswith("hand-off: run account-takeover") for n in run.notes)


def test_exposure_links_tie_the_endpoint_to_its_accounts():
    lab = _lab()
    _endpoint(lab, users=("jsmith@example.com", "it.support@example.com"))
    _detection(lab, sha=None)
    run = _run(lab)
    links = [link for link in run.correlation.links if link.kind is LinkKind.WORKFLOW]
    assert len(links) == 1 and links[0].origin == "workflow:credential-dumping"
    assert {e.value for e in links[0].entities} == {HOST, "jsmith@example.com", "it.support@example.com"}
    assert "credential exposure" in links[0].note


def test_hooks_contribute_nothing_for_an_empty_run():
    lab = _lab()
    run = _run(lab)
    view = _view(run)
    assert _facts(run) == {"credential_hosts": [], "exposed_users": [], "hashes": [], "domain_controllers": []}
    assert list(HOOKS.considered(view)) == [] and list(HOOKS.handoffs(view)) == []
    assert list(HOOKS.correlate(view)) == []
    assert run.proposals == ()
