"""Account-takeover hooks and rules on the simulated read-only lab (no lifecycle, no writes)."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.evidence import EvidenceBuilder
from xdr_response.integrations.simulated import FaultKind
from xdr_response.models import ActionType, ObservableType, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.account_takeover import HOOKS, WORKFLOW
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

SUITE: Mapping[str, tuple[str, ...]] = {
    "entra": ("identity",), "cisco_xdr": ("intel",), "microsoft_cloud": ("network",),
    "secure_endpoint": ("endpoint",), "meraki": ("network",),
}
USER = "jsmith@example.com"
ATTACKER = "203.0.113.145"
OFFICE = "198.51.100.10"
HOST = "TH-LT-1047"
O = ObservableType


@pytest.fixture()
def lab() -> Lab:
    return make_lab(SUITE)


def _incident(*observables: tuple[ObservableType, str], users: tuple[str, ...] = (USER,)):
    obs = observables or ((O.USER, USER),)
    return make_incident(*obs, workflow_id="account-takeover", title="Entra risky sign-in", users=users,
                         incident_id="XDR-ATO-U-1")


def _run(lab: Lab, incident=None, *, dry_run: bool = True) -> WorkflowRun:
    return lab.runner.run(WORKFLOW, HOOKS, incident or _incident(), dry_run=dry_run)


def _proposed(run: WorkflowRun) -> set[str]:
    return {f"{p.action_type.value}:{p.target}" for p in run.proposals}


def _facts(lab: Lab, incident=None) -> dict[str, Any]:
    run = _run(lab, incident)
    view = RunView(workflow=WORKFLOW, incident=incident or _incident(), results=run.results, index=run.index,
                   correlation=run.correlation, blast_radius=run.blast_radius)
    return dict(HOOKS.facts(view))


def _profile(lab: Lab, user: str = USER, **fields: Any) -> None:
    lab.typed("investigate_user", user, "entra", kind="user_profile", user=user, account_enabled=True,
              **{"risk_level": "medium", "risk_state": "at_risk", **fields})


def _sign_in(lab: Lab, sid: str, ip: str, *, user: str = USER, result: str = "success", at: str = "11:05",
             **fields: Any) -> None:
    lab.typed("investigate_authentication", user, "entra", kind="sign_in", sign_in_id=sid, user=user,
              timestamp=f"2026-01-15T{at}:00Z", ip=ip, app="Office 365 Exchange Online", result=result, **fields)


def _reputation(lab: Lab, ip: str, verdict: Verdict, risk: int = 90) -> None:
    lab.environment.set_reputation(O.IP, ip, verdict, risk_score=risk, confidence=80, integrations=["cisco_xdr"])


def _infected_laptop(lab: Lab, *, user: str = USER, status: str = "active", users=None) -> None:
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST,
              users=list(users if users is not None else [user]), groups=["Workstations"],
              isolation_state="not_isolated")
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="detection", detection_id="det-u-1",
              name="Infostealer.Generic", verdict="MALICIOUS", severity="HIGH", endpoint=HOST, user=user,
              status=status)


def _takeover(lab: Lab) -> None:
    _profile(lab)
    _sign_in(lab, "si-office", OFFICE, at="09:10")
    _sign_in(lab, "si-attacker", ATTACKER)
    _reputation(lab, ATTACKER, Verdict.MALICIOUS)
    _reputation(lab, OFFICE, Verdict.CLEAN, risk=0)


def _no_errors(run: WorkflowRun) -> None:
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)
    assert not [n for n in run.notes if n.startswith("hook ")], run.notes


# ---------------------------------------------------------------- compromise --
def test_a_success_from_a_malicious_ip_proposes_revoke_and_block_with_cited_evidence(lab):
    _takeover(lab)
    run = _run(lab)
    _no_errors(run)
    assert _proposed(run) == {f"revoke_sessions:{USER}", f"block_ip:{ATTACKER}"}
    builder = EvidenceBuilder(run.index)
    for proposal in run.proposals:
        builder.verify(proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
    revoke = next(p for p in run.proposals if p.action_type is ActionType.REVOKE_SESSIONS)
    kinds = {e.data["kind"] for e in revoke.evidence}
    assert {"sign_in", "enrichment", "user_profile"} <= kinds
    assert "successful sign-in from an IP rated malicious or suspicious (203.0.113.145)" in revoke.rationale
    office = [e for e in revoke.evidence if e.data["fields"].get("ip") == OFFICE]
    assert office == [], "the clean office sign-in is not evidence of the takeover"
    assert lab.environment.state_changing_calls() == []


def test_business_travel_with_a_clean_ip_is_not_a_takeover(lab):
    _profile(lab)
    _sign_in(lab, "si-travel", "198.51.100.77", mfa_result="satisfied")
    _reputation(lab, "198.51.100.77", Verdict.CLEAN, risk=0)
    lab.typed("investigate_authentication", USER, "entra", kind="anomaly", anomaly_id="rd-travel",
              anomaly_type="impossible_travel", severity="MEDIUM", user=USER, ip="198.51.100.77")
    run = _run(lab)
    _no_errors(run)
    assert run.proposals == () and run.outcomes == ()
    assert _facts(lab)["compromised_users"] == []


def test_failed_attempts_from_a_suspicious_ip_recommend_nothing(lab):
    _profile(lab, risk_level="low", risk_state="none")
    _sign_in(lab, "si-fail-1", "192.0.2.200", result="failure", at="07:58")
    _sign_in(lab, "si-fail-2", "192.0.2.200", result="failure", at="08:01")
    _reputation(lab, "192.0.2.200", Verdict.SUSPICIOUS, risk=45)
    run = _run(lab)
    assert run.proposals == ()
    facts = _facts(lab)
    assert facts["compromised_users"] == [] and facts["block_ips"] == []
    assert [i["ip"] for i in facts["ips"]] == ["192.0.2.200"]


def test_a_suspicious_only_ip_supports_revocation_but_is_not_blocked(lab):
    _profile(lab)
    _sign_in(lab, "si-sus", "192.0.2.201")
    _reputation(lab, "192.0.2.201", Verdict.SUSPICIOUS, risk=50)
    run = _run(lab)
    assert _proposed(run) == {f"revoke_sessions:{USER}"}


def test_a_high_user_risk_alone_recommends_revocation(lab):
    _profile(lab, risk_level="high")
    _sign_in(lab, "si-any", "192.0.2.202")
    run = _run(lab)
    assert _proposed(run) == {f"revoke_sessions:{USER}"}
    assert run.risk_score >= 50


def test_a_shared_ip_is_never_proposed_for_a_block(lab):
    _takeover(lab)
    lab.typed("search_ip_enterprise", ATTACKER, "microsoft_cloud", kind="network_connection", endpoint="TH-LT-0501",
              remote_ip=ATTACKER, remote_port=443, direction="outbound")
    run = _run(lab)
    assert _proposed(run) == {f"revoke_sessions:{USER}"}
    facts = _facts(lab)
    assert facts["shared_ips"] == [ATTACKER] and facts["block_ips"] == []


# ------------------------------------------------------------------ disable --
def test_a_privileged_compromised_account_is_also_disabled(lab):
    _profile(lab, roles=["Security Administrator"], privileged=True)
    _sign_in(lab, "si-attacker", ATTACKER)
    _reputation(lab, ATTACKER, Verdict.MALICIOUS)
    run = _run(lab)
    assert _proposed(run) == {f"revoke_sessions:{USER}", f"disable_user:{USER}", f"block_ip:{ATTACKER}"}
    disable = next(p for p in run.proposals if p.action_type is ActionType.DISABLE_USER)
    assert "privileged account (Security Administrator)" in disable.rationale
    assert disable.asset is not None and "Security Administrator" in disable.asset.roles


def test_a_privileged_role_assigned_by_the_attacker_counts(lab):
    _takeover(lab)
    lab.typed("search_user_activity", USER, "entra", kind="role_change", user=USER,
              role_name="Privileged Role Administrator", change="assigned", privileged=True, actor=USER,
              timestamp="2026-01-15T11:12:00Z")
    run = _run(lab)
    assert f"disable_user:{USER}" in _proposed(run)
    revoke = next(p for p in run.proposals if p.action_type is ActionType.REVOKE_SESSIONS)
    assert "role_change" in {e.data["kind"] for e in revoke.evidence}


def test_an_attacker_sign_in_after_the_revocation_disables_the_account(lab):
    _profile(lab, sessions_valid_from="2026-01-15T08:00:00Z")
    _sign_in(lab, "si-again", ATTACKER, at="09:40")
    _reputation(lab, ATTACKER, Verdict.MALICIOUS)
    run = _run(lab)
    assert f"disable_user:{USER}" in _proposed(run)
    assert any(s.note == "attacker sign-in after the sessions were revoked" for s in run.signals)


def test_a_sign_in_before_the_last_revocation_does_not_disable(lab):
    _profile(lab, sessions_valid_from="2026-01-15T11:30:00Z")
    _sign_in(lab, "si-before", ATTACKER, at="09:40")
    _reputation(lab, ATTACKER, Verdict.MALICIOUS)
    run = _run(lab)
    assert f"disable_user:{USER}" not in _proposed(run)
    assert f"revoke_sessions:{USER}" in _proposed(run)


# -------------------------------------------------------------- MFA / token --
def _mfa(lab: Lab, results: list[str]) -> None:
    for minute, result in enumerate(results):
        lab.typed("investigate_authentication", USER, "entra", kind="mfa_event", user=USER,
                  timestamp=f"2026-01-15T06:{minute:02d}:00Z", method="push", result=result, ip="192.0.2.177")


@pytest.mark.parametrize("results, compromised", [
    (["denied", "denied", "denied", "approved"], True),
    (["denied", "fraud_reported", "denied", "denied", "approved"], True),
    (["denied", "approved"], False),
    (["denied", "denied", "denied", "denied"], False),
])
def test_mfa_approval_after_repeated_denials(lab, results, compromised):
    _profile(lab)
    _mfa(lab, results)
    _sign_in(lab, "si-mfa", "192.0.2.177", at="06:30")
    run = _run(lab)
    assert (f"revoke_sessions:{USER}" in _proposed(run)) is compromised
    assert all(not a.startswith("block_ip") for a in _proposed(run)), "an IP without reputation is not blocked"


def test_a_token_replay_recommends_revocation(lab):
    _profile(lab)
    _sign_in(lab, "si-replay", "192.0.2.150")
    lab.typed("investigate_authentication", USER, "entra", kind="anomaly", anomaly_id="rd-replay",
              anomaly_type="token_replay", severity="MEDIUM", user=USER, ip="192.0.2.150")
    run = _run(lab)
    assert _proposed(run) == {f"revoke_sessions:{USER}"}


# ---------------------------------------------------------------- endpoints --
def test_an_infected_laptop_of_the_compromised_user_is_isolated(lab):
    _takeover(lab)
    _infected_laptop(lab)
    run = _run(lab, _incident((O.USER, USER), (O.HOSTNAME, HOST)))
    assert f"isolate_endpoint:{HOST}" in _proposed(run)
    isolate = next(p for p in run.proposals if p.action_type is ActionType.ISOLATE_ENDPOINT)
    kinds = {e.data["kind"] for e in isolate.evidence}
    # The endpoint's own records, plus the compromise records of the account the rationale names
    # ("endpoint ... of compromised account(s) ..."): the claim is backed by numbered evidence.
    assert {"detection", "endpoint"} <= kinds
    assert kinds & {"sign_in", "mfa_event", "anomaly", "user_profile", "role_change"}
    assert "could not be assessed" not in isolate.rationale


@pytest.mark.parametrize("change", [{"status": "resolved"}, {"user": "other@example.com", "users": []}])
def test_a_resolved_or_unlinked_detection_is_not_isolated(lab, change):
    _takeover(lab)
    _infected_laptop(lab, **change)
    run = _run(lab, _incident((O.USER, USER), (O.HOSTNAME, HOST)))
    assert f"isolate_endpoint:{HOST}" not in _proposed(run)


def test_a_laptop_is_not_isolated_when_no_account_is_compromised(lab):
    _profile(lab, risk_level="low")
    _infected_laptop(lab)
    run = _run(lab, _incident((O.USER, USER), (O.HOSTNAME, HOST)))
    assert run.proposals == ()


# ------------------------------------------------------- signals and safety --
def test_hook_signals_cite_run_records_of_their_own_source(lab):
    _takeover(lab)
    run = _run(lab)
    assert run.signals
    for signal in run.signals:
        assert signal.origin == "workflow:account-takeover"
        assert signal.category is SignalCategory.AUTHENTICATION_ANOMALY
        cited = run.index.require(signal.record_ids)
        assert signal.integration in {r.integration for r in cited}
        assert signal.vendor_verdict is False  # behaviour over sign-in records, not one vendor's word alone


def test_a_failed_reputation_source_never_blocks_the_revocation(lab):
    _profile(lab, risk_level="high")
    _sign_in(lab, "si-attacker", ATTACKER)
    _reputation(lab, ATTACKER, Verdict.MALICIOUS)
    lab.environment.inject(FaultKind.UNAVAILABLE, integration="cisco_xdr", operation="enrich", times=None)
    run = _run(lab)
    assert run.degraded_sources() == ("cisco_xdr",)
    assert _proposed(run) == {f"revoke_sessions:{USER}"}
    assert any(n.startswith("degraded source: cisco_xdr") for n in run.notes)


def test_dry_run_and_live_score_identically(lab):
    _takeover(lab)
    dry = _run(lab, dry_run=True)
    live = _run(lab, dry_run=False)
    assert [(p.action_type, p.target, p.risk_score, p.confidence_score) for p in dry.proposals] == \
           [(p.action_type, p.target, p.risk_score, p.confidence_score) for p in live.proposals]
    assert lab.environment.state_changing_calls() == []


def test_facts_are_json_and_empty_without_records(lab):
    facts = _facts(lab)
    assert json.loads(json.dumps(facts)) == facts
    assert facts["compromised_users"] == [] and facts["block_ips"] == [] and facts["endpoints"] == []
    assert facts["users"] == []


def test_an_incident_without_users_investigates_nothing_and_recommends_nothing(lab):
    run = _run(lab, _incident((O.IP, ATTACKER), users=()))
    _no_errors(run)
    assert run.proposals == ()
    assert any("step user_profile" in n for n in run.notes)
