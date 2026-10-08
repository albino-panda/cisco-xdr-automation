"""Cloud-compromise hooks and rules on the simulated read-only lab (no lifecycle, no writes)."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.evidence import EvidenceBuilder
from xdr_response.integrations.simulated import FaultKind
from xdr_response.models import ActionType, ObservableType, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.cloud_compromise import HOOKS, WORKFLOW
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

SUITE: Mapping[str, tuple[str, ...]] = {
    "entra": ("identity",), "microsoft_cloud": ("identity",), "cisco_xdr": ("intel",), "meraki": ("network",),
}
USER = "jsmith@example.com"
OTHER = "kmorris@example.com"
ATTACKER = "203.0.113.145"
OFFICE = "198.51.100.10"
APP = "00000000-0000-4000-8000-0000000c9001"
ROLE_ID = "00000000-0000-4000-8000-0000000000e1"
O = ObservableType


@pytest.fixture()
def lab() -> Lab:
    return make_lab(SUITE)


def _incident(*users: str):
    users = users or (USER,)
    return make_incident(*((O.USER, u) for u in users), workflow_id="cloud-compromise",
                         title="New client secret on app registration", users=users, incident_id="XDR-CC-U-1")


def _run(lab: Lab, incident=None, *, dry_run: bool = True) -> WorkflowRun:
    return lab.runner.run(WORKFLOW, HOOKS, incident or _incident(), dry_run=dry_run)


def _view(lab: Lab, incident=None) -> RunView:
    incident = incident or _incident()
    run = _run(lab, incident)
    return RunView(workflow=WORKFLOW, incident=incident, results=run.results, index=run.index,
                   correlation=run.correlation, blast_radius=run.blast_radius)


def _proposed(run: WorkflowRun) -> set[str]:
    return {f"{p.action_type.value}:{p.target}" for p in run.proposals}


def _considered(run: WorkflowRun, *, manual: bool) -> set[str]:
    return {c.subject for c in run.considered if c.manual is manual}


def _profile(lab: Lab, user: str = USER, **fields: Any) -> None:
    lab.typed("investigate_user", user, "entra", kind="user_profile", user=user, account_enabled=True,
              **{"risk_level": "high", "risk_state": "at_risk", **fields})


def _sign_in(lab: Lab, sid: str, ip: str, *, user: str = USER, result: str = "success", at: str = "10:05",
             **fields: Any) -> None:
    lab.typed("investigate_authentication", user, "entra", kind="sign_in", sign_in_id=sid, user=user,
              timestamp=f"2026-01-15T{at}:00Z", ip=ip, app="Azure Portal", result=result, **fields)


def _reputation(lab: Lab, ip: str, verdict: Verdict, risk: int = 90) -> None:
    lab.environment.set_reputation(O.IP, ip, verdict, risk_score=risk, confidence=80, integrations=["cisco_xdr"])


def _app(lab: Lab, user: str = USER, integration: str = "entra", **fields: Any) -> None:
    lab.typed("search_user_activity", user, integration, kind="cloud_app",
              **{"app_id": APP, "display_name": "Report Sync (test)", "publisher_verified": False,
                 "permissions": ["Mail.Read", "offline_access"], **fields})


def _role(lab: Lab, subject: str, **fields: Any) -> None:
    lab.typed("search_user_activity", subject, "entra", kind="role_change",
              **{"role_name": "Global Administrator", "role_definition_id": ROLE_ID, "change": "assigned",
                 "privileged": True, "timestamp": "2026-01-15T10:20:00Z", **fields})


def _compromise(lab: Lab, user: str = USER, **profile: Any) -> None:
    _profile(lab, user, **profile)
    _sign_in(lab, f"si-{user}", ATTACKER, user=user)
    _reputation(lab, ATTACKER, Verdict.MALICIOUS)


def _no_errors(run: WorkflowRun) -> None:
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)
    assert not [n for n in run.notes if n.startswith("hook ")], run.notes


# -------------------------------------------------------------- compromise --
def test_a_compromised_account_is_revoked_and_the_attacker_ip_blocked_with_cited_evidence(lab):
    _compromise(lab)
    _sign_in(lab, "si-office", OFFICE, at="08:00")
    _reputation(lab, OFFICE, Verdict.CLEAN, risk=0)
    run = _run(lab)
    _no_errors(run)
    assert _proposed(run) == {f"revoke_sessions:{USER}", f"block_ip:{ATTACKER}"}
    builder = EvidenceBuilder(run.index)
    for proposal in run.proposals:
        builder.verify(proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
    revoke = next(p for p in run.proposals if p.action_type is ActionType.REVOKE_SESSIONS)
    assert not [e for e in revoke.evidence if e.data["fields"].get("ip") == OFFICE], "the office sign-in is context"
    assert "refresh tokens" in revoke.rationale
    assert lab.environment.state_changing_calls() == []


def test_a_privileged_role_alone_never_triggers_anything(lab):
    _profile(lab, risk_level="none", risk_state="none", roles=["Cloud Application Administrator"], privileged=True)
    _sign_in(lab, "si-office", OFFICE)
    _reputation(lab, OFFICE, Verdict.CLEAN, risk=0)
    _app(lab, publisher_verified=True, credential_added_at="2026-01-15T10:10:00Z", verdict="CLEAN")
    run = _run(lab)
    _no_errors(run)
    assert run.proposals == () and run.outcomes == () and run.considered == () and run.handoffs == ()


def test_medium_risk_with_detections_revokes_but_never_disables(lab):
    _profile(lab, risk_level="medium", roles=["Application Administrator"], privileged=True)
    _sign_in(lab, "si-office", OFFICE)
    _reputation(lab, OFFICE, Verdict.CLEAN, risk=0)
    lab.typed("investigate_authentication", USER, "entra", kind="anomaly", anomaly_id="rd-new-device",
              anomaly_type="new_device", severity="MEDIUM", user=USER, ip=OFFICE)
    facts = HOOKS.facts(_view(lab))
    user = facts["users"][0]
    assert user["compromised"] and not user["strong"]
    assert facts["disable_users"] == [], "a weak indicator never disables, even a privileged account"
    assert [u["user"] for u in facts["revoke_users"]] == [USER]


def test_a_privileged_compromised_account_is_disabled(lab):
    _compromise(lab, roles=["Application Administrator"])
    run = _run(lab)
    _no_errors(run)
    assert f"disable_user:{USER}" in _proposed(run)
    disable = next(p for p in run.proposals if p.action_type is ActionType.DISABLE_USER)
    assert "privileged account (Application Administrator)" in disable.rationale


def test_a_malicious_cloud_alert_is_a_strong_indicator_without_any_sign_in(lab):
    _profile(lab, risk_level="low", risk_state="none")
    lab.typed("search_user_activity", USER, "microsoft_cloud", kind="detection", detection_id="da-1",
              name="Suspicious OAuth app consent", verdict="MALICIOUS", severity="HIGH", user=USER, status="active")
    facts = HOOKS.facts(_view(lab))
    user = facts["users"][0]
    assert user["compromised"] and user["strong"]
    assert "cloud alert rated malicious (Suspicious OAuth app consent)" in user["indicators"]


def test_a_resolved_cloud_alert_is_not_an_indicator(lab):
    _profile(lab, risk_level="low", risk_state="none")
    lab.typed("search_user_activity", USER, "microsoft_cloud", kind="detection", detection_id="da-2",
              name="Suspicious OAuth app consent", verdict="MALICIOUS", severity="HIGH", user=USER,
              status="resolved")
    run = _run(lab)
    assert run.proposals == ()
    assert HOOKS.facts(_view(lab))["compromised_users"] == []


# -------------------------------------------------------------- applications --
def test_a_credential_added_by_a_compromised_account_disables_it_and_lists_manual_steps(lab):
    _compromise(lab)
    _app(lab, credential_added_at="2026-01-15T10:20:00Z")
    run = _run(lab)
    _no_errors(run)
    assert _proposed(run) == {f"revoke_sessions:{USER}", f"disable_user:{USER}", f"block_ip:{ATTACKER}"}
    assert _considered(run, manual=True) == {f"remove-app-credentials:{APP}", f"disable-service-principal:{APP}"}
    disable = next(p for p in run.proposals if p.action_type is ActionType.DISABLE_USER)
    assert "added a credential to application 'Report Sync (test)'" in disable.rationale
    assert {e.data["kind"] for e in disable.evidence} >= {"cloud_app", "sign_in", "user_profile"}
    for item in run.considered:
        assert set(item.record_ids) <= set(run.index.ids())


def test_a_user_consent_to_a_malicious_app_revokes_the_consenting_account_only(lab):
    _profile(lab, risk_level="low", risk_state="none")
    _app(lab, integration="microsoft_cloud", consent_type="user", consented_by=USER, verdict="MALICIOUS")
    run = _run(lab)
    _no_errors(run)
    assert _proposed(run) == {f"revoke_sessions:{USER}"}
    assert run.handoffs == (), "a consent alone does not show the credentials are in attacker hands"
    assert _considered(run, manual=True) == {f"revoke-oauth-consent:{APP}", f"disable-service-principal:{APP}"}
    revoke = run.proposals[0]
    assert "consented to risky OAuth application 'Report Sync (test)'" in revoke.rationale
    assert "cloud_app" in {e.data["kind"] for e in revoke.evidence}


def test_an_admin_consent_by_an_uncompromised_admin_is_considered_not_proposed(lab):
    _profile(lab, risk_level="none", risk_state="none", roles=["Cloud Application Administrator"])
    _app(lab, integration="microsoft_cloud", consent_type="admin", consented_by=USER, verdict="SUSPICIOUS")
    run = _run(lab)
    _no_errors(run)
    assert run.proposals == ()
    assert _considered(run, manual=False) == {f"revoke_sessions:{USER}"}
    assert _considered(run, manual=True) == {f"revoke-oauth-consent:{APP}", f"disable-service-principal:{APP}"}


def test_an_admin_consent_by_a_compromised_admin_is_planted_persistence(lab):
    _compromise(lab)
    _app(lab, consent_type="admin", consented_by=USER, verdict="SUSPICIOUS")
    facts = HOOKS.facts(_view(lab))
    user = facts["users"][0]
    assert user["disable_reasons"] == ["granted tenant-wide consent to risky application 'Report Sync (test)'"]


def test_an_unrated_verified_app_is_not_risky(lab):
    _compromise(lab)
    _app(lab, publisher_verified=True, consent_type="user", consented_by=USER)
    facts = HOOKS.facts(_view(lab))
    assert facts["risky_apps"] == []


def test_an_uncompromised_owner_of_a_rated_app_is_considered_for_disable(lab):
    _profile(lab, risk_level="low", risk_state="none")
    _app(lab, integration="microsoft_cloud", credential_added_at="2026-01-14T16:00:00Z", verdict="SUSPICIOUS")
    run = _run(lab)
    assert run.proposals == ()
    assert _considered(run, manual=False) == {f"disable_user:{USER}"}
    assert _considered(run, manual=True) == {f"remove-app-credentials:{APP}", f"disable-service-principal:{APP}"}


# --------------------------------------------------------------------- roles --
def test_a_role_granted_by_a_compromised_account_is_removed_and_always_elevated(lab):
    _compromise(lab, roles=["Privileged Role Administrator"])
    _role(lab, USER, user="backup-ops@example.com", actor=USER)
    run = _run(lab)
    _no_errors(run)
    target = f"backup-ops@example.com/{ROLE_ID}"
    assert f"remove_privileged_role:{target}" in _proposed(run)
    removal = next(p for p in run.proposals if p.action_type is ActionType.REMOVE_PRIVILEGED_ROLE)
    assert "granted by compromised account jsmith@example.com" in removal.rationale
    assert {e.data["kind"] for e in removal.evidence} >= {"role_change", "sign_in"}
    disable = next(p for p in run.proposals if p.action_type is ActionType.DISABLE_USER)
    assert "granted privileged role Global Administrator to backup-ops@example.com" in disable.rationale


def test_a_role_received_by_a_compromised_account_is_removed(lab):
    _compromise(lab)
    _role(lab, USER, user=USER, actor="it-admin@example.com", role_name="Application Administrator")
    facts = HOOKS.facts(_view(lab))
    assert [r["target"] for r in facts["remove_roles"]] == [f"{USER}/{ROLE_ID}"]
    assert facts["users"][0]["privileged"], "a privileged role received during the incident makes it privileged"


def test_a_role_removed_later_is_not_proposed_again(lab):
    _compromise(lab)
    _role(lab, USER, user="backup-ops@example.com", actor=USER)
    _role(lab, USER, user="backup-ops@example.com", actor="it-admin@example.com", change="removed",
          timestamp="2026-01-15T10:40:00Z")
    facts = HOOKS.facts(_view(lab))
    assert facts["remove_roles"] == []


def test_a_grant_between_uncompromised_accounts_is_considered(lab):
    _profile(lab, risk_level="none", risk_state="none")
    _role(lab, USER, user=USER, actor="id-team@example.com", role_name="Exchange Administrator")
    run = _run(lab)
    assert run.proposals == ()
    assert _considered(run, manual=False) == {f"remove_privileged_role:{USER}/{ROLE_ID}"}


def test_a_role_change_without_a_role_id_is_a_manual_step(lab):
    _compromise(lab)
    _role(lab, USER, user="backup-ops@example.com", actor=USER, role_definition_id=None)
    run = _run(lab)
    _no_errors(run)
    assert not [p for p in run.proposals if p.action_type is ActionType.REMOVE_PRIVILEGED_ROLE]
    assert "remove-role:backup-ops@example.com/Global Administrator" in _considered(run, manual=True)


def test_a_non_privileged_role_is_ignored(lab):
    _compromise(lab)
    _role(lab, USER, user="backup-ops@example.com", actor=USER, role_name="Reports Reader", privileged=False)
    facts = HOOKS.facts(_view(lab))
    assert facts["remove_roles"] == []


# ----------------------------------------------------------------------- IPs --
def test_a_suspicious_ip_is_blocked_only_after_a_high_risk_account_signed_in(lab):
    _profile(lab, risk_level="medium")
    _sign_in(lab, "si-sus", "198.51.100.77")
    _reputation(lab, "198.51.100.77", Verdict.SUSPICIOUS, risk=60)
    facts = HOOKS.facts(_view(lab))
    assert facts["block_ips"] == []
    lab2 = make_lab(SUITE)
    _profile(lab2, risk_level="high")
    _sign_in(lab2, "si-sus", "198.51.100.77")
    _reputation(lab2, "198.51.100.77", Verdict.SUSPICIOUS, risk=60)
    assert [i["ip"] for i in HOOKS.facts(_view(lab2))["block_ips"]] == ["198.51.100.77"]


def test_failed_sign_ins_from_a_malicious_ip_block_the_ip_but_touch_no_account(lab):
    _profile(lab, risk_level="low", risk_state="none")
    _sign_in(lab, "si-fail", ATTACKER, result="failure")
    _reputation(lab, ATTACKER, Verdict.MALICIOUS)
    run = _run(lab)
    _no_errors(run)
    assert _proposed(run) == {f"block_ip:{ATTACKER}"}
    assert run.handoffs == ()


# ---------------------------------------------------- hand-offs and signals --
def test_compromised_accounts_are_handed_off_to_account_takeover(lab):
    _compromise(lab)
    _compromise(lab, OTHER)
    run = _run(lab, _incident(USER, OTHER))
    _no_errors(run)
    assert [(h.workflow_id, set(h.subjects)) for h in run.handoffs] == [("account-takeover", {USER, OTHER})]
    assert set(run.handoffs[0].record_ids) <= set(run.index.ids())


def test_derived_signals_cite_their_own_integration(lab):
    _compromise(lab)
    _app(lab, credential_added_at="2026-01-15T10:20:00Z")
    view = _view(lab)
    signals = list(HOOKS.derive_signals(view))
    assert signals
    for signal in signals:
        assert signal.origin == "workflow:cloud-compromise"
        cited = [view.index.get(i) for i in signal.record_ids]
        assert signal.integration in {r.integration for r in cited}
    categories = {s.category for s in signals}
    assert {SignalCategory.AUTHENTICATION_ANOMALY, SignalCategory.PERSISTENCE} <= categories


def test_hooks_are_pure_and_deterministic(lab):
    _compromise(lab)
    _app(lab, credential_added_at="2026-01-15T10:20:00Z")
    _role(lab, USER, user="backup-ops@example.com", actor=USER)
    view = _view(lab)
    assert HOOKS.facts(view) == HOOKS.facts(view)
    assert list(HOOKS.considered(view)) == list(HOOKS.considered(view))
    assert lab.environment.state_changing_calls() == []


# --------------------------------------------------------------- degradation --
def test_a_failed_defender_source_never_blocks_the_identity_evidence(lab):
    _compromise(lab)
    lab.environment.inject(FaultKind.UNAVAILABLE, integration="microsoft_cloud", operation="investigate", times=None)
    run = _run(lab)
    _no_errors(run)
    assert "microsoft_cloud" in run.degraded_sources()
    assert {f"revoke_sessions:{USER}", f"block_ip:{ATTACKER}"} <= _proposed(run)


def test_dry_run_and_live_recommend_the_same_package(lab):
    _compromise(lab)
    _app(lab, credential_added_at="2026-01-15T10:20:00Z")
    dry = _run(lab, dry_run=True)
    live_lab = make_lab(SUITE, dry_run=False)
    _compromise(live_lab)
    _app(live_lab, credential_added_at="2026-01-15T10:20:00Z")
    live = _run(live_lab, dry_run=False)
    assert _proposed(dry) == _proposed(live)
    assert [(p.risk_score, p.confidence_score) for p in dry.proposals] == \
        [(p.risk_score, p.confidence_score) for p in live.proposals]
