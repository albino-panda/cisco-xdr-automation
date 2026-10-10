"""Privilege-escalation hooks and rules on the simulated read-only lab (no lifecycle, no writes)."""
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
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.privilege_escalation import HOOKS, WORKFLOW
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

SUITE: Mapping[str, tuple[str, ...]] = {
    "secure_endpoint": ("endpoint",), "entra": ("identity",), "virustotal": ("intel",),
}
HOST = "TH-LT-1047"
USER = "jsmith@example.com"
NEW = "svc-sync-temp@example.com"
OTHER = "bwhite@example.com"
ROLE_ID = "00000000-0000-4000-8000-0000000000e1"
APP = "00000000-0000-4000-8000-0000000c9101"
SHA = "7d1a0c3e" * 8
O = ObservableType


@pytest.fixture()
def lab() -> Lab:
    return make_lab(SUITE)


def _incident(*observables: tuple[ObservableType, str], users: tuple[str, ...] = (USER,), **extra: Any):
    observables = observables or ((O.USER, USER),)
    return make_incident(*observables, workflow_id="privilege-escalation", users=users,
                         title="Privileged role assigned", incident_id="XDR-PE-U-1", **extra)


def _run(lab: Lab, incident=None) -> WorkflowRun:
    return lab.runner.run(WORKFLOW, HOOKS, incident or _incident(), dry_run=True)


def _view(lab: Lab, incident=None) -> RunView:
    incident = incident or _incident()
    run = _run(lab, incident)
    return RunView(workflow=WORKFLOW, incident=incident, results=run.results, index=run.index,
                   correlation=run.correlation, blast_radius=run.blast_radius)


def _proposed(run: WorkflowRun) -> set[str]:
    return {f"{p.action_type.value}:{p.target}" for p in run.proposals}


def _considered(run: WorkflowRun, *, manual: bool) -> set[str]:
    return {c.subject for c in run.considered if c.manual is manual}


def _reason(run: WorkflowRun, subject: str) -> str:
    return next(c.reason for c in run.considered if c.subject == subject)


def _profile(lab: Lab, user: str = USER, **fields: Any) -> None:
    lab.typed("investigate_user", user, "entra", kind="user_profile", user=user, account_enabled=True,
              **{"risk_level": "none", "risk_state": "none", **fields})


def _sign_in(lab: Lab, sid: str, *, user: str = USER, at: str = "09:00", **fields: Any) -> None:
    lab.typed("investigate_authentication", user, "entra", kind="sign_in", sign_in_id=sid, user=user,
              timestamp=f"2026-01-15T{at}:00Z", ip="198.51.100.20", app="Azure Portal",
              **{"result": "success", "risk_level": "none", **fields})


def _role(lab: Lab, subject: str, *, user: str, actor: str | None, at: str = "10:12", **fields: Any) -> None:
    lab.typed("search_user_activity", subject, "entra", kind="role_change", user=user, actor=actor,
              timestamp=f"2026-01-15T{at}:00Z",
              **{"role_name": "Global Administrator", "role_definition_id": ROLE_ID, "change": "assigned",
                 "privileged": True, **fields})


def _compromised(lab: Lab, user: str = USER) -> None:
    """A strong identity compromise: high identity risk and a high-risk successful sign-in."""
    _profile(lab, user, risk_level="high", risk_state="at_risk")
    _sign_in(lab, f"si-risky-{user}", user=user, at="09:30", risk_level="high")


def _exploited_host(lab: Lab, host: str = HOST, user: str = USER, *, verdict: str = "MALICIOUS",
                    capable: bool | None = True, **endpoint: Any) -> None:
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host,
              users=[user], isolation_capable=capable,
              **{"connector_guid": "00000000-0000-4000-8000-000000001047", **endpoint})
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", detection_id=f"det-{host}",
              name="Exploit Prevention - local privilege escalation", verdict=verdict, severity="HIGH",
              endpoint=host, user=user, mitre_techniques=["T1068"], status="active",
              first_seen="2026-01-15T10:00:00Z")


def _no_errors(run: WorkflowRun) -> None:
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)
    assert not [n for n in run.notes if n.startswith("hook ")], run.notes


def _facts(lab: Lab, incident=None) -> Mapping[str, Any]:
    return HOOKS.facts(_view(lab, incident))


# ------------------------------------------------------------ anomalous vs normal --
def test_a_grant_by_a_compromised_account_is_anomalous_and_fully_contained_with_cited_evidence(lab):
    _compromised(lab)
    _role(lab, USER, user=NEW, actor=USER)
    _profile(lab, NEW)
    run = _run(lab)
    _no_errors(run)
    assert _proposed(run) == {f"remove_privileged_role:{NEW}/{ROLE_ID}", f"revoke_sessions:{USER}",
                              f"disable_user:{USER}", f"revoke_sessions:{NEW}", f"disable_user:{NEW}"}
    builder = EvidenceBuilder(run.index)
    for proposal in run.proposals:
        builder.verify(proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
        assert proposal.evidence, proposal.target
    removal = next(p for p in run.proposals if p.action_type is ActionType.REMOVE_PRIVILEGED_ROLE)
    assert f"granted by compromised account {USER}" in removal.rationale
    assert {e.data["fields"].get("role_name") for e in removal.evidence} >= {"Global Administrator"}
    assert lab.environment.state_changing_calls() == []


def test_who_when_reference_and_status_are_in_the_change_facts(lab):
    _compromised(lab)
    _role(lab, USER, user=NEW, actor=USER, directory_scope_id="/", reference="audit-0001")
    _profile(lab, NEW)
    facts = _facts(lab, _incident(trigger={"change_reference": "CHG0000001"}))
    (change,) = facts["changes"]
    assert change["user"] == NEW and change["actor"] == USER
    assert change["timestamp"].startswith("2026-01-15T10:12")
    assert change["status"] == "anomalous" and change["kind"] == "directory_role"
    assert change["source_reference"] == "audit-0001" and change["change_reference"] == "CHG0000001"
    assert change["directory_scope_id"] == "/"
    assert facts["remove_roles"] == [change]


def test_a_change_reference_never_withholds_an_anomalous_change(lab):
    _compromised(lab)
    _role(lab, USER, user=NEW, actor=USER)
    _profile(lab, NEW)
    run = _run(lab, _incident(trigger={"change_reference": "CHG0000001"}))
    assert f"remove_privileged_role:{NEW}/{ROLE_ID}" in _proposed(run)


def test_a_normal_grant_is_considered_with_the_unverified_change_reference(lab):
    _profile(lab, USER, roles=["Exchange Administrator"])
    _role(lab, USER, user=USER, actor="it-admin@example.com", role_name="Exchange Administrator")
    _profile(lab, "it-admin@example.com")
    run = _run(lab, _incident(trigger={"change_reference": "CHG0000002"}))
    _no_errors(run)
    assert run.proposals == ()
    subject = f"remove_privileged_role:{USER}/{ROLE_ID}"
    assert _considered(run, manual=False) == {subject}
    reason = _reason(run, subject)
    assert "normal change" in reason and "CHG0000002" in reason and "not verified" in reason


def test_a_self_assignment_is_anomalous_without_a_compromise_indicator(lab):
    _profile(lab, USER, last_sign_in="2026-01-15T08:00:00Z")
    _sign_in(lab, "si-normal", at="08:00")
    _role(lab, USER, user=USER, actor=USER)
    run = _run(lab)
    _no_errors(run)
    assert _proposed(run) == {f"remove_privileged_role:{USER}/{ROLE_ID}", f"revoke_sessions:{USER}"}
    assert _considered(run, manual=False) == {f"disable_user:{USER}"}
    assert "self-assigned" in next(p.rationale for p in run.proposals
                                   if p.action_type is ActionType.REMOVE_PRIVILEGED_ROLE)


def test_a_privileged_identity_management_activation_is_normal(lab):
    _profile(lab, USER, roles=["Global Administrator"], privileged=True)
    _role(lab, USER, user=USER, actor=USER, change="activated")
    run = _run(lab)
    assert run.proposals == ()
    assert _considered(run, manual=False) == {f"remove_privileged_role:{USER}/{ROLE_ID}"}


def test_a_grant_removed_later_is_not_proposed(lab):
    _compromised(lab)
    _role(lab, USER, user=NEW, actor=USER)
    _role(lab, USER, user=NEW, actor=USER, change="removed", at="10:40")
    _profile(lab, NEW)
    run = _run(lab)
    assert not [p for p in run.proposals if p.action_type is ActionType.REMOVE_PRIVILEGED_ROLE]
    assert f"revoke_sessions:{NEW}" not in _proposed(run)


def test_a_grant_that_predates_the_compromise_is_considered_not_removed(lab):
    _profile(lab, USER, risk_level="medium")
    lab.typed("investigate_authentication", USER, "entra", kind="anomaly", anomaly_id="rd-1",
              anomaly_type="unfamiliar_location", severity="HIGH", user=USER, first_seen="2026-01-15T09:30:00Z")
    _sign_in(lab, "si-risky", at="09:30")
    lab.typed("search_user_activity", USER, "entra", kind="role_change", user=OTHER, actor=USER,
              role_name="Global Administrator", role_definition_id=ROLE_ID, change="assigned", privileged=True,
              timestamp="2026-01-10T09:00:00Z")
    _profile(lab, OTHER)
    run = _run(lab)
    subject = f"remove_privileged_role:{OTHER}/{ROLE_ID}"
    assert subject not in _proposed(run)
    assert subject in _considered(run, manual=False)
    assert "pre-existing" in _reason(run, subject)


def test_an_unassessed_change_is_shown_never_proposed_on_a_guess(lab):
    _role(lab, USER, user=OTHER, actor=USER)
    _profile(lab, USER)
    lab.environment.inject(FaultKind.UNAVAILABLE, integration="entra", operation="investigate", target=OTHER,
                           times=None)
    run = _run(lab)
    assert run.proposals == ()
    subject = f"remove_privileged_role:{OTHER}/{ROLE_ID}"
    assert "could not be assessed" in _reason(run, subject) and "entra" in _reason(run, subject)


# ---------------------------------------------------------------- disable --
def test_an_account_with_no_prior_sign_in_made_privileged_by_the_change_is_disabled(lab):
    _exploited_host(lab)
    _profile(lab, USER, risk_level="medium")
    _role(lab, USER, user=NEW, actor=USER, role_name="User Administrator")
    _profile(lab, NEW)
    run = _run(lab, _incident((O.HOSTNAME, HOST), (O.USER, USER)))
    proposed = _proposed(run)
    assert f"disable_user:{NEW}" in proposed and f"revoke_sessions:{NEW}" in proposed
    assert f"disable_user:{USER}" not in proposed, "weak indicator: the actor is revoked, not disabled"
    assert f"disable_user:{USER}" in _considered(run, manual=False)
    disable = next(p for p in run.proposals if p.action_type is ActionType.DISABLE_USER)
    assert "no sign-in before it received the privilege" in disable.rationale


def test_an_established_grantee_is_revoked_not_disabled(lab):
    _compromised(lab)
    _role(lab, USER, user=OTHER, actor=USER)
    _profile(lab, OTHER)
    _sign_in(lab, "si-other", user=OTHER, at="07:45")
    run = _run(lab)
    assert f"revoke_sessions:{OTHER}" in _proposed(run)
    assert f"disable_user:{OTHER}" not in _proposed(run)
    assert "established account" in _reason(run, f"disable_user:{OTHER}")


def test_a_compromised_account_that_elevated_itself_is_disabled_even_with_a_weak_indicator(lab):
    _exploited_host(lab)
    _profile(lab, USER, risk_level="low")
    _role(lab, USER, user=USER, actor=USER, role_name="Domain Admins", role_definition_id=None, privileged=False)
    run = _run(lab, _incident((O.HOSTNAME, HOST), (O.USER, USER)))
    assert {f"revoke_sessions:{USER}", f"disable_user:{USER}", f"isolate_endpoint:{HOST}"} <= _proposed(run)
    assert _considered(run, manual=True) == {f"remove-group-membership:{USER}/Domain Admins"}


# ---------------------------------------------------- never shielded by the privilege --
def test_an_account_the_anomalous_change_made_privileged_is_passed_as_privileged(lab):
    """A group the source does not flag still makes the account privileged: ELEVATED, never shielded."""
    _exploited_host(lab)
    _profile(lab, USER, risk_level="low", groups=["Engineering"])
    _role(lab, USER, user=USER, actor=USER, role_name="Domain Admins", role_definition_id=None, privileged=False)
    run = _run(lab, _incident((O.HOSTNAME, HOST), (O.USER, USER)))
    account_actions = [p for p in run.proposals if p.target == USER]
    assert {p.action_type for p in account_actions} == {ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER}
    for proposal in account_actions:
        assert proposal.asset is not None and proposal.asset.privileged
        assert "never shielded" in proposal.rationale or "remove the privilege" in proposal.rationale
    built = [b for b in run.built if b.target == USER]
    assert built and all(b.elevation_expected for b in built)


def test_a_role_record_without_a_role_id_is_a_manual_step(lab):
    _compromised(lab)
    _role(lab, USER, user=NEW, actor=USER, role_name="Exchange Administrator", role_definition_id=None)
    _profile(lab, NEW)
    run = _run(lab)
    assert not [p for p in run.proposals if p.action_type is ActionType.REMOVE_PRIVILEGED_ROLE]
    assert _considered(run, manual=True) == {f"remove-role-assignment:{NEW}/Exchange Administrator"}
    assert f"revoke_sessions:{NEW}" in _proposed(run)


# ------------------------------------------------------------- applications --
def _app(lab: Lab, user: str = USER, **fields: Any) -> None:
    lab.typed("search_user_activity", user, "entra", kind="cloud_app",
              **{"app_id": APP, "display_name": "Directory Helper (test)", "publisher_verified": False,
                 "permissions": ["RoleManagement.ReadWrite.Directory"], "consent_type": "admin",
                 "consented_by": user, **fields})


def test_a_high_privilege_app_permission_by_a_compromised_admin_is_a_manual_step(lab):
    _compromised(lab)
    _app(lab)
    run = _run(lab)
    assert _considered(run, manual=True) == {f"revoke-app-permissions:{APP}"}
    assert {f"revoke_sessions:{USER}", f"disable_user:{USER}"} <= _proposed(run)
    assert not [p for p in run.proposals if APP in p.target], "an application is never a package target"


def test_a_high_privilege_app_permission_by_an_uncompromised_admin_is_only_considered(lab):
    _profile(lab, USER, roles=["Cloud Application Administrator"], privileged=True)
    _app(lab)
    run = _run(lab)
    assert run.proposals == ()
    assert _considered(run, manual=False) == {f"revoke-app-permissions:{APP}"}


def test_a_low_privilege_app_consent_is_not_a_privilege_change(lab):
    _compromised(lab)
    _app(lab, permissions=["User.Read"])
    facts = _facts(lab)
    assert facts["apps"] == []


# ------------------------------------------------------------------ endpoints --
def test_the_originating_endpoint_is_isolated_on_a_malicious_detection(lab):
    _exploited_host(lab)
    _profile(lab, USER)
    run = _run(lab, _incident((O.HOSTNAME, HOST), users=()))
    assert _proposed(run) == {f"isolate_endpoint:{HOST}"}
    isolation = run.proposals[0]
    assert isolation.params.get("connector_guid") == "00000000-0000-4000-8000-000000001047"
    assert "originating endpoint" in isolation.rationale


def test_a_file_rated_malicious_on_the_endpoint_is_enough_to_isolate(lab):
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST, users=[USER],
              connector_guid="00000000-0000-4000-8000-000000001047", isolation_capable=True)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="process_event", event_id="evt-1",
              endpoint=HOST, timestamp="2026-01-15T09:59:00Z", event_type="process_start", process_name="tool.exe",
              pid=4120, sha256=SHA)
    lab.environment.set_reputation(O.SHA256, SHA, Verdict.MALICIOUS, risk_score=90, confidence=85,
                                   integrations=["secure_endpoint", "virustotal"])
    run = _run(lab, _incident((O.HOSTNAME, HOST), users=()))
    assert _proposed(run) == {f"isolate_endpoint:{HOST}"}
    EvidenceBuilder(run.index).verify(run.proposals[0].evidence)


def test_a_sanctioned_binary_alone_never_isolates_its_host_or_contains_its_users(lab):
    rmm = "1" * 64  # config/allowlists.yaml approved_rmm (fake)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST, users=[USER],
              connector_guid="00000000-0000-4000-8000-000000001047", isolation_capable=True)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="process_event", event_id="evt-rmm-1",
              endpoint=HOST, timestamp="2026-01-15T09:59:00Z", event_type="process_start", process_name="rmmagent.exe",
              pid=3120, sha256=rmm, user=USER)
    lab.environment.set_reputation(O.SHA256, rmm, Verdict.MALICIOUS, risk_score=90, confidence=85,
                                   integrations=["secure_endpoint", "virustotal"])
    _profile(lab)
    _role(lab, USER, user=NEW, actor=USER)
    _profile(lab, NEW)
    incident = _incident((O.HOSTNAME, HOST), (O.USER, USER))
    facts = _facts(lab, incident)
    assert facts["isolate_hosts"][0]["binaries"] == [rmm]
    assert all(c["binaries"] == [rmm] for c in facts["anomalous_changes"])
    run = _run(lab, incident)
    _no_errors(run)
    assert run.proposals == ()
    withheld = {o.selector for o in run.outcomes_with(RuleOutcomeStatus.ALLOWLISTED)}
    assert {f"isolate_endpoint:{HOST}", f"revoke_sessions:{USER}", f"revoke_sessions:{NEW}",
            f"remove_privileged_role:{NEW}/{ROLE_ID}"} <= withheld
    assert f"isolate_endpoint:{HOST}" in _considered(run, manual=False)


def test_a_self_assignment_stands_on_its_own_beside_a_sanctioned_binary(lab):
    rmm = "1" * 64
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST, users=[USER],
              connector_guid="00000000-0000-4000-8000-000000001047", isolation_capable=True)
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="process_event", event_id="evt-rmm-1",
              endpoint=HOST, timestamp="2026-01-15T09:59:00Z", event_type="process_start", process_name="rmmagent.exe",
              pid=3120, sha256=rmm, user=USER)
    lab.environment.set_reputation(O.SHA256, rmm, Verdict.MALICIOUS, risk_score=90, confidence=85,
                                   integrations=["secure_endpoint", "virustotal"])
    _profile(lab)
    _role(lab, USER, user=USER, actor=USER)
    run = _run(lab, _incident((O.HOSTNAME, HOST), (O.USER, USER)))
    _no_errors(run)
    proposed = _proposed(run)
    assert f"isolate_endpoint:{HOST}" not in proposed
    assert {f"remove_privileged_role:{USER}/{ROLE_ID}", f"revoke_sessions:{USER}"} <= proposed


def test_a_suspicious_only_detection_is_considered_not_isolated(lab):
    _exploited_host(lab, verdict="SUSPICIOUS")
    run = _run(lab, _incident((O.HOSTNAME, HOST), users=()))
    assert run.proposals == ()
    assert "SUSPICIOUS detection only" in _reason(run, f"isolate_endpoint:{HOST}")


def test_an_endpoint_that_cannot_be_isolated_is_considered(lab):
    _exploited_host(lab, capable=False)
    run = _run(lab, _incident((O.HOSTNAME, HOST), users=()))
    assert run.proposals == ()
    assert "contain it by hand" in _reason(run, f"isolate_endpoint:{HOST}")


def test_an_endpoint_outage_never_blocks_the_identity_recommendations(lab):
    _compromised(lab)
    _role(lab, USER, user=NEW, actor=USER)
    _profile(lab, NEW)
    lab.environment.inject(FaultKind.UNAVAILABLE, integration="secure_endpoint", operation="investigate", times=None)
    run = _run(lab, _incident((O.HOSTNAME, HOST), (O.USER, USER)))
    assert "secure_endpoint" in run.degraded_sources()
    assert f"remove_privileged_role:{NEW}/{ROLE_ID}" in _proposed(run)


# ------------------------------------------------------- hand-offs and signals --
def test_compromised_accounts_are_handed_off_to_account_takeover(lab):
    _compromised(lab)
    _role(lab, USER, user=NEW, actor=USER)
    _profile(lab, NEW)
    run = _run(lab)
    assert [(h.workflow_id, h.subjects) for h in run.handoffs] == [("account-takeover", (USER,))]
    for handoff in run.handoffs:
        assert run.index.require(list(handoff.record_ids)), "a hand-off cites records of the run"


def test_signals_cite_the_role_change_records_of_their_own_integration(lab):
    _compromised(lab)
    _role(lab, USER, user=NEW, actor=USER)
    _profile(lab, NEW)
    view = _view(lab)
    signals = HOOKS.derive_signals(view)
    assert signals
    for signal in signals:
        assert signal.origin == "workflow:privilege-escalation"
        assert signal.category is SignalCategory.PERSISTENCE and signal.verdict is Verdict.MALICIOUS
        records = view.index.require(list(signal.record_ids))
        assert records and all(r.integration == signal.integration for r in records)


def test_hooks_return_json_facts_and_never_error(lab):
    _exploited_host(lab)
    _compromised(lab)
    _role(lab, USER, user=NEW, actor=USER)
    _profile(lab, NEW)
    _app(lab)
    run = _run(lab, _incident((O.HOSTNAME, HOST), (O.USER, USER)))
    _no_errors(run)
    json.dumps(HOOKS.facts(_view(lab, _incident((O.HOSTNAME, HOST), (O.USER, USER)))))
    assert lab.environment.state_changing_calls() == []
