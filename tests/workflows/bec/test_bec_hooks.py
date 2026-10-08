"""``bec`` hooks and rules over a simulated read-only lab (no network, fake data only).

The runner here is the production ``WorkflowRunner`` over simulated adapters; nothing is approved or
executed. These tests pin the workflow's own logic: what counts as identity compromise and mailbox
abuse, which messages and domains are recommended, that every fact and signal cites records of the
run, and that the look-alike heuristic is deterministic.
"""
from __future__ import annotations

from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.evidence import EvidenceBuilder
from xdr_response.models import ActionType, ObservableType, Verdict
from xdr_response.workflows.bec import HOOKS, WORKFLOW
from xdr_response.workflows.bec.hooks import is_lookalike, registrable_label, skeleton
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

SUITE = {"entra": ("identity",), "secure_email": ("email",), "secure_endpoint": ("endpoint",),
         "umbrella": ("network",), "cisco_xdr": ("intel",)}
USER = "jsmith@example.com"
MSG = "etd-msg-unit-0001"
BAD_IP = "203.0.113.80"


# ------------------------------------------------------------------ helpers --
def _lab() -> Lab:
    return make_lab(SUITE)


def _profile(lab: Lab, user: str = USER, **extra: Any) -> None:
    lab.typed("investigate_user", user, "entra", kind="user_profile", user=user, department="Finance",
              **{"risk_level": "medium", **extra})


def _rule(lab: Lab, rule_id: str, *, forward_to: tuple[str, ...] = ("invoices@remit-desk.example",),
          user: str = USER, **extra: Any) -> None:
    lab.typed("investigate_user", user, "entra", kind="mailbox_rule", mailbox=user, rule_id=rule_id,
              name=f"Rule {rule_id}", forward_to=list(forward_to), **{"enabled": True, **extra})


def _risky_sign_in(lab: Lab, user: str = USER, ip: str = BAD_IP) -> None:
    lab.typed("investigate_authentication", user, "entra", kind="sign_in", sign_in_id=f"si-{user}", user=user,
              timestamp="2026-01-15T09:10:00Z", ip=ip, result="success")
    lab.environment.set_reputation(ObservableType.IP, ip, Verdict.MALICIOUS, risk_score=85, confidence=80,
                                   integrations=["cisco_xdr"])


def _message(lab: Lab, message_id: str = MSG, *, sender: str = USER, verdict: str = "SUSPICIOUS",
             location: str = "inbox", atomic: str = "investigate_email", subject: str | None = None,
             direction: str = "internal", recipients: tuple[str, ...] = ("ap-clerk-02@example.com",)) -> None:
    lab.typed(atomic, subject or message_id, "secure_email", kind="email_message", message_id=message_id,
              sender=sender, sender_domain=sender.rpartition("@")[2], recipients=list(recipients),
              recipient_count=len(recipients), direction=direction, verdict=verdict, delivery_location=location)


def _run(lab: Lab, *observables: tuple[ObservableType, str], users: tuple[str, ...] = (USER,)) -> WorkflowRun:
    incident = make_incident(*observables, workflow_id="bec", title="BEC unit test", users=users)
    return lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)


def _proposed(run: WorkflowRun) -> set[str]:
    return {o.selector for o in run.outcomes_with(RuleOutcomeStatus.PROPOSED)}


def _facts(run: WorkflowRun, lab_incident_users: tuple[str, ...] = (USER,)) -> dict[str, Any]:
    incident = make_incident(workflow_id="bec", title="BEC unit test", users=lab_incident_users)
    view = RunView(workflow=WORKFLOW, incident=incident, results=run.results, index=run.index,
                   correlation=run.correlation, blast_radius=run.blast_radius)
    return dict(HOOKS.facts(view))


# --------------------------------------------------------------- look-alike --
@pytest.mark.parametrize("domain, org, expected", [
    ("examp1e.test", "example.com", True),           # homoglyph digit, other suffix
    ("exarnple.com", "example.com", True),           # rn -> m
    ("exampl.com", "example.com", True),             # one edit
    ("example-payments.test", "example.com", True),  # organisation name as a hyphenated token
    ("example.net", "example.com", True),            # same name, other suffix
    ("example.com", "example.com", False),           # the organisation itself
    ("pay.example.com", "example.com", False),       # a subdomain of the organisation
    ("vendor-supplies.example", "example.com", False),
    ("remit-desk.example", "example.com", False),
    ("abc.test", "abd.com", False),                  # organisation names under 4 characters are never compared
])
def test_lookalike_heuristic(domain, org, expected):
    assert is_lookalike(domain, org) is expected


def test_registrable_label_and_skeleton():
    assert registrable_label("pay.examp1e.test") == "examp1e"
    assert registrable_label("mail.example.co.uk") == "example"
    assert skeleton("examp1e") == skeleton("example")
    assert skeleton("rnicrosoft") == skeleton("microsoft")


# ------------------------------------------------------------------- rules --
def test_compromised_mailbox_gets_the_full_package_with_manual_rule_removal():
    lab = _lab()
    _profile(lab)
    _rule(lab, "rule-unit-1")
    _risky_sign_in(lab)
    _message(lab)
    run = _run(lab, (ObservableType.EMAIL_MESSAGE_ID, MSG), (ObservableType.EMAIL_ADDRESS, USER))
    assert _proposed(run) == {f"revoke_sessions:{USER}", f"disable_user:{USER}", f"quarantine_email:{MSG}"}
    revoke = next(p for p in run.proposals if p.action_type is ActionType.REVOKE_SESSIONS)
    assert "manual step after approval: remove mailbox rule 'Rule rule-unit-1' (id rule-unit-1)" in revoke.rationale
    assert "successful sign-in from 203.0.113.80 rated" in revoke.rationale
    assert lab.environment.state_changing_calls() == []


def test_external_forwarding_alone_revokes_but_does_not_disable():
    lab = _lab()
    _profile(lab, risk_level="none")
    _rule(lab, "rule-unit-2")
    run = _run(lab, (ObservableType.EMAIL_ADDRESS, USER))
    assert _proposed(run) == {f"revoke_sessions:{USER}"}


def test_risky_sign_in_alone_revokes_but_does_not_disable():
    lab = _lab()
    _profile(lab)
    _risky_sign_in(lab)
    run = _run(lab, (ObservableType.EMAIL_ADDRESS, USER))
    assert _proposed(run) == {f"revoke_sessions:{USER}"}


@pytest.mark.parametrize("rule_kwargs", [
    {"forward_to": ("colleague@corp.example.com",)},     # internal forwarding (exclusions.internal_domains)
    {"enabled": False},                                  # a disabled rule is context, not abuse
    {"forward_to": (), "move_to_folder": "Archive"},     # a filing rule
])
def test_benign_mailbox_rules_are_not_abuse(rule_kwargs):
    lab = _lab()
    _profile(lab, risk_level="none")
    _rule(lab, "rule-unit-3", **rule_kwargs)
    run = _run(lab, (ObservableType.EMAIL_ADDRESS, USER))
    assert _proposed(run) == set()
    assert _facts(run)["mailboxes"][0]["abuse"] is False


def test_deleting_rule_is_abuse():
    lab = _lab()
    _profile(lab, risk_level="none")
    _rule(lab, "rule-unit-4", forward_to=(), delete=True)
    run = _run(lab, (ObservableType.EMAIL_ADDRESS, USER))
    facts = _facts(run)["mailboxes"][0]
    assert facts["abuse"] and "deletes messages" in facts["summary"]
    assert _proposed(run) == {f"revoke_sessions:{USER}"}


def test_medium_anomalies_alone_are_not_compromise():
    lab = _lab()
    _profile(lab)
    lab.typed("investigate_authentication", USER, "entra", kind="anomaly", anomaly_id="an-unit-1",
              anomaly_type="unfamiliar_location", severity="MEDIUM", user=USER)
    run = _run(lab, (ObservableType.EMAIL_ADDRESS, USER))
    assert _proposed(run) == set()


def test_mfa_fraud_report_is_identity_compromise():
    lab = _lab()
    _profile(lab)
    lab.typed("investigate_authentication", USER, "entra", kind="mfa_event", user=USER,
              timestamp="2026-01-15T09:00:00Z", method="push", result="fraud_reported")
    run = _run(lab, (ObservableType.EMAIL_ADDRESS, USER))
    assert _facts(run)["mailboxes"][0]["identity_compromise"] is True
    assert f"revoke_sessions:{USER}" in _proposed(run)


def test_external_sender_never_gets_identity_actions_and_lookalike_domain_is_blocked():
    lab = _lab()
    _profile(lab, user="ap-clerk-02@example.com", risk_level="none")
    _message(lab, sender="cfo@examp1e.test", verdict="UNKNOWN", direction="inbound")
    run = _run(lab, (ObservableType.EMAIL_MESSAGE_ID, MSG), users=("ap-clerk-02@example.com",))
    assert _proposed(run) == {f"quarantine_email:{MSG}", "block_domain:examp1e.test"}


def test_clean_lookalike_domain_is_not_blocked_but_its_message_is_quarantined():
    lab = _lab()
    _message(lab, sender="ceo@example-pay.test", verdict="UNKNOWN", direction="inbound")
    lab.environment.set_reputation(ObservableType.DOMAIN, "example-pay.test", Verdict.CLEAN, risk_score=0,
                                   confidence=80, integrations=["umbrella"])
    run = _run(lab, (ObservableType.EMAIL_MESSAGE_ID, MSG), users=("ap-clerk-02@example.com",))
    assert _proposed(run) == {f"quarantine_email:{MSG}"}


def test_compromised_tenant_sender_domain_is_never_an_impersonation_domain():
    lab = _lab()
    _profile(lab)
    _risky_sign_in(lab)
    _message(lab)
    run = _run(lab, (ObservableType.EMAIL_MESSAGE_ID, MSG), (ObservableType.EMAIL_ADDRESS, USER))
    assert _facts(run)["impersonation_domains"] == []
    assert not any(o.action_type is ActionType.BLOCK_DOMAIN for o in run.outcomes)


def test_messages_already_out_of_the_mailbox_are_not_quarantined():
    lab = _lab()
    _profile(lab)
    _risky_sign_in(lab)
    _message(lab, location="quarantine")
    _message(lab, "etd-msg-unit-0002", atomic="search_email_campaign", subject=MSG)
    run = _run(lab, (ObservableType.EMAIL_MESSAGE_ID, MSG), (ObservableType.EMAIL_ADDRESS, USER))
    assert {o.target for o in run.outcomes_with(RuleOutcomeStatus.PROPOSED)
            if o.action_type is ActionType.QUARANTINE_EMAIL} == {"etd-msg-unit-0002"}


def test_unverified_oauth_app_with_mail_access_is_abuse():
    lab = _lab()
    _profile(lab)
    _risky_sign_in(lab)
    lab.typed("investigate_user", USER, "entra", kind="cloud_app", app_id="app-unit-1", display_name="Mail Helper",
              publisher_verified=False, permissions=["Mail.Send", "User.Read"], consent_type="user",
              consented_by=USER)
    run = _run(lab, (ObservableType.EMAIL_ADDRESS, USER))
    assert _proposed(run) == {f"revoke_sessions:{USER}", f"disable_user:{USER}"}
    disable = next(p for p in run.proposals if p.action_type is ActionType.DISABLE_USER)
    assert "revoke the OAuth consent of 'Mail Helper'" in disable.rationale


def test_verified_app_without_mail_access_is_context_only():
    lab = _lab()
    _profile(lab, risk_level="none")
    lab.typed("investigate_user", USER, "entra", kind="cloud_app", app_id="app-unit-2", display_name="Calendar",
              publisher_verified=True, permissions=["Calendars.Read"], consent_type="user", consented_by=USER)
    run = _run(lab, (ObservableType.EMAIL_ADDRESS, USER))
    assert _proposed(run) == set()


def test_infected_endpoint_is_isolated_and_resolved_detection_is_not():
    lab = _lab()
    lab.typed("investigate_endpoint", "TH-LT-1047", "secure_endpoint", kind="endpoint", hostname="TH-LT-1047",
              groups=["Workstations"])
    lab.typed("investigate_endpoint", "TH-LT-1047", "secure_endpoint", kind="detection", detection_id="det-unit-1",
              name="Infostealer.Generic", verdict="MALICIOUS", severity="HIGH", endpoint="TH-LT-1047",
              status="active")
    lab.typed("investigate_endpoint", "TH-LT-1048", "secure_endpoint", kind="detection", detection_id="det-unit-2",
              name="Infostealer.Generic", verdict="MALICIOUS", severity="HIGH", endpoint="TH-LT-1048",
              status="resolved")
    run = _run(lab, (ObservableType.HOSTNAME, "TH-LT-1047"), (ObservableType.HOSTNAME, "TH-LT-1048"))
    assert _proposed(run) == {"isolate_endpoint:TH-LT-1047"}


# -------------------------------------------------------- evidence & signals --
def _full_lab() -> tuple[Lab, WorkflowRun]:
    lab = _lab()
    _profile(lab)
    _rule(lab, "rule-unit-9")
    _risky_sign_in(lab)
    _message(lab)
    _message(lab, "etd-msg-unit-0009", sender="cfo@examp1e.test", verdict="SUSPICIOUS", direction="inbound")
    run = _run(lab, (ObservableType.EMAIL_MESSAGE_ID, MSG), (ObservableType.EMAIL_MESSAGE_ID, "etd-msg-unit-0009"),
               (ObservableType.EMAIL_ADDRESS, USER))
    return lab, run


def test_every_fact_signal_link_and_proposal_cites_records_of_the_run():
    _, run = _full_lab()
    facts = _facts(run)
    cited = [i for box in facts["mailboxes"] for key in ("profile_record_ids", "identity_record_ids",
                                                         "abuse_record_ids") for i in box[key]]
    cited += [i for m in facts["fraud_messages"] for i in m["record_ids"]]
    cited += [i for d in facts["impersonation_domains"] for i in d["record_ids"]]
    assert cited and all(i in run.index for i in cited)
    assert run.signals and all(s.origin == "workflow:bec" for s in run.signals)
    assert all(i in run.index for s in run.signals for i in s.record_ids)
    links = [lnk for lnk in run.correlation.links if lnk.origin == "workflow:bec"]
    assert links and all(i in run.index for lnk in links for i in lnk.record_ids)
    EvidenceBuilder(run.index).verify([d for p in run.proposals for d in p.evidence])
    for proposal in run.proposals:
        assert proposal.evidence
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
    assert not [n for n in run.notes if n.startswith("hook ")]
    assert not run.outcomes_with(RuleOutcomeStatus.ERROR)


def test_hooks_are_deterministic():
    _, first = _full_lab()
    _, second = _full_lab()
    assert _facts(first) == _facts(second)
    assert [o.model_dump() for o in first.outcomes] == [o.model_dump() for o in second.outcomes]
    assert first.signals == second.signals


def test_workflow_never_sets_an_approval_level():
    _, run = _full_lab()
    for proposal in run.proposals:
        dumped = proposal.model_dump(mode="json")
        assert "approval_level" not in dumped
        assert not {"approval_level", "requires_approval", "approve", "approved"} & set(dumped.get("params") or {})


def test_entra_outage_degrades_without_blocking_mail_evidence():
    lab = _lab()
    _message(lab, sender="cfo@examp1e.test", verdict="SUSPICIOUS", direction="inbound")
    lab.environment.inject("UNAVAILABLE", integration="entra", operation="investigate", times=None)
    run = _run(lab, (ObservableType.EMAIL_MESSAGE_ID, MSG), users=("ap-clerk-02@example.com",))
    assert "entra" in run.degraded_sources()
    assert _proposed(run) == {f"quarantine_email:{MSG}", "block_domain:examp1e.test"}
