"""Rules and hooks of ``mail-bombing`` on a simulated read-only lab (no lifecycle, no state change).

Each test builds typed records for the simulated adapters, runs the workflow with the real
``WorkflowRunner`` and checks the facts, the record-backed signals and the rule outcomes.
"""
from __future__ import annotations

from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from tools.simulator.scenario import SIMULATION_SUITE
from xdr_response.atomics.evidence import EvidenceBuilder
from xdr_response.models import ActionType, ObservableType, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.mail_bombing import HOOKS, WORKFLOW
from xdr_response.workflows.mail_bombing.hooks import (
    FLOOD_MIN_CLEAN_RATIO_PCT,
    FLOOD_MIN_MESSAGES,
    FLOOD_MIN_SENDER_DOMAINS,
)
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

USER = "jsmith@example.com"
SEED = "etd-mb-9000-001"
HOST = "TH-LT-1047"
START, END = "2026-01-15T11:00:00Z", "2026-01-15T11:05:00Z"


def metrics(*, total: int = 120, domains: int = 45, neutral: int = 100, graymail: int = 7, spam: int = 13,
            malicious: int = 0) -> dict[str, Any]:
    return {"window_start": START, "window_end": END, "total_messages": total, "unique_sender_domains": domains,
            "neutral_count": neutral, "graymail_count": graymail, "spam_count": spam, "malicious_count": malicious}


def detector_incident(*extra_observables, with_metrics: dict[str, Any] | None = None, **kwargs):
    trigger: dict[str, Any] = {"source": "cisco-xdr-mailbomb-detector", "event_type": "mailbomb.detection",
                               "recipient": USER}
    if with_metrics is not None:
        trigger["metrics"] = with_metrics
    return make_incident((ObservableType.EMAIL_ADDRESS, USER), (ObservableType.EMAIL_MESSAGE_ID, SEED),
                         *extra_observables, workflow_id="mail-bombing", title="Possible email bombing",
                         users=(USER,), source="cisco-xdr-mailbomb-detector", trigger=trigger, **kwargs)


def message(lab: Lab, number: int, *, domain: str | None = None, subject: str = "Welcome aboard",
            at: str = "2026-01-15T11:01:00Z", verdict: str = "CLEAN", threat_types: tuple[str, ...] = (),
            **fields: Any) -> str:
    mid = f"etd-mb-9000-{number:03d}"
    sender_domain = domain or f"list-{number}.example"
    lab.typed("search_email_campaign", SEED, "secure_email", kind="email_message", message_id=mid,
              sender=f"news@{sender_domain}", sender_domain=sender_domain, recipients=[USER], recipient_count=1,
              subject_line=subject, received_at=at, direction="inbound", verdict=verdict,
              threat_types=list(threat_types), delivery_location="inbox", **fields)
    return mid


def entra(lab: Lab, atomic: str, **record: Any) -> None:
    lab.typed(atomic, USER, "entra", **record)


def run(lab: Lab, incident) -> WorkflowRun:
    return lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)


def facts(lab: Lab, incident) -> tuple[WorkflowRun, dict[str, Any]]:
    result = run(lab, incident)
    view = RunView(workflow=WORKFLOW, incident=incident, results=result.results, index=result.index,
                   correlation=result.correlation, blast_radius=result.blast_radius)
    return result, dict(HOOKS.facts(view))


def proposed(result: WorkflowRun) -> set[str]:
    return {o.selector for o in result.outcomes_with(RuleOutcomeStatus.PROPOSED)}


@pytest.fixture
def lab() -> Lab:
    return make_lab(SIMULATION_SUITE)


# ----------------------------------------------------------------- flood --
def test_qualifying_flood_quarantines_bulk_and_keeps_buried_messages(lab):
    bulk = [message(lab, 1), message(lab, 2, threat_types=("graymail",))]
    buried = message(lab, 3, subject="Your password was changed", domain="login.example")
    invoice = message(lab, 4, subject="Invoice 2291 attached", domain="billing.example")
    lure = message(lab, 5, subject="DocuSign: sign now", domain="docs-sign.example", verdict="MALICIOUS",
                   threat_types=("phish",))
    result, f = facts(lab, detector_incident(with_metrics=metrics()))
    assert f["flood"]["qualifies"] is True and f["flood"]["detector"] is True
    quarantined = {m["message_id"] for m in f["flood_messages"]}
    assert quarantined == {*bulk, lure}  # the buried notice and the invoice stay visible; the lure goes
    assert {b["message_id"] for b in f["buried_messages"]} == {buried, invoice, lure}
    assert {f"quarantine_email:{m}" for m in quarantined} <= proposed(result)
    assert not any(o.target in (buried, invoice) and o.action_type is ActionType.QUARANTINE_EMAIL
                   for o in result.outcomes)


@pytest.mark.parametrize("override, qualifies", [
    ({"domains": FLOOD_MIN_SENDER_DOMAINS}, True),
    ({"domains": FLOOD_MIN_SENDER_DOMAINS - 1}, False),
    ({"total": 100, "neutral": FLOOD_MIN_CLEAN_RATIO_PCT, "graymail": 0}, True),
    ({"total": 100, "neutral": FLOOD_MIN_CLEAN_RATIO_PCT - 1, "graymail": 0}, False),
    ({"total": 0}, None),  # unusable metrics: judged on the (too few) observed messages
])
def test_flood_qualification_boundaries(lab, override, qualifies):
    message(lab, 1)
    result, f = facts(lab, detector_incident(with_metrics=metrics(**override)))
    if qualifies is None:
        assert f["flood"]["detector"] is False
        assert f["flood"]["qualifies"] is False
    else:
        assert f["flood"]["qualifies"] is qualifies
    assert ("quarantine_email:etd-mb-9000-001" in proposed(result)) is bool(qualifies)


def test_observed_flood_without_detector_metrics(lab):
    ids = [message(lab, n, at=f"2026-01-15T11:{n:02d}:00Z") for n in range(1, FLOOD_MIN_MESSAGES + 1)]
    result, f = facts(lab, detector_incident())
    assert f["flood"]["detector"] is False
    assert f["flood"]["window_start"] == "2026-01-15T11:01:00Z"
    assert f["flood"]["window_end"] == f"2026-01-15T11:{FLOOD_MIN_MESSAGES:02d}:00Z"
    assert f["flood"]["qualifies"] is True
    assert {f"quarantine_email:{i}" for i in ids} == proposed(result)


def test_too_few_observed_messages_without_metrics_is_no_flood(lab):
    message(lab, 1)
    result, f = facts(lab, detector_incident())
    assert f["flood"]["window_start"] is None and f["flood"]["qualifies"] is False
    assert proposed(result) == set() and result.proposals == ()


def test_spam_storm_is_left_to_the_phishing_workflow(lab):
    lab.environment.set_reputation(ObservableType.DOMAIN, "invoice-portal.example", Verdict.MALICIOUS,
                                   risk_score=90, confidence=85, integrations=["umbrella", "virustotal"])
    message(lab, 1, verdict="SUSPICIOUS", threat_types=("spam",))
    message(lab, 2, domain="invoice-portal.example", verdict="MALICIOUS", threat_types=("phish",),
            domains=["invoice-portal.example"])
    result, f = facts(lab, detector_incident(with_metrics=metrics(total=90, domains=30, neutral=10, graymail=5)))
    assert f["flood"]["qualifies"] is False and "spam or malicious storm" in f["flood"]["reason"]
    assert f["malicious_domains"] == []
    assert result.proposals == ()


def test_messages_outside_the_window_or_to_others_are_not_flood(lab):
    message(lab, 1, at="2026-01-15T10:30:00Z")
    lab.typed("search_email_campaign", SEED, "secure_email", kind="email_message", message_id="etd-mb-9000-002",
              sender="a@list.example", sender_domain="list.example", recipients=["other@example.com"],
              recipient_count=1, received_at="2026-01-15T11:01:00Z", direction="inbound", verdict="CLEAN")
    _, f = facts(lab, detector_incident(with_metrics=metrics()))
    assert f["flood"]["observed"]["messages"] == 0 and f["flood_messages"] == []


# -------------------------------------------------------------- identity --
def test_identity_events_inside_the_window_revoke_sessions(lab):
    message(lab, 1)
    entra(lab, "investigate_authentication", kind="mfa_event", user=USER, timestamp="2026-01-15T11:02:00Z",
          method="push", result="denied")
    result, f = facts(lab, detector_incident(with_metrics=metrics()))
    assert [e["user"] for e in f["identity_events"]] == [USER]
    assert f["takeover"] == []
    assert f"revoke_sessions:{USER}" in proposed(result)
    assert f"disable_user:{USER}" not in proposed(result)


def test_identity_events_before_the_window_are_ignored(lab):
    message(lab, 1)
    entra(lab, "investigate_authentication", kind="mfa_event", user=USER, timestamp="2026-01-15T10:00:00Z",
          method="push", result="denied")
    entra(lab, "investigate_authentication", kind="sign_in", user=USER, timestamp="2026-01-14T16:40:00Z",
          result="success", risk_level="high")
    result, f = facts(lab, detector_incident(with_metrics=metrics()))
    assert f["identity_events"] == [] and f["takeover"] == []
    assert f"revoke_sessions:{USER}" not in proposed(result)


def test_low_risk_sign_in_inside_the_window_is_not_an_identity_event(lab):
    entra(lab, "investigate_authentication", kind="sign_in", user=USER, timestamp="2026-01-15T11:02:00Z",
          result="success", risk_level="low", device_compliant=True)
    result, f = facts(lab, detector_incident(with_metrics=metrics()))
    assert f["identity_events"] == []
    assert result.proposals == ()


def test_buried_notification_alone_backs_revocation(lab):
    message(lab, 1)
    notice = message(lab, 2, subject="New sign-in to your account", domain="login.example")
    result, f = facts(lab, detector_incident(with_metrics=metrics()))
    events = f["identity_events"]
    assert len(events) == 1 and events[0]["kinds"] == ["buried_notification"]
    outcome = next(o for o in result.outcomes if o.action_type is ActionType.REVOKE_SESSIONS)
    assert outcome.status is RuleOutcomeStatus.PROPOSED
    cited = {result.index.get(i) for i in outcome.record_ids}
    assert {r.message_id for r in cited} == {notice}


@pytest.mark.parametrize("records, reason", [
    ([{"kind": "sign_in", "user": USER, "timestamp": "2026-01-15T11:03:00Z", "result": "success",
       "risk_level": "high", "ip": "198.51.100.77"}], "successful high-risk sign-in"),
    ([{"kind": "mfa_event", "user": USER, "timestamp": "2026-01-15T11:02:00Z", "method": "push", "result": "denied"},
      {"kind": "mfa_event", "user": USER, "timestamp": "2026-01-15T11:02:40Z", "method": "push",
       "result": "approved"}], "MFA prompt approved after denied prompts"),
])
def test_takeover_indications_disable_the_account(lab, records, reason):
    for record in records:
        entra(lab, "investigate_authentication", **record)
    result, f = facts(lab, detector_incident(with_metrics=metrics()))
    assert len(f["takeover"]) == 1 and any(reason in r for r in f["takeover"][0]["reasons"])
    assert {f"disable_user:{USER}", f"revoke_sessions:{USER}"} <= proposed(result)


def test_hiding_mailbox_rule_inside_the_window_is_a_takeover_indication(lab):
    lab.typed("search_user_activity", USER, "entra", kind="mailbox_rule", mailbox=USER, rule_id="r-1",
              name="Security notices", move_to_folder="RSS Subscriptions", mark_as_read=True,
              created_at="2026-01-15T11:04:00Z")
    result, f = facts(lab, detector_incident(with_metrics=metrics()))
    assert f["takeover"] and "mailbox rule" in f["takeover"][0]["reasons"][0]
    assert f"disable_user:{USER}" in proposed(result)


def test_privileged_recipient_carries_roles_for_elevation(lab):
    entra(lab, "investigate_user", kind="user_profile", user=USER, roles=["Global Administrator"],
          groups=["IT Operations"])
    entra(lab, "investigate_authentication", kind="mfa_event", user=USER, timestamp="2026-01-15T11:02:00Z",
          method="push", result="denied")
    result, f = facts(lab, detector_incident(with_metrics=metrics()))
    assert f["identity_events"][0]["roles"] == ["Global Administrator"]
    built = next(b for b in result.built if b.action_type is ActionType.REVOKE_SESSIONS)
    assert built.warnings and built.proposal is not None
    assert "Global Administrator" in built.proposal.asset.roles


# -------------------------------------------------------------- endpoint --
def test_endpoint_detection_after_the_flood_isolates_and_older_one_does_not(lab):
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST,
              users=[USER], groups=["Workstations"])
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="detection", detection_id="old",
              name="PUA.Toolbar", verdict="SUSPICIOUS", severity="LOW", endpoint=HOST,
              first_seen="2026-01-14T15:00:00Z")
    result, f = facts(lab, detector_incident((ObservableType.HOSTNAME, HOST), with_metrics=metrics()))
    assert f["endpoint_activity"] == []
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="detection", detection_id="rat",
              name="RemoteAccess.Unapproved", verdict="MALICIOUS", severity="HIGH", endpoint=HOST,
              first_seen="2026-01-15T11:30:00Z")
    lab2_result, f2 = facts(lab, detector_incident((ObservableType.HOSTNAME, HOST), with_metrics=metrics(),
                                                   incident_id="XDR-SM-9002"))
    assert [e["hostname"] for e in f2["endpoint_activity"]] == [HOST]
    assert len(f2["endpoint_activity"][0]["record_ids"]) == 1
    assert f"isolate_endpoint:{HOST}" in proposed(lab2_result)
    assert f"isolate_endpoint:{HOST}" not in proposed(result)


# --------------------------------------------------------------- domains --
def test_malicious_lure_domain_in_a_qualifying_flood_is_blocked(lab):
    lab.environment.set_reputation(ObservableType.DOMAIN, "docs-sign.example", Verdict.MALICIOUS, risk_score=90,
                                   confidence=85, integrations=["umbrella", "virustotal"])
    message(lab, 1)
    message(lab, 2, domain="docs-sign.example", subject="Please sign", verdict="MALICIOUS",
            threat_types=("phish",), domains=["docs-sign.example"])
    result, f = facts(lab, detector_incident(with_metrics=metrics()))
    assert [d["domain"] for d in f["malicious_domains"]] == ["docs-sign.example"]
    assert "block_domain:docs-sign.example" in proposed(result)


def test_single_vendor_suspicious_domain_without_behaviour_is_not_blocked(lab):
    lab.environment.set_reputation(ObservableType.DOMAIN, "maybe-bad.example", Verdict.MALICIOUS, risk_score=70,
                                   confidence=60, integrations=["umbrella"])
    message(lab, 1)
    result, f = facts(lab, detector_incident((ObservableType.DOMAIN, "maybe-bad.example"), with_metrics=metrics()))
    report = next(r for r in result.results if r.atomic == "enrich_domain")
    assert report.verdict is Verdict.SUSPICIOUS  # one vendor's word is never an aggregate MALICIOUS
    assert f["malicious_domains"] == []


# --------------------------------------------------------------- signals --
def test_signals_cite_existing_records_of_their_own_source(lab):
    message(lab, 1)
    message(lab, 2, subject="Password reset requested", domain="login.example")
    entra(lab, "investigate_authentication", kind="mfa_event", user=USER, timestamp="2026-01-15T11:02:00Z",
          method="push", result="denied")
    result = run(lab, detector_incident(with_metrics=metrics()))
    assert result.signals, "hook signals are validated and kept by the runner"
    assert not [n for n in result.notes if n.startswith("hook ")]
    for signal in result.signals:
        cited = result.index.require(signal.record_ids)
        assert signal.integration in {r.integration for r in cited}
        assert signal.origin == "workflow:mail-bombing"
        assert signal.verdict is Verdict.SUSPICIOUS
    categories = {(s.category, s.integration) for s in result.signals}
    assert (SignalCategory.CAMPAIGN_ASSOCIATION, "secure_email") in categories
    assert (SignalCategory.AUTHENTICATION_ANOMALY, "entra") in categories
    assert (SignalCategory.AUTHENTICATION_ANOMALY, "secure_email") in categories


def test_every_proposal_has_record_backed_evidence_and_separate_scores(lab):
    message(lab, 1)
    entra(lab, "investigate_authentication", kind="sign_in", user=USER, timestamp="2026-01-15T11:03:00Z",
          result="success", risk_level="high")
    result = run(lab, detector_incident(with_metrics=metrics()))
    assert result.proposals
    builder = EvidenceBuilder(result.index)
    for proposal in result.proposals:
        assert proposal.evidence
        builder.verify(proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
        assert "settings" in proposal.rationale  # the score explanation reaches the package


def test_failed_flood_source_does_not_block_identity_recommendations(lab):
    from xdr_response.integrations.simulated import FaultKind  # test-only: inject a vendor outage

    lab.environment.inject(FaultKind.UNAVAILABLE, integration="secure_email", operation="investigate", times=5)
    entra(lab, "investigate_authentication", kind="anomaly", anomaly_type="mfa_fatigue", severity="MEDIUM",
          user=USER, first_seen="2026-01-15T11:02:00Z")
    result = run(lab, detector_incident(with_metrics=metrics()))
    assert result.degraded_sources() == ("secure_email",)
    assert proposed(result) == {f"revoke_sessions:{USER}"}


def test_dry_run_and_live_score_identically(lab):
    message(lab, 1)
    incident = detector_incident(with_metrics=metrics())
    dry = lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)
    live = lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=False)
    assert [(p.action_type, p.target, p.risk_score, p.confidence_score) for p in dry.proposals] == \
           [(p.action_type, p.target, p.risk_score, p.confidence_score) for p in live.proposals]
    assert lab.environment.state_changing_calls() == []
