"""Phishing hooks and rules on a simulated read-only lab (fake data, fixed clock, no network).

The lab serves typed records through simulated adapters; ``WorkflowRunner`` runs the real definition
and hooks. These tests pin the hook semantics: what confirms a message, which indicators are listed,
what counts as a click, when a user is compromised and when disabling is justified, and that every
fact and signal cites records of the run.
"""
from __future__ import annotations

from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.evidence import EvidenceBuilder
from xdr_response.models import ActionType, ObservableType, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.phishing import HOOKS, WORKFLOW
from xdr_response.workflows.phishing.hooks import CLICK_SIGNIN_SEVERITY, ORIGIN
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

SUITE = {"secure_email": ("email",), "entra": ("identity",), "umbrella": ("network",), "virustotal": ("intel",),
         "secure_endpoint": ("endpoint",), "microsoft_cloud": ("network",)}
MSG = "<20260115.0900.0001@pay-portal.test>"
MSG2 = "<20260115.0901.0002@pay-portal.test>"
DOMAIN = "pay-portal.test"
URL = "https://pay-portal.test/login"
SHA = "7e7e7e7e" * 8
USER = "jsmith@example.com"
HOST = "TH-LT-1047"
O = ObservableType


def _lab() -> Lab:
    return make_lab(SUITE)


def _message(lab: Lab, message_id: str = MSG, *, atomic: str = "investigate_email", subject: str = MSG,
             **fields: Any) -> None:
    record = {"kind": "email_message", "message_id": message_id, "sender": "billing@pay-portal.test",
              "sender_domain": DOMAIN, "recipients": [USER], "recipient_count": 1,
              "received_at": "2026-01-15T09:00:00Z", "direction": "inbound", "urls": [URL], "domains": [DOMAIN],
              "delivery_location": "inbox"}
    record.update(fields)
    lab.typed(atomic, subject, "secure_email", **record)


def _malicious(lab: Lab, observable_type: ObservableType, value: str, *, sources=("umbrella", "virustotal")) -> None:
    lab.environment.set_reputation(observable_type, value, Verdict.MALICIOUS, risk_score=90, confidence=85,
                                   integrations=list(sources))


def _click(lab: Lab, at: str = "2026-01-15T09:20:00Z", host: str = HOST, user: str = USER) -> None:
    lab.typed("search_domain_enterprise", DOMAIN, "microsoft_cloud", kind="dns_query", endpoint=host, domain=DOMAIN,
              query_type="A", count=1, action="allowed", first_seen=at)
    lab.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host,
              connector_guid="00000000-0000-4000-8000-000000001047", users=[user], groups=["Workstations"],
              isolation_state="not_isolated")


def _signin(lab: Lab, at: str = "2026-01-15T09:31:00Z", *, result: str = "success", sign_in_id: str = "si-1") -> None:
    lab.typed("investigate_authentication", USER, "entra", kind="sign_in", sign_in_id=sign_in_id, user=USER,
              timestamp=at, ip="198.51.100.77", country="NL", app="Office 365", result=result)


def _profile(lab: Lab, **fields: Any) -> None:
    lab.typed("investigate_user", USER, "entra", kind="user_profile", user=USER, groups=["Finance"],
              account_enabled=True, **fields)


def _run(lab: Lab, *, dry_run: bool = True, **extra: Any) -> WorkflowRun:
    incident = make_incident((O.EMAIL_MESSAGE_ID, MSG), workflow_id="phishing", title="Credential phishing",
                             users=(USER,), **extra)
    return lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=dry_run)


def _facts(run: WorkflowRun) -> dict[str, Any]:
    incident = make_incident((O.EMAIL_MESSAGE_ID, MSG), workflow_id="phishing", title="Credential phishing",
                             users=(USER,))
    view = RunView(workflow=run.workflow, incident=incident, results=run.results, index=run.index,
                   correlation=run.correlation, blast_radius=run.blast_radius)
    return dict(HOOKS.facts(view))


def _proposed(run: WorkflowRun) -> set[str]:
    return {o.selector for o in run.outcomes_with(RuleOutcomeStatus.PROPOSED)}


def _all_fact_ids(facts: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for items in facts.values():
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                ids += item.get("record_ids", []) + item.get("disable_record_ids", [])
    return ids


# ------------------------------------------------------------- confirmation --
def test_gateway_verdict_confirms_and_quarantines_a_delivered_message():
    lab = _lab()
    _message(lab, verdict="MALICIOUS", threat_types=["phish"])
    run = _run(lab)
    facts = _facts(run)
    assert [m["message_id"] for m in facts["phishing_messages"]] == [MSG]
    assert f"quarantine_email:{MSG}" in _proposed(run)
    proposal = next(p for p in run.proposals if p.action_type is ActionType.QUARANTINE_EMAIL)
    assert proposal.params["verdict"] == "phishing" and proposal.params["recipient"] == USER


def test_a_clean_message_with_clean_indicators_is_not_confirmed():
    lab = _lab()
    _message(lab, verdict="CLEAN")
    lab.environment.set_reputation(O.DOMAIN, DOMAIN, Verdict.CLEAN, risk_score=0, confidence=80,
                                   integrations=["umbrella", "virustotal"])
    run = _run(lab)
    assert _facts(run)["phishing_messages"] == []
    assert run.proposals == () and run.outcomes == ()


def test_a_rated_indicator_confirms_a_message_without_a_gateway_verdict():
    lab = _lab()
    _message(lab)  # gateway verdict UNKNOWN
    _malicious(lab, O.DOMAIN, DOMAIN)
    facts = _facts(_run(lab))
    message = facts["phishing_messages"][0]
    assert message["message_id"] == MSG and len(message["record_ids"]) >= 2  # the message plus the enrichment answers


def test_a_campaign_link_confirms_siblings_and_cites_the_gateway_rated_copy():
    lab = _lab()
    _message(lab, verdict="MALICIOUS", campaign_id="CMP-1", urls=[], domains=[])
    _message(lab, MSG2, atomic="search_email_campaign", campaign_id="CMP-1", urls=[], domains=[],
             recipients=["ops-02@example.com"])
    run = _run(lab)
    facts = _facts(run)
    by_id = {m["message_id"]: m for m in facts["phishing_messages"]}
    assert set(by_id) == {MSG, MSG2}
    original = next(r for r in run.index.records() if str(r.kind) == "email_message" and r.message_id == MSG)
    assert original.record_id in by_id[MSG2]["record_ids"]
    assert {f"quarantine_email:{MSG}", f"quarantine_email:{MSG2}"} <= _proposed(run)


def test_an_already_quarantined_copy_is_not_proposed_again():
    lab = _lab()
    _message(lab, verdict="MALICIOUS", delivery_location="quarantine")
    run = _run(lab)
    assert _facts(run)["phishing_messages"][0]["delivered"] is False
    assert not any(o.action_type is ActionType.QUARANTINE_EMAIL for o in run.outcomes)


# --------------------------------------------------------------- indicators --
def test_a_url_on_a_listed_domain_is_covered_by_the_domain_block():
    lab = _lab()
    _message(lab, verdict="MALICIOUS")
    _malicious(lab, O.DOMAIN, DOMAIN)
    _malicious(lab, O.URL, URL)
    run = _run(lab)
    facts = _facts(run)
    assert [d["domain"] for d in facts["phishing_domains"]] == [DOMAIN]
    assert facts["phishing_urls"] == []
    assert f"block_domain:{DOMAIN}" in _proposed(run)
    assert not any(o.action_type is ActionType.BLOCK_URL for o in run.outcomes)


def test_a_url_on_a_clean_host_is_blocked_by_itself():
    lab = _lab()
    url = "https://files.docs-share.test/s/a1/remit.html"
    _message(lab, verdict="MALICIOUS", urls=[url], domains=["files.docs-share.test"])
    _malicious(lab, O.URL, url)
    lab.environment.set_reputation(O.DOMAIN, "files.docs-share.test", Verdict.CLEAN, risk_score=0, confidence=80,
                                   integrations=["umbrella", "virustotal"])
    run = _run(lab)
    assert [u["url"] for u in _facts(run)["phishing_urls"]] == [url]
    assert f"block_url:{url}" in _proposed(run)
    assert not any(o.action_type is ActionType.BLOCK_DOMAIN for o in run.outcomes)


def test_reputation_alone_never_reaches_the_proposal_line():
    """An indicator only the incident names (no message, click or detection) stays below threshold."""
    lab = _lab()
    _malicious(lab, O.DOMAIN, DOMAIN)
    incident = make_incident((O.DOMAIN, DOMAIN), workflow_id="phishing", title="Credential phishing")
    run = lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)
    outcome = next(o for o in run.outcomes if o.action_type is ActionType.BLOCK_DOMAIN)
    assert outcome.status is RuleOutcomeStatus.BELOW_THRESHOLD and outcome.risk_score < 60
    assert run.proposals == ()


def test_an_attachment_detected_on_an_endpoint_is_blocked_and_the_endpoint_isolated():
    lab = _lab()
    _message(lab, verdict="MALICIOUS", attachment_hashes=[SHA], urls=[], domains=[])
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST,
              connector_guid="00000000-0000-4000-8000-000000001047", users=[USER])
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="detection", detection_id="det-1",
              name="Trojan.Generic", verdict="MALICIOUS", severity="HIGH", endpoint=HOST, sha256=SHA,
              first_seen="2026-01-15T09:10:00Z")
    incident = make_incident((O.EMAIL_MESSAGE_ID, MSG), (O.HOSTNAME, HOST), workflow_id="phishing",
                             title="Credential phishing", users=(USER,))
    run = lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)
    assert {f"block_hash:{SHA}", f"isolate_endpoint:{HOST}"} <= _proposed(run)
    isolate = next(p for p in run.proposals if p.action_type is ActionType.ISOLATE_ENDPOINT)
    assert isolate.params["integration"] == "secure_endpoint"


# ------------------------------------------------------------ clicks, users --
def test_click_then_successful_signin_with_a_high_risk_detection_recommends_revoke_and_disable():
    lab = _lab()
    _message(lab, verdict="MALICIOUS")
    _malicious(lab, O.DOMAIN, DOMAIN)
    _click(lab)
    _profile(lab, risk_level="medium", risk_state="at_risk")
    _signin(lab)
    lab.typed("investigate_authentication", USER, "entra", kind="anomaly", anomaly_id="an-1",
              anomaly_type="unfamiliar_location", severity="HIGH", user=USER, first_seen="2026-01-15T09:31:00Z")
    run = _run(lab)
    facts = _facts(run)
    assert [c["user"] for c in facts["clicks"]] == [USER]
    user = facts["compromised_users"][0]
    assert user["user"] == USER and user["disable_justified"] is True and user["signins_after_click"] == 1
    assert facts["account_takeover_handoff"] == [USER]
    assert {f"revoke_sessions:{USER}", f"disable_user:{USER}"} <= _proposed(run)
    revoke = next(p for p in run.proposals if p.action_type is ActionType.REVOKE_SESSIONS)
    assert "account-takeover" in revoke.rationale


def test_a_click_without_post_click_authentication_proposes_no_account_action():
    lab = _lab()
    _message(lab, verdict="MALICIOUS")
    _malicious(lab, O.DOMAIN, DOMAIN)
    _click(lab)
    _profile(lab, risk_level="none", risk_state="none")
    _signin(lab, at="2026-01-15T08:00:00Z")  # before the click
    run = _run(lab)
    facts = _facts(run)
    assert facts["clicks"] and facts["compromised_users"] == []
    assert not any(o.action_type in (ActionType.REVOKE_SESSIONS, ActionType.DISABLE_USER) for o in run.outcomes)


def test_a_dns_query_before_delivery_is_not_a_click():
    lab = _lab()
    _message(lab, verdict="MALICIOUS")
    _malicious(lab, O.DOMAIN, DOMAIN)
    _click(lab, at="2026-01-15T06:00:00Z")
    _signin(lab)
    facts = _facts(_run(lab))
    assert facts["clicks"] == [] and facts["compromised_users"] == []


def test_a_click_on_an_unrated_link_of_an_unconfirmed_message_is_ignored():
    lab = _lab()
    _message(lab, verdict="CLEAN")
    _click(lab)
    _signin(lab)
    facts = _facts(_run(lab))
    assert facts["clicks"] == [] and facts["compromised_users"] == []


def test_signin_without_high_risk_revokes_but_does_not_disable():
    lab = _lab()
    _message(lab, verdict="MALICIOUS")
    _malicious(lab, O.DOMAIN, DOMAIN)
    _click(lab)
    _profile(lab, risk_level="low", risk_state="none")
    _signin(lab)
    run = _run(lab)
    user = _facts(run)["compromised_users"][0]
    assert user["disable_justified"] is False
    assert f"revoke_sessions:{USER}" in _proposed(run)
    assert not any(o.action_type is ActionType.DISABLE_USER for o in run.outcomes)


def test_identity_provider_confirmation_justifies_disabling():
    lab = _lab()
    _message(lab, verdict="MALICIOUS")
    _malicious(lab, O.DOMAIN, DOMAIN)
    _click(lab)
    _profile(lab, risk_level="high", risk_state="confirmed_compromised")
    run = _run(lab)
    assert _facts(run)["compromised_users"][0]["disable_justified"] is True
    assert f"disable_user:{USER}" in _proposed(run)


def test_a_privileged_clicking_user_gets_role_context_for_elevation():
    lab = _lab()
    _message(lab, verdict="MALICIOUS")
    _malicious(lab, O.DOMAIN, DOMAIN)
    _click(lab)
    lab.typed("investigate_user", USER, "entra", kind="user_profile", user=USER, roles=["Global Administrator"],
              privileged=True, risk_level="high", risk_state="at_risk")
    _signin(lab)
    run = _run(lab)
    revoke = next(b for b in run.built if b.action_type is ActionType.REVOKE_SESSIONS)
    assert revoke.proposal is not None and "Global Administrator" in revoke.proposal.asset.roles
    assert revoke.warnings  # builder preview; PackageBuilder makes it ELEVATED


# ------------------------------------------------------------ the signal --
def test_click_then_signin_signal_is_attributed_to_the_identity_source_and_cites_records():
    lab = _lab()
    _message(lab, verdict="MALICIOUS")
    _malicious(lab, O.DOMAIN, DOMAIN)
    _click(lab)
    _signin(lab)
    run = _run(lab)
    signals = [s for s in run.signals if s.origin == ORIGIN]
    assert len(signals) == 1
    signal = signals[0]
    assert (signal.category, signal.integration, signal.verdict) == (
        SignalCategory.AUTHENTICATION_ANOMALY, "entra", Verdict.SUSPICIOUS)
    assert signal.severity == CLICK_SIGNIN_SEVERITY and signal.vendor_verdict is False
    kinds = {str(r.kind) for r in run.index.require(signal.record_ids)}
    assert {"sign_in", "dns_query", "email_message"} <= kinds


# ---------------------------------------------------- read zone, evidence --
def test_every_fact_and_proposal_cites_records_of_the_run():
    lab = _lab()
    _message(lab, verdict="MALICIOUS", attachment_hashes=[SHA])
    _malicious(lab, O.DOMAIN, DOMAIN)
    _malicious(lab, O.SHA256, SHA, sources=("secure_endpoint", "virustotal"))
    _click(lab)
    _signin(lab)
    run = _run(lab)
    facts = _facts(run)
    ids = _all_fact_ids(facts)
    assert ids and all(i in run.index for i in ids)
    for proposal in run.proposals:
        EvidenceBuilder(run.index).verify(proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int


@pytest.mark.parametrize("dry_run", [True, False])
def test_the_run_only_reads(dry_run):
    lab = make_lab(SUITE, dry_run=dry_run)
    _message(lab, verdict="MALICIOUS", attachment_hashes=[SHA])
    _malicious(lab, O.DOMAIN, DOMAIN)
    _click(lab)
    _signin(lab)
    run = _run(lab, dry_run=dry_run)
    assert run.proposals
    assert lab.environment.state_changing_calls() == []


def test_dry_run_and_live_score_identically():
    def outcomes(dry_run: bool):
        lab = make_lab(SUITE, dry_run=dry_run)
        _message(lab, verdict="MALICIOUS")
        _malicious(lab, O.DOMAIN, DOMAIN)
        _click(lab)
        _signin(lab)
        run = _run(lab, dry_run=dry_run)
        return [(o.rule_id, o.selector, o.status, o.risk_score, o.confidence_score) for o in run.outcomes]

    assert outcomes(True) == outcomes(False)


def test_a_failing_expected_source_degrades_without_blocking():
    lab = _lab()
    _message(lab, verdict="MALICIOUS")
    _malicious(lab, O.DOMAIN, DOMAIN)
    lab.environment.inject("UNAVAILABLE", integration="umbrella", operation="enrich", times=10)
    run = _run(lab)
    assert "umbrella" in run.degraded_sources()
    assert {f"quarantine_email:{MSG}", f"block_domain:{DOMAIN}"} <= _proposed(run)


def test_hooks_on_an_empty_run_return_empty_facts():
    lab = _lab()
    run = _run(lab)
    facts = _facts(run)
    assert all(value == [] for value in facts.values())
    assert run.outcomes_with(RuleOutcomeStatus.ERROR) == ()
    assert not [n for n in run.notes if n.startswith("hook ")]
