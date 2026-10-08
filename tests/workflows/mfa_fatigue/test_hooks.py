"""Unit tests of the mfa-fatigue hooks: the pattern, facts, signals and links (pure, fake data only)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.atomics.evidence import RecordIndex
from xdr_response.atomics.records import (
    AnomalyRecord,
    DetectionRecord,
    EndpointRecord,
    MailboxRuleRecord,
    MfaEventRecord,
    NetworkConnectionRecord,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import Incident, Observable, ObservableType, Severity, TargetKind, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.mfa_fatigue import HOOKS, WORKFLOW
from xdr_response.workflows.mfa_fatigue.hooks import (
    MAX_PROMPT_EVIDENCE,
    MIN_UNSUCCESSFUL_PROMPTS,
    analyze,
    facts_of,
)

USER = "jsmith@example.com"
ATTACKER = "203.0.113.80"
HOME = "198.51.100.20"
HOST = "TH-LT-1047"
T0 = datetime(2026, 1, 15, 10, 30, tzinfo=timezone.utc)
_USER_OBS = Observable(type=ObservableType.USER, value=USER)
_HOST_OBS = Observable(type=ObservableType.HOSTNAME, value=HOST)


def at(minutes: float) -> datetime:
    return T0 + timedelta(minutes=minutes)


def mfa(minutes: float, result: str, *, ip: str = ATTACKER, user: str = USER, integration: str = "entra"
        ) -> MfaEventRecord:
    return MfaEventRecord(integration=integration, atomic="investigate_authentication",
                          subject=Observable(type=ObservableType.USER, value=user), user=user,
                          timestamp=at(minutes), method="push", result=result, ip=ip)


def sign_in(minutes: float, result: str = "success", *, ip: str = ATTACKER, mfa_result: str = "satisfied",
            user: str = USER) -> SignInRecord:
    return SignInRecord(integration="entra", atomic="investigate_authentication",
                        subject=Observable(type=ObservableType.USER, value=user), user=user,
                        timestamp=at(minutes), ip=ip, result=result, mfa_result=mfa_result,
                        sign_in_id=f"si-{user}-{minutes}-{ip}")


def profile(**fields: Any) -> UserProfileRecord:
    return UserProfileRecord(integration="entra", atomic="investigate_user", subject=_USER_OBS, user=USER, **fields)


def mailbox_rule(created_minutes: float | None, **fields: Any) -> MailboxRuleRecord:
    created = at(created_minutes) if created_minutes is not None else None
    return MailboxRuleRecord(integration="entra", atomic="search_user_activity", subject=_USER_OBS, mailbox=USER,
                             rule_id=f"rule-{created_minutes}", name="Archive copy", created_at=created, **fields)


def fatigue(denied: int = 5, *, approve: bool = True, login: bool = True, spacing: float = 2.0) -> list[Any]:
    """``denied`` rejected prompts, then optionally an approval and a successful sign-in."""
    records: list[Any] = [mfa(i * spacing, "denied") for i in range(denied)]
    if approve:
        records.append(mfa(denied * spacing + 1, "approved"))
    if login:
        records.append(sign_in(denied * spacing + 1.5))
    return records


def view(records: list[Any]) -> RunView:
    incident = Incident(incident_id="XDR-MFA-9001", title="MFA fatigue pattern followed by successful sign-in",
                        severity=Severity.HIGH, created_at=at(120), workflow_id=WORKFLOW.id,
                        workflow_version=WORKFLOW.version,
                        observables=(_USER_OBS,))
    return RunView(workflow=WORKFLOW, incident=incident, results=(), index=RecordIndex(records=records),
                   correlation=None, blast_radius=None)


def facts(records: list[Any]) -> dict[str, Any]:
    return dict(HOOKS.facts(view(records)))


def user_fact(records: list[Any]) -> dict[str, Any]:
    found = [u for u in facts(records)["users"] if u["user"] == USER]
    assert len(found) == 1
    return found[0]


# ------------------------------------------------------------------ pattern --
def test_approval_after_the_threshold_is_a_compromise_and_cites_every_step():
    records = fatigue(5)
    fact = user_fact(records)
    assert fact["pattern"] == "approved_after_prompts" and fact["compromised"] is True
    assert fact["unsuccessful_prompts"] == 5
    assert fact["source_ips"] == [ATTACKER] and fact["login_ips"] == [ATTACKER]
    assert set(fact["record_ids"]) == {r.record_id for r in records}
    assert "5 rejected or unanswered prompts from 203.0.113.80" in fact["summary"]
    assert "approved at 2026-01-15T10:41:00Z" in fact["summary"]


def test_below_the_threshold_nothing_is_reported():
    records = fatigue(MIN_UNSUCCESSFUL_PROMPTS - 1)
    assert facts(records)["users"] == []
    assert facts(records)["compromised_users"] == []
    assert list(HOOKS.derive_signals(view(records))) == []


def test_prompts_spread_beyond_the_window_do_not_make_the_approval_count():
    records = [mfa(-200, "denied"), mfa(-150, "denied"), mfa(-100, "denied"), mfa(0, "approved"), sign_in(1)]
    fact = user_fact(records)
    assert fact["pattern"] == "prompts_only" and fact["compromised"] is False
    assert facts(records)["compromised_users"] == []


def test_denials_only_is_prompts_only_with_a_suspicious_signal():
    records = fatigue(4, approve=False, login=False)
    fact = user_fact(records)
    assert fact["pattern"] == "prompts_only" and fact["approved_at"] is None
    signals = list(HOOKS.derive_signals(view(records)))
    user_signal = [s for s in signals if s.observable.type is ObservableType.USER]
    assert [(s.verdict, s.severity) for s in user_signal] == [(Verdict.SUSPICIOUS, 60)]
    ip_signal = [s for s in signals if s.observable.value == ATTACKER]
    assert [(s.verdict, s.severity) for s in ip_signal] == [(Verdict.SUSPICIOUS, 60)]


def test_timeouts_and_fraud_reports_count_as_unsuccessful_prompts():
    records = [mfa(0, "timeout"), mfa(1, "fraud_reported"), mfa(2, "denied"), mfa(3, "approved"), sign_in(3.5)]
    assert user_fact(records)["compromised"] is True


def test_approval_without_a_sign_in_record_is_still_a_compromise_with_lower_severity():
    with_login = {s.observable.value: s for s in HOOKS.derive_signals(view(fatigue(4)))}
    without = {s.observable.value: s for s in HOOKS.derive_signals(view(fatigue(4, login=False)))}
    assert with_login[USER].severity == 85 and without[USER].severity == 75
    assert with_login[USER].verdict is Verdict.MALICIOUS and without[USER].verdict is Verdict.MALICIOUS
    assert "no successful sign-in record" in user_fact(fatigue(4, login=False))["summary"]


def test_sign_in_mfa_results_are_the_fallback_when_no_mfa_event_exists():
    records = [sign_in(i, "failure", mfa_result="denied") for i in range(3)]
    records.append(sign_in(4, "success", mfa_result="satisfied"))
    fact = user_fact(records)
    assert fact["compromised"] is True and fact["unsuccessful_prompts"] == 3


def test_mfa_events_and_sign_ins_of_the_same_attempts_are_never_counted_twice():
    records = [*fatigue(3), *(sign_in(i * 2, "failure", mfa_result="denied") for i in range(3))]
    assert user_fact(records)["unsuccessful_prompts"] == 3


def test_a_sign_in_long_after_the_approval_is_not_the_suspicious_login():
    records = [*fatigue(4, login=False), sign_in(300)]
    assert user_fact(records)["login_ips"] == []


def test_evidence_is_capped_to_the_newest_prompts():
    records = fatigue(MAX_PROMPT_EVIDENCE + 5, spacing=1.0)
    fact = user_fact(records)
    prompt_ids = [r.record_id for r in records if isinstance(r, MfaEventRecord) and r.result == "denied"]
    cited = set(fact["record_ids"])
    assert set(prompt_ids[-MAX_PROMPT_EVIDENCE:]) <= cited
    assert not set(prompt_ids[:5]) & cited


def test_vendor_mfa_fatigue_anomalies_are_cited():
    anomaly = AnomalyRecord(integration="entra", atomic="investigate_user", subject=_USER_OBS,
                            anomaly_id="risk-1", anomaly_type="mfa_fatigue", severity=Severity.MEDIUM, user=USER)
    assert anomaly.record_id in user_fact([*fatigue(4), anomaly])["record_ids"]


# ------------------------------------------------------- disable reasons --
def test_a_forwarding_rule_after_the_approval_is_a_disable_reason():
    rule = mailbox_rule(20, forward_to=("drop@mail.example.net",), external_forwarding=True)
    fact = user_fact([*fatigue(4), rule])
    assert rule.record_id in fact["disable_record_ids"]
    assert "forwards externally" in fact["disable_summary"]


def test_activity_before_the_approval_or_without_a_time_is_not_attributed():
    before = mailbox_rule(-120, forward_to=("drop@mail.example.net",))
    unknown = mailbox_rule(None, forward_to=("drop@mail.example.net",))
    fact = user_fact([*fatigue(4), before, unknown])
    assert fact["disable_reasons"] == [] and fact["disable_record_ids"] == []


def test_a_privileged_profile_is_a_disable_reason_and_its_roles_reach_the_asset():
    admin = profile(roles=("Global Administrator",), groups=("IT Operations",))
    fact = user_fact([*fatigue(4), admin])
    assert any("privileged account" in r for r in fact["disable_reasons"])
    assert fact["roles"] == ["Global Administrator"] and fact["groups"] == ["IT Operations"]


def test_a_role_granted_after_the_approval_is_a_reason_and_part_of_the_roles():
    grant = RoleChangeRecord(integration="entra", atomic="search_user_activity", subject=_USER_OBS, user=USER,
                             role_name="Exchange Administrator", change="assigned", privileged=True,
                             timestamp=at(25))
    fact = user_fact([*fatigue(4), grant])
    assert grant.record_id in fact["disable_record_ids"]
    assert "Exchange Administrator" in fact["roles"]


def test_a_new_attacker_sign_in_after_revocation_is_a_disable_reason():
    revoked = profile(sessions_valid_from=at(30))
    again = sign_in(45)
    fact = user_fact([*fatigue(4), revoked, again])
    assert any("after sessions were revoked" in r for r in fact["disable_reasons"])
    assert again.record_id in fact["disable_record_ids"]


def test_identity_provider_risk_alone_without_the_pattern_proposes_nothing():
    assert facts([profile(risk_level="high", risk_state="confirmed_compromised")])["compromised_users"] == []


# ------------------------------------------------------------- source IPs --
def test_source_ips_count_prompts_per_ip_and_flag_internal_addresses():
    records = [mfa(0, "denied", ip="10.1.2.3"), mfa(1, "denied", ip="10.1.2.3"), mfa(2, "denied", ip=ATTACKER),
               mfa(3, "denied", ip=ATTACKER), mfa(4, "denied", ip=ATTACKER), mfa(5, "approved", ip=ATTACKER)]
    by_ip = {p["ip"]: p for p in facts(records)["source_ips"]}
    assert by_ip[ATTACKER]["unsuccessful"] == 3 and by_ip[ATTACKER]["approved"] is True
    assert by_ip[ATTACKER]["internal"] is False and by_ip[ATTACKER]["compromise"] is True
    assert by_ip["10.1.2.3"]["internal"] is True
    assert by_ip[ATTACKER]["enrichment_key"] == f"ip:{ATTACKER}"


def test_ipv6_sources_use_the_ipv6_enrichment_key():
    ip6 = "2001:db8::80"
    records = [mfa(i, "denied", ip=ip6) for i in range(3)]
    (item,) = facts(records)["source_ips"]
    assert item["enrichment_key"] == f"ipv6:{ip6}" and item["internal"] is False


def test_compromise_sign_in_ips_map_to_their_records():
    records = [*fatigue(4, login=False), sign_in(9.5, ip="198.51.100.66")]
    out = facts(records)
    assert out["compromise_signin_ips"] == ["198.51.100.66"]
    assert len(out["signin_ids_by_ip"]["198.51.100.66"]) == 2  # the sign-in and the approval


# --------------------------------------------------------------- endpoints --
def _endpoint(users: tuple[str, ...] = (USER,)) -> EndpointRecord:
    return EndpointRecord(integration="secure_endpoint", atomic="investigate_endpoint", subject=_HOST_OBS,
                          hostname=HOST, users=users, groups=("Workstations",))


def _detection(user: str | None = USER, verdict: Verdict = Verdict.MALICIOUS) -> DetectionRecord:
    return DetectionRecord(integration="secure_endpoint", atomic="investigate_endpoint", subject=_HOST_OBS,
                           detection_id="det-1", name="Sample.InfoStealer.Generic", verdict=verdict,
                           severity=Severity.HIGH, endpoint=HOST, user=user)


def test_an_endpoint_of_the_compromised_user_with_a_detection_is_tied():
    (endpoint,) = facts([*fatigue(4), _endpoint(), _detection()])["endpoints"]
    assert endpoint["hostname"] == HOST and endpoint["groups"] == ["Workstations"]
    assert "MALICIOUS detection Sample.InfoStealer.Generic" in endpoint["summary"]


def test_an_endpoint_without_a_tie_or_without_bad_activity_is_not_proposed():
    assert facts([*fatigue(4), _endpoint(users=("other@example.com",)), _detection(user=None)])["endpoints"] == []
    assert facts([*fatigue(4), _endpoint(), _detection(verdict=Verdict.CLEAN)])["endpoints"] == []


def test_no_endpoint_is_tied_without_a_compromised_user():
    assert facts([*fatigue(4, approve=False, login=False), _endpoint(), _detection()])["endpoints"] == []


def test_a_connection_to_the_prompt_source_ties_the_endpoint_and_signals_network_behaviour():
    connection = NetworkConnectionRecord(
        integration="splunk", atomic="investigate_ip", subject=Observable(type=ObservableType.IP, value=ATTACKER),
        endpoint=HOST, remote_ip=ATTACKER, remote_port=443, first_seen=at(30))
    (endpoint,) = facts([*fatigue(4), connection])["endpoints"]
    assert connection.record_id in endpoint["record_ids"]
    signals = [s for s in HOOKS.derive_signals(view([*fatigue(4), connection]))
               if s.observable.type is ObservableType.HOSTNAME]
    assert [(s.category, s.integration) for s in signals] == [(SignalCategory.NETWORK_BEHAVIOUR, "splunk")]


# ------------------------------------------------------- signals and links --
def test_signals_cite_existing_records_of_their_own_integration_with_the_workflow_origin():
    records = [*fatigue(4), _endpoint(), _detection()]
    run_view = view(records)
    signals = list(HOOKS.derive_signals(run_view))
    assert signals
    for signal in signals:
        assert signal.origin == "workflow:mfa-fatigue"
        cited = run_view.index.require(signal.record_ids)
        assert signal.integration in {r.integration for r in cited}
        assert not signal.vendor_verdict


def test_links_join_the_user_to_each_prompt_source_and_cite_the_prompts():
    records = [*fatigue(4), _endpoint(), _detection()]
    links = list(HOOKS.correlate(view(records)))
    kinds = {frozenset(e.kind for e in link.entities) for link in links}
    assert kinds == {frozenset({TargetKind.USER, TargetKind.IP}), frozenset({TargetKind.USER, TargetKind.ENDPOINT})}
    for link in links:
        assert link.kind is LinkKind.WORKFLOW and link.origin == "workflow:mfa-fatigue"
        assert set(link.record_ids) <= {r.record_id for r in records}


def test_facts_are_json_and_deterministic_whatever_the_record_order():
    records = [*fatigue(5), mailbox_rule(20, forward_to=("drop@mail.example.net",)), _endpoint(), _detection()]
    first = facts(records)
    assert json.loads(json.dumps(first)) == first
    assert facts(list(reversed(records))) == first


def test_hooks_contribute_nothing_for_an_empty_run():
    empty = view([])
    assert list(HOOKS.correlate(empty)) == [] and list(HOOKS.derive_signals(empty)) == []
    assert facts_of(analyze(empty))["users"] == []


@pytest.mark.parametrize("other_user", ["pchen@example.com"])
def test_users_are_judged_separately(other_user: str):
    records = [*fatigue(4), *(mfa(i, "denied", user=other_user, ip="203.0.113.81") for i in range(2))]
    out = facts(records)
    assert [u["user"] for u in out["compromised_users"]] == [USER]
    assert all(u["user"] != other_user for u in out["users"])
