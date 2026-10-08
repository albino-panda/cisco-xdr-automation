"""Pure tests of the suspicious-authentication hooks over hand-built typed records (no adapters, no lifecycle)."""
from __future__ import annotations

import ipaddress
import json
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from xdr_response.atomics.correlation.models import BlastRadiusReport, CorrelationResult, LinkKind
from xdr_response.atomics.evidence import RecordIndex
from xdr_response.atomics.records import (
    AnomalyRecord,
    AtomicResult,
    DetectionRecord,
    EndpointRecord,
    EnrichmentRecord,
    MailboxRuleRecord,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.suspicious_authentication import HOOKS, WORKFLOW
from xdr_response.workflows.suspicious_authentication import hooks as module
from xdr_response.workflows.suspicious_authentication.hooks import assess_users, source_ips

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
USER = "jsmith@example.com"
OFFICE = "198.51.100.10"
ATTACKER = "203.0.113.145"
EGRESS = "198.51.100.20"
DEVICE = "dev-sa-a001"

_ACTION = {"investigate_authentication": ActionType.INVESTIGATE_AUTHENTICATION,
           "investigate_user": ActionType.INVESTIGATE_USER, "search_user_activity": ActionType.SEARCH_USER_ACTIVITY,
           "enrich_ip": ActionType.ENRICH_IP, "enrich_email_address": ActionType.ENRICH_EMAIL_ADDRESS,
           "search_ip_enterprise": ActionType.SEARCH_IP_ENTERPRISE,
           "investigate_endpoint": ActionType.INVESTIGATE_ENDPOINT}


def _user(value: str = USER) -> Observable:
    return Observable(type=ObservableType.USER, value=value)


def _ipo(value: str) -> Observable:
    return Observable(type=ObservableType.IP, value=value)


def sign_in(at: datetime, ip: str = OFFICE, country: str = "GB", result: str = "success", user: str = USER,
            device_id: str | None = DEVICE, atomic: str = "investigate_authentication", **extra: Any) -> SignInRecord:
    subject = _ipo(ip) if atomic == "search_ip_enterprise" else _user(user)
    return SignInRecord(integration="microsoft_cloud" if atomic == "search_ip_enterprise" else "entra",
                        atomic=atomic, subject=subject, sign_in_id=f"si-{user}-{ip}-{at.isoformat()}", user=user,
                        timestamp=at, ip=ip, country=country, result=result, device_id=device_id, **extra)


def baseline(n: int = 3, hour: int = 9) -> list[SignInRecord]:
    return [sign_in(NOW - timedelta(days=3 - i) + timedelta(hours=hour - 12, minutes=10 * i), device_compliant=True)
            for i in range(n)]


def at(hour: int, minute: int = 0) -> datetime:
    return NOW.replace(hour=hour, minute=minute)


def profile(user: str = USER, **extra: Any) -> UserProfileRecord:
    return UserProfileRecord(integration="entra", atomic="investigate_user", subject=_user(user), user=user, **extra)


def anomaly(anomaly_type: str, severity: Severity = Severity.MEDIUM, ip: str | None = None,
            first_seen: datetime | None = None) -> AnomalyRecord:
    return AnomalyRecord(integration="entra", atomic="investigate_authentication", subject=_user(),
                         anomaly_id=f"an-{anomaly_type}-{ip}", anomaly_type=anomaly_type, severity=severity, user=USER,
                         ip=ip, first_seen=first_seen)


def reputation(ip: str, verdict: Verdict, integration: str = "cisco_xdr", categories: tuple[str, ...] = ()
               ) -> EnrichmentRecord:
    return EnrichmentRecord(integration=integration, atomic="enrich_ip", subject=_ipo(ip), verdict=verdict,
                            risk_score=80 if verdict is Verdict.MALICIOUS else 40, confidence=70, categories=categories)


def breach(user: str = USER) -> EnrichmentRecord:
    return EnrichmentRecord(integration="hibp", atomic="enrich_email_address",
                            subject=Observable(type=ObservableType.EMAIL_ADDRESS, value=user),
                            verdict=Verdict.SUSPICIOUS, risk_score=40, confidence=90)


def view(records: Sequence[Any], *, users: Sequence[str] = (USER,), ips: Sequence[str] = ()) -> RunView:
    grouped: dict[tuple[str, str, str], list[Any]] = {}
    for record in records:
        grouped.setdefault((record.atomic, record.subject.type.value, record.subject.value), []).append(record)
    results = [AtomicResult(atomic=atomic, action_type=_ACTION[atomic], subject=Observable(type=t, value=v),
                            records=tuple(recs), started_at=NOW, finished_at=NOW)
               for (atomic, t, v), recs in grouped.items()]
    incident = Incident(incident_id="XDR-SA-H-0001", title="Suspicious sign-in", severity=Severity.MEDIUM,
                        created_at=NOW, workflow_id="suspicious-authentication", workflow_version=WORKFLOW.version,
                        users=tuple(users), observables=tuple([_user(u) for u in users] + [_ipo(i) for i in ips]))
    return RunView(workflow=WORKFLOW, incident=incident, results=tuple(results), index=RecordIndex(results),
                   correlation=CorrelationResult(incident_id=incident.incident_id), blast_radius=BlastRadiusReport())


def assess(records: Sequence[Any], **kwargs: Any) -> dict[str, Any]:
    return {u["user"]: u for u in assess_users(view(records, **kwargs))}[USER]


def attacker_sign_in(**extra: Any) -> SignInRecord:
    values = {"ip": ATTACKER, "country": "NL", "device_id": None}
    values.update(extra)
    return sign_in(at(2, 40), **values)


# ------------------------------------------------------------ indicators --
def test_a_malicious_source_unusual_country_device_and_hour_make_a_likely_compromise():
    late = attacker_sign_in(device_compliant=False)
    user = assess([*baseline(), late, reputation(ATTACKER, Verdict.MALICIOUS)])
    assert user["compromised"]
    assert user["families"] == {"device": 1, "flagged_ip": 2, "geography": 1, "time": 1}
    assert user["points"] == 5 and user["sign_in_points"] == 5
    assert user["record_ids"][0] == late.record_id
    assert "country NL" in user["summary"] and "hour 02 UTC" in user["summary"]


def test_without_a_baseline_country_device_and_hour_are_not_assessed():
    user = assess([attacker_sign_in(), reputation(ATTACKER, Verdict.SUSPICIOUS)])
    assert user["families"] == {"flagged_ip": 1}
    assert not user["compromised"] and user["baseline_signins"] == 0


def test_a_suspicious_rating_is_one_point_and_a_malicious_one_two():
    late = attacker_sign_in(country="GB", device_id=DEVICE)
    assert assess([*baseline(hour=2), late, reputation(ATTACKER, Verdict.SUSPICIOUS)])["families"] == {"flagged_ip": 1}
    assert assess([*baseline(hour=2), late, reputation(ATTACKER, Verdict.MALICIOUS)])["families"] == {"flagged_ip": 2}


def test_anonymising_networks_from_detections_and_categories():
    late = attacker_sign_in(country="GB", device_id=DEVICE)
    quiet = baseline(hour=2)
    by_anomaly = assess([*quiet, late, anomaly("anonymous_ip", ip=ATTACKER)])
    assert by_anomaly["families"] == {"anonymizer": 2}
    by_tor = assess([*quiet, late, reputation(ATTACKER, Verdict.SUSPICIOUS, categories=("Tor exit node",))])
    assert by_tor["families"] == {"anonymizer": 2, "flagged_ip": 1} and by_tor["compromised"]
    by_vpn = assess([*quiet, late, reputation(ATTACKER, Verdict.SUSPICIOUS, "alienvault_otx", ("VPN",))])
    assert by_vpn["families"] == {"anonymizer": 1, "flagged_ip": 1} and not by_vpn["compromised"]
    clean_vpn = assess([*quiet, late, reputation(ATTACKER, Verdict.CLEAN, categories=("VPN",))])
    assert clean_vpn["families"] == {}


def test_impossible_travel_is_two_countries_within_two_hours():
    office = sign_in(at(9, 0))
    far = sign_in(at(9, 40), ip=ATTACKER, country="SG")
    user = assess([*baseline(), office, far])
    assert user["families"]["travel"] == 2 and user["families"]["geography"] == 1
    assert user["compromised"]
    later = sign_in(at(11, 30), ip=ATTACKER, country="SG")
    assert "travel" not in assess([*baseline(), office, later])["families"]


def test_the_hour_needs_three_baseline_sign_ins_and_a_four_hour_gap():
    late = sign_in(at(2, 0))
    assert assess([*baseline(2), late])["families"] == {}
    assert assess([*baseline(3), late])["families"] == {"time": 1}
    assert assess([*baseline(3, hour=5), late])["families"] == {}  # 3 hours from the 05:xx baseline
    assert assess([*baseline(3, hour=6), late])["families"] == {"time": 1}  # exactly the 4-hour gap
    nights = [sign_in(NOW - timedelta(days=d, hours=13), device_compliant=True) for d in (3, 4, 5)]  # 23:00 UTC
    assert assess([*nights, late])["families"] == {}  # hours are circular: 23 to 02 is 3 hours


def test_device_indicators():
    new = sign_in(at(10), device_id="dev-sa-x999")
    assert assess([*baseline(), new])["families"] == {"device": 1}
    unregistered = sign_in(at(10), device_id=None)
    assert assess([*baseline(), unregistered])["indicators"][0].startswith("new or unmanaged device")
    noncompliant = sign_in(at(10), device_compliant=False)
    assert assess([*baseline(), noncompliant])["families"] == {"device": 1}


def test_an_intune_non_compliant_managed_device_is_a_device_indicator():
    device = EndpointRecord(integration="intune", atomic="investigate_endpoint",
                            subject=Observable(type=ObservableType.ENDPOINT_ID,
                                               value="00000000-0000-4000-8000-0000000000c1"),
                            hostname="TH-LT-2044", intune_device_id="00000000-0000-4000-8000-0000000000c1",
                            users=(USER,), health_state="noncompliant")
    user = assess([*baseline(), sign_in(at(10)), device])
    assert user["families"] == {"device": 1} and device.record_id in user["record_ids"]


def test_credential_exposure_never_concludes_alone():
    exposed = assess([*baseline(), sign_in(at(10)), breach(), anomaly("leaked_credentials", Severity.HIGH)])
    assert exposed["families"] == {"exposure": 1} and not exposed["compromised"]


def test_identity_risk_needs_two_points_from_the_sign_in_itself():
    risky = assess([*baseline(), sign_in(at(10), device_id="dev-sa-x999"), profile(risk_level="high")])
    assert risky["points"] == 3 and risky["sign_in_points"] == 1 and not risky["compromised"]
    sign_in_risky = assess([*baseline(), sign_in(at(2), device_id="dev-sa-x999"), profile(risk_level="high")])
    assert sign_in_risky["compromised"]


def test_exposure_counts_with_an_unusual_sign_in():
    late = sign_in(at(3), device_id=None, device_compliant=False)
    user = assess([*baseline(), late, breach()])
    assert user["families"] == {"device": 1, "exposure": 1, "time": 1} and user["compromised"]
    assert user["exposure_record_ids"] == [breach().record_id]


def test_a_detection_for_a_failed_attempt_does_not_count_for_the_account():
    failed = sign_in(at(6), ip=ATTACKER, result="failure", device_id=None)
    user = assess([*baseline(), failed, sign_in(at(9)), anomaly("anonymous_ip", Severity.HIGH, ATTACKER)])
    assert user["families"] == {} and not user["compromised"]


def test_old_detections_and_alerts_are_ignored():
    old = anomaly("unfamiliar_location", Severity.HIGH, first_seen=NOW - timedelta(days=5))
    assert assess([*baseline(), sign_in(at(10)), old])["families"] == {}


def test_identity_protection_alerts_map_to_families():
    alert = DetectionRecord(integration="microsoft_cloud", atomic="investigate_user", subject=_user(),
                            detection_id="alert-sa-1", name="Anonymous IP address", verdict=Verdict.SUSPICIOUS,
                            severity=Severity.MEDIUM, user=USER, first_seen=at(10))
    leak = DetectionRecord(integration="microsoft_cloud", atomic="investigate_user", subject=_user(),
                           detection_id="alert-sa-2", name="Leaked credentials", verdict=Verdict.SUSPICIOUS,
                           severity=Severity.HIGH, user=USER, first_seen=at(10))
    user = assess([*baseline(), sign_in(at(10)), alert, leak])
    assert user["families"] == {"anonymizer": 2, "exposure": 1} and user["compromised"]


# ------------------------------------------------------------ shared egress --
def colleagues(n: int, ip: str = EGRESS) -> list[SignInRecord]:
    return [sign_in(at(8, 5 * i), ip=ip, country="DE", user=f"user{i}@example.com", atomic="search_ip_enterprise")
            for i in range(n)]


def test_a_shared_corporate_egress_is_not_a_new_country():
    vpn = sign_in(at(9, 45), ip=EGRESS, country="DE")
    detection = anomaly("unfamiliar_location", Severity.MEDIUM, EGRESS)
    user = assess([*baseline(), vpn, detection, *colleagues(3)])
    assert user["families"] == {}
    assert len(user["discounted"]) == 2 and all("shared egress 198.51.100.20" in d for d in user["discounted"])
    assert vpn.record_id in user["discounted_record_ids"] and detection.record_id in user["discounted_record_ids"]


def test_one_other_account_does_not_make_an_egress():
    vpn = sign_in(at(9, 45), ip=EGRESS, country="DE")
    assert assess([*baseline(), vpn, *colleagues(1)])["families"] == {"geography": 1}


def test_a_flagged_ip_is_never_a_trusted_egress():
    vpn = sign_in(at(9, 45), ip=EGRESS, country="DE")
    user = assess([*baseline(), vpn, *colleagues(3), reputation(EGRESS, Verdict.MALICIOUS)])
    assert user["families"] == {"flagged_ip": 2, "geography": 1} and user["compromised"]
    ip = {i["ip"]: i for i in source_ips(view([*baseline(), vpn, *colleagues(3),
                                                reputation(EGRESS, Verdict.MALICIOUS)]))}[EGRESS]
    assert ip["shared"] and ip["block_worthy"] and not ip["block_candidate"]


def test_a_non_public_source_is_internal(monkeypatch: pytest.MonkeyPatch):
    lab = ipaddress.ip_network("198.51.100.0/24")  # stands in for an RFC 1918 range (test data rules)
    monkeypatch.setattr(module, "non_public_network",
                        lambda value, extra=(): lab if ipaddress.ip_address(value) in lab else None)
    records = [*baseline(), sign_in(at(2, 30), ip="198.51.100.77", country="DE"),
               reputation("198.51.100.77", Verdict.MALICIOUS)]
    user = assess(records)
    assert "geography" not in user["families"] and "time" not in user["families"]
    ip = {i["ip"]: i for i in source_ips(view(records))}["198.51.100.77"]
    assert ip["non_public"] and not ip["block_candidate"]
    considered = {c.subject: c for c in HOOKS.considered(view(records))}
    assert "non-public" in considered["block_ip:198.51.100.77"].reason


# -------------------------------------------------------------- disable --
def compromised(*extra: Any) -> list[Any]:
    return [*baseline(), attacker_sign_in(), reputation(ATTACKER, Verdict.MALICIOUS), *extra]


def test_no_disable_reason_for_an_ordinary_account():
    user = assess(compromised(profile()))
    assert user["compromised"] and user["disable_reasons"] == []


def test_disable_reasons():
    admin = assess(compromised(profile(roles=("Security Administrator",))))
    assert admin["disable_reasons"] == ["privileged account (Security Administrator)"] and admin["privileged"]
    revoked = profile(sessions_valid_from=at(1))
    used_again = assess(compromised(revoked))
    assert used_again["disable_reasons"][0].startswith("suspicious sign-in after the sessions were revoked")
    assert revoked.record_id in used_again["disable_record_ids"]
    confirmed = assess(compromised(profile(risk_state="confirmed_compromised")))
    assert "the identity provider confirmed the compromise" in confirmed["disable_reasons"]


def test_post_sign_in_persistence_counts_only_after_the_suspicious_sign_in():
    def rule(created: datetime) -> MailboxRuleRecord:
        return MailboxRuleRecord(integration="entra", atomic="search_user_activity", subject=_user(), mailbox=USER,
                                 rule_id=f"r-{created.isoformat()}", name="Archive copy", external_forwarding=True,
                                 forward_to=("archive-box@mailbox.test",), created_at=created)
    after, before = rule(at(2, 55)), rule(at(1, 0))
    assert assess(compromised(after))["disable_reasons"] == ["post-sign-in persistence: mailbox rule 'Archive copy'"]
    assert assess(compromised(before))["disable_reasons"] == []


def test_a_privileged_role_granted_during_the_incident_is_privileged():
    grant = RoleChangeRecord(integration="entra", atomic="search_user_activity", subject=_user(), user=USER,
                             role_name="Exchange Administrator", change="assigned", privileged=True,
                             timestamp=at(3))
    user = assess(compromised(grant))
    assert user["privileged"] and "Exchange Administrator" in user["roles"]
    assert grant.record_id in user["disable_record_ids"]


# ------------------------------------------------------------------- IPs --
def test_block_candidates():
    failed = sign_in(at(6), ip=ATTACKER, result="failure", device_id=None)
    ips = {i["ip"]: i for i in source_ips(view([*baseline(), failed, reputation(ATTACKER, Verdict.MALICIOUS)]))}
    assert ips[ATTACKER]["block_candidate"] and failed.record_id in ips[ATTACKER]["record_ids"]
    suspicious = {i["ip"]: i for i in source_ips(view([failed, reputation(ATTACKER, Verdict.SUSPICIOUS)]))}
    assert not suspicious[ATTACKER]["block_worthy"]
    detected = {i["ip"]: i for i in source_ips(view([failed, anomaly("anonymous_ip", Severity.HIGH, ATTACKER)]))}
    assert detected[ATTACKER]["block_candidate"]


def test_an_incident_ip_is_blocked_on_its_reputation_when_no_sign_in_is_known():
    rating = reputation(ATTACKER, Verdict.MALICIOUS)
    ips = {i["ip"]: i for i in source_ips(view([rating], ips=(ATTACKER,)))}
    assert ips[ATTACKER]["named_by_incident"] and ips[ATTACKER]["record_ids"] == [rating.record_id]
    assert ips[ATTACKER]["block_candidate"]


def test_an_old_sign_in_ip_is_not_a_block_candidate():
    old = sign_in(NOW - timedelta(days=4), ip=ATTACKER)
    assert source_ips(view([old, reputation(ATTACKER, Verdict.MALICIOUS)])) == []


def test_a_shared_malicious_ip_is_considered_not_blocked():
    late = attacker_sign_in()
    records = [*baseline(), late, reputation(ATTACKER, Verdict.MALICIOUS), *colleagues(1, ATTACKER)]
    facts = HOOKS.facts(view(records))
    assert facts["block_ips"] == []
    considered = {c.subject: c for c in HOOKS.considered(view(records))}
    assert "shared egress" in considered[f"block_ip:{ATTACKER}"].reason


# ----------------------------------------------------- facts and hooks --
def test_facts_are_json_and_cite_only_run_records():
    records = compromised(profile(sessions_valid_from=at(1)), breach())
    run_view = view(records, ips=(ATTACKER,))
    facts = HOOKS.facts(run_view)
    json.dumps(facts)
    for item in (*facts["compromised_users"], *facts["block_ips"]):
        assert item["record_ids"] and all(i in run_view.index for i in item["record_ids"])
    assert [u["user"] for u in facts["disable_users"]] == [USER]


def test_signals_cite_their_own_records_and_only_for_conclusions():
    records = compromised(profile(sessions_valid_from=at(1)))
    run_view = view(records)
    signals = HOOKS.derive_signals(run_view)
    assert signals
    for signal in signals:
        cited = run_view.index.require(signal.record_ids)
        assert signal.origin == "workflow:suspicious-authentication"
        assert signal.category is SignalCategory.AUTHENTICATION_ANOMALY
        assert signal.integration in {r.integration for r in cited}
    assert {s.observable.value for s in signals} == {USER, ATTACKER}
    benign = view([*baseline(), sign_in(at(10), country="FR")])
    assert HOOKS.derive_signals(benign) == []


def test_considerations_handoffs_and_manual_steps():
    records = compromised()
    items = {c.subject: c for c in HOOKS.considered(view(records))}
    assert set(items) == {f"password-reset:{USER}"} and items[f"password-reset:{USER}"].manual
    (handoff,) = HOOKS.handoffs(view(records))
    assert handoff.workflow_id == "account-takeover" and handoff.subjects == (USER,)
    weak = {c.subject: c for c in HOOKS.considered(view([*baseline(), sign_in(at(10), country="FR"), breach()]))}
    assert "below the threshold" in weak[f"revoke_sessions:{USER}"].reason
    assert weak[f"password-reset:{USER}"].manual
    assert HOOKS.handoffs(view([*baseline(), sign_in(at(10))])) == ()


def test_correlation_links_tie_the_account_to_its_suspicious_sources():
    late = attacker_sign_in()
    links = HOOKS.correlate(view([*baseline(), late, reputation(ATTACKER, Verdict.MALICIOUS)]))
    assert len(links) == 1
    link = links[0]
    assert link.kind is LinkKind.WORKFLOW and link.origin == "workflow:suspicious-authentication"
    assert {e.value for e in link.entities} == {USER, ATTACKER} and link.record_ids == (late.record_id,)


def test_records_of_other_accounts_never_count_for_the_investigated_account():
    other = sign_in(at(2, 40), ip=ATTACKER, country="NL", user="akim@example.com")
    user = assess([*baseline(), other, reputation(ATTACKER, Verdict.MALICIOUS)])
    assert user["families"] == {} and user["recent_signins"] == 0
