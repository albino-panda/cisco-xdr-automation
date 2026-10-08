"""Pure tests of the password-spray hooks over hand-built typed records (no adapters, no lifecycle)."""
from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from xdr_response.atomics.correlation.models import BlastRadiusReport, CorrelationResult
from xdr_response.atomics.evidence import RecordIndex
from xdr_response.atomics.records import (
    AnomalyRecord,
    AtomicResult,
    EndpointRecord,
    EnrichmentRecord,
    NetworkConnectionRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, Verdict
from xdr_response.models.scoring import SignalCategory
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.password_spray import HOOKS, WORKFLOW
from xdr_response.workflows.password_spray.hooks import compromised_accounts, spray_sources

T0 = datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)
SPRAY = "198.51.100.77"
OTHER = "203.0.113.150"
HOME = "198.51.100.25"
USERS = ("jsmith@example.com", "akim@example.com", "rlopez@example.com")


def _user(value: str) -> Observable:
    return Observable(type=ObservableType.USER, value=value)


def _ipo(value: str) -> Observable:
    return Observable(type=ObservableType.IP, value=value)


def sign_in(user: str, ip: str, result: str, minute: int = 0, integration: str = "entra", **extra: Any) -> SignInRecord:
    return SignInRecord(integration=integration, atomic="investigate_authentication", subject=_user(user),
                        sign_in_id=f"si-{integration}-{user}-{ip}-{result}-{minute}", user=user,
                        timestamp=T0 + timedelta(minutes=minute), ip=ip, result=result, **extra)


def profile(user: str, **extra: Any) -> UserProfileRecord:
    return UserProfileRecord(integration="entra", atomic="investigate_user", subject=_user(user), user=user, **extra)


def anomaly(user: str, anomaly_type: str, severity: Severity = Severity.MEDIUM) -> AnomalyRecord:
    return AnomalyRecord(integration="entra", atomic="investigate_user", subject=_user(user),
                         anomaly_id=f"an-{user}-{anomaly_type}", anomaly_type=anomaly_type, severity=severity, user=user)


def reputation(ip: str, verdict: Verdict, integration: str = "cisco_xdr") -> EnrichmentRecord:
    return EnrichmentRecord(integration=integration, atomic="enrich_ip", subject=_ipo(ip), verdict=verdict,
                            risk_score=70 if verdict is not Verdict.CLEAN else 0, confidence=70)


def sighting(ip: str, endpoint: str) -> NetworkConnectionRecord:
    return NetworkConnectionRecord(integration="cisco_xdr", atomic="search_ip_enterprise", subject=_ipo(ip),
                                   endpoint=endpoint, remote_ip=ip, remote_port=443, first_seen=T0)


def endpoint(ip: str, hostname: str) -> EndpointRecord:
    return EndpointRecord(integration="cisco_xdr", atomic="search_ip_enterprise", subject=_ipo(ip),
                          hostname=hostname, ip_addresses=(ip,))


_ACTION = {"investigate_authentication": ActionType.INVESTIGATE_AUTHENTICATION,
           "investigate_user": ActionType.INVESTIGATE_USER, "enrich_ip": ActionType.ENRICH_IP,
           "search_ip_enterprise": ActionType.SEARCH_IP_ENTERPRISE}


def view(records: Sequence[Any], *, ips: Sequence[str] = (SPRAY,), users: Sequence[str] = USERS) -> RunView:
    grouped: dict[tuple[str, str, str], list[Any]] = {}
    for record in records:
        grouped.setdefault((record.atomic, record.subject.type.value, record.subject.value), []).append(record)
    results = [AtomicResult(atomic=atomic, action_type=_ACTION[atomic], subject=Observable(type=t, value=v),
                            records=tuple(recs), started_at=T0, finished_at=T0)
               for (atomic, t, v), recs in grouped.items()]
    incident = Incident(incident_id="XDR-PS-H-0001", title="Password spray", severity=Severity.MEDIUM,
                        created_at=T0, workflow_id="password-spray", workflow_version=WORKFLOW.version,
                        observables=tuple([_ipo(i) for i in ips] + [_user(u) for u in users]))
    return RunView(workflow=WORKFLOW, incident=incident, results=tuple(results), index=RecordIndex(results),
                   correlation=CorrelationResult(incident_id=incident.incident_id), blast_radius=BlastRadiusReport())


def spray(ip: str = SPRAY, users: Sequence[str] = USERS, start: int = 0) -> list[SignInRecord]:
    return [sign_in(u, ip, "failure", start + i) for i, u in enumerate(users)]


def by_ip(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["ip"]: item for item in items}


# --------------------------------------------------------------- sources --
def test_incident_addresses_are_sources_and_cite_their_sign_ins():
    records = spray()
    sources = by_ip(spray_sources(view(records)))
    assert list(sources) == [SPRAY]
    item = sources[SPRAY]
    assert item["named_by_incident"] and item["failure_count"] == 3 and item["success_count"] == 0
    assert item["failed_accounts"] == sorted(USERS)
    assert item["record_ids"] == [r.record_id for r in records]
    assert not item["shared_infrastructure"] and item["internal_endpoint"] is None


def test_an_unnamed_address_is_a_source_only_with_failures_against_three_accounts():
    three = spray() + spray(OTHER, USERS, 10)
    two = spray() + spray(OTHER, USERS[:2], 10)
    assert set(by_ip(spray_sources(view(three)))) == {SPRAY, OTHER}
    assert not by_ip(spray_sources(view(three)))[OTHER]["named_by_incident"]
    assert "not named by the incident" in by_ip(spray_sources(view(three)))[OTHER]["summary"]
    assert set(by_ip(spray_sources(view(two)))) == {SPRAY}


def test_a_named_address_without_any_record_has_no_evidence():
    item = by_ip(spray_sources(view(spray(), ips=(SPRAY, OTHER))))[OTHER]
    assert item["record_ids"] == [] and item["failure_count"] == 0  # the rule reports it as NO_EVIDENCE


def test_supporting_reputation_is_cited_but_clean_is_not():
    bad, clean = reputation(SPRAY, Verdict.MALICIOUS), reputation(OTHER, Verdict.CLEAN)
    items = by_ip(spray_sources(view([*spray(), bad, clean], ips=(SPRAY, OTHER))))
    assert bad.record_id in items[SPRAY]["record_ids"]
    assert items[SPRAY]["verdicts"] == {"cisco_xdr": "MALICIOUS"}
    assert clean.record_id not in items[OTHER]["record_ids"]


def test_clean_rating_marks_shared_infrastructure_unless_another_source_contradicts_it():
    clean = reputation(SPRAY, Verdict.CLEAN)
    shared = by_ip(spray_sources(view([*spray(), clean])))[SPRAY]
    assert shared["shared_infrastructure"] and shared["shared_reasons"] == ["rated CLEAN by cisco_xdr"]
    contradicted = by_ip(spray_sources(view([*spray(), clean, reputation(SPRAY, Verdict.SUSPICIOUS,
                                                                            "alienvault_otx")])))[SPRAY]
    assert not contradicted["shared_infrastructure"]


def test_internal_sightings_mark_shared_infrastructure():
    item = by_ip(spray_sources(view([*spray(), sighting(SPRAY, "TH-LT-1047"), sighting(SPRAY, "TH-LT-1052")])))[SPRAY]
    assert item["shared_infrastructure"] and item["internal_sightings"] == 2
    assert item["sighting_endpoints"] == ["TH-LT-1047", "TH-LT-1052"]
    assert item["shared_reasons"] == ["2 internal endpoints talk to it"]


def test_an_address_owned_by_an_investigated_endpoint_is_internal():
    record = endpoint("192.0.2.70", "TH-LT-2210")
    item = by_ip(spray_sources(view([*spray("192.0.2.70"), record], ips=("192.0.2.70",))))["192.0.2.70"]
    assert item["internal_endpoint"] == "TH-LT-2210" and item["internal_record_ids"] == [record.record_id]


# -------------------------------------------------------------- accounts --
def test_only_a_success_from_a_spray_source_marks_an_account():
    success = sign_in("jsmith@example.com", SPRAY, "success", 9)
    home = sign_in("rlopez@example.com", HOME, "success", 9)
    accounts = compromised_accounts(view([*spray(), success, home]))
    assert [a["user"] for a in accounts] == ["jsmith@example.com"]
    item = accounts[0]
    assert item["success_ips"] == [SPRAY] and item["success_count"] == 1 and item["failure_count"] == 1
    assert set(item["record_ids"]) == {success.record_id, spray()[0].record_id}
    assert not item["follow_on"] and item["follow_on_record_ids"] == []


def test_failed_attempts_and_account_risk_alone_never_mark_an_account():
    records = [*spray(), profile("akim@example.com", risk_level="high"), anomaly("akim@example.com", "mfa_fatigue")]
    assert compromised_accounts(view(records)) == []


def test_follow_on_activity_counts_only_listed_anomalies_and_high_risk():
    success = sign_in("jsmith@example.com", SPRAY, "success", 9)
    unfamiliar = anomaly("jsmith@example.com", "unfamiliar_location")
    assert not compromised_accounts(view([*spray(), success, unfamiliar]))[0]["follow_on"]
    fatigue = anomaly("jsmith@example.com", "mfa_fatigue", Severity.HIGH)
    item = compromised_accounts(view([*spray(), success, unfamiliar, fatigue]))[0]
    assert item["follow_on"] and item["follow_on_record_ids"] == [fatigue.record_id]
    assert "mfa_fatigue anomaly" in item["follow_on_summary"]
    risky = profile("jsmith@example.com", risk_level="high", groups=("Sales",))
    item = compromised_accounts(view([*spray(), success, risky]))[0]
    assert item["follow_on_record_ids"] == [risky.record_id] and item["groups"] == ["Sales"]
    risky_sign_in = sign_in("jsmith@example.com", SPRAY, "success", 11, risk_level="high")
    item = compromised_accounts(view([*spray(), risky_sign_in]))[0]
    assert item["follow_on_record_ids"] == [risky_sign_in.record_id]


def test_account_items_carry_privileged_context_for_the_package_builder():
    success = sign_in("adm-tgreen@example.com", SPRAY, "success", 9)
    admin = profile("adm-tgreen@example.com", groups=("Domain Admins",), roles=("Global Administrator",))
    item = compromised_accounts(view([success, admin], users=("adm-tgreen@example.com",)))[0]
    assert item["groups"] == ["Domain Admins"] and item["roles"] == ["Global Administrator"]
    assert item["profile_record_ids"] == [admin.record_id]


# --------------------------------------------------------------- signals --
def test_signals_cite_only_sign_ins_and_are_attributed_to_their_source():
    success = sign_in("jsmith@example.com", SPRAY, "success", 9)
    splunk_rows = [sign_in(u, SPRAY, "failure", 20 + i, integration="splunk") for i, u in enumerate(USERS[:2])]
    run_view = view([*spray(), success, *splunk_rows, reputation(SPRAY, Verdict.MALICIOUS)])
    signals = HOOKS.derive_signals(run_view)
    assert signals
    for signal in signals:
        cited = [run_view.index.get(i) for i in signal.record_ids]
        assert all(isinstance(r, SignInRecord) for r in cited)
        assert {r.integration for r in cited} == {signal.integration}
        assert signal.origin == "workflow:password-spray" and signal.category is SignalCategory.AUTHENTICATION_ANOMALY
        assert signal.verdict is Verdict.SUSPICIOUS and not signal.vendor_verdict
    ip_signals = [s for s in signals if s.observable.type is ObservableType.IP]
    assert {s.integration for s in ip_signals} == {"entra", "splunk"}
    assert {s.severity for s in ip_signals} == {80}  # the spray succeeded from this address
    user_signals = [s for s in signals if s.observable.type is ObservableType.USER]
    # one signal per source integration: jsmith's spray attempts were seen by Entra and by Splunk
    assert {(s.observable.value, s.integration) for s in user_signals} == {
        ("jsmith@example.com", "entra"), ("jsmith@example.com", "splunk")}


def test_pattern_signal_needs_two_accounts_and_grows_with_the_fan_out():
    assert HOOKS.derive_signals(view(spray(users=USERS[:1]))) == []
    narrow = HOOKS.derive_signals(view(spray(users=USERS[:2])))
    assert [s.severity for s in narrow] == [60]
    wide_users = [f"user{n}@example.com" for n in range(5)]
    wide = HOOKS.derive_signals(view(spray(users=wide_users), users=wide_users))
    assert [s.severity for s in wide] == [70]


def test_facts_are_plain_json_and_deterministic():
    records = [*spray(), sign_in("jsmith@example.com", SPRAY, "success", 9), reputation(SPRAY, Verdict.SUSPICIOUS)]
    first = HOOKS.facts(view(records))
    second = HOOKS.facts(view(list(reversed(records))))
    assert json.loads(json.dumps(first)) == first
    assert first == second
    assert set(first) == {"spray_sources", "compromised_accounts"}


def test_hooks_never_cite_unknown_records():
    run_view = view([*spray(), sign_in("jsmith@example.com", SPRAY, "success", 9), anomaly("jsmith@example.com",
                                                                                          "new_device")])
    facts = HOOKS.facts(run_view)
    cited = [i for item in facts["spray_sources"] for i in item["record_ids"]]
    cited += [i for item in facts["compromised_accounts"] for i in item["record_ids"] + item["follow_on_record_ids"]]
    cited += [i for signal in HOOKS.derive_signals(run_view) for i in signal.record_ids]
    assert cited and all(i in run_view.index for i in cited)
