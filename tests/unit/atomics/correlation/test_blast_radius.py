"""Blast radius / scoping (architecture 14.1.5): scope from the incident's clusters, critical assets
always reported, caps informational only."""
from __future__ import annotations

from xdr_response.atomics.correlation import EntityRef, blast_radius, correlate
from xdr_response.atomics.records import (
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    HashPrevalenceRecord,
    UserProfileRecord,
)
from xdr_response.config import Settings
from xdr_response.models import Asset, BlastRadius, CriticalAssetClass, TargetKind, Verdict

from tests.unit.atomics.evidence._factories import (
    EVIL_DOMAIN,
    HASH_A,
    HASH_B,
    HOST_1,
    HOST_2,
    HOST_3,
    USER_1,
    USER_2,
    at,
    context,
    incident,
    obs,
    record,
    result,
)

CRITICAL = {
    "classes": {
        "domain_controller": {"display_name": "Domain controller", "role": "Active Directory DC",
                              "potential_impact": "Authentication outage", "match": {"hostname_patterns": ["th-dc-*"]}},
        "privileged_account": {"display_name": "Privileged account", "role": "Tier 0 admin",
                               "potential_impact": "Admin lockout", "match": {"groups": ["Tier0-Admins"]}},
    }
}


def ref(kind: str, value: str) -> EntityRef:
    return EntityRef(kind=TargetKind(kind), value=value)


def _prevalence(sha: str, *hosts: str):
    return record(HashPrevalenceRecord, atomic="search_hash_enterprise", subject=obs("sha256", sha), sha256=sha,
                  prevalence=len(hosts), endpoints=hosts)


def _endpoint(host: str, *users: str, groups: tuple[str, ...] = ()):
    return record(EndpointRecord, hostname=host, users=users, groups=groups, connector_guid=f"guid-{host}",
                  observed_at=at(0))


def _run(inc, *results, settings=None, scope=None):
    ctx = context(inc, settings)
    corr = correlate(ctx, list(results))
    return blast_radius(ctx, corr, list(results), scope=scope)


def test_scope_is_the_incident_cluster_only():
    linked = _prevalence(HASH_A, HOST_1, HOST_2)
    unrelated = _prevalence(HASH_B, HOST_3, "TH-LT-9001")
    inc = incident(obs("sha256", HASH_A))
    report = _run(inc, result(linked, unrelated))
    assert report.endpoints == (HOST_1, HOST_2)
    assert report.indicators == (HASH_A,)
    assert report.users == () and report.messages == 0
    assert report.record_ids == (linked.record_id,)
    assert report.critical_assets == ()


def test_incident_entities_are_in_scope_even_without_records():
    inc = incident(obs("domain", EVIL_DOMAIN), users=(USER_1,))
    report = _run(inc)
    assert report.indicators == (EVIL_DOMAIN,)
    assert report.users == (USER_1,)
    assert report.record_ids == ()


def test_caps_are_reported_but_never_decide_anything():
    settings = Settings(thresholds={"blast_radius": {"max_endpoints": 1, "max_users": 0}})
    prevalence = _prevalence(HASH_A, HOST_1, HOST_2)
    report = _run(incident(obs("sha256", HASH_A), users=(USER_1,)), result(prevalence), settings=settings)
    assert report.caps == {"endpoints": 1, "users": 0, "indicators": 50, "messages": 500}
    assert report.exceeds == ("endpoints", "users")
    assert report.to_blast_radius() == BlastRadius(endpoints=(HOST_1, HOST_2), users=(USER_1,),
                                                   indicators=(HASH_A,), messages=0)


def test_critical_assets_in_scope_are_always_reported():
    settings = Settings(critical_assets=CRITICAL)
    prevalence = _prevalence(HASH_A, HOST_1, HOST_3)
    profile = record(UserProfileRecord, integration="entra", atomic="investigate_user", subject=obs("user", USER_2),
                     user=USER_2, groups=("Tier0-Admins",))
    endpoint = _endpoint(HOST_1, USER_2)
    report = _run(incident(obs("sha256", HASH_A)), result(prevalence), result(profile), result(endpoint),
                  settings=settings)
    hits = {hit.entity: hit for hit in report.critical_assets}
    dc = hits[ref("ENDPOINT", HOST_3)]
    assert dc.classes == (CriticalAssetClass.DOMAIN_CONTROLLER,)
    assert dc.record_ids == (prevalence.record_id,)
    admin = hits[ref("USER", USER_2)]  # classified from the group the run's own profile record reports
    assert admin.classes == (CriticalAssetClass.PRIVILEGED_ACCOUNT,)
    assert set(admin.record_ids) == {profile.record_id, endpoint.record_id}
    assert report.rule_item()["has_critical_asset"] is True


def test_incident_asset_context_feeds_classification():
    settings = Settings(critical_assets=CRITICAL)
    inc = incident(obs("hostname", HOST_2),
                   assets=(Asset(name=HOST_2, kind=TargetKind.ENDPOINT, groups=("Tier0-Admins",)),))
    report = _run(inc, settings=settings)
    assert [h.entity for h in report.critical_assets] == [ref("ENDPOINT", HOST_2)]


def test_messages_and_users_of_a_phishing_scope():
    msgs = [record(EmailMessageRecord, integration="secure_email", atomic="search_email_campaign",
                   subject=obs("email_message_id", "msg-1@sender.example"), message_id=mid,
                   sender="billing@sender.example", recipients=(user,), recipient_count=1, campaign_id="camp-1",
                   verdict=Verdict.MALICIOUS, domains=(EVIL_DOMAIN,), received_at=at(0))
            for mid, user in (("msg-1@sender.example", USER_1), ("msg-2@sender.example", USER_2))]
    report = _run(incident(obs("email_message_id", "msg-1@sender.example")), result(*msgs))
    assert report.messages == 2
    assert report.users == tuple(sorted((USER_1, USER_2)))
    assert report.indicators == (EVIL_DOMAIN,)
    assert "billing@sender.example" not in report.users  # senders are not affected users


def test_explicit_scope_is_used_as_given():
    q = record(DnsQueryRecord, integration="umbrella", atomic="investigate_domain", subject=obs("domain", EVIL_DOMAIN),
               endpoint=HOST_1, domain=EVIL_DOMAIN, first_seen=at(1))
    report = _run(incident(obs("domain", EVIL_DOMAIN)), result(q), scope=[ref("ENDPOINT", HOST_1)])
    assert report.endpoints == (HOST_1,) and report.indicators == ()
    assert report.record_ids == (q.record_id,)


def test_blast_radius_is_deterministic():
    results = [result(_prevalence(HASH_A, HOST_2, HOST_1)), result(_endpoint(HOST_1, USER_1))]
    inc = incident(obs("sha256", HASH_A))
    assert _run(inc, *results) == _run(inc, *reversed(results))


def test_one_hop_adds_assets_but_not_indicators_other_records_mention():
    single = _prevalence(HASH_A, HOST_1)  # one endpoint: no same_hash link, still in scope
    benign = record(DnsQueryRecord, integration="umbrella", atomic="investigate_domain",
                    subject=obs("domain", "cdn.benign.example"), endpoint=HOST_1, domain="cdn.benign.example",
                    first_seen=at(2))
    report = _run(incident(obs("sha256", HASH_A)), result(single), result(benign))
    assert report.endpoints == (HOST_1,)
    assert report.indicators == (HASH_A,)
    assert report.record_ids == tuple(sorted([single.record_id, benign.record_id]))  # records naming scope
