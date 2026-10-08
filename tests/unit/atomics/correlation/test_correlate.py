"""Framework correlation rules (architecture 14.1.5): pure, deterministic, citing records only."""
from __future__ import annotations

from datetime import timedelta

import pytest

from xdr_response.atomics.correlation import (
    FRAMEWORK_LINK_KINDS,
    CorrelationLink,
    EntityRef,
    LinkKind,
    build_timeline,
    correlate,
)
from xdr_response.atomics.evidence import EvidenceError, RecordIndex
from xdr_response.atomics.records import (
    CloudAppRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    HashPrevalenceRecord,
    MailboxRuleRecord,
    NetworkConnectionRecord,
    ProcessEventRecord,
    RoleChangeRecord,
    SignInRecord,
)
from xdr_response.models import TargetKind, Verdict

from tests.unit.atomics.evidence._factories import (
    EVIL_DOMAIN,
    EVIL_IP,
    HASH_A,
    HASH_B,
    HOST_1,
    HOST_2,
    USER_1,
    USER_2,
    at,
    context,
    obs,
    record,
    result,
)

CTX = context()


def ref(kind: str, value: str) -> EntityRef:
    return EntityRef(kind=TargetKind(kind), value=value)


def links_of(corr, kind: LinkKind):
    return [link for link in corr.links if link.kind is kind]


def _endpoint(host: str, *users: str):
    return record(EndpointRecord, hostname=host, users=users, connector_guid=f"guid-{host}", observed_at=at(0))


def _dns(host: str, domain: str, minutes: int):
    return record(DnsQueryRecord, integration="umbrella", atomic="investigate_domain", subject=obs("domain", domain),
                  endpoint=host, domain=domain, first_seen=at(minutes))


def _sign_in(user: str, minutes: int, outcome: str = "success", ip: str = "198.51.100.7"):
    return record(SignInRecord, integration="entra", atomic="investigate_user", subject=obs("user", user),
                  user=user, timestamp=at(minutes), ip=ip, result=outcome, sign_in_id=f"si-{user}-{minutes}")


def _mail_rule(user: str, minutes: int, rule_id: str = "rule-1"):
    return record(MailboxRuleRecord, integration="microsoft_cloud", atomic="investigate_user",
                  subject=obs("user", user), mailbox=user, rule_id=rule_id, name="fwd",
                  forward_to=("drop@external.example",), external_forwarding=True, created_at=at(minutes))


def _message(message_id: str, recipient: str = USER_1, **extra):
    fields = {"sender": "billing@sender.example", "sender_domain": "sender.example", "recipients": (recipient,),
              "recipient_count": 1, "received_at": at(0), "verdict": Verdict.MALICIOUS, **extra}
    return record(EmailMessageRecord, integration="secure_email", atomic="investigate_email",
                  subject=obs("email_message_id", message_id), message_id=message_id, **fields)


# ------------------------------------------------------------------------------- shared-entity rules


def test_same_hash_links_an_indicator_seen_on_two_endpoints():
    prevalence = record(HashPrevalenceRecord, integration="secure_endpoint", atomic="search_hash_enterprise",
                        subject=obs("sha256", HASH_A), sha256=HASH_A, prevalence=2, endpoints=(HOST_1, HOST_2))
    corr = correlate(CTX, [result(prevalence)])
    (link,) = links_of(corr, LinkKind.SAME_HASH)
    assert link.entities == (ref("ENDPOINT", HOST_1), ref("ENDPOINT", HOST_2), ref("HASH", HASH_A))
    assert link.record_ids == (prevalence.record_id,)
    assert link.origin == "framework" and "2 endpoint(s)" in link.note


def test_same_domain_needs_two_distinct_assets():
    one = correlate(CTX, [result(_dns(HOST_1, EVIL_DOMAIN, 1), _dns(HOST_1, EVIL_DOMAIN, 2))])
    assert links_of(one, LinkKind.SAME_DOMAIN) == []
    q1, q2 = _dns(HOST_1, EVIL_DOMAIN, 1), _dns(HOST_2, EVIL_DOMAIN, 2)
    two = correlate(CTX, [result(q1, q2)])
    (link,) = links_of(two, LinkKind.SAME_DOMAIN)
    assert set(link.record_ids) == {q1.record_id, q2.record_id}
    assert ref("DOMAIN", EVIL_DOMAIN) in link.entities


def test_same_ip_from_connections_of_two_users():
    conns = [record(NetworkConnectionRecord, integration="defender_endpoint", atomic="investigate_ip",
                    subject=obs("ip", EVIL_IP), user=user, remote_ip=EVIL_IP, remote_port=443, first_seen=at(i))
             for i, user in enumerate((USER_1, USER_2))]
    (link,) = links_of(correlate(CTX, [result(*conns)]), LinkKind.SAME_IP)
    assert link.entities == (ref("IP", EVIL_IP), ref("USER", USER_2), ref("USER", USER_1))
    assert link.first_seen == at(0) and link.last_seen == at(1)


def test_same_user_and_same_endpoint():
    e1, e2 = _endpoint(HOST_1, USER_1), _endpoint(HOST_2, USER_1, USER_2)
    corr = correlate(CTX, [result(e1, e2)])
    (same_user,) = links_of(corr, LinkKind.SAME_USER)
    assert same_user.entities == (ref("ENDPOINT", HOST_1), ref("ENDPOINT", HOST_2), ref("USER", USER_1))
    (same_endpoint,) = links_of(corr, LinkKind.SAME_ENDPOINT)
    assert same_endpoint.record_ids == (e2.record_id,)
    assert corr.related(ref("USER", USER_2)) == (ref("ENDPOINT", HOST_1), ref("ENDPOINT", HOST_2),
                                                 ref("USER", USER_1))


# ------------------------------------------------------------------------------------ lineage


def _proc(pid: int, minutes: int, name: str, parent_pid: int | None = None, sha: str | None = None,
          host: str = HOST_1):
    return record(ProcessEventRecord, endpoint=host, timestamp=at(minutes), event_type="process_start",
                  process_name=name, pid=pid, parent_pid=parent_pid, sha256=sha, event_id=f"ev-{host}-{pid}")


def test_process_lineage_links_parent_and_child_on_one_endpoint():
    parent, child = _proc(100, 0, "winword.exe"), _proc(200, 1, "powershell.exe", parent_pid=100, sha=HASH_B)
    unrelated = _proc(300, 2, "notepad.exe", parent_pid=999)
    corr = correlate(CTX, [result(parent, child, unrelated)])
    (link,) = links_of(corr, LinkKind.PROCESS_LINEAGE)
    assert link.entities == (ref("ENDPOINT", HOST_1), ref("PROCESS", f"{HOST_1}/100"), ref("PROCESS", f"{HOST_1}/200"))
    assert link.record_ids == tuple(sorted([parent.record_id, child.record_id]))
    assert link.first_seen == at(0) and link.last_seen == at(1)


def test_process_lineage_matches_parent_hash_but_never_across_endpoints():
    parent = record(ProcessEventRecord, endpoint=HOST_1, timestamp=at(0), event_type="process_start",
                    sha256=HASH_A, event_id="ev-p")
    child = record(ProcessEventRecord, endpoint=HOST_1, timestamp=at(1), event_type="process_start",
                   sha256=HASH_B, parent_sha256=HASH_A, event_id="ev-c")
    elsewhere = _proc(400, 1, "x.exe", host=HOST_2, sha=HASH_B)
    other_host_child = record(ProcessEventRecord, endpoint=HOST_2, timestamp=at(2), event_type="process_start",
                              pid=401, parent_sha256=HASH_A, event_id="ev-o")
    corr = correlate(CTX, [result(parent, child, elsewhere, other_host_child)])
    (link,) = links_of(corr, LinkKind.PROCESS_LINEAGE)
    assert ref("PROCESS", f"{HOST_1}/{HASH_A}") in link.entities
    assert other_host_child.record_id not in link.record_ids


# ------------------------------------------------------------------------------ sign-in to activity


def test_sign_in_followed_by_mailbox_rule_within_window():
    si, rule = _sign_in(USER_1, 0), _mail_rule(USER_1, 10)
    corr = correlate(CTX, [result(si, rule)])
    (link,) = links_of(corr, LinkKind.SIGN_IN_TO_ACTIVITY)
    assert link.record_ids == tuple(sorted([si.record_id, rule.record_id]))
    assert link.entities == (ref("EMAIL_ADDRESS", "drop@external.example"), ref("IP", "198.51.100.7"),
                             ref("USER", USER_1))
    assert "mailbox rule" in link.note


def test_sign_in_activity_respects_window_order_and_success():
    late = correlate(CTX, [result(_sign_in(USER_1, 0), _mail_rule(USER_1, 61))])
    assert links_of(late, LinkKind.SIGN_IN_TO_ACTIVITY) == []
    wider = correlate(CTX, [result(_sign_in(USER_1, 0), _mail_rule(USER_1, 61))], window=timedelta(minutes=90))
    assert len(links_of(wider, LinkKind.SIGN_IN_TO_ACTIVITY)) == 1
    before = correlate(CTX, [result(_sign_in(USER_1, 30), _mail_rule(USER_1, 10))])
    assert links_of(before, LinkKind.SIGN_IN_TO_ACTIVITY) == []
    failed = correlate(CTX, [result(_sign_in(USER_1, 0, outcome="failure"), _mail_rule(USER_1, 5))])
    assert links_of(failed, LinkKind.SIGN_IN_TO_ACTIVITY) == []
    other_user = correlate(CTX, [result(_sign_in(USER_2, 0), _mail_rule(USER_1, 5))])
    assert links_of(other_user, LinkKind.SIGN_IN_TO_ACTIVITY) == []


def test_sign_in_followed_by_role_change_and_app_consent():
    si = _sign_in(USER_1, 0)
    role = record(RoleChangeRecord, integration="entra", atomic="investigate_user", subject=obs("user", USER_1),
                  user=USER_1, role_name="Global Administrator", role_definition_id="role-def-1",
                  change="assigned", privileged=True, actor=USER_1, timestamp=at(3))
    app = record(CloudAppRecord, integration="entra", atomic="investigate_user", subject=obs("user", USER_1),
                 app_id="00000000-0000-4000-8000-0000000000aa", consent_type="user", consented_by=USER_1,
                 created_at=at(4))
    corr = correlate(CTX, [result(si, role, app)])
    found = links_of(corr, LinkKind.SIGN_IN_TO_ACTIVITY)
    assert len(found) == 2
    entities = {e for link in found for e in link.entities}
    assert ref("ROLE_ASSIGNMENT", f"{USER_1}/role-def-1") in entities
    assert ref("APPLICATION", "00000000-0000-4000-8000-0000000000aa") in entities


# ------------------------------------------------------------------------------------ email to click


def test_email_to_click_by_recipient_user_and_recipient_endpoint():
    msg = _message("msg-1@sender.example", urls=(f"https://{EVIL_DOMAIN}/invoice",))
    click = record(NetworkConnectionRecord, integration="umbrella", atomic="investigate_domain",
                   subject=obs("domain", EVIL_DOMAIN), user=USER_1, domain=EVIL_DOMAIN, remote_port=443,
                   first_seen=at(5))
    dns = _dns(HOST_1, f"cdn.{EVIL_DOMAIN}", 6)
    corr = correlate(CTX, [result(msg), result(click), result(dns), result(_endpoint(HOST_1, USER_1))])
    (link,) = links_of(corr, LinkKind.EMAIL_TO_CLICK)
    assert set(link.record_ids) == {msg.record_id, click.record_id, dns.record_id}
    assert ref("EMAIL_MESSAGE", "msg-1@sender.example") in link.entities
    assert ref("DOMAIN", EVIL_DOMAIN) in link.entities
    assert ref("ENDPOINT", HOST_1) in link.entities and ref("USER", USER_1) in link.entities


def test_email_to_click_ignores_earlier_late_and_non_recipient_activity():
    msg = _message("msg-2@sender.example", domains=(EVIL_DOMAIN,))
    early = _dns(HOST_1, EVIL_DOMAIN, -5)
    late = _dns(HOST_1, EVIL_DOMAIN, 90)
    stranger = _dns(HOST_2, EVIL_DOMAIN, 5)
    corr = correlate(CTX, [result(msg), result(early, late, stranger), result(_endpoint(HOST_1, USER_1))])
    assert links_of(corr, LinkKind.EMAIL_TO_CLICK) == []


# ------------------------------------------------------------------------------------------ campaign


def test_campaign_by_campaign_id_and_by_sender_domain_and_url():
    a = _message("msg-a@sender.example", campaign_id="camp-1")
    b = _message("msg-b@sender.example", recipient=USER_2, campaign_id="camp-1")
    c = _message("msg-c@sender.example", urls=("https://files.example/x",))
    d = _message("msg-d@sender.example", recipient=USER_2, urls=("https://files.example/x",))
    corr = correlate(CTX, [result(a, b, c, d)])
    found = links_of(corr, LinkKind.CAMPAIGN)
    assert len(found) == 2
    by_ids = {link.record_ids for link in found}
    assert tuple(sorted([a.record_id, b.record_id])) in by_ids
    assert tuple(sorted([c.record_id, d.record_id])) in by_ids
    url_link = next(link for link in found if c.record_id in link.record_ids)
    assert ref("URL", "https://files.example/x") in url_link.entities


def test_single_message_is_not_a_campaign():
    corr = correlate(CTX, [result(_message("msg-solo@sender.example", campaign_id="camp-9"))])
    assert links_of(corr, LinkKind.CAMPAIGN) == []


# ------------------------------------------------------------------------- options, hooks, determinism


def test_link_kinds_filter_and_window_validation():
    e1, e2 = _endpoint(HOST_1, USER_1), _endpoint(HOST_2, USER_1)
    corr = correlate(CTX, [result(e1, e2)], link_kinds=(LinkKind.SAME_ENDPOINT,))
    assert corr.links == ()
    assert ref("USER", USER_1) in corr.entities
    with pytest.raises(ValueError):
        correlate(CTX, [result(e1)], window=timedelta(0))
    assert LinkKind.WORKFLOW not in FRAMEWORK_LINK_KINDS


def test_extra_links_must_cite_known_records_and_are_kept():
    e1 = _endpoint(HOST_1, USER_1)
    hook = CorrelationLink(kind=LinkKind.WORKFLOW, entities=(ref("ENDPOINT", HOST_1), ref("IP", EVIL_IP)),
                           record_ids=(e1.record_id,), note="hook: beacon pattern", origin="workflow:wf_test")
    corr = correlate(CTX, [result(e1)], extra_links=[hook], link_kinds=())
    assert corr.links == (hook,)
    assert ref("IP", EVIL_IP) in corr.entities  # link entities join the entity list
    assert corr.related(ref("IP", EVIL_IP)) == (ref("ENDPOINT", HOST_1),)  # no framework links requested
    bogus = hook.model_copy(update={"record_ids": ("rec_" + "f" * 32,)})
    with pytest.raises(EvidenceError):
        correlate(CTX, [result(e1)], extra_links=[bogus])


def test_every_link_cites_records_of_the_run():
    records = [_sign_in(USER_1, 0), _mail_rule(USER_1, 5), _endpoint(HOST_1, USER_1), _endpoint(HOST_2, USER_1),
               _dns(HOST_1, EVIL_DOMAIN, 1), _dns(HOST_2, EVIL_DOMAIN, 2)]
    results = [result(r) for r in records]
    corr = correlate(CTX, results)
    index = RecordIndex(results)
    assert corr.links
    for link in corr.links:
        index.require(link.record_ids)


def test_correlation_is_deterministic_regardless_of_result_order():
    records = [_sign_in(USER_1, 0), _mail_rule(USER_1, 5), _endpoint(HOST_1, USER_1), _endpoint(HOST_2, USER_1),
               _dns(HOST_1, EVIL_DOMAIN, 1), _dns(HOST_2, EVIL_DOMAIN, 2), _proc(1, 0, "a"), _proc(2, 1, "b", 1)]
    forward = correlate(CTX, [result(r) for r in records])
    backward = correlate(CTX, [result(r) for r in reversed(records)])
    assert forward == backward
    assert forward.model_dump_json() == backward.model_dump_json()
    assert forward.incident_id == CTX.incident.incident_id


def test_clusters_partition_entities():
    corr = correlate(CTX, [result(_endpoint(HOST_1, USER_1), _endpoint(HOST_2, USER_1)),
                           result(_dns(HOST_1, EVIL_DOMAIN, 1))])
    members = [e for cluster in corr.clusters for e in cluster]
    assert sorted(members, key=EntityRef.sort_key) == list(corr.entities)
    assert corr.related(ref("DOMAIN", EVIL_DOMAIN)) == ()  # one endpoint only: no link
    assert corr.rule_item()["related"]["DOMAIN:" + EVIL_DOMAIN] == []


def test_timeline_sorted_by_time_and_deduplicated():
    si, rule, ep = _sign_in(USER_1, 7), _mail_rule(USER_1, 3), _endpoint(HOST_1)
    timeline = build_timeline([result(si, rule), result(ep), result(si)])
    assert [e.record_id for e in timeline] == [ep.record_id, rule.record_id, si.record_id]
    assert timeline[0].at == at(0) and timeline[-1].summary.startswith("entra: sign-in success")
    assert correlate(CTX, [result(ep), result(si, rule)]).timeline == timeline


def test_empty_results_give_an_empty_correlation():
    corr = correlate(CTX, [])
    assert corr.entities == () and corr.links == () and corr.clusters == () and corr.timeline == ()
    assert corr.rule_item() == {"entities": [], "links": [], "clusters": [], "related": {}}

