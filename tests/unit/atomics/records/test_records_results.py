"""AtomicResult, SourceStatus and InvestigationBundle rule items (architecture 14.1.2, 14.1.4)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from xdr_response.atomics.records import (
    AtomicResult,
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    HashPrevalenceRecord,
    MfaEventRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
    RecordKind,
    SignInRecord,
    SourceOutcome,
    SourceStatus,
    UserProfileRecord,
    InvestigationBundle,
)
from xdr_response.models import (
    ActionType,
    CriticalAssetClass,
    ErrorCode,
    ErrorInfo,
    HealthStatus,
    Observable,
    ObservableType,
    Severity,
    Verdict,
)

T0 = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
SHA = "ab" * 32
_O = ObservableType
COMMON = {"atomic", "subject_type", "subject", "record_ids", "sources", "failed_sources", "degraded"}


def obs(otype: ObservableType, value: str) -> Observable:
    return Observable(type=otype, value=value)


def bundle(action: ActionType, subject: Observable, records: tuple[Any, ...] = (),
           sources: tuple[SourceStatus, ...] = (), **extra: Any) -> InvestigationBundle:
    return InvestigationBundle(atomic=action.value, action_type=action, subject=subject, records=records,
                               sources=sources, started_at=T0, finished_at=T0 + timedelta(seconds=1), **extra)


def status(name: str, outcome: SourceOutcome, **kw: Any) -> SourceStatus:
    return SourceStatus(integration=name, outcome=outcome, health=kw.pop("health", HealthStatus.CONNECTED), **kw)


def rec(cls: type, action: ActionType, subject: Observable, integration: str = "secure_endpoint", **fields: Any):
    return cls(integration=integration, atomic=action.value, subject=subject, **fields)


# ---------------------------------------------------------- SourceStatus --
def test_source_status_requires_a_known_integration_and_non_negative_records():
    assert status("splunk", SourceOutcome.NOT_QUERIED, reason="not enabled").records == 0
    with pytest.raises(ValidationError):
        status("ai", SourceOutcome.ANSWERED)
    with pytest.raises(ValidationError):
        status("entra", SourceOutcome.ANSWERED, records=-1)


# ---------------------------------------------------------- AtomicResult --
def test_atomic_result_properties():
    subject = obs(_O.HOSTNAME, "th-lt-1047")
    detection = rec(DetectionRecord, ActionType.INVESTIGATE_ENDPOINT, subject, name="X", verdict=Verdict.MALICIOUS,
                    severity=Severity.HIGH)
    endpoint = rec(EndpointRecord, ActionType.INVESTIGATE_ENDPOINT, subject, hostname="th-lt-1047")
    error = ErrorInfo(code=ErrorCode.TIMEOUT, message="timeout", integration="defender_endpoint")
    result = bundle(ActionType.INVESTIGATE_ENDPOINT, subject, (detection, endpoint), (
        status("secure_endpoint", SourceOutcome.ANSWERED, records=2),
        status("defender_endpoint", SourceOutcome.FAILED, health=HealthStatus.DEGRADED, error=error),
        status("splunk", SourceOutcome.NOT_QUERIED, health=HealthStatus.UNKNOWN, reason="not enabled"),
    ))
    assert result.subject.value == "TH-LT-1047"
    assert result.degraded is True
    assert result.answered == ("secure_endpoint",) and result.failed == ("defender_endpoint",)
    assert result.of(RecordKind.ENDPOINT) == (endpoint,) and result.of("detection") == (detection,)
    assert result.record_ids() == (detection.record_id, endpoint.record_id)
    item = AtomicResult.rule_item(result)
    assert item == {"atomic": "investigate_endpoint", "subject_type": "hostname", "subject": "TH-LT-1047",
                    "record_ids": [detection.record_id, endpoint.record_id], "sources": ["secure_endpoint"],
                    "failed_sources": ["defender_endpoint"], "degraded": True}


def test_atomic_result_refuses_duplicate_ids_and_foreign_records():
    subject = obs(_O.HOSTNAME, "TH-LT-1047")
    endpoint = rec(EndpointRecord, ActionType.INVESTIGATE_ENDPOINT, subject, hostname="TH-LT-1047")
    with pytest.raises(ValidationError, match="unique"):
        bundle(ActionType.INVESTIGATE_ENDPOINT, subject, (endpoint, endpoint))
    foreign = rec(EndpointRecord, ActionType.SEARCH_RELATED_ENDPOINTS, subject, hostname="TH-LT-1047")
    with pytest.raises(ValidationError, match="another atomic"):
        bundle(ActionType.INVESTIGATE_ENDPOINT, subject, (foreign,))


def test_atomic_result_refuses_write_types_duplicate_sources_and_reversed_times():
    subject = obs(_O.HOSTNAME, "TH-LT-1047")
    with pytest.raises(ValidationError, match="ENRICHMENT or INVESTIGATION"):
        InvestigationBundle(atomic="isolate_endpoint", action_type=ActionType.ISOLATE_ENDPOINT, subject=subject,
                            started_at=T0, finished_at=T0)
    with pytest.raises(ValidationError, match="one source status"):
        bundle(ActionType.INVESTIGATE_ENDPOINT, subject, (), (status("entra", SourceOutcome.EMPTY),) * 2)
    with pytest.raises(ValidationError, match="finished_at"):
        InvestigationBundle(atomic="investigate_endpoint", action_type=ActionType.INVESTIGATE_ENDPOINT,
                            subject=subject, started_at=T0, finished_at=T0 - timedelta(seconds=1))


def test_not_degraded_without_failed_sources():
    result = bundle(ActionType.INVESTIGATE_DOMAIN, obs(_O.DOMAIN, "bad.example.test"),
                    sources=(status("splunk", SourceOutcome.NOT_QUERIED, reason="not enabled"),))
    assert result.degraded is False and result.failed == () and result.answered == ()


# ------------------------------------------------------------- rule items --
def test_endpoint_rule_item_keys_and_values():
    a = ActionType.INVESTIGATE_ENDPOINT
    s = obs(_O.HOSTNAME, "TH-LT-1047")
    endpoint = rec(EndpointRecord, a, s, hostname="TH-LT-1047", connector_guid="guid-1",
                   ip_addresses=("192.0.2.10",), users=("jsmith@example.com",), groups=("Workstations",),
                   isolation_capable=True)
    mde = rec(EndpointRecord, a, s, integration="defender_endpoint", hostname="TH-LT-1047", mde_machine_id="mde-1",
              ip_addresses=("192.0.2.10", "198.51.100.4"), isolation_state="not_isolated", tags=("vip",))
    late = rec(ProcessEventRecord, a, s, endpoint="TH-LT-1047", timestamp=T0 + timedelta(minutes=5),
               event_type="file_rename", count=1204)
    early = rec(ProcessEventRecord, a, s, endpoint="TH-LT-1047", timestamp=T0, event_type="process_start")
    persistence = rec(PersistenceItemRecord, a, s, endpoint="TH-LT-1047", item_id="t1", mechanism="run_key", name="r")
    item = bundle(a, s, (endpoint, mde, late, early, persistence),
                  critical_asset_classes=(CriticalAssetClass.EXECUTIVE_ENDPOINT,)).rule_item()
    assert set(item) == COMMON | {
        "hostname", "endpoint", "endpoints", "connector_guid", "mde_machine_id", "intune_device_id", "ip_addresses",
        "users", "groups", "tags", "isolation_capable", "isolation_state", "detections", "trajectory",
        "network_connections", "dns_queries", "persistence", "is_critical_asset", "critical_asset_classes"}
    assert item["hostname"] == "TH-LT-1047" and item["endpoint"]["connector_guid"] == "guid-1"
    assert len(item["endpoints"]) == 2
    assert (item["connector_guid"], item["mde_machine_id"], item["intune_device_id"]) == ("guid-1", "mde-1", None)
    assert item["ip_addresses"] == ["192.0.2.10", "198.51.100.4"]
    assert item["isolation_capable"] is True and item["isolation_state"] == "not_isolated"
    assert [e["event_type"] for e in item["trajectory"]] == ["process_start", "file_rename"]
    assert item["trajectory"][1]["count"] == 1204
    assert item["detections"] == [] and len(item["persistence"]) == 1
    assert item["is_critical_asset"] is True and item["critical_asset_classes"] == ["executive_endpoint"]


def test_endpoint_rule_item_without_records_keeps_every_key():
    item = bundle(ActionType.SEARCH_RELATED_ENDPOINTS, obs(_O.ENDPOINT_ID, "guid-9")).rule_item()
    assert item["hostname"] is None and item["endpoint"] is None and item["endpoints"] == []
    assert item["isolation_state"] == "unknown" and item["isolation_capable"] is None
    assert item["is_critical_asset"] is False and item["critical_asset_classes"] == []


def test_user_rule_item_keys_and_values():
    a = ActionType.INVESTIGATE_USER
    s = obs(_O.USER, "jsmith@example.com")
    profile = rec(UserProfileRecord, a, s, integration="entra", user="jsmith@example.com", risk_level="high",
                  risk_state="at_risk", account_enabled=True, roles=("Exchange Administrator",))
    item = bundle(a, s, (profile,)).rule_item()
    assert set(item) == COMMON | {"user", "profile", "users", "risk_level", "risk_state", "is_privileged",
                                  "account_enabled", "signins", "anomalies", "mfa_events", "mailbox_rules",
                                  "role_changes", "cloud_apps", "is_critical_asset", "critical_asset_classes"}
    assert item["user"] == "jsmith@example.com" and item["profile"]["roles"] == ["Exchange Administrator"]
    assert (item["risk_level"], item["risk_state"], item["is_privileged"], item["account_enabled"]) == \
        ("high", "at_risk", True, True)
    empty = bundle(ActionType.SEARCH_RELATED_USERS, s).rule_item()
    assert empty["profile"] is None and empty["is_privileged"] is None and empty["user"] == "jsmith@example.com"


def test_authentication_rule_item_counts():
    a = ActionType.INVESTIGATE_AUTHENTICATION
    s = obs(_O.USER, "jsmith@example.com")
    signins = tuple(rec(SignInRecord, a, s, integration="entra", user="jsmith@example.com",
                        timestamp=T0 + timedelta(minutes=i), ip=ip, country=country, result=result)
                    for i, (ip, country, result) in enumerate([("198.51.100.7", "US", "success"),
                                                               ("203.0.113.9", "NL", "failure"),
                                                               ("203.0.113.9", "NL", "failure")]))
    mfa = tuple(rec(MfaEventRecord, a, s, integration="entra", user="jsmith@example.com",
                    timestamp=T0 + timedelta(seconds=i), method="push", result=r, ip="203.0.113.9", country="NL")
                for i, r in enumerate(["denied", "denied", "fraud_reported", "approved", "timeout"]))
    item = bundle(a, s, signins + mfa).rule_item()
    assert set(item) == COMMON | {"user", "signins", "mfa_events", "anomalies", "success_count", "failure_count",
                                  "mfa_denied_count", "mfa_approved_count", "distinct_ips", "distinct_countries"}
    assert (item["success_count"], item["failure_count"]) == (1, 2)
    assert (item["mfa_denied_count"], item["mfa_approved_count"]) == (3, 1)
    assert (item["distinct_ips"], item["distinct_countries"]) == (2, 2)


@pytest.mark.parametrize("action", [ActionType.INVESTIGATE_IP, ActionType.INVESTIGATE_NETWORK_CONNECTION,
                                    ActionType.SEARCH_IP_ENTERPRISE])
def test_ip_rule_item(action):
    s = obs(_O.IP, "203.0.113.10")
    net = rec(NetworkConnectionRecord, action, s, endpoint="TH-LT-2001", user="b@example.com",
              remote_ip="203.0.113.10")
    net2 = rec(NetworkConnectionRecord, action, s, endpoint="TH-LT-1047", remote_ip="203.0.113.10", remote_port=80)
    sign_in = rec(SignInRecord, action, s, integration="entra", user="a@example.com", timestamp=T0,
                  ip="203.0.113.10", result="success")
    item = bundle(action, s, (net, net2, sign_in)).rule_item()
    assert set(item) == COMMON | {"ip", "network_connections", "dns_queries", "signins", "endpoints", "users"}
    assert item["ip"] == "203.0.113.10" and item["endpoints"] == ["TH-LT-1047", "TH-LT-2001"]
    assert item["users"] == ["a@example.com", "b@example.com"] and len(item["signins"]) == 1


def test_domain_rule_item():
    a = ActionType.SEARCH_DOMAIN_ENTERPRISE
    s = obs(_O.DOMAIN, "bad.example.test")
    dns1 = rec(DnsQueryRecord, a, s, endpoint="TH-LT-1047", domain="bad.example.test", count=14,
               first_seen=T0 + timedelta(hours=1))
    dns2 = rec(DnsQueryRecord, a, s, endpoint="TH-LT-2001", domain="bad.example.test", count=2, first_seen=T0)
    item = bundle(a, s, (dns1, dns2)).rule_item()
    assert set(item) == COMMON | {"domain", "dns_queries", "network_connections", "endpoints", "users",
                                  "query_count", "first_seen"}
    assert item["query_count"] == 16 and item["first_seen"] == "2026-01-15T12:00:00Z"
    assert bundle(a, s).rule_item()["first_seen"] is None


def test_hash_rule_item():
    a = ActionType.INVESTIGATE_HASH
    s = obs(_O.SHA256, SHA)
    prevalence = rec(HashPrevalenceRecord, a, s, sha256=SHA, prevalence=3, endpoints=("TH-LT-2001",),
                     file_name="invoice.exe", verdict=Verdict.SUSPICIOUS)
    detection = rec(DetectionRecord, a, s, integration="defender_endpoint", name="Trojan", sha256=SHA,
                    verdict=Verdict.MALICIOUS, severity=Severity.HIGH, endpoint="TH-LT-1047")
    event = rec(ProcessEventRecord, a, s, endpoint="TH-LT-3000", timestamp=T0, event_type="process_start",
                sha256=SHA, process_name="invoice.exe")
    item = bundle(a, s, (prevalence, detection, event)).rule_item()
    assert set(item) == COMMON | {"sha256", "prevalence", "endpoints", "verdict", "detections", "process_events",
                                  "file_names"}
    assert item["sha256"] == SHA and item["prevalence"] == 3 and item["verdict"] == "MALICIOUS"
    assert item["endpoints"] == ["TH-LT-1047", "TH-LT-2001", "TH-LT-3000"]
    assert item["file_names"] == ["invoice.exe"]
    empty = bundle(ActionType.SEARCH_HASH_ENTERPRISE, obs(_O.MD5, "12" * 16)).rule_item()
    assert (empty["sha256"], empty["prevalence"], empty["verdict"]) == (None, None, None)


def test_email_rule_item():
    a = ActionType.SEARCH_EMAIL_CAMPAIGN
    s = obs(_O.EMAIL_MESSAGE_ID, "msg-1")
    m1 = rec(EmailMessageRecord, a, s, integration="secure_email", message_id="msg-1", sender="x@lookalike.example",
             recipients=("b@example.com", "a@example.com"), urls=("https://lookalike.example/login",),
             domains=("lookalike.example",), delivery_location="inbox", campaign_id="c-1")
    m2 = rec(EmailMessageRecord, a, s, integration="secure_email", message_id="msg-2", sender="x@lookalike.example",
             recipients=("a@example.com",), attachment_hashes=(SHA,), delivery_location="quarantine",
             campaign_id="c-1")
    item = bundle(a, s, (m1, m2)).rule_item()
    assert set(item) == COMMON | {"message_id", "messages", "recipients", "senders", "urls", "domains",
                                  "attachment_hashes", "campaign_ids", "delivered_count"}
    assert item["recipients"] == ["a@example.com", "b@example.com"] and item["senders"] == ["x@lookalike.example"]
    assert item["campaign_ids"] == ["c-1"] and item["delivered_count"] == 1 and item["attachment_hashes"] == [SHA]


@pytest.mark.parametrize("ident, child_field", [("4242", {"parent_pid": 4242}), (SHA, {"parent_sha256": SHA})])
def test_process_rule_item_children(ident, child_field):
    a = ActionType.INVESTIGATE_PROCESS
    s = obs(_O.PROCESS, f"th-lt-1047/{ident}")
    parent = rec(ProcessEventRecord, a, s, endpoint="TH-LT-1047", timestamp=T0, event_type="process_start",
                 pid=4242, sha256=SHA)
    child = rec(ProcessEventRecord, a, s, endpoint="TH-LT-1047", timestamp=T0 + timedelta(seconds=1),
                event_type="process_start", pid=5000, **child_field)
    item = bundle(a, s, (child, parent)).rule_item()
    assert set(item) == COMMON | {"process", "endpoint", "events", "network_connections", "children"}
    assert item["process"] == f"TH-LT-1047/{ident}" and item["endpoint"] == "TH-LT-1047"
    assert [e["pid"] for e in item["events"]] == [4242, 5000]
    assert [e["pid"] for e in item["children"]] == [5000]


def test_rule_items_are_json_serializable():
    import json

    a = ActionType.INVESTIGATE_ENDPOINT
    s = obs(_O.HOSTNAME, "TH-LT-1047")
    item = bundle(a, s, (rec(EndpointRecord, a, s, hostname="TH-LT-1047", last_seen=T0),)).rule_item()
    json.dumps(item)
