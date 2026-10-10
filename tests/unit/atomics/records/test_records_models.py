"""Normalized records (architecture 14.1.2): ids, validators, natural keys and evidence fields."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from xdr_response.atomics.records import (
    PRIVILEGED_ROLE_NAMES,
    RECORD_TYPES,
    AnomalyRecord,
    AnyRecord,
    CloudAppRecord,
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    EnrichmentRecord,
    GenericRecord,
    HashPrevalenceRecord,
    MailboxRuleRecord,
    MfaEventRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
    RecordBase,
    RecordKind,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
    make_record_id,
)
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import Observable, ObservableType, Severity, Verdict

T0 = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
SHA = "ab" * 32
HOST_SUBJECT = Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047")
USER_SUBJECT = Observable(type=ObservableType.USER, value="jsmith@example.com")
_ANY = TypeAdapter(AnyRecord)


def base(subject: Observable = HOST_SUBJECT, **fields: Any) -> dict[str, Any]:
    return {"integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": subject, **fields}


#: One valid instance per kind (field values are fake test data).
SAMPLES: dict[RecordKind, dict[str, Any]] = {
    RecordKind.ENRICHMENT: base(Observable(type=ObservableType.DOMAIN, value="bad.example.test"),
                                integration="virustotal", atomic="enrich_domain", verdict=Verdict.MALICIOUS,
                                risk_score=90, confidence=80, categories=("Malware",)),
    RecordKind.ENDPOINT: base(hostname="th-lt-1047", connector_guid="guid-1", os="Windows 11",
                              ip_addresses=("192.0.2.10",), groups=("Workstations",)),
    RecordKind.DETECTION: base(name="Ransomware.Generic", verdict=Verdict.MALICIOUS, severity=Severity.CRITICAL,
                               endpoint="th-lt-1047", sha256=SHA.upper()),
    RecordKind.PROCESS_EVENT: base(endpoint="th-lt-1047", timestamp=T0, event_type="process_start",
                                   process_name="example.exe", pid=4242, sha256=SHA),
    RecordKind.NETWORK_CONNECTION: base(endpoint="th-lt-1047", remote_ip="203.0.113.10", remote_port=443,
                                        domain="bad.example.test.", direction="outbound", first_seen=T0),
    RecordKind.DNS_QUERY: base(endpoint="th-lt-1047", domain="Bad.Example.Test", query_type="A", count=3),
    RecordKind.HASH_PREVALENCE: base(Observable(type=ObservableType.SHA256, value=SHA), atomic="investigate_hash",
                                     sha256=SHA, prevalence=2, endpoints=("th-lt-1047", "th-lt-2001")),
    RecordKind.PERSISTENCE_ITEM: base(endpoint="th-lt-1047", item_id="task-7", mechanism="scheduled_task",
                                      name="Updater"),
    RecordKind.USER_PROFILE: base(USER_SUBJECT, integration="entra", atomic="investigate_user",
                                  user="JSmith@Example.com", roles=("Helpdesk Operator",)),
    RecordKind.SIGN_IN: base(USER_SUBJECT, integration="entra", atomic="investigate_authentication",
                             user="jsmith@example.com", timestamp=T0, ip="198.51.100.7", result="success"),
    RecordKind.ANOMALY: base(USER_SUBJECT, integration="entra", atomic="investigate_authentication",
                             anomaly_type="impossible_travel", severity=Severity.HIGH, user="jsmith@example.com"),
    RecordKind.MFA_EVENT: base(USER_SUBJECT, integration="entra", atomic="investigate_authentication",
                               user="jsmith@example.com", timestamp=T0, method="push", result="denied"),
    RecordKind.MAILBOX_RULE: base(USER_SUBJECT, integration="microsoft_cloud", atomic="investigate_user",
                                  mailbox="jsmith@example.com", rule_id="r1", name="fwd",
                                  forward_to=("Drop@Mail.Example",)),
    RecordKind.ROLE_CHANGE: base(USER_SUBJECT, integration="entra", atomic="investigate_user",
                                 user="jsmith@example.com", role_name="Helpdesk Operator", change="assigned",
                                 role_definition_id="role-1", timestamp=T0),
    RecordKind.EMAIL_MESSAGE: base(Observable(type=ObservableType.EMAIL_MESSAGE_ID, value="msg-1"),
                                   integration="secure_email", atomic="investigate_email", message_id="msg-1",
                                   sender="Billing@Lookalike.Example", recipients=("jsmith@example.com",)),
    RecordKind.CLOUD_APP: base(USER_SUBJECT, integration="microsoft_cloud", atomic="investigate_user",
                               app_id="app-1", display_name="Example App", permissions=("Mail.Read",)),
    RecordKind.GENERIC: base(name="splunk:investigate_endpoint", integration="splunk",
                             attributes={"host": "TH-LT-1047", "count": 3}),
}

NATURAL_KEYS: dict[RecordKind, set[str]] = {
    RecordKind.ENRICHMENT: set(),
    RecordKind.ENDPOINT: {"hostname", "id"},
    RecordKind.DETECTION: {"name", "endpoint", "sha256", "first_seen"},
    RecordKind.PROCESS_EVENT: {"endpoint", "timestamp", "event_type", "pid", "sha256"},
    RecordKind.NETWORK_CONNECTION: {"endpoint", "remote_ip", "remote_port", "domain", "first_seen"},
    RecordKind.DNS_QUERY: {"endpoint", "client_ip", "domain", "query_type", "first_seen"},
    RecordKind.HASH_PREVALENCE: {"sha256"},
    RecordKind.PERSISTENCE_ITEM: {"endpoint", "item_id"},
    RecordKind.USER_PROFILE: {"user"},
    RecordKind.SIGN_IN: {"user", "timestamp", "ip"},
    RecordKind.ANOMALY: {"anomaly_type", "user", "endpoint", "first_seen"},
    RecordKind.MFA_EVENT: {"user", "timestamp", "method"},
    RecordKind.MAILBOX_RULE: {"mailbox", "rule_id"},
    RecordKind.ROLE_CHANGE: {"user", "role_name", "change", "timestamp"},
    RecordKind.EMAIL_MESSAGE: {"message_id"},
    RecordKind.CLOUD_APP: {"app_id"},
    RecordKind.GENERIC: {"name", "attributes"},
}

EVIDENCE_FIELDS: dict[RecordKind, list[str]] = {
    RecordKind.ENRICHMENT: ["verdict", "risk_score", "confidence", "categories"],
    RecordKind.ENDPOINT: ["hostname", "os", "isolation_state", "groups", "tags"],
    RecordKind.DETECTION: ["name", "verdict", "severity", "category", "endpoint", "user", "sha256",
                           "mitre_techniques"],
    RecordKind.PROCESS_EVENT: ["endpoint", "timestamp", "event_type", "process_name", "parent_process_name",
                               "sha256", "command_line", "verdict", "count"],
    RecordKind.NETWORK_CONNECTION: ["endpoint", "user", "remote_ip", "remote_port", "domain", "url",
                                    "direction", "action", "verdict", "bytes_out", "count"],
    RecordKind.DNS_QUERY: ["endpoint", "domain", "query_type", "count", "unique_subdomains", "action", "verdict"],
    RecordKind.HASH_PREVALENCE: ["sha256", "file_name", "verdict", "prevalence", "endpoints"],
    RecordKind.PERSISTENCE_ITEM: ["endpoint", "mechanism", "name", "path", "sha256", "command_line", "verdict"],
    RecordKind.USER_PROFILE: ["user", "risk_level", "risk_state", "account_enabled", "privileged", "roles"],
    RecordKind.SIGN_IN: ["user", "timestamp", "ip", "country", "app", "result", "mfa_result", "risk_level"],
    RecordKind.ANOMALY: ["anomaly_type", "severity", "user", "endpoint", "ip", "detail"],
    RecordKind.MFA_EVENT: ["user", "timestamp", "method", "result", "ip", "country"],
    RecordKind.MAILBOX_RULE: ["mailbox", "name", "enabled", "forward_to", "redirect_to", "external_forwarding",
                              "delete"],
    RecordKind.ROLE_CHANGE: ["user", "role_name", "change", "privileged", "actor", "timestamp"],
    RecordKind.EMAIL_MESSAGE: ["message_id", "sender", "recipient_count", "verdict", "threat_types",
                               "delivery_location", "campaign_id"],
    RecordKind.CLOUD_APP: ["app_id", "display_name", "consent_type", "permissions", "publisher_verified"],
    RecordKind.GENERIC: ["name", "attributes"],
}


def build(kind: RecordKind, **changes: Any) -> RecordBase:
    return RECORD_TYPES[kind](**{**SAMPLES[kind], **changes})


# --------------------------------------------------------------- tables --
def test_record_types_cover_every_kind_and_fix_their_kind():
    assert set(RECORD_TYPES) == set(RecordKind)
    for kind, cls in RECORD_TYPES.items():
        assert build(kind).kind is kind
        assert issubclass(cls, RecordBase)
    with pytest.raises(TypeError):
        RECORD_TYPES[RecordKind.GENERIC] = EndpointRecord  # type: ignore[index]


def test_privileged_role_names_include_the_documented_minimum():
    assert {"global administrator", "privileged role administrator", "security administrator",
            "exchange administrator"} <= PRIVILEGED_ROLE_NAMES
    assert all(name == name.lower() for name in PRIVILEGED_ROLE_NAMES)


# ----------------------------------------------------------------- ids --
def test_make_record_id_is_deterministic_and_case_insensitive_on_the_subject():
    a = make_record_id("secure_endpoint", RecordKind.ENDPOINT, HOST_SUBJECT, {"hostname": "X", "id": None})
    b = make_record_id("secure_endpoint", RecordKind.ENDPOINT,
                       Observable(type=ObservableType.HOSTNAME, value="  th-lt-1047 "), {"id": None, "hostname": "X"})
    assert a == b
    assert a.startswith("rec_") and len(a) == 36 and set(a[4:]) <= set("0123456789abcdef")


@pytest.mark.parametrize("change", [
    {"integration": "defender_endpoint"},
    {"kind": RecordKind.DETECTION},
    {"subject": Observable(type=ObservableType.ENDPOINT_ID, value="TH-LT-1047")},
    {"natural_key": {"hostname": "Y", "id": None}},
])
def test_make_record_id_changes_with_every_input(change):
    args = {"integration": "secure_endpoint", "kind": RecordKind.ENDPOINT, "subject": HOST_SUBJECT,
            "natural_key": {"hostname": "X", "id": None}}
    assert make_record_id(**args) != make_record_id(**{**args, **change})


def test_make_record_id_accepts_datetimes_and_floats_in_the_natural_key():
    key = {"timestamp": T0, "score": 1.5}
    same_instant = {"timestamp": T0.astimezone(timezone(timedelta(hours=2))), "score": 1.5}
    assert make_record_id("entra", RecordKind.GENERIC, USER_SUBJECT, key) == \
        make_record_id("entra", RecordKind.GENERIC, USER_SUBJECT, same_instant)


@pytest.mark.parametrize("kind", list(RecordKind))
def test_omitted_record_id_is_computed_from_the_natural_key(kind):
    record = build(kind)
    assert set(record.natural_key()) == NATURAL_KEYS[kind]
    assert record.record_id == make_record_id(record.integration, kind, record.subject, record.natural_key())


@pytest.mark.parametrize("kind", list(RecordKind))
def test_records_round_trip_through_json_and_the_discriminated_union(kind):
    record = build(kind)
    dumped = record.model_dump(mode="json")
    again = _ANY.validate_python(json.loads(json.dumps(dumped)))
    assert type(again) is type(record)
    assert again == record
    assert record.rule_item() == dumped


def test_wrong_record_id_is_refused_and_the_right_one_accepted():
    record = build(RecordKind.DETECTION)
    assert DetectionRecord(**{**SAMPLES[RecordKind.DETECTION], "record_id": record.record_id}) == record
    with pytest.raises(ValidationError, match="does not match the record content"):
        DetectionRecord(**{**SAMPLES[RecordKind.DETECTION], "record_id": "rec_" + "0" * 32})


def test_id_ignores_non_key_fields_and_follows_key_fields():
    record = build(RecordKind.ENDPOINT)
    assert build(RecordKind.ENDPOINT, os="Windows 10").record_id == record.record_id
    assert build(RecordKind.ENDPOINT, connector_guid="guid-2").record_id != record.record_id


def test_id_based_natural_keys_prefer_the_vendor_id():
    with_id = build(RecordKind.DETECTION, detection_id="det-1")
    assert with_id.natural_key() == {"id": "det-1"}
    assert build(RecordKind.DETECTION, detection_id="det-1", name="Other").record_id == with_id.record_id
    assert build(RecordKind.SIGN_IN, sign_in_id="s-1").natural_key() == {"id": "s-1"}
    assert build(RecordKind.PROCESS_EVENT, event_id="e-1").natural_key() == {"id": "e-1"}
    assert build(RecordKind.ANOMALY, anomaly_id="a-1").natural_key() == {"id": "a-1"}


def test_network_connection_key_adds_the_url_only_when_reported():
    """14.13.3: two requests of one source to one server at the same time with different URLs stay two records;
    a connection without a URL keeps the 14.1.2 key (and so its earlier id)."""
    plain = build(RecordKind.NETWORK_CONNECTION, url=None)
    assert "url" not in plain.natural_key()
    first = build(RecordKind.NETWORK_CONNECTION, url="https://shop.example.com/cart/checkout")
    second = build(RecordKind.NETWORK_CONNECTION, url="https://shop.example.com/admin/upload")
    assert first.natural_key()["url"] == "https://shop.example.com/cart/checkout"
    assert len({plain.record_id, first.record_id, second.record_id}) == 3
    assert build(RecordKind.NETWORK_CONNECTION, url="https://shop.example.com/admin/upload").record_id == \
        second.record_id


def test_endpoint_natural_key_id_takes_the_first_present_vendor_id():
    record = build(RecordKind.ENDPOINT, connector_guid=None, mde_machine_id="mde-1", intune_device_id="int-1")
    assert record.natural_key() == {"hostname": "TH-LT-1047", "id": "mde-1"}


# ---------------------------------------------------------- validators --
@pytest.mark.parametrize("integration", ["ai", "analyst", "unknown_vendor"])
def test_integration_must_be_a_known_integration(integration):
    with pytest.raises(ValidationError, match="INTEGRATION_NAMES"):
        build(RecordKind.ENDPOINT, integration=integration)


def test_entity_values_are_normalized_for_their_kind():
    net = build(RecordKind.NETWORK_CONNECTION, user="JSmith@Example.COM", remote_ip="2001:DB8:0:0::1",
                sha256=SHA.upper())
    assert (net.endpoint, net.domain, net.user, net.remote_ip, net.sha256) == \
        ("TH-LT-1047", "bad.example.test", "jsmith@example.com", "2001:db8::1", SHA)
    prevalence = build(RecordKind.HASH_PREVALENCE)
    assert prevalence.endpoints == ("TH-LT-1047", "TH-LT-2001")
    message = build(RecordKind.EMAIL_MESSAGE, sender_domain="Lookalike.Example.")
    assert (message.sender, message.sender_domain) == ("billing@lookalike.example", "lookalike.example")
    assert build(RecordKind.MAILBOX_RULE).forward_to == ("drop@mail.example",)


def test_invalid_ip_values_are_refused():
    with pytest.raises(ValidationError):
        build(RecordKind.NETWORK_CONNECTION, remote_ip="not-an-ip")


def test_subject_is_normalized_and_must_be_parseable():
    record = build(RecordKind.ENDPOINT, subject=Observable(type=ObservableType.HOSTNAME, value=" th-lt-1047 "))
    assert record.subject.value == "TH-LT-1047"
    with pytest.raises(ValidationError, match="invalid sha256"):
        build(RecordKind.HASH_PREVALENCE, subject=Observable(type=ObservableType.SHA256, value="abc"))


def _redacted_cap(text: str, limit: int) -> str:
    return get_redactor().redact_text(text)[:limit]


def test_free_text_is_redacted_and_capped():
    secret_line = "cmd /c set password=Hunter2Secret " + "Copy-Item report.docx; " * 100
    event = build(RecordKind.PROCESS_EVENT, command_line=secret_line)
    assert "Hunter2Secret" not in event.command_line
    assert event.command_line == _redacted_cap(secret_line, 1024) and len(event.command_line) <= 1024
    subject_line = "Invoice overdue, please review the attached statement " * 10
    message = build(RecordKind.EMAIL_MESSAGE, subject_line=subject_line)
    assert message.subject_line == _redacted_cap(subject_line, 200) and len(message.subject_line) <= 200
    detail = "token=abcdef0123456789 " + "travel between distant locations " * 40
    anomaly = build(RecordKind.ANOMALY, detail=detail)
    assert "abcdef0123456789" not in anomaly.detail
    assert anomaly.detail == _redacted_cap(detail, 500) and len(anomaly.detail) <= 500
    reason = "Sign-in was blocked by a conditional access policy. " * 20
    sign_in = build(RecordKind.SIGN_IN, result="failure", failure_reason=reason)
    assert sign_in.failure_reason == _redacted_cap(reason, 500) and len(sign_in.failure_reason) <= 500
    condition = "subject contains invoice and sender is external " * 20
    rule = build(RecordKind.MAILBOX_RULE, conditions=(condition,))
    assert rule.conditions[0] == _redacted_cap(condition, 500) and len(rule.conditions[0]) <= 500


def test_reference_that_needs_redaction_is_refused():
    assert build(RecordKind.ENDPOINT, reference="https://console.example/computers/guid-1").reference
    with pytest.raises(ValidationError, match="reference must not contain secrets"):
        build(RecordKind.ENDPOINT, reference="https://console.example/x?api_key=abcdef123456")


def test_counts_and_ports_are_bounded():
    with pytest.raises(ValidationError):
        build(RecordKind.DNS_QUERY, count=0)
    with pytest.raises(ValidationError):
        build(RecordKind.NETWORK_CONNECTION, remote_port=70000)
    with pytest.raises(ValidationError):
        build(RecordKind.HASH_PREVALENCE, prevalence=-1)


def test_records_are_frozen_and_refuse_unknown_fields():
    record = build(RecordKind.ENDPOINT)
    with pytest.raises(ValidationError):
        record.hostname = "OTHER"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        build(RecordKind.ENDPOINT, is_protected=True)


def test_user_profile_is_privileged_when_a_role_is_privileged():
    assert build(RecordKind.USER_PROFILE).privileged is False
    assert build(RecordKind.USER_PROFILE, roles=("Global Administrator",)).privileged is True
    assert build(RecordKind.USER_PROFILE, privileged=True).privileged is True
    assert build(RecordKind.USER_PROFILE).user == "jsmith@example.com"


def test_role_change_privilege_and_target():
    change = build(RecordKind.ROLE_CHANGE, role_name="Security Administrator")
    assert change.privileged is True
    assert change.target == "jsmith@example.com/role-1"
    assert build(RecordKind.ROLE_CHANGE, role_definition_id=None).target is None


def test_persistence_item_target():
    assert build(RecordKind.PERSISTENCE_ITEM).target == "TH-LT-1047/task-7"


def test_email_recipients_are_capped_and_the_true_count_kept():
    many = tuple(f"user{i}@example.com" for i in range(150))
    message = build(RecordKind.EMAIL_MESSAGE, recipients=many)
    assert len(message.recipients) == 100 and message.recipient_count == 150
    assert build(RecordKind.EMAIL_MESSAGE, recipient_count=7).recipient_count == 7


def test_generic_attributes_are_redacted_and_capped():
    record = build(RecordKind.GENERIC, attributes={"client_secret": "s3cr3t-value", "note": "ok"})
    assert record.attributes["client_secret"] != "s3cr3t-value" and record.attributes["note"] == "ok"
    big = build(RecordKind.GENERIC, attributes={"blob": " ".join(f"line{i}" for i in range(2000))})
    assert big.attributes["_truncated"] is True and big.attributes["_original_bytes"] > 4096
    assert len(json.dumps(big.attributes).encode()) <= 4096


# ------------------------------------------------------- evidence fields --
@pytest.mark.parametrize("kind", list(RecordKind))
def test_evidence_fields_follow_the_table_and_are_json_ready(kind):
    fields = build(kind).evidence_fields()
    assert list(fields) == EVIDENCE_FIELDS[kind]
    json.dumps(fields)


def test_rule_item_has_every_field_with_none_when_unknown():
    item = build(RecordKind.DETECTION).rule_item()
    assert item["user"] is None and item["verdict"] == "MALICIOUS" and item["severity"] == "CRITICAL"
    assert set(item) == set(DetectionRecord.model_fields)


def test_sample_records_construct_for_every_class():
    for cls in (EnrichmentRecord, EndpointRecord, DetectionRecord, ProcessEventRecord, NetworkConnectionRecord,
                DnsQueryRecord, HashPrevalenceRecord, PersistenceItemRecord, UserProfileRecord, SignInRecord,
                AnomalyRecord, MfaEventRecord, MailboxRuleRecord, RoleChangeRecord, EmailMessageRecord,
                CloudAppRecord, GenericRecord):
        kind = cls.model_fields["kind"].default
        assert isinstance(build(kind), cls)
