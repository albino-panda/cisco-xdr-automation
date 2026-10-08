"""Investigation normalizers (architecture 14.1.4): vendor fields, typed records, generic fallback."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from tests.unit.atomics.investigation._support import FAKE_SHA256, HOST, USER, typed
from xdr_response.atomics.investigation.normalize import (
    NORMALIZERS,
    TYPED_RECORD_KEY,
    NormalizeContext,
    normalize,
)
from xdr_response.atomics.records import (
    DetectionRecord,
    EndpointRecord,
    GenericRecord,
    MailboxRuleRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import (
    ActionType,
    InvestigationResult,
    Observable,
    ObservableType,
    Severity,
    Verdict,
)

_A = ActionType
HOST_OBS = Observable(type=ObservableType.HOSTNAME, value=HOST)
USER_OBS = Observable(type=ObservableType.USER, value=USER)


def nctx(atomic: str = "investigate_endpoint", subject: Observable = HOST_OBS, *, typed_allowed: bool = False,
         internal_domains: tuple[str, ...] = ("example.com",)) -> NormalizeContext:
    return NormalizeContext(atomic=atomic, subject=subject, internal_domains=internal_domains,
                            typed_allowed=typed_allowed)


def result(integration: str, action: ActionType, subject: Observable, *findings: dict[str, Any]) -> InvestigationResult:
    return InvestigationResult(integration=integration, action_type=action, subject=subject, findings=findings)


def run(integration: str, action: ActionType, subject: Observable, *findings: dict[str, Any], **kw: Any):
    return normalize(integration, result(integration, action, subject, *findings),
                     nctx(action.value, subject, **kw))


def test_normalizers_cover_the_investigating_integrations():
    assert set(NORMALIZERS) == {"cisco_xdr", "secure_endpoint", "defender_endpoint", "entra", "microsoft_cloud",
                                "secure_email", "intune", "splunk"}
    assert TYPED_RECORD_KEY == "xdr_record"


def test_result_integration_must_match():
    with pytest.raises(ValueError, match="passed as"):
        normalize("entra", result("intune", _A.INVESTIGATE_ENDPOINT, HOST_OBS), nctx())


# ------------------------------------------------------- defender_endpoint --
MACHINE = {"id": "mde-0001", "computerDnsName": "th-lt-1047.corp.example", "osPlatform": "Windows11",
           "lastIpAddress": "192.0.2.10", "lastExternalIpAddress": "198.51.100.20", "healthStatus": "Active",
           "riskScore": "High", "rbacGroupName": "Finance", "machineTags": ["vip", "vip", ""],
           "lastSeen": "2026-01-15T11:59:00.1234567Z", "exposureLevel": "Medium"}


def test_defender_machine_becomes_an_endpoint_record():
    (record,) = run("defender_endpoint", _A.INVESTIGATE_ENDPOINT, HOST_OBS, MACHINE)
    assert isinstance(record, EndpointRecord)
    assert (record.hostname, record.mde_machine_id, record.os) == ("TH-LT-1047.CORP.EXAMPLE", "mde-0001", "Windows11")
    assert record.ip_addresses == ("192.0.2.10", "198.51.100.20")
    assert (record.groups, record.tags) == (("Finance",), ("vip",))
    assert (record.health_state, record.risk_level, record.isolation_state) == ("Active", "high", "unknown")
    assert record.last_seen == datetime(2026, 1, 15, 11, 59, 0, 123456, tzinfo=timezone.utc)
    assert record.reference == "mde-0001" and record.integration == "defender_endpoint"


def test_defender_machine_without_dns_name_uses_the_hostname_subject_and_drops_bad_ips():
    (record,) = run("defender_endpoint", _A.INVESTIGATE_ENDPOINT, HOST_OBS,
                    {"id": "mde-2", "lastIpAddress": "not-an-ip", "riskScore": "Informational"})
    assert record.hostname == HOST and record.ip_addresses == () and record.risk_level == "low"
    endpoint_id = Observable(type=ObservableType.ENDPOINT_ID, value="mde-2")
    (generic,) = run("defender_endpoint", _A.INVESTIGATE_ENDPOINT, endpoint_id, {"id": "mde-2"})
    assert isinstance(generic, GenericRecord)


def test_defender_non_machine_finding_is_generic():
    (record,) = run("defender_endpoint", _A.INVESTIGATE_ENDPOINT, HOST_OBS, {"unexpected": 1})
    assert isinstance(record, GenericRecord) and record.name == "defender_endpoint:investigate_endpoint"
    assert record.attributes == {"unexpected": 1}


# ------------------------------------------------------------------ intune --
def test_intune_managed_device_becomes_an_endpoint_record():
    device = {"id": "int-1", "deviceName": "th-lt-1047", "operatingSystem": "Windows",
              "userPrincipalName": "JSmith@Example.com", "complianceState": "compliant",
              "lastSyncDateTime": "2026-01-15T10:00:00Z", "wiFiMacAddress": "AABBCCDDEEFF",
              "ethernetMacAddress": "aabbccddeeff"}
    subject = Observable(type=ObservableType.ENDPOINT_ID, value="int-1")
    (record,) = run("intune", _A.INVESTIGATE_ENDPOINT, subject, device)
    assert isinstance(record, EndpointRecord)
    assert (record.hostname, record.intune_device_id, record.users) == ("TH-LT-1047", "int-1", (USER,))
    assert record.mac_addresses == ("aabbccddeeff",) and record.health_state == "compliant"
    (generic,) = run("intune", _A.INVESTIGATE_ENDPOINT, subject, {"id": "int-1"})
    assert isinstance(generic, GenericRecord)


# ------------------------------------------------------------------- entra --
def test_entra_user_becomes_a_profile():
    user = {"id": "obj-1", "userPrincipalName": "JSmith@Example.com", "displayName": "J Smith",
            "accountEnabled": True, "department": "Finance", "jobTitle": "Analyst"}
    (record,) = run("entra", _A.INVESTIGATE_USER, USER_OBS, user)
    assert isinstance(record, UserProfileRecord)
    assert (record.user, record.object_id, record.account_enabled, record.department) == \
        (USER, "obj-1", True, "Finance")
    assert record.roles == () and record.risk_level == "unknown" and record.privileged is False


def test_entra_user_without_upn_or_id_is_generic():
    (record,) = run("entra", _A.INVESTIGATE_USER, USER_OBS, {"displayName": "x"})
    assert isinstance(record, GenericRecord)


SIGN_IN = {"id": "si-1", "createdDateTime": "2026-01-15T11:00:00Z", "userPrincipalName": USER,
           "ipAddress": "203.0.113.9", "location": {"city": "Amsterdam", "countryOrRegion": "NL"},
           "appDisplayName": "Office 365", "clientAppUsed": "Browser",
           "deviceDetail": {"deviceId": "", "isCompliant": False},
           "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
           "conditionalAccessStatus": "notApplied", "riskLevelDuringSignIn": "hidden"}


@pytest.mark.parametrize("action", [_A.INVESTIGATE_AUTHENTICATION, _A.SEARCH_USER_ACTIVITY])
def test_entra_sign_in_mapping(action):
    (record,) = run("entra", action, USER_OBS, SIGN_IN)
    assert isinstance(record, SignInRecord)
    assert (record.sign_in_id, record.user, record.ip, record.country, record.city) == \
        ("si-1", USER, "203.0.113.9", "NL", "Amsterdam")
    assert (record.app, record.client_app, record.device_id, record.device_compliant) == \
        ("Office 365", "Browser", None, False)
    assert (record.result, record.failure_reason) == ("failure", "Invalid username or password")
    assert (record.conditional_access, record.risk_level, record.mfa_result) == ("not_applied", "unknown", "unknown")


@pytest.mark.parametrize("status, expected", [({"errorCode": 0}, "success"), ({}, "unknown"),
                                              ({"errorCode": True}, "unknown")])
def test_entra_sign_in_result(status, expected):
    (record,) = run("entra", _A.INVESTIGATE_AUTHENTICATION, USER_OBS, {**SIGN_IN, "status": status})
    assert record.result == expected and record.failure_reason is None


def test_entra_sign_in_without_timestamp_is_generic():
    (record,) = run("entra", _A.INVESTIGATE_AUTHENTICATION, USER_OBS, {**SIGN_IN, "createdDateTime": "yesterday"})
    assert isinstance(record, GenericRecord)


# --------------------------------------------------------- microsoft_cloud --
ALERT = {"id": "alert-1", "title": "Suspicious PowerShell", "severity": "high", "status": "inProgress",
         "classification": "truePositive", "category": "Execution", "mitreTechniques": ["T1059.001"],
         "serviceSource": "microsoftDefenderForEndpoint", "alertWebUrl": "https://security.example/alerts/alert-1",
         "createdDateTime": "2026-01-15T11:30:00Z", "firstActivityDateTime": "2026-01-15T11:20:00Z",
         "lastActivityDateTime": "2026-01-15T11:25:00Z",
         "evidence": [{"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "th-lt-1047"},
                      {"@odata.type": "#microsoft.graph.security.userEvidence",
                       "userAccount": {"userPrincipalName": "JSmith@Example.com"}},
                      {"@odata.type": "#microsoft.graph.security.fileEvidence",
                       "fileDetails": {"sha256": FAKE_SHA256.upper(), "filePath": "C:\\Users\\Public"}}]}


def test_microsoft_cloud_alert_becomes_a_detection():
    (record,) = run("microsoft_cloud", _A.INVESTIGATE_ENDPOINT, HOST_OBS, ALERT)
    assert isinstance(record, DetectionRecord)
    assert (record.detection_id, record.name, record.verdict, record.severity) == \
        ("alert-1", "Suspicious PowerShell", Verdict.MALICIOUS, Severity.HIGH)
    assert (record.endpoint, record.user, record.sha256) == (HOST, USER, FAKE_SHA256)
    assert record.mitre_techniques == ("T1059.001",) and record.status == "active"
    assert record.reference == "https://security.example/alerts/alert-1"
    assert record.observed_at == datetime(2026, 1, 15, 11, 30, tzinfo=timezone.utc)


@pytest.mark.parametrize("classification, severity, verdict, mapped", [
    ("falsePositive", "low", Verdict.CLEAN, Severity.LOW),
    ("informationalExpectedActivity", "informational", Verdict.CLEAN, Severity.INFO),
    ("unknown", "unknown", Verdict.SUSPICIOUS, Severity.INFO),
    (None, "medium", Verdict.SUSPICIOUS, Severity.MEDIUM),
])
def test_microsoft_cloud_alert_verdict_and_severity(classification, severity, verdict, mapped):
    alert = {**ALERT, "classification": classification, "severity": severity, "evidence": None, "status": "resolved"}
    (record,) = run("microsoft_cloud", _A.INVESTIGATE_ENDPOINT, HOST_OBS, alert)
    assert (record.verdict, record.severity, record.status) == (verdict, mapped, "resolved")
    assert record.endpoint is None and record.sha256 is None


def test_microsoft_cloud_hunting_rows_are_generic():
    row = {"Timestamp": "2026-01-15T11:00:00Z", "DeviceName": "th-lt-1047", "FileName": "example.exe"}
    (record,) = run("microsoft_cloud", _A.SEARCH_HASH_ENTERPRISE,
                    Observable(type=ObservableType.SHA256, value=FAKE_SHA256), row)
    assert isinstance(record, GenericRecord) and record.name == "microsoft_cloud:search_hash_enterprise"


# --------------------------------------------------------- generic sources --
@pytest.mark.parametrize("integration, action, subject, finding", [
    ("cisco_xdr", _A.INVESTIGATE_IP, Observable(type=ObservableType.IP, value="203.0.113.10"),
     {"module": "Secure Endpoint", "sightings": 3}),
    ("secure_endpoint", _A.INVESTIGATE_ENDPOINT, Observable(type=ObservableType.ENDPOINT_ID, value="guid-1"),
     {"event_type": "Executed by", "date": 1}),
    ("secure_email", _A.INVESTIGATE_EMAIL, Observable(type=ObservableType.EMAIL_MESSAGE_ID, value="msg-1"),
     {"subject": "Invoice"}),
    ("splunk", _A.SEARCH_DOMAIN_ENTERPRISE, Observable(type=ObservableType.DOMAIN, value="bad.example.test"),
     {"_time": "2026-01-15T11:00:00Z", "host": "th-lt-1047"}),
])
def test_sources_without_documented_fields_produce_generic_records(integration, action, subject, finding):
    (record,) = run(integration, action, subject, finding)
    assert isinstance(record, GenericRecord) and record.name == f"{integration}:{action.value}"
    assert record.attributes == finding and record.integration == integration


def test_generic_records_redact_secrets_and_dedupe_by_content():
    records = run("splunk", _A.SEARCH_USER_ACTIVITY, USER_OBS, {"raw": "Authorization: Bearer abc.def.ghi"},
                  {"raw": "Authorization: Bearer abc.def.ghi"})
    assert "abc.def.ghi" not in records[0].attributes["raw"]
    assert records[0].record_id == records[1].record_id  # the atomic keeps the first


def test_no_findings_no_records():
    assert run("entra", _A.INVESTIGATE_USER, USER_OBS) == []


# ------------------------------------------------------------- typed path --
def test_typed_record_accepted_from_a_simulated_adapter():
    (record,) = run("secure_endpoint", _A.INVESTIGATE_ENDPOINT, HOST_OBS,
                    typed("detection", name="Ransomware.Generic", verdict="MALICIOUS", severity="CRITICAL",
                          endpoint="th-lt-1047"), typed_allowed=True)
    assert isinstance(record, DetectionRecord)
    assert (record.integration, record.atomic, record.subject, record.endpoint) == \
        ("secure_endpoint", "investigate_endpoint", HOST_OBS, HOST)


def test_typed_record_flat_form_is_accepted():
    finding = {TYPED_RECORD_KEY: True, "kind": "endpoint", "hostname": "th-lt-1047", "xdr_integration": "intune"}
    (record,) = run("intune", _A.INVESTIGATE_ENDPOINT, HOST_OBS, finding, typed_allowed=True)
    assert isinstance(record, EndpointRecord) and record.hostname == HOST


def test_typed_record_from_a_real_adapter_becomes_generic():
    finding = typed("detection", name="Fake", verdict="MALICIOUS", severity="CRITICAL")
    (record,) = run("defender_endpoint", _A.INVESTIGATE_ENDPOINT, HOST_OBS, finding, typed_allowed=False)
    assert isinstance(record, GenericRecord)
    assert record.attributes[TYPED_RECORD_KEY]["name"] == "Fake"


def test_typed_record_restricted_to_another_adapter_is_skipped():
    finding = typed("endpoint", only="intune", hostname="th-lt-1047")
    assert run("secure_endpoint", _A.INVESTIGATE_ENDPOINT, HOST_OBS, finding, typed_allowed=True) == []
    assert len(run("intune", _A.INVESTIGATE_ENDPOINT, HOST_OBS, finding, typed_allowed=True)) == 1


@pytest.mark.parametrize("finding, message", [
    (typed("endpoint", only="not_a_vendor", hostname="h"), "not an integration name"),
    (typed("endpoint", record_id="rec_x", hostname="h"), "never carry"),
    (typed("endpoint", subject="x", hostname="h"), "never carry"),
    (typed("no_such_kind"), "unknown typed record kind"),
    (typed("endpoint"), "invalid typed endpoint record"),
    ({TYPED_RECORD_KEY: "yes"}, "must be a record mapping"),
])
def test_malformed_typed_records_raise(finding, message):
    with pytest.raises(ValueError, match=message):
        run("secure_endpoint", _A.INVESTIGATE_ENDPOINT, HOST_OBS, finding, typed_allowed=True)


@pytest.mark.parametrize("forward, internal, expected", [
    (("ops@example.com",), ("example.com",), False),
    (("ops@mail.example.com",), ("example.com",), False),
    (("drop@exfil.example",), ("example.com",), True),
    (("ops@example.com",), (), True),
    ((), ("example.com",), False),
])
def test_typed_mailbox_rule_external_forwarding_is_computed(forward, internal, expected):
    finding = typed("mailbox_rule", mailbox=USER, rule_id="r1", name="fwd", forward_to=list(forward))
    (record,) = run("entra", _A.INVESTIGATE_USER, USER_OBS, finding, typed_allowed=True, internal_domains=internal)
    assert isinstance(record, MailboxRuleRecord) and record.external_forwarding is expected


def test_typed_mailbox_rule_keeps_an_explicit_value():
    finding = typed("mailbox_rule", mailbox=USER, rule_id="r1", name="fwd", forward_to=["drop@exfil.example"],
                    external_forwarding=False)
    (record,) = run("entra", _A.INVESTIGATE_USER, USER_OBS, finding, typed_allowed=True)
    assert record.external_forwarding is False


def test_integration_without_a_dedicated_normalizer_gets_typed_and_generic_records():
    domain = Observable(type=ObservableType.DOMAIN, value="bad.example.test")
    records = run("umbrella", _A.INVESTIGATE_DOMAIN, domain, typed("dns_query", domain="bad.example.test"),
                  {"other": 1}, typed_allowed=True)
    assert [r.kind.value for r in records] == ["dns_query", "generic"]
